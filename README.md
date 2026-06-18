# Kota PII-Masking — Customer Deployment Guide

De-identify your Langfuse traces **inside your own GCP project** before Kota ever
reads them. A scheduled Cloud Run job pulls traces from the Langfuse API,
de-identifies them with Google Cloud Sensitive Data Protection (Cloud DLP), and
writes the masked records to a single bucket in your project. Kota reads **only**
that masked bucket, through a dedicated service account it impersonates keylessly.

**Raw PII never lands in durable storage, and never reaches Kota's storage, logs,
or models.**

```
            ┌────────────────── your GCP project (your trust boundary) ──────────────────┐
            │                                                                             │
 Cloud Scheduler ──run──▶ Cloud Run job ──pull──▶ Langfuse API                            │
            │                   │                                                         │
            │                   ├── DLP mask (in memory, raw PII never written)           │
            │                   ▼                                                         │
            │            masked bucket  ◀── write masked JSONL                            │
            │                   ▲                                                         │
            └───────────────────┼─────────────────────────────────────────────────────────┘
                                │  read-only, keyless impersonation
                              Kota
```

---

## Get the module

Two ways to obtain it — pick whichever fits your workflow:

**A. Download a release (no git tooling needed)**
1. Open the [**Releases**](../../releases) page and download the latest
   `kota-pii-masking-vX.Y.Z.tar.gz` **and** its `.sha256`.
2. Verify integrity:
   ```bash
   shasum -a 256 -c kota-pii-masking-vX.Y.Z.tar.gz.sha256
   ```
3. Unpack and enter it:
   ```bash
   tar -xzf kota-pii-masking-vX.Y.Z.tar.gz && cd kota-pii-masking
   ```

**B. Pin it in your own Terraform**
```hcl
source = "git::https://github.com/Kota-ai-org/kota-pii-masking//?ref=v1.0.0"
```

Then follow the steps below. Questions at any point: **roee@kota-ai.com**.

---

## 1. What Kota delivers to you

| Deliverable | What it is |
|---|---|
| **This Terraform module** | `terraform/kota-pii-masking/` — everything below, version-pinned |
| `exporter/` | The masking job's full source code — **auditable**, you build it yourself |
| `deploy.sh` | One-command deploy (build image → apply) |
| `scripts/build_image.sh` | Builds the exporter image in *your* Artifact Registry |
| `scripts/dry_run.py` | Pre-go-live review: shows masked before/after on a sample |
| **`kota_sa_email`** | The Kota identity you authorize to read the masked bucket — **provided by Kota** in your onboarding email. |
| **Support** | Kota runs the dry-run review with you and helps with go-live |

## 2. What you deploy (and what stays yours)

Everything runs in **your** project. The module creates:

- a **masked bucket** (the only thing Kota reads), one subdir per Langfuse project,
- a private **state bucket** (per-project watermarks — Kota never reads it),
- a **Cloud Run job** + **Cloud Scheduler** cron that does the masking,
- two **Cloud DLP templates** you own and can tune anytime,
- a dedicated **reader service account** Kota impersonates,
- your **Langfuse keys** (one pair per project) stored in **Secret Manager** (never in code, image, or logs).

## 3. Security model at a glance

- **Keyless.** Kota reads via short-lived (~1h) impersonation tokens. **No
  service-account key is ever created, exported, or stored.**
- **Least privilege.** Kota's reader SA has `objectViewer` on the **masked bucket
  only** — nothing else in your project. Verified: it cannot read the state bucket.
- **You hold the off switch.** Disable the reader SA and Kota's access is gone
  instantly — no key to chase.
- **You own the masking policy.** Both DLP templates live in your project; tune
  detection/transformation anytime, no Kota redeploy.
- **Whole trace kept, every text field masked.** The job preserves the full
  trace structure (nothing is dropped — `userId`, `metadata`, `tags`,
  observations, all of it) and runs DLP over **every string value**: detected PII
  is replaced with `[INFO_TYPE]` placeholders, non-PII strings (ids, timestamps,
  type/name) pass through unchanged.
- **Residual-PII caveat (shared responsibility).** Because every field is kept and
  scrubbed in place, coverage depends entirely on DLP detection, which is
  probabilistic — strong on structured PII (emails, cards, SSNs), weaker on
  free-form names. Masking **fails closed per chunk** (a DLP error doesn't advance
  that project's watermark, so nothing partial is trusted). Treat the masked
  bucket as **reduced-sensitivity** data governed by your DPA with Kota, not a
  guarantee of zero PII — tune the inspect template to your data (Section 7) and
  review a sample before go-live (Section 6).

---

## Requirements

- A GCP project with billing enabled.
- OpenTofu/Terraform ≥ 1.5, `gcloud` CLI authenticated to the project.
- One or more Langfuse project API key pairs (public `pk-lf-...` + secret `sk-lf-...`) — one pair per Langfuse project you want masked.
- The deploying identity needs rights to create buckets, service accounts, IAM
  bindings, DLP templates, secrets, a Cloud Run job, and a Cloud Scheduler job —
  plus, for the one-time image build, `cloudbuild.builds.editor` +
  `artifactregistry.writer`. Project **Owner** covers all of it.

---

## Deploy — 3 steps

### Step 0 — pre-flight: org policy (check once)

The module grants Kota's SA `tokenCreator` on your in-project reader SA — the
**only** binding referencing an identity outside your org. If your org enforces
**domain-restricted sharing** (`constraints/iam.allowedPolicyMemberDomains` —
**on by default for orgs created on/after 2024-05-03**), that binding is rejected
and the deploy fails.

**Check:**
```bash
gcloud org-policies describe iam.allowedPolicyMemberDomains --project <YOUR_PROJECT>
```
If it returns an `allowedValues` list **without** Kota's customer ID, add a
project-scoped exception:
```yaml
# policy.yaml
name: projects/<YOUR_PROJECT>/policies/iam.allowedPolicyMemberDomains
spec:
  inheritFromParent: true          # keep your own org's allowed principals
  rules:
    - values:
        allowedValues:
          - is:<KOTA_CUSTOMER_ID>  # Kota's Workspace customer ID — provided by Kota
```
```bash
gcloud org-policies set-policy policy.yaml
```
`inheritFromParent: true` and the `is:` prefix are both required. This loosens
the policy for **this one project only**; revert by deleting it after off-boarding.
If an exception isn't acceptable, contact Kota — masked traces can instead be
delivered by an outbound push that places no Kota identity in your project.

### Step 1 — deploy (one command)

First, list your Langfuse projects (and their keys) in a gitignored tfvars file:

```bash
cp langfuse_projects.auto.tfvars.example langfuse_projects.auto.tfvars
# edit it — one entry per Langfuse project:
#   langfuse_projects = [
#     { name = "support-bot", public_key = "pk-lf-...", secret_key = "sk-lf-...",
#       host = "https://us.cloud.langfuse.com" },
#     { name = "sales-agent", public_key = "pk-lf-...", secret_key = "sk-lf-..." },
#   ]
```

Then deploy:

```bash
PROJECT=<YOUR_PROJECT> \
REGION=<REGION> \
KOTA_SA_EMAIL=<KOTA_SA_EMAIL> \   # provided by Kota in onboarding
SCHEDULER_PAUSED=true \
./deploy.sh
```

> **Per-project `host`.** Each project's `host` must match the region of *that*
> project's key pair. US: `https://us.cloud.langfuse.com` (default if omitted).
> EU: `https://cloud.langfuse.com`. Self-hosted: your own base URL. A mismatched
> host authenticates against the wrong region and returns no traces.

> **Multiple projects, one bucket.** Every project's masked traces land in the
> **same** masked bucket under its own subdir (`exports/<name>/`), so Kota still
> only needs the single `(masked_bucket, reader_sa)` pair. Add or remove projects
> later by editing the list and re-running `deploy.sh`.

`deploy.sh` builds the exporter image **in your project** (Cloud Build, ~1–3 min),
captures its immutable `@sha256` digest, runs `tofu apply` pinned to that digest,
and prints the two values you send back to Kota. `SCHEDULER_PAUSED=true` keeps the
cron paused so you can review the dry-run first (Section 6), then unpause.

> The keys flow **only** to Secret Manager (one secret pair per project) and are
> injected into the job at runtime — never written to the image or your shell
> history. The `*.auto.tfvars` file holding them is gitignored.

### Step 2 — hand two values back to Kota

`deploy.sh` prints them; you can re-print anytime:
```bash
tofu output -raw masked_bucket_name   # e.g. acme-pii-masked-123456789
tofu output -raw reader_sa_email      # e.g. acme-pii-reader@acme.iam.gserviceaccount.com
```
Send both to Kota. That's all Kota needs to start reading masked traces.

---

## 6. Review the dry-run before going live

Deploy with `SCHEDULER_PAUSED=true`, then run the dry-run with Kota. It samples
traces from your Langfuse API and shows DLP detections + a masked before/after
preview (raw text is never printed). Your team signs off, then you unpause.

```bash
# One project (export its key pair):
export LANGFUSE_PUBLIC_KEY=... LANGFUSE_SECRET_KEY=... LANGFUSE_HOST=...
python scripts/dry_run.py \
  --project <YOUR_PROJECT> --region <REGION> \
  --inspect-template "$(tofu output -raw dlp_inspect_template_id)" \
  --deidentify-template "$(tofu output -raw dlp_deidentify_template_id)"

# All configured projects at once: set LANGFUSE_PROJECTS (the [{name,host},...]
# manifest) plus LF_PUB_<SLUG>/LF_SEC_<SLUG> per project, then add --all.
```

**Go live** — unpause the cron:
```bash
# in your tfvars set scheduler_paused = false, then:
tofu apply
```

---

## How it runs

- **Schedule:** hourly (UTC) by default — set `schedule_cron` to change it.
- **Incremental, per project:** the job persists each project's last-exported
  timestamp in `gs://<state-bucket>/watermark-<name>.json` and only pulls newer
  traces each run. The first run for a project looks back `initial_lookback_days`
  (default 1).
- **Streamed in chunks, checkpointed:** within a run, traces are pulled
  oldest-first and processed in chunks of `export_chunk_size` — each chunk is
  masked, written as its own object, then the watermark is advanced. Peak memory
  stays flat regardless of backlog, and an interrupted run (OOM/timeout/error)
  keeps every committed chunk and resumes from its watermark next run. For very
  large backlogs set `max_records_per_run` to bound each run; the cron drains the
  rest over subsequent runs.
- **Per-project fail-closed:** the single job exports every configured project in
  one run. If one project errors, its watermark is left untouched (so its window
  retries next run) and the **other projects still complete**. The run then exits
  non-zero so the failure is visible/alertable.
- **Stays under your DLP quota:** the job batches all of a trace's fields into one
  DLP request, self-throttles below `dlp_max_rpm` (default 500, under the 600/min
  region quota), and backs off + retries on quota errors. At high volume a run
  paces itself and the watermark resumes the rest next run — **no action needed**.
  Want faster catch-up? Your GCP admin can raise the DLP quota and `dlp_max_rpm`.
- **Run on demand:**
  ```bash
  gcloud run jobs execute "$(tofu output -raw exporter_job_name)" --region <REGION> --wait
  ```
- **After a code change:** if Kota ships a new `exporter/` version, re-run
  `./deploy.sh` — it rebuilds, re-pins the new digest, and applies. Nothing else
  changes.

## 7. Tuning the masking policy

You own both DLP templates. From your own console (or via the module variables)
you can:
- **Add detectors** — extend `dlp_info_types`, or add custom regex/dictionary
  detectors for your own identifiers (member IDs, account numbers). DLP is weakest
  on custom formats, so this is the highest-leverage tightening.
- **Change sensitivity** — `dlp_min_likelihood` (`POSSIBLE` catches more at the
  cost of more over-masking; `LIKELY` is the default).
- **Change the transformation** — the default replaces each detected span with a
  typed placeholder (`[EMAIL_ADDRESS]`, `[PERSON_NAME]`, …), preserving structure.

Changes take effect on the next run — no Kota redeploy.

## Revoking Kota access

Disable or delete the reader service account
(`tofu output -raw reader_sa_email`), or remove the `tokenCreator` binding. Either
cuts Kota's access immediately — no key exists to revoke. Kota has no other access
and **no write access** to your project.

---

## Inputs

| Variable | Required | Default | Description |
|---|---|---|---|
| `project_id` | ✅ | — | Your GCP project. All resources live here. |
| `region` | | `us-central1` | Region for buckets, job, and DLP templates (data residency). |
| `kota_sa_email` | ✅ | — | Kota's reader identity (provided by Kota). |
| `exporter_image` | ✅ | — | Set automatically by `deploy.sh` (digest-pinned). |
| `langfuse_projects` | ✅ | — | List of Langfuse projects to export (sensitive → Secret Manager). Each is `{ name, public_key, secret_key, host }`. `name` is a slug (`^[a-z0-9][a-z0-9-]*$`, ≤30 chars, unique) used in the output subdir `exports/<name>/`; `host` is optional per project (default `https://us.cloud.langfuse.com` — EU: `https://cloud.langfuse.com`, or self-hosted). See `langfuse_projects.auto.tfvars.example`. |
| `name_prefix` | | `kota-pii` | Prefix for all resource names. |
| `schedule_cron` | | `0 * * * *` | Cron (UTC) for the exporter. |
| `initial_lookback_days` | | `1` | First-run lookback when no watermark exists. |
| `scheduler_paused` | | `false` | Deploy the cron paused (review first). |
| `dlp_info_types` | | common PII set | DLP infoTypes to detect + replace. |
| `dlp_min_likelihood` | | `LIKELY` | Minimum match confidence to act on. |
| `dlp_max_rpm` | | `500` | Client-side DLP requests/min ceiling. The job self-throttles below this and backs off on quota errors. |
| `dlp_timeout_seconds` | | `120` | Per-call DLP deadline. A stuck call raises `DeadlineExceeded` → retried/checkpointed instead of hanging. |
| `export_chunk_size` | | `200` | Records masked + written + checkpointed per chunk. Caps peak memory regardless of backlog. |
| `max_records_per_run` | | `0` | Per-run record cap per project (0 = unlimited). Bounds a run under the job timeout; watermark resumes the rest next run. Set for very large backlogs. |
| `exporter_cpu` | | `"1"` | CPU for the exporter job container. |
| `exporter_memory` | | `"1Gi"` | Memory for the exporter job container. A run holds its pulled traces in memory before writing — raise (`"2Gi"`/`"4Gi"`) for large/busy projects if runs are OOM-killed. |

## Outputs

| Output | Use |
|---|---|
| `masked_bucket_name` | **Send to Kota.** |
| `reader_sa_email` | **Send to Kota.** |
| `langfuse_project_names`, `masked_prefixes` | Per-project subdirs under the masked bucket (`exports/<name>/`). |
| `masked_bucket_url`, `state_bucket_name` | Reference. |
| `exporter_job_name`, `scheduler_job_name`, `exporter_sa_email` | Operate the job. |
| `dlp_inspect_template_id`, `dlp_deidentify_template_id` | Used by the dry-run. |

---

## Advanced — run the steps manually

`deploy.sh` just chains a build and an apply; you can run them yourself (e.g. to
build in CI and apply elsewhere). Copy `terraform.tfvars.example` →
`terraform.tfvars` for the non-secret values, and put the Langfuse projects in
`langfuse_projects.auto.tfvars` (or pass `TF_VAR_langfuse_projects` as JSON):

```bash
# 1. build the image in your project, capture the digest
PROJECT=<YOUR_PROJECT> REGION=<REGION> ./scripts/build_image.sh
#    prints: exporter_image = "REGION-docker.pkg.dev/<proj>/kota-pii-exporter/exporter@sha256:..."

# 2. apply with that digest (langfuse_projects.auto.tfvars is auto-loaded)
export TF_VAR_exporter_image="<digest from step 1>"
tofu init && tofu apply
```
