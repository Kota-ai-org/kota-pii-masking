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
| **`kota_sa_email`** | The Kota identity you authorize to read the masked bucket: `kota-masked-reader@kota-production.iam.gserviceaccount.com` |
| **Support** | Kota runs the dry-run review with you and helps with go-live |

## 2. What you deploy (and what stays yours)

Everything runs in **your** project. The module creates:

- a **masked bucket** (the only thing Kota reads),
- a private **state bucket** (watermark only — Kota never reads it),
- a **Cloud Run job** + **Cloud Scheduler** cron that does the masking,
- two **Cloud DLP templates** you own and can tune anytime,
- a dedicated **reader service account** Kota impersonates,
- your **Langfuse keys** stored in **Secret Manager** (never in code, image, or logs).

## 3. Security model at a glance

- **Keyless.** Kota reads via short-lived (~1h) impersonation tokens. **No
  service-account key is ever created, exported, or stored.**
- **Least privilege.** Kota's reader SA has `objectViewer` on the **masked bucket
  only** — nothing else in your project. Verified: it cannot read the state bucket.
- **You hold the off switch.** Disable the reader SA and Kota's access is gone
  instantly — no key to chase.
- **You own the masking policy.** Both DLP templates live in your project; tune
  detection/transformation anytime, no Kota redeploy.
- **Residual-PII caveat (shared responsibility).** DLP is detection-based and
  probabilistic — it is strong on structured PII (emails, cards, SSNs) and weaker
  on free-form names. Whole PII-carrier fields (`userId`, raw `metadata`, `tags`)
  are **dropped**, not just masked, and masking **fails closed** (a DLP error
  writes nothing). Treat the masked bucket as **reduced-sensitivity** data
  governed by your DPA with Kota, not as a guarantee of zero PII. You can tighten
  detection (Section 7) and review a sample before go-live (Section 6).

---

## Requirements

- A GCP project with billing enabled.
- OpenTofu/Terraform ≥ 1.5, `gcloud` CLI authenticated to the project.
- A Langfuse project API key pair (public `pk-lf-...` + secret `sk-lf-...`).
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
          - is:C02ovz1en           # Kota's Google Workspace customer ID
```
```bash
gcloud org-policies set-policy policy.yaml
```
`inheritFromParent: true` and the `is:` prefix are both required. This loosens
the policy for **this one project only**; revert by deleting it after off-boarding.
If an exception isn't acceptable, contact Kota — masked traces can instead be
delivered by an outbound push that places no Kota identity in your project.

### Step 1 — deploy (one command)

```bash
# Langfuse keys are sensitive — export them, or omit and the script prompts silently.
export TF_VAR_langfuse_public_key=pk-lf-...
export TF_VAR_langfuse_secret_key=sk-lf-...

PROJECT=<YOUR_PROJECT> \
REGION=<REGION> \
KOTA_SA_EMAIL=kota-masked-reader@kota-production.iam.gserviceaccount.com \
SCHEDULER_PAUSED=true \
./deploy.sh
```

`deploy.sh` builds the exporter image **in your project** (Cloud Build, ~1–3 min),
captures its immutable `@sha256` digest, runs `tofu apply` pinned to that digest,
and prints the two values you send back to Kota. `SCHEDULER_PAUSED=true` keeps the
cron paused so you can review the dry-run first (Section 6), then unpause.

> The keys flow **only** to Secret Manager and are injected into the job at
> runtime — never written to the image, the tfvars, or your shell history.

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
export LANGFUSE_PUBLIC_KEY=... LANGFUSE_SECRET_KEY=... LANGFUSE_HOST=...
python scripts/dry_run.py \
  --project <YOUR_PROJECT> --region <REGION> \
  --inspect-template "$(tofu output -raw dlp_inspect_template_id)" \
  --deidentify-template "$(tofu output -raw dlp_deidentify_template_id)"
```

**Go live** — unpause the cron:
```bash
# in your tfvars set scheduler_paused = false, then:
tofu apply
```

---

## How it runs

- **Schedule:** hourly (UTC) by default — set `schedule_cron` to change it.
- **Incremental:** the job persists the last-exported timestamp in
  `gs://<state-bucket>/watermark.json` and only pulls newer traces each run. The
  first run looks back `initial_lookback_days` (default 1).
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
| `langfuse_public_key` | ✅ | — | `pk-lf-...` (sensitive → Secret Manager). |
| `langfuse_secret_key` | ✅ | — | `sk-lf-...` (sensitive → Secret Manager). |
| `langfuse_host` | | `https://us.cloud.langfuse.com` | Langfuse API base URL. |
| `name_prefix` | | `kota-pii` | Prefix for all resource names. |
| `schedule_cron` | | `0 * * * *` | Cron (UTC) for the exporter. |
| `initial_lookback_days` | | `1` | First-run lookback when no watermark exists. |
| `scheduler_paused` | | `false` | Deploy the cron paused (review first). |
| `dlp_info_types` | | common PII set | DLP infoTypes to detect + replace. |
| `dlp_min_likelihood` | | `LIKELY` | Minimum match confidence to act on. |

## Outputs

| Output | Use |
|---|---|
| `masked_bucket_name` | **Send to Kota.** |
| `reader_sa_email` | **Send to Kota.** |
| `masked_bucket_url`, `state_bucket_name` | Reference. |
| `exporter_job_name`, `scheduler_job_name`, `exporter_sa_email` | Operate the job. |
| `dlp_inspect_template_id`, `dlp_deidentify_template_id` | Used by the dry-run. |

---

## Advanced — run the steps manually

`deploy.sh` just chains a build and an apply; you can run them yourself (e.g. to
build in CI and apply elsewhere). Copy `terraform.tfvars.example` →
`terraform.tfvars` for the non-secret values, and pass the Langfuse keys as env:

```bash
# 1. build the image in your project, capture the digest
PROJECT=<YOUR_PROJECT> REGION=<REGION> ./scripts/build_image.sh
#    prints: exporter_image = "REGION-docker.pkg.dev/<proj>/kota-pii-exporter/exporter@sha256:..."

# 2. apply with that digest
export TF_VAR_langfuse_public_key=pk-lf-... TF_VAR_langfuse_secret_key=sk-lf-...
export TF_VAR_exporter_image="<digest from step 1>"
tofu init && tofu apply
```
