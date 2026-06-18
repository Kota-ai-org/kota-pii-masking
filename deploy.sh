#!/usr/bin/env bash
# One-command deploy: build the exporter image in YOUR project, then apply the
# module pinned to that image's digest. This is a thin orchestrator — it does NOT
# build inside Terraform; it builds first, then hands Terraform a static digest,
# so the plan/state stay clean.
#
# Required env:
#   PROJECT         your GCP project id
#   REGION          region (e.g. us-central1, europe-west1)
#   KOTA_SA_EMAIL   Kota's service account email (provided by Kota)
#
# Langfuse projects (sensitive) — provide the langfuse_projects list EITHER way:
#   - create langfuse_projects.auto.tfvars from langfuse_projects.auto.tfvars.example
#     (auto-loaded by tofu; gitignored via *.tfvars), OR
#   - export TF_VAR_langfuse_projects as a JSON value (e.g. in CI).
# Each project = {name, public_key, secret_key, host?}; keys go to Secret Manager,
# never to the image, tfstate, or shell history.
#
# Optional env:
#   NAME_PREFIX       resource name prefix (default: kota-pii)
#   SCHEDULER_PAUSED  =true to deploy the hourly cron PAUSED (review the dry-run,
#                     then unpause). Default: live (module default).
#   AUTO_APPROVE=1    skip the interactive apply confirmation
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${PROJECT:?set PROJECT to your GCP project id}"
: "${REGION:?set REGION (e.g. us-central1)}"
: "${KOTA_SA_EMAIL:?set KOTA_SA_EMAIL (provided by Kota)}"
NAME_PREFIX="${NAME_PREFIX:-kota-pii}"

# --- Langfuse projects: require a tfvars file or TF_VAR_langfuse_projects ------
# The list is sensitive and structured, so it isn't prompted. Supply it via a
# gitignored *.auto.tfvars file (preferred) or the TF_VAR env (CI).
if [ ! -f "$HERE/langfuse_projects.auto.tfvars" ] \
   && [ -z "${TF_VAR_langfuse_projects:-}" ]; then
  echo "ERROR: no Langfuse projects configured." >&2
  echo "  Create langfuse_projects.auto.tfvars (copy langfuse_projects.auto.tfvars.example)," >&2
  echo "  or export TF_VAR_langfuse_projects as a JSON value." >&2
  exit 1
fi

# --- Step 1: build image in the customer project, capture the digest ----------
echo "== building exporter image (Cloud Build, ~1-3 min) ==" >&2
DIGEST="$(PROJECT="$PROJECT" REGION="$REGION" NAME_PREFIX="$NAME_PREFIX" \
  "$HERE/scripts/build_image.sh")"
echo "== image digest: $DIGEST ==" >&2

# --- Step 2: apply, pinned to that digest -------------------------------------
# DLP template reads use this project for the ADC quota project.
export USER_PROJECT_OVERRIDE=true GOOGLE_BILLING_PROJECT="$PROJECT"
export TF_VAR_project_id="$PROJECT"
export TF_VAR_region="$REGION"
export TF_VAR_kota_sa_email="$KOTA_SA_EMAIL"
export TF_VAR_name_prefix="$NAME_PREFIX"
export TF_VAR_exporter_image="$DIGEST"
[ -n "${SCHEDULER_PAUSED:-}" ] && export TF_VAR_scheduler_paused="$SCHEDULER_PAUSED"

tofu -chdir="$HERE" init -input=false
if [ -n "${AUTO_APPROVE:-}" ]; then
  tofu -chdir="$HERE" apply -auto-approve
else
  tofu -chdir="$HERE" apply
fi

echo
echo "== done. Share these two values with Kota: =="
tofu -chdir="$HERE" output -raw masked_bucket_name; echo
tofu -chdir="$HERE" output -raw reader_sa_email; echo
