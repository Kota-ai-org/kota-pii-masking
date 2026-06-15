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
# Langfuse credentials (sensitive) — provide EITHER way:
#   - export TF_VAR_langfuse_public_key / TF_VAR_langfuse_secret_key, OR
#   - leave them unset and this script prompts (silent, no echo, no history).
#
# Optional env:
#   NAME_PREFIX       resource name prefix (default: kota-pii)
#   LANGFUSE_HOST     Langfuse API base (default: https://us.cloud.langfuse.com)
#   SCHEDULER_PAUSED  =true to deploy the hourly cron PAUSED (review the dry-run,
#                     then unpause). Default: live (module default).
#   AUTO_APPROVE=1    skip the interactive apply confirmation
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${PROJECT:?set PROJECT to your GCP project id}"
: "${REGION:?set REGION (e.g. us-central1)}"
: "${KOTA_SA_EMAIL:?set KOTA_SA_EMAIL (provided by Kota)}"
NAME_PREFIX="${NAME_PREFIX:-kota-pii}"

# --- Langfuse keys: env, else interactive silent prompt -----------------------
if [ -z "${TF_VAR_langfuse_public_key:-}" ]; then
  if [ -t 0 ]; then
    read -r -p "Langfuse public key (pk-lf-...): " TF_VAR_langfuse_public_key
  else
    echo "ERROR: set TF_VAR_langfuse_public_key (no TTY to prompt)." >&2; exit 1
  fi
fi
if [ -z "${TF_VAR_langfuse_secret_key:-}" ]; then
  if [ -t 0 ]; then
    read -r -s -p "Langfuse secret key (sk-lf-...): " TF_VAR_langfuse_secret_key; echo
  else
    echo "ERROR: set TF_VAR_langfuse_secret_key (no TTY to prompt)." >&2; exit 1
  fi
fi
export TF_VAR_langfuse_public_key TF_VAR_langfuse_secret_key

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
[ -n "${LANGFUSE_HOST:-}" ] && export TF_VAR_langfuse_host="$LANGFUSE_HOST"
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
