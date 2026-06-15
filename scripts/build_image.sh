#!/usr/bin/env bash
# Build the PII-masking exporter image in YOUR project and print its immutable
# digest. Run this ONCE before `tofu apply`, and again whenever the exporter
# source under `exporter/` changes. Terraform never builds — it only references
# the digest you paste into `exporter_image`.
#
# The image lives in an Artifact Registry repo in your own project; the Cloud Run
# job pulls it from there on every run. Nothing is pulled from Kota.
#
# Required env:
#   PROJECT   GCP project to build in (your project).
#   REGION    Artifact Registry / build region (e.g. us-central1, europe-west1).
# Optional env:
#   REPO      Artifact Registry repo (default: <NAME_PREFIX>-exporter).
#   NAME_PREFIX  Used only to derive REPO default (default: kota-pii).
#   TAG       Image tag (default: git short SHA of the exporter tree, else a
#             content hash). The digest, not the tag, is what Terraform pins.
#
# The identity running this needs: cloudbuild.builds.editor + artifactregistry.writer
# (and rights to enable APIs / create the repo on first run).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPORTER_DIR="$HERE/../exporter"

: "${PROJECT:?set PROJECT to your GCP project id}"
: "${REGION:?set REGION (e.g. us-central1)}"
NAME_PREFIX="${NAME_PREFIX:-kota-pii}"
REPO="${REPO:-${NAME_PREFIX}-exporter}"

if [ -z "${TAG:-}" ]; then
  if TAG="$(git -C "$EXPORTER_DIR" rev-parse --short HEAD 2>/dev/null)"; then
    :
  else
    TAG="$(find "$EXPORTER_DIR" -type f -exec md5 -q {} + 2>/dev/null | md5 -q | cut -c1-12)"
  fi
fi

IMAGE_PATH="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/exporter"

echo "== enabling APIs (artifactregistry, cloudbuild) ==" >&2
gcloud services enable artifactregistry.googleapis.com cloudbuild.googleapis.com \
  --project "$PROJECT" >&2

# Cloud Build runs as the Compute Engine default SA; it needs to push the image
# into Artifact Registry and write build logs. Idempotent.
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
BUILD_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for ROLE in roles/cloudbuild.builds.builder roles/artifactregistry.writer; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:${BUILD_SA}" --role "$ROLE" \
    --condition=None --quiet >/dev/null 2>&1 || true
done

if ! gcloud artifacts repositories describe "$REPO" \
       --location "$REGION" --project "$PROJECT" >/dev/null 2>&1; then
  echo "== creating Artifact Registry repo: $REPO ==" >&2
  gcloud artifacts repositories create "$REPO" \
    --repository-format=docker --location "$REGION" --project "$PROJECT" \
    --description="Kota PII-masking trace exporter images." >&2
fi

echo "== building image $IMAGE_PATH:$TAG via Cloud Build ==" >&2
# The IAM grants above are eventually consistent; on a first run the build can
# 403 on the staging bucket before they propagate. Retry through the lag.
ATTEMPT=0
until gcloud builds submit "$EXPORTER_DIR" \
        --tag "${IMAGE_PATH}:${TAG}" --project "$PROJECT" >&2; do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -ge 6 ]; then
    echo "ERROR: build failed after $ATTEMPT attempts." >&2; exit 1
  fi
  echo "== build failed (likely IAM propagation); retry $ATTEMPT in 20s ==" >&2
  sleep 20
done

DIGEST_REF="$(gcloud artifacts docker images describe "${IMAGE_PATH}:${TAG}" \
  --project "$PROJECT" \
  --format='value(image_summary.fullyQualifiedDigest)')"

echo >&2
echo "== done. Set this in your tfvars: ==" >&2
echo "exporter_image = \"${DIGEST_REF}\"" >&2
echo >&2
# Print the bare digest ref to stdout so callers can capture it:
#   export TF_VAR_exporter_image="$(scripts/build_image.sh)"
echo "$DIGEST_REF"
