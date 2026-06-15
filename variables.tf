variable "project_id" {
  type        = string
  description = "Your GCP project ID. All resources are created here, inside your trust boundary."
}

variable "region" {
  type        = string
  description = "Region for buckets, the exporter job, and DLP templates (e.g. europe-west1, us-central1). DLP templates are regional — keep this aligned with your data-residency requirements."
  default     = "us-central1"
}

variable "kota_sa_email" {
  type        = string
  description = "Kota's GCP service account email (provided by Kota). Granted token-creator on the dedicated reader SA so Kota can impersonate it (keyless) to read the masked bucket. Must be a GCP service account, not a user account."
}

variable "exporter_image" {
  type        = string
  description = "Exporter image pinned by immutable digest (REGION-docker.pkg.dev/PROJECT/REPO/exporter@sha256:...). Build it first with scripts/build_image.sh, which prints this value. Terraform does not build the image."

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.exporter_image))
    error_message = "exporter_image must be pinned by digest (end with @sha256:<64 hex chars>), not a mutable tag. Run scripts/build_image.sh to get it."
  }
}

variable "name_prefix" {
  type        = string
  description = "Prefix for all resource names."
  default     = "kota-pii"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "name_prefix must be lowercase alphanumeric/hyphen, start with a letter, max 21 chars."
  }
}

variable "langfuse_host" {
  type        = string
  description = "Langfuse API base URL (e.g. https://us.cloud.langfuse.com, https://cloud.langfuse.com, or your self-hosted host)."
  default     = "https://us.cloud.langfuse.com"
}

variable "langfuse_public_key" {
  type        = string
  description = "Langfuse public API key (pk-lf-...). Stored in Secret Manager and injected into the exporter job."
  sensitive   = true
}

variable "langfuse_secret_key" {
  type        = string
  description = "Langfuse secret API key (sk-lf-...). Stored in Secret Manager and injected into the exporter job."
  sensitive   = true
}

variable "schedule_cron" {
  type        = string
  description = "Cron schedule (Cloud Scheduler syntax, UTC) for the exporter job. Default: hourly."
  default     = "0 * * * *"
}

variable "initial_lookback_days" {
  type        = number
  description = "On the first run (no watermark yet), pull traces from this many days back."
  default     = 1

  validation {
    condition     = var.initial_lookback_days >= 1 && var.initial_lookback_days <= 90
    error_message = "initial_lookback_days must be between 1 and 90."
  }
}

variable "scheduler_paused" {
  type        = bool
  description = "Create the Cloud Scheduler trigger in a paused state (run the job manually instead)."
  default     = false
}

variable "dlp_info_types" {
  type        = list(string)
  description = "Cloud DLP infoTypes to detect and replace. Defaults cover common global PII. Extend from your own console anytime — no Kota redeploy needed."
  default = [
    "PERSON_NAME",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "STREET_ADDRESS",
    "CREDIT_CARD_NUMBER",
    "IBAN_CODE",
    "US_SOCIAL_SECURITY_NUMBER",
    "IP_ADDRESS",
  ]
}

variable "dlp_min_likelihood" {
  type        = string
  description = "Minimum DLP match likelihood to act on (POSSIBLE, LIKELY, VERY_LIKELY)."
  default     = "LIKELY"
}

variable "labels" {
  type        = map(string)
  description = "Labels applied to created resources."
  default = {
    managed-by = "terraform"
    component  = "kota-pii-masking"
  }
}
