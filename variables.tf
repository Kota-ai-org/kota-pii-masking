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

variable "langfuse_projects" {
  description = <<-EOT
    Langfuse projects to export. Each project gets its own Secret Manager key
    pair, its own watermark, and its own output subdir (exports/<name>/) in the
    single shared masked bucket. Kota reads the one bucket and separates traces
    by prefix.

    Each `name` is a slug used in resource names, the output prefix, and the
    env-var the exporter reads — keep it short, lowercase, hyphenated.
    `host` is per-project and optional (defaults to Langfuse US cloud); set it to
    https://cloud.langfuse.com for EU or to your self-hosted base URL.

    `extra_headers` (optional) is sent verbatim on every request to that
    project's host — use it when the host sits behind a proxy that requires
    its own credentials, e.g. Cloudflare Access service tokens:
      extra_headers = {
        "CF-Access-Client-Id"     = "<id>.access"
        "CF-Access-Client-Secret" = "<secret>"
      }
    Header values are stored in Secret Manager (never in the image, manifest,
    or shell history) and injected into the job at runtime, like the API keys.
  EOT
  type = list(object({
    name          = string
    public_key    = string
    secret_key    = string
    host          = optional(string, "https://us.cloud.langfuse.com")
    extra_headers = optional(map(string), {})
  }))
  sensitive = true

  validation {
    condition     = length(var.langfuse_projects) > 0
    error_message = "langfuse_projects must contain at least one project."
  }
  validation {
    condition     = alltrue([for p in var.langfuse_projects : can(regex("^[a-z0-9][a-z0-9-]*$", p.name))])
    error_message = "Each project name must match ^[a-z0-9][a-z0-9-]*$ (lowercase alphanumeric and hyphens, starting alphanumeric)."
  }
  validation {
    condition     = alltrue([for p in var.langfuse_projects : length(p.name) <= 30])
    error_message = "Each project name must be at most 30 characters (keeps Secret Manager secret ids within limits)."
  }
  validation {
    condition     = length(distinct([for p in var.langfuse_projects : p.name])) == length(var.langfuse_projects)
    error_message = "Project names must be unique."
  }
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

variable "dlp_max_rpm" {
  type        = number
  description = "Client-side ceiling on DLP requests per minute. The exporter self-throttles below this and backs off on quota errors, keeping runs under your project's DLP quota (600/min per region by default). Lower it if you share the DLP quota with other workloads; raise it only after raising the quota."
  default     = 500

  validation {
    condition     = var.dlp_max_rpm >= 1 && var.dlp_max_rpm <= 10000
    error_message = "dlp_max_rpm must be between 1 and 10000."
  }
}

variable "export_chunk_size" {
  type        = number
  description = "Records masked, written, and checkpointed per chunk. The job writes one masked object and advances the watermark per chunk, so this caps peak memory regardless of backlog size."
  default     = 200
}

variable "max_records_per_run" {
  type        = number
  description = "Per-run cap on records processed per project (0 = unlimited). Bounds each invocation under the Cloud Run job timeout; the watermark resumes the remainder on the next run. Set this for very large backlogs."
  default     = 0
}

variable "dlp_timeout_seconds" {
  type        = number
  description = "Per-call deadline (seconds) for Cloud DLP requests. A slow/stuck call raises DeadlineExceeded and is retried+checkpointed instead of hanging the run."
  default     = 120
}

variable "exporter_cpu" {
  type        = string
  description = "CPU for the exporter Cloud Run job container (e.g. \"1\", \"2\")."
  default     = "1"
}

variable "exporter_memory" {
  type        = string
  description = "Memory for the exporter Cloud Run job container. The job holds a run's pulled traces in memory before writing; large/busy projects need more. Raise (e.g. \"2Gi\", \"4Gi\") if runs are OOM-killed. Must respect Cloud Run's CPU/memory ratios (cpu \"1\" allows up to 4Gi)."
  default     = "1Gi"
}

variable "labels" {
  type        = map(string)
  description = <<-EOT
    Labels applied to every labelable resource (buckets, secrets, the Cloud Run job).
    Put deploy-time / custom billing-grouping labels here, e.g. {cost-center="acme", team="ml"}
    — deploy.sh injects these from LABELS="key=value,...". The module also sets reserved
    labels component=kota-pii-masking and deployment=<name_prefix>, which always win over
    any same-named entry here (see local.common_labels). NOTE: DLP templates, Cloud Scheduler,
    and service accounts cannot carry labels (no provider support).
  EOT
  default = {
    managed-by = "terraform"
  }
}
