data "google_project" "this" {
  project_id = var.project_id
}

locals {
  masked_bucket_name = "${var.name_prefix}-masked-${data.google_project.this.number}"
  state_bucket_name  = "${var.name_prefix}-state-${data.google_project.this.number}"
  dlp_parent         = "projects/${var.project_id}/locations/${var.region}"

  # Canonical billing-grouping labels. merge() places these last so they ALWAYS win
  # over var.labels — a customer customizing/injecting labels can't drop the billing
  # dimension. Filter Cloud Billing on label.component=kota-pii-masking.
  billing_labels = {
    component  = "kota-pii-masking" # canonical billing filter key
    deployment = var.name_prefix    # distinguishes multiple deployments in one project
  }
  common_labels = merge(var.labels, local.billing_labels)

  # Slug-keyed map for looking up each project's (sensitive) keys.
  langfuse_projects = { for p in var.langfuse_projects : p.name => p }

  # Project names are NOT secret; use this non-sensitive set for for_each
  # (Terraform forbids sensitive values as for_each keys).
  langfuse_project_names = nonsensitive(toset([for p in var.langfuse_projects : p.name]))

  # Non-secret manifest the exporter loops over. Secrets are injected separately
  # via per-project LF_PUB_<SLUG>/LF_SEC_<SLUG> env vars (secret_key_ref).
  langfuse_manifest = nonsensitive(jsonencode([
    for p in var.langfuse_projects : { name = p.name, host = p.host }
  ]))
}

###############################################################################
# APIs
###############################################################################

resource "google_project_service" "required" {
  for_each = toset([
    "dlp.googleapis.com",
    "run.googleapis.com",
    "storage.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "iam.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

###############################################################################
# Buckets
###############################################################################

# The ONLY resource shared with Kota: masked, de-identified traces (read-only).
resource "google_storage_bucket" "masked" {
  name                        = local.masked_bucket_name
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false
  labels                      = local.common_labels

  depends_on = [google_project_service.required]
}

# Private state bucket for the exporter watermark. Never shared with Kota.
resource "google_storage_bucket" "state" {
  name                        = local.state_bucket_name
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  labels                      = local.common_labels

  depends_on = [google_project_service.required]
}

# Dedicated, customer-owned identity representing "Kota's read access". Its only
# power is read-only on the masked bucket; Kota never touches the bucket IAM
# directly. Revoke all Kota access by disabling/deleting this SA.
resource "google_service_account" "reader" {
  account_id   = "${var.name_prefix}-reader"
  display_name = "Kota masked-bucket reader"
  project      = var.project_id

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket_iam_member" "reader_masked" {
  bucket = google_storage_bucket.masked.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.reader.email}"
}

# Kota's own GCP identity is allowed to mint short-lived tokens AS the reader SA
# (keyless impersonation). No long-lived key exists anywhere. Revoke Kota's
# ability to impersonate by removing this binding.
resource "google_service_account_iam_member" "kota_impersonate_reader" {
  service_account_id = google_service_account.reader.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${var.kota_sa_email}"
}

###############################################################################
# Cloud DLP templates (owned by you; extend from your console anytime)
###############################################################################

resource "google_data_loss_prevention_inspect_template" "this" {
  parent       = local.dlp_parent
  display_name = "${var.name_prefix}-inspect"
  description  = "InfoTypes detected before traces are shared with Kota."

  inspect_config {
    min_likelihood = var.dlp_min_likelihood

    dynamic "info_types" {
      for_each = var.dlp_info_types
      content {
        name = info_types.value
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_data_loss_prevention_deidentify_template" "this" {
  parent       = local.dlp_parent
  display_name = "${var.name_prefix}-deidentify"
  description  = "Replaces detected PII with [INFO_TYPE] placeholders, preserving structure."

  deidentify_config {
    info_type_transformations {
      transformations {
        dynamic "info_types" {
          for_each = var.dlp_info_types
          content {
            name = info_types.value
          }
        }
        primitive_transformation {
          replace_with_info_type_config = true
        }
      }
    }
  }

  depends_on = [google_project_service.required]
}

###############################################################################
# Langfuse API credentials (Secret Manager)
###############################################################################

resource "google_secret_manager_secret" "langfuse_public_key" {
  for_each  = local.langfuse_project_names
  secret_id = "${var.name_prefix}-langfuse-public-key-${each.key}"
  project   = var.project_id
  labels    = local.common_labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "langfuse_public_key" {
  for_each    = local.langfuse_project_names
  secret      = google_secret_manager_secret.langfuse_public_key[each.key].id
  secret_data = local.langfuse_projects[each.key].public_key
}

resource "google_secret_manager_secret" "langfuse_secret_key" {
  for_each  = local.langfuse_project_names
  secret_id = "${var.name_prefix}-langfuse-secret-key-${each.key}"
  project   = var.project_id
  labels    = local.common_labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "langfuse_secret_key" {
  for_each    = local.langfuse_project_names
  secret      = google_secret_manager_secret.langfuse_secret_key[each.key].id
  secret_data = local.langfuse_projects[each.key].secret_key
}

###############################################################################
# Exporter Cloud Run job (pulls Langfuse traces, DLP-masks, writes masked JSONL)
#
# The image is built out-of-band in your project (scripts/build_image.sh, which
# creates the Artifact Registry repo and pushes the image) and pinned here by
# immutable digest via var.exporter_image. Terraform never builds.
###############################################################################

resource "google_service_account" "exporter" {
  account_id   = "${var.name_prefix}-exporter"
  display_name = "Kota PII-masking trace exporter"
  project      = var.project_id
}

resource "google_project_iam_member" "exporter_dlp_user" {
  project = var.project_id
  role    = "roles/dlp.user"
  member  = "serviceAccount:${google_service_account.exporter.email}"
}

# dlp.user can run content methods but not read the inspect/deidentify templates;
# dlp.reader grants the templates.get the job needs.
resource "google_project_iam_member" "exporter_dlp_reader" {
  project = var.project_id
  role    = "roles/dlp.reader"
  member  = "serviceAccount:${google_service_account.exporter.email}"
}

resource "google_storage_bucket_iam_member" "exporter_masked_writer" {
  bucket = google_storage_bucket.masked.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.exporter.email}"
}

resource "google_storage_bucket_iam_member" "exporter_state_writer" {
  bucket = google_storage_bucket.state.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.exporter.email}"
}

resource "google_secret_manager_secret_iam_member" "exporter_public_key" {
  for_each  = local.langfuse_project_names
  secret_id = google_secret_manager_secret.langfuse_public_key[each.key].secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.exporter.email}"
}

resource "google_secret_manager_secret_iam_member" "exporter_secret_key" {
  for_each  = local.langfuse_project_names
  secret_id = google_secret_manager_secret.langfuse_secret_key[each.key].secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.exporter.email}"
}

resource "google_cloud_run_v2_job" "exporter" {
  name                = "${var.name_prefix}-exporter"
  project             = var.project_id
  location            = var.region
  deletion_protection = false
  labels              = local.common_labels

  template {
    template {
      service_account = google_service_account.exporter.email
      max_retries     = 1
      timeout         = "3600s"

      containers {
        image = var.exporter_image

        env {
          name  = "MASKED_BUCKET"
          value = google_storage_bucket.masked.name
        }
        env {
          name  = "STATE_BUCKET"
          value = google_storage_bucket.state.name
        }
        env {
          name  = "MASKED_PREFIX"
          value = "exports/"
        }
        env {
          name  = "DLP_PARENT"
          value = local.dlp_parent
        }
        env {
          name  = "DLP_PROJECT"
          value = var.project_id
        }
        env {
          name  = "DLP_INSPECT_TEMPLATE"
          value = google_data_loss_prevention_inspect_template.this.id
        }
        env {
          name  = "DLP_DEIDENTIFY_TEMPLATE"
          value = google_data_loss_prevention_deidentify_template.this.id
        }
        env {
          name  = "DLP_MAX_RPM"
          value = tostring(var.dlp_max_rpm)
        }
        env {
          name  = "DLP_TIMEOUT"
          value = tostring(var.dlp_timeout_seconds)
        }
        env {
          name  = "EXPORT_CHUNK_SIZE"
          value = tostring(var.export_chunk_size)
        }
        env {
          name  = "MAX_RECORDS_PER_RUN"
          value = tostring(var.max_records_per_run)
        }
        env {
          name  = "INITIAL_LOOKBACK_DAYS"
          value = tostring(var.initial_lookback_days)
        }

        # Non-secret per-project manifest: [{name, host}, ...]. The exporter
        # loops over this and reads each project's keys from LF_PUB_<SLUG> /
        # LF_SEC_<SLUG>, where SLUG = upper(replace(name, "-", "_")).
        env {
          name  = "LANGFUSE_PROJECTS"
          value = local.langfuse_manifest
        }

        # Per-project Langfuse keys, injected from Secret Manager at runtime.
        dynamic "env" {
          for_each = local.langfuse_project_names
          content {
            name = "LF_PUB_${upper(replace(env.key, "-", "_"))}"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.langfuse_public_key[env.key].secret_id
                version = "latest"
              }
            }
          }
        }
        dynamic "env" {
          for_each = local.langfuse_project_names
          content {
            name = "LF_SEC_${upper(replace(env.key, "-", "_"))}"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.langfuse_secret_key[env.key].secret_id
                version = "latest"
              }
            }
          }
        }

        resources {
          limits = {
            cpu    = var.exporter_cpu
            memory = var.exporter_memory
          }
        }
      }
    }
  }

  depends_on = [
    google_project_iam_member.exporter_dlp_user,
    google_project_iam_member.exporter_dlp_reader,
    google_storage_bucket_iam_member.exporter_masked_writer,
    google_storage_bucket_iam_member.exporter_state_writer,
    google_secret_manager_secret_iam_member.exporter_public_key,
    google_secret_manager_secret_iam_member.exporter_secret_key,
    google_secret_manager_secret_version.langfuse_public_key,
    google_secret_manager_secret_version.langfuse_secret_key,
  ]
}

###############################################################################
# Cloud Scheduler cron (triggers the job via the Run Admin API)
###############################################################################

resource "google_service_account" "scheduler" {
  account_id   = "${var.name_prefix}-scheduler"
  display_name = "Kota PII-masking exporter scheduler"
  project      = var.project_id
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_invoker" {
  name     = google_cloud_run_v2_job.exporter.name
  location = var.region
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "exporter" {
  name     = "${var.name_prefix}-exporter-trigger"
  project  = var.project_id
  region   = var.region
  schedule = var.schedule_cron
  paused   = var.scheduler_paused

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.exporter.name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [
    google_project_service.required,
    google_cloud_run_v2_job_iam_member.scheduler_invoker,
  ]
}
