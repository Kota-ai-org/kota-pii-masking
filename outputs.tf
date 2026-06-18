output "masked_bucket_url" {
  description = "Masked, Kota-readable bucket. Share this with Kota."
  value       = "gs://${google_storage_bucket.masked.name}"
}

output "masked_bucket_name" {
  description = "Masked bucket name (without gs:// prefix)."
  value       = google_storage_bucket.masked.name
}

output "reader_sa_email" {
  description = "Service account Kota impersonates (keyless) to read the masked bucket. Share this with Kota along with the masked bucket name."
  value       = google_service_account.reader.email
}

output "langfuse_project_names" {
  description = "Configured Langfuse project subdir names. Masked traces land at gs://<masked_bucket>/exports/<name>/<ts>.jsonl."
  value       = nonsensitive([for p in var.langfuse_projects : p.name])
}

output "masked_prefixes" {
  description = "Per-project object prefixes Kota reads under the masked bucket."
  value       = nonsensitive({ for p in var.langfuse_projects : p.name => "exports/${p.name}/" })
}

output "state_bucket_name" {
  description = "Private bucket holding the exporter watermark. Not shared with Kota."
  value       = google_storage_bucket.state.name
}

output "exporter_job_name" {
  description = "Cloud Run job that pulls + masks traces. Run on demand with `gcloud run jobs execute`."
  value       = google_cloud_run_v2_job.exporter.name
}

output "exporter_sa_email" {
  description = "Runtime service account for the exporter job."
  value       = google_service_account.exporter.email
}

output "scheduler_job_name" {
  description = "Cloud Scheduler cron that triggers the exporter job."
  value       = google_cloud_scheduler_job.exporter.name
}

output "dlp_inspect_template_id" {
  value = google_data_loss_prevention_inspect_template.this.id
}

output "dlp_deidentify_template_id" {
  value = google_data_loss_prevention_deidentify_template.this.id
}

output "billing_labels" {
  description = "Canonical labels applied to all labelable resources. Use as the Cloud Billing filter, e.g. label.component=kota-pii-masking."
  value       = local.billing_labels
}
