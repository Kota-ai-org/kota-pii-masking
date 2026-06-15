"""Cloud Run job: pull Langfuse traces, DLP-mask PII inline, write masked JSONL.

Runs to completion on a Cloud Scheduler cron. Pulls full TraceWithFullDetails
records from the Langfuse public API since a persisted watermark, de-identifies
the transcript fields via Cloud DLP (see deidentify_core), writes the masked
records as JSONL to the masked bucket, then advances the watermark. The masked
bucket is the only resource shared with Kota; raw PII never lands in storage.

Identity comes from ADC (the job's runtime service account). Langfuse keys are
injected as env vars from Secret Manager by Cloud Run. Trace content is never
logged — only counts and object names.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

from deidentify_core import DEFAULT_MAX_RPM, DlpMasker, RateLimiter
from google.api_core import client_options as co
from google.cloud import dlp_v2, storage
from langfuse_api import LangfuseAPIClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("exporter")

DEFAULT_STATE_OBJECT = "watermark.json"
DEFAULT_MASKED_PREFIX = "exports/"
WATERMARK_KEY = "last_timestamp_seconds"
SECONDS_PER_DAY = 86400


def _env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"missing required env var: {name}")
    return value


def _read_watermark(storage_client, state_bucket, state_object, initial_lookback_days):
    blob = storage_client.bucket(state_bucket).blob(state_object)
    if blob.exists():
        data = json.loads(blob.download_as_text())
        return int(data[WATERMARK_KEY])
    return int(time.time()) - initial_lookback_days * SECONDS_PER_DAY


def _write_watermark(storage_client, state_bucket, state_object, watermark):
    blob = storage_client.bucket(state_bucket).blob(state_object)
    blob.upload_from_string(
        json.dumps({WATERMARK_KEY: watermark}), content_type="application/json"
    )


def _trace_epoch_seconds(record):
    raw = record.get("timestamp")
    if not raw:
        return None
    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


async def _pull(host, public_key, secret_key, since_seconds):
    records = []
    async with LangfuseAPIClient(host, public_key, secret_key) as client:
        async for summary in client.iter_trace_summaries_since(since_seconds):
            records.append(await client.get_trace_details(summary["id"]))
    return records


def main():
    host = _env("LANGFUSE_HOST", required=True)
    public_key = _env("LANGFUSE_PUBLIC_KEY", required=True)
    secret_key = _env("LANGFUSE_SECRET_KEY", required=True)
    masked_bucket = _env("MASKED_BUCKET", required=True)
    state_bucket = _env("STATE_BUCKET", required=True)
    masked_prefix = _env("MASKED_PREFIX", DEFAULT_MASKED_PREFIX)
    state_object = _env("STATE_OBJECT", DEFAULT_STATE_OBJECT)
    dlp_parent = _env("DLP_PARENT", required=True)
    inspect_template = _env("DLP_INSPECT_TEMPLATE", required=True)
    deidentify_template = _env("DLP_DEIDENTIFY_TEMPLATE", required=True)
    dlp_project = _env("DLP_PROJECT")
    initial_lookback_days = int(_env("INITIAL_LOOKBACK_DAYS", "1"))
    dlp_max_rpm = int(_env("DLP_MAX_RPM", str(DEFAULT_MAX_RPM)))

    storage_client = storage.Client()
    watermark = _read_watermark(
        storage_client, state_bucket, state_object, initial_lookback_days
    )
    logger.info("starting export since watermark=%s", watermark)

    records = asyncio.run(_pull(host, public_key, secret_key, watermark))
    logger.info("pulled %d trace(s) from Langfuse", len(records))
    if not records:
        logger.info("no new traces; watermark unchanged")
        return

    dlp_options = (
        co.ClientOptions(quota_project_id=dlp_project) if dlp_project else None
    )
    dlp_client = dlp_v2.DlpServiceClient(client_options=dlp_options)
    masker = DlpMasker(
        dlp_client,
        dlp_parent,
        inspect_template,
        deidentify_template,
        RateLimiter(dlp_max_rpm),
    )

    masked_lines = []
    max_seen = watermark
    for record in records:
        seconds = _trace_epoch_seconds(record)
        if seconds is not None:
            max_seen = max(max_seen, seconds)
        masked = masker.mask_record(record)
        masked_lines.append(json.dumps(masked, ensure_ascii=False))

    object_name = f"{masked_prefix}{int(time.time())}.jsonl"
    body = "\n".join(masked_lines) + "\n"
    storage_client.bucket(masked_bucket).blob(object_name).upload_from_string(
        body, content_type="application/x-ndjson"
    )
    logger.info(
        "wrote %d masked record(s) to gs://%s/%s",
        len(masked_lines),
        masked_bucket,
        object_name,
    )

    _write_watermark(storage_client, state_bucket, state_object, max_seen)
    logger.info("advanced watermark to %s", max_seen)


if __name__ == "__main__":
    main()
