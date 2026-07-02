"""Cloud Run job: pull Langfuse traces, DLP-mask PII inline, write masked JSONL.

Runs to completion on a Cloud Scheduler cron. For each configured project it
streams full TraceWithFullDetails records from the Langfuse public API since a
persisted watermark (oldest-first), DLP-masks input/output/metadata/tags/
statusMessage while keeping the whole trace intact (see deidentify_core), and
writes them as JSONL to the masked bucket in bounded chunks — advancing the
watermark after EACH chunk. The
masked bucket is the only resource shared with Kota; raw PII never lands in
storage.

Streaming + per-chunk checkpoint keeps memory flat regardless of backlog size
and makes progress durable: a run that is OOM-killed, times out, or fails
mid-stream leaves every already-written chunk committed and its watermark
advanced, so the next run resumes where it stopped (graceful catch-up). An
optional per-run cap bounds each invocation under the Cloud Run job timeout.

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

from deidentify_core import DEFAULT_DLP_TIMEOUT, DEFAULT_MAX_RPM, DlpMasker, RateLimiter
from google.api_core import client_options as co
from google.cloud import dlp_v2, storage
from langfuse_api import LangfuseAPIClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("exporter")

DEFAULT_MASKED_PREFIX = "exports/"
WATERMARK_KEY = "last_timestamp_seconds"
SECONDS_PER_DAY = 86400
# Records masked + written + checkpointed per chunk. Caps peak memory.
DEFAULT_CHUNK_SIZE = 200
# Per-run record cap (0 = unlimited). Bounds a run under the job timeout; the
# watermark resumes the remainder next run.
DEFAULT_MAX_RECORDS_PER_RUN = 0


def _env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"missing required env var: {name}")
    return value


def _project_env_slug(name):
    """Env-var suffix for a project. Must mirror the Terraform expression
    upper(replace(name, "-", "_")) used to name the LF_PUB_/LF_SEC_ env vars."""
    return name.upper().replace("-", "_")


def _watermark_object(name):
    return f"watermark-{name}.json"


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


async def _stream_export(proj, masker, storage_client, masked_bucket, masked_prefix,
                         state_bucket, watermark, chunk_size, max_records):
    """Stream a project's traces oldest-first, masking + writing + checkpointing
    one bounded chunk at a time. Returns the number of records written.

    The watermark is advanced to a chunk's max timestamp only AFTER that chunk's
    masked object is durably written — so an interruption never loses committed
    data and never double-advances past unprocessed traces (ascending order
    guarantees every trace at/below the checkpoint has been handled)."""
    name = proj["name"]
    host = proj["host"]
    slug = _project_env_slug(name)
    public_key = _env(f"LF_PUB_{slug}", required=True)
    secret_key = _env(f"LF_SEC_{slug}", required=True)
    # Optional proxy headers (JSON object from Secret Manager), e.g. Cloudflare
    # Access service-token credentials. Absent for most projects.
    extra_headers = json.loads(_env(f"LF_HDR_{slug}", "{}"))
    state_object = _watermark_object(name)

    run_ts = int(time.time())
    seq = 0
    written = 0
    chunk = []
    max_seen = watermark

    def flush():
        nonlocal seq, written, chunk
        if not chunk:
            return
        lines = [json.dumps(masker.mask_record(r), ensure_ascii=False) for r in chunk]
        object_name = f"{masked_prefix}{name}/{run_ts}-{seq:05d}.jsonl"
        body = "\n".join(lines) + "\n"
        storage_client.bucket(masked_bucket).blob(object_name).upload_from_string(
            body, content_type="application/x-ndjson"
        )
        # Checkpoint AFTER the write lands.
        _write_watermark(storage_client, state_bucket, state_object, max_seen)
        logger.info(
            "[%s] wrote %d record(s) to gs://%s/%s; watermark=%s",
            name, len(chunk), masked_bucket, object_name, max_seen,
        )
        seq += 1
        written += len(chunk)
        chunk = []

    async with LangfuseAPIClient(
        host, public_key, secret_key, extra_headers=extra_headers
    ) as client:
        async for summary in client.iter_trace_summaries_since(watermark):
            record = await client.get_trace_details(summary["id"])
            seconds = _trace_epoch_seconds(record)
            if seconds is not None:
                max_seen = max(max_seen, seconds)
            chunk.append(record)
            if len(chunk) >= chunk_size:
                flush()
            if max_records and (written + len(chunk)) >= max_records:
                flush()
                logger.info(
                    "[%s] hit per-run cap of %d; remainder resumes next run",
                    name, max_records,
                )
                return written
        flush()
    return written


def _export_project(proj, storage_client, masker, masked_bucket, masked_prefix,
                    state_bucket, initial_lookback_days, chunk_size, max_records):
    """Export one Langfuse project. Raises on failure so the caller can fail
    closed for this project alone; chunks committed before a failure stay."""
    name = proj["name"]
    state_object = _watermark_object(name)
    watermark = _read_watermark(
        storage_client, state_bucket, state_object, initial_lookback_days
    )
    logger.info("[%s] starting export since watermark=%s", name, watermark)

    written = asyncio.run(
        _stream_export(
            proj, masker, storage_client, masked_bucket, masked_prefix,
            state_bucket, watermark, chunk_size, max_records,
        )
    )
    if written == 0:
        logger.info("[%s] no new traces; watermark unchanged", name)
    else:
        logger.info("[%s] export complete: %d record(s) written", name, written)


def main():
    masked_bucket = _env("MASKED_BUCKET", required=True)
    state_bucket = _env("STATE_BUCKET", required=True)
    masked_prefix = _env("MASKED_PREFIX", DEFAULT_MASKED_PREFIX)
    dlp_parent = _env("DLP_PARENT", required=True)
    inspect_template = _env("DLP_INSPECT_TEMPLATE", required=True)
    deidentify_template = _env("DLP_DEIDENTIFY_TEMPLATE", required=True)
    dlp_project = _env("DLP_PROJECT")
    initial_lookback_days = int(_env("INITIAL_LOOKBACK_DAYS", "1"))
    dlp_max_rpm = int(_env("DLP_MAX_RPM", str(DEFAULT_MAX_RPM)))
    dlp_timeout = int(_env("DLP_TIMEOUT", str(DEFAULT_DLP_TIMEOUT)))
    chunk_size = int(_env("EXPORT_CHUNK_SIZE", str(DEFAULT_CHUNK_SIZE)))
    max_records = int(_env("MAX_RECORDS_PER_RUN", str(DEFAULT_MAX_RECORDS_PER_RUN)))

    projects = json.loads(_env("LANGFUSE_PROJECTS", required=True))
    if not isinstance(projects, list) or not projects:
        raise RuntimeError("LANGFUSE_PROJECTS must be a non-empty JSON list")

    storage_client = storage.Client()

    # One DLP client + masker + rate limiter shared across all projects: the DLP
    # quota is per-GCP-project-per-region, so a single client-side limiter keeps
    # the whole run under quota (independent limiters would collectively exceed).
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
        timeout=dlp_timeout,
    )

    failures = 0
    for proj in projects:
        name = proj.get("name", "<unknown>")
        try:
            _export_project(
                proj, storage_client, masker, masked_bucket, masked_prefix,
                state_bucket, initial_lookback_days, chunk_size, max_records,
            )
        except Exception:
            # Fail closed for this project only: its watermark is untouched, so
            # the window is retried next run. Other projects still proceed.
            failures += 1
            logger.exception(
                "[%s] export failed; watermark unchanged, continuing", name
            )

    if failures:
        raise SystemExit(f"{failures} of {len(projects)} project(s) failed")


if __name__ == "__main__":
    main()
