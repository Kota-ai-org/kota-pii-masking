"""Core de-identify logic, shared by the Cloud Run job and the e2e check.

Strategy: targeted masking + projection. Per trace record we
  1. DLP-mask only the free-text transcript fields — trace `input`/`output` and
     each observation `input`/`output` — by serializing each field to text,
     de-identifying it, and parsing it back (replace_with_info_type keeps it
     valid JSON);
  2. project the record down to the fields Kota's parser consumes, DROPPING the
     non-transcript PII carriers entirely (`userId`, `tags`, raw `metadata`
     except `agent_name`, usage/cost/model on observations).

Rate-limit hardening: the job runs in the customer's project, where we cannot
raise the Cloud DLP quota (600 requests/min per region). So `DlpMasker`
  - **batches** every maskable field of a record into ONE DLP table request
    (instead of one request per field), cutting call volume ~10-20x;
  - **rate-limits** every request to stay under the quota (`RateLimiter`);
  - **backs off** on `RESOURCE_EXHAUSTED`/transient errors and retries, so a
    throttled run paces itself and completes rather than failing closed.

Pure DLP logic, no storage deps, so it is directly testable.
"""

import json
import time

from google.api_core.exceptions import (
    DeadlineExceeded,
    ResourceExhausted,
    ServiceUnavailable,
)
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

DEFAULT_MAX_BATCH_BYTES = 200_000
# A serialized field at/above this is chunked leaf-by-leaf instead of whole.
FIELD_SIZE_LIMIT = 450_000
# Max rows per DLP table request (DLP allows 50,000 values; stay well under).
MAX_TABLE_ROWS = 2000
# Default client-side ceiling, below the 600/min-per-region DLP quota.
DEFAULT_MAX_RPM = 500
# Per-call DLP RPC deadline (seconds). Bounds a slow/stuck deidentify so it
# raises DeadlineExceeded and is retried, instead of hanging the run silently.
DEFAULT_DLP_TIMEOUT = 120

# Trace-level fields whose values are masked (their full subtree).
TRACE_TEXT_FIELDS = ("input", "output")
# Observation-level fields that are masked.
OBSERVATION_TEXT_FIELDS = ("input", "output")
# Observation fields kept after projection (masked io + non-PII structure).
OBSERVATION_KEEP_FIELDS = (
    "input",
    "output",
    "startTime",
    "endTime",
    "type",
    "name",
)
# Trace fields dropped by projection — non-transcript PII carriers / bloat.
TRACE_DROP_FIELDS = (
    "userId",
    "tags",
    "release",
    "version",
    "public",
    "bookmarked",
    "scores",
    "totalCost",
    "htmlPath",
    "externalId",
)
# Metadata keys preserved (everything else in metadata is dropped).
METADATA_KEEP_KEYS = ("agent_name",)


def _string_leaves(node, refs):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                refs.append((node, k))
            else:
                _string_leaves(v, refs)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                refs.append((node, i))
            else:
                _string_leaves(v, refs)


class RateLimiter:
    """Min-interval throttle. Serial (single-threaded) callers only."""

    def __init__(self, max_rpm):
        self._interval = 60.0 / max_rpm if max_rpm > 0 else 0.0
        self._next_allowed = time.monotonic()

    def acquire(self):
        if self._interval <= 0:
            return
        now = time.monotonic()
        if now < self._next_allowed:
            time.sleep(self._next_allowed - now)
            now = time.monotonic()
        self._next_allowed = now + self._interval


class DlpMasker:
    """De-identifies trace records via Cloud DLP, batched and rate-limited.

    Owns the DLP client, the parent/template names, and a `RateLimiter`. Every
    `deidentify_content` request (batched table calls and oversized-field
    leaf-by-leaf fallbacks alike) is paced by the limiter and retried with
    exponential backoff on transient/quota errors.
    """

    def __init__(
        self,
        client,
        parent,
        inspect_template,
        deidentify_template,
        rate_limiter,
        max_bytes=DEFAULT_MAX_BATCH_BYTES,
        timeout=DEFAULT_DLP_TIMEOUT,
    ):
        self.client = client
        self.parent = parent
        self.inspect_template = inspect_template
        self.deidentify_template = deidentify_template
        self.rate_limiter = rate_limiter
        self.max_bytes = max_bytes
        self.timeout = timeout

    @retry(
        stop=stop_after_attempt(6),
        wait=wait_exponential(multiplier=1, min=2, max=60),
        retry=retry_if_exception_type(
            (ResourceExhausted, ServiceUnavailable, DeadlineExceeded)
        ),
        reraise=True,
    )
    def _deidentify(self, item):
        return self.client.deidentify_content(
            request={
                "parent": self.parent,
                "inspect_template_name": self.inspect_template,
                "deidentify_template_name": self.deidentify_template,
                "item": item,
            },
            timeout=self.timeout,
        )

    def _call(self, item):
        self.rate_limiter.acquire()
        return self._deidentify(item)

    def _deidentify_text(self, text):
        if not text.strip():
            return text
        return self._call({"value": text}).item.value

    def _mask_by_leaves(self, value):
        """Fallback for oversized fields: mask each string leaf individually."""
        refs = []
        _string_leaves(value, refs)
        for container, key in refs:
            leaf = container[key]
            if leaf.strip():
                container[key] = self._deidentify_text(leaf)
        return value

    def _collect_field(self, container, key, slots):
        """Queue a field for batched masking, or mask oversized fields inline."""
        value = container.get(key)
        if value is None:
            return
        text = json.dumps(value, ensure_ascii=False)
        if len(text.encode("utf-8")) >= FIELD_SIZE_LIMIT:
            container[key] = self._mask_by_leaves(value)
            return
        slots.append((container, key, value, text))

    def _mask_slots(self, slots):
        """Mask queued fields in table batches bounded by row count and bytes."""
        index = 0
        while index < len(slots):
            chunk = []
            chunk_bytes = 0
            while index < len(slots) and len(chunk) < MAX_TABLE_ROWS:
                text = slots[index][3]
                text_bytes = len(text.encode("utf-8"))
                if chunk and chunk_bytes + text_bytes > self.max_bytes:
                    break
                chunk.append(slots[index])
                chunk_bytes += text_bytes
                index += 1
            self._mask_chunk(chunk)

    def _mask_chunk(self, chunk):
        rows = [{"values": [{"string_value": text}]} for (_, _, _, text) in chunk]
        item = {"table": {"headers": [{"name": "v"}], "rows": rows}}
        masked_rows = self._call(item).item.table.rows
        for (container, key, value, _text), masked_row in zip(chunk, masked_rows):
            masked_text = masked_row.values[0].string_value
            try:
                container[key] = json.loads(masked_text)
            except json.JSONDecodeError:
                container[key] = self._mask_by_leaves(value)

    def mask_record(self, record):
        """Mask transcript fields and project away non-transcript PII carriers."""
        slots = []
        for key in TRACE_TEXT_FIELDS:
            self._collect_field(record, key, slots)

        observations = record.get("observations")
        if isinstance(observations, list):
            for obs in observations:
                if isinstance(obs, dict):
                    for key in OBSERVATION_TEXT_FIELDS:
                        self._collect_field(obs, key, slots)

        self._mask_slots(slots)

        if isinstance(observations, list):
            record["observations"] = [
                {k: obs[k] for k in OBSERVATION_KEEP_FIELDS if k in obs}
                for obs in observations
                if isinstance(obs, dict)
            ]

        for key in TRACE_DROP_FIELDS:
            record.pop(key, None)

        metadata = record.get("metadata")
        if isinstance(metadata, dict):
            record["metadata"] = {
                k: metadata[k] for k in METADATA_KEEP_KEYS if k in metadata
            }

        return record

    def mask_jsonl(self, raw_text):
        """De-identify a JSONL blob record-by-record, preserving order/trailing NL."""
        lines = raw_text.split("\n")
        has_trailing_newline = raw_text.endswith("\n")
        if has_trailing_newline:
            lines = lines[:-1]

        masked_lines = []
        for line in lines:
            if not line.strip():
                masked_lines.append(line)
                continue
            masked_lines.append(
                json.dumps(self.mask_record(json.loads(line)), ensure_ascii=False)
            )

        result = "\n".join(masked_lines)
        if has_trailing_newline:
            result += "\n"
        return result, len(lines)
