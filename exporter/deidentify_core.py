"""Core de-identify logic, shared by the Cloud Run job and the e2e check.

Strategy: **keep the whole trace, mask a fixed set of fields**. Per record we
DLP-mask `input`, `output`, and `metadata` — on the trace and on each observation
(their full string-leaf subtree) — replacing detected PII with `[INFO_TYPE]`
placeholders. Every other field (ids, timestamps, `userId`, `tags`, costs,
type/name) is preserved AS-IS: not masked, not dropped. Kota receives the full
trace with only those fields scrubbed.

Because detection is DLP-based (probabilistic) and limited to the masked fields,
the result is reduced-sensitivity data, not a guarantee of zero PII — any PII
outside those fields is passed through unchanged. Tune the inspect template to
your data.

Rate-limit hardening: the job runs in the customer's project, where we cannot
raise the Cloud DLP quota (600 requests/min per region). So `DlpMasker`
  - **batches** a record's string leaves into table requests (bounded by row
    count and bytes) instead of one request per value;
  - **splits** any single oversized string on safe boundaries so it never
    exceeds DLP's per-item limit or hangs the run;
  - **rate-limits** every request to stay under the quota (`RateLimiter`);
  - **backs off** on `RESOURCE_EXHAUSTED`/transient errors and retries.

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
# Max rows per DLP table request (DLP allows 50,000 values; stay well under).
MAX_TABLE_ROWS = 2000
# Default client-side ceiling, below the 600/min-per-region DLP quota.
DEFAULT_MAX_RPM = 500
# Per-call DLP RPC deadline (seconds). Bounds a slow/stuck deidentify so it
# raises DeadlineExceeded and is retried, instead of hanging the run silently.
DEFAULT_DLP_TIMEOUT = 120

# Fields that are DLP-masked (the free-text transcript plus metadata, which can
# carry PII). Masked wherever they appear (trace + observations). Every other
# field is kept as-is. This is the DEFAULT — override per-deployment via the
# `masked_fields` DlpMasker arg (wired to an env var / TF variable). `userId` and
# `tags` are included because they routinely carry PII in real Langfuse traffic.
DEFAULT_MASKED_FIELDS = ("input", "output", "metadata", "userId", "tags")
# Tag entries with these prefixes are DROPPED entirely before DLP: they are
# structured identifiers (a raw email, a tenant slug), not free text, so DLP
# won't reliably detect them (e.g. `account:<slug>` is no infoType). Configurable.
DEFAULT_DROP_TAG_PREFIXES = ("email:", "account:")
# Backwards-compatible alias for callers that referenced the old constant.
MASKED_FIELDS = DEFAULT_MASKED_FIELDS


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
        masked_fields=DEFAULT_MASKED_FIELDS,
        drop_tag_prefixes=DEFAULT_DROP_TAG_PREFIXES,
    ):
        self.client = client
        self.parent = parent
        self.inspect_template = inspect_template
        self.deidentify_template = deidentify_template
        self.rate_limiter = rate_limiter
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.masked_fields = tuple(masked_fields)
        self.drop_tag_prefixes = tuple(drop_tag_prefixes)

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

    def _split_for_dlp(self, text):
        """Split `text` into pieces each < max_bytes, such that ''.join(pieces)
        reconstructs the original exactly. Splits on line boundaries — PII tokens
        never span a newline, so masking pieces independently can't miss PII at a
        boundary. A single line larger than max_bytes is hard-split by character
        (rare; the only place a token could straddle a boundary)."""
        pieces = []
        cur = []
        cur_bytes = 0
        for line in text.splitlines(keepends=True):
            line_bytes = len(line.encode("utf-8"))
            if line_bytes >= self.max_bytes:
                if cur:
                    pieces.append("".join(cur))
                    cur, cur_bytes = [], 0
                seg = []
                seg_bytes = 0
                for ch in line:
                    cb = len(ch.encode("utf-8"))
                    if seg and seg_bytes + cb > self.max_bytes:
                        pieces.append("".join(seg))
                        seg, seg_bytes = [], 0
                    seg.append(ch)
                    seg_bytes += cb
                if seg:
                    pieces.append("".join(seg))
                continue
            if cur and cur_bytes + line_bytes > self.max_bytes:
                pieces.append("".join(cur))
                cur, cur_bytes = [], 0
            cur.append(line)
            cur_bytes += line_bytes
        if cur:
            pieces.append("".join(cur))
        return pieces

    def _mask_strings(self, texts):
        """Mask a list of strings (each < max_bytes) via DLP table calls batched
        by row count and bytes. Returns the masked strings in input order."""
        masked = []
        index = 0
        while index < len(texts):
            chunk = []
            chunk_bytes = 0
            while index < len(texts) and len(chunk) < MAX_TABLE_ROWS:
                tb = len(texts[index].encode("utf-8"))
                if chunk and chunk_bytes + tb > self.max_bytes:
                    break
                chunk.append(texts[index])
                chunk_bytes += tb
                index += 1
            rows = [{"values": [{"string_value": t}]} for t in chunk]
            item = {"table": {"headers": [{"name": "v"}], "rows": rows}}
            masked_rows = self._call(item).item.table.rows
            masked.extend(r.values[0].string_value for r in masked_rows)
        return masked

    def _mask_big_text(self, text):
        """Mask a single oversized string by splitting it into sub-max_bytes
        pieces (on safe boundaries), masking them batched, and rejoining."""
        pieces = self._split_for_dlp(text)
        return "".join(self._mask_strings(pieces))

    def _mask_refs(self, refs):
        """Mask the string leaves referenced by `refs` (a list of (container,
        key)) in place, BATCHED into DLP table calls (not one request per leaf).
        A leaf at/above max_bytes is split and masked piecewise (see
        _mask_big_text) so it never exceeds DLP's per-item limit or hangs."""
        small_refs = []
        small_texts = []
        for container, key in refs:
            text = container[key]
            if not text.strip():
                continue
            if len(text.encode("utf-8")) >= self.max_bytes:
                container[key] = self._mask_big_text(text)
            else:
                small_refs.append((container, key))
                small_texts.append(text)
        masked = self._mask_strings(small_texts)
        for (container, key), masked_text in zip(small_refs, masked):
            container[key] = masked_text

    def _collect_mask_refs(self, container, refs):
        """Add string-leaf refs for the configured masked fields of `container`.
        A field that is itself a string is one leaf; a nested field (dict/list)
        contributes all of its string leaves."""
        for key in self.masked_fields:
            value = container.get(key)
            if isinstance(value, str):
                refs.append((container, key))
            elif isinstance(value, (dict, list)):
                _string_leaves(value, refs)

    def _drop_tags(self, container):
        """Remove tag entries whose prefix is in `drop_tag_prefixes` (identifiers
        like `email:` / `account:` that DLP can't reliably detect). No-op if the
        drop set is empty or `tags` is absent/not a list."""
        tags = container.get("tags")
        if isinstance(tags, list) and self.drop_tag_prefixes:
            container["tags"] = [
                t
                for t in tags
                if not (isinstance(t, str) and t.startswith(self.drop_tag_prefixes))
            ]

    def mask_record(self, record):
        """Keep the whole trace intact; DLP-mask only `input`, `output`, and
        `metadata` (on the trace and on each observation).

        Every other field — ids, timestamps, `userId`, `tags`, costs, type/name —
        is preserved AS-IS (not masked, not dropped). Detected PII in the masked
        fields is replaced with `[INFO_TYPE]`. Masking is DLP-based and
        probabilistic, so the result is reduced-sensitivity data, not a guarantee
        of zero PII; any PII that lives outside the masked fields is passed
        through unchanged."""
        self._drop_tags(record)
        refs = []
        self._collect_mask_refs(record, refs)
        observations = record.get("observations")
        if isinstance(observations, list):
            for obs in observations:
                if isinstance(obs, dict):
                    self._collect_mask_refs(obs, refs)
        self._mask_refs(refs)
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
