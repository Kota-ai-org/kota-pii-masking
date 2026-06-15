"""Core de-identify logic, shared by the Cloud Function and the e2e check.

Strategy: targeted masking + projection. Per trace record we
  1. DLP-mask only the free-text transcript fields — trace `input`/`output` and
     each observation `input`/`output` — by serializing the field to text,
     de-identifying it, and parsing it back (replace_with_info_type keeps it
     valid JSON);
  2. project the record down to the fields Kota's parser consumes, DROPPING the
     non-transcript PII carriers entirely (`userId`, `tags`, raw `metadata`
     except `agent_name`, usage/cost/model on observations).

This keeps the PII surface minimal (leaky fields are removed, not just masked),
keeps payloads small (no whole-record DLP), and preserves exactly what the parser
needs plus observation io for future signal work.

Pure DLP logic, no Cloud Functions / storage deps, so it is directly testable.
"""

import json

DEFAULT_MAX_BATCH_BYTES = 200_000
# A serialized field at/above this is chunked leaf-by-leaf instead of whole.
FIELD_SIZE_LIMIT = 450_000

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


def deidentify_text(client, parent, inspect_template, deidentify_template, text):
    if not text.strip():
        return text
    response = client.deidentify_content(
        request={
            "parent": parent,
            "inspect_template_name": inspect_template,
            "deidentify_template_name": deidentify_template,
            "item": {"value": text},
        }
    )
    return response.item.value


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


def _mask_by_leaves(client, parent, inspect, deid, value):
    """Fallback for oversized fields: mask each string leaf individually."""
    refs = []
    _string_leaves(value, refs)
    for container, key in refs:
        leaf = container[key]
        if leaf.strip():
            container[key] = deidentify_text(client, parent, inspect, deid, leaf)
    return value


def mask_field_value(client, parent, inspect, deid, value):
    """De-identify a trace/observation field value (string or nested JSON).

    Serializes to text, masks once, parses back. Falls back to leaf-by-leaf if
    the field is too large for one request or if masking somehow breaks JSON.
    """
    if value is None:
        return None
    text = json.dumps(value, ensure_ascii=False)
    if len(text.encode("utf-8")) >= FIELD_SIZE_LIMIT:
        return _mask_by_leaves(client, parent, inspect, deid, value)
    masked = deidentify_text(client, parent, inspect, deid, text)
    try:
        return json.loads(masked)
    except json.JSONDecodeError:
        return _mask_by_leaves(client, parent, inspect, deid, value)


def deidentify_record(client, parent, inspect, deid, record):
    """Mask transcript fields and project away non-transcript PII carriers."""
    for key in TRACE_TEXT_FIELDS:
        if record.get(key) is not None:
            record[key] = mask_field_value(client, parent, inspect, deid, record[key])

    observations = record.get("observations")
    if isinstance(observations, list):
        projected_obs = []
        for obs in observations:
            if not isinstance(obs, dict):
                continue
            for key in OBSERVATION_TEXT_FIELDS:
                if obs.get(key) is not None:
                    obs[key] = mask_field_value(client, parent, inspect, deid, obs[key])
            projected_obs.append(
                {k: obs[k] for k in OBSERVATION_KEEP_FIELDS if k in obs}
            )
        record["observations"] = projected_obs

    for key in TRACE_DROP_FIELDS:
        record.pop(key, None)

    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        record["metadata"] = {
            k: metadata[k] for k in METADATA_KEEP_KEYS if k in metadata
        }

    return record


def deidentify_jsonl(
    client,
    parent,
    inspect_template,
    deidentify_template,
    raw_text,
    max_bytes=DEFAULT_MAX_BATCH_BYTES,
):
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
        record = json.loads(line)
        masked = deidentify_record(
            client, parent, inspect_template, deidentify_template, record
        )
        masked_lines.append(json.dumps(masked, ensure_ascii=False))

    result = "\n".join(masked_lines)
    if has_trailing_newline:
        result += "\n"
    return result, len(lines)
