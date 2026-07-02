"""Onboarding dry-run: DLP findings report over a sample of Langfuse traces.

Run by Kota with your team on the onboarding call BEFORE any data is shared. It
pulls a small sample of traces from your Langfuse API, inspects their transcript
fields with your inspect template, and prints what would be detected plus how a
record looks before/after de-identification. Nothing leaves your project;
clear-text PII is never printed.

Single project (default): set LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY in env
(host via --langfuse-host or LANGFUSE_HOST, defaults to Langfuse US cloud).

All configured projects (--all): set LANGFUSE_PROJECTS to the same JSON manifest
the exporter job uses ([{name, host}, ...]) plus LF_PUB_<SLUG> / LF_SEC_<SLUG>
per project. Reports per project. ADC is required for the DLP API either way.

Usage:
  python dry_run.py \
    --project <PROJECT_ID> \
    --region <REGION> \
    --inspect-template <projects/.../inspectTemplates/...> \
    --deidentify-template <projects/.../deidentifyTemplates/...> \
    [--langfuse-host https://us.cloud.langfuse.com] \
    [--all] [--lookback-seconds 86400] [--max-traces 5]
"""

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from google.api_core import client_options as co
from google.cloud import dlp_v2

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[0] / "exporter"))

from langfuse_api import LangfuseAPIClient  # noqa: E402

MAX_INSPECT_BYTES = 200_000
# Fields the report inspects — must mirror the job's masked set (deidentify_core
# DEFAULT_MASKED_FIELDS) so the findings report doesn't hide PII in fields the job
# masks (notably `tags`, where our confirmed leak lives). Was ("input","output").
INSPECT_FIELDS = ("input", "output", "metadata", "userId", "tags")


def _parent(project, region):
    return f"projects/{project}/locations/{region}"


def _transcript_text(record):
    parts = []
    for key in INSPECT_FIELDS:
        value = record.get(key)
        if value is not None:
            parts.append(json.dumps(value, ensure_ascii=False))
    return "\n".join(parts)


def _extra_headers(slug=None):
    """Optional per-request headers (Cloudflare Access etc.), mirroring the
    exporter (main.py). Global CF_ACCESS_CLIENT_ID/SECRET plus optional
    LF_HDR_<SLUG> JSON. Returns None when unset (no-op)."""
    headers = {}
    if slug:
        raw = os.environ.get(f"LF_HDR_{slug}")
        if raw:
            headers.update(json.loads(raw))
    cid = os.environ.get("CF_ACCESS_CLIENT_ID")
    csec = os.environ.get("CF_ACCESS_CLIENT_SECRET")
    if cid and csec:
        headers["CF-Access-Client-Id"] = cid
        headers["CF-Access-Client-Secret"] = csec
    return headers or None


async def _pull(host, public_key, secret_key, lookback_seconds, max_traces, extra_headers=None):
    since = int(time.time()) - lookback_seconds
    records = []
    async with LangfuseAPIClient(host, public_key, secret_key, extra_headers) as client:
        async for summary in client.iter_trace_summaries_since(since):
            records.append(await client.get_trace_details(summary["id"]))
            if len(records) >= max_traces:
                break
    return records


def _inspect(dlp_client, parent, inspect_template, text):
    response = dlp_client.inspect_content(
        request={
            "parent": parent,
            "inspect_template_name": inspect_template,
            "item": {"value": text},
        }
    )
    return response.result.findings


def _deidentify(dlp_client, parent, inspect_template, deidentify_template, text):
    response = dlp_client.deidentify_content(
        request={
            "parent": parent,
            "inspect_template_name": inspect_template,
            "deidentify_template_name": deidentify_template,
            "item": {"value": text},
        }
    )
    return response.item.value


def _env_slug(name):
    """Mirror the exporter / Terraform slug: upper(replace(name, "-", "_"))."""
    return name.upper().replace("-", "_")


def _run_report(dlp_client, parent, args, host, public_key, secret_key, label, extra_headers=None):
    records = asyncio.run(
        _pull(host, public_key, secret_key, args.lookback_seconds, args.max_traces, extra_headers)
    )

    print("=" * 70)
    print(f"KOTA PII-MASKING DRY-RUN FINDINGS REPORT{label}")
    print("=" * 70)
    if not records:
        print("No traces in the lookback window. Nothing to inspect.\n")
        return

    texts = [_transcript_text(r) for r in records]
    sample = "\n".join(texts)[:MAX_INSPECT_BYTES]

    findings = _inspect(dlp_client, parent, args.inspect_template, sample)
    by_type = Counter(f.info_type.name for f in findings)
    by_likelihood = Counter(f.likelihood.name for f in findings)

    print(f"Sampled {len(records)} trace(s) from {host}\n")
    print(f"Total PII findings: {len(findings)}\n")
    print("By infoType:")
    for name, count in by_type.most_common():
        print(f"  {name:30s} {count}")
    print("\nBy likelihood:")
    for name, count in by_likelihood.most_common():
        print(f"  {name:30s} {count}")

    print("\n" + "-" * 70)
    print("BEFORE → AFTER preview (first detected trace, de-identified)")
    print("-" * 70)
    preview = next(
        (t for t in texts if _inspect(dlp_client, parent, args.inspect_template, t)),
        texts[0],
    )
    masked = _deidentify(
        dlp_client, parent, args.inspect_template, args.deidentify_template, preview
    )
    print("AFTER (masked, safe to share):")
    print(f"  {masked[:1000]}")
    print(
        "\nRaw trace text is NOT printed. Review the masked form above before sign-off.\n"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--region", required=True)
    ap.add_argument("--inspect-template", required=True)
    ap.add_argument("--deidentify-template", required=True)
    ap.add_argument(
        "--langfuse-host",
        default=os.environ.get("LANGFUSE_HOST", "https://us.cloud.langfuse.com"),
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Report every project in LANGFUSE_PROJECTS (keys from LF_PUB_/LF_SEC_).",
    )
    ap.add_argument("--lookback-seconds", type=int, default=86400)
    ap.add_argument("--max-traces", type=int, default=5)
    args = ap.parse_args()

    parent = _parent(args.project, args.region)
    dlp_client = dlp_v2.DlpServiceClient(
        client_options=co.ClientOptions(quota_project_id=args.project)
    )

    if args.all:
        projects = json.loads(os.environ["LANGFUSE_PROJECTS"])
        for proj in projects:
            name = proj["name"]
            slug = _env_slug(name)
            _run_report(
                dlp_client,
                parent,
                args,
                proj.get("host", args.langfuse_host),
                os.environ[f"LF_PUB_{slug}"],
                os.environ[f"LF_SEC_{slug}"],
                f" — {name}",
                _extra_headers(slug),
            )
        return

    _run_report(
        dlp_client,
        parent,
        args,
        args.langfuse_host,
        os.environ["LANGFUSE_PUBLIC_KEY"],
        os.environ["LANGFUSE_SECRET_KEY"],
        "",
        _extra_headers(),
    )


if __name__ == "__main__":
    main()
