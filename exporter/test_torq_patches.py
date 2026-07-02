"""Tests for the Torq patches: Gap 1 (Cloudflare Access headers) and Gap 2 (tags masking).

Run: cd exporter && . .venv/bin/activate && python -m pytest test_torq_patches.py -v
"""

import sys
import types

# ---------------------------------------------------------------------------
# Gap 1 — Cloudflare Access header support (langfuse_api.py, no network needed)
# ---------------------------------------------------------------------------
from langfuse_api import LangfuseAPIClient


def test_extra_headers_are_sent():
    c = LangfuseAPIClient(
        "https://lf.example",
        "pk",
        "sk",
        extra_headers={"CF-Access-Client-Id": "cid", "CF-Access-Client-Secret": "csec"},
    )
    h = c._client.headers
    assert h["CF-Access-Client-Id"] == "cid"
    assert h["CF-Access-Client-Secret"] == "csec"
    assert h["Accept"] == "application/json"


def test_no_extra_headers_is_noop():
    c = LangfuseAPIClient("https://lf.example", "pk", "sk")
    assert "cf-access-client-id" not in c._client.headers
    assert c._client.headers["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# Gap 2 — configurable masked-field set + tags scrubbing (deidentify_core.py)
# deidentify_core imports google.api_core.exceptions at module top, so stub it.
# ---------------------------------------------------------------------------
if "google" not in sys.modules:
    google = types.ModuleType("google")
    api_core = types.ModuleType("google.api_core")
    exceptions = types.ModuleType("google.api_core.exceptions")
    for name in ("DeadlineExceeded", "ResourceExhausted", "ServiceUnavailable"):
        setattr(exceptions, name, type(name, (Exception,), {}))
    api_core.exceptions = exceptions
    google.api_core = api_core
    sys.modules["google"] = google
    sys.modules["google.api_core"] = api_core
    sys.modules["google.api_core.exceptions"] = exceptions

from deidentify_core import DlpMasker, RateLimiter  # noqa: E402


class FakeDlp:
    """Echoes table rows back, replacing any value containing '@' with [EMAIL_ADDRESS]."""

    def deidentify_content(self, request, timeout=None):
        rows = request["item"]["table"]["rows"]
        out = []
        for r in rows:
            v = r["values"][0]["string_value"]
            out.append("[EMAIL_ADDRESS]" if "@" in v else v)
        resp = types.SimpleNamespace(
            item=types.SimpleNamespace(
                table=types.SimpleNamespace(
                    rows=[
                        types.SimpleNamespace(
                            values=[types.SimpleNamespace(string_value=v)]
                        )
                        for v in out
                    ]
                )
            )
        )
        return resp


def _masker(**kwargs):
    return DlpMasker(FakeDlp(), "parent", "inspect", "deidentify", RateLimiter(0), **kwargs)


def test_tags_email_is_masked_and_account_dropped():
    m = _masker()
    rec = {
        "input": "contact alice@example.com",
        "output": "ok",
        "metadata": {},
        "userId": "6a1969c7-50ac-47ac-9df9-1c5bbfab9bf8",
        "tags": ["agent:plan", "model:opus", "email:carol@example.com", "account:socrates-playground"],
    }
    out = m.mask_record(rec)
    # input still masked (baseline behavior preserved)
    assert "@" not in out["input"]
    # the email: tag is dropped entirely (personal PII, no analytic value)
    assert not any(t.startswith("email:") for t in out["tags"])
    # account: tag dropped by default drop-prefix set
    assert not any(t.startswith("account:") for t in out["tags"])
    # useful pseudonymous tags preserved
    assert "agent:plan" in out["tags"]
    assert "model:opus" in out["tags"]
    # userId (opaque UUID) preserved as-is
    assert out["userId"] == "6a1969c7-50ac-47ac-9df9-1c5bbfab9bf8"


def test_masked_fields_is_configurable():
    import inspect

    assert "masked_fields" in inspect.signature(DlpMasker.__init__).parameters


def test_drop_prefixes_configurable_keep_account():
    # With only "email:" in the drop set, account: survives.
    m = _masker(drop_tag_prefixes=("email:",))
    rec = {"input": "", "output": "", "metadata": {}, "tags": ["email:x@y.com", "account:acme"]}
    out = m.mask_record(rec)
    assert not any(t.startswith("email:") for t in out["tags"])
    assert "account:acme" in out["tags"]
