"""Langfuse public REST API client for trace polling.

Polls `GET /api/public/traces` since a watermark and (optionally) hydrates
each trace via `GET /api/public/traces/{traceId}` for the full
`TraceWithFullDetails` payload (with `observations`, `scores`, `latency`,
`totalCost`, `htmlPath`).

Rate-limit handling mirrors the Kustomer client pattern: 429 responses raise
a typed error carrying `Retry-After`, and tenacity retries with exponential
backoff on that error.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

_TRACES_LIST_PATH = "/api/public/traces"
_TRACE_DETAIL_PATH = "/api/public/traces/{trace_id}"
_PAGE_SIZE = 100
_REQUEST_TIMEOUT = 30


class LangfuseRateLimitError(Exception):
    """Raised on HTTP 429. Carries Retry-After when the server provides it."""

    def __init__(self, retry_after: Optional[float] = None) -> None:
        self.retry_after = retry_after
        super().__init__(f"rate-limited (retry_after={retry_after})")


class LangfuseAPIClient:
    """Async client for the Langfuse public REST API."""

    def __init__(
        self,
        host: str,
        public_key: str,
        secret_key: str,
    ) -> None:
        self._host = host.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._host,
            auth=(public_key, secret_key),
            headers={"Accept": "application/json"},
            timeout=_REQUEST_TIMEOUT,
        )

    async def __aenter__(self) -> LangfuseAPIClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.aclose()

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=60),
        retry=retry_if_exception_type(LangfuseRateLimitError),
    )
    async def _get(
        self, path: str, params: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        response = await self._client.get(path, params=params)
        if response.status_code == 429:
            retry_after_raw = response.headers.get("Retry-After")
            try:
                retry_after = float(retry_after_raw) if retry_after_raw else None
            except (TypeError, ValueError):
                retry_after = None
            if retry_after:
                logger.warning(
                    "Langfuse 429, sleeping per Retry-After",
                    extra={"path": path, "retry_after": retry_after},
                )
                await asyncio.sleep(retry_after)
            raise LangfuseRateLimitError(retry_after=retry_after)
        response.raise_for_status()
        return response.json()

    async def iter_trace_summaries_since(
        self, from_timestamp_seconds: int
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield trace rows whose timestamp >= from_timestamp_seconds.

        Pages forward through the list endpoint. Each yielded dict already
        contains top-level `latency`, `totalCost`, `htmlPath`, `observations`
        (as IDs), and `scores` (as IDs). Use `get_trace_details` to hydrate
        observation/score objects.
        """
        from_ts = (
            _to_iso_z(from_timestamp_seconds) if from_timestamp_seconds > 0 else None
        )

        page = 1
        while True:
            params: dict[str, Any] = {"page": page, "limit": _PAGE_SIZE}
            if from_ts is not None:
                params["fromTimestamp"] = from_ts

            payload = await self._get(_TRACES_LIST_PATH, params=params)
            data = payload.get("data") or []
            if not data:
                return

            for trace in data:
                yield trace

            meta = payload.get("meta") or {}
            total_pages = meta.get("totalPages")
            if total_pages is not None and page >= int(total_pages):
                return
            if len(data) < _PAGE_SIZE:
                return
            page += 1

    async def get_trace_details(self, trace_id: str) -> dict[str, Any]:
        """Fetch a single trace with full observations, scores, latency, totalCost."""
        return await self._get(_TRACE_DETAIL_PATH.format(trace_id=trace_id))


def _to_iso_z(unix_seconds: int) -> str:
    """Convert a Unix timestamp (seconds, UTC) to Langfuse's expected ISO-Z form."""
    dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")
