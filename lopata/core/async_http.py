"""Async HTTP fan-out core (httpx + asyncio).

This is the replacement for the per-module ``ThreadPoolExecutor`` fetch loops.
Concurrency is bounded by an ``asyncio.Semaphore`` instead of a thread-pool
``max_workers``; retries mirror the urllib3 ``Retry`` the synchronous session
used (``total`` attempts, 0.5s exponential backoff, retry only on 502/503/504);
and an optional token-spacing rate limiter is available for targets that need to
be probed gently.

Synchronous modules stay synchronous: they call :func:`fetch_all` (a one-shot
batch) or drive their own coroutine through :func:`run`, which owns the event
loop so callers never see ``async``/``await``. The single sync ``requests``
session on ``ScanContext`` is untouched — this layer is additive, and modules
that issue one request at a time keep using it.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Iterable, Optional

import httpx

DEFAULT_USER_AGENT = "lopata/1.0 (+authorized-security-testing)"
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Same transient statuses the urllib3 Retry retried on, and the same backoff.
_RETRY_STATUS = frozenset({502, 503, 504})
_BACKOFF_FACTOR = 0.5
# urllib3's Retry only retried idempotent methods by default; match that so a
# POST payload is never silently re-sent.
_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})


class _RateLimiter:
    """Spaces request *starts* to at most ``rate`` per second (global).

    Disabled (zero cost) when ``rate`` is None or <= 0, which is the default and
    preserves the old behaviour where the only throttle was the concurrency cap.
    """

    def __init__(self, rate: Optional[float]) -> None:
        self._interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self._interval


class AsyncFetcher:
    """Bounded-concurrency async HTTP client.

    Use as an async context manager so the underlying ``httpx.AsyncClient`` and
    the semaphore are created inside the running loop and closed on exit::

        async with AsyncFetcher.from_ctx(ctx) as f:
            for url, resp in await f.get_many(urls):
                ...
    """

    def __init__(self, *, headers: Optional[dict] = None,
                 cookies: Optional[dict] = None, verify: bool = True,
                 timeout: float = 10.0, retries: int = 1, concurrency: int = 10,
                 rate_limit: Optional[float] = None,
                 follow_redirects: bool = False) -> None:
        self._headers = dict(DEFAULT_HEADERS)
        if headers:
            self._headers.update(headers)
        self._cookies = dict(cookies or {})
        self._verify = verify
        self._timeout = float(timeout)
        self._retries = max(int(retries), 0)
        self._concurrency = max(int(concurrency), 1)
        self._rate_limit = rate_limit
        self._follow = follow_redirects
        self._client: Optional[httpx.AsyncClient] = None
        self._sem: Optional[asyncio.Semaphore] = None
        self._rate: Optional[_RateLimiter] = None

    @classmethod
    def from_ctx(cls, ctx, **overrides) -> "AsyncFetcher":
        """Build a fetcher configured identically to ``ctx.session``.

        Auth headers, cookies, TLS-verify and timeout are carried across so an
        authenticated scan stays authenticated on the async path, and the
        concurrency cap defaults to ``ctx.threads`` — the same number the thread
        pools used.
        """
        session = ctx.session
        headers = {k: v for k, v in session.headers.items()}
        cookies = {c.name: c.value for c in session.cookies}
        params = dict(
            headers=headers,
            cookies=cookies,
            verify=bool(getattr(session, "verify", True)),
            timeout=float(ctx.timeout),
            retries=int(ctx.config.get("retries", 1)),
            concurrency=int(ctx.threads),
            rate_limit=ctx.config.get("rate_limit"),
        )
        params.update(overrides)
        return cls(**params)

    async def __aenter__(self) -> "AsyncFetcher":
        limits = httpx.Limits(max_connections=self._concurrency,
                              max_keepalive_connections=self._concurrency)
        self._client = httpx.AsyncClient(
            headers=self._headers, cookies=self._cookies, verify=self._verify,
            timeout=self._timeout, follow_redirects=self._follow, limits=limits)
        self._sem = asyncio.Semaphore(self._concurrency)
        self._rate = _RateLimiter(self._rate_limit)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(self, method: str, url: str, *,
                      allow_redirects: Optional[bool] = None,
                      headers: Optional[dict] = None,
                      data=None) -> Optional[httpx.Response]:
        """Issue one request; return the response, or ``None`` if it never
        succeeded.

        Retries transient failures (connection errors and 502/503/504) up to
        ``retries`` extra times with exponential backoff — but only for
        idempotent methods, matching the synchronous session's urllib3 Retry.
        Any other error resolves to ``None`` — callers treated a failed fetch as
        "nothing here", exactly as before.
        """
        follow = self._follow if allow_redirects is None else allow_redirects
        method = method.upper()
        attempts = (self._retries + 1) if method in _IDEMPOTENT else 1
        result: Optional[httpx.Response] = None
        for attempt in range(attempts):
            await self._rate.acquire()
            async with self._sem:
                try:
                    result = await self._client.request(
                        method, url, follow_redirects=follow,
                        headers=headers, data=data)
                except Exception:
                    result = None
            if result is not None and result.status_code not in _RETRY_STATUS:
                return result
            if attempt < attempts - 1:
                await asyncio.sleep(_BACKOFF_FACTOR * (2 ** attempt))
        return result

    async def get(self, url: str, *, allow_redirects: Optional[bool] = None,
                  headers: Optional[dict] = None) -> Optional[httpx.Response]:
        return await self.request("GET", url, allow_redirects=allow_redirects,
                                  headers=headers)

    async def post(self, url: str, *, data=None,
                   allow_redirects: Optional[bool] = None,
                   headers: Optional[dict] = None) -> Optional[httpx.Response]:
        return await self.request("POST", url, data=data,
                                  allow_redirects=allow_redirects,
                                  headers=headers)

    async def get_many(self, urls: Iterable[str], *,
                       allow_redirects: Optional[bool] = None
                       ) -> list[tuple[str, Optional[httpx.Response]]]:
        """Fetch every URL concurrently (bounded by the semaphore).

        Returns ``(url, response_or_None)`` pairs in the same order as ``urls``.
        """
        urls = list(urls)

        async def one(u: str):
            return u, await self.get(u, allow_redirects=allow_redirects)

        return list(await asyncio.gather(*(one(u) for u in urls)))


def run(coro):
    """Drive a coroutine to completion from synchronous code.

    Normally there is no running loop (modules are synchronous), so this is just
    ``asyncio.run``. If lopata is ever embedded inside an existing event loop,
    the coroutine is run on a dedicated thread with its own loop so we never try
    to nest ``asyncio.run``.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    box: dict = {}

    def _worker() -> None:
        box["value"] = asyncio.run(coro)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join()
    return box["value"]


def fetch_all(ctx, urls: Iterable[str], *, allow_redirects: bool = False,
              **overrides) -> list[tuple[str, Optional[httpx.Response]]]:
    """One-shot synchronous batch GET for callers that just want responses.

    Opens a fetcher from ``ctx``, fetches all ``urls``, closes it, and returns
    ``(url, response_or_None)`` pairs. This is the drop-in replacement for a
    ``ThreadPoolExecutor`` that mapped a plain GET over a list of URLs.
    """
    urls = list(urls)

    async def _driver():
        async with AsyncFetcher.from_ctx(ctx, **overrides) as fetcher:
            return await fetcher.get_many(urls, allow_redirects=allow_redirects)

    return run(_driver())
