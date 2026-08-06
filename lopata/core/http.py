from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_USER_AGENT = "lopata/1.0 (+authorized-security-testing)"


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError(f"could not parse a hostname from {raw!r}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parsed.scheme!r}")
    netloc = parsed.netloc
    return urlunparse((parsed.scheme, netloc, "", "", "", ""))


def build_session(
    timeout: float = 10.0,
    retries: int = 1,
    verify_tls: bool = True,
    auth_headers: dict | None = None,
    auth_cookies: dict | None = None,
) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    if auth_headers:
        session.headers.update(auth_headers)
    if auth_cookies:
        session.cookies.update(auth_cookies)

    session.verify = verify_tls

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=0.5,
        status_forcelist=(502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),


        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def parse_auth_args(header_list: list[str] | None, cookie_str: str | None) -> tuple[dict, dict]:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for item in header_list or []:
        if ":" not in item:
            raise ValueError(f"header must be 'Name: value', got {item!r}")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    if cookie_str:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise ValueError(f"cookie must be 'name=value', got {pair!r}")
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return headers, cookies
