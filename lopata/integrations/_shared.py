"""Target selection shared by the discovery-consuming integrations.

Nuclei, Dalfox, sqlmap and Arjun all need the *same* thing that the crawler and
Arjun produced: a bounded, de-duplicated set of URLs and injectable
parameters. Keeping that selection in one place means every tool tests the same
surface, and the per-parameter location strings they emit line up with the
`[param: name]` convention `core.correlate.injection_point` keys on — which is
what lets an external tool corroborate lopata's own finding rather than produce
a second, unlinked one.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from .base import host_of


def _in_primary_scope(url: str, ctx) -> bool:
    """Keep tools pointed at the target and its confirmed subdomains only."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    allowed = {host_of(ctx.target).lower()} | {s.lower() for s in ctx.subdomains}
    return host in allowed


def candidate_urls(ctx, limit: int = 40) -> list[str]:
    """A bounded, in-scope URL list for surface scanners (nuclei/httpx).

    Prefers URLs that carry parameters (more interesting to a template
    scanner), then falls back to plain pages, always including the target root.
    """
    root = ctx.target.rstrip("/") + "/"
    with_params: list[str] = []
    plain: list[str] = []
    for url in sorted(ctx.discovered_urls):
        if not _in_primary_scope(url, ctx):
            continue
        if urlparse(url).query:
            with_params.append(url)
        else:
            plain.append(url)

    ordered: list[str] = [root]
    for url in with_params + plain:
        if url not in ordered:
            ordered.append(url)
        if len(ordered) >= limit:
            break
    return ordered[:limit]


def injectable_targets(ctx, limit: int = 40) -> list[dict]:
    """Every (method, url, param) worth aiming an injection tool at.

    Sources, in order: query parameters on discovered URLs, GET/POST form
    fields, and the hidden parameters Arjun surfaced. Deduplicated on
    (method, scheme, host, path, param) so `?id=1` and `?id=2` collapse to one.
    """
    seen: set[tuple] = set()
    out: list[dict] = []

    def add(method: str, url: str, param: str, data: dict) -> None:
        if not param or not _in_primary_scope(url, ctx):
            return
        parsed = urlparse(url)
        key = (method, parsed.scheme, parsed.netloc, parsed.path, param)
        if key in seen:
            return
        seen.add(key)
        out.append({"method": method, "url": url, "param": param,
                    "data": dict(data)})

    for url in sorted(ctx.discovered_urls):
        for param in parse_qs(urlparse(url).query).keys():
            add("GET", url, param, {})

    for form in ctx.forms:
        method = (form.get("method") or "get").upper()
        if method not in ("GET", "POST"):
            continue
        action = form.get("action") or ctx.target
        fields = {i["name"]: (i.get("value") or "1")
                  for i in form.get("inputs", []) if i.get("name")}
        for param in fields:
            data = {k: v for k, v in fields.items() if k != param}
            add(method, action, param, data)

    for url, params in (ctx.discovered_params or {}).items():
        for param in params:
            add("GET", url, param, {})

    return out[:limit]


def param_urls(ctx, limit: int = 40) -> list[str]:
    """URLs that carry at least one query parameter, for tools that take a URL
    list rather than a param list (e.g. `dalfox pipe`). Arjun params are folded
    in by appending a placeholder value so the tool sees the parameter."""
    urls: list[str] = []
    seen: set[str] = set()
    for t in injectable_targets(ctx, limit * 2):
        if t["method"] != "GET":
            continue
        parsed = urlparse(t["url"])
        if parsed.query and t["param"] in parse_qs(parsed.query):
            url = t["url"]
        else:
            sep = "&" if parsed.query else "?"
            url = f"{t['url']}{sep}{t['param']}=1"
        if url not in seen:
            seen.add(url)
            urls.append(url)
        if len(urls) >= limit:
            break
    return urls[:limit]
