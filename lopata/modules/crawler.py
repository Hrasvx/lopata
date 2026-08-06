from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "crawler"
CATEGORY = "Attack Surface"

_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
             ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".webp", ".eot")


def run(ctx, phase=None) -> None:
    if BeautifulSoup is None:
        ctx.logger and ctx.logger.warning("beautifulsoup4 missing; crawl limited")
    ctx.modules_run.append(MODULE_NAME)

    base = ctx.target
    base_host = urlparse(base).hostname or ""
    allowed_hosts = {base_host} | set(ctx.subdomains)

    seeds = [base + "/"]
    for sub in ctx.subdomains:
        scheme = urlparse(base).scheme
        seeds.append(f"{scheme}://{sub}/")

    seen: set[str] = set()
    queue: deque[str] = deque(seeds)
    if phase:
        phase.set_total(ctx.max_pages)

    while queue and len(seen) < ctx.max_pages:
        url = queue.popleft()
        url, _ = urldefrag(url)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = ctx.session.get(url, timeout=ctx.timeout)
        except requests.RequestException:
            continue
        phase and phase.step()

        ctx.discovered_urls.add(url)
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue
        body = resp.text or ""
        ctx.page_bodies[url] = body[:200000]

        if BeautifulSoup is None:
            continue
        soup = BeautifulSoup(body, "html.parser")
        _extract_forms(ctx, url, soup)

        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            nxt, _ = urldefrag(nxt)
            p = urlparse(nxt)
            if p.scheme not in ("http", "https"):
                continue
            if p.hostname not in allowed_hosts:
                continue
            if nxt.lower().endswith(_SKIP_EXT):
                continue
            if nxt not in seen:
                queue.append(nxt)

    if phase:
        phase.done()

    ctx.add_finding(Finding(
        name="Attack surface mapped",
        severity=Severity.INFO, location=base,
        description=(
            f"Crawl reached {len(ctx.discovered_urls)} URL(s) and "
            f"{len(ctx.forms)} form(s) across {len(allowed_hosts)} host(s)."
        ),
        remediation="Review that all reachable endpoints are intended to be public.",
        module=MODULE_NAME, category=CATEGORY,
        confidence=Confidence.FIRM,
    ))


def _extract_forms(ctx, page_url: str, soup) -> None:
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "get").lower()
        inputs = []
        for el in form.find_all(("input", "textarea", "select")):
            name = el.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": (el.get("type") or el.name or "text").lower(),
                "value": el.get("value") or "",
            })


        sig = (action, method, tuple(i["name"] for i in inputs))
        if sig in ctx._form_sigs:
            continue
        ctx._form_sigs.add(sig)
        ctx.forms.append({
            "page": page_url,
            "action": action,
            "method": method,
            "inputs": inputs,
            "html": str(form)[:2000],
        })
