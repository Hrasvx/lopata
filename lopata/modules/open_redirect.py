from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "open_redirect"
CATEGORY = "Open Redirect"

MARKER_HOST = "lopata-openredirect-probe.example"
MARKER_URL = f"https://{MARKER_HOST}/"

PARAMS = ["next", "url", "redirect", "redirect_uri", "redirect_url", "redir",
          "return", "returnurl", "return_url", "dest", "destination",
          "continue", "r", "u", "target", "to", "out", "go", "link", "forward"]


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    targets = [(ctx.target + "/", PARAMS)]
    for url in ctx.discovered_urls:
        existing = list(parse_qs(urlparse(url).query).keys())
        names = existing + [p for p in PARAMS if p not in existing]
        targets.append((url, names))

    if phase:
        phase.set_total(len(targets))
    found = 0
    with ThreadPoolExecutor(max_workers=ctx.threads) as pool:
        futures = {pool.submit(_test, ctx, url, names): url
                   for url, names in targets}
        for fut in as_completed(futures):
            for finding in fut.result():
                ctx.add_finding(finding)
                found += 1
            phase and phase.step()
    phase and phase.done()


def _is_marker(location: str | None) -> bool:
    if not location:
        return False
    target = location
    if location.startswith("//"):
        target = "https:" + location
    return (urlparse(target).hostname or "").lower() == MARKER_HOST


def _test(ctx, url, params) -> list[Finding]:
    out = []
    parsed = urlparse(url)
    base = parse_qs(parsed.query, keep_blank_values=True)
    for param in params:
        mutated = {k: v[:] for k, v in base.items()}
        mutated[param] = [MARKER_URL]
        test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        try:
            resp = ctx.session.get(test_url, timeout=ctx.timeout,
                                   allow_redirects=False)
        except requests.RequestException:
            continue
        if resp.is_redirect and _is_marker(resp.headers.get("Location")):
            out.append(Finding(
                name="Open redirect",
                severity=Severity.MEDIUM,
                location=f"{url} [param: {param}]",
                description=f"Parameter '{param}' accepts an arbitrary external "
                            "URL as the redirect target, usable for phishing or "
                            "OAuth token theft on the trusted domain.",
                remediation="Validate redirect targets against an allow-list of "
                            "internal paths; permit only relative URLs.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=f"Location -> {resp.headers.get('Location')}",
                request=f"GET {test_url}",
                response=f"{resp.status_code} Location: {resp.headers.get('Location')}",
                confidence=Confidence.CONFIRMED))
            break
    return out
