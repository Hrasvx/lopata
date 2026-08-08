from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core import async_http
from ..core.async_http import AsyncFetcher
from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

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

    async def _driver():
        async with AsyncFetcher.from_ctx(ctx) as fetcher:
            async def one(url, names):
                for finding in await _test(ctx, fetcher, url, names):
                    ctx.add_finding(finding)
                phase and phase.step()
            await asyncio.gather(*(one(url, names) for url, names in targets))

    async_http.run(_driver())
    phase and phase.done()


def _is_marker(location: str | None) -> bool:
    if not location:
        return False
    target = location
    if location.startswith("//"):
        target = "https:" + location
    return (urlparse(target).hostname or "").lower() == MARKER_HOST


async def _test(ctx, fetcher, url, params) -> list[Finding]:
    out = []
    parsed = urlparse(url)
    base = parse_qs(parsed.query, keep_blank_values=True)
    for param in params:
        mutated = {k: v[:] for k, v in base.items()}
        mutated[param] = [MARKER_URL]
        test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        resp = await fetcher.get(test_url, allow_redirects=False)
        if resp is None:
            continue
        if resp.is_redirect and _is_marker(resp.headers.get("Location")):
            finding = Finding(
                name="Open redirect",
                severity=Severity.INFO,
                location=f"{url} [param: {param}]",
                description=(
                    f"The parameter `{param}` accepts an absolute external URL "
                    "and the server issues a redirect to it. lopata supplied a "
                    "host it controls the name of and confirmed the Location "
                    "header pointed there, so this is reproduced behaviour "
                    "rather than a pattern match."
                ),
                remediation="Only redirect to paths, validated against an "
                            "allow-list.",
                ftype=FindingType.CONFIRMED_VULN,
                module=MODULE_NAME, category=CATEGORY,
                summary=f"`{param}` redirects to an arbitrary external URL.",
                risk=(
                    "The redirect launders the trust in your domain. A phishing "
                    "link that starts with your hostname passes visual "
                    "inspection, survives link-preview checks, and is often "
                    "allow-listed by mail filters that trust the domain."
                ),
                impact=(
                    "Credential phishing with a link that genuinely originates "
                    "from your site. Where the application is an OAuth or SSO "
                    "provider, an open redirect on a redirect_uri is a direct "
                    "path to authorisation-code theft and account takeover."
                ),
                remediation_steps=[
                    "Accept only relative paths: reject any value containing "
                    "'://', starting with '//', or resolving to a different host.",
                    "Where external destinations are genuinely needed, keep a "
                    "server-side allow-list and pass an index or key, never a URL.",
                    "Resolve the final URL server-side and re-check the host "
                    "after parsing — attackers use backslashes, encoded "
                    "characters and userinfo tricks to slip past naive checks.",
                    "For OAuth flows, require exact-match registered redirect "
                    "URIs with no wildcards.",
                ],
                verification=(
                    f"Request the URL with `{param}=https://example.org/` and "
                    "confirm the response is not a redirect to example.org."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                ],
                effort=Effort.EASY,
                score_area=AREA_WEBAPP,
                evidence=f"Location -> {resp.headers.get('Location')}",
                request=f"GET {test_url}",
                response=f"{resp.status_code} Location: "
                         f"{resp.headers.get('Location')}",
                verified_by="lopata followed the parameter and read the "
                            "Location header back",
                sources=[MODULE_NAME],
            )
            apply(finding, SeverityFactors(
                impact=Impact.LIMITED,
                exploitability=Exploitability.EASY,
                auth=AuthRequirement.NONE,
                exposure=Exposure.PUBLIC,
                confidence=Confidence.CONFIRMED,
                notes=["impact depends on user interaction: the victim must "
                       "follow the crafted link"],
            ))
            out.append(finding)
            break
    return out


def register():
    from ..core.plugins import web_module
    return web_module('redirect', run, requires_crawl=True, order=90)
