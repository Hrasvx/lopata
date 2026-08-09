"""Content discovery.

"0 URLs discovered" should mean the site really has nothing reachable, not
that the crawler only followed <a href>. This module pulls from every cheap
source available before falling back to guessing:

  robots.txt -> sitemap.xml (recursively) -> HTML links, forms and assets
  -> endpoints referenced inside JavaScript -> SPA route tables
  -> a targeted wordlist of admin panels, API roots and common directories.

Everything guessed is validated against the learned not-found baseline, so a
site that answers 200 for every path does not produce hundreds of phantom URLs.
"""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse
from xml.etree import ElementTree as ET

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

from ..core import async_http
from ..core.async_http import AsyncFetcher
from ..core.baseline import ResponseSnapshot, similarity
from ..core.models import (AREA_SURFACE, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "crawler"
CATEGORY = "Attack Surface"

_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
             ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".webp", ".eot", ".mp3",
             ".avi", ".mov", ".dmg", ".exe")

ADMIN_PATHS = (
    "admin", "admin/", "administrator/", "admin/login", "admin.php",
    "wp-admin/", "wp-login.php", "login", "login.php", "signin", "user/login",
    "cpanel", "phpmyadmin/", "pma/", "adminer.php", "manager/html",
    "webadmin/", "console", "dashboard", "portal", "auth/login",
)

API_PATHS = (
    "api/", "api/v1/", "api/v2/", "graphql", "graphiql", "rest/",
    "swagger.json", "swagger-ui.html", "openapi.json", "api-docs",
    "v1/openapi.json", ".well-known/openid-configuration",
    "actuator", "actuator/health", "actuator/env", "metrics", "health",
)

COMMON_DIRS = (
    "backup/", "backups/", "old/", "tmp/", "temp/", "test/", "dev/", "staging/",
    "uploads/", "files/", "download/", "downloads/", "private/", "internal/",
    "logs/", "log/", "config/", "conf/", "includes/", "inc/", "src/", "docs/",
    ".well-known/", "cgi-bin/", "server-info", "status",
)

# Endpoint-ish strings inside JavaScript.
_JS_URL = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_\-./]{2,120}))["'`]"""
    r"""|(?:fetch|axios(?:\.\w+)?|\.open|url\s*:)\s*\(?\s*["'`]([^"'`\s]{2,200})["'`]""")
_JS_ROUTE = re.compile(
    r"""(?:path|route)\s*:\s*["'`]([^"'`]{1,120})["'`]""")
_HTML_URL = re.compile(
    r"""(?:href|src|action|data-url)\s*=\s*["']([^"'>\s]{1,300})["']""", re.I)

_NOISE_PATH = re.compile(
    r"^/(?:$|#)|^//|\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|map)$"
    r"|^/\*|\s|^/[A-Za-z0-9+/=]{60,}$", re.I)


def run(ctx, phase=None) -> None:
    if BeautifulSoup is None:
        ctx.logger and ctx.logger.warning(
            "beautifulsoup4 missing; falling back to regex link extraction")
    ctx.modules_run.append(MODULE_NAME)

    base = ctx.target
    base_host = (urlparse(base).hostname or "").lower()
    allowed = {base_host} | {s.lower() for s in ctx.subdomains}
    depth_limit = int(ctx.config.get("crawl_depth", 3))

    if phase:
        phase.set_total(ctx.max_pages + 40)

    seeds: list[tuple[str, int]] = [(base + "/", 0)]
    scheme = urlparse(base).scheme
    for sub in sorted(ctx.subdomains)[:20]:
        seeds.append((f"{scheme}://{sub}/", 0))

    robots_paths, sitemaps = _read_robots(ctx, base)
    seeds += [(u, 1) for u in robots_paths]
    seeds += [(u, 1) for u in _read_sitemaps(ctx, base, sitemaps)]
    phase and phase.step(4)

    visited, js_found, guessed = async_http.run(
        _discover(ctx, seeds, allowed, depth_limit, phase))

    phase and phase.done()
    _report(ctx, base, allowed, len(visited), len(robots_paths), len(sitemaps),
            js_found, guessed)


async def _discover(ctx, seeds, allowed, depth_limit, phase):
    """Run BFS, JavaScript mining and content discovery on one async client."""
    async with AsyncFetcher.from_ctx(ctx) as fetcher:
        visited = await _bfs(ctx, fetcher, seeds, allowed, depth_limit, phase)
        js_found = await _crawl_javascript(ctx, fetcher, allowed, phase)
        guessed = await _content_discovery(ctx, fetcher, allowed, phase)
    return visited, js_found, guessed



def _read_robots(ctx, base) -> tuple[list[str], list[str]]:
    """robots.txt is a map of what the owner would rather you did not visit."""
    paths: list[str] = []
    sitemaps: list[str] = []
    url = base.rstrip("/") + "/robots.txt"
    try:
        resp = ctx.session.get(url, timeout=ctx.timeout)
    except requests.RequestException:
        return paths, sitemaps
    if resp.status_code != 200 or "html" in resp.headers.get("Content-Type", ""):
        return paths, sitemaps

    ctx.discovered_urls.add(url)
    disallowed = []
    for line in (resp.text or "").splitlines()[:500]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        if key == "sitemap":
            sitemaps.append(value)
        elif key in ("disallow", "allow") and value != "/":
            candidate = urljoin(base + "/", value.split("*")[0].split("$")[0])
            if candidate.startswith(base) and candidate not in paths:
                paths.append(candidate)
                if key == "disallow":
                    disallowed.append(value)

    if disallowed:
        ctx.logger and ctx.logger.info(
            "robots.txt lists %d disallowed path(s); crawling them",
            len(disallowed))
    return paths[:80], sitemaps[:10]


def _read_sitemaps(ctx, base, declared: list[str]) -> list[str]:
    """Follow sitemap.xml, sitemap indexes and anything robots.txt declared."""
    queue = deque(declared or [])
    for guess in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        queue.append(base.rstrip("/") + guess)

    seen_maps: set[str] = set()
    urls: list[str] = []
    while queue and len(urls) < 500 and len(seen_maps) < 12:
        sm_url = queue.popleft()
        if sm_url in seen_maps:
            continue
        seen_maps.add(sm_url)
        try:
            resp = ctx.session.get(sm_url, timeout=ctx.timeout)
        except requests.RequestException:
            continue
        if resp.status_code != 200 or not resp.text.strip().startswith("<"):
            continue
        ctx.discovered_urls.add(sm_url)
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            continue
        for loc in root.iter():
            if not loc.tag.endswith("loc") or not (loc.text or "").strip():
                continue
            value = loc.text.strip()
            if value.endswith(".xml"):
                queue.append(value)
            elif len(urls) < 500:
                urls.append(value)
    return urls


async def _bfs(ctx, fetcher, seeds, allowed, depth_limit, phase) -> set[str]:
    """Breadth-first walk of HTML, bounded by max_pages and crawl depth.

    Each depth level is fetched concurrently through the async fetcher; links
    extracted from the responses form the next level. This replaces the old
    single-URL-per-thread loop while preserving the max_pages/depth bounds and
    the redirect-following behaviour of the synchronous session.
    """
    seen: set[str] = set()
    queued: set[str] = set()
    frontier: list[tuple[str, int]] = []
    for url, depth in seeds:
        url, _ = urldefrag(url)
        if url in queued or not _in_scope(url, allowed):
            continue
        queued.add(url)
        frontier.append((url, depth))

    while frontier and len(seen) < ctx.max_pages:
        batch: list[tuple[str, int]] = []
        for url, depth in frontier:
            if len(seen) + len(batch) >= ctx.max_pages:
                break
            if url in seen:
                continue
            batch.append((url, depth))
        for url, _ in batch:
            seen.add(url)

        results = dict(await fetcher.get_many([u for u, _ in batch],
                                              allow_redirects=True))
        next_frontier: list[tuple[str, int]] = []
        for url, depth in batch:
            resp = results.get(url)
            phase and phase.step()
            if resp is None:
                continue
            ctx.discovered_urls.add(str(resp.url) if resp.url else url)
            ctype = resp.headers.get("Content-Type", "").lower()
            if "html" not in ctype:
                continue
            body = resp.text or ""
            ctx.page_bodies[url] = body[:200000]
            if depth >= depth_limit:
                continue
            for link in _links_from_html(url, body, ctx):
                if link not in seen and link not in queued and _in_scope(link, allowed):
                    queued.add(link)
                    next_frontier.append((link, depth + 1))
        frontier = next_frontier
    return seen


def _links_from_html(page_url: str, body: str, ctx) -> list[str]:
    out: list[str] = []
    if BeautifulSoup is not None:
        soup = BeautifulSoup(body, "html.parser")
        _extract_forms(ctx, page_url, soup)
        attrs = (("a", "href"), ("link", "href"), ("iframe", "src"),
                 ("form", "action"), ("area", "href"), ("frame", "src"))
        for tag, attr in attrs:
            for el in soup.find_all(tag):
                value = el.get(attr)
                if value:
                    out.append(urljoin(page_url, value))
        for script in soup.find_all("script", src=True):
            ctx._script_urls.add(urljoin(page_url, script["src"]))
        for script in soup.find_all("script", src=False):
            text = script.string or ""
            if text:
                ctx._inline_js.append((page_url, text[:60000]))
    else:
        for match in _HTML_URL.finditer(body):
            out.append(urljoin(page_url, match.group(1)))

    cleaned = []
    for url in out:
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue
        if url.lower().endswith(_SKIP_EXT):
            continue
        cleaned.append(url)
    return cleaned


async def _crawl_javascript(ctx, fetcher, allowed, phase) -> int:
    """Pull endpoint strings out of script files and inline scripts.

    Single-page applications put their entire route table and API surface in
    JavaScript; without this step such a site looks like one URL.
    """
    script_urls = sorted(ctx._script_urls)[:40]
    bodies: list[tuple[str, str]] = list(ctx._inline_js)

    if script_urls:
        for url, resp in await fetcher.get_many(script_urls, allow_redirects=True):
            if resp is not None and resp.status_code == 200:
                bodies.append((url, (resp.text or "")[:400000]))
                ctx.discovered_urls.add(url)
        phase and phase.step(5)

    candidates: set[str] = set()
    routes: set[str] = set()
    for source_url, text in bodies:
        for match in _JS_URL.finditer(text):
            value = match.group(1) or match.group(2) or ""
            if not value or _NOISE_PATH.search(value):
                continue
            if value.startswith("http"):
                candidates.add(value)
            elif value.startswith("/"):
                candidates.add(urljoin(ctx.target + "/", value))
        for match in _JS_ROUTE.finditer(text):
            route = match.group(1)
            if route.startswith("/") and not _NOISE_PATH.search(route):
                routes.add(urljoin(ctx.target + "/", route.split(":")[0]))

    ctx.spa_routes = sorted(routes)[:100]
    found = 0
    for url in sorted(candidates | routes)[:120]:
        if _in_scope(url, allowed) and url not in ctx.discovered_urls:
            ctx.discovered_urls.add(url)
            found += 1
    phase and phase.step(5)
    return found


async def _content_discovery(ctx, fetcher, allowed, phase) -> list[tuple[str, int, str]]:
    """Probe a focused wordlist, validating every hit against the baseline."""
    if not ctx.config.get("content_discovery", True):
        return []

    wordlist = list(ADMIN_PATHS) + list(API_PATHS) + list(COMMON_DIRS)
    extra = ctx.config.get("extra_paths") or []
    wordlist += [str(p) for p in extra]

    baseline = getattr(ctx, "baseline", None)
    base = ctx.target.rstrip("/") + "/"
    hits: list[tuple[str, int, str]] = []

    probe_urls = [urljoin(base, path) for path in wordlist]
    for url, resp in await fetcher.get_many(probe_urls, allow_redirects=False):
        phase and phase.step()
        result = _classify_probe(baseline, url, resp)
        if result is None:
            continue
        hits.append(result)
        ctx.discovered_urls.add(result[0])

    _report_admin_surfaces(ctx, hits)
    return hits


def _classify_probe(baseline, url: str, resp):
    """Decide whether a content-discovery probe response is a real hit.

    A missing response or a 4xx/5xx is nothing; a redirect is reported only when
    it carries a Location; a 2xx/3xx body is compared against the learned
    not-found and root baselines so a soft-404 or a site that answers 200 for
    everything does not manufacture phantom URLs.
    """
    if resp is None or resp.status_code >= 400:
        return None
    if resp.is_redirect:
        location = resp.headers.get("Location", "")
        return (url, resp.status_code, f"redirect -> {location}") \
            if resp.status_code in (301, 302, 307, 308) and location else None
    snap = ResponseSnapshot.capture(resp)
    if baseline is not None:
        if baseline.looks_like_not_found(snap):
            return None
        root = getattr(baseline, "root", None)
        if root is not None and similarity(snap.body, root.body) >= 0.98:
            return None
    title = _title_of(resp.text or "")
    return (url, resp.status_code, title)



_ADMIN_HINT = re.compile("|".join(re.escape(p.strip("/")) for p in ADMIN_PATHS),
                         re.I)


def _report_admin_surfaces(ctx, hits) -> None:
    """An internet-reachable admin panel is an exposure worth naming."""
    panels = [h for h in hits if _ADMIN_HINT.search(urlparse(h[0]).path or "")]
    if not panels:
        return

    listing = "\n".join(f"  {status}  {url}  {title}".rstrip()
                        for url, status, title in panels[:15])
    finding = Finding(
        name=f"Administrative interface reachable from the internet "
             f"({len(panels)} path(s))",
        severity=Severity.INFO, location=panels[0][0],
        description=(
            "One or more administrative or authentication endpoints answer "
            "requests from the public internet:\n\n" + listing + "\n\n"
            "This is not a vulnerability by itself — the panel may be perfectly "
            "well protected — but it is the surface every credential-stuffing "
            "and brute-force campaign aims at, and it is usually cheap to "
            "restrict."
        ),
        remediation="Restrict administrative endpoints to trusted networks.",
        ftype=FindingType.EXPOSURE,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{len(panels)} administrative endpoint(s) are publicly reachable.",
        risk="Public admin panels receive continuous automated credential "
             "attacks. They also disclose the software in use, and their login "
             "responses often allow username enumeration.",
        impact="A single weak or reused administrator password yields full "
               "control of the application, and in many stacks, code execution "
               "on the server.",
        remediation_steps=[
            "Restrict the admin paths by source IP at the reverse proxy, or "
            "place them behind a VPN.",
            "Enforce multi-factor authentication for administrative accounts.",
            "Rate-limit and lock out repeated failed logins.",
            "Ensure failed logins return an identical response regardless of "
            "whether the username exists.",
        ],
        verification="From an unlisted network, request the admin path and "
                     "confirm it returns 403 rather than a login form.",
        effort=Effort.EASY,
        score_area=AREA_SURFACE,
        evidence=listing[:800],
        related_locations=[u for u, _, _ in panels[1:15]],
        verified_by="lopata requested each path and received a non-baseline response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.LIMITED, exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
    ))
    ctx.add_finding(finding)


def _report(ctx, base, allowed, visited, robots_n, sitemaps_n, js_n, guessed) -> None:
    sources = []
    if robots_n:
        sources.append(f"{robots_n} path(s) from robots.txt")
    if sitemaps_n:
        sources.append(f"{sitemaps_n} sitemap(s)")
    if js_n:
        sources.append(f"{js_n} endpoint(s) referenced in JavaScript")
    if guessed:
        sources.append(f"{len(guessed)} path(s) confirmed by targeted probing")
    if getattr(ctx, "spa_routes", None):
        sources.append(f"{len(ctx.spa_routes)} client-side route(s)")

    ctx.add_finding(Finding(
        name="Attack surface mapped",
        severity=Severity.INFO, location=base,
        description=(
            f"Content discovery reached {len(ctx.discovered_urls)} distinct URL(s) "
            f"and {len(ctx.forms)} form(s) across {len(allowed)} host(s), "
            f"visiting {visited} page(s) directly."
            + (" Sources: " + "; ".join(sources) + "." if sources else "")
        ),
        remediation="Confirm every reachable endpoint is intended to be public.",
        ftype=FindingType.INVENTORY,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{len(ctx.discovered_urls)} URL(s) and {len(ctx.forms)} form(s) "
                "discovered.",
        risk="Endpoints the owner has forgotten about are the ones that do not "
             "get patched, reviewed or monitored.",
        impact="Informational — this section establishes what the rest of the "
               "assessment was performed against.",
        remediation_steps=[
            "Review the URL inventory in the appendix against your intended "
            "public surface.",
            "Remove or restrict anything that should not be reachable.",
        ],
        verification="Compare the discovered URL list with your routing "
                     "configuration.",
        effort=Effort.MODERATE,
        score_area=AREA_SURFACE,
        confidence=Confidence.INFORMATIONAL,
        evidence="; ".join(sources)[:500],
        sources=[MODULE_NAME],
    ))



def _in_scope(url: str, allowed: set[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    return host in allowed


_TITLE = re.compile(r"<title[^>]*>(.{0,120}?)</title>", re.I | re.S)


def _title_of(body: str) -> str:
    match = _TITLE.search(body or "")
    return " ".join(match.group(1).split()) if match else ""


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


def register():
    from ..core.plugins import web_module
    return web_module('crawler', run, requires_crawl=False, order=0)
