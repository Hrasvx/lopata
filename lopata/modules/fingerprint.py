"""Passive technology fingerprinting.

Runs regardless of whether whatweb is installed, and merges into the same
registry so external and internal detections corroborate each other — a
technology seen by two sources is promoted to High confidence automatically.

Everything here is passive: headers, cookies, markup and script URLs that the
site volunteers. Nothing is probed for, and nothing here is a finding on its
own; the output is the report's Technology Summary.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from ..core.models import (AREA_PATCH, Confidence, Effort, Finding, FindingType,
                           Severity, Technology)

MODULE_NAME = "fingerprint"
CATEGORY = "Technology Fingerprint"


# (regex, technology name, category, version-capturing group or 0)
_SERVER_PATTERNS = [
    (re.compile(r"Apache(?:/([\d.]+))?", re.I), "Apache HTTP Server", "Web Server", 1),
    (re.compile(r"nginx(?:/([\d.]+))?", re.I), "nginx", "Web Server", 1),
    (re.compile(r"Microsoft-IIS(?:/([\d.]+))?", re.I), "Microsoft IIS", "Web Server", 1),
    (re.compile(r"LiteSpeed(?:/([\d.]+))?", re.I), "LiteSpeed", "Web Server", 1),
    (re.compile(r"lighttpd(?:/([\d.]+))?", re.I), "lighttpd", "Web Server", 1),
    (re.compile(r"Caddy(?:/([\d.]+))?", re.I), "Caddy", "Web Server", 1),
    (re.compile(r"openresty(?:/([\d.]+))?", re.I), "OpenResty", "Web Server", 1),
    (re.compile(r"gunicorn(?:/([\d.]+))?", re.I), "Gunicorn", "Web Server", 1),
    (re.compile(r"Werkzeug(?:/([\d.]+))?", re.I), "Werkzeug", "Framework", 1),
    (re.compile(r"Jetty\(?([\d.]+)?", re.I), "Jetty", "Web Server", 1),
    (re.compile(r"(?:Apache-)?Coyote|Tomcat(?:/([\d.]+))?", re.I), "Apache Tomcat", "Web Server", 1),
    (re.compile(r"Cowboy", re.I), "Cowboy", "Web Server", 0),
]

_POWERED_PATTERNS = [
    (re.compile(r"PHP/([\d.]+)", re.I), "PHP", "Language", 1),
    (re.compile(r"ASP\.NET", re.I), "ASP.NET", "Framework", 0),
    (re.compile(r"Express", re.I), "Express", "Framework", 0),
    (re.compile(r"Next\.js", re.I), "Next.js", "Framework", 0),
    (re.compile(r"Nuxt", re.I), "Nuxt", "Framework", 0),
    (re.compile(r"Servlet/([\d.]+)", re.I), "Java Servlet", "Language", 1),
    (re.compile(r"Phusion Passenger(?:\s*([\d.]+))?", re.I), "Phusion Passenger", "Web Server", 1),
]

# Session cookie names are one of the most reliable passive language tells.
_COOKIE_TECH = {
    "phpsessid": ("PHP", "Language"),
    "jsessionid": ("Java", "Language"),
    "asp.net_sessionid": ("ASP.NET", "Framework"),
    "aspxauth": ("ASP.NET", "Framework"),
    "laravel_session": ("Laravel", "Framework"),
    "xsrf-token": ("Laravel", "Framework"),
    "_rails_session": ("Ruby on Rails", "Framework"),
    "_session_id": ("Ruby on Rails", "Framework"),
    "csrftoken": ("Django", "Framework"),
    "sessionid": ("Django", "Framework"),
    "connect.sid": ("Express", "Framework"),
    "ci_session": ("CodeIgniter", "Framework"),
    "symfony": ("Symfony", "Framework"),
    "wordpress_logged_in": ("WordPress", "CMS"),
    "wp-settings": ("WordPress", "CMS"),
    "joomla_user_state": ("Joomla", "CMS"),
    "sid": ("Generic session", "Other"),
    "incap_ses": ("Imperva Incapsula", "WAF"),
    "visid_incap": ("Imperva Incapsula", "WAF"),
    "__cfduid": ("Cloudflare", "CDN / Proxy"),
    "__cf_bm": ("Cloudflare", "CDN / Proxy"),
    "awsalb": ("AWS Application Load Balancer", "CDN / Proxy"),
}

# CDN / WAF fingerprints keyed on response headers.
_HEADER_TECH = {
    "cf-ray": ("Cloudflare", "CDN / Proxy"),
    "cf-cache-status": ("Cloudflare", "CDN / Proxy"),
    "x-amz-cf-id": ("Amazon CloudFront", "CDN / Proxy"),
    "x-amz-request-id": ("Amazon S3", "CDN / Proxy"),
    "x-served-by": ("Fastly", "CDN / Proxy"),
    "fastly-io-info": ("Fastly", "CDN / Proxy"),
    "x-akamai-transformed": ("Akamai", "CDN / Proxy"),
    "x-cache": ("Caching proxy", "CDN / Proxy"),
    "x-sucuri-id": ("Sucuri", "WAF"),
    "x-sucuri-cache": ("Sucuri", "WAF"),
    "x-mod-security": ("ModSecurity", "WAF"),
    "x-waf-event-info": ("Generic WAF", "WAF"),
    "x-vercel-id": ("Vercel", "CDN / Proxy"),
    "x-nf-request-id": ("Netlify", "CDN / Proxy"),
    "x-github-request-id": ("GitHub Pages", "CDN / Proxy"),
    "x-shopify-stage": ("Shopify", "CMS"),
    "x-drupal-cache": ("Drupal", "CMS"),
    "x-drupal-dynamic-cache": ("Drupal", "CMS"),
    "x-generator": ("", "Other"),
    "x-redirect-by": ("", "Other"),
}

# Body/markup fingerprints.
_BODY_PATTERNS = [
    (re.compile(r"/wp-content/|/wp-includes/|wp-json", re.I), "WordPress", "CMS"),
    (re.compile(r"/sites/(?:default|all)/files/|Drupal\.settings", re.I), "Drupal", "CMS"),
    (re.compile(r"/media/jui/|option=com_|Joomla!", re.I), "Joomla", "CMS"),
    (re.compile(r"typo3temp|typo3conf", re.I), "TYPO3", "CMS"),
    (re.compile(r"Mage\.Cookies|/static/version\d+/frontend/", re.I), "Magento", "CMS"),
    (re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I), "Shopify", "CMS"),
    (re.compile(r"ghost-sdk|/assets/built/", re.I), "Ghost", "CMS"),
    (re.compile(r"__NEXT_DATA__|/_next/static/", re.I), "Next.js", "Framework"),
    (re.compile(r"__NUXT__|/_nuxt/", re.I), "Nuxt", "Framework"),
    (re.compile(r"ng-version=|ng-app|angular\.min\.js", re.I), "Angular", "Framework"),
    (re.compile(r"data-reactroot|react(?:-dom)?(?:\.min)?\.js", re.I), "React", "Framework"),
    (re.compile(r"vue(?:\.min)?\.js|data-v-[0-9a-f]{8}", re.I), "Vue.js", "Framework"),
    (re.compile(r"svelte-[0-9a-z]{6}", re.I), "Svelte", "Framework"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django", "Framework"),
    (re.compile(r"__RequestVerificationToken", re.I), "ASP.NET", "Framework"),
    (re.compile(r"cdnjs\.cloudflare\.com", re.I), "cdnjs", "CDN / Proxy"),
]

# Versioned JavaScript libraries from script URLs.
_JS_LIB = re.compile(
    r"/((?:jquery(?:-ui)?|bootstrap|angular|react|vue|lodash|underscore|moment|"
    r"d3|three|axios|handlebars|backbone|ember|swiper|slick|gsap))"
    r"[.\-/]?(?:min\.)?(?:js)?[.\-/]?v?(\d+(?:\.\d+){1,2})?", re.I)

_META_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,120})["']""",
    re.I)

_OS_HINT = re.compile(
    r"\((Ubuntu|Debian|CentOS|Red Hat|Fedora|Win32|Win64|Unix|FreeBSD|Alpine)[^)]*\)",
    re.I)


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException as exc:
        ctx.logger and ctx.logger.warning("fingerprint: request failed: %s", exc)
        return
    phase and phase.done()

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text or ""

    _from_headers(ctx, headers)
    _from_cookies(ctx, resp, headers)
    _from_body(ctx, body)
    _from_scripts(ctx, body)
    _from_other_pages(ctx)
    _report(ctx)


def _add(ctx, name, version, category, evidence, confidence=Confidence.MEDIUM):
    if not name:
        return
    ctx.add_technology(Technology(
        name=name, version=version or "", category=category,
        sources=[MODULE_NAME], confidence=confidence, evidence=evidence[:200]))


def _from_headers(ctx, headers) -> None:
    server = headers.get("server", "")
    for pattern, name, category, group in _SERVER_PATTERNS:
        match = pattern.search(server)
        if match:
            version = match.group(group) if group and match.lastindex else ""
            _add(ctx, name, version or "", category, f"Server: {server}",
                 # A Server header is self-reported; treat it as a weak signal.
                 Confidence.LOW if not version else Confidence.MEDIUM)

    os_match = _OS_HINT.search(server)
    if os_match:
        _add(ctx, os_match.group(1), "", "Operating System",
             f"Server header discloses the distribution: {server}",
             Confidence.LOW)

    powered = " ".join(v for k, v in headers.items()
                       if k in ("x-powered-by", "x-aspnet-version",
                                "x-aspnetmvc-version", "x-runtime"))
    for pattern, name, category, group in _POWERED_PATTERNS:
        match = pattern.search(powered)
        if match:
            version = match.group(group) if group and match.lastindex else ""
            _add(ctx, name, version or "", category, f"X-Powered-By: {powered}")

    if headers.get("x-aspnet-version"):
        _add(ctx, "ASP.NET", headers["x-aspnet-version"], "Framework",
             f"X-AspNet-Version: {headers['x-aspnet-version']}")

    for header, (name, category) in _HEADER_TECH.items():
        if header not in headers:
            continue
        value = headers[header]
        if not name:
            # x-generator / x-redirect-by carry the product name themselves.
            _add(ctx, value.split("/")[0].strip(), "", "CMS",
                 f"{header}: {value}")
            continue
        _add(ctx, name, "", category, f"{header}: {value}")


def _from_cookies(ctx, resp, headers) -> None:
    names = [c.name for c in resp.cookies]
    raw = headers.get("set-cookie", "")
    for cookie_name in names or re.findall(r"(?:^|,\s*)([A-Za-z0-9_.\-]+)=", raw):
        key = cookie_name.strip().lower()
        for marker, (name, category) in _COOKIE_TECH.items():
            if key == marker or key.startswith(marker):
                _add(ctx, name, "", category, f"cookie name: {cookie_name}")


def _from_body(ctx, body: str) -> None:
    head = body[:200000]
    generator = _META_GENERATOR.search(head)
    if generator:
        value = generator.group(1).strip()
        version = ""
        version_match = re.search(r"([\d.]{2,})", value)
        if version_match:
            version = version_match.group(1)
        _add(ctx, re.split(r"[\d]", value)[0].strip(" -"), version, "CMS",
             f"<meta name=generator> {value}", Confidence.MEDIUM)

    for pattern, name, category in _BODY_PATTERNS:
        match = pattern.search(head)
        if match:
            _add(ctx, name, "", category,
                 f"page markup matched {match.group(0)[:60]!r}")


def _from_scripts(ctx, body: str) -> None:
    for match in _JS_LIB.finditer(body[:200000]):
        name = match.group(1).lower()
        version = match.group(2) or ""
        pretty = {"jquery": "jQuery", "jquery-ui": "jQuery UI",
                  "bootstrap": "Bootstrap", "d3": "D3.js",
                  "vue": "Vue.js", "gsap": "GSAP"}.get(name, name.capitalize())
        _add(ctx, pretty, version, "JavaScript Library",
             f"script reference: {match.group(0)[:80]}")


def _from_other_pages(ctx) -> None:
    """Cheap second look at pages the crawler already downloaded."""
    for url, body in list(ctx.page_bodies.items())[:15]:
        for pattern, name, category in _BODY_PATTERNS:
            if pattern.search(body[:80000]):
                _add(ctx, name, "", category,
                     f"markup on {urlparse(url).path or '/'}")


def _report(ctx) -> None:
    if not ctx.technologies:
        return
    grouped: dict[str, list[str]] = {}
    for tech in ctx.technologies.values():
        grouped.setdefault(tech.category, []).append(tech.display)

    lines = [f"{category}: {', '.join(sorted(items))}"
             for category, items in sorted(grouped.items())]
    versioned = [t for t in ctx.technologies.values() if t.version]

    ctx.add_finding(Finding(
        name=f"Technology stack identified ({len(ctx.technologies)} components)",
        severity=Severity.INFO, location=ctx.target,
        description=(
            "Passive fingerprinting identified the following stack:\n\n"
            + "\n".join(lines)
            + "\n\nThis is inventory, not a defect. It matters because it "
              "determines which advisories apply to this host, and because "
              f"{len(versioned)} component(s) disclose an exact version — which "
              "lets an attacker check applicability without touching the site."
        ),
        remediation="Keep an accurate inventory and suppress unnecessary version "
                    "disclosure.",
        ftype=FindingType.INVENTORY,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{len(ctx.technologies)} technologies fingerprinted, "
                f"{len(versioned)} with a disclosed version.",
        risk="Precise version disclosure lets an attacker select working "
             "exploits offline, before generating any traffic you could detect.",
        impact="Informational on its own; it shortens an attacker's "
               "reconnaissance phase and drives which CVEs are worth checking.",
        remediation_steps=[
            "Suppress version numbers in Server and X-Powered-By headers "
            "(`ServerTokens Prod` in Apache, `server_tokens off;` in nginx, "
            "`expose_php = Off` in php.ini).",
            "Track each listed component in your patch process.",
            "Remove `<meta name=\"generator\">` tags emitted by the CMS.",
        ],
        verification="`curl -sI <url>` should show a generic Server value with "
                     "no version, and no X-Powered-By header.",
        effort=Effort.TRIVIAL,
        score_area=AREA_PATCH,
        confidence=Confidence.INFORMATIONAL,
        evidence="\n".join(lines)[:1200],
        sources=[MODULE_NAME],
    ))
