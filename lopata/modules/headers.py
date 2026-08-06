from __future__ import annotations

import requests

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "headers"
CATEGORY = "Security Headers"


CHECKS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Without a CSP the browser has no allow-list for scripts/resources, so "
        "injected content (XSS) executes freely.",
        "Define a restrictive policy, e.g. \"default-src 'self'; object-src "
        "'none'; base-uri 'none'\", and tighten from there.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Missing HSTS lets a network attacker downgrade to HTTP (SSL-strip) and "
        "capture cookies/traffic.",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "over HTTPS; add 'preload' once verified.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Without X-Frame-Options (or CSP frame-ancestors) the site can be framed "
        "invisibly for clickjacking.",
        "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or CSP "
        "'frame-ancestors 'none''.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing 'nosniff' lets browsers MIME-sniff responses, which can turn an "
        "uploaded file into executable script.",
        "Set 'X-Content-Type-Options: nosniff' on all responses.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Without a Referrer-Policy, full URLs (possibly containing tokens/IDs) "
        "leak to third parties via the Referer header.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "No Permissions-Policy means powerful browser features (camera, mic, "
        "geolocation) are not explicitly restricted.",
        "Send a Permissions-Policy disabling unused features, e.g. "
        "'geolocation=(), camera=(), microphone=()'.",
    ),
}


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException as exc:
        ctx.logger and ctx.logger.warning("headers: request failed: %s", exc)
        return
    phase and phase.done()

    present = {k.lower(): v for k, v in resp.headers.items()}
    for header, (sev, why, fix) in CHECKS.items():

        if header == "strict-transport-security" and not ctx.target.startswith("https"):
            continue
        if header not in present:
            ctx.add_finding(Finding(
                name=f"Missing header: {_title(header)}",
                severity=sev, location=resp.url,
                description=why, remediation=fix,
                module=MODULE_NAME, category=CATEGORY,
                evidence="header absent from root response",
                confidence=Confidence.FIRM,
            ))
        else:
            _quality_check(ctx, header, present[header], resp.url)

    _info_leak_headers(ctx, present, resp.url)


def _quality_check(ctx, header, value, url) -> None:
    v = value.lower()
    if header == "strict-transport-security":
        import re
        m = re.search(r"max-age=(\d+)", v)
        if m and int(m.group(1)) < 15552000:
            ctx.add_finding(Finding(
                name="Weak HSTS max-age",
                severity=Severity.LOW, location=url,
                description=f"HSTS max-age is {m.group(1)}s (< 180 days), leaving "
                            "a downgrade window.",
                remediation="Use max-age=31536000 (1 year) with includeSubDomains.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=value, confidence=Confidence.FIRM))
    if header == "content-security-policy":
        if "unsafe-inline" in v or "unsafe-eval" in v:
            ctx.add_finding(Finding(
                name="Weak CSP (unsafe-inline/unsafe-eval)",
                severity=Severity.LOW, location=url,
                description="CSP permits inline scripts or eval, which largely "
                            "defeats its XSS protection.",
                remediation="Remove 'unsafe-inline'/'unsafe-eval'; use nonces or "
                            "hashes for required inline scripts.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=value[:300], confidence=Confidence.FIRM))


_LEAKY = {
    "server": "Server banner reveals software/version, aiding targeted exploits.",
    "x-powered-by": "X-Powered-By reveals the backend framework/version.",
    "x-aspnet-version": "Exposes the exact ASP.NET version.",
    "x-generator": "Reveals the CMS/generator and often its version.",
}


def _info_leak_headers(ctx, present, url) -> None:
    for header, why in _LEAKY.items():
        if header in present and present[header].strip():
            ctx.add_finding(Finding(
                name=f"Information disclosure: {_title(header)}",
                severity=Severity.INFO, location=url,
                description=why + f" Value: {present[header]!r}.",
                remediation=f"Suppress or genericise the {_title(header)} header.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=present[header][:120], confidence=Confidence.FIRM))


def _title(h: str) -> str:
    return "-".join(p.upper() if p.lower() in ("csp",) else p.capitalize()
                    for p in h.split("-"))
