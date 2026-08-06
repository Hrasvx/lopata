from __future__ import annotations

import requests

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "clickjacking"
CATEGORY = "Clickjacking"


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException:
        return
    phase and phase.done()

    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    has_fa = "frame-ancestors" in csp.lower()

    if not xfo and not has_fa:
        ctx.add_finding(Finding(
            name="No clickjacking protection",
            severity=Severity.MEDIUM, location=resp.url,
            description="Neither X-Frame-Options nor a CSP frame-ancestors "
                        "directive is set, so the page can be embedded in a "
                        "hidden iframe and used for clickjacking.",
            remediation="Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and a CSP "
                        "'frame-ancestors 'none''.",
            module=MODULE_NAME, category=CATEGORY,
            evidence="no X-Frame-Options, no CSP frame-ancestors",
            confidence=Confidence.FIRM))
    elif xfo and xfo.lower() not in ("deny", "sameorigin") and not has_fa:
        ctx.add_finding(Finding(
            name="Weak X-Frame-Options value",
            severity=Severity.LOW, location=resp.url,
            description=f"X-Frame-Options is set to {xfo!r}, which is not a "
                        "recognised protective value (DENY/SAMEORIGIN).",
            remediation="Use 'X-Frame-Options: DENY' or SAMEORIGIN, ideally "
                        "alongside CSP frame-ancestors.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=xfo, confidence=Confidence.FIRM))
