from __future__ import annotations

import requests

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "cors"
CATEGORY = "CORS"

EVIL_ORIGIN = "https://lopata-cors-probe.example"


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    targets = [ctx.target + "/"]
    targets += [u for u in list(ctx.discovered_urls)[:20]]
    checked = set()
    if phase:
        phase.set_total(len(targets))
    for url in targets:
        if url in checked:
            phase and phase.step()
            continue
        checked.add(url)
        _check(ctx, url)
        phase and phase.step()
    phase and phase.done()


def _check(ctx, url) -> None:
    try:
        resp = ctx.session.get(url, timeout=ctx.timeout,
                               headers={"Origin": EVIL_ORIGIN})
    except requests.RequestException:
        return
    h = {k.lower(): v for k, v in resp.headers.items()}
    acao = h.get("access-control-allow-origin")
    acac = (h.get("access-control-allow-credentials") or "").lower() == "true"
    if acao is None:
        return

    if acao == EVIL_ORIGIN:
        sev = Severity.HIGH if acac else Severity.MEDIUM
        ctx.add_finding(Finding(
            name="CORS reflects arbitrary Origin",
            severity=sev, location=url,
            description=(
                "The server reflects any supplied Origin in "
                "Access-Control-Allow-Origin"
                + (" together with Allow-Credentials: true, letting a malicious "
                   "site read authenticated responses." if acac else
                   ", allowing any site to read responses.")
            ),
            remediation="Validate Origin against a strict allow-list; never "
                        "reflect it. Only send Allow-Credentials for trusted "
                        "origins, never with '*'.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=f"ACAO: {acao}  ACAC: {acac}",
            confidence=Confidence.CONFIRMED))
    elif acao == "*" and acac:
        ctx.add_finding(Finding(
            name="CORS wildcard with credentials",
            severity=Severity.HIGH, location=url,
            description="Access-Control-Allow-Origin '*' combined with "
                        "credentials is invalid per spec and, where honoured, "
                        "exposes authenticated data.",
            remediation="Never pair '*' with Allow-Credentials; use an explicit "
                        "trusted origin.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=f"ACAO: * ACAC: true", confidence=Confidence.CONFIRMED))
    elif acao == "null":
        ctx.add_finding(Finding(
            name="CORS trusts 'null' origin",
            severity=Severity.MEDIUM, location=url,
            description="Allowing the 'null' origin lets sandboxed iframes and "
                        "some local files bypass the same-origin policy.",
            remediation="Do not allow the 'null' origin; use an explicit "
                        "allow-list.",
            module=MODULE_NAME, category=CATEGORY,
            evidence="ACAO: null", confidence=Confidence.FIRM))
