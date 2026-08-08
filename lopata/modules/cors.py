"""Cross-Origin Resource Sharing configuration.

Every positive result here is verified by lopata itself: it sends a hostile
Origin and reads back what the server was willing to allow, so these findings
carry Confirmed confidence rather than a header-shape guess.
"""

from __future__ import annotations

import requests

from ..core.models import (AREA_HTTP, Confidence, Effort, Finding, FindingType,
                           PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "cors"
CATEGORY = "CORS"

EVIL_ORIGIN = "https://lopata-cors-probe.example"

_REFS = [
    "https://developer.mozilla.org/docs/Web/HTTP/CORS",
    "https://portswigger.net/web-security/cors",
]


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    targets = [ctx.target + "/"] + list(ctx.discovered_urls)[:20]
    checked: set[str] = set()
    if phase:
        phase.set_total(len(targets))

    any_cors = False
    for url in targets:
        if url in checked:
            phase and phase.step()
            continue
        checked.add(url)
        if _check(ctx, url):
            any_cors = True
        phase and phase.step()
    phase and phase.done()

    if not any_cors:
        ctx.add_passed(PassedCheck(
            name="No permissive CORS policy detected",
            detail=f"A hostile Origin ({EVIL_ORIGIN}) was sent to "
                   f"{len(checked)} endpoint(s); none reflected it or returned "
                   "a wildcard with credentials.",
            source=MODULE_NAME, location=ctx.target, score_area=AREA_HTTP))


def _check(ctx, url) -> bool:
    """Returns True if a permissive policy was found at this URL."""
    try:
        resp = ctx.session.get(url, timeout=ctx.timeout,
                               headers={"Origin": EVIL_ORIGIN})
    except requests.RequestException:
        return False

    headers = {k.lower(): v for k, v in resp.headers.items()}
    acao = headers.get("access-control-allow-origin")
    acac = (headers.get("access-control-allow-credentials") or "").lower() == "true"
    if acao is None:
        return False

    evidence = (f"Request Origin: {EVIL_ORIGIN}\n"
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}")

    if acao == EVIL_ORIGIN:
        _reflected(ctx, url, acac, evidence)
        return True
    if acao == "*" and acac:
        _wildcard_creds(ctx, url, evidence)
        return True
    if acao == "null":
        _null_origin(ctx, url, evidence)
        return True
    return False


def _reflected(ctx, url, acac, evidence) -> None:
    finding = Finding(
        name="CORS policy reflects any Origin",
        severity=Severity.INFO, location=url,
        description=(
            "The server echoed an arbitrary attacker-supplied Origin back in "
            "Access-Control-Allow-Origin"
            + (" together with Access-Control-Allow-Credentials: true."
               if acac else ".")
            + "\n\nReflecting the Origin header is equivalent to allowing every "
              "site on the internet, because the value is entirely under the "
              "requester's control. lopata verified this by sending an Origin "
              "that cannot legitimately be on any allow-list."
        ),
        remediation="Validate Origin against a fixed allow-list; never echo it back.",
        ftype=FindingType.CONFIRMED_VULN,
        module=MODULE_NAME, category=CATEGORY,
        summary="Arbitrary origins are permitted to read responses"
                + (" with credentials attached." if acac else "."),
        risk=(
            "Any website a victim visits can issue requests to this endpoint "
            + ("with the victim's cookies attached and read the full response. "
               "This bypasses the same-origin policy entirely for authenticated "
               "data." if acac else
               "and read the response. For unauthenticated endpoints this is "
               "often intentional — but it must be a decision, not a side "
               "effect of reflecting a header.")
        ),
        impact=(
            "An attacker-controlled page can exfiltrate whatever this endpoint "
            "returns to the logged-in user: profile data, tokens, internal API "
            "responses — silently, in the background, with no user interaction "
            "beyond visiting the page."
            if acac else
            "Any origin can read the response body. The impact depends on "
            "whether this endpoint ever returns data that is not already public."
        ),
        remediation_steps=[
            "Replace the reflection with an explicit allow-list: compare the "
            "Origin header against known values and echo only on an exact match.",
            "Send `Access-Control-Allow-Credentials: true` only for origins on "
            "that list, never alongside a reflected or wildcard value.",
            "Include `Vary: Origin` so caches do not serve one origin's "
            "response to another.",
            "Prefer same-origin API paths where cross-origin access is not a "
            "product requirement.",
        ],
        verification=(
            f"`curl -sI -H 'Origin: {EVIL_ORIGIN}' {url}` must not return that "
            "origin in Access-Control-Allow-Origin."
        ),
        references=_REFS,
        effort=Effort.EASY,
        score_area=AREA_HTTP,
        evidence=evidence,
        request=f"GET {url}\nOrigin: {EVIL_ORIGIN}",
        response=evidence,
        verified_by="lopata sent a hostile Origin and observed it reflected",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS if acac else Impact.LIMITED,
        exploitability=Exploitability.EASY,
        auth=AuthRequirement.USER if acac else AuthRequirement.NONE,
        exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
        notes=(["credentials are permitted cross-origin, so authenticated data "
                "is readable"] if acac else
               ["no credentials are permitted, which limits this to data the "
                "endpoint would return anonymously"]),
    ))
    ctx.add_finding(finding)


def _wildcard_creds(ctx, url, evidence) -> None:
    finding = Finding(
        name="CORS wildcard combined with credentials",
        severity=Severity.INFO, location=url,
        description=(
            "The endpoint returns `Access-Control-Allow-Origin: *` together "
            "with `Access-Control-Allow-Credentials: true`. Browsers reject "
            "this combination, so the practical effect today is that "
            "credentialed cross-origin requests fail — but the configuration "
            "states an intent to share authenticated data with every origin, "
            "and non-browser clients and proxies do not enforce the same rule."
        ),
        remediation="Never pair a wildcard origin with credentials.",
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary="Wildcard ACAO is paired with Allow-Credentials.",
        risk="The policy expresses an unsafe intent and is likely masking a "
             "broken feature; a later 'fix' that replaces `*` with origin "
             "reflection converts this directly into full cross-origin data "
             "disclosure.",
        impact="Currently blocked by browsers. If the wildcard is replaced with "
               "reflection, any site could read authenticated responses.",
        remediation_steps=[
            "Decide whether this endpoint should be readable cross-origin at all.",
            "If yes and it needs credentials, list the specific origins.",
            "If yes without credentials, drop the Allow-Credentials header.",
            "Add `Vary: Origin`.",
        ],
        verification=f"`curl -sI -H 'Origin: {EVIL_ORIGIN}' {url}` should not "
                     "return both headers together.",
        references=_REFS,
        effort=Effort.TRIVIAL,
        score_area=AREA_HTTP,
        evidence=evidence,
        response=evidence,
        verified_by="lopata observed both headers on the same response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.INFORMATION, exploitability=Exploitability.THEORETICAL,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
    ))
    ctx.add_finding(finding)


def _null_origin(ctx, url, evidence) -> None:
    finding = Finding(
        name="CORS policy trusts the 'null' origin",
        severity=Severity.INFO, location=url,
        description=(
            "The endpoint allows the `null` origin. `null` is not a specific "
            "site — it is what the browser sends from sandboxed iframes, "
            "redirected requests and local files, all of which an attacker can "
            "produce at will from their own page."
        ),
        remediation="Remove `null` from the allowed origins.",
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary="The 'null' origin is accepted, which any site can produce.",
        risk="An attacker embeds a sandboxed iframe on their own page; the "
             "request it makes carries Origin: null and is accepted, defeating "
             "the allow-list.",
        impact="Cross-origin read access to this endpoint's responses from any "
               "attacker-controlled page, subject to whether credentials are "
               "also permitted.",
        remediation_steps=[
            "Remove `null` from the allow-list — there is no legitimate case "
            "for trusting it on a public web application.",
            "If a sandboxed context genuinely needs access, give it a real "
            "origin instead of relying on `null`.",
        ],
        verification=f"`curl -sI -H 'Origin: null' {url}` must not return "
                     "`Access-Control-Allow-Origin: null`.",
        references=_REFS,
        effort=Effort.TRIVIAL,
        score_area=AREA_HTTP,
        evidence=evidence,
        response=evidence,
        verified_by="lopata observed the null origin being allowed",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.LIMITED, exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.USER, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
    ))
    ctx.add_finding(finding)


def register():
    from ..core.plugins import web_module
    return web_module('cors', run, requires_crawl=True, order=60)
