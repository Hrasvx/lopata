"""Framing protection.

Owns both X-Frame-Options and the CSP frame-ancestors directive, because the
site is protected if *either* is set correctly — checking them separately
produces a false positive whenever a site has modernised to CSP only.
"""

from __future__ import annotations

import re

import requests

from ..core.models import (AREA_HTTP, Confidence, Effort, Finding, FindingType,
                           PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "clickjacking"
CATEGORY = "Clickjacking"

_FRAME_ANCESTORS = re.compile(r"frame-ancestors\s+([^;]+)", re.I)

_RISK = (
    "Nothing stops another website from loading this page inside a transparent "
    "iframe, positioning it under a decoy interface, and harvesting the user's "
    "clicks. The victim sees the attacker's page; the browser sends "
    "authenticated requests to this one."
)
_IMPACT = (
    "Any single-click state change an authenticated user can make — approving a "
    "payment, changing an email address, granting OAuth consent, deleting "
    "content — can be triggered without the user's knowledge. No injection flaw "
    "is required; the application behaves exactly as designed."
)
_STEPS = [
    "Send `Content-Security-Policy: frame-ancestors 'none'` — this is the "
    "directive current browsers actually enforce.",
    "Send `X-Frame-Options: DENY` alongside it for older clients.",
    "If partners legitimately embed the page, name them explicitly: "
    "`frame-ancestors https://partner.example` — do not fall back to "
    "SAMEORIGIN as a shortcut.",
    "For genuinely sensitive one-click actions, require a confirmation step "
    "that cannot be satisfied by a single framed click.",
]
_VERIFY = (
    "Save an HTML file containing `<iframe src=\"<target>\"></iframe>`, open it "
    "from a different origin, and confirm the browser refuses to render the "
    "frame (a console message naming the policy should appear)."
)
_REFS = [
    "https://developer.mozilla.org/docs/Web/HTTP/Headers/"
    "Content-Security-Policy/frame-ancestors",
    "https://owasp.org/www-community/attacks/Clickjacking",
]


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException:
        return
    phase and phase.done()

    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = (headers.get("x-frame-options") or "").strip()
    csp = headers.get("content-security-policy") or ""
    ancestors = _FRAME_ANCESTORS.search(csp)
    ancestors_value = (ancestors.group(1).strip() if ancestors else "")

    protected_by_csp = bool(ancestors_value) and ancestors_value not in ("*",)
    protected_by_xfo = xfo.lower() in ("deny", "sameorigin")

    if protected_by_csp or protected_by_xfo:
        detail = "; ".join(x for x in (
            f"X-Frame-Options: {xfo}" if protected_by_xfo else "",
            f"CSP frame-ancestors {ancestors_value}" if protected_by_csp else "",
        ) if x)
        ctx.add_passed(PassedCheck(
            name="Framing protection is in place",
            detail=detail, source=MODULE_NAME, location=resp.url,
            score_area=AREA_HTTP))
        if not protected_by_csp:
            _weak_only_xfo(ctx, resp.url, xfo)
        return

    if xfo and not protected_by_xfo:
        _invalid_xfo(ctx, resp.url, xfo, ancestors_value)
        return

    finding = Finding(
        name="No clickjacking protection",
        severity=Severity.INFO, location=resp.url,
        description=(
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is "
            "present, so the page may be framed by any origin.\n\n" + _RISK
        ),
        remediation=_STEPS[0],
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary="The page can be framed by any origin.",
        risk=_RISK, impact=_IMPACT,
        remediation_steps=_STEPS, verification=_VERIFY, references=_REFS,
        effort=Effort.TRIVIAL, score_area=AREA_HTTP,
        evidence="no X-Frame-Options header and no CSP frame-ancestors directive "
                 f"in the response to GET {resp.url}",
        verified_by="lopata inspected both headers on the live response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.LIMITED, exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.USER, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
        notes=["exploitation requires the victim to be authenticated and to "
               "visit an attacker-controlled page"],
    ))
    ctx.add_finding(finding)


def _invalid_xfo(ctx, url, xfo, ancestors_value) -> None:
    finding = Finding(
        name="Ineffective X-Frame-Options value",
        severity=Severity.INFO, location=url,
        description=(
            f"X-Frame-Options is set to {xfo!r}. Browsers only honour DENY and "
            "SAMEORIGIN — ALLOW-FROM was removed from every major browser — so "
            "this header currently provides no protection, and no CSP "
            "frame-ancestors directive is present to take its place.\n\n" + _RISK
        ),
        remediation="Replace the value with DENY and express any allow-list "
                    "through CSP frame-ancestors.",
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"X-Frame-Options value {xfo!r} is not honoured by browsers.",
        risk=_RISK, impact=_IMPACT,
        remediation_steps=_STEPS, verification=_VERIFY, references=_REFS,
        effort=Effort.TRIVIAL, score_area=AREA_HTTP,
        evidence=f"X-Frame-Options: {xfo}"
                 + (f" / frame-ancestors {ancestors_value}" if ancestors_value else ""),
        verified_by="lopata parsed the header value from the live response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.LIMITED, exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.USER, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
    ))
    ctx.add_finding(finding)


def _weak_only_xfo(ctx, url, xfo) -> None:
    """Protected, but only by the legacy header — worth a low-severity note."""
    finding = Finding(
        name="Framing protection relies on X-Frame-Options alone",
        severity=Severity.INFO, location=url,
        description=(
            f"X-Frame-Options is set to {xfo!r}, which browsers still honour, "
            "but no CSP frame-ancestors directive is present. frame-ancestors "
            "is the specified successor: it is the directive that receives "
            "ongoing browser work, and it is the only one that can express a "
            "per-origin allow-list."
        ),
        remediation="Add `Content-Security-Policy: frame-ancestors 'none'` "
                    "alongside the existing header.",
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary="Legacy framing protection only; CSP frame-ancestors is absent.",
        risk="The site is currently protected, but on the older of the two "
             "mechanisms, with no defence in depth if the header is dropped by "
             "a future proxy or CDN configuration change.",
        impact="No immediate impact — this is a hardening improvement.",
        remediation_steps=[_STEPS[0], "Keep X-Frame-Options in place for older "
                                      "clients."],
        verification=_VERIFY, references=_REFS,
        effort=Effort.TRIVIAL, score_area=AREA_HTTP,
        evidence=f"X-Frame-Options: {xfo}; no frame-ancestors directive",
        verified_by="lopata inspected both headers on the live response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.NEGLIGIBLE, exploitability=Exploitability.NONE,
        auth=AuthRequirement.USER, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
    ))
    ctx.add_finding(finding)
