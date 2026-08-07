"""Severity calculation.

Severity is *derived*, never inherited from whatever an external tool
happened to print. A finding's severity comes from how reachable the issue
is, what it takes to exploit it, what an attacker gains, and — crucially —
how sure we are that it is real. The same engine produces the human-readable
reasons shown in the report, so a reader can always see why something is High.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .models import BusinessImpact, Confidence, Severity


class Exploitability(IntEnum):

    NONE = 0          # not directly exploitable, informational weight only
    THEORETICAL = 1   # requires conditions unlikely to hold
    DIFFICULT = 2     # needs chained bugs, local access, or a race
    MODERATE = 3      # requires user interaction or some setup
    EASY = 4          # single unauthenticated request
    PUBLIC_EXPLOIT = 5  # weaponised exploit is publicly available


class AuthRequirement(IntEnum):

    ADMIN = 0         # only an administrator can reach it
    USER = 1          # any authenticated user
    NONE = 2          # no authentication at all


class Exposure(IntEnum):

    LOCAL = 0         # loopback / same host
    INTERNAL = 1      # private address space, adjacent network
    PUBLIC = 2        # reachable from the internet


class Impact(IntEnum):

    NEGLIGIBLE = 0    # no meaningful security consequence on its own
    INFORMATION = 1   # discloses information useful to an attacker
    LIMITED = 2       # affects a single user or a narrow function
    SERIOUS = 3       # data disclosure/modification at scale
    TOTAL = 4         # full compromise of the host or application


@dataclass
class SeverityFactors:

    impact: Impact = Impact.INFORMATION
    exploitability: Exploitability = Exploitability.MODERATE
    auth: AuthRequirement = AuthRequirement.NONE
    exposure: Exposure = Exposure.PUBLIC
    confidence: Confidence = Confidence.MEDIUM
    cvss: float | None = None
    # Free-form notes appended verbatim to the explanation (e.g. "public
    # exploit exists for this version").
    notes: list[str] = field(default_factory=list)


_IMPACT_BASE = {
    Impact.NEGLIGIBLE: 0.0,
    Impact.INFORMATION: 2.0,
    Impact.LIMITED: 4.0,
    Impact.SERIOUS: 7.0,
    Impact.TOTAL: 9.0,
}

_EXPLOIT_ADJ = {
    Exploitability.NONE: -2.0,
    Exploitability.THEORETICAL: -1.5,
    Exploitability.DIFFICULT: -1.0,
    Exploitability.MODERATE: 0.0,
    Exploitability.EASY: 0.8,
    Exploitability.PUBLIC_EXPLOIT: 1.5,
}

_AUTH_ADJ = {
    AuthRequirement.ADMIN: -2.0,
    AuthRequirement.USER: -1.0,
    AuthRequirement.NONE: 0.5,
}

_EXPOSURE_ADJ = {
    Exposure.LOCAL: -3.0,
    Exposure.INTERNAL: -1.5,
    Exposure.PUBLIC: 0.5,
}

# Unverified evidence must not manufacture alarming severities. A finding
# resting on a banner alone can never be worse than Low, no matter what the
# scanner that produced it claimed.
_CONFIDENCE_CAP = {
    Confidence.INFORMATIONAL: Severity.INFO,
    Confidence.LOW: Severity.LOW,
    Confidence.MEDIUM: Severity.MEDIUM,
    Confidence.HIGH: Severity.HIGH,
    Confidence.CONFIRMED: Severity.CRITICAL,
}

_SCORE_BANDS = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


def cap_for(confidence: Confidence) -> Severity:
    """The worst severity a finding at this confidence level may claim."""
    return _CONFIDENCE_CAP[confidence]


def score_to_severity(score: float) -> Severity:
    for threshold, sev in _SCORE_BANDS:
        if score >= threshold:
            return sev
    return Severity.INFO


def calculate(factors: SeverityFactors) -> tuple[Severity, list[str], float]:
    """Return (severity, reasons, numeric score 0-10)."""

    if factors.cvss is not None:
        score = max(0.0, min(10.0, float(factors.cvss)))
        reasons = [f"CVSS base score {score:.1f} published for this issue"]
    else:
        score = _IMPACT_BASE[factors.impact]
        score += _EXPLOIT_ADJ[factors.exploitability]
        score += _AUTH_ADJ[factors.auth]
        score += _EXPOSURE_ADJ[factors.exposure]
        score = max(0.0, min(10.0, score))
        reasons = _explain(factors)

    severity = score_to_severity(score)

    cap = _CONFIDENCE_CAP[factors.confidence]
    if severity > cap:
        reasons.append(
            f"capped at {cap.label} because the evidence is "
            f"{factors.confidence.label.lower()}-confidence and was not verified"
        )
        severity = cap

    for note in factors.notes:
        if note:
            reasons.append(note)
    return severity, reasons, score


def _explain(f: SeverityFactors) -> list[str]:
    reasons: list[str] = []

    reasons.append({
        Impact.NEGLIGIBLE: "No direct security impact on its own",
        Impact.INFORMATION: "Discloses information useful for further attacks",
        Impact.LIMITED: "Impact is bounded — it assists an attacker but does not by itself grant access",
        Impact.SERIOUS: "Allows disclosure or modification of protected data",
        Impact.TOTAL: "Can lead to full compromise of the host or application",
    }[f.impact])

    reasons.append({
        Exposure.LOCAL: "Only reachable from the host itself",
        Exposure.INTERNAL: "Reachable from the internal network only",
        Exposure.PUBLIC: "Publicly accessible from the internet",
    }[f.exposure])

    reasons.append({
        AuthRequirement.ADMIN: "Requires administrative access to exploit",
        AuthRequirement.USER: "Requires an authenticated user account",
        AuthRequirement.NONE: "No authentication required",
    }[f.auth])

    reasons.append({
        Exploitability.NONE: "Not directly exploitable",
        Exploitability.THEORETICAL: "Exploitation is theoretical under normal conditions",
        Exploitability.DIFFICULT: "Exploitation requires chaining or privileged position",
        Exploitability.MODERATE: "Exploitable with moderate effort or user interaction",
        Exploitability.EASY: "Exploitable with a single crafted request",
        Exploitability.PUBLIC_EXPLOIT: "Public exploit code exists",
    }[f.exploitability])

    reasons.append({
        Confidence.CONFIRMED: "Reproduced by lopata during the scan",
        Confidence.HIGH: "Strong evidence — directly observed, or corroborated by more than one independent check",
        Confidence.MEDIUM: "Strong single-source evidence, not independently verified",
        Confidence.LOW: "Based on banner or version matching only",
        Confidence.INFORMATIONAL: "Discovery data only, nothing asserted",
    }[f.confidence])

    return reasons


def business_impact_for(severity: Severity, impact: Impact) -> BusinessImpact:
    """Coarse business-impact estimate for the remediation planning table."""
    if severity >= Severity.CRITICAL or impact >= Impact.TOTAL:
        return BusinessImpact.SEVERE
    if severity >= Severity.HIGH or impact >= Impact.SERIOUS:
        return BusinessImpact.HIGH
    if severity >= Severity.MEDIUM:
        return BusinessImpact.MODERATE
    if severity >= Severity.LOW:
        return BusinessImpact.LOW
    return BusinessImpact.NEGLIGIBLE


def apply(finding, factors: SeverityFactors):
    """Compute and stamp severity/reasons/business impact onto a Finding."""
    severity, reasons, score = calculate(factors)
    finding.severity = severity
    finding.severity_reasons = reasons
    finding.confidence = factors.confidence
    if factors.cvss is not None:
        finding.cvss = factors.cvss
    finding.business_impact = business_impact_for(severity, factors.impact)
    return finding
