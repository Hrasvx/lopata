"""Security scoring.

A single "risk score" derived from how many findings there are rewards a
scanner for staying quiet. Instead each finding is charged against the area it
belongs to, areas are scored independently, and the headline number is a
weighted average of the areas that were actually assessed. An area nobody
tested is reported as "not assessed" rather than silently scoring 100.
"""

from __future__ import annotations

from .models import (AREA_CONFIG, AREA_HTTP, AREA_PATCH, AREA_SURFACE, AREA_TLS,
                     AREA_WEBAPP, SCORE_AREAS, Confidence, Severity)

# How much each area matters to the headline score.
AREA_WEIGHTS = {
    AREA_WEBAPP: 0.25,
    AREA_HTTP: 0.20,
    AREA_TLS: 0.15,
    AREA_SURFACE: 0.15,
    AREA_PATCH: 0.15,
    AREA_CONFIG: 0.10,
}

# Which modules/integrations count as having assessed an area at all.
AREA_PROVIDERS = {
    AREA_TLS: {"ssl_tls"},
    AREA_HTTP: {"headers", "cookies", "clickjacking", "cors"},
    AREA_SURFACE: {"nmap", "subfinder", "crawler", "attack_surface"},
    AREA_PATCH: {"nmap", "whatweb", "fingerprint", "nikto"},
    AREA_WEBAPP: {"xss", "sqli", "csrf", "open_redirect", "exposure"},
    AREA_CONFIG: {"misconfig", "nikto", "exposure", "headers"},
}

_SEVERITY_COST = {
    Severity.CRITICAL: 45.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 10.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

# A finding we are unsure about should not wreck the score.
_CONFIDENCE_WEIGHT = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH: 0.9,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.35,
    Confidence.INFORMATIONAL: 0.0,
}


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


def _band(score: float) -> str:
    if score >= 90:
        return "Strong"
    if score >= 80:
        return "Good"
    if score >= 70:
        return "Fair"
    if score >= 55:
        return "Weak"
    return "Poor"


# A weighted average dilutes a single catastrophic finding across six
# categories, which is how a host with a publicly readable .env ends up with a
# respectable-looking grade. These ceilings stop that: the headline number can
# never be better than the worst thing actually found.
_CEILINGS = (
    (Severity.CRITICAL, Confidence.HIGH, 40.0,
     "a Critical finding was confirmed, which caps the overall score "
     "regardless of how well the other areas score"),
    (Severity.HIGH, Confidence.HIGH, 65.0,
     "a High-severity finding was confirmed, which caps the overall score"),
    (Severity.CRITICAL, Confidence.MEDIUM, 60.0,
     "a Critical finding was reported with credible but unverified evidence"),
)


def _apply_ceiling(overall: float, findings) -> tuple[float, str]:
    for severity, confidence, ceiling, reason in _CEILINGS:
        if any(f.severity >= severity and f.confidence >= confidence
               for f in findings):
            if overall > ceiling:
                return ceiling, reason
            return overall, reason
    return overall, ""


def compute(ctx) -> dict:
    ran = set(ctx.modules_run)
    assessed = {area for area, providers in AREA_PROVIDERS.items()
                if providers & ran}

    deductions: dict[str, float] = {area: 0.0 for area in SCORE_AREAS}
    drivers: dict[str, list] = {area: [] for area in SCORE_AREAS}

    for finding in ctx.findings:
        area = finding.score_area if finding.score_area in deductions else AREA_CONFIG
        cost = (_SEVERITY_COST[finding.severity]
                * _CONFIDENCE_WEIGHT[finding.confidence])
        if cost <= 0:
            continue
        deductions[area] += cost
        drivers[area].append((cost, finding))
        # An area with findings has plainly been assessed.
        assessed.add(area)

    # Clean results earn a little credit back, so a hardened target can reach
    # the top of the band rather than merely avoiding penalties.
    credit: dict[str, float] = {area: 0.0 for area in SCORE_AREAS}
    for check in ctx.passed_checks:
        area = getattr(check, "score_area", "") or AREA_PATCH
        if area in credit:
            credit[area] = min(5.0, credit[area] + 1.0)

    categories = {}
    for area in SCORE_AREAS:
        if area not in assessed:
            categories[area] = {
                "score": None, "grade": "—", "band": "Not assessed",
                "findings": 0, "top_issue": "",
            }
            continue
        score = max(0.0, min(100.0, 100.0 - deductions[area] + credit[area]))
        top = max(drivers[area], key=lambda item: item[0])[1] if drivers[area] else None
        categories[area] = {
            "score": round(score),
            "grade": _grade(score),
            "band": _band(score),
            "findings": len(drivers[area]),
            "top_issue": top.name if top is not None else "",
        }

    scored = [(area, categories[area]["score"]) for area in SCORE_AREAS
              if categories[area]["score"] is not None]
    if scored:
        total_weight = sum(AREA_WEIGHTS[a] for a, _ in scored)
        overall = sum(AREA_WEIGHTS[a] * s for a, s in scored) / total_weight
    else:
        overall = 100.0

    overall, gate = _apply_ceiling(overall, ctx.findings)

    result = {
        "overall": round(overall),
        "grade": _grade(overall),
        "band": _band(overall),
        "categories": categories,
        "weights": {a: AREA_WEIGHTS[a] for a in SCORE_AREAS},
        "assessed": sorted(assessed),
        "ceiling_reason": gate,
    }
    ctx.scores = result
    return result


def weakest_areas(scores: dict, limit: int = 3) -> list[tuple[str, dict]]:
    items = [(area, data) for area, data in scores.get("categories", {}).items()
             if data.get("score") is not None]
    items.sort(key=lambda item: item[1]["score"])
    return items[:limit]
