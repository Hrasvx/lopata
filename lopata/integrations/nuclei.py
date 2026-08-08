"""Nuclei integration — template-based detection of known issues.

Nuclei is run against the surface the crawler discovered (post-discovery
phase). Its matches are real HTTP observations, so they are trustworthy as a
*single source* — but, exactly like every other tool here, its verdict is not
copied into the report:

* a pure detection template ("… Detection", tech/version tags) feeds the
  technology registry, not a finding;
* a template's advertised severity is an *input* to lopata's own severity
  calculation, never an override — and because a nuclei-only hit is a single
  unverified source, the confidence cap holds it to Medium until something
  else corroborates it, at which point the existing correlation logic raises it;
* a published CVSS carried in the template is used where present, which is
  still bounded by that confidence cap.
"""

from __future__ import annotations

import json

from ..core.models import (AREA_CONFIG, AREA_HTTP, AREA_PATCH, AREA_TLS,
                           AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity, Technology)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from ._shared import candidate_urls
from .base import detect, run_tool, temp_input

MODULE_NAME = "nuclei"
CATEGORY = "Known Vulnerabilities"
PHASE = "post"

# nuclei severity -> (impact, exploitability) seed for lopata's own calc.
_SEV_SEED = {
    "critical": (Impact.TOTAL, Exploitability.PUBLIC_EXPLOIT),
    "high": (Impact.SERIOUS, Exploitability.EASY),
    "medium": (Impact.LIMITED, Exploitability.MODERATE),
    "low": (Impact.INFORMATION, Exploitability.DIFFICULT),
    "info": (Impact.NEGLIGIBLE, Exploitability.NONE),
    "unknown": (Impact.INFORMATION, Exploitability.THEORETICAL),
}

_WEBAPP_TAGS = {"xss", "sqli", "injection", "rce", "ssrf", "lfi", "rfi",
                "ssti", "xxe", "redirect", "idor", "traversal", "deserialization"}
_EXPOSURE_TAGS = {"exposure", "exposures", "disclosure", "files", "backup",
                  "logs", "config", "secret", "token"}
_MISCONFIG_TAGS = {"misconfig", "misconfiguration", "default-login",
                   "unauth", "cors"}
_DETECT_TAGS = {"tech", "detect", "favicon", "waf"}


def available(ctx):
    return detect(ctx, "nuclei", ("nuclei",), lambda p: [p, "-version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    urls = candidate_urls(ctx, int(ctx.config.get("nuclei_max_urls", 40)))
    severity = str(ctx.config.get("nuclei_severity",
                                  "low,medium,high,critical"))
    with temp_input("\n".join(urls) + "\n") as list_path:
        argv = [info.path, "-jsonl", "-silent", "-no-color", "-duc",
                "-severity", severity, "-l", list_path,
                "-timeout", str(int(ctx.timeout) + 5),
                "-rate-limit", str(int(ctx.config.get("nuclei_rate_limit", 150)))]
        proc = run_tool(argv, timeout=int(ctx.config.get("nuclei_timeout", 600)),
                        logger=ctx.logger)
    phase and phase.step()
    if proc is None or not proc.stdout.strip():
        return
    ctx.add_raw_output("nuclei", proc.stdout)

    kept = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            if _handle(ctx, obj):
                kept += 1
        except Exception as exc:
            ctx.logger and ctx.logger.warning(
                "nuclei item skipped (%s)", exc.__class__.__name__)
    if ctx.logger:
        ctx.logger.info("nuclei: %d match(es) classified", kept)
    phase and phase.done()


def _tags(info: dict) -> set[str]:
    raw = info.get("tags")
    if isinstance(raw, str):
        raw = raw.split(",")
    return {str(t).strip().lower() for t in (raw or []) if str(t).strip()}


def _references(info: dict) -> list[str]:
    ref = info.get("reference")
    if isinstance(ref, str):
        ref = [ref]
    return [str(r) for r in (ref or []) if str(r).startswith("http")][:5]


def _cvss(info: dict):
    cls = info.get("classification") or {}
    try:
        score = float(cls.get("cvss-score"))
        return score if 0 < score <= 10 else None
    except (TypeError, ValueError):
        return None


def _score_area(tags: set[str]) -> str:
    if tags & {"ssl", "tls"}:
        return AREA_TLS
    if tags & _WEBAPP_TAGS:
        return AREA_WEBAPP
    if tags & {"cve", "tech", "version"}:
        return AREA_PATCH
    if tags & {"headers", "http"}:
        return AREA_HTTP
    return AREA_CONFIG


def _classify(sev: str, tags: set[str]) -> FindingType:
    if tags & _WEBAPP_TAGS or "cve" in tags:
        return FindingType.POTENTIAL_VULN
    if tags & _EXPOSURE_TAGS:
        return FindingType.EXPOSURE
    if tags & _MISCONFIG_TAGS:
        return FindingType.MISCONFIGURATION
    if sev in ("high", "critical"):
        return FindingType.POTENTIAL_VULN
    if sev in ("medium", "low"):
        return FindingType.MISCONFIGURATION
    return FindingType.INFORMATIONAL


def _handle(ctx, obj: dict) -> bool:
    info = obj.get("info") or {}
    name = info.get("name") or obj.get("template-id") or "nuclei match"
    sev = str(info.get("severity") or "unknown").lower()
    tags = _tags(info)
    location = obj.get("matched-at") or obj.get("matched") or obj.get("host") \
        or ctx.target
    template_id = obj.get("template-id") or ""

    # Pure detection templates are inventory: route them to the tech registry
    # rather than manufacturing a finding.
    is_detection = (tags & _DETECT_TAGS
                    or template_id.endswith("-detect")
                    or name.lower().endswith("detection"))
    if is_detection and sev in ("info", "unknown"):
        ctx.add_technology(Technology(
            name=name.replace(" Detection", "").strip(),
            category="Other", sources=[MODULE_NAME],
            confidence=Confidence.LOW,
            evidence=f"nuclei template {template_id} matched at {location}"))
        return True

    ftype = _classify(sev, tags)
    impact, exploit = _SEV_SEED.get(sev, _SEV_SEED["unknown"])
    cvss = _cvss(info)

    # A nuclei match is one real observation from one tool: Medium confidence,
    # which the correlation pass will raise if lopata or another tool agrees,
    # and which caps severity until then. Detection-only info stays Low.
    confidence = Confidence.MEDIUM if sev not in ("info", "unknown") else Confidence.LOW

    extracted = obj.get("extracted-results") or []
    evidence = f"template {template_id} [{sev}] matched at {location}"
    if extracted:
        evidence += "\nextracted: " + ", ".join(str(e) for e in extracted[:5])

    finding = Finding(
        name=name,
        severity=Severity.INFO,
        location=location,
        description=(
            f"Nuclei template `{template_id}` (advertised severity: {sev}) "
            f"matched at {location}.\n\n"
            + (info.get("description") or "").strip()
            + "\n\nThis is a single-source detection from nuclei. lopata rates "
            "it on its own severity model and holds confidence to Medium until "
            "another check corroborates it."
        ),
        remediation=(info.get("remediation")
                     or "Review the matched resource and apply the referenced fix."),
        ftype=ftype,
        module=MODULE_NAME,
        category=CATEGORY,
        summary=f"nuclei matched `{template_id}` ({sev}).",
        risk="A published detection template matched a response from the target, "
             "indicating a known-vulnerable condition, exposure or "
             "misconfiguration described by that template.",
        impact=("If confirmed, impact follows the referenced advisory."
                if ftype is FindingType.POTENTIAL_VULN
                else "Assists an attacker or weakens the target's posture."),
        remediation_steps=[
            "Open the referenced advisory and confirm the condition applies to "
            "your version and configuration.",
            "Apply the vendor fix or the template's stated remediation.",
            "Re-run nuclei with the same template to confirm it no longer matches.",
        ],
        verification="Re-run the specific template against the URL and confirm "
                     "it no longer matches.",
        references=_references(info),
        effort=Effort.MODERATE,
        score_area=_score_area(tags),
        evidence=evidence[:1200],
        request=f"nuclei -id {template_id} -u {location}",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact, exploitability=exploit,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=confidence, cvss=cvss,
        notes=[f"reported by nuclei template {template_id}; "
               "not independently reproduced by lopata"],
    ))
    ctx.add_finding(finding)
    return True


def register():
    from ..core.plugins import integration
    return integration('nuclei', run, available, phase='post', order=90)
