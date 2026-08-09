from __future__ import annotations

import json
import os

from .models import (BusinessImpact, Confidence, Effort, Finding, FindingType,
                     PassedCheck, Service, Severity, Technology)

CHECKPOINT_VERSION = 3


def checkpoint_path(target: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    return f".lopata_checkpoint_{safe}.json"


def save(ctx, path: str, completed: list[str]) -> None:
    data = {
        "version": CHECKPOINT_VERSION,
        "target": ctx.target,
        "completed_modules": completed,
        "modules_run": ctx.modules_run,
        "discovered_urls": sorted(ctx.discovered_urls),
        "spa_routes": list(getattr(ctx, "spa_routes", [])),
        "subdomains": sorted(ctx.subdomains),
        "forms": ctx.forms,
        "findings": [f.as_dict() for f in ctx.findings],
        "passed_checks": [c.as_dict() for c in ctx.passed_checks],
        "technologies": [t.as_dict() for t in ctx.technologies.values()],
        "services": [s.as_dict() for s in ctx.services],
        "raw_outputs": ctx.raw_outputs,
        "tool_status": ctx.tool_status.as_dict(),
        "retry_attempts": _attempts_spent(ctx),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def load(ctx, path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    if data.get("target") != ctx.target:
        return []
    if data.get("version") != CHECKPOINT_VERSION:
        ctx.logger and ctx.logger.info(
            "ignoring checkpoint written by an older lopata version")
        return []

    ctx.tool_status.restore(data.get("tool_status") or {})
    ctx.discovered_urls.update(data.get("discovered_urls", []))
    ctx.subdomains.update(data.get("subdomains", []))
    ctx.forms.extend(data.get("forms", []))
    ctx.spa_routes = list(data.get("spa_routes", []))
    ctx.raw_outputs.update(data.get("raw_outputs", {}))
    for name in data.get("modules_run", []):
        if name not in ctx.modules_run:
            ctx.modules_run.append(name)

    for d in data.get("findings", []):
        ctx.findings.append(_finding_from_dict(d))
    for d in data.get("passed_checks", []):
        ctx.passed_checks.append(PassedCheck(
            name=d.get("name", ""), detail=d.get("detail", ""),
            source=d.get("source", ""), location=d.get("location", "")))
    for d in data.get("technologies", []):
        ctx.add_technology(Technology(
            name=d.get("name", ""), version=d.get("version", ""),
            category=d.get("category", "Other"),
            sources=list(d.get("sources", [])),
            confidence=_enum(Confidence, d.get("confidence"), Confidence.MEDIUM),
            evidence=d.get("evidence", "")))
    for d in data.get("services", []):
        ctx.add_service(Service(
            host=d.get("host", ""), port=int(d.get("port", 0)),
            proto=d.get("proto", "tcp"), name=d.get("service", "unknown"),
            product=d.get("product", ""), version=d.get("version", ""),
            group=d.get("group", "Other"), internal=bool(d.get("internal")),
            tunnel=d.get("tunnel", "")))

    return data.get("completed_modules", [])


def resumed_attempts(path: str) -> dict:
    """Retry attempts already spent per tool, for :class:`RetrySupervisor`.

    Read straight off the checkpoint file rather than from the context so the
    supervisor can be built before the scan context is restored.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError, FileNotFoundError):
        return {}
    if data.get("version") != CHECKPOINT_VERSION:
        return {}
    attempts = data.get("retry_attempts")
    if isinstance(attempts, dict):
        return {str(k): int(v) for k, v in attempts.items()
                if str(v).lstrip("-").isdigit()}
    return {}


def _attempts_spent(ctx) -> dict:
    supervisor = getattr(ctx, "retry_supervisor", None)
    if supervisor is not None and hasattr(supervisor, "attempts_spent"):
        return supervisor.attempts_spent()
    return ctx.tool_status.attempts_by_tool()


def clear(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _enum(enum_cls, label, default):
    try:
        return enum_cls[str(label).strip().upper().replace(" ", "_")]
    except (KeyError, AttributeError):
        return default


def _finding_type(label, default=FindingType.INFORMATIONAL):
    for member in FindingType:
        if member.value == label:
            return member
    return default


def _finding_from_dict(d: dict) -> Finding:
    affected = d.get("affected") or []
    return Finding(
        name=d["name"],
        severity=Severity.from_name(d["severity"]),
        location=d["location"],
        description=d.get("description", ""),
        remediation=d.get("remediation", ""),
        ftype=_finding_type(d.get("type")),
        module=d.get("module", ""),
        category=d.get("category", ""),
        evidence=d.get("evidence", ""),
        confidence=_enum(Confidence, d.get("confidence"), Confidence.MEDIUM),
        request=d.get("request", ""),
        response=d.get("response", ""),
        summary=d.get("summary", ""),
        risk=d.get("risk", ""),
        impact=d.get("impact", ""),
        remediation_steps=list(d.get("remediation_steps", [])),
        verification=d.get("verification", ""),
        references=list(d.get("references", [])),
        severity_reasons=list(d.get("severity_reasons", [])),
        cvss=d.get("cvss"),
        effort=_enum(Effort, d.get("remediation_effort"), Effort.MODERATE),
        business_impact=_enum(BusinessImpact, d.get("business_impact"),
                              BusinessImpact.LOW),
        sources=list(d.get("sources", [])),
        related_locations=[a for a in affected if a != d["location"]],
        score_area=d.get("score_area", ""),
        verified_by=d.get("verified_by", ""),
        contributing_tools=list(d.get("contributing_tools", [])),
        incomplete_coverage=bool(d.get("incomplete_coverage", False)),
    )
