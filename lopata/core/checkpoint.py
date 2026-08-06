from __future__ import annotations

import json
import os

from .models import Confidence, Finding, Severity

CHECKPOINT_VERSION = 1


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
        "discovered_urls": sorted(ctx.discovered_urls),
        "subdomains": sorted(ctx.subdomains),
        "forms": ctx.forms,
        "findings": [f.as_dict() for f in ctx.findings],
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def load(ctx, path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("target") != ctx.target:
        return []
    ctx.discovered_urls.update(data.get("discovered_urls", []))
    ctx.subdomains.update(data.get("subdomains", []))
    ctx.forms.extend(data.get("forms", []))
    for d in data.get("findings", []):
        ctx.findings.append(_finding_from_dict(d))
    return data.get("completed_modules", [])


def clear(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        name=d["name"],
        severity=Severity.from_name(d["severity"]),
        location=d["location"],
        description=d["description"],
        remediation=d["remediation"],
        module=d.get("module", ""),
        category=d.get("category", ""),
        evidence=d.get("evidence", ""),
        confidence=Confidence[d.get("confidence", "FIRM").upper()],
        request=d.get("request", ""),
        response=d.get("response", ""),
    )
