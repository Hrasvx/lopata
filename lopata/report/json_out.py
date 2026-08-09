from __future__ import annotations

import json

from ..core.correlate import summarize
from ..core.scoring import completeness as _scan_completeness


def _completeness(ctx) -> dict:
    """Prefer what scoring already computed; recompute if scoring was skipped."""
    stored = (ctx.scores or {}).get("scan_completeness")
    return stored if stored else _scan_completeness(ctx)


def write_json(ctx, path: str, meta: dict, version: str) -> None:
    """Machine-readable output.

    Deliberately mirrors the PDF's structure so a consumer can filter by
    severity, category, type or confidence without re-deriving anything: every
    finding carries its own type, confidence rank, score area and priority.
    """
    findings = sorted(ctx.findings, key=lambda f: -f.priority)

    payload = {
        "tool": f"lopata {version}",
        "target": ctx.target,
        "started_at": (meta["started_at"].isoformat()
                       if meta.get("started_at") else None),
        "finished_at": (meta["finished_at"].isoformat()
                        if meta.get("finished_at") else None),
        "duration_seconds": round(meta.get("duration_seconds", 0), 3),
        "modules_run": ctx.modules_run,
        "tools": {
            name: {"available": t.available, "version": t.version,
                   "path": t.path, "note": t.note}
            for name, t in ctx.tools.items()
        },
        "scan_completeness": _completeness(ctx),
        "tool_runs": {name: s.as_dict()
                      for name, s in ctx.tool_status.statuses().items()},
        "scores": ctx.scores,
        "summary": summarize(findings),
        "technologies": [t.as_dict() for t in sorted(
            ctx.technologies.values(), key=lambda t: (t.category, t.name.lower()))],
        "services": [s.as_dict() for s in sorted(
            ctx.services, key=lambda s: (s.host, s.port))],
        "findings": [f.as_dict() for f in findings],
        "passed_checks": [c.as_dict() for c in ctx.passed_checks],
        "discovered_urls": sorted(ctx.discovered_urls),
        "spa_routes": list(getattr(ctx, "spa_routes", [])),
        "subdomains": sorted(ctx.subdomains),
        "forms": [{"page": f.get("page"), "action": f.get("action"),
                   "method": f.get("method"),
                   "inputs": [i.get("name") for i in f.get("inputs", [])]}
                  for f in ctx.forms],
        "raw_outputs": ctx.raw_outputs,
        "notes": meta.get("notes", []),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
