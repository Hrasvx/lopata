from __future__ import annotations

import json
from collections import Counter

from ..core.models import Confidence


def write_json(ctx, path: str, meta: dict, version: str) -> None:
    counts = Counter(f.severity.label for f in ctx.findings)
    payload = {
        "tool": f"lopata {version}",
        "target": ctx.target,
        "started_at": meta["started_at"].isoformat() if meta.get("started_at") else None,
        "finished_at": meta["finished_at"].isoformat() if meta.get("finished_at") else None,
        "duration_seconds": round(meta.get("duration_seconds", 0), 3),
        "modules_run": ctx.modules_run,
        "tools": {
            name: {"available": t.available, "version": t.version,
                   "path": t.path, "note": t.note}
            for name, t in ctx.tools.items()
        },
        "summary": {
            "total": len(ctx.findings),
            "by_severity": dict(counts),
            "confirmed": sum(1 for f in ctx.findings
                             if f.confidence == Confidence.CONFIRMED),
            "leads": sum(1 for f in ctx.findings
                         if f.confidence == Confidence.TENTATIVE),
        },
        "findings": [f.as_dict() for f in sorted(
            ctx.findings, key=lambda f: (int(f.severity), int(f.confidence)),
            reverse=True)],
        "discovered_urls": sorted(ctx.discovered_urls),
        "subdomains": sorted(ctx.subdomains),
        "notes": meta.get("notes", []),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
