from __future__ import annotations

import json

from ..core.models import Confidence, Finding, Severity
from .base import detect, run_tool

MODULE_NAME = "whatweb"
CATEGORY = "Tech Fingerprint"


def available(ctx):
    info = detect(ctx, "whatweb", ("whatweb",), lambda p: [p, "--version"])
    if info.available:
        info.note = "whatweb"
        return info
    enabled = ctx.config.get("tools", {}).get("whatweb", True)
    if enabled:
        from .base import which
        path = which("wappalyzer")
        if path:
            info.available = True
            info.path = path
            info.note = "wappalyzer"
            ctx.tools["whatweb"] = info
    return info


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)
    if info.note == "wappalyzer":
        techs = _run_wappalyzer(ctx, info)
    else:
        techs = _run_whatweb(ctx, info)
    phase and phase.done()

    if techs:
        ctx.config.setdefault("tech", set()).update(t.lower() for t in techs)
        ctx.add_finding(Finding(
            name="Technology fingerprint",
            severity=Severity.INFO, location=ctx.target,
            description="Detected stack: " + ", ".join(sorted(techs)),
            remediation=(
                "Ensure version banners are not more revealing than necessary; "
                "keep all detected components patched."
            ),
            module=MODULE_NAME, category=CATEGORY,
            evidence=", ".join(sorted(techs))[:800],
            confidence=Confidence.FIRM,
        ))


def _run_whatweb(ctx, info) -> set[str]:
    argv = [info.path, "--log-json=-", "--no-errors", "-a", "1", ctx.target]
    proc = run_tool(argv, timeout=int(ctx.config.get("whatweb_timeout", 90)),
                    logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return set()
    techs: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for name, meta in (obj.get("plugins") or {}).items():
            versions = meta.get("version") if isinstance(meta, dict) else None
            if versions:
                techs.add(f"{name} {'/'.join(map(str, versions))}")
            else:
                techs.add(name)
    return techs


def _run_wappalyzer(ctx, info) -> set[str]:
    proc = run_tool([info.path, ctx.target], timeout=90, logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return set()
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return set()
    techs = set()
    for t in data.get("technologies", []):
        name = t.get("name")
        version = t.get("version")
        techs.add(f"{name} {version}".strip() if version else name)
    return {t for t in techs if t}
