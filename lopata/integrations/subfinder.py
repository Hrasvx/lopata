from __future__ import annotations

import socket

from ..core.models import Confidence, Finding, Severity
from .base import detect, host_of, run_tool

MODULE_NAME = "subfinder"
CATEGORY = "Subdomain Enumeration"


def available(ctx):
    info = detect(ctx, "subfinder", ("subfinder",), lambda p: [p, "-version"])
    if info.available:
        info.note = "subfinder"
        return info
    enabled = ctx.config.get("tools", {}).get("subfinder", True)
    if enabled:
        from .base import which
        path = which("amass")
        if path:
            info.available = True
            info.path = path
            info.note = "amass"
            ctx.tools["subfinder"] = info
    return info


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)
    domain = host_of(ctx.target)

    if info.note == "amass":
        argv = [info.path, "enum", "-passive", "-d", domain, "-silent"]
    else:
        argv = [info.path, "-d", domain, "-silent"]
    proc = run_tool(argv, timeout=int(ctx.config.get("subfinder_timeout", 120)),
                    logger=ctx.logger)
    phase and phase.step()
    if proc is None:
        return

    names = {ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()}
    resolved = _resolve(names, phase)
    ctx.subdomains.update(resolved)

    if resolved:
        ctx.add_finding(Finding(
            name=f"{len(resolved)} subdomain(s) discovered",
            severity=Severity.INFO, location=domain,
            description=(
                "Passive enumeration found live subdomains. Each is additional "
                "attack surface; ensure none are stale/forgotten (takeover risk)."
            ),
            remediation=(
                "Inventory all subdomains, decommission unused ones, and remove "
                "dangling DNS records pointing at unclaimed services."
            ),
            module=MODULE_NAME, category=CATEGORY,
            evidence=", ".join(sorted(resolved))[:1500],
            confidence=Confidence.FIRM,
        ))
    phase and phase.done()


def _resolve(names: set[str], phase) -> set[str]:
    resolved = set()
    if phase:
        phase.set_total(max(len(names), 1))
    for name in names:
        try:
            socket.gethostbyname(name)
            resolved.add(name)
        except OSError:
            pass
        phase and phase.step()
    return resolved
