"""Passive subdomain enumeration (subfinder, or amass as a fallback).

Subdomains are attack-surface inventory, not a vulnerability. They are
recorded as an Informational inventory finding and seeded into the crawler so
the discovered hosts actually get looked at.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.models import (AREA_SURFACE, Confidence, Effort, Finding,
                           FindingType, Severity)
from .base import detect, host_of, run_tool

MODULE_NAME = "subfinder"
CATEGORY = "Attack Surface"


def available(ctx):
    info = detect(ctx, "subfinder", ("subfinder",), lambda p: [p, "-version"])
    if info.available:
        info.note = "subfinder"
        return info
    if ctx.config.get("tools", {}).get("subfinder", True):
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
    ctx.add_raw_output("subfinder", proc.stdout)

    names = {ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()}
    resolved = _resolve(names, ctx.threads, phase)
    ctx.subdomains.update(resolved)
    unresolved = len(names) - len(resolved)

    if resolved:
        ctx.add_finding(Finding(
            name=f"{len(resolved)} live subdomain(s) in scope",
            severity=Severity.INFO, location=domain,
            description=(
                f"Passive sources listed {len(names)} name(s) under {domain}; "
                f"{len(resolved)} of them currently resolve. Each live name is "
                "an independent entry point that needs the same hardening as "
                "the primary site.\n\n"
                + (f"{unresolved} name(s) no longer resolve. Names that resolve "
                   "to a decommissioned provider — rather than not resolving at "
                   "all — are the ones that lead to subdomain takeover, so the "
                   "dangling-record check below is worth running periodically."
                   if unresolved else "")
            ),
            remediation="Maintain an inventory of live subdomains and remove DNS "
                        "records for services you no longer operate.",
            ftype=FindingType.INVENTORY,
            module=MODULE_NAME, category=CATEGORY,
            summary=f"{len(resolved)} live subdomain(s) discovered by passive enumeration.",
            risk="Forgotten subdomains are rarely patched or monitored, and DNS "
                 "records pointing at deprovisioned cloud resources can be "
                 "claimed by anyone, yielding a valid certificate on your domain.",
            impact="Attack surface beyond the primary site; in the takeover case, "
                   "an attacker serves content from your domain, which defeats "
                   "cookie scoping and user trust alike.",
            remediation_steps=[
                "Reconcile this list against your DNS zone and decommission "
                "records for services that no longer exist.",
                "For each live name, confirm it is covered by the same TLS, "
                "header and patching standards as the main site.",
                "Run `dig CNAME <name>` on each and check that no CNAME points "
                "at an unclaimed provider resource.",
            ],
            verification="Re-run passive enumeration after cleanup and confirm "
                         "the list matches your intended inventory.",
            effort=Effort.MODERATE,
            score_area=AREA_SURFACE,
            evidence=", ".join(sorted(resolved))[:1500],
            confidence=Confidence.INFORMATIONAL,
            related_locations=sorted(resolved)[:50],
            sources=[MODULE_NAME],
        ))
    phase and phase.done()


def _resolve(names: set[str], threads: int, phase) -> set[str]:
    resolved: set[str] = set()
    if phase:
        phase.set_total(max(len(names), 1))
    if not names:
        return resolved

    def check(name: str) -> str | None:
        try:
            socket.gethostbyname(name)
            return name
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=max(threads, 4)) as pool:
        futures = [pool.submit(check, name) for name in names]
        for fut in as_completed(futures):
            name = fut.result()
            if name:
                resolved.add(name)
            phase and phase.step()
    return resolved


def register():
    from ..core.plugins import integration
    return integration('subfinder', run, available, phase='recon', order=10)
