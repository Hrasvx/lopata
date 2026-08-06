from __future__ import annotations

import xml.etree.ElementTree as ET

from ..core.models import Confidence, Finding, Severity
from .base import detect, host_of, run_tool

MODULE_NAME = "nmap"
CATEGORY = "Port/Service Recon"


def available(ctx):
    return detect(ctx, "nmap", ("nmap",), lambda p: [p, "--version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)
    host = host_of(ctx.target)

    fast = bool(ctx.config.get("nmap_fast", True))
    argv = [info.path, "-sV", "-T4", "-oX", "-"]
    if fast:
        argv += ["-F"]
    if ctx.config.get("nmap_vuln", True):
        argv += ["--script", "vuln"]
    argv.append(host)

    timeout = int(ctx.config.get("nmap_timeout", 300))
    proc = run_tool(argv, timeout=timeout, logger=ctx.logger)
    phase and phase.step()
    if proc is None or not proc.stdout.strip():
        return
    try:
        _parse(ctx, proc.stdout)
    except ET.ParseError as exc:
        ctx.logger and ctx.logger.warning("nmap XML parse failed: %s", exc)


def _parse(ctx, xml_text: str) -> None:
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else host_of(ctx.target)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
            product = " ".join(filter(None, [
                svc.get("product") if svc is not None else None,
                svc.get("version") if svc is not None else None,
            ])).strip()
            loc = f"{addr}:{portid}/{proto}"
            ctx.add_finding(Finding(
                name=f"Open port {portid}/{proto} ({svc_name})",
                severity=Severity.INFO,
                location=loc,
                description=(
                    f"nmap reports {svc_name} "
                    + (f"({product}) " if product else "")
                    + "listening. Every exposed service widens the attack "
                    "surface and should be intentional."
                ),
                remediation=(
                    "Confirm this service should be internet-reachable; firewall "
                    "or bind to localhost anything not required externally."
                ),
                module=MODULE_NAME, category=CATEGORY,
                evidence=product or svc_name,
                confidence=Confidence.FIRM,
            ))

            for script in port.findall("script"):
                _script_finding(ctx, loc, svc_name, script)

    for script in root.findall("./host/hostscript/script"):
        _script_finding(ctx, host_of(ctx.target), "host", script)


_VULN_MARKERS = ("VULNERABLE", "CVE-", "State: VULNERABLE")


def _script_finding(ctx, loc, svc_name, script) -> None:
    sid = script.get("id", "")
    output = (script.get("output") or "").strip()
    if not output:
        return
    is_vuln = any(m in output for m in _VULN_MARKERS)
    if not (is_vuln or sid.startswith("vuln")):
        return
    severity = Severity.HIGH if "VULNERABLE" in output else Severity.MEDIUM
    ctx.add_finding(Finding(
        name=f"nmap NSE: {sid}",
        severity=severity,
        location=loc,
        description=(
            f"The nmap script '{sid}' flagged a potential issue on {svc_name}. "
            "Reported by an external scanner and not independently re-verified "
            "by lopata — treat as a lead for manual confirmation."
        ),
        remediation=(
            "Review the script output, confirm the affected version, and patch "
            "or mitigate per the referenced advisory/CVE."
        ),
        module=MODULE_NAME, category=CATEGORY,
        evidence=output[:800],
        confidence=Confidence.TENTATIVE,
    ))
