"""nmap integration.

Two rules govern everything here:

1. An open port is inventory, not a vulnerability. Ports land in
   ``ctx.services`` and the attack-surface module decides what, if anything,
   is worth reporting about them.
2. NSE output is *read*, not forwarded. A script that says "NOT VULNERABLE"
   produces a passed check; a script that matched a version banner produces a
   low-confidence lead; only a script that states it verified the condition
   produces a vulnerability.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..core.knowledge import group_for, is_internal_address
from ..core.models import (AREA_PATCH, Confidence, Effort, Finding,
                           FindingType, PassedCheck, Service, Severity,
                           Technology)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from .base import detect, host_of, run_tool

MODULE_NAME = "nmap"
CATEGORY = "Host & Service Recon"


def available(ctx):
    return detect(ctx, "nmap", ("nmap",), lambda p: [p, "--version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)
    host = host_of(ctx.target)

    timeout = int(ctx.config.get("nmap_timeout", 300))

    argv = [info.path, "-sV", "-T4", "-oX", "-"]
    if bool(ctx.config.get("nmap_fast", True)):
        argv += ["-F"]
    if ctx.config.get("nmap_vuln", True):
        argv += ["--script", str(ctx.config.get("nmap_scripts", "vuln")),
                 "--script-timeout",
                 str(ctx.config.get("nmap_script_timeout", 60)) + "s"]
    argv += ["--host-timeout", f"{max(timeout - 30, 30)}s"]
    argv.append(host)

    proc = run_tool(argv, timeout=timeout, logger=ctx.logger,
    ctx=ctx, tool="nmap")
    phase and phase.step()
    if proc is None or not proc.stdout.strip():
        ctx.logger and ctx.logger.warning(
            "nmap produced no usable output (timed out or failed); "
            "attack-surface analysis will be skipped")
        return
    ctx.add_raw_output("nmap", proc.stdout)
    try:
        _parse(ctx, proc.stdout)
    except ET.ParseError as exc:
        ctx.logger and ctx.logger.warning("nmap XML parse failed: %s", exc)


def _parse(ctx, xml_text: str) -> None:
    root = ET.fromstring(xml_text)
    fallback_host = host_of(ctx.target)

    for host in root.findall("host"):
        addr = fallback_host
        for addr_el in host.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                addr = addr_el.get("addr") or addr
                break
        internal = is_internal_address(addr)

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = _service_from_xml(ctx, addr, port, internal)
            ctx.add_service(service)
            _tech_from_service(ctx, service)
            for script in port.findall("script"):
                _handle_script(ctx, service.endpoint, service, script)

        for script in host.findall("./hostscript/script"):
            _handle_script(ctx, addr, None, script)


def _service_from_xml(ctx, addr, port, internal) -> Service:
    svc = port.find("service")

    def attr(name, default=""):
        return (svc.get(name) or default) if svc is not None else default

    return Service(
        host=addr,
        port=int(port.get("portid", "0") or 0),
        proto=port.get("protocol", "tcp"),
        name=attr("name", "unknown"),
        product=attr("product"),
        version=attr("version"),
        extra=attr("extrainfo"),
        tunnel=attr("tunnel"),
        internal=internal,
        group=group_for(int(port.get("portid", "0") or 0), attr("name")),
    )


_SERVER_TECH = {
    "apache httpd": "Web Server", "nginx": "Web Server",
    "microsoft iis httpd": "Web Server", "lighttpd": "Web Server",
    "openssh": "Remote Access", "postfix smtpd": "Mail Server",
    "exim smtpd": "Mail Server", "dovecot": "Mail Server",
    "mysql": "Database", "mariadb": "Database", "postgresql": "Database",
}


def _tech_from_service(ctx, service: Service) -> None:
    """A version from -sV is a fingerprint, so record it as one."""
    if not service.product:
        return
    key = service.product.strip().lower()
    category = next((cat for name, cat in _SERVER_TECH.items() if name in key),
                    "Service")
    ctx.add_technology(Technology(
        name=service.product.strip(),
        version=service.version.strip(),
        category=category,
        sources=[MODULE_NAME],
        # Service banners are self-reproted and trivially spoofed.
        confidence=Confidence.LOW,
        evidence=f"nmap -sV on {service.endpoint}: {service.banner}",
    ))



_NEGATIVE = re.compile(
    r"\bNOT\s+VULNERABLE\b"
    r"|\bnot\s+vulnerable\b"
    r"|\bnot\s+affected\b"
    r"|\bno\s+vulnerabilit(?:y|ies)\s+(?:were\s+)?found\b"
    r"|\bnothing\s+found\b"
    r"|\bappears?\s+to\s+be\s+patched\b"
    r"|\b(?:is|was|already)\s+patched\b"
    r"|\bno\s+(?:known\s+)?(?:issues|problems)\s+found\b"
    r"|\bserver\s+is\s+not\s+vulnerable\b"
    r"|\b(?:could\s*n[o']?t|did\s*n[o']?t|unable\s+to)\s+find\s+any\b"
    r"[^.\n]{0,40}vulnerabilit",
    re.I,
)

_NEGATIVE_OVERRIDE = re.compile(
    r"\bnot\s+patched\b|\bunpatched\b|\bstill\s+vulnerable\b", re.I)

# Script noise that carries no verdict either way.
_ERRORISH = re.compile(
    r"^\s*(ERROR|WARNING)\b|couldn'?t|could not|unable to|timed? out"
    r"|no reply|connection refused|false positive",
    re.I,
)

_STATE_VULNERABLE = re.compile(r"State:\s*VULNERABLE(?:\s*\(([^)]*)\))?", re.I)
_STATE_LIKELY = re.compile(r"State:\s*LIKELY\s+VULNERABLE", re.I)
_VULNERABLE_HEADER = re.compile(r"^\s*VULNERABLE:", re.I | re.M)

# vulners / vulscan lines:  "  CVE-2021-1234   7.5   https://..."
_CVE_LINE = re.compile(
    r"(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)?", re.I)
_CVE_ANY = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

_VERSION_MATCH_SCRIPTS = {"vulners", "vulscan", "http-vuln-cve2017-5638"}


def classify(script_id: str, output: str) -> str:
    """Return one of: passed, error, vulnerable, likely, version-match, info."""
    text = (output or "").strip()
    if not text:
        return "info"
    negated = _NEGATIVE_OVERRIDE.search(text)
    if _NEGATIVE.search(text) and not negated:
        return "passed"
    if negated:
        return "likely"
    if _ERRORISH.search(text) and not _STATE_VULNERABLE.search(text):
        return "error"
    if _STATE_VULNERABLE.search(text):
        return "vulnerable"
    if _STATE_LIKELY.search(text) or _VULNERABLE_HEADER.search(text):
        return "likely"
    if script_id.lower() in _VERSION_MATCH_SCRIPTS or _CVE_ANY.search(text):
        return "version-match"
    return "info"


def _handle_script(ctx, location, service, script) -> None:
    sid = script.get("id", "") or "nse"
    output = (script.get("output") or "").strip()
    verdict = classify(sid, output)

    if verdict == "passed":
        ctx.add_passed(PassedCheck(
            name=f"{sid}: not vulnerable",
            detail=_squash(output, 300),
            source="nmap NSE", location=location,
            score_area=AREA_PATCH,
        ))
        return
    if verdict in ("error", "info"):
        return
    if verdict == "version-match":
        _version_match_finding(ctx, location, service, sid, output)
        return

    _nse_vuln_finding(ctx, location, service, sid, output,
                      exploitable=verdict == "vulnerable")


def _nse_vuln_finding(ctx, location, service, sid, output, exploitable) -> None:
    state_match = _STATE_VULNERABLE.search(output)
    qualifier = (state_match.group(1) or "").strip().lower() if state_match else ""
    cves = sorted(set(m.upper() for m in _CVE_ANY.findall(output)))
    title = _script_title(output) or sid

    if exploitable and "exploitable" in qualifier:
        confidence = Confidence.HIGH
        ftype = FindingType.CONFIRMED_VULN
        verified = f"nmap NSE script {sid} reported an exploitable state"
    elif exploitable:
        confidence = Confidence.MEDIUM
        ftype = FindingType.POTENTIAL_VULN
        verified = ""
    else:
        confidence = Confidence.LOW
        ftype = FindingType.POTENTIAL_VULN
        verified = ""

    svc_label = service.name if service is not None else "the host"
    finding = Finding(
        name=f"{title} ({sid})",
        severity=Severity.INFO, location=location,
        description=(
            f"The nmap NSE script `{sid}` reported a vulnerable state for "
            f"{svc_label}. The script's own verdict line is reproduced in the "
            "evidence below so its basis can be judged directly."
            + (f"\n\nAssociated identifiers: {', '.join(cves)}." if cves else "")
        ),
        remediation="Patch the affected service to a fixed release.",
        ftype=ftype, module=MODULE_NAME, category=CATEGORY,
        evidence=_squash(output, 1200),
        summary=f"{sid} reports {svc_label} as vulnerable",
        risk=(
            "A vulnerability check against this service returned a positive "
            "result. Until the version is confirmed and the advisory read, "
            "treat this as a credible lead rather than a settled fact."
        ),
        impact=(
            "If the condition holds, an attacker can exploit a known flaw in a "
            "service that is reachable across the network — impact depends on "
            "the specific advisory, but published vulnerabilities in exposed "
            "services are routinely weaponised within days."
        ),
        remediation_steps=[
            f"Confirm the exact running version of {svc_label} on {location}.",
            "Read the referenced advisory and check whether your distribution "
            "backported the fix (distribution version strings often look "
            "unpatched when they are not).",
            "Apply the vendor patch or upgrade to a fixed release.",
            "If patching must wait, restrict access to the service by source "
            "address in the meantime.",
        ],
        verification=(
            f"Re-run `nmap --script {sid} -p {location.rsplit(':', 1)[-1]} "
            "<target>` after patching; the script should report NOT VULNERABLE."
        ),
        references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:5]],
        effort=Effort.MODERATE,
        score_area=AREA_PATCH,
        verified_by=verified,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS,
        exploitability=(Exploitability.PUBLIC_EXPLOIT
                        if "exploitable" in qualifier else Exploitability.MODERATE),
        auth=AuthRequirement.NONE,
        exposure=(Exposure.INTERNAL
                  if service is not None and service.internal else Exposure.PUBLIC),
        confidence=confidence,
        notes=([f"nmap classified the state as VULNERABLE ({qualifier})"]
               if qualifier else []),
    ))
    ctx.add_finding(finding)


def _version_match_finding(ctx, location, service, sid, output) -> None:
    """vulners-style CVE lists: one finding per service, never one per CVE.

    These come from matching a banner against a CVE database. That is a
    starting point for patch review, not evidence that anything is exploitable,
    so it is reported as Low confidence and the severity engine caps it
    accordingly.
    """
    entries: list[tuple[str, float]] = []
    for match in _CVE_LINE.finditer(output):
        cve = match.group(1).upper()
        try:
            score = float(match.group(2)) if match.group(2) else 0.0
        except (TypeError, ValueError):
            score = 0.0
        entries.append((cve, score))
    if not entries:
        entries = [(c.upper(), 0.0) for c in set(_CVE_ANY.findall(output))]
    if not entries:
        return

    entries.sort(key=lambda item: item[1], reverse=True)
    top_cve, top_score = entries[0]
    banner = service.banner if service is not None else ""
    svc_label = (f"{service.name} ({banner})" if service is not None and banner
                 else (service.name if service is not None else "the host"))

    finding = Finding(
        name=f"Outdated software indicated by version banner: {svc_label}",
        severity=Severity.INFO, location=location,
        description=(
            f"`{sid}` matched the advertised version banner of {svc_label} "
            f"against a vulnerability database and returned {len(entries)} "
            "potentially applicable CVE(s). No exploitation, and no check of "
            "the actual code, was performed — this is a patch-review lead.\n\n"
            "Distribution packages very often carry backported fixes while "
            "keeping the original upstream version string, so a banner match "
            "regularly points at issues that are already fixed on the host."
        ),
        remediation="Review the listed CVEs against the actual installed package "
                    "version and patch where they apply.",
        ftype=FindingType.POTENTIAL_VULN,
        module=MODULE_NAME, category="Patch Management",
        evidence=_squash(output, 1500),
        summary=f"{len(entries)} CVE(s) matched against the {svc_label} banner",
        risk=(
            "The service advertises a version associated with published "
            "vulnerabilities. Whether the host is genuinely affected depends on "
            "the installed package build, which a banner cannot tell us."
        ),
        impact=(
            "If any of the matched CVEs genuinely applies, the consequences "
            f"range up to the highest scored entry ({top_cve}"
            + (f", CVSS {top_score:.1f}" if top_score else "") + ")."
        ),
        remediation_steps=[
            "Determine the installed package version on the host "
            "(`dpkg -l`, `rpm -q`, `apk info -v`) rather than trusting the "
            "network banner.",
            "Compare it against your distribution's security tracker for the "
            "listed CVEs.",
            "Apply outstanding security updates and restart the service.",
            "Consider suppressing detailed version banners so the service is "
            "less attractive to opportunistic scanning.",
        ],
        verification=(
            "After patching, re-run the scan; the matched CVE list should "
            "shrink. Confirm independently with the distribution security "
            "tracker for the installed package version."
        ),
        references=[f"https://nvd.nist.gov/vuln/detail/{cve}"
                    for cve, _ in entries[:5]],
        effort=Effort.EASY,
        score_area=AREA_PATCH,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS if top_score >= 7.0 else Impact.LIMITED,
        exploitability=Exploitability.THEORETICAL,
        auth=AuthRequirement.NONE,
        exposure=(Exposure.INTERNAL
                  if service is not None and service.internal else Exposure.PUBLIC),
        confidence=Confidence.LOW,
        notes=["derived from a version banner alone; no behaviour was tested"],
    ))
    ctx.add_finding(finding)


def _script_title(output: str) -> str:
    """The line after 'VULNERABLE:' is usually the human-readable title."""
    lines = [ln.strip() for ln in output.splitlines()]
    for i, line in enumerate(lines):
        if line.upper().startswith("VULNERABLE:") and i + 1 < len(lines):
            title = lines[i + 1].strip()
            if title and not title.lower().startswith("state:"):
                return title[:90]
    return ""


def _squash(text: str, limit: int) -> str:
    text = "\n".join(ln.rstrip() for ln in (text or "").splitlines() if ln.strip())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def register():
    from ..core.plugins import integration
    return integration('nmap', run, available, phase='recon', order=30)
