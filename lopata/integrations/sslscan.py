from __future__ import annotations

import json
from urllib.parse import urlparse

from ..core.models import Confidence, Finding, Severity
from .base import detect, host_of, run_tool

MODULE_NAME = "ssl_tls"
CATEGORY = "TLS/SSL"


def available(ctx):
    info = detect(ctx, "sslscan", ("sslyze",), lambda p: [p, "--help"])
    if info.available:
        info.note = "sslyze"

        try:
            from importlib.metadata import version
            info.version = f"sslyze {version('sslyze')}"
        except Exception:
            info.version = "sslyze"
        return info

    enabled = ctx.config.get("tools", {}).get("sslscan", True)
    if enabled:
        from .base import which
        path = which("testssl.sh", "testssl")
        if path:
            info.available = True
            info.path = path
            info.name = "sslscan"
            info.note = "testssl.sh"
            info.version = "testssl.sh"
            ctx.tools["sslscan"] = info
    return info


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not ctx.target.startswith("https"):

        from ..core.models import ToolInfo
        ctx.tools["sslscan"] = ToolInfo(
            name="sslscan", available=False,
            note="skipped: target is not HTTPS")
        return
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)
    host = host_of(ctx.target)
    port = urlparse(ctx.target).port or 443
    endpoint = f"{host}:{port}"

    if info.note == "sslyze":
        _run_sslyze(ctx, info, endpoint)
    else:
        _run_testssl(ctx, info, endpoint)
    phase and phase.done()


def _run_sslyze(ctx, info, endpoint) -> None:
    argv = [info.path, "--json_out=-", "--quiet", endpoint]
    proc = run_tool(argv, timeout=int(ctx.config.get("ssl_timeout", 180)),
                    logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return
    for result in data.get("server_scan_results", []):
        scan = result.get("scan_result", {})
        _sslyze_protocols(ctx, endpoint, scan)
        _sslyze_cert(ctx, endpoint, scan)


_WEAK_PROTOCOLS = {
    "ssl_2_0_cipher_suites": ("SSLv2", Severity.CRITICAL),
    "ssl_3_0_cipher_suites": ("SSLv3", Severity.HIGH),
    "tls_1_0_cipher_suites": ("TLS 1.0", Severity.MEDIUM),
    "tls_1_1_cipher_suites": ("TLS 1.1", Severity.MEDIUM),
}


def _sslyze_protocols(ctx, endpoint, scan) -> None:
    for key, (label, sev) in _WEAK_PROTOCOLS.items():
        node = scan.get(key, {})
        accepted = (node.get("result", {}) or {}).get("accepted_cipher_suites", [])
        if accepted:
            ctx.add_finding(Finding(
                name=f"Deprecated protocol enabled: {label}",
                severity=sev, location=endpoint,
                description=(
                    f"The server negotiates {label}, a protocol with known "
                    "cryptographic weaknesses that modern clients reject."
                ),
                remediation=(
                    f"Disable {label} at the TLS terminator; serve TLS 1.2+ only "
                    "(prefer TLS 1.3)."
                ),
                module=MODULE_NAME, category=CATEGORY,
                evidence=f"{len(accepted)} cipher suite(s) accepted under {label}",
                confidence=Confidence.CONFIRMED,
            ))


def _sslyze_cert(ctx, endpoint, scan) -> None:
    node = scan.get("certificate_info", {})
    deployments = (node.get("result", {}) or {}).get("certificate_deployments", [])
    for dep in deployments:
        for validation in dep.get("path_validation_results", []):
            if validation.get("was_validation_successful") is False:
                ctx.add_finding(Finding(
                    name="Certificate chain validation failed",
                    severity=Severity.HIGH, location=endpoint,
                    description=(
                        "The presented certificate chain failed validation "
                        f"against {validation.get('trust_store', {}).get('name', 'a trust store')}."
                    ),
                    remediation=(
                        "Install a complete, valid certificate chain from a "
                        "trusted CA; verify intermediate certificates are served."
                    ),
                    module=MODULE_NAME, category=CATEGORY,
                    confidence=Confidence.CONFIRMED,
                ))
                break


def _run_testssl(ctx, info, endpoint) -> None:
    argv = [info.path, "--jsonfile", "-", "--quiet", "--color", "0", endpoint]
    proc = run_tool(argv, timeout=int(ctx.config.get("ssl_timeout", 300)),
                    logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return
    try:
        items = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return
    sev_map = {
        "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        "WARN": Severity.LOW,
    }
    for it in items if isinstance(items, list) else []:
        sev = sev_map.get(str(it.get("severity", "")).upper())
        if sev is None:
            continue
        ctx.add_finding(Finding(
            name=f"TLS: {it.get('id', 'issue')}",
            severity=sev, location=endpoint,
            description=str(it.get("finding", "")),
            remediation="Harden the TLS configuration per the testssl.sh finding.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=str(it.get("finding", ""))[:400],
            confidence=Confidence.CONFIRMED,
        ))
