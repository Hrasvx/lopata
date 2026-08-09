"""TLS assessment via sslyze (preferred) or testssl.sh.

TLS results are one of the few places where a scanner genuinely *proves*
something: sslyze negotiates the connection rather than reading a banner, so
a deprecated protocol it accepted is Confirmed. The same run also produces
negative results, and those are recorded as passed checks so the report can
show that TLS 1.0 was tested for and rejected.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from ..core.models import (AREA_TLS, Confidence, Effort, Finding, FindingType,
                           PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from .base import detect, host_of, run_tool, temp_output

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

    if ctx.config.get("tools", {}).get("sslscan", True):
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
        from .base import mark_skipped
        mark_skipped(ctx, "sslscan", "target is not HTTPS")
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
                    logger=ctx.logger,
                    ctx=ctx, tool="sslscan")
    if proc is None or not proc.stdout.strip():
        return
    ctx.add_raw_output("sslyze", proc.stdout)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return
    for result in data.get("server_scan_results", []):
        scan = result.get("scan_result", {}) or {}
        _sslyze_protocols(ctx, endpoint, scan)
        _sslyze_ciphers(ctx, endpoint, scan)
        _sslyze_cert(ctx, endpoint, scan)
        _sslyze_known_flaws(ctx, endpoint, scan)


_PROTOCOLS = {
    "ssl_2_0_cipher_suites": ("SSLv2", Impact.SERIOUS, Exploitability.EASY),
    "ssl_3_0_cipher_suites": ("SSLv3", Impact.SERIOUS, Exploitability.MODERATE),
    "tls_1_0_cipher_suites": ("TLS 1.0", Impact.LIMITED, Exploitability.DIFFICULT),
    "tls_1_1_cipher_suites": ("TLS 1.1", Impact.LIMITED, Exploitability.DIFFICULT),
}


def _accepted(node) -> list:
    return ((node or {}).get("result", {}) or {}).get("accepted_cipher_suites", []) or []


def _sslyze_protocols(ctx, endpoint, scan) -> None:
    for key, (label, impact, exploit) in _PROTOCOLS.items():
        node = scan.get(key)
        if node is None:
            continue
        accepted = _accepted(node)
        if not accepted:
            ctx.add_passed(PassedCheck(
                name=f"{label} is not offered",
                detail=f"The server rejected every {label} handshake attempt.",
                source="sslyze", location=endpoint, score_area=AREA_TLS))
            continue

        names = [c.get("cipher_suite", {}).get("name", "") for c in accepted]
        finding = Finding(
            name=f"Deprecated TLS protocol enabled: {label}",
            severity=Severity.INFO, location=endpoint,
            description=(
                f"The server completed a {label} handshake. {label} has known "
                "cryptographic weaknesses, is prohibited by PCI DSS and is "
                "rejected outright by current browsers — so leaving it enabled "
                "protects no real client while widening the attack surface for "
                "downgrade attacks."
            ),
            remediation=f"Disable {label} and serve TLS 1.2 and 1.3 only.",
            ftype=FindingType.MISCONFIGURATION,
            module=MODULE_NAME, category=CATEGORY,
            summary=f"{label} is accepted with {len(accepted)} cipher suite(s).",
            risk=(
                f"An attacker positioned on the network can attempt to force "
                f"clients down to {label}, where the available cipher suites are "
                "susceptible to well-published attacks (POODLE, BEAST, and the "
                "general weakness of CBC padding in these versions)."
            ),
            impact=(
                "Successful downgrade allows partial or full recovery of session "
                "data — most importantly authentication cookies — for clients "
                "old enough to negotiate it."
            ),
            remediation_steps=[
                f"Remove {label} from the enabled protocol list "
                "(`ssl_protocols TLSv1.2 TLSv1.3;` in nginx, "
                "`SSLProtocol -all +TLSv1.2 +TLSv1.3` in Apache).",
                "Reload the TLS terminator and confirm the change took effect.",
                "If a legacy client genuinely requires it, isolate that client "
                "to a dedicated endpoint rather than weakening the main site.",
            ],
            verification=(
                f"`openssl s_client -connect {endpoint} "
                f"-{label.lower().replace(' ', '').replace('.', '_')}` should "
                "fail to negotiate after the change."
            ),
            references=["https://www.rfc-editor.org/rfc/rfc8996"],
            effort=Effort.TRIVIAL,
            score_area=AREA_TLS,
            evidence=f"{len(accepted)} suite(s) accepted under {label}: "
                     + ", ".join(n for n in names[:8] if n),
            verified_by=f"sslyze completed a {label} handshake with the server",
            sources=[MODULE_NAME],
        )
        apply(finding, SeverityFactors(
            impact=impact, exploitability=exploit,
            auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
            confidence=Confidence.CONFIRMED,
        ))
        ctx.add_finding(finding)


_WEAK_CIPHER_TOKENS = ("RC4", "_DES_", "3DES", "NULL", "EXPORT", "anon", "MD5")


def _sslyze_ciphers(ctx, endpoint, scan) -> None:
    weak: set[str] = set()
    for key in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
        for suite in _accepted(scan.get(key)):
            name = suite.get("cipher_suite", {}).get("name", "")
            if any(token in name for token in _WEAK_CIPHER_TOKENS):
                weak.add(name)
    if not weak:
        ctx.add_passed(PassedCheck(
            name="No weak cipher suites offered on TLS 1.2/1.3",
            detail="No RC4, 3DES, NULL, EXPORT or anonymous suites were accepted.",
            source="sslyze", location=endpoint, score_area=AREA_TLS))
        return

    finding = Finding(
        name="Weak cipher suites accepted",
        severity=Severity.INFO, location=endpoint,
        description=(
            "The server accepts cipher suites that are no longer considered "
            "secure: " + ", ".join(sorted(weak)) + ". These remain negotiable "
            "and will be selected by any client that offers nothing better."
        ),
        remediation="Restrict the cipher list to modern AEAD suites.",
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{len(weak)} weak cipher suite(s) are negotiable.",
        risk="Weak suites offer materially less protection than the connection "
             "appears to provide — 3DES is vulnerable to birthday attacks on "
             "long-lived connections (Sweet32), RC4 to keystream biases, and "
             "anonymous suites provide no server authentication at all.",
        impact="Recovery of session data for clients that negotiate the weak "
               "suite, and in the anonymous case, undetected interception.",
        remediation_steps=[
            "Set an explicit modern cipher list "
            "(`ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...`).",
            "Enable `ssl_prefer_server_ciphers on` so the server's ordering wins.",
            "Re-test and confirm the weak suites are gone.",
        ],
        verification=f"Re-run `sslyze {endpoint}` and confirm the listed suites "
                     "no longer appear as accepted.",
        references=["https://ssl-config.mozilla.org/"],
        effort=Effort.TRIVIAL,
        score_area=AREA_TLS,
        evidence=", ".join(sorted(weak))[:500],
        verified_by="sslyze negotiated these suites with the server",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.LIMITED, exploitability=Exploitability.DIFFICULT,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
    ))
    ctx.add_finding(finding)


def _sslyze_cert(ctx, endpoint, scan) -> None:
    node = scan.get("certificate_info") or {}
    deployments = ((node.get("result", {}) or {})
                   .get("certificate_deployments", []) or [])
    if not deployments:
        return

    clean = True
    for dep in deployments:
        for validation in dep.get("path_validation_results", []):
            if validation.get("was_validation_successful") is not False:
                continue
            clean = False
            store = (validation.get("trust_store", {}) or {}).get("name", "a trust store")
            _cert_finding(
                ctx, endpoint,
                name="Certificate chain fails validation",
                detail=f"The presented chain failed validation against {store}.",
                risk="Clients cannot establish that they are talking to the "
                     "genuine server. Browsers show a full-page interstitial, "
                     "and API clients either fail outright or — worse — are "
                     "configured to ignore verification entirely.",
                impact="Users are trained to click through certificate warnings, "
                       "which removes any protection TLS offered against "
                       "interception on this site.",
                steps=["Serve the complete chain: leaf certificate followed by "
                       "every intermediate, in order.",
                       "Verify with `openssl s_client -connect "
                       f"{endpoint} -showcerts`.",
                       "If the certificate is self-signed, replace it with one "
                       "from a publicly trusted CA."],
                impact_level=Impact.SERIOUS,
                evidence=str(validation)[:400])

        if dep.get("leaf_certificate_subject_matches_hostname") is False:
            clean = False
            _cert_finding(
                ctx, endpoint,
                name="Certificate hostname mismatch",
                detail="The certificate's subject and SAN entries do not cover "
                       "the hostname being served.",
                risk="Every client sees a name-mismatch error, which is "
                     "indistinguishable from an active interception attempt.",
                impact="Clients cannot verify server identity; browser access is "
                       "blocked by an interstitial.",
                steps=["Reissue the certificate with the correct Subject "
                       "Alternative Names covering every hostname served.",
                       "Confirm the vhost serves the matching certificate."],
                impact_level=Impact.SERIOUS,
                evidence="leaf_certificate_subject_matches_hostname = false")

    if clean:
        ctx.add_passed(PassedCheck(
            name="Certificate chain validates and matches the hostname",
            detail="Path validation succeeded against the bundled trust stores.",
            source="sslyze", location=endpoint, score_area=AREA_TLS))


def _cert_finding(ctx, endpoint, name, detail, risk, impact, steps,
                  impact_level, evidence) -> None:
    finding = Finding(
        name=name, severity=Severity.INFO, location=endpoint,
        description=detail,
        remediation=steps[0],
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary=detail, risk=risk, impact=impact,
        remediation_steps=steps,
        verification=f"`openssl s_client -connect {endpoint} -verify_return_error` "
                     "should complete without error.",
        references=["https://www.ssllabs.com/ssltest/"],
        effort=Effort.EASY, score_area=AREA_TLS,
        evidence=evidence,
        verified_by="sslyze validated the presented chain",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact_level, exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
    ))
    ctx.add_finding(finding)


_KNOWN_FLAWS = {
    "heartbleed": ("is_vulnerable_to_heartbleed", "Heartbleed (CVE-2014-0160)",
                   Impact.TOTAL, Exploitability.PUBLIC_EXPLOIT,
                   "Memory disclosure from the server process, including private "
                   "keys and session data.",
                   "Upgrade OpenSSL to a fixed version and reissue the "
                   "certificate — the private key must be assumed compromised."),
    "openssl_ccs_injection": ("is_vulnerable_to_ccs_injection",
                              "OpenSSL CCS injection (CVE-2014-0224)",
                              Impact.SERIOUS, Exploitability.DIFFICULT,
                              "An attacker in the network path can force a weak "
                              "key and decrypt the session.",
                              "Upgrade OpenSSL to a fixed version."),
    "robot": ("robot_result", "ROBOT (RSA decryption oracle)",
              Impact.SERIOUS, Exploitability.DIFFICULT,
              "Recovery of the session key, and forging of signatures using the "
              "server's private key.",
              "Disable RSA key-exchange cipher suites; use ECDHE only."),
}


def _sslyze_known_flaws(ctx, endpoint, scan) -> None:
    for key, (field, label, impact, exploit, impact_text, fix) in _KNOWN_FLAWS.items():
        node = scan.get(key)
        if node is None:
            continue
        result = (node.get("result", {}) or {})
        value = result.get(field)
        vulnerable = value is True or (isinstance(value, str)
                                       and "not_vulnerable" not in value.lower()
                                       and "no_" not in value.lower())
        if not vulnerable:
            ctx.add_passed(PassedCheck(
                name=f"Not vulnerable to {label}",
                detail=f"sslyze tested the condition directly: {field}={value}.",
                source="sslyze", location=endpoint, score_area=AREA_TLS))
            continue

        finding = Finding(
            name=f"TLS implementation vulnerable to {label}",
            severity=Severity.INFO, location=endpoint,
            description=(
                f"sslyze actively tested for {label} and the server responded in "
                "the vulnerable manner. This is a behavioural test, not a version "
                "comparison."
            ),
            remediation=fix,
            ftype=FindingType.CONFIRMED_VULN,
            module=MODULE_NAME, category=CATEGORY,
            summary=f"{label} confirmed by active test.",
            risk=f"{label} is a well-documented flaw with public tooling.",
            impact=impact_text,
            remediation_steps=[fix,
                               "Restart the affected services after upgrading.",
                               "Re-test to confirm the condition is cleared."],
            verification=f"Re-run `sslyze {endpoint}` and confirm the check "
                         "reports not vulnerable.",
            effort=Effort.MODERATE, score_area=AREA_TLS,
            evidence=f"{field} = {value}",
            verified_by="sslyze performed the vulnerability-specific handshake test",
            sources=[MODULE_NAME],
        )
        apply(finding, SeverityFactors(
            impact=impact, exploitability=exploit,
            auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
            confidence=Confidence.CONFIRMED,
        ))
        ctx.add_finding(finding)



_TESTSSL_SEVERITY = {
    "CRITICAL": (Impact.SERIOUS, Exploitability.EASY),
    "HIGH": (Impact.SERIOUS, Exploitability.MODERATE),
    "MEDIUM": (Impact.LIMITED, Exploitability.DIFFICULT),
    "LOW": (Impact.INFORMATION, Exploitability.THEORETICAL),
    "WARN": (Impact.INFORMATION, Exploitability.THEORETICAL),
}


def _run_testssl(ctx, info, endpoint) -> None:
    with temp_output(".json") as (json_path, read_output):
        argv = [info.path, "--jsonfile", json_path, "--quiet", "--color", "0",
                endpoint]
        proc = run_tool(argv, timeout=int(ctx.config.get("ssl_timeout", 300)),
                        logger=ctx.logger,
                        ctx=ctx, tool="sslscan")
        if proc is not None and proc.stdout:
            ctx.add_raw_output("testssl.sh", proc.stdout)
        raw = read_output()

    if not raw.strip():
        ctx.logger and ctx.logger.warning("testssl.sh produced no JSON output")
        return
    ctx.add_raw_output("testssl.sh (json)", raw)
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(items, list):
        return
    _testssl_items(ctx, endpoint, items)


def _testssl_items(ctx, endpoint, items) -> None:

    for item in items:
        level = str(item.get("severity", "")).upper()
        ident = str(item.get("id", "issue"))
        finding_text = str(item.get("finding", "")).strip()

        if level in ("OK", "INFO"):
            if level == "OK" and finding_text:
                ctx.add_passed(PassedCheck(
                    name=f"{ident}: OK",
                    detail=finding_text[:200], source="testssl.sh",
                    location=endpoint, score_area=AREA_TLS))
            continue

        mapping = _TESTSSL_SEVERITY.get(level)
        if mapping is None:
            continue
        impact, exploit = mapping
        cve = item.get("cve") or ""

        finding = Finding(
            name=f"TLS: {finding_text[:80] or ident}",
            severity=Severity.INFO, location=endpoint,
            description=(
                f"testssl.sh check `{ident}` returned: {finding_text}\n\n"
                "testssl.sh performs live handshakes, so this reflects the "
                "server's actual negotiated behaviour."
            ),
            remediation="Adjust the TLS configuration so this check passes.",
            ftype=FindingType.MISCONFIGURATION,
            module=MODULE_NAME, category=CATEGORY,
            summary=finding_text[:180],
            risk="The TLS configuration deviates from current best practice in a "
                 "way testssl.sh rates as " + level.title() + ".",
            impact="Reduced confidentiality or integrity of connections to this "
                   "endpoint, to the degree implied by the specific check.",
            remediation_steps=[
                "Consult the Mozilla SSL Configuration Generator for a "
                "configuration matching your server and required client support.",
                f"Apply the change and re-run `testssl.sh {endpoint}` to confirm "
                f"`{ident}` clears.",
            ],
            verification=f"`testssl.sh {endpoint}` must no longer report "
                         f"`{ident}` at {level}.",
            references=([f"https://nvd.nist.gov/vuln/detail/{c}"
                         for c in str(cve).split()[:3]] if cve
                        else ["https://ssl-config.mozilla.org/"]),
            effort=Effort.EASY, score_area=AREA_TLS,
            evidence=f"{ident}: {finding_text}"[:500],
            verified_by="testssl.sh negotiated with the server to reach this verdict",
            sources=[MODULE_NAME],
        )
        apply(finding, SeverityFactors(
            impact=impact, exploitability=exploit,
            auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
            confidence=Confidence.CONFIRMED,
        ))
        ctx.add_finding(finding)


def register():
    from ..core.plugins import integration
    return integration('sslscan', run, available, phase='recon', order=60)
