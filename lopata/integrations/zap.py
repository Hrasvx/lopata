"""OWASP ZAP integration — a second, independent DAST signal.

ZAP is driven through its REST API. lopata manages the daemon's lifecycle: it
first tries to *attach* to a running instance at ``zap_api`` and, failing that,
*spawns* its own ``zap.sh -daemon`` (when ``zap_autostart``) on a free port with
a generated API key, waits for the API to come up, and tears it down at scan end
— including on error or interrupt (an ``atexit`` net backs the normal cleanup).
Set ``zap_autostart: false`` to require a pre-running daemon instead, or
``zap_cmd`` to point at the launcher. lopata spiders the target, reads ZAP's
passive alerts and — only when ``zap_active: true`` — runs a bounded active scan,
then classifies the alerts through the same pipeline as everything else.

Its purpose here is corroboration: ZAP alerts about XSS/SQLi/CSRF are emitted at
the same ``[param: name]`` locations lopata's own modules use, so when the two
agree the correlation pass raises confidence. A ZAP-only alert stands at the
conservative Medium a single external source earns; ZAP false-positive alerts
are dropped.
"""

from __future__ import annotations

import atexit
import os
import secrets
import socket
import subprocess
import time
from urllib.parse import urlparse

from ..core.models import (AREA_CONFIG, AREA_HTTP, AREA_WEBAPP, Confidence,
                           Effort, Finding, FindingType, Severity, ToolInfo)
from ..core.retry import supervise
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from ..core.tool_status import ToolRunStatus, ToolStatus
from .base import mark_skipped, which

_DEFAULT_API = "http://127.0.0.1:8080"

MODULE_NAME = "zap"
CATEGORY = "DAST"
PHASE = "post"

_RISK_SEED = {
    "High": (Impact.SERIOUS, Exploitability.EASY),
    "Medium": (Impact.LIMITED, Exploitability.MODERATE),
    "Low": (Impact.INFORMATION, Exploitability.DIFFICULT),
    "Informational": (Impact.NEGLIGIBLE, Exploitability.NONE),
}

_WEBAPP_HINTS = ("cross site scripting", "sql injection", "injection",
                 "path traversal", "remote", "command", "xxe", "ssrf",
                 "deserial", "redirect")


def _base(ctx) -> str:
    return str(ctx.config.get("zap_api", "http://127.0.0.1:8080")).rstrip("/")


def _get(ctx, path: str, **params):
    params["apikey"] = ctx.config.get("zap_api_key") or ""
    try:
        resp = ctx.session.get(_base(ctx) + path, params=params,
                               timeout=min(ctx.timeout, 15))
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        return None
    return None


def available(ctx):
    if "zap" in ctx.tools:
        return ctx.tools["zap"]
    if not ctx.config.get("tools", {}).get("zap", True):
        info = ToolInfo(name="zap", available=False, note="disabled in config")
        ctx.tools["zap"] = info
        return info

    # 1. Attach to an already-running instance at the configured API, if any.
    data = _get(ctx, "/JSON/core/view/version/")
    if data and data.get("version"):
        info = ToolInfo(name="zap", available=True, version=data["version"],
                        path=_base(ctx),
                        note=f"ZAP API {data['version']} (attached)")
        ctx.tools["zap"] = info
        return info

    # 2. Otherwise spawn our own daemon and tear it down at scan end.
    if ctx.config.get("zap_autostart", True):
        info = _spawn_zap(ctx)
        if info is not None:
            ctx.tools["zap"] = info
            return info

    # 3. Nothing to talk to.
    info = ToolInfo(
        name="zap", available=False,
        note=(f"ZAP API not reachable at {_base(ctx)} and could not autostart "
              "(install ZAP or start `zap.sh -daemon`, or set zap_cmd)"))
    ctx.logger and ctx.logger.info("[-] zap not available; skipping")
    ctx.tools["zap"] = info
    return info



def _find_zap(ctx) -> str | None:
    explicit = ctx.config.get("zap_cmd")
    if explicit:
        if os.path.isabs(explicit) and os.access(explicit, os.X_OK):
            return explicit
        return which(explicit)
    return which("zap.sh", "zap", "owasp-zap", "zaproxy")


def _free_port(host: str) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _resolve_bind(ctx) -> tuple[str, int]:
    api = str(ctx.config.get("zap_api", _DEFAULT_API))
    parsed = urlparse(api)
    host = parsed.hostname or "127.0.0.1"
    if api.rstrip("/") == _DEFAULT_API:
        return host, _free_port(host)
    return host, (parsed.port or 8080)


def _spawn_zap(ctx):
    binary = _find_zap(ctx)
    if not binary:
        ctx.logger and ctx.logger.info(
            "[-] zap binary not found; cannot autostart")
        return None

    host, port = _resolve_bind(ctx)
    key = ctx.config.get("zap_api_key") or secrets.token_hex(16)
    argv = [binary, "-daemon", "-host", host, "-port", str(port),
            "-config", f"api.key={key}",
            "-config", "api.addrs.addr.name=127.0.0.1",
            "-config", "api.addrs.addr.regex=true"]
    ctx.logger and ctx.logger.info(
        "starting ZAP daemon: %s -daemon -host %s -port %s", binary, host, port)

    try:
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 start_new_session=True)
    except Exception as exc:
        ctx.logger and ctx.logger.warning("failed to launch ZAP: %s", exc)
        return None

    # Point the API helpers at the daemon we just started.
    ctx.config["zap_api"] = f"http://{host}:{port}"
    ctx.config["zap_api_key"] = key
    ctx._zap_proc = proc
    ctx._zap_spawned = True
    ctx.add_cleanup(lambda: shutdown(ctx))
    atexit.register(lambda: shutdown(ctx))  # safety net for interrupt/crash

    timeout = int(ctx.config.get("zap_start_timeout", 90))
    ctx.ui and ctx.ui.note(f"starting ZAP daemon on port {port} "
                           f"(up to {timeout}s)…")
    if not _wait_ready(ctx, time.monotonic() + timeout, proc):
        ctx.logger and ctx.logger.warning(
            "ZAP did not become ready within %ss; giving up", timeout)
        shutdown(ctx)
        return None

    data = _get(ctx, "/JSON/core/view/version/") or {}
    version = data.get("version", "")
    ctx.logger and ctx.logger.info("ZAP daemon ready (version %s, pid %s)",
                                   version or "?", proc.pid)
    return ToolInfo(name="zap", available=True, version=version,
                    path=f"http://{host}:{port}",
                    note=f"ZAP {version} (auto-started, pid {proc.pid})")


def _wait_ready(ctx, deadline: float, proc) -> bool:
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            ctx.logger and ctx.logger.warning(
                "ZAP process exited early (code %s)", proc.returncode)
            return False
        data = _get(ctx, "/JSON/core/view/version/")
        if data and data.get("version"):
            return True
        time.sleep(2)
    return False


def shutdown(ctx) -> None:
    """Tear down a ZAP daemon we started. Idempotent; a no-op for attach mode."""
    proc = getattr(ctx, "_zap_proc", None)
    if not getattr(ctx, "_zap_spawned", False) or proc is None:
        return
    ctx._zap_spawned = False  # guard against the atexit + cleanup double-call
    ctx.logger and ctx.logger.info("shutting down ZAP daemon (pid %s)", proc.pid)
    try:
        _get(ctx, "/JSON/core/action/shutdown/")  # graceful
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    ctx._zap_proc = None


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        mark_skipped(ctx, MODULE_NAME, info.note or "ZAP API not reachable")
        return
    ctx.modules_run.append(MODULE_NAME)
    budget = int(ctx.config.get("zap_timeout", 600))

    def attempt(timeout: float):
        """One full spider (+ optional active scan) pass inside `timeout`.

        ZAP keeps its session between calls, so a retry with a longer budget
        continues from the crawl the previous attempt got through rather than
        starting over.
        """
        started = time.monotonic()
        deadline = started + timeout
        finished = True

        scan = _get(ctx, "/JSON/spider/action/scan/", url=ctx.target,
                    maxChildren=str(ctx.max_pages))
        if scan is None:
            return None, ToolRunStatus(
                tool_name=MODULE_NAME, status=ToolStatus.FAILED,
                duration_s=time.monotonic() - started,
                note="ZAP API stopped responding during the spider")
        if "scan" in scan:
            finished &= _poll(ctx, "/JSON/spider/view/status/", scan["scan"],
                              deadline)
        phase and phase.step()

        if ctx.config.get("zap_active", False):
            ascan = _get(ctx, "/JSON/ascan/action/scan/", url=ctx.target,
                         recurse="true", inScopeOnly="false")
            if ascan and "scan" in ascan:
                finished &= _poll(ctx, "/JSON/ascan/view/status/",
                                  ascan["scan"], deadline)
        phase and phase.step()

        alerts = _get(ctx, "/JSON/alert/view/alerts/", baseurl=ctx.target,
                      start="0", count="1000") or {}
        raw = alerts.get("alerts", []) or []
        status = ToolStatus.COMPLETED if finished else ToolStatus.TIMED_OUT
        return raw, ToolRunStatus(
            tool_name=MODULE_NAME, status=status,
            duration_s=time.monotonic() - started,
            note=("" if finished else
                  f"scan was still running when the {timeout:.0f}s budget ran out"))

    raw, _status = supervise(ctx, MODULE_NAME, attempt, budget)
    raw = raw or []
    if raw:
        ctx.add_raw_output("zap", _summarize_raw(raw))

    seen: set[tuple] = set()
    for alert in raw:
        if str(alert.get("confidence")) == "False Positive":
            continue
        key = (alert.get("pluginId"), alert.get("param"),
               (urlparse(alert.get("url", "")).path))
        if key in seen:
            continue
        seen.add(key)
        finding = _finding(alert)
        if finding:
            ctx.add_finding(finding)
    phase and phase.done()


def _poll(ctx, path: str, scan_id, deadline: float) -> bool:
    """Wait for a ZAP scan to reach 100%. False means it never got there —
    the budget ran out, or the API stopped answering."""
    while time.monotonic() < deadline:
        status = _get(ctx, path, scanId=str(scan_id))
        if not status:
            return False
        try:
            if int(status.get("status", "0")) >= 100:
                return True
        except (TypeError, ValueError):
            return False
        time.sleep(2)
    return False


def _summarize_raw(alerts) -> str:
    lines = []
    for a in alerts[:80]:
        lines.append(f"[{a.get('risk')}/{a.get('confidence')}] "
                     f"{a.get('alert')} — {a.get('url')}"
                     + (f" (param: {a.get('param')})" if a.get("param") else ""))
    return "\n".join(lines)


def _score_area(name: str) -> str:
    low = name.lower()
    if any(h in low for h in _WEBAPP_HINTS):
        return AREA_WEBAPP
    if "header" in low or "cookie" in low or "cors" in low or "csp" in low:
        return AREA_HTTP
    return AREA_CONFIG


def _finding(alert: dict) -> Finding | None:
    name = alert.get("alert") or alert.get("name") or "ZAP alert"
    risk = alert.get("risk") or "Low"
    url = alert.get("url") or ""
    param = alert.get("param") or ""
    low = name.lower()

    location = url
    if param:
        location = f"{url} [param: {param}]"

    if any(h in low for h in _WEBAPP_HINTS):
        ftype = FindingType.POTENTIAL_VULN
    elif risk == "Informational":
        ftype = FindingType.INFORMATIONAL
    else:
        ftype = FindingType.MISCONFIGURATION

    zap_conf = str(alert.get("confidence") or "")
    confidence = (Confidence.MEDIUM if zap_conf in ("High", "Confirmed", "Medium")
                  else Confidence.LOW)
    impact, exploit = _RISK_SEED.get(risk, _RISK_SEED["Low"])

    finding = Finding(
        name=name,
        severity=Severity.INFO,
        location=location or "(site-wide)",
        description=(
            f"OWASP ZAP raised this alert (risk: {risk}, ZAP confidence: "
            f"{zap_conf or 'n/a'})"
            + (f" against parameter `{param}`" if param else "") + ".\n\n"
            + (alert.get("description") or "").strip()
            + "\n\nZAP is a second, independent scanner. On its own this alert "
            "is held to Medium; where lopata's own check agrees, correlation "
            "raises confidence."
        ),
        remediation=(alert.get("solution")
                     or "Review the alert and apply the recommended control."),
        ftype=ftype,
        module=MODULE_NAME,
        category=_zap_category(low),
        summary=f"ZAP: {name} ({risk})",
        risk=(alert.get("description") or "").strip()[:400] or
             "Flagged by ZAP's passive/active rules.",
        impact="Follows the referenced ZAP alert; confirm against the target.",
        remediation_steps=[s for s in [(alert.get("solution") or "").strip()] if s]
                          or ["Review the flagged response and apply the fix ZAP "
                              "recommends."],
        verification="Re-run the ZAP scan and confirm the alert no longer fires.",
        references=[r for r in [(alert.get("reference") or "").strip()]
                    if r.startswith("http")],
        effort=Effort.MODERATE,
        score_area=_score_area(name),
        evidence=(f"url={url}\nparam={param}\nevidence={alert.get('evidence', '')}"
                  f"\ncweid={alert.get('cweid', '')}")[:900],
        request=f"GET {url}" if url else "",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact, exploitability=exploit,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=confidence,
        notes=["reported by OWASP ZAP; not independently reproduced by lopata"],
    ))
    return finding


def _zap_category(low: str) -> str:
    if "cross site scripting" in low:
        return "XSS"
    if "sql injection" in low:
        return "SQL Injection"
    if "csrf" in low:
        return "CSRF"
    if "cors" in low:
        return "CORS"
    if "header" in low:
        return "Security Headers"
    if "cookie" in low:
        return "Cookies"
    return "DAST"


def register():
    from ..core.plugins import integration
    return integration('zap', run, available, phase='post', order=120)
