from __future__ import annotations

import json

import requests

from ..core.baseline import ResponseSnapshot
from ..core.models import Confidence, Finding, Severity
from .base import detect, run_tool

MODULE_NAME = "nikto"
CATEGORY = "Server Misconfiguration"

_OSVDB_SEVERITY = {
    "default": Severity.LOW,
}


def available(ctx):
    return detect(ctx, "nikto", ("nikto", "nikto.pl"), lambda p: [p, "-Version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    argv = [info.path, "-h", ctx.target, "-Format", "json", "-output", "-",
            "-nointeractive", "-maxtime", str(int(ctx.config.get("nikto_maxtime", 120)))]
    if not ctx.config.get("verify_tls", True):
        argv += ["-nossl"] if ctx.target.startswith("http://") else []
    proc = run_tool(argv, timeout=int(ctx.config.get("nikto_timeout", 240)),
                    logger=ctx.logger)
    phase and phase.step()
    if proc is None:
        return
    items = _parse_json(proc.stdout)
    kept = 0
    for it in items:
        if _confirm(ctx, it):
            kept += 1
    if phase:
        phase.done()


def _parse_json(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:

        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            return []
        try:
            data = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return []
    if isinstance(data, list):
        data = data[0] if data else {}
    return data.get("vulnerabilities", []) or []


def _confirm(ctx, item: dict) -> bool:
    url = item.get("url") or ""
    msg = (item.get("msg") or "").strip()
    method = item.get("method", "GET")
    if not msg:
        return False

    full = url if url.startswith("http") else ctx.target.rstrip("/") + "/" + url.lstrip("/")
    confidence = Confidence.TENTATIVE
    baseline = getattr(ctx, "baseline", None)

    if url and method.upper() == "GET":
        try:
            resp = ctx.session.get(full, timeout=ctx.timeout, allow_redirects=False)
            snap = ResponseSnapshot.capture(resp)
            if baseline is not None and baseline.looks_like_not_found(snap):
                ctx.logger and ctx.logger.debug(
                    "nikto item dropped (matches soft-404): %s", full)
                return False
            if resp.status_code < 400:
                confidence = Confidence.FIRM
        except requests.RequestException:
            pass

    ctx.add_finding(Finding(
        name=_short(msg),
        severity=_severity_for(msg),
        location=full or ctx.target,
        description=(
            f"nikto reported: {msg}\n\nCross-checked against the not-found "
            "baseline; " + ("re-fetch confirmed the resource is present."
                            if confidence == Confidence.FIRM
                            else "could not independently confirm — manual review advised.")
        ),
        remediation=(
            "Review the flagged resource/header. Remove exposed files, restrict "
            "access, or correct the misconfiguration nikto identified."
        ),
        module=MODULE_NAME, category=CATEGORY,
        evidence=(item.get("id", "") + " " + msg)[:800],
        confidence=confidence,
    ))
    return True


def _severity_for(msg: str) -> Severity:
    low = msg.lower()
    if any(k in low for k in ("sql", "traversal", "rce", "remote code", "shell")):
        return Severity.HIGH
    if any(k in low for k in ("exposed", "backup", ".git", "config", "phpinfo",
                              "directory indexing", "default")):
        return Severity.MEDIUM
    return Severity.LOW


def _short(msg: str, limit: int = 90) -> str:
    msg = msg.replace("\n", " ").strip()
    return msg if len(msg) <= limit else msg[:limit - 1] + "…"
