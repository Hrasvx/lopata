"""Dalfox integration — an independent, context-aware XSS engine.

Dalfox runs alongside lopata's own ``modules/xss.py`` (post-discovery phase),
against the same injection points. It is deliberately *not* a replacement: its
value is being a second, independent opinion. Every finding it produces is
emitted with the same canonical name ("… cross-site scripting") and the same
``[param: name]`` location convention lopata's own XSS module uses, so when both
engines flag the same parameter the correlation pass sees two distinct sources
for one issue and raises confidence — exactly the way independent nmap/nikto
agreement is treated elsewhere. A Dalfox-only or lopata-only hit stays at
whatever confidence its single source justifies.

Confidence mapping: Dalfox's ``V`` (verified — it triggered the payload in a
headless browser) is treated as a real verification and kept as a Confirmed
Vulnerability at High confidence; its ``G``/``R`` (reflected / DOM-reflected but
not triggered) stay Potential at Medium.
"""

from __future__ import annotations

import json

from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from ._shared import injectable_targets
from .base import detect, run_tool

MODULE_NAME = "dalfox"
CATEGORY = "XSS"
PHASE = "post"

_REFS = ["https://cheatsheetseries.owasp.org/cheatsheets/"
         "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]


def available(ctx):
    return detect(ctx, "dalfox", ("dalfox",), lambda p: [p, "version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    max_targets = int(ctx.config.get("dalfox_max_targets", 40))
    targets = injectable_targets(ctx, max_targets)
    if not targets:
        targets = [{"method": "GET", "url": ctx.target.rstrip("/") + "/?q=1",
                    "param": "q", "data": {}}]
    total_budget = int(ctx.config.get("dalfox_timeout", 300))
    per_call = max(20, total_budget // max(len(targets), 1))
    if phase:
        phase.set_total(len(targets))

    seen: set[tuple] = set()
    raw_chunks: list[str] = []
    for target in targets:
        pocs, raw = _scan(ctx, info, target, per_call)
        if raw:
            raw_chunks.append(raw)
        for poc in pocs:
            key = (target["method"], target["url"], target["param"],
                   poc.get("type"))
            if key in seen:
                continue
            seen.add(key)
            finding = _finding(target, poc)
            if finding:
                ctx.add_finding(finding)
        phase and phase.step()

    if raw_chunks:
        ctx.add_raw_output("dalfox", "\n".join(raw_chunks))
    phase and phase.done()


def _scan(ctx, info, target, timeout):
    argv = [info.path, "url", target["url"], "-p", target["param"],
            "--format", "json", "--silence", "--no-color", "--skip-bav",
            "--timeout", str(int(ctx.timeout) + 3),
            "-w", str(min(ctx.threads, 20))]
    if target["method"] == "POST":
        argv += ["-X", "POST"]
        if target["data"]:
            argv += ["-d", "&".join(f"{k}={v}" for k, v in target["data"].items())]
    if not ctx.config.get("verify_tls", True):
        argv.append("--skip-verify")
    proc = run_tool(argv, timeout=timeout, logger=ctx.logger)
    if proc is None:
        return [], ""
    out = (proc.stdout or "").strip()
    return _parse(out), out


def _parse(text: str) -> list[dict]:
    """Dalfox emits either a JSON array or one JSON object per line depending on
    version; accept both."""
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    pocs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                pocs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return pocs


def _finding(target, poc: dict) -> Finding | None:
    ptype = str(poc.get("type") or "").upper()
    payload = poc.get("data") or poc.get("payload") or ""
    inject = poc.get("inject_type") or poc.get("evidence") or ""
    method = target["method"]
    loc_method = "" if method == "GET" else f"{method} "
    location = f"{target['url']} [{loc_method}param: {target['param']}]"

    if ptype == "V":
        ftype = FindingType.CONFIRMED_VULN
        confidence = Confidence.HIGH
        exploit = Exploitability.EASY
        verified_by = ("Dalfox triggered the payload in a headless browser "
                       "(independent verification)")
        headline = "Reflected cross-site scripting"
        detail = ("Dalfox injected a context-appropriate payload into "
                  f"`{target['param']}` and confirmed it executed in a real "
                  "browser engine.")
    else:
        ftype = FindingType.POTENTIAL_VULN
        confidence = Confidence.MEDIUM
        exploit = Exploitability.MODERATE
        verified_by = ""
        headline = ("DOM-based cross-site scripting"
                    if ptype == "R" else "Reflected cross-site scripting")
        detail = ("Dalfox observed the payload reflected into an executable "
                  f"context via `{target['param']}` but did not trigger it; a "
                  "context-appropriate break-out is likely but unproven.")

    finding = Finding(
        name=headline,
        severity=Severity.INFO,
        location=location,
        description=(
            detail + "\n\nThis result is from Dalfox, a dedicated XSS engine "
            "run independently of lopata's own checks. Where lopata's XSS "
            "module flags the same parameter, the two agree and confidence is "
            "raised; on its own it carries the confidence its evidence supports."
        ),
        remediation="Encode output for the context it lands in, at the point of "
                    "rendering; add a Content-Security-Policy without "
                    "'unsafe-inline'.",
        ftype=ftype,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"Dalfox flagged `{target['param']}` as XSS ({ptype or '?'}).",
        risk="Attacker-controlled input reaches an executable context in the "
             "page without adequate encoding.",
        impact="Script execution in the victim's session on this origin: session "
               "theft, actions as the user, and credential capture.",
        remediation_steps=[
            "Encode on output for the specific context (HTML/attribute/JS/URL).",
            "Use the template engine's contextual auto-escaping.",
            "Add a strict Content-Security-Policy as defence in depth.",
        ],
        verification=(f"Replay the Dalfox payload against `{target['param']}` and "
                      "confirm it is returned entity-encoded once fixed."),
        references=_REFS,
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=f"[{ptype}] {inject}\npayload: {payload}"[:1000],
        request=f"{method} {payload or target['url']}",
        verified_by=verified_by,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS, exploitability=exploit,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=confidence,
        notes=["reflected XSS requires the victim to follow a crafted link, "
               "which bounds it below stored XSS"],
    ))
    return finding


def register():
    from ..core.plugins import integration
    return integration('dalfox', run, available, phase='post', order=100)
