"""Arjun integration — hidden HTTP parameter discovery.

Runs in the post-discovery phase, after the crawler has mapped endpoints.
Parameters an application reads but never links (debug flags, id overrides,
redirect targets) are invisible to link- and form-parsing, yet they are exactly
the injection points that matter. Arjun brute-forces them against each endpoint.

What it produces is not a finding on its own — a hidden parameter is inventory,
recorded as an Informational item — but it is fed into ``ctx.discovered_params``
so the injection tools that run after it (Dalfox, sqlmap) test those points too.
"""

from __future__ import annotations

import json

from ..core.models import (AREA_SURFACE, Confidence, Effort, Finding,
                           FindingType, Severity)
from ._shared import candidate_urls
from .base import detect, run_tool, temp_output

MODULE_NAME = "arjun"
CATEGORY = "Attack Surface"
PHASE = "post"


def available(ctx):
    return detect(ctx, "arjun", ("arjun",), lambda p: [p, "--version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    max_urls = int(ctx.config.get("arjun_max_urls", 10))
    timeout = int(ctx.config.get("arjun_timeout", 180))
    endpoints = candidate_urls(ctx, max_urls)
    if phase:
        phase.set_total(max(len(endpoints), 1))

    discovered: dict[str, set] = {}
    for url in endpoints:
        params = _run_one(ctx, info, url, timeout)
        if params:
            ctx.add_params(url, params)
            discovered[url] = set(params)
        phase and phase.step()

    if discovered:
        _report(ctx, discovered)
    phase and phase.done()


def _run_one(ctx, info, url, timeout) -> list[str]:
    with temp_output(".json") as (out_path, read_output):
        argv = [info.path, "-u", url, "-oJ", out_path, "-q",
                "-t", str(min(ctx.threads, 10))]
        if not ctx.config.get("verify_tls", True):
            argv.append("--disable-redirects")  # harmless if unsupported
        run_tool(argv, timeout=timeout, logger=ctx.logger)
        raw = read_output()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return _extract_params(data, url)


def _extract_params(data, url) -> list[str]:
    """Arjun's JSON shape varies by version: sometimes {url: {params: [...]}},
    sometimes {url: [...]}, sometimes a bare {params: [...]}."""
    def as_names(value):
        if isinstance(value, dict):
            return [str(p) for p in value.get("params", []) if p]
        if isinstance(value, list):
            return [str(p) for p in value if p]
        return []

    if not isinstance(data, dict):
        return []
    if "params" in data and not any(k.startswith("http") for k in data):
        return as_names(data)
    names: list[str] = []
    for key, value in data.items():
        names.extend(as_names(value))
    return sorted(set(names))


def _report(ctx, discovered: dict[str, set]) -> None:
    total = sum(len(v) for v in discovered.values())
    lines = [f"  {url}\n    {', '.join(sorted(names))}"
             for url, names in sorted(discovered.items())]
    ctx.add_finding(Finding(
        name=f"{total} hidden HTTP parameter(s) discovered",
        severity=Severity.INFO,
        location=next(iter(sorted(discovered))),
        description=(
            f"Arjun found {total} parameter(s) across {len(discovered)} "
            "endpoint(s) that the application accepts but does not expose "
            "through any link or form:\n\n" + "\n".join(lines) + "\n\n"
            "Hidden parameters are not a vulnerability in themselves, but they "
            "are untested input surface. lopata handed them to its injection "
            "tools so they are covered by the XSS and SQL-injection checks."
        ),
        remediation="Confirm each accepted parameter is intentional and "
                    "validated; remove handling for any that are legacy.",
        ftype=FindingType.INVENTORY,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{total} undocumented parameter(s) on {len(discovered)} endpoint(s).",
        risk="Parameters that are read but never advertised are frequently "
             "forgotten by developers and skipped by testing, which is what "
             "makes them a common home for injection and access-control flaws.",
        impact="Informational — expands the input surface the injection checks "
               "were run against.",
        remediation_steps=[
            "Review each parameter and confirm it is still required.",
            "Ensure every accepted parameter is validated and authorised, "
            "including ones with no UI.",
        ],
        verification="Diff the discovered parameters against the application's "
                     "documented API contract.",
        effort=Effort.MODERATE,
        score_area=AREA_SURFACE,
        confidence=Confidence.INFORMATIONAL,
        evidence="\n".join(lines)[:1500],
        verified_by="Arjun confirmed each parameter changed the response",
        sources=[MODULE_NAME],
    ))


def register():
    from ..core.plugins import integration
    return integration('arjun', run, available, phase='post', order=80)
