"""httpx (projectdiscovery) integration — fast HTTP probing.

Runs in the recon phase, after subfinder, to answer one question cheaply before
the crawler and the heavier tools spend time on dead names: *which* of the
discovered hosts actually serve HTTP? Live hosts are recorded on the context so
later phases can skip the rest, and httpx's technology fingerprints feed the
same technology registry whatweb and the passive fingerprinter populate — so a
component seen by two of them is promoted to High confidence by the existing
merge logic in ``ScanContext.add_technology``.

This is enrichment, not a finding source: httpx never asserts a vulnerability.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from ..core.models import Confidence, Technology
from .base import detect, host_of, run_tool, temp_input

MODULE_NAME = "httpx"
CATEGORY = "Technology Fingerprint"
PHASE = "recon"


def available(ctx):
    return detect(ctx, "httpx", ("httpx",), lambda p: [p, "-version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    scheme = urlparse(ctx.target).scheme or "https"
    inputs = [ctx.target]
    for sub in sorted(ctx.subdomains):
        inputs.append(f"{scheme}://{sub}")
    inputs = list(dict.fromkeys(inputs))

    with temp_input("\n".join(inputs) + "\n") as list_path:
        argv = [info.path, "-silent", "-json", "-no-color",
                "-status-code", "-title", "-tech-detect", "-web-server",
                "-timeout", str(int(ctx.timeout) + 5),
                "-l", list_path]
        proc = run_tool(argv, timeout=int(ctx.config.get("httpx_timeout", 120)),
                        logger=ctx.logger,
                        ctx=ctx, tool="httpx")
    phase and phase.step()
    if proc is None or not proc.stdout.strip():
        return
    ctx.add_raw_output("httpx", proc.stdout)

    live = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input") or ""
        host = (obj.get("host") or urlparse(url).hostname or "").lower()
        if not host:
            continue
        ctx.live_hosts.add(host)
        live += 1
        if url and _in_scope(url, ctx):
            ctx.discovered_urls.add(url)

        server = obj.get("webserver") or ""
        if server:
            ctx.add_technology(Technology(
                name=server, category="Web Server", sources=[MODULE_NAME],
                confidence=Confidence.LOW,
                evidence=f"httpx Server header on {url or host}"))
        for tech in obj.get("tech") or []:
            name = str(tech).strip()
            if not name:
                continue
            ctx.add_technology(Technology(
                name=name, category="Other", sources=[MODULE_NAME],
                confidence=Confidence.MEDIUM,
                evidence=f"httpx tech-detect on {url or host}"))

    if ctx.logger:
        ctx.logger.info("httpx: %d live host(s) confirmed", live)
    phase and phase.done()


def _in_scope(url: str, ctx) -> bool:
    host = (urlparse(url).hostname or "").lower()
    allowed = {host_of(ctx.target).lower()} | {s.lower() for s in ctx.subdomains}
    return host in allowed


def register():
    from ..core.plugins import integration
    return integration('httpx', run, available, phase='recon', order=20)
