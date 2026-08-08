"""Content discovery (ffuf, or gobuster as a fallback).

Widens the URL inventory the crawler builds so that ``exposure`` and
``misconfig`` — which run later as web modules — have more paths to examine:
admin panels, backups, config files and the like that are never linked from the
HTML. Runs in the recon phase so its hits are in ``ctx.discovered_urls`` before
those modules execute.

An open port is not a finding and neither is a discovered path: ffuf only
populates the surface. Whether any path is *sensitive* is decided by the
existing modules, which apply the soft-404 baseline and their own knowledge
base. To keep ffuf itself honest we run it with auto-calibration (``-ac``), so a
site that answers 200 for everything does not flood the inventory.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from .base import detect, run_tool, temp_input, temp_output, which

MODULE_NAME = "ffuf"
CATEGORY = "Attack Surface"
PHASE = "recon"

# Small, high-signal list used when no wordlist is configured or installed.
# Deliberately compact — this is targeted discovery, not brute force.
_BUILTIN_WORDS = (
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "portal", "console", "manager", "phpmyadmin", "adminer.php", "cpanel",
    "api", "api/v1", "api/v2", "graphql", "swagger.json", "openapi.json",
    "actuator", "actuator/env", "metrics", "health", "status", "server-status",
    "server-info", "backup", "backups", "old", "tmp", "temp", "test", "dev",
    "staging", "uploads", "files", "private", "internal", "logs", "config",
    "conf", "includes", ".git/config", ".env", ".htaccess", "web.config",
    "robots.txt", "sitemap.xml", "database.sql", "dump.sql", "backup.zip",
    "backup.tar.gz", ".svn/entries", ".DS_Store", "config.php.bak",
)

_COMMON_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)


def available(ctx):
    info = detect(ctx, "ffuf", ("ffuf",), lambda p: [p, "-V"])
    if info.available:
        info.note = "ffuf"
        return info
    if ctx.config.get("tools", {}).get("ffuf", True):
        path = which("gobuster")
        if path:
            info.available = True
            info.path = path
            info.note = "gobuster"
            ctx.tools["ffuf"] = info
    return info


def _wordlist_path(ctx):
    import os
    configured = ctx.config.get("ffuf_wordlist")
    if configured and os.path.isfile(configured):
        return configured, None
    for candidate in _COMMON_WORDLISTS:
        if os.path.isfile(candidate):
            return candidate, None
    return None, "\n".join(_BUILTIN_WORDS) + "\n"


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    wl_path, builtin = _wordlist_path(ctx)
    max_hits = int(ctx.config.get("ffuf_max_hits", 60))
    timeout = int(ctx.config.get("ffuf_timeout", 180))

    ctxmgr = temp_input(builtin, ".txt") if builtin is not None else _noop(wl_path)
    with ctxmgr as list_path:
        if info.note == "gobuster":
            hits = _run_gobuster(ctx, info, list_path, timeout)
        else:
            hits = _run_ffuf(ctx, info, list_path, timeout)
    phase and phase.step()

    added = 0
    for url in hits[:max_hits]:
        if url not in ctx.discovered_urls:
            ctx.discovered_urls.add(url)
            added += 1
    if ctx.logger:
        ctx.logger.info("ffuf: %d path(s) added to the surface (%s)",
                        added, info.note)
    phase and phase.done()


class _noop:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, *a):
        return False


def _run_ffuf(ctx, info, wl_path, timeout) -> list[str]:
    base = ctx.target.rstrip("/") + "/FUZZ"
    with temp_output(".json") as (out_path, read_output):
        argv = [info.path, "-w", f"{wl_path}:FUZZ", "-u", base,
                "-mc", "200,204,301,302,307,401,403", "-ac", "-s",
                "-t", str(min(ctx.threads, 40)),
                "-timeout", str(int(ctx.timeout)),
                "-of", "json", "-o", out_path]
        if not ctx.config.get("verify_tls", True):
            argv.append("-k")
        run_tool(argv, timeout=timeout, logger=ctx.logger)
        raw = read_output()
    if not raw:
        return []
    ctx.add_raw_output("ffuf", raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    urls = []
    for res in data.get("results", []) or []:
        url = res.get("url")
        if not url:
            fuzz = (res.get("input") or {}).get("FUZZ")
            if fuzz:
                url = urljoin(ctx.target.rstrip("/") + "/", fuzz)
        if url:
            urls.append(url)
    return urls


_GOBUSTER_LINE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)", re.M)


def _run_gobuster(ctx, info, wl_path, timeout) -> list[str]:
    base = ctx.target.rstrip("/")
    argv = [info.path, "dir", "-u", base, "-w", wl_path, "-q", "-t",
            str(min(ctx.threads, 40)),
            "-s", "200,204,301,302,307,401,403", "-b", ""]
    if not ctx.config.get("verify_tls", True):
        argv.append("-k")
    proc = run_tool(argv, timeout=timeout, logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return []
    ctx.add_raw_output("gobuster", proc.stdout)
    urls = []
    for match in _GOBUSTER_LINE.finditer(proc.stdout):
        urls.append(urljoin(base + "/", match.group(1).lstrip("/")))
    return urls


def register():
    from ..core.plugins import integration
    return integration('ffuf', run, available, phase='recon', order=70)
