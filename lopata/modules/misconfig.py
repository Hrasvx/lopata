from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from ..core.baseline import ResponseSnapshot, similarity
from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "misconfig"
CATEGORY = "Server Misconfiguration"

_STACK_SIGNS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"at [\w\.]+\([\w\.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"(Warning|Fatal error|Notice):.*on line \d+", re.I), "PHP error"),
    (re.compile(r"Microsoft \.NET Framework|System\.[A-Za-z]+Exception"), ".NET exception"),
    (re.compile(r"Whoops, looks like something went wrong"), "Laravel debug page"),
    (re.compile(r"Werkzeug Debugger|The debugger caught an exception"), "Flask/Werkzeug debugger"),
    (re.compile(r"ORA-\d{5}|SQLSTATE\["), "Database error"),
    (re.compile(r"Exception in thread"), "Runtime exception"),
]

_DIRLIST = re.compile(r"<title>Index of /|Directory listing for /|\[To Parent Directory\]", re.I)


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    baseline = getattr(ctx, "baseline", None)
    _verbose_errors(ctx, baseline)
    _directory_listing(ctx, baseline)
    phase and phase.done()


def _verbose_errors(ctx, baseline) -> None:

    candidates = [
        urljoin(ctx.target + "/", "%2e%2e%2f%2e%2e%2f"),
        ctx.target + "/'\";lopata",
    ]
    for url in list(ctx.discovered_urls)[:10]:
        if "?" in url:
            candidates.append(url + "%00lopata[]=1")
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = ctx.session.get(url, timeout=ctx.timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        body = resp.text or ""
        for pattern, label in _STACK_SIGNS:
            m = pattern.search(body)
            if not m:
                continue


            snap = ResponseSnapshot.capture(resp)
            if baseline is not None and baseline.looks_like_not_found(snap):
                continue
            ctx.add_finding(Finding(
                name=f"Verbose error disclosure ({label})",
                severity=Severity.MEDIUM, location=url,
                description=f"The server returned a {label} in the response body. "
                            "Stack traces reveal file paths, framework versions "
                            "and query structure useful to an attacker.",
                remediation="Disable debug mode in production; return generic "
                            "error pages and log details server-side only.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=body[max(0, m.start() - 40):m.start() + 160].replace("\n", " "),
                request=f"GET {url}",
                response=f"HTTP {resp.status_code}",
                confidence=Confidence.CONFIRMED))
            break


def _directory_listing(ctx, baseline) -> None:

    dirs = {"assets/", "uploads/", "images/", "static/", "files/", "backup/",
            "js/", "css/", "media/"}
    for url in ctx.discovered_urls:
        path = url[len(ctx.target):].strip("/")
        if "/" in path:
            dirs.add(path.rsplit("/", 1)[0] + "/")
    checked = set()
    for d in dirs:
        target = urljoin(ctx.target + "/", d)
        if target in checked:
            continue
        checked.add(target)
        try:
            resp = ctx.session.get(target, timeout=ctx.timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        body = resp.text or ""
        if not _DIRLIST.search(body):
            continue
        snap = ResponseSnapshot.capture(resp)
        if baseline is not None and baseline.looks_like_not_found(snap):
            continue
        ctx.add_finding(Finding(
            name="Directory listing enabled",
            severity=Severity.MEDIUM, location=target,
            description="The server returns an automatic index of directory "
                        "contents, exposing file names an attacker can harvest.",
            remediation="Disable auto-indexing (e.g. 'Options -Indexes' in "
                        "Apache, 'autoindex off' in nginx).",
            module=MODULE_NAME, category=CATEGORY,
            evidence=body[:200].replace("\n", " "),
            request=f"GET {target}",
            response=f"HTTP 200 directory index",
            confidence=Confidence.CONFIRMED))
