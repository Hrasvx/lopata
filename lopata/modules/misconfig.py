from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from ..core.baseline import ResponseSnapshot
from ..core.models import (AREA_CONFIG, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

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
            finding = Finding(
                name=f"Verbose error disclosure ({label})",
                severity=Severity.INFO, location=url,
                description=(
                    f"The server returned a {label} in the response body when "
                    "sent a deliberately malformed request. Debug output of this "
                    "kind is produced by a framework running with development "
                    "settings enabled in production."
                ),
                remediation="Disable debug mode and return generic error pages.",
                ftype=FindingType.MISCONFIGURATION,
                module=MODULE_NAME, category=CATEGORY,
                summary=f"A {label} is rendered to unauthenticated visitors.",
                risk=(
                    "Stack traces hand an attacker the internal file layout, "
                    "framework and library versions, the shape of the query that "
                    "failed, and frequently fragments of configuration or "
                    "credentials. Some debug pages (Werkzeug, Laravel Ignition) "
                    "go further and expose an interactive console or the full "
                    "environment."
                ),
                impact=(
                    "Reconnaissance that turns blind probing into targeted "
                    "attack. Where the debug page includes a console or "
                    "environment dump, the impact rises to direct compromise."
                ),
                remediation_steps=[
                    "Turn off debug mode in the production environment "
                    "(`DEBUG=False` in Django, `APP_DEBUG=false` in Laravel, "
                    "`display_errors=Off` in PHP).",
                    "Configure a generic error page for 4xx and 5xx responses.",
                    "Log the detail server-side, where only operators can read it.",
                    "Verify the setting is enforced by the deployment "
                    "configuration, not just by a local .env file.",
                ],
                verification=(
                    "Re-send the malformed request shown below; the response "
                    "should be a generic error page with no trace."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                effort=Effort.EASY,
                score_area=AREA_CONFIG,
                evidence=body[max(0, m.start() - 40):m.start() + 160].replace("\n", " "),
                request=f"GET {url}",
                response=f"HTTP {resp.status_code}",
                verified_by="lopata triggered the error and read the trace back",
                sources=[MODULE_NAME],
            )
            apply(finding, SeverityFactors(
                impact=Impact.INFORMATION,
                exploitability=Exploitability.EASY,
                auth=AuthRequirement.NONE,
                exposure=Exposure.PUBLIC,
                confidence=Confidence.CONFIRMED,
            ))
            ctx.add_finding(finding)
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
        finding = Finding(
            name="Directory listing enabled",
            severity=Severity.INFO, location=target,
            description=(
                "The server generated an index of this directory's contents "
                "instead of returning 403. Everything in the directory is "
                "therefore enumerable, including files that are not linked from "
                "anywhere on the site."
            ),
            remediation="Disable automatic directory indexing.",
            ftype=FindingType.MISCONFIGURATION,
            module=MODULE_NAME, category=CATEGORY,
            summary=f"Directory contents are listed at {target}.",
            risk=(
                "Attackers harvest listings for exactly the files that are never "
                "linked: editor backups, database dumps left after a migration, "
                "old copies of configuration, and staging artefacts. It removes "
                "the guesswork from finding them."
            ),
            impact=(
                "Discovery of unlinked files, which frequently leads directly to "
                "credential or source-code disclosure. The listing itself also "
                "reveals naming conventions useful elsewhere in the application."
            ),
            remediation_steps=[
                "Apache: `Options -Indexes` for the directory (or globally).",
                "nginx: ensure `autoindex off;` (the default) is not overridden.",
                "Place an empty index.html in directories that must stay served.",
                "Separately, move anything in the directory that should not be "
                "public out of the web root — hiding the listing is not the same "
                "as protecting the files.",
            ],
            verification=f"`curl -s {target}` should return 403 or an index page, "
                         "not a file listing.",
            references=[
                "https://owasp.org/www-community/attacks/Forced_browsing",
            ],
            effort=Effort.TRIVIAL,
            score_area=AREA_CONFIG,
            evidence=body[:300].replace("\n", " "),
            request=f"GET {target}",
            response="HTTP 200 with a generated directory index",
            verified_by="lopata requested the directory and parsed the index page",
            sources=[MODULE_NAME],
        )
        apply(finding, SeverityFactors(
            impact=Impact.LIMITED,
            exploitability=Exploitability.EASY,
            auth=AuthRequirement.NONE,
            exposure=Exposure.PUBLIC,
            confidence=Confidence.CONFIRMED,
        ))
        ctx.add_finding(finding)


def register():
    from ..core.plugins import web_module
    return web_module('misconfig', run, requires_crawl=True, order=80)
