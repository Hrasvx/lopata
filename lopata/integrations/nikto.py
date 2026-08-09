"""nikto integration.

nikto is high-recall and low-precision by design. Everything it reports is
treated as a *claim* that lopata then tries to check: GET-able findings are
re-fetched and compared against the learned soft-404 baseline, and the message
is classified so that a missing header becomes a Misconfiguration rather than
a "vulnerability", and an outdated-version notice becomes a Low-confidence
patch-management lead rather than a High.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

import requests

from ..core.baseline import ResponseSnapshot, similarity
from ..core.models import (AREA_CONFIG, AREA_HTTP, AREA_PATCH, AREA_WEBAPP,
                           Confidence, Effort, Finding, FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from .base import detect, run_tool, temp_output

MODULE_NAME = "nikto"
CATEGORY = "Server Misconfiguration"


def available(ctx):
    return detect(ctx, "nikto", ("nikto", "nikto.pl"), lambda p: [p, "-Version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    with temp_output(".json") as (json_path, read_output):
        argv = [info.path, "-h", ctx.target, "-Format", "json",
                "-output", json_path, "-nointeractive",
                "-maxtime", str(int(ctx.config.get("nikto_maxtime", 120)))]
        if not ctx.config.get("verify_tls", True):
            argv += ["-nossl"] if ctx.target.startswith("http://") else []
        proc = run_tool(argv, timeout=int(ctx.config.get("nikto_timeout", 240)),
                        logger=ctx.logger,
                        ctx=ctx, tool="nikto")
        phase and phase.step()
        raw = read_output()

    if not raw:
        if proc is not None:
            ctx.logger and ctx.logger.warning(
                "nikto wrote no JSON output; skipping its results")
        return
    ctx.add_raw_output("nikto", raw)

    items = _parse_json(raw)
    kept = dropped = 0
    for item in items:
        try:
            handled = _handle(ctx, item)
        except Exception as exc:
            ctx.logger and ctx.logger.warning(
                "nikto item skipped (%s): %.120s", exc.__class__.__name__, item)
            dropped += 1
            continue
        if handled:
            kept += 1
        else:
            dropped += 1
    if dropped and ctx.logger:
        ctx.logger.info("nikto: %d/%d item(s) discarded as unverifiable or noise",
                        dropped, kept + dropped)
    if phase:
        phase.done()


def _parse_json(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return []
        try:
            data = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return []
    if isinstance(data, list):
        data = data[0] if data else {}
    return data.get("vulnerabilities", []) or []



class _Rule:
    """One recognised class of nikto message."""

    __slots__ = ("pattern", "name", "ftype", "category", "area", "impact",
                 "exploit", "effort", "risk", "fix_steps", "verify", "drop")

    def __init__(self, pattern, name, ftype, category, area, impact, exploit,
                 effort, risk="", fix_steps=(), verify="", drop=False):
        self.pattern = re.compile(pattern, re.I)
        self.name = name
        self.ftype = ftype
        self.category = category
        self.area = area
        self.impact = impact
        self.exploit = exploit
        self.effort = effort
        self.risk = risk
        self.fix_steps = list(fix_steps)
        self.verify = verify
        self.drop = drop


_RULES = [
    # Pure noise or things covered far better by lopata's own checks.
    _Rule(r"no CGI directories found|scan terminated|host header|retrieved x-powered-by"
          r"|allowed http methods.*\bGET\b.*\bHEAD\b.*\bPOST\b\s*$",
          "", FindingType.INFORMATIONAL, "", AREA_CONFIG, Impact.NEGLIGIBLE,
          Exploitability.NONE, Effort.TRIVIAL, drop=True),

    _Rule(r"appears to be outdated|the anti-clickjacking.*not present|is out of date"
          r"|current is at least",
          "Outdated server software indicated by banner",
          FindingType.POTENTIAL_VULN, "Patch Management", AREA_PATCH,
          Impact.LIMITED, Exploitability.THEORETICAL, Effort.EASY,
          risk="nikto compared the advertised server banner against its version "
               "database and believes the software is behind. This is a banner "
               "comparison only — no behaviour was tested, and backported "
               "distribution patches are invisible to it.",
          fix_steps=["Check the installed package version on the host rather "
                     "than the network banner.",
                     "Apply outstanding vendor security updates.",
                     "Suppress detailed version information in the Server header."],
          verify="Confirm the installed package version against your "
                 "distribution's security tracker."),

    _Rule(r"header is not (present|set)|missing.*header|header missing"
          r"|uncommon header",
          "", FindingType.MISCONFIGURATION, "Security Headers", AREA_HTTP,
          Impact.INFORMATION, Exploitability.DIFFICULT, Effort.TRIVIAL,
          risk="A response header that hardens the browser's handling of this "
               "site is absent.",
          fix_steps=["Set the header on all responses at the web server or "
                     "reverse proxy."],
          verify="`curl -sI <url>` should show the header on every response."),

    _Rule(r"directory indexing|index of /",
          "Directory indexing enabled",
          FindingType.MISCONFIGURATION, "Server Misconfiguration", AREA_CONFIG,
          Impact.INFORMATION, Exploitability.EASY, Effort.TRIVIAL,
          risk="The server returns a generated listing of directory contents, "
               "letting an attacker harvest file names — including backups and "
               "files never meant to be linked.",
          fix_steps=["Disable auto-indexing (`Options -Indexes` in Apache, "
                     "`autoindex off` in nginx).",
                     "Place an index file in directories that must remain served."],
          verify="Request the directory again; it should return 403 or an index "
                 "page rather than a file listing."),

    _Rule(r"\.git|\.svn|\.env\b|config(uration)? file|backup|\.bak\b|\.old\b"
          r"|phpinfo|\.sql\b|password file|private key",
          "Sensitive file or directory reachable",
          FindingType.EXPOSURE, "Sensitive File Exposure", AREA_CONFIG,
          Impact.SERIOUS, Exploitability.EASY, Effort.EASY,
          risk="A file that should not be served from the web root is reachable "
               "over HTTP. Source metadata, configuration and backups routinely "
               "contain credentials and internal hostnames.",
          fix_steps=["Remove the file from the web root.",
                     "Add a server rule denying access to the path or extension.",
                     "Rotate any credentials the file may have exposed.",
                     "Move deployment artefacts out of the served directory tree."],
          verify="Re-request the URL; it must return 403 or 404."),

    _Rule(r"trace|track method",
          "HTTP TRACE/TRACK method enabled",
          FindingType.MISCONFIGURATION, "Server Misconfiguration", AREA_CONFIG,
          Impact.INFORMATION, Exploitability.DIFFICULT, Effort.TRIVIAL,
          risk="TRACE echoes the request back, which historically enabled "
               "cross-site tracing to read headers the browser would otherwise "
               "protect.",
          fix_steps=["Set `TraceEnable off` in Apache, or reject TRACE at the "
                     "reverse proxy."],
          verify="`curl -X TRACE <url>` must return 405."),

    _Rule(r"put method|webdav|allows.*(PUT|DELETE)",
          "Dangerous HTTP method enabled",
          FindingType.MISCONFIGURATION, "Server Misconfiguration", AREA_CONFIG,
          Impact.SERIOUS, Exploitability.EASY, Effort.EASY,
          risk="The server advertises write methods. If they are not tightly "
               "authenticated, an attacker can upload or delete content — often "
               "leading directly to code execution.",
          fix_steps=["Disable PUT/DELETE/WebDAV unless an application requires them.",
                     "Where required, enforce authentication and restrict them to "
                     "specific paths."],
          verify="`curl -X PUT <url> -d test` must return 405 or 403."),

    _Rule(r"cookie.*without.*(httponly|secure)|cookie.*flag",
          "", FindingType.MISCONFIGURATION, "Cookies", AREA_HTTP,
          Impact.INFORMATION, Exploitability.DIFFICULT, Effort.TRIVIAL,
          risk="A cookie is set without its protective attributes.",
          fix_steps=["Add the missing attribute where the cookie is issued."],
          verify="Inspect Set-Cookie on the response."),

    _Rule(r"sql injection|cross[- ]site scripting|remote file inclusion"
          r"|command execution|traversal",
          "", FindingType.POTENTIAL_VULN, "Injection", AREA_WEBAPP,
          Impact.SERIOUS, Exploitability.MODERATE, Effort.MODERATE,
          risk="nikto's signature database matched a pattern associated with an "
               "injection flaw. Signature matches of this kind are frequently "
               "wrong and must be reproduced by hand before being believed.",
          fix_steps=["Reproduce the request manually and observe the response.",
                     "If confirmed, parameterise the query or encode the output "
                     "at the point of use.",
                     "Add input validation at the trust boundary."],
          verify="Replay the request shown in the evidence and confirm whether "
                 "the payload is reflected or executed."),

    _Rule(r"leaks inodes|etag",
          "Server discloses inode numbers via ETag",
          FindingType.INFORMATIONAL, "Information Disclosure", AREA_CONFIG,
          Impact.NEGLIGIBLE, Exploitability.NONE, Effort.TRIVIAL,
          risk="The ETag header includes the file inode, leaking a small amount "
               "of filesystem detail.",
          fix_steps=["Set `FileETag MTime Size` in Apache to omit the inode."],
          verify="`curl -sI <url> | grep ETag` should no longer show three "
                 "hyphen-separated fields."),
]

_GENERIC = _Rule(
    r".", "", FindingType.INFORMATIONAL, "Server Misconfiguration", AREA_CONFIG,
    Impact.INFORMATION, Exploitability.THEORETICAL, Effort.MODERATE,
    risk="nikto flagged this item from its signature database.",
    fix_steps=["Review the flagged resource and confirm whether the behaviour "
               "is intended."],
    verify="Reproduce the request in the evidence and judge the response.")


def _match_rule(msg: str) -> _Rule:
    for rule in _RULES:
        if rule.pattern.search(msg):
            return rule
    return _GENERIC



def _handle(ctx, item: dict) -> bool:
    url = item.get("url") or ""
    msg = (item.get("msg") or "").strip()
    method = (item.get("method") or "GET").upper()
    if not msg:
        return False

    rule = _match_rule(msg)
    if rule.drop:
        return False

    full = (url if url.startswith("http")
            else ctx.target.rstrip("/") + "/" + url.lstrip("/"))

    confidence = Confidence.LOW
    verified_by = ""
    evidence_http = ""

    if url and method == "GET":
        verdict, detail = _reverify(ctx, full)
        if verdict == "absent":
            ctx.logger and ctx.logger.debug(
                "nikto item dropped (soft-404 / not present): %s", full)
            return False
        if verdict == "present":
            confidence = Confidence.MEDIUM
            verified_by = "lopata re-fetched the URL and it returned content "\
                          "distinct from the not-found baseline"
            evidence_http = detail
        else:
            evidence_http = detail
    elif not url:
        # A header/banner observation about the site as a whole.
        confidence = Confidence.MEDIUM
        full = ctx.target

    # An outdated-banner claim is version matching however it is dressed up.
    if rule.area == AREA_PATCH:
        confidence = Confidence.LOW
        verified_by = ""

    name = rule.name or _short(msg)
    path = urlparse(full).path
    if not rule.name and path not in ("", "/") and len(msg) < 60:
        name = f"{_short(msg, 60).rstrip('.')}: {path}"
    finding = Finding(
        name=name,
        severity=Severity.INFO, location=full or ctx.target,
        description=(
            f"nikto reported: {msg}\n\n"
            + (f"lopata re-requested the URL to check the claim: {evidence_http}"
               if evidence_http else
               "This item could not be re-checked automatically (non-GET or no "
               "URL), so it rests on nikto's report alone.")
        ),
        remediation=(rule.fix_steps[0] if rule.fix_steps
                     else "Review the flagged item and correct the configuration."),
        ftype=rule.ftype,
        module=MODULE_NAME,
        category=rule.category or CATEGORY,
        # nikto's "id" is a number in its JSON output, not a string.
        evidence=" ".join(str(x) for x in (item.get("id", ""), msg) if x)[:800],
        summary=_short(msg, 140),
        risk=rule.risk,
        impact=_impact_text(rule),
        remediation_steps=rule.fix_steps,
        verification=rule.verify,
        references=_references(item),
        effort=rule.effort,
        score_area=rule.area,
        request=f"{method} {full}" if url else "",
        response=evidence_http,
        verified_by=verified_by,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=rule.impact,
        exploitability=rule.exploit,
        auth=AuthRequirement.NONE,
        exposure=Exposure.PUBLIC,
        confidence=confidence,
    ))
    ctx.add_finding(finding)
    return True


def _reverify(ctx, url: str) -> tuple[str, str]:
    """Fetch the URL ourselves. Returns (present|absent|unknown, detail)."""
    baseline = getattr(ctx, "baseline", None)
    try:
        resp = ctx.session.get(url, timeout=ctx.timeout, allow_redirects=False)
    except requests.RequestException as exc:
        return "unknown", f"re-request failed: {exc.__class__.__name__}"

    detail = f"HTTP {resp.status_code}, {len(resp.content or b'')} bytes"
    if resp.status_code >= 400:
        return "absent", detail
    if resp.is_redirect:
        return "unknown", detail + f", redirects to {resp.headers.get('Location', '')}"

    snap = ResponseSnapshot.capture(resp)
    if baseline is not None:
        if baseline.looks_like_not_found(snap):
            return "absent", detail + " (matches the soft-404 baseline)"
        root = getattr(baseline, "root", None)
        if (root is not None and not _is_root(url)
                and similarity(snap.body, root.body) >= 0.98):
            return "absent", detail + " (identical to the site homepage)"
    return "present", detail


def _is_root(url: str) -> bool:
    return urlparse(url).path in ("", "/")


def _impact_text(rule: _Rule) -> str:
    return {
        Impact.TOTAL: "Full compromise of the host or application is plausible "
                      "if the condition is real.",
        Impact.SERIOUS: "Confirmed, this would expose protected data or allow "
                        "an attacker to change server-side state.",
        Impact.LIMITED: "Impact is bounded — it assists an attacker but does not "
                        "on its own grant access.",
        Impact.INFORMATION: "Provides an attacker with information that makes "
                            "other attacks easier or more reliable.",
        Impact.NEGLIGIBLE: "No direct security impact; recorded for completeness.",
    }[rule.impact]


def _references(item: dict) -> list[str]:
    refs = []
    for key in ("references", "OSVDB", "osvdb", "id"):
        value = item.get(key)
        if isinstance(value, str) and value.startswith("http"):
            refs.append(value)
    return refs[:5]


def _short(msg: str, limit: int = 90) -> str:
    msg = " ".join(str(msg).split())
    return msg if len(msg) <= limit else msg[:limit - 1] + "…"


def register():
    from ..core.plugins import integration
    return integration('nikto', run, available, phase='recon', order=50)
