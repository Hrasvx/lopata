"""Post-scan correlation.

Runs once, after every module and integration has reported. Its job is to turn
a pile of per-tool observations into one coherent finding set:

* identical observations from the same source collapse,
* the same issue seen by *different* sources becomes one finding with raised
  confidence (independent agreement is evidence),
* the same issue seen at many locations becomes one grouped finding,
* a single unverified source loses confidence rather than gaining it,
* severity is re-derived afterwards, because confidence caps severity.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse

from .models import Confidence, Finding, FindingType, Severity
from .severity import cap_for

# Canonical issue identities. Different tools describe the same problem in
# very different words; without this table "Missing header: X-Frame-Options"
# and nikto's "The anti-clickjacking X-Frame-Options header is not present"
# would be reported twice as if they were two problems.
_ALIASES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"x-frame-options|clickjack|frame-ancestors", re.I), "clickjacking"),
    (re.compile(r"content-security-policy|\bcsp\b", re.I), "csp"),
    (re.compile(r"strict-transport-security|\bhsts\b", re.I), "hsts"),
    (re.compile(r"x-content-type-options|nosniff", re.I), "content-type-options"),
    (re.compile(r"referrer-policy", re.I), "referrer-policy"),
    (re.compile(r"permissions-policy|feature-policy", re.I), "permissions-policy"),
    (re.compile(r"cross-origin-opener", re.I), "coop"),
    (re.compile(r"cross-origin-embedder", re.I), "coep"),
    (re.compile(r"cross-origin-resource-policy", re.I), "corp"),
    (re.compile(r"directory (listing|index)|index of /|autoindex", re.I), "directory-listing"),
    (re.compile(r"sql injection|\bsqli\b", re.I), "sqli"),
    (re.compile(r"cross[- ]site scripting|\bxss\b", re.I), "xss"),
    (re.compile(r"open redirect", re.I), "open-redirect"),
    (re.compile(r"\.git\b|git repository", re.I), "git-exposure"),
    (re.compile(r"\.svn\b", re.I), "svn-exposure"),
    (re.compile(r"phpinfo", re.I), "phpinfo"),
    (re.compile(r"\.env\b", re.I), "env-exposure"),
    (re.compile(r"backup (file|archive)|\.bak\b|database dump", re.I), "backup-exposure"),
    (re.compile(r"server (banner|header)|x-powered-by|version disclos", re.I),
     "banner-disclosure"),
    (re.compile(r"ssl ?v2|ssl ?v3|tls ?1\.0|tls ?1\.1|deprecated protocol", re.I),
     "weak-tls-protocol"),
    (re.compile(r"certificate (chain|valid|expire|name)", re.I), "certificate"),
    (re.compile(r"weak cipher|rc4|3des|null cipher|export cipher", re.I), "weak-cipher"),
    (re.compile(r"anti-?csrf|cross[- ]site request forgery|\bcsrf\b", re.I), "csrf"),
    (re.compile(r"\bcors\b|access-control-allow-origin", re.I), "cors"),
    (re.compile(r"cookie.*httponly", re.I), "cookie-httponly"),
    (re.compile(r"cookie.*secure", re.I), "cookie-secure"),
    (re.compile(r"cookie.*samesite", re.I), "cookie-samesite"),
    (re.compile(r"trace|track method", re.I), "http-trace"),
    (re.compile(r"stack trace|verbose error|debug (mode|page)", re.I), "verbose-error"),
]


# Locations that name a specific injection point, e.g.
# "https://host/search?q=1 [param: q]" or "... [POST param: id]".
_PER_PARAM = re.compile(r"\[(?:(\w+)\s+)?param:\s*([^\]]+)\]", re.I)


def injection_point(location: str) -> tuple | None:
    """Identify an injection point as (method, path, parameter).

    Crawling one endpoint with three different query values yields three URLs,
    but `/products?id=1` and `/products?id=3` are the same injectable
    parameter and the same one-line fix. Keying on path-plus-parameter — with
    the query values discarded — collapses them, while a genuinely different
    parameter or a different path stays separate.
    """
    match = _PER_PARAM.search(location)
    if not match:
        return None
    method = (match.group(1) or "GET").upper()
    param = match.group(2).strip()
    url = location[:match.start()].strip()
    parsed = urlparse(url)
    return (method, parsed.scheme, parsed.netloc, parsed.path, param)


def signature(finding: Finding) -> str:
    """Canonical identity for an issue, independent of the reporting tool."""
    haystack = f"{finding.name} {finding.summary}"
    for pattern, canon in _ALIASES:
        if pattern.search(haystack):
            return canon
    normalized = re.sub(r"[^a-z0-9]+", "-", finding.name.lower()).strip("-")
    return normalized or "unknown"


def correlate(ctx, logger=None) -> list[Finding]:
    """Collapse, corroborate and re-score ctx.findings in place."""
    findings = list(ctx.findings)
    before = len(findings)

    findings = _merge_same_location(findings)
    findings = _group_across_locations(findings)
    for finding in findings:
        _adjust_confidence(finding)
        _recap_severity(finding)

    findings.sort(key=lambda f: (-f.priority, -f.ftype.rank, f.name))
    ctx.findings = findings
    if logger and before != len(findings):
        logger.info("correlation: %d observation(s) -> %d finding(s)",
                    before, len(findings))
    return findings


def _merge_same_location(findings: list[Finding]) -> list[Finding]:
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[(signature(f), f.location)].append(f)

    merged: list[Finding] = []
    for group in buckets.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        # Keep the richest report as the base: strongest claim first, then the
        # one that actually verified something.
        group.sort(key=lambda f: (f.ftype.rank, int(f.confidence),
                                  int(f.severity), len(f.description)),
                   reverse=True)
        base = group[0]
        for other in group[1:]:
            _absorb(base, other)
        merged.append(base)
    return merged


def _group_across_locations(findings: list[Finding]) -> list[Finding]:
    """One issue affecting many URLs is one finding, not twenty.

    The exception is a per-parameter injection point: two SQL injections in
    two different parameters are two bugs with two fixes and two pieces of
    evidence, even though they share a name. A server-wide policy problem —
    CORS, a missing header, a framing gap — is one fix regardless of how many
    URLs exhibit it.
    """
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        point = injection_point(f.location)
        if point is not None:
            buckets[(signature(f), f.name) + point].append(f)
        else:
            buckets[(signature(f), f.name, f.severity)].append(f)

    out: list[Finding] = []
    for group in buckets.values():
        if len(group) == 1:
            out.append(group[0])
            continue
        group.sort(key=lambda f: (int(f.confidence), len(f.evidence)), reverse=True)
        base = group[0]
        for other in group[1:]:
            for loc in other.all_locations():
                if loc not in base.related_locations and loc != base.location:
                    base.related_locations.append(loc)
            for src in other.sources:
                if src not in base.sources:
                    base.sources.append(src)
        extra = len(base.related_locations)
        if extra:
            base.description = (
                base.description.rstrip()
                + f"\n\nThe same issue was observed at {extra + 1} locations in "
                  "total; they are listed under Affected below and share a "
                  "single fix."
            )
        out.append(base)
    return out


def _absorb(base: Finding, other: Finding) -> None:
    for src in other.sources:
        if src not in base.sources:
            base.sources.append(src)
    if other.evidence and other.evidence not in base.evidence:
        base.evidence = (base.evidence + "\n---\n" + other.evidence).strip("\n-")
    if not base.request and other.request:
        base.request = other.request
    if not base.response and other.response:
        base.response = other.response
    for ref in other.references:
        if ref not in base.references:
            base.references.append(ref)
    if not base.verified_by and other.verified_by:
        base.verified_by = other.verified_by
    if other.cvss is not None and (base.cvss is None or other.cvss > base.cvss):
        base.cvss = other.cvss


def _adjust_confidence(finding: Finding) -> None:
    """Independent agreement raises confidence; a lone unverified voice lowers it."""
    distinct = {s for s in finding.sources if s}
    if len(distinct) >= 2 and finding.confidence < Confidence.HIGH:
        finding.confidence = Confidence.HIGH
        finding.severity_reasons.append(
            f"{len(distinct)} independent sources agree ({', '.join(sorted(distinct))})"
        )
    elif (len(distinct) <= 1 and finding.confidence >= Confidence.HIGH
            and not finding.verified_by
            and finding.ftype is not FindingType.CONFIRMED_VULN):
        finding.confidence = Confidence.MEDIUM
        finding.severity_reasons.append(
            "reported by a single source and not independently verified — "
            "confidence reduced"
        )


def _recap_severity(finding: Finding) -> None:
    cap = cap_for(finding.confidence)
    if finding.severity > cap:
        finding.severity_reasons.append(
            f"severity capped at {cap.label} by {finding.confidence.label.lower()} "
            "confidence"
        )
        finding.severity = cap
    # A finding nobody could confirm is a lead, not a vulnerability.
    if (finding.ftype is FindingType.CONFIRMED_VULN
            and finding.confidence < Confidence.CONFIRMED
            and not finding.verified_by):
        finding.ftype = FindingType.POTENTIAL_VULN


def summarize(findings: list[Finding]) -> dict:
    by_type: dict[str, int] = defaultdict(int)
    by_sev: dict[str, int] = defaultdict(int)
    by_conf: dict[str, int] = defaultdict(int)
    by_cat: dict[str, int] = defaultdict(int)
    for f in findings:
        by_type[f.ftype.label] += 1
        by_sev[f.severity.label] += 1
        by_conf[f.confidence.label] += 1
        by_cat[f.resolved_category()] += 1
    return {
        "total": len(findings),
        "vulnerabilities": sum(1 for f in findings if f.is_vulnerability),
        "confirmed": sum(1 for f in findings
                         if f.confidence == Confidence.CONFIRMED),
        "actionable": sum(1 for f in findings
                          if f.severity >= Severity.MEDIUM
                          and f.confidence >= Confidence.MEDIUM),
        "quick_wins": sum(1 for f in findings if f.quick_win),
        "by_type": dict(by_type),
        "by_severity": dict(by_sev),
        "by_confidence": dict(by_conf),
        "by_category": dict(by_cat),
    }
