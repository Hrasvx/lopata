"""SARIF 2.1.0 output for CI / GitHub code-scanning.

Deliberately mirrors ``json_out.write_json``: one entry point that walks
``ctx.findings`` and serialises them, adding nothing the finding does not
already carry. The target here is ``github/codeql-action/upload-sarif``, so the
document validates against the SARIF 2.1.0 schema and follows the two GitHub
conventions that are not in the base spec: a ``security-severity`` rule
property (a 0-10 number that drives the Security tab's severity), and stable
``partialFingerprints`` so the same issue is tracked as one alert across runs.

Web findings rarely have a source file and line — they live at URLs — so the
finding's ``location`` becomes the result's ``artifactLocation.uri``. When a
location does look like ``path:line`` (some tool-sourced findings do) the line
is emitted as a ``region`` as well.
"""

from __future__ import annotations

import json
import re

from ..core.models import Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemas/sarif-schema-2.1.0.json")
INFORMATION_URI = "https://github.com/hrasvx/lopata"

# SARIF has three result levels; map our five severities onto them. GitHub then
# refines the ordering from ``security-severity`` below, so this only decides
# error vs. warning vs. note in the Actions annotations.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub's numeric severity (0.0-10.0) when a finding carries no CVSS of its
# own. Aligned with GitHub's own CVSS bands: >=9 critical, >=7 high, >=4 medium.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

# location strings that already look like "some/file.py:123" — captured so a
# real line number survives into the SARIF region.
_FILE_LINE = re.compile(r"^(?P<path>[^\s?#]+?):(?P<line>\d+)$")


def _slug(text: str) -> str:
    """Stable, human-readable rule-id fragment.

    Digits and parenthetical asides (usually counts like "(3 path(s))") are
    stripped first so a rule keeps the same id whether one or five instances of
    the same issue were found.
    """
    text = re.sub(r"\([^)]*\)", "", text or "")
    text = re.sub(r"\d+", "", text)
    text = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return text or "finding"


def _rule_id(finding) -> str:
    module = _slug(finding.module or "lopata")
    return f"lopata/{module}/{_slug(finding.name)}"


def _location(finding) -> dict:
    """One SARIF location for a finding.

    A ``path:line`` location yields an artifact + region; anything else (the
    common case: a URL) yields a bare artifactLocation whose uri is that URL.
    """
    raw = finding.location or "unknown"
    match = _FILE_LINE.match(raw)
    if match:
        artifact = {"uri": match.group("path")}
        region = {"startLine": max(int(match.group("line")), 1)}
        phys = {"artifactLocation": artifact, "region": region}
    else:
        phys = {"artifactLocation": {"uri": raw}}
    return {"physicalLocation": phys}


def _message(finding) -> str:
    parts = [finding.name]
    detail = finding.summary or finding.description
    if detail and detail != finding.name:
        parts.append(detail.strip())
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence.strip()[:400]}")
    return "\n\n".join(p for p in parts if p)


def _help_text(finding) -> str:
    blocks = []
    if finding.description:
        blocks.append(finding.description.strip())
    if finding.remediation:
        blocks.append("Remediation: " + finding.remediation.strip())
    if finding.remediation_steps:
        blocks.append("\n".join(f"- {s}" for s in finding.remediation_steps))
    return "\n\n".join(blocks)


def _tags(finding) -> list[str]:
    tags = ["security"]
    cat = finding.resolved_category()
    if cat:
        tags.append(cat.lower())
    if finding.is_vulnerability:
        tags.append("vulnerability")
    return sorted(set(tags))


def _build_rule(finding) -> dict:
    security_severity = (f"{float(finding.cvss):.1f}" if finding.cvss is not None
                         else f"{_SECURITY_SEVERITY[finding.severity]:.1f}")
    help_uri = next((r for r in finding.references
                     if isinstance(r, str) and r.startswith("http")), None)
    rule = {
        "id": _rule_id(finding),
        "name": _slug(finding.name).replace("-", "_"),
        "shortDescription": {"text": finding.name[:200]},
        "fullDescription": {"text": (finding.summary
                                     or finding.description
                                     or finding.name)[:1000]},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "tags": _tags(finding),
            "security-severity": security_severity,
        },
    }
    help_text = _help_text(finding)
    if help_text:
        rule["help"] = {"text": help_text, "markdown": help_text}
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def _build_result(finding, rule_index: int) -> dict:
    result = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": _message(finding)},
        "locations": [_location(finding)],
        "partialFingerprints": {
            # Stable across runs: module + name + location, matching the JSON
            # report's dedup key, so GitHub keeps one alert per real issue.
            "lopataFingerprint/v1": "|".join((
                finding.module or "", finding.name, finding.location or "")),
        },
        "properties": {
            "confidence": finding.confidence.label,
            "finding_type": finding.ftype.label,
            "score_area": finding.score_area,
            "priority": finding.priority,
            "sources": finding.sources,
        },
    }
    extra = [loc for loc in finding.all_locations()[1:] if loc]
    if extra:
        result["relatedLocations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": loc}}}
            for loc in extra
        ]
    return result


def write_sarif(ctx, path: str, meta: dict, version: str) -> None:
    """Write ctx.findings as a SARIF 2.1.0 log ready for upload-sarif.

    Rules are deduplicated by id so the tool.driver.rules array carries one
    reportingDescriptor per finding class; every result references its rule by
    both id and index.
    """
    findings = sorted(ctx.findings, key=lambda f: -f.priority)

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    for finding in findings:
        rid = _rule_id(finding)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append(_build_rule(finding))
        else:
            # Keep the most severe defaultConfiguration/security-severity seen
            # for a shared rule, so the Security tab does not understate it.
            existing = rules[rule_index[rid]]
            new_ss = float(_build_rule(finding)["properties"]["security-severity"])
            old_ss = float(existing["properties"]["security-severity"])
            if new_ss > old_ss:
                existing["properties"]["security-severity"] = f"{new_ss:.1f}"
                existing["defaultConfiguration"]["level"] = _LEVEL[finding.severity]
        results.append(_build_result(finding, rule_index[rid]))

    invocation = {
        "executionSuccessful": True,
    }
    if meta.get("started_at"):
        invocation["startTimeUtc"] = meta["started_at"].isoformat()
    if meta.get("finished_at"):
        invocation["endTimeUtc"] = meta["finished_at"].isoformat()

    run = {
        "tool": {
            "driver": {
                "name": "lopata",
                "version": version,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "invocations": [invocation],
        "results": results,
    }
    if ctx.target:
        run["properties"] = {"target": ctx.target}

    payload = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
