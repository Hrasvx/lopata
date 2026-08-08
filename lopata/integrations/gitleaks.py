"""Secret scanning (gitleaks, or trufflehog as a fallback).

Credential leaks in client-side assets are a high-value finding class lopata's
own modules do not cover. This integration runs in the post-discovery phase over
the material the crawler already pulled down — page HTML, inline scripts and the
external JavaScript bundles it referenced — plus a bounded re-fetch of those
bundles, and hands the lot to gitleaks/trufflehog.

Matches become Security Exposure findings. Secrets are redacted in the report
(only a fingerprint of the value is shown); a leak backed by a provider-specific
rule (AWS keys, GitHub tokens, private keys) is High confidence, while a
generic high-entropy match stays Medium and is flagged for manual confirmation.
"""

from __future__ import annotations

import json
import os
import tempfile
from urllib.parse import urlparse

from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from .base import detect, run_tool, which

MODULE_NAME = "gitleaks"
CATEGORY = "Secret Exposure"
PHASE = "post"

# Rules that name a concrete provider secret — high signal, low false-positive.
_HIGH_CONFIDENCE_RULES = {
    "aws-access-token", "aws-secret-key", "github-pat", "github-fine-grained-pat",
    "gitlab-pat", "private-key", "rsa-private-key", "stripe-access-token",
    "slack-bot-token", "google-api-key", "gcp-service-account",
    "jwt", "twilio-api-key", "sendgrid-api-token", "npm-access-token",
}


def available(ctx):
    info = detect(ctx, "gitleaks", ("gitleaks",), lambda p: [p, "version"])
    if info.available:
        info.note = "gitleaks"
        return info
    if ctx.config.get("tools", {}).get("gitleaks", True):
        path = which("trufflehog")
        if path:
            info.available = True
            info.path = path
            info.note = "trufflehog"
            ctx.tools["gitleaks"] = info
    return info


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    corpus = _collect_corpus(ctx)
    if not corpus:
        ctx.logger and ctx.logger.info("gitleaks: no client-side assets to scan")
        phase and phase.done()
        return

    directory = tempfile.mkdtemp(prefix="lopata-secrets-")
    mapping: dict[str, str] = {}
    try:
        for i, (source, text) in enumerate(corpus):
            ext = ".js" if source.endswith(".js") or "javascript" in source else ".txt"
            fname = f"asset_{i}{ext}"
            with open(os.path.join(directory, fname), "w", encoding="utf-8") as fh:
                fh.write(text)
            mapping[fname] = source
        phase and phase.step()
        if info.note == "trufflehog":
            hits = _run_trufflehog(ctx, info, directory)
        else:
            hits = _run_gitleaks(ctx, info, directory)
    finally:
        import shutil
        shutil.rmtree(directory, ignore_errors=True)

    seen: set[tuple] = set()
    for hit in hits:
        key = (hit["rule"], hit["fingerprint"], hit["file"])
        if key in seen:
            continue
        seen.add(key)
        ctx.add_finding(_finding(hit, mapping))
    phase and phase.done()


def _collect_corpus(ctx) -> list[tuple[str, str]]:
    corpus: list[tuple[str, str]] = []
    for url, body in list(ctx.page_bodies.items())[:60]:
        if body:
            corpus.append((url, body))
    for url, text in list(getattr(ctx, "_inline_js", []))[:60]:
        if text:
            corpus.append((url + " (inline js)", text))

    # Re-fetch a bounded number of external bundles: secrets in built JS are the
    # highest-value target and the crawler did not retain their bodies.
    max_js = int(ctx.config.get("gitleaks_max_js", 30))
    for script_url in sorted(getattr(ctx, "_script_urls", set()))[:max_js]:
        try:
            resp = ctx.session.get(script_url, timeout=ctx.timeout)
        except Exception:
            continue
        if resp.status_code == 200 and resp.text:
            corpus.append((script_url, resp.text[:500000]))
    return corpus


def _run_gitleaks(ctx, info, directory) -> list[dict]:
    out_path = os.path.join(directory, "_gitleaks.json")
    argv = [info.path, "detect", "--source", directory, "--no-git",
            "--report-format", "json", "--report-path", out_path,
            "--redact", "--exit-code", "0"]
    run_tool(argv, timeout=int(ctx.config.get("gitleaks_timeout", 180)),
             logger=ctx.logger)
    try:
        with open(out_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    ctx.add_raw_output("gitleaks", json.dumps(data[:50], indent=1))
    hits = []
    for item in data or []:
        rule = str(item.get("RuleID") or item.get("Rule") or "").lower()
        secret = item.get("Secret") or item.get("Match") or ""
        hits.append({
            "rule": rule,
            "description": item.get("Description") or rule,
            "file": os.path.basename(item.get("File") or ""),
            "line": item.get("StartLine") or item.get("Line") or "?",
            "match": (item.get("Match") or "")[:160],
            "fingerprint": _fingerprint(secret),
        })
    return hits


def _run_trufflehog(ctx, info, directory) -> list[dict]:
    argv = [info.path, "filesystem", directory, "--json", "--no-update"]
    proc = run_tool(argv, timeout=int(ctx.config.get("gitleaks_timeout", 180)),
                    logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return []
    ctx.add_raw_output("trufflehog", proc.stdout[:20000])
    hits = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = (((obj.get("SourceMetadata") or {}).get("Data") or {})
                .get("Filesystem") or {})
        raw = obj.get("Raw") or obj.get("Redacted") or ""
        rule = str(obj.get("DetectorName") or "").lower()
        hits.append({
            "rule": rule,
            "description": f"{obj.get('DetectorName') or 'secret'}"
                           + (" (verified)" if obj.get("Verified") else ""),
            "file": os.path.basename(meta.get("file") or ""),
            "line": meta.get("line", "?"),
            "match": "",
            "fingerprint": _fingerprint(raw),
            "verified": bool(obj.get("Verified")),
        })
    return hits


def _fingerprint(secret: str) -> str:
    import hashlib
    if not secret:
        return "n/a"
    digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]
    tail = secret[-4:] if len(secret) >= 8 else ""
    return f"sha256:{digest}…{tail}"


def _finding(hit: dict, mapping: dict) -> Finding:
    source_url = mapping.get(hit["file"], hit["file"])
    high = hit["rule"] in _HIGH_CONFIDENCE_RULES or hit.get("verified")
    confidence = Confidence.HIGH if high else Confidence.MEDIUM

    finding = Finding(
        name=f"Secret leaked in client-side asset ({hit['description']})",
        severity=Severity.INFO,
        location=source_url,
        description=(
            f"A secret matching the `{hit['rule'] or 'generic'}` rule was found "
            f"in an asset served to every visitor:\n\n  {source_url}\n  line "
            f"{hit['line']}\n  fingerprint {hit['fingerprint']}\n\n"
            "The value is redacted here — only a fingerprint is shown — but it "
            "is present verbatim in content the target serves publicly. "
            + ("The pattern is provider-specific, so this is very likely a real "
               "credential." if high else "The match is a generic high-entropy "
               "string and may be a false positive; confirm it by hand.")
        ),
        remediation="Revoke and rotate the exposed credential, then remove it "
                    "from client-side code.",
        ftype=FindingType.EXPOSURE,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{hit['rule'] or 'high-entropy'} secret exposed in {source_url}.",
        risk="Any secret shipped to the browser is readable by every visitor and "
             "by anyone who fetches the asset. Front-end bundles routinely leak "
             "API keys, tokens and, occasionally, private keys.",
        impact="Direct use of the leaked credential against the service it "
               "authenticates to — data access, quota abuse, or account "
               "takeover depending on the key's scope.",
        remediation_steps=[
            "Revoke the credential immediately; assume it is compromised.",
            "Issue a new secret and keep it server-side only.",
            "Proxy calls that need the secret through your backend rather than "
            "embedding it in the client.",
            "Add secret scanning to CI so this is caught before deployment.",
        ],
        verification="Fetch the asset and grep for the credential; it must no "
                     "longer be present, and the old value must be revoked.",
        effort=Effort.EASY,
        score_area=AREA_WEBAPP,
        evidence=f"rule={hit['rule']} file={hit['file']} line={hit['line']} "
                 f"fingerprint={hit['fingerprint']}",
        verified_by=(f"{MODULE_NAME} matched a provider-specific rule"
                     if high else ""),
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=confidence,
        notes=["secret is served in client-side content and readable by anyone"],
    ))
    return finding


def register():
    from ..core.plugins import integration
    return integration('gitleaks', run, available, phase='post', order=130)
