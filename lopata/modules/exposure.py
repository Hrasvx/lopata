from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests

from ..core.baseline import ResponseSnapshot
from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "exposure"
CATEGORY = "Sensitive File Exposure"


PROBES = {
    ".git/config": (Severity.HIGH, re.compile(r"\[core\]"), "Exposed .git repository"),
    ".git/HEAD": (Severity.HIGH, re.compile(r"ref:\s*refs/"), "Exposed .git repository"),
    ".env": (Severity.CRITICAL, re.compile(r"^\s*[A-Z0-9_]+\s*=", re.M), "Exposed .env file"),
    ".env.local": (Severity.CRITICAL, re.compile(r"^\s*[A-Z0-9_]+\s*=", re.M), "Exposed .env.local file"),
    "config.php.bak": (Severity.HIGH, None, "Backup source file"),
    "index.php.bak": (Severity.MEDIUM, None, "Backup source file"),
    "wp-config.php.bak": (Severity.CRITICAL, None, "Exposed WordPress config backup"),
    "backup.zip": (Severity.HIGH, None, "Exposed backup archive"),
    "backup.sql": (Severity.CRITICAL, re.compile(r"(CREATE TABLE|INSERT INTO)", re.I), "Exposed database dump"),
    "dump.sql": (Severity.CRITICAL, re.compile(r"(CREATE TABLE|INSERT INTO)", re.I), "Exposed database dump"),
    ".DS_Store": (Severity.LOW, None, "Exposed .DS_Store"),
    ".htaccess": (Severity.MEDIUM, None, "Exposed .htaccess"),
    "phpinfo.php": (Severity.HIGH, re.compile(r"phpinfo\(\)|PHP Version"), "Exposed phpinfo()"),
    "server-status": (Severity.MEDIUM, re.compile(r"Apache Server Status"), "Apache server-status exposed"),
    ".svn/entries": (Severity.HIGH, None, "Exposed .svn metadata"),
    "web.config": (Severity.MEDIUM, re.compile(r"<configuration"), "Exposed web.config"),
    "id_rsa": (Severity.CRITICAL, re.compile(r"PRIVATE KEY"), "Exposed private key"),
    ".aws/credentials": (Severity.CRITICAL, re.compile(r"aws_access_key_id", re.I), "Exposed AWS credentials"),
    "composer.lock": (Severity.LOW, re.compile(r"\"packages\""), "Exposed dependency lockfile"),
    "package-lock.json": (Severity.LOW, re.compile(r"\"lockfileVersion\""), "Exposed dependency lockfile"),
}


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    baseline = getattr(ctx, "baseline", None)
    if phase:
        phase.set_total(len(PROBES))


    tech = ctx.config.get("tech")
    probes = dict(PROBES)
    if tech and not any("php" in t for t in tech):
        probes = {p: v for p, v in probes.items() if ".php" not in p}

    with ThreadPoolExecutor(max_workers=ctx.threads) as pool:
        futures = {pool.submit(_probe, ctx, baseline, path, meta): path
                   for path, meta in probes.items()}
        for fut in as_completed(futures):
            finding = fut.result()
            if finding:
                ctx.add_finding(finding)
            phase and phase.step()
    phase and phase.done()


def _probe(ctx, baseline, path, meta) -> Finding | None:
    severity, signature, name = meta
    url = urljoin(ctx.target + "/", path)
    try:
        resp = ctx.session.get(url, timeout=ctx.timeout, allow_redirects=False)
    except requests.RequestException:
        return None

    if resp.status_code >= 400 or resp.is_redirect:
        return None

    snap = ResponseSnapshot.capture(resp)
    if baseline is not None and baseline.looks_like_not_found(snap):
        return None

    body = resp.text or ""
    confidence = Confidence.FIRM
    if signature is not None:
        if not signature.search(body):


            confidence = Confidence.TENTATIVE
            if len(body) < 40:
                return None
        else:
            confidence = Confidence.CONFIRMED

    return Finding(
        name=name,
        severity=severity if confidence != Confidence.TENTATIVE
        else max(Severity.LOW, Severity(severity - 1)),
        location=url,
        description=(
            f"{name} is reachable ({resp.status_code}, {len(resp.content)} bytes)"
            + (" and its content matches the expected signature."
               if confidence == Confidence.CONFIRMED
               else " but content could not be positively confirmed; verify manually.")
        ),
        remediation="Remove the file from the web root or block access to it at "
                    "the server; rotate any secrets it may have exposed.",
        module=MODULE_NAME, category=CATEGORY,
        evidence=body[:300].replace("\n", " "),
        request=f"GET {url}",
        response=f"HTTP {resp.status_code}, {len(resp.content)} bytes",
        confidence=confidence,
    )
