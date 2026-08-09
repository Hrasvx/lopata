"""Sensitive file exposure.

Every probe has a content signature wherever one exists. A 200 response is not
evidence — plenty of sites answer 200 for everything — so a hit only becomes a
Confirmed finding when the body actually looks like the file it claims to be.
Signature-less hits are reported at reduced confidence and the severity engine
caps them accordingly.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..core import async_http
from ..core.baseline import ResponseSnapshot, similarity
from ..core.models import (AREA_CONFIG, Confidence, Effort, Finding,
                           FindingType, PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "exposure"
CATEGORY = "Sensitive File Exposure"


class _Probe:

    __slots__ = ("path", "name", "signature", "impact", "what", "steps",
                 "php_only")

    def __init__(self, path, name, signature, impact, what, steps, php_only=False):
        self.path = path
        self.name = name
        self.signature = re.compile(signature, re.M) if signature else None
        self.impact = impact
        self.what = what
        self.steps = list(steps)
        self.php_only = php_only


_SECRET_STEPS = [
    "Remove the file from the web root immediately.",
    "Treat every credential it contained as compromised and rotate it — "
    "assume it has been read.",
    "Add a server rule denying the path and extension outright.",
    "Review access logs for prior requests to the path.",
]

_VCS_STEPS = [
    "Remove the version-control directory from the deployed tree.",
    "Deny access to `.git`, `.svn` and `.hg` at the web server as a safety net.",
    "Deploy from a build artefact rather than by cloning or pulling in place.",
    "Rotate any credential that has ever appeared in the repository history.",
]

PROBES = [
    _Probe(".git/config", "Exposed .git repository", r"\[core\]", Impact.SERIOUS,
           "the repository configuration, which usually names the remote and "
           "sometimes embeds credentials in the URL", _VCS_STEPS),
    _Probe(".git/HEAD", "Exposed .git repository", r"ref:\s*refs/", Impact.SERIOUS,
           "the git HEAD reference — the whole repository, including deleted "
           "files and full history, can be reconstructed from a served .git "
           "directory", _VCS_STEPS),
    _Probe(".svn/entries", "Exposed .svn metadata", None, Impact.LIMITED,
           "Subversion metadata that discloses the source tree layout", _VCS_STEPS),
    _Probe(".env", "Exposed .env file", r"^\s*[A-Z0-9_]+\s*=", Impact.TOTAL,
           "the application's environment file — in practice this means database "
           "passwords, API keys, mail credentials and the app secret key",
           _SECRET_STEPS),
    _Probe(".env.local", "Exposed .env.local file", r"^\s*[A-Z0-9_]+\s*=",
           Impact.TOTAL, "a local environment override file containing secrets",
           _SECRET_STEPS),
    _Probe(".env.backup", "Exposed .env backup", r"^\s*[A-Z0-9_]+\s*=",
           Impact.TOTAL, "a backup of the environment file", _SECRET_STEPS),
    _Probe("config.php.bak", "Backup of PHP configuration", None, Impact.SERIOUS,
           "a backup copy of a configuration file, served as text rather than "
           "executed — so the database credentials inside it are readable",
           _SECRET_STEPS, php_only=True),
    _Probe("wp-config.php.bak", "Exposed WordPress config backup", None,
           Impact.TOTAL, "the WordPress database credentials and auth salts",
           _SECRET_STEPS, php_only=True),
    _Probe("index.php.bak", "Backup of application source", None, Impact.LIMITED,
           "application source code served as text", _SECRET_STEPS, php_only=True),
    _Probe("backup.zip", "Exposed backup archive", None, Impact.SERIOUS,
           "a site backup archive", _SECRET_STEPS),
    _Probe("backup.tar.gz", "Exposed backup archive", None, Impact.SERIOUS,
           "a site backup archive", _SECRET_STEPS),
    _Probe("backup.sql", "Exposed database dump", r"(CREATE TABLE|INSERT INTO)",
           Impact.TOTAL, "a full database dump", _SECRET_STEPS),
    _Probe("dump.sql", "Exposed database dump", r"(CREATE TABLE|INSERT INTO)",
           Impact.TOTAL, "a full database dump", _SECRET_STEPS),
    _Probe("database.sql", "Exposed database dump", r"(CREATE TABLE|INSERT INTO)",
           Impact.TOTAL, "a full database dump", _SECRET_STEPS),
    _Probe("id_rsa", "Exposed SSH private key", r"PRIVATE KEY", Impact.TOTAL,
           "an SSH private key", _SECRET_STEPS),
    _Probe(".ssh/id_rsa", "Exposed SSH private key", r"PRIVATE KEY", Impact.TOTAL,
           "an SSH private key", _SECRET_STEPS),
    _Probe(".aws/credentials", "Exposed AWS credentials", r"aws_access_key_id",
           Impact.TOTAL, "AWS access keys", _SECRET_STEPS),
    _Probe(".npmrc", "Exposed npm credentials", r"_authToken", Impact.SERIOUS,
           "an npm registry auth token", _SECRET_STEPS),
    _Probe("phpinfo.php", "Exposed phpinfo() output", r"phpinfo\(\)|PHP Version",
           Impact.LIMITED,
           "the full PHP configuration: absolute paths, loaded extensions, "
           "environment variables and often database credentials",
           ["Delete the file — it exists only for debugging.",
            "Set `expose_php = Off` in php.ini.",
            "Audit for other debug endpoints left in the deployment."],
           php_only=True),
    _Probe("server-status", "Apache server-status exposed",
           r"Apache Server Status", Impact.LIMITED,
           "live request logs for every visitor, including URLs with tokens in "
           "the query string",
           ["Restrict the /server-status handler to localhost "
            "(`Require local` inside the Location block).",
            "Disable mod_status entirely if you do not use it."]),
    _Probe("server-info", "Apache server-info exposed", r"Apache Server Information",
           Impact.LIMITED, "the full server configuration and loaded modules",
           ["Restrict or disable mod_info."]),
    _Probe(".htaccess", "Exposed .htaccess", r"(RewriteRule|Deny from|Require)",
           Impact.INFORMATION,
           "the server's own access rules, which tells an attacker precisely "
           "what you are trying to protect",
           ["Deny access to files beginning with a dot at the server level.",
            "Verify the `<FilesMatch \"^\\.\">` rule is present and effective."]),
    _Probe("web.config", "Exposed web.config", r"<configuration", Impact.SERIOUS,
           "the IIS application configuration, frequently including connection "
           "strings", _SECRET_STEPS),
    _Probe(".DS_Store", "Exposed .DS_Store", r"Bud1", Impact.INFORMATION,
           "a macOS directory index that reveals file names in the directory, "
           "including ones that are not linked anywhere",
           ["Remove .DS_Store files from the deployed tree.",
            "Add them to .gitignore and to the deployment exclusion list."]),
    _Probe("composer.lock", "Exposed dependency lockfile", r"\"packages\"",
           Impact.INFORMATION,
           "the exact version of every backend dependency, which lets an "
           "attacker check known vulnerabilities offline",
           ["Exclude lockfiles from the served directory.",
            "Keep dependencies patched — the file only matters because it "
            "reveals what is out of date."]),
    _Probe("package-lock.json", "Exposed dependency lockfile",
           r"\"lockfileVersion\"", Impact.INFORMATION,
           "the exact version of every frontend dependency",
           ["Exclude lockfiles from the served directory."]),
    _Probe("docker-compose.yml", "Exposed docker-compose file",
           r"(services:|image:)", Impact.SERIOUS,
           "the service topology and, very often, environment secrets",
           _SECRET_STEPS),
    _Probe("Dockerfile", "Exposed Dockerfile", r"^FROM\s", Impact.INFORMATION,
           "the build recipe, including base image versions and build-time "
           "arguments", ["Exclude build files from the served directory."]),
]


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    baseline = getattr(ctx, "baseline", None)

    tech = ctx.tech_names()
    php = (not tech) or any("php" in t for t in tech)
    probes = [p for p in PROBES if php or not p.php_only]
    if phase:
        phase.set_total(len(probes))

    found = 0
    urls = [urljoin(ctx.target + "/", p.path) for p in probes]
    responses = dict(async_http.fetch_all(ctx, urls, allow_redirects=False))
    for probe, url in zip(probes, urls):
        finding = _probe(ctx, baseline, probe, responses.get(url))
        if finding:
            ctx.add_finding(finding)
            found += 1
        phase and phase.step()
    phase and phase.done()

    if not found:
        ctx.add_passed(PassedCheck(
            name=f"No sensitive files exposed ({len(probes)} paths checked)",
            detail="Version-control metadata, environment files, database "
                   "dumps, backups and private keys were all requested and "
                   "none was served.",
            source=MODULE_NAME, location=ctx.target, score_area=AREA_CONFIG))


def _probe(ctx, baseline, probe: _Probe, resp) -> Finding | None:
    url = urljoin(ctx.target + "/", probe.path)
    if resp is None or resp.status_code >= 400 or resp.is_redirect:
        return None

    snap = ResponseSnapshot.capture(resp)
    if baseline is not None:
        if baseline.looks_like_not_found(snap):
            return None
        root = getattr(baseline, "root", None)
        if root is not None and similarity(snap.body, root.body) >= 0.98:
            # Catch-all routing serving the homepage — not the file.
            return None

    body = resp.text or ""
    if probe.signature is not None:
        if probe.signature.search(body):
            confidence = Confidence.CONFIRMED
            verified = ("lopata fetched the file and its contents match the "
                        "expected format")
        elif len(body) < 40:
            return None
        else:
            confidence = Confidence.LOW
            verified = ""
    else:
        confidence = Confidence.MEDIUM
        verified = "lopata fetched the path and received non-baseline content"

    matched = confidence == Confidence.CONFIRMED
    finding = Finding(
        name=probe.name,
        severity=Severity.INFO, location=url,
        description=(
            f"`{urlparse(url).path}` is reachable over HTTP and returned "
            f"{resp.status_code} with {len(resp.content or b'')} bytes.\n\n"
            + ("The response content matches the expected format for this file, "
               "so this is confirmed rather than inferred from the status code."
               if matched else
               "The response did not match the expected content signature for "
               "this file, so it may be an unrelated page that happens to "
               "answer on this path — confirm by hand before acting.")
        ),
        remediation=probe.steps[0],
        ftype=(FindingType.EXPOSURE if matched else FindingType.POTENTIAL_VULN),
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{probe.name} at {urlparse(url).path}",
        risk=(
            f"The path serves {probe.what}. Files like this are indexed by "
            "automated scanners within hours of becoming reachable; exposure is "
            "rarely discovered by the owner first."
        ),
        impact=_impact_text(probe.impact),
        remediation_steps=probe.steps,
        verification=f"`curl -i {url}` must return 403 or 404.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        effort=Effort.EASY,
        score_area=AREA_CONFIG,
        evidence=_safe_evidence(body),
        request=f"GET {url}",
        response=f"HTTP {resp.status_code}, {len(resp.content or b'')} bytes, "
                 f"Content-Type: {resp.headers.get('Content-Type', '-')}",
        verified_by=verified,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=probe.impact,
        exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE,
        exposure=Exposure.PUBLIC,
        confidence=confidence,
    ))
    return finding


_SECRET_PATTERN = re.compile(
    r"(?i)(pass(word)?|secret|token|key|api[_-]?key|aws_secret)"
    r"\s*[=:]\s*\S+")


def _safe_evidence(body: str, limit: int = 300) -> str:
    """Show enough to prove the file is real without printing the secrets."""
    snippet = " ".join(body[:limit * 2].split())[:limit]
    return _SECRET_PATTERN.sub(lambda m: m.group(0).split("=")[0].split(":")[0]
                               + "=<redacted>", snippet)


def _impact_text(impact: Impact) -> str:
    return {
        Impact.TOTAL: "Full compromise. The credentials or data served here "
                      "grant direct access to the application's backend, and in "
                      "most deployments to the host itself.",
        Impact.SERIOUS: "Disclosure of protected data or credentials that "
                        "substantially shorten the path to full compromise.",
        Impact.LIMITED: "Discloses internal detail that materially assists an "
                        "attacker in targeting the rest of the application.",
        Impact.INFORMATION: "Provides reconnaissance value: file names, versions "
                            "or configuration that make other attacks more "
                            "reliable.",
        Impact.NEGLIGIBLE: "Minimal direct impact.",
    }[impact]


def register():
    from ..core.plugins import web_module
    return web_module('exposure', run, requires_crawl=False, order=70)
