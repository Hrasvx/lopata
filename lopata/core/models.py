from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Optional

import requests


class Severity(IntEnum):

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


class Confidence(IntEnum):
    """How much evidence stands behind a finding.

    INFORMATIONAL  inventory/discovery only — nothing is being claimed
    LOW            banner or version matching only, never re-tested
    MEDIUM         strong evidence from one source, not independently verified
    HIGH           multiple independent sources agree, or a targeted re-test passed
    CONFIRMED      lopata reproduced the behaviour itself (safe exploitation)
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CONFIRMED = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class FindingType(Enum):
    """What kind of thing was found — not everything is a vulnerability."""

    CONFIRMED_VULN = "Confirmed Vulnerability"
    POTENTIAL_VULN = "Potential Vulnerability"
    MISCONFIGURATION = "Misconfiguration"
    EXPOSURE = "Security Exposure"
    INVENTORY = "Service Inventory"
    INFORMATIONAL = "Informational"

    @property
    def label(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        return _TYPE_RANK[self]


_TYPE_RANK = {
    FindingType.CONFIRMED_VULN: 5,
    FindingType.POTENTIAL_VULN: 4,
    FindingType.MISCONFIGURATION: 3,
    FindingType.EXPOSURE: 2,
    FindingType.INVENTORY: 1,
    FindingType.INFORMATIONAL: 0,
}


class Effort(IntEnum):
    """Rough remediation cost, used to surface quick wins."""

    TRIVIAL = 0      # a header, a flag, one config line
    EASY = 1         # a config change + restart
    MODERATE = 2     # code change, testing needed
    SIGNIFICANT = 3  # architectural / migration work

    @property
    def label(self) -> str:
        return self.name.capitalize()


class BusinessImpact(IntEnum):

    NEGLIGIBLE = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    SEVERE = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


SEVERITY_HEX = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#4b5563",
}


SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


CONFIDENCE_HEX = {
    Confidence.CONFIRMED: "#15803d",
    Confidence.HIGH: "#0f766e",
    Confidence.MEDIUM: "#475569",
    Confidence.LOW: "#6b7280",
    Confidence.INFORMATIONAL: "#94a3b8",
}


# Scoring areas a finding can be charged against. Kept small on purpose so the
# report's category scores stay meaningful.
AREA_TLS = "TLS"
AREA_HTTP = "HTTP Security"
AREA_SURFACE = "Attack Surface"
AREA_PATCH = "Patch Management"
AREA_WEBAPP = "Web Application Security"
AREA_CONFIG = "Configuration"

SCORE_AREAS = (AREA_TLS, AREA_HTTP, AREA_SURFACE, AREA_PATCH, AREA_WEBAPP,
               AREA_CONFIG)


@dataclass
class Finding:
    """A single reported item.

    Only `name`/`severity`/`location` are structurally required; the richer
    fields (risk, impact, steps, verification) are what make the report read
    like an assessment rather than a scanner dump, so producers should fill
    them in whenever they have something real to say.
    """

    name: str
    severity: Severity
    location: str
    description: str
    remediation: str

    ftype: FindingType = FindingType.INFORMATIONAL
    module: str = ""
    category: str = ""
    evidence: str = ""
    confidence: Confidence = Confidence.MEDIUM

    request: str = ""
    response: str = ""

    summary: str = ""
    risk: str = ""
    impact: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    verification: str = ""
    references: list[str] = field(default_factory=list)
    severity_reasons: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    effort: Effort = Effort.MODERATE
    business_impact: BusinessImpact = BusinessImpact.LOW
    sources: list[str] = field(default_factory=list)
    related_locations: list[str] = field(default_factory=list)
    score_area: str = AREA_CONFIG
    # Set when lopata re-tested the issue itself rather than trusting a tool.
    verified_by: str = ""

    def __post_init__(self) -> None:
        if not self.sources and self.module:
            self.sources = [self.module]
        if not self.summary:
            self.summary = _first_sentence(self.description)

    def resolved_category(self) -> str:
        return self.category or self.module or "Other"

    @property
    def is_vulnerability(self) -> bool:
        return self.ftype in (FindingType.CONFIRMED_VULN,
                              FindingType.POTENTIAL_VULN)

    @property
    def quick_win(self) -> bool:
        """High value for very little work — worth calling out up front."""
        return (self.effort <= Effort.EASY
                and self.severity >= Severity.MEDIUM
                and self.confidence >= Confidence.MEDIUM)

    @property
    def priority(self) -> int:
        """Remediation ordering: severity first, then how sure we are."""
        base = int(self.severity) * 10 + int(self.confidence) * 2
        if self.quick_win:
            base += 3
        return base

    def all_locations(self) -> list[str]:
        seen = [self.location]
        for loc in self.related_locations:
            if loc not in seen:
                seen.append(loc)
        return seen

    def as_dict(self) -> dict:
        return {
            "type": self.ftype.label,
            "category": self.resolved_category(),
            "score_area": self.score_area,
            "name": self.name,
            "summary": self.summary,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "severity_reasons": self.severity_reasons,
            "cvss": self.cvss,
            "confidence": self.confidence.label,
            "confidence_rank": int(self.confidence),
            "location": self.location,
            "affected": self.all_locations(),
            "description": self.description,
            "risk": self.risk,
            "impact": self.impact,
            "business_impact": self.business_impact.label,
            "remediation": self.remediation,
            "remediation_steps": self.remediation_steps,
            "remediation_effort": self.effort.label,
            "quick_win": self.quick_win,
            "priority": self.priority,
            "verification": self.verification,
            "verified_by": self.verified_by,
            "references": self.references,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "module": self.module,
            "sources": self.sources,
        }


@dataclass
class PassedCheck:
    """A check that ran and came back clean.

    Recording these is what lets the report say "we looked and it was fine"
    instead of silently dropping a negative result — and it is where NSE
    'NOT VULNERABLE' output goes instead of becoming a false positive.
    """

    name: str
    detail: str = ""
    source: str = ""
    location: str = ""
    score_area: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "detail": self.detail,
                "source": self.source, "location": self.location}


@dataclass
class Technology:

    name: str
    version: str = ""
    category: str = "Other"     # CMS / Framework / Web Server / Language / ...
    sources: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = ""

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}".strip()

    def as_dict(self) -> dict:
        return {"name": self.name, "version": self.version,
                "category": self.category, "sources": self.sources,
                "confidence": self.confidence.label, "evidence": self.evidence}


@dataclass
class Service:
    """One open port as observed by a port scanner."""

    host: str
    port: int
    proto: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra: str = ""
    group: str = "Other"        # assigned by the knowledge base
    internal: bool = False      # host resolves to RFC1918/loopback space
    tunnel: str = ""            # e.g. "ssl"

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}/{self.proto}"

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extra) if x)

    def as_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "proto": self.proto,
                "service": self.name, "product": self.product,
                "version": self.version, "group": self.group,
                "internal": self.internal, "tunnel": self.tunnel}


@dataclass
class ToolInfo:

    name: str
    available: bool
    version: str = ""
    path: str = ""
    note: str = ""


@dataclass
class ScanContext:

    target: str
    session: requests.Session
    config: dict = field(default_factory=dict)
    threads: int = 10
    timeout: float = 10.0
    max_pages: int = 100
    verbose: bool = False
    logger: logging.Logger = field(default=None)
    ui: object = None

    findings: list[Finding] = field(default_factory=list)
    passed_checks: list[PassedCheck] = field(default_factory=list)
    discovered_urls: set[str] = field(default_factory=set)
    subdomains: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    page_bodies: dict[str, str] = field(default_factory=dict)
    modules_run: list[str] = field(default_factory=list)
    tools: dict[str, ToolInfo] = field(default_factory=dict)

    technologies: dict[str, Technology] = field(default_factory=dict)
    services: list[Service] = field(default_factory=list)
    # Client-side routes recovered from JavaScript bundles (SPA targets).
    spa_routes: list[str] = field(default_factory=list)
    # Hosts confirmed to be answering HTTP (populated by httpx); used to avoid
    # scanning subdomains that only resolve in DNS but serve nothing.
    live_hosts: set[str] = field(default_factory=set)
    # Hidden HTTP parameters found by Arjun, keyed by the URL they belong to.
    # Fed to the injection-testing tools that run after discovery.
    discovered_params: dict[str, set] = field(default_factory=dict)
    # tool name -> raw stdout, reproduced verbatim in the report appendix
    raw_outputs: dict[str, str] = field(default_factory=dict)
    scores: dict = field(default_factory=dict)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cleanups: list = field(default_factory=list, repr=False)
    _form_sigs: set = field(default_factory=set, repr=False)
    # Script sources and inline script bodies collected while crawling, mined
    # afterwards for endpoints the HTML never links to.
    _script_urls: set = field(default_factory=set, repr=False)
    _inline_js: list = field(default_factory=list, repr=False)

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
        if self.ui is not None:
            self.ui.on_finding(finding)
        elif self.logger:
            self.logger.info(
                "[%s] %s @ %s", finding.severity.label.upper(),
                finding.name, finding.location,
            )

    def add_passed(self, check: PassedCheck) -> None:
        with self._lock:
            self.passed_checks.append(check)
        if self.logger:
            self.logger.debug("passed: %s (%s)", check.name, check.source)

    def add_technology(self, tech: Technology) -> None:
        """Merge into the registry, keeping the most specific version seen."""
        key = tech.name.strip().lower()
        if not key:
            return
        with self._lock:
            existing = self.technologies.get(key)
            if existing is None:
                self.technologies[key] = tech
                return
            if tech.version and not existing.version:
                existing.version = tech.version
            if tech.category != "Other" and existing.category == "Other":
                existing.category = tech.category
            for src in tech.sources:
                if src not in existing.sources:
                    existing.sources.append(src)
            # Independent agreement is itself evidence.
            if len(existing.sources) > 1 and existing.confidence < Confidence.HIGH:
                existing.confidence = Confidence.HIGH
            elif tech.confidence > existing.confidence:
                existing.confidence = tech.confidence
            if tech.evidence and not existing.evidence:
                existing.evidence = tech.evidence

    def add_service(self, service: Service) -> None:
        with self._lock:
            for existing in self.services:
                if (existing.host == service.host
                        and existing.port == service.port
                        and existing.proto == service.proto):
                    return
            self.services.append(service)

    def add_params(self, url: str, params) -> None:
        """Record hidden parameters discovered for a URL (Arjun)."""
        names = {str(p).strip() for p in params if str(p).strip()}
        if not url or not names:
            return
        with self._lock:
            self.discovered_params.setdefault(url, set()).update(names)

    def add_cleanup(self, fn) -> None:
        """Register a teardown callback (e.g. stopping a spawned daemon).

        Run once, at the end of the scan, by :meth:`run_cleanups`. Kept generic
        so an integration can spawn a resource without the runner knowing about
        it. An ``atexit`` safety net should back critical teardowns for the
        interrupt/crash path, since a hard exit skips this.
        """
        with self._lock:
            self._cleanups.append(fn)

    def run_cleanups(self) -> None:
        with self._lock:
            pending, self._cleanups = self._cleanups, []
        for fn in pending:
            try:
                fn()
            except Exception as exc:
                self.logger and self.logger.warning("cleanup failed: %s", exc)

    def add_raw_output(self, tool: str, text: str, limit: int = 40000) -> None:
        if not text or not text.strip():
            return
        with self._lock:
            self.raw_outputs[tool] = text[:limit]

    def tech_names(self) -> set[str]:
        return {t.name.lower() for t in self.technologies.values()}

    def dedup_key(self, finding: Finding) -> tuple:
        return (finding.module, finding.name, finding.location)


def _first_sentence(text: str, limit: int = 180) -> str:
    text = " ".join((text or "").split())
    if not text:
        return ""
    for stop in (". ", "! ", "? "):
        idx = text.find(stop)
        if 0 < idx <= limit:
            return text[:idx + 1].strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"
