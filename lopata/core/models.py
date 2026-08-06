from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import IntEnum
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

    TENTATIVE = 0
    FIRM = 1
    CONFIRMED = 2

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


@dataclass
class Finding:

    name: str
    severity: Severity
    location: str
    description: str
    remediation: str
    module: str = ""
    category: str = ""
    evidence: str = ""
    confidence: Confidence = Confidence.FIRM

    request: str = ""
    response: str = ""

    def resolved_category(self) -> str:
        return self.category or self.module or "Other"

    def as_dict(self) -> dict:
        return {
            "category": self.resolved_category(),
            "name": self.name,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "confidence": self.confidence.label,
            "location": self.location,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "module": self.module,
        }


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
    discovered_urls: set[str] = field(default_factory=set)
    subdomains: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    page_bodies: dict[str, str] = field(default_factory=dict)
    modules_run: list[str] = field(default_factory=list)
    tools: dict[str, ToolInfo] = field(default_factory=dict)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _form_sigs: set = field(default_factory=set, repr=False)

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

    def dedup_key(self, finding: Finding) -> tuple:
        return (finding.module, finding.name, finding.location)
