"""Shared fixtures.

The tests here exercise the tool-status / retry / ETA machinery, so they need
a scan context but never a network: every ScanContext below is inert — no
module runs against it unless the test asks for it.
"""

from __future__ import annotations

import pytest
import requests

from lopata.core.config import load_config
from lopata.core.models import (Confidence, Finding, FindingType, ScanContext,
                                Severity)
from lopata.core.retry import RetryPolicy, RetrySupervisor
from lopata.core.tool_status import ToolRunStatus, ToolStatus


@pytest.fixture
def ctx():
    context = ScanContext(target="https://example.test",
                          session=requests.Session(),
                          config=load_config(None))
    return context


@pytest.fixture
def supervised_ctx(ctx):
    """A context whose tools retry twice with no real backoff delay."""
    policy = RetryPolicy(max_attempts=2, timeout_multiplier=2.0, backoff_s=0.0)
    ctx.retry_supervisor = RetrySupervisor(policy, sleep=lambda _s: None)
    return ctx


def make_finding(name="Reflected XSS", sources=("dalfox",),
                 confidence=Confidence.MEDIUM, severity=Severity.MEDIUM,
                 module="dalfox", **kwargs) -> Finding:
    """A finding shaped like something an integration would actually emit."""
    return Finding(
        name=name,
        severity=severity,
        location="https://example.test/search?q=1 [param: q]",
        description="A payload was reflected into the response body.",
        remediation="Encode output on the way into the page.",
        ftype=kwargs.pop("ftype", FindingType.POTENTIAL_VULN),
        module=module,
        confidence=confidence,
        sources=list(sources),
        **kwargs)


def timed_out(tool: str, attempts: int = 1) -> ToolRunStatus:
    return ToolRunStatus(tool_name=tool, status=ToolStatus.TIMED_OUT,
                         duration_s=300.0, attempts=attempts,
                         note="exceeded its 300s budget")


def completed(tool: str, duration: float = 12.0) -> ToolRunStatus:
    return ToolRunStatus(tool_name=tool, status=ToolStatus.COMPLETED,
                         duration_s=duration, exit_code=0)
