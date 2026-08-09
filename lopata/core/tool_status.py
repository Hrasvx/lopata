"""Per-invocation status for every external tool.

A report that quietly drops a tool's output is worse than one that admits the
gap: the reader cannot tell "we looked and found nothing" apart from "we never
finished looking". Every external invocation therefore leaves a
:class:`ToolRunStatus` behind, and the registry on the scan context keeps the
worst outcome per tool for the whole run.

Two consumers depend on it:

* :mod:`lopata.core.correlate` caps a finding whose only evidence came from a
  tool that never finished, and
* :mod:`lopata.core.scoring` derives the run-level completion rate that the
  report banner and the JSON ``scan_completeness`` object are built from.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ToolStatus(str, Enum):
    """How an external tool invocation ended."""

    COMPLETED = "completed"              # ran to completion (any exit code)
    TIMED_OUT = "timed_out"              # killed at the timeout boundary
    FAILED = "failed"                    # could not run, or died on a signal
    SKIPPED_MISSING = "skipped_missing"  # binary/service absent or N/A here

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")


# Statuses that mean the tool's coverage of this target is not trustworthy.
DEGRADED = (ToolStatus.TIMED_OUT, ToolStatus.FAILED)

_PRECEDENCE = {
    ToolStatus.COMPLETED: 0,
    ToolStatus.SKIPPED_MISSING: 1,
    ToolStatus.FAILED: 2,
    ToolStatus.TIMED_OUT: 3,
}

_SOURCE_ALIASES = {
    "ssl_tls": "sslscan",
    "sslyze": "sslscan",
    "testssl.sh": "sslscan",
    "gobuster": "ffuf",
    "trufflehog": "gitleaks",
}


def _tail(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    return text[-limit:] if len(text) > limit else text


@dataclass
class ToolRunStatus:
    """The outcome of one external tool invocation (or of a whole run, once
    the registry has merged every invocation of that tool together)."""

    tool_name: str
    status: ToolStatus
    duration_s: float = 0.0
    exit_code: Optional[int] = None
    stderr_tail: str = ""
    attempts: int = 1
    timeout_s: Optional[float] = None
    note: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.status, str):
            self.status = ToolStatus(self.status)
        self.stderr_tail = _tail(self.stderr_tail)

    @property
    def completed(self) -> bool:
        return self.status is ToolStatus.COMPLETED

    @property
    def degraded(self) -> bool:
        """True when the tool did not finish — its silence proves nothing."""
        return self.status in DEGRADED

    def as_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "duration_s": round(self.duration_s, 3),
            "exit_code": self.exit_code,
            "stderr_tail": self.stderr_tail,
            "attempts": self.attempts,
            "timeout_s": self.timeout_s,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ToolRunStatus":
        try:
            status = ToolStatus(str(data.get("status")))
        except ValueError:
            status = ToolStatus.FAILED
        return cls(
            tool_name=str(data.get("tool_name") or "unknown"),
            status=status,
            duration_s=float(data.get("duration_s") or 0.0),
            exit_code=data.get("exit_code"),
            stderr_tail=str(data.get("stderr_tail") or ""),
            attempts=int(data.get("attempts") or 1),
            timeout_s=data.get("timeout_s"),
            note=str(data.get("note") or ""),
        )


class ToolStatusRegistry:
    """Run-level view: one merged :class:`ToolRunStatus` per tool.

    Also remembers which tools the run *expected* to use, so a tool that was
    selected but never produced a status (its binary was missing, or it had
    nothing applicable to scan) still counts against the completion rate
    instead of vanishing.
    """

    def __init__(self) -> None:
        self._by_tool: dict[str, ToolRunStatus] = {}
        self._expected: list[str] = []
        self._lock = threading.Lock()


    def expect(self, names) -> None:
        """Declare the tools this run intends to use."""
        with self._lock:
            for name in names:
                if name and name not in self._expected:
                    self._expected.append(name)

    @property
    def expected(self) -> list[str]:
        return list(self._expected)

    def record(self, status: ToolRunStatus) -> ToolRunStatus:
        """Merge one invocation's outcome into the run-level status."""
        with self._lock:
            current = self._by_tool.get(status.tool_name)
            if current is None:
                self._by_tool[status.tool_name] = status
                return status
            merged = current
            if _PRECEDENCE[status.status] > _PRECEDENCE[current.status]:
                # A worse outcome takes over, but keeps the accumulated cost.
                merged = status
                merged.duration_s += current.duration_s
            else:
                merged.duration_s += status.duration_s
            merged.attempts = max(current.attempts, status.attempts)
            if status.timeout_s and (not merged.timeout_s
                                     or status.timeout_s > merged.timeout_s):
                merged.timeout_s = status.timeout_s
            self._by_tool[merged.tool_name] = merged
            return merged

    def mark(self, tool_name: str, status: ToolStatus, **kwargs) -> ToolRunStatus:
        return self.record(ToolRunStatus(tool_name=tool_name, status=status,
                                         **kwargs))

    def mark_unrun(self, tool_name: str, note: str = "") -> Optional[ToolRunStatus]:
        """Record ``skipped_missing`` for a tool that never invoked anything.

        Used by the orchestrator after an integration returns without having
        run its binary at all — an absent tool, a non-HTTPS target for the TLS
        integration, no client-side assets for gitleaks. Silent about tools
        that did report, so it is safe to call unconditionally.
        """
        with self._lock:
            if tool_name in self._by_tool:
                return None
        return self.mark(tool_name, ToolStatus.SKIPPED_MISSING, note=note,
                         stderr_tail=note)


    def get(self, tool_name: str) -> Optional[ToolRunStatus]:
        return self._by_tool.get(tool_name)

    def known(self) -> set[str]:
        return set(self._by_tool) | set(self._expected)

    def resolve(self, source: str) -> Optional[str]:
        """Map a finding's source name to the tool key that produced it.

        Returns ``None`` for lopata's own modules, which is what marks them as
        independent (non-tool) corroboration during the coverage pass.
        """
        if not source:
            return None
        name = str(source).strip().lower()
        name = _SOURCE_ALIASES.get(name, name)
        return name if name in self.known() else None

    def is_degraded(self, tool_name: str) -> bool:
        status = self._by_tool.get(tool_name)
        return bool(status and status.degraded)

    def degraded(self) -> list[ToolRunStatus]:
        return [s for s in self._by_tool.values() if s.degraded]

    def attempts(self, tool_name: str) -> int:
        status = self._by_tool.get(tool_name)
        return status.attempts if status else 0

    def attempts_by_tool(self) -> dict[str, int]:
        return {name: s.attempts for name, s in self._by_tool.items()}

    def statuses(self) -> dict[str, ToolRunStatus]:
        return dict(self._by_tool)


    def as_dict(self) -> dict:
        return {
            "expected": list(self._expected),
            "statuses": {name: s.as_dict() for name, s in self._by_tool.items()},
        }

    def restore(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        self.expect(data.get("expected") or [])
        for name, raw in (data.get("statuses") or {}).items():
            try:
                self._by_tool[name] = ToolRunStatus.from_dict(raw)
            except Exception:
                continue


@dataclass
class ToolCoverage:
    """Run-level completion, as rendered in the report banner."""

    expected: int = 0
    completed: int = 0
    incomplete: list = field(default_factory=list)

    @property
    def rate(self) -> float:
        if self.expected <= 0:
            return 1.0
        return self.completed / self.expected

    @property
    def complete(self) -> bool:
        return self.rate >= 1.0

    def banner(self) -> str:
        if self.complete:
            return ""
        detail = ", ".join(f"{item['tool']}: {item['status'].replace('_', ' ')}"
                           for item in self.incomplete)
        return (f"This report may be incomplete — {self.completed} of "
                f"{self.expected} tools finished (list: {detail}).")

    def as_dict(self) -> dict:
        return {
            "tool_completion_rate": round(self.rate, 3),
            "completed_tools": self.completed,
            "expected_tools": self.expected,
            "complete": self.complete,
            "incomplete_tools": list(self.incomplete),
            "banner": self.banner(),
        }


def coverage(registry: ToolStatusRegistry) -> ToolCoverage:
    """Summarise a registry into the run-level completeness record."""
    expected = registry.expected or sorted(registry.statuses())
    completed = 0
    incomplete: list[dict] = []
    for name in expected:
        status = registry.get(name)
        if status is not None and status.completed:
            completed += 1
            continue
        incomplete.append({
            "tool": name,
            "status": status.status.value if status else "skipped_missing",
            "note": (status.note or status.stderr_tail) if status else "never ran",
            "attempts": status.attempts if status else 0,
        })
    return ToolCoverage(expected=len(expected), completed=completed,
                        incomplete=incomplete)
