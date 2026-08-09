"""Retry orchestration for external tools.

A tool that times out costs twice: its own findings are lost, and every
finding that depended on it has to be presented as unverified. Often the only
thing wrong was the budget — the same invocation with a longer timeout
finishes. :class:`RetrySupervisor` wraps every external invocation so that a
`timed_out`/`failed` attempt is retried with a geometrically larger timeout
before the run gives up and hands a degraded :class:`ToolRunStatus` to the
coverage pass in :mod:`lopata.core.correlate`.

Retries happen inside the tool phase, so they are finished — or exhausted —
long before correlation runs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from .tool_status import DEGRADED, ToolStatus

_NEVER_RETRY = (ToolStatus.SKIPPED_MISSING,)

DEFAULT_BACKOFF_S = 2.0


@dataclass
class RetryPolicy:
    """How hard to try before accepting a degraded result."""

    max_attempts: int = 2
    timeout_multiplier: float = 2.0
    retry_on: tuple = DEGRADED
    backoff_s: float = DEFAULT_BACKOFF_S
    # Hard ceiling on base_timeout * multiplier ** (attempt - 1); None = no cap.
    max_tool_timeout: Optional[float] = None

    @property
    def enabled(self) -> bool:
        return self.max_attempts > 1

    def timeout_for(self, base_timeout: float, attempt: int) -> float:
        """The timeout attempt N (1-based) should be given.

        ``--max-tool-timeout`` is a hard ceiling: if the user capped growth
        below the tool's own base timeout, the cap wins.
        """
        grown = float(base_timeout) * (self.timeout_multiplier ** max(attempt - 1, 0))
        if self.max_tool_timeout:
            grown = min(grown, float(self.max_tool_timeout))
        return grown

    @classmethod
    def from_config(cls, config: dict, *, no_retry: bool = False,
                    max_tool_timeout: Optional[float] = None) -> "RetryPolicy":
        raw = (config or {}).get("retry") or {}
        try:
            max_attempts = max(1, int(raw.get("max_attempts", 2)))
        except (TypeError, ValueError):
            max_attempts = 2
        try:
            multiplier = float(raw.get("timeout_multiplier", 2.0))
        except (TypeError, ValueError):
            multiplier = 2.0
        multiplier = max(1.0, multiplier)

        statuses = []
        for name in (raw.get("retry_on") or ["timed_out", "failed"]):
            try:
                status = ToolStatus(str(name).strip().lower())
            except ValueError:
                continue
            if status not in _NEVER_RETRY:
                statuses.append(status)

        try:
            backoff = max(0.0, float(raw.get("backoff_seconds", DEFAULT_BACKOFF_S)))
        except (TypeError, ValueError):
            backoff = DEFAULT_BACKOFF_S

        ceiling = max_tool_timeout
        if ceiling is None and raw.get("max_tool_timeout"):
            try:
                ceiling = float(raw["max_tool_timeout"])
            except (TypeError, ValueError):
                ceiling = None

        return cls(max_attempts=1 if no_retry else max_attempts,
                   timeout_multiplier=multiplier,
                   retry_on=tuple(statuses) or DEGRADED,
                   backoff_s=backoff,
                   max_tool_timeout=ceiling)


@dataclass
class _Spend:
    """Attempts charged against a tool's budget.

    ``carried`` is what an interrupted run had already spent; ``total`` is the
    highest attempt number reached since, which is what the next checkpoint
    records so a second interruption resumes from the right place.
    """

    carried: int = 0
    total: int = 0


class RetrySupervisor:
    """Runs one external invocation, retrying it with a growing timeout.

    ``attempt_fn`` is any callable taking a timeout in seconds and returning
    ``(result, ToolRunStatus)``. The supervisor never inspects the result; it
    only reads the status, so it works equally well for a subprocess wrapper
    and for an API-driven integration such as ZAP.
    """

    def __init__(self, policy: Optional[RetryPolicy] = None, *, logger=None,
                 ui=None, resumed_attempts: Optional[dict] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.policy = policy or RetryPolicy()
        self.logger = logger
        self.ui = ui
        self._sleep = sleep
        self._spend: dict[str, _Spend] = {}
        for tool, attempts in (resumed_attempts or {}).items():
            try:
                carried = max(0, int(attempts))
            except (TypeError, ValueError):
                continue
            self._spend[tool] = _Spend(carried=carried, total=carried)


    def attempts_spent(self) -> dict:
        """Attempts charged per tool, for the checkpoint."""
        return {tool: s.total for tool, s in self._spend.items() if s.total}

    def _take_carried(self, tool: str) -> int:
        """Consume the resumed budget, which applies to the first invocation
        of a tool in this process only.

        An integration that invokes its binary once per target would otherwise
        read the previous target's attempts as budget already spent and refuse
        to retry anything after the first one.
        """
        spend = self._spend.setdefault(tool, _Spend())
        carried, spend.carried = spend.carried, 0
        return carried


    def run(self, tool_name: str, attempt_fn: Callable, base_timeout: float):
        """Execute ``attempt_fn``, retrying per policy. Returns
        ``(result, ToolRunStatus)`` from the last usable attempt."""
        policy = self.policy
        already = self._take_carried(tool_name)
        attempt = already + 1
        result, status = None, None

        while True:
            timeout = policy.timeout_for(base_timeout, attempt)
            if attempt > 1:
                self._announce_retry(tool_name, attempt, timeout)
            result, status = attempt_fn(timeout)
            status.attempts = attempt
            status.timeout_s = timeout
            spend = self._spend.setdefault(tool_name, _Spend())
            spend.total = max(spend.total, attempt)

            if status.status not in policy.retry_on:
                break
            if attempt >= policy.max_attempts:
                self._log("%s: attempt %d/%d %s after %.0fs — giving up, "
                          "findings from this tool will be marked unverified",
                          tool_name, attempt, policy.max_attempts,
                          status.status.label, timeout)
                break

            next_timeout = policy.timeout_for(base_timeout, attempt + 1)
            self._log("%s: attempt %d/%d %s after %.0fs, retrying with %.0fs "
                      "timeout", tool_name, attempt, policy.max_attempts,
                      status.status.label, timeout, next_timeout)
            if policy.backoff_s:
                self._sleep(policy.backoff_s)
            attempt += 1

        return result, status

    def _announce_retry(self, tool_name: str, attempt: int, timeout: float) -> None:
        """Tell the console the tool is on a longer leash now, so the ETA
        reflects the new bound rather than the original estimate."""
        hook = getattr(self.ui, "on_tool_retry", None)
        if callable(hook):
            try:
                hook(tool_name, attempt, timeout)
            except Exception:
                pass

    def _log(self, message: str, *args) -> None:
        if self.logger:
            self.logger.info(message, *args)


def single_attempt(attempt_fn: Callable, base_timeout: float,
                   tool_name: str = "") -> tuple:
    """Run ``attempt_fn`` once — the ``--no-retry`` path, and the fallback for
    call sites that have no supervisor available."""
    result, status = attempt_fn(base_timeout)
    status.timeout_s = base_timeout
    if tool_name and not status.tool_name:
        status.tool_name = tool_name
    return result, status


def supervise(ctx, tool_name: str, attempt_fn: Callable, base_timeout: float):
    """Run an attempt under ``ctx``'s supervisor when there is one, recording
    the final status in ``ctx.tool_status``. The single entry point every
    integration goes through, whether it drives a subprocess or an API."""
    supervisor = getattr(ctx, "retry_supervisor", None) if ctx else None
    if supervisor is not None:
        result, status = supervisor.run(tool_name, attempt_fn, base_timeout)
    else:
        result, status = single_attempt(attempt_fn, base_timeout, tool_name)
    registry = getattr(ctx, "tool_status", None) if ctx else None
    if registry is not None:
        registry.record(status)
    return result, status
