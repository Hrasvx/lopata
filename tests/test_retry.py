"""Feature 2: retrying a tool that ran out of budget, and what happens when
even the retry is not enough.

These drive the real `integrations.base.run_tool` path — supervisor, status
recording and the coverage capping that reads it — with only the subprocess
call itself faked, so the three features are tested as they compose.
"""

from __future__ import annotations

import subprocess
import types

import pytest
from conftest import make_finding

from lopata.core import correlate
from lopata.core.models import Confidence, Severity
from lopata.core.retry import RetryPolicy, RetrySupervisor
from lopata.core.tool_status import ToolRunStatus, ToolStatus
from lopata.integrations import base


class FakeProc:
    def __init__(self, stdout="ok", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def fake_runs(*outcomes):
    """Scripted subprocess.run: each outcome is an exception or a FakeProc."""
    calls = []

    def runner(argv, capture_output=True, text=True, timeout=None):
        calls.append(timeout)
        outcome = outcomes[min(len(calls) - 1, len(outcomes) - 1)]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    runner.calls = calls
    return runner


def test_timeout_growth_follows_the_multiplier_and_respects_the_cap():
    policy = RetryPolicy(max_attempts=3, timeout_multiplier=2.0)
    assert policy.timeout_for(300, 1) == 300
    assert policy.timeout_for(300, 2) == 600
    assert policy.timeout_for(300, 3) == 1200

    capped = RetryPolicy(max_attempts=3, timeout_multiplier=2.0,
                         max_tool_timeout=900)
    assert capped.timeout_for(300, 3) == 900


def test_skipped_missing_is_never_retryable():
    policy = RetryPolicy.from_config(
        {"retry": {"retry_on": ["timed_out", "failed", "skipped_missing"]}})
    assert ToolStatus.SKIPPED_MISSING not in policy.retry_on


def test_no_retry_flag_restores_single_attempt_behaviour():
    policy = RetryPolicy.from_config({"retry": {"max_attempts": 4}},
                                     no_retry=True)
    assert policy.max_attempts == 1
    assert policy.enabled is False


def test_success_on_attempt_two_leaves_the_finding_uncapped(supervised_ctx,
                                                            monkeypatch):
    """(c) the retry finished, so nothing about the finding is degraded."""
    ctx = supervised_ctx
    runner = fake_runs(subprocess.TimeoutExpired(cmd="dalfox", timeout=300),
                       FakeProc(stdout="{}"))
    monkeypatch.setattr(base.subprocess, "run", runner)

    proc = base.run_tool(["dalfox", "url"], timeout=300, ctx=ctx, tool="dalfox")

    assert proc is not None                      # attempt 2's output is usable
    assert runner.calls == [300, 600]            # and it got the longer budget
    status = ctx.tool_status.get("dalfox")
    assert status.status is ToolStatus.COMPLETED
    assert status.attempts == 2

    ctx.tool_status.expect(["dalfox"])
    finding = make_finding(confidence=Confidence.MEDIUM)
    ctx.findings.append(finding)
    correlate.correlate(ctx)

    assert correlate.apply_tool_coverage(ctx) == 0
    assert finding.incomplete_coverage is False
    assert finding.confidence is Confidence.MEDIUM


def test_exhausted_retries_cap_the_finding_without_crashing(supervised_ctx,
                                                            monkeypatch):
    """(d) both attempts timed out: a capped finding, not an exception."""
    ctx = supervised_ctx
    runner = fake_runs(subprocess.TimeoutExpired(cmd="dalfox", timeout=300))
    monkeypatch.setattr(base.subprocess, "run", runner)

    proc = base.run_tool(["dalfox", "url"], timeout=300, ctx=ctx, tool="dalfox")

    assert proc is None
    assert runner.calls == [300, 600]            # budget spent, then stopped
    status = ctx.tool_status.get("dalfox")
    assert status.status is ToolStatus.TIMED_OUT
    assert status.attempts == 2

    ctx.tool_status.expect(["dalfox"])
    finding = make_finding(confidence=Confidence.HIGH, severity=Severity.HIGH)
    ctx.findings.append(finding)
    correlate.correlate(ctx)

    assert correlate.apply_tool_coverage(ctx) == 1
    assert finding.confidence is Confidence.LOW
    assert finding.severity <= Severity.LOW
    assert finding.incomplete_coverage is True


def test_non_zero_exit_is_a_completed_run_not_a_failure(supervised_ctx,
                                                        monkeypatch):
    """ffuf, nikto and sqlmap all exit non-zero for "nothing found"."""
    ctx = supervised_ctx
    runner = fake_runs(FakeProc(stdout="", returncode=1))
    monkeypatch.setattr(base.subprocess, "run", runner)

    base.run_tool(["ffuf"], timeout=180, ctx=ctx, tool="ffuf")

    assert ctx.tool_status.get("ffuf").status is ToolStatus.COMPLETED
    assert runner.calls == [180]                 # and nothing was retried


def test_death_by_signal_is_a_failure_and_is_retried(supervised_ctx,
                                                     monkeypatch):
    ctx = supervised_ctx
    runner = fake_runs(FakeProc(stdout="", returncode=-9),
                       FakeProc(stdout="found", returncode=0))
    monkeypatch.setattr(base.subprocess, "run", runner)

    base.run_tool(["nuclei"], timeout=600, ctx=ctx, tool="nuclei")

    assert runner.calls == [600, 1200]
    assert ctx.tool_status.get("nuclei").status is ToolStatus.COMPLETED


def test_unsupervised_call_still_records_a_status(ctx, monkeypatch):
    """--no-retry (or a context with no supervisor) keeps Feature 1 intact."""
    runner = fake_runs(subprocess.TimeoutExpired(cmd="nmap", timeout=300))
    monkeypatch.setattr(base.subprocess, "run", runner)

    base.run_tool(["nmap"], timeout=300, ctx=ctx, tool="nmap")

    assert runner.calls == [300]
    assert ctx.tool_status.get("nmap").status is ToolStatus.TIMED_OUT


def test_resumed_scan_continues_the_retry_budget(monkeypatch):
    """An interrupted scan does not hand the tool a fresh full budget."""
    attempts = []

    def attempt(timeout):
        attempts.append(timeout)
        return None, ToolRunStatus(tool_name="dalfox",
                                   status=ToolStatus.TIMED_OUT)

    supervisor = RetrySupervisor(
        RetryPolicy(max_attempts=3, timeout_multiplier=2.0, backoff_s=0.0),
        resumed_attempts={"dalfox": 1}, sleep=lambda _s: None)
    supervisor.run("dalfox", attempt, 300)

    # Attempt 1 was spent before the interruption, so this run picks up at 2.
    assert attempts == [600, 1200]
    assert supervisor.attempts_spent()["dalfox"] == 3


def test_resume_budget_applies_only_to_the_first_invocation():
    """A per-target tool must not read the previous target's attempts as
    budget already spent."""
    seen = []

    def attempt(timeout):
        seen.append(timeout)
        return None, ToolRunStatus(tool_name="sqlmap",
                                   status=ToolStatus.COMPLETED)

    supervisor = RetrySupervisor(
        RetryPolicy(max_attempts=2, timeout_multiplier=2.0, backoff_s=0.0),
        resumed_attempts={"sqlmap": 1}, sleep=lambda _s: None)
    supervisor.run("sqlmap", attempt, 300)
    supervisor.run("sqlmap", attempt, 300)

    assert seen == [600, 300]


def test_retry_notifies_the_ui_so_the_eta_can_widen():
    notified = []
    ui = types.SimpleNamespace(
        on_tool_retry=lambda tool, attempt, timeout:
            notified.append((tool, attempt, timeout)))

    def attempt(timeout):
        return None, ToolRunStatus(tool_name="zap",
                                   status=ToolStatus.TIMED_OUT)

    RetrySupervisor(RetryPolicy(max_attempts=2, backoff_s=0.0), ui=ui,
                    sleep=lambda _s: None).run("zap", attempt, 600)

    assert notified == [("zap", 2, 1200.0)]


@pytest.mark.parametrize("status", [ToolStatus.TIMED_OUT, ToolStatus.FAILED])
def test_every_attempt_is_logged_at_info(status, caplog):
    def attempt(timeout):
        return None, ToolRunStatus(tool_name="dalfox", status=status)

    import logging
    logger = logging.getLogger("lopata.test.retry")
    with caplog.at_level(logging.INFO, logger="lopata.test.retry"):
        RetrySupervisor(RetryPolicy(max_attempts=2, backoff_s=0.0),
                        logger=logger, sleep=lambda _s: None
                        ).run("dalfox", attempt, 1800)

    messages = [record.getMessage() for record in caplog.records]
    assert any("attempt 1/2" in m and "retrying with 3600s timeout" in m
               for m in messages), messages
    assert any("giving up" in m for m in messages), messages
