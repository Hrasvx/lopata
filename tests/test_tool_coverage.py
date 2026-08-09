"""Feature 1: a finding is only as complete as the tool behind it."""

from __future__ import annotations

from conftest import completed, make_finding, timed_out

from lopata.core import correlate, scoring
from lopata.core.models import Confidence, Severity
from lopata.core.tool_status import ToolStatus, coverage


def test_sole_timed_out_tool_caps_confidence_and_explains_itself(ctx):
    """(a) dalfox timed out and nothing else saw it — Low, and it says why."""
    ctx.tool_status.expect(["dalfox"])
    ctx.tool_status.record(timed_out("dalfox"))
    finding = make_finding(confidence=Confidence.HIGH, severity=Severity.HIGH)
    ctx.findings.append(finding)

    correlate.correlate(ctx)
    capped = correlate.apply_tool_coverage(ctx)

    assert capped == 1
    assert finding.incomplete_coverage is True
    assert finding.confidence is Confidence.LOW
    assert finding.severity <= Severity.LOW
    assert finding.contributing_tools == ["dalfox"]
    assert "timed out before completing this target" in finding.description
    assert any("treat as unverified" in reason
               for reason in finding.severity_reasons)


def test_corroborated_finding_survives_one_tool_timing_out(ctx):
    """(b) two tools agree; one timed out, the other finished — not capped."""
    ctx.tool_status.expect(["dalfox", "nuclei"])
    ctx.tool_status.record(timed_out("dalfox"))
    ctx.tool_status.record(completed("nuclei"))
    finding = make_finding(sources=("dalfox", "nuclei"))
    ctx.findings.append(finding)

    correlate.correlate(ctx)
    capped = correlate.apply_tool_coverage(ctx)

    assert capped == 0
    assert finding.incomplete_coverage is False
    assert set(finding.contributing_tools) == {"dalfox", "nuclei"}
    # Independent agreement raised it, and the timeout did not take it back.
    assert finding.confidence >= Confidence.HIGH


def test_own_module_corroboration_also_protects_the_finding(ctx):
    """lopata's own check is evidence too: a module cannot time out."""
    ctx.tool_status.expect(["dalfox"])
    ctx.tool_status.record(timed_out("dalfox"))
    finding = make_finding(sources=("dalfox", "xss"))
    ctx.findings.append(finding)

    correlate.correlate(ctx)

    assert correlate.apply_tool_coverage(ctx) == 0
    assert finding.contributing_tools == ["dalfox"]
    assert finding.incomplete_coverage is False


def test_source_alias_resolves_to_the_tool_that_ran(ctx):
    """The TLS integration reports as `ssl_tls` but the tool key is `sslscan`."""
    ctx.tool_status.expect(["sslscan"])
    ctx.tool_status.record(timed_out("sslscan"))
    finding = make_finding(name="TLS 1.0 accepted", sources=("ssl_tls",),
                           module="ssl_tls")
    ctx.findings.append(finding)

    correlate.correlate(ctx)

    assert correlate.apply_tool_coverage(ctx) == 1
    assert finding.contributing_tools == ["sslscan"]


def test_worst_status_wins_when_a_tool_is_invoked_many_times(ctx):
    """sqlmap runs per parameter: one timeout means partial coverage."""
    ctx.tool_status.expect(["sqlmap"])
    ctx.tool_status.record(completed("sqlmap", duration=10.0))
    ctx.tool_status.record(timed_out("sqlmap"))
    ctx.tool_status.record(completed("sqlmap", duration=5.0))

    status = ctx.tool_status.get("sqlmap")
    assert status.status is ToolStatus.TIMED_OUT
    assert status.duration_s == 315.0   # cost of every invocation, merged


def test_completeness_banner_lists_what_did_not_finish(ctx):
    ctx.tool_status.expect(["nmap", "dalfox", "zap"])
    ctx.tool_status.record(completed("nmap"))
    ctx.tool_status.record(timed_out("dalfox"))
    ctx.tool_status.mark_unrun("zap", "ZAP API not reachable")

    report = coverage(ctx.tool_status)
    assert report.expected == 3
    assert report.completed == 1
    assert report.rate == 1 / 3
    banner = report.banner()
    assert "1 of 3 tools finished" in banner
    assert "dalfox: timed out" in banner
    assert "zap: skipped missing" in banner


def test_scoring_exposes_completeness_without_touching_the_score(ctx):
    ctx.tool_status.expect(["nmap", "dalfox"])
    ctx.tool_status.record(completed("nmap"))
    ctx.tool_status.record(timed_out("dalfox"))
    ctx.findings.append(make_finding())

    scores = scoring.compute(ctx)
    completeness = scores["scan_completeness"]

    assert completeness["tool_completion_rate"] == 0.5
    assert completeness["complete"] is False
    assert completeness["expected_tools"] == 2
    assert "may be incomplete" in completeness["banner"]
    # The caveat is surfaced, not silently priced into the number.
    baseline = dict(scores)
    ctx.tool_status.record(completed("dalfox"))
    assert scoring.compute(ctx)["overall"] == baseline["overall"]


def test_complete_run_produces_no_banner(ctx):
    ctx.tool_status.expect(["nmap"])
    ctx.tool_status.record(completed("nmap"))
    assert coverage(ctx.tool_status).banner() == ""
    assert scoring.compute(ctx)["scan_completeness"]["banner"] == ""
