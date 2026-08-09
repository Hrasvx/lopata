"""Feature 4: the ETA, its fallback, and how it moves as a scan progresses."""

from __future__ import annotations

import json

from lopata.core.timing import (MODULE, TOOL, ScanEstimator, TimingHistory,
                                format_duration, format_eta)


class Clock:
    """A hand-cranked clock so elapsed time is exact, not wall-clock flaky."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def history(tmp_path, **series) -> TimingHistory:
    hist = TimingHistory(path=str(tmp_path / "timings.json"), load=False)
    for name, values in series.items():
        for value in values:
            hist.record(name, value)
    return hist


def test_estimator_falls_back_to_the_configured_budget_with_no_history(tmp_path):
    """(f) no history: use the tool's own timeout, and admit it is a guess."""
    est = ScanEstimator(history=history(tmp_path), clock=Clock())
    est.plan([("nuclei", TOOL, 600.0), ("headers", MODULE, 30.0)])

    est.start("nuclei")
    snap = est.snapshot()

    assert snap["estimate"] == 600.0
    assert snap["from_history"] is False
    assert "no history yet" in est.line()
    assert snap["remaining"] == 630.0        # 600 unspent + the 30s module


def test_history_beats_the_fallback_and_averages_recent_runs(tmp_path):
    est = ScanEstimator(history=history(tmp_path, nuclei=[100.0, 200.0, 300.0]),
                        clock=Clock())
    est.plan([("nuclei", TOOL, 600.0)])
    est.start("nuclei")

    snap = est.snapshot()
    assert snap["estimate"] == 200.0         # mean of the last three runs
    assert snap["from_history"] is True
    assert "no history yet" not in est.line()


def test_eta_shrinks_as_tools_complete(tmp_path):
    """(f) the whole-scan estimate is refreshed as each unit finishes."""
    clock = Clock()
    est = ScanEstimator(history=history(tmp_path, nmap=[60.0], nuclei=[120.0]),
                        clock=clock)
    est.plan([("nmap", TOOL, 300.0), ("nuclei", TOOL, 600.0)])

    assert est.remaining() == 180.0          # 60 + 120, nothing started

    est.start("nmap")
    clock.advance(20)
    # 40s left of nmap's estimate, plus nuclei untouched.
    assert est.remaining() == 160.0
    assert est.snapshot()["position"] == 1

    clock.advance(25)
    est.finish("nmap")
    assert est.remaining() == 120.0          # only nuclei left

    est.start("nuclei")
    clock.advance(30)
    assert est.remaining() == 90.0
    assert est.snapshot()["position"] == 2


def test_a_unit_running_past_its_estimate_never_reports_negative_time(tmp_path):
    clock = Clock()
    est = ScanEstimator(history=history(tmp_path, nmap=[60.0]), clock=clock)
    est.plan([("nmap", TOOL, 300.0)])
    est.start("nmap")
    clock.advance(600)

    assert est.remaining() == 0.0
    assert "elapsed 10m00s" in est.line()


def test_retry_widens_the_estimate_to_the_new_timeout(tmp_path):
    """(Feature 2 x 4) attempt 2 has a bigger budget, so the ETA must grow."""
    clock = Clock()
    est = ScanEstimator(history=history(tmp_path, dalfox=[100.0]), clock=clock)
    est.plan([("dalfox", TOOL, 300.0)])
    est.start("dalfox")
    clock.advance(100)

    est.retry("dalfox", 600.0)               # supervisor's second attempt

    snap = est.snapshot()
    assert snap["estimate"] == 600.0
    assert snap["attempt"] == 2
    assert snap["elapsed"] == 0.0            # the new attempt starts fresh
    assert est.remaining() == 600.0
    assert "attempt 2" in est.line()


def test_finished_units_feed_the_history_for_next_time(tmp_path):
    clock = Clock()
    hist = history(tmp_path)
    est = ScanEstimator(history=hist, clock=clock)
    est.plan([("nmap", TOOL, 300.0)])

    est.start("nmap")
    clock.advance(42)
    assert est.finish("nmap") == 42.0
    assert hist.estimate("nmap") == 42.0

    assert hist.save() is True
    saved = json.loads((tmp_path / "timings.json").read_text())
    assert saved["durations"]["nmap"] == [42.0]


def test_a_timed_out_unit_does_not_poison_the_history(tmp_path):
    """A timeout measures the budget, not the work."""
    clock = Clock()
    hist = history(tmp_path, nmap=[60.0])
    est = ScanEstimator(history=hist, clock=clock)
    est.plan([("nmap", TOOL, 300.0)])

    est.start("nmap")
    clock.advance(300)
    est.finish("nmap", record=False)

    assert hist.estimate("nmap") == 60.0


def test_history_keeps_only_the_last_n_observations(tmp_path):
    hist = TimingHistory(path=str(tmp_path / "t.json"), window=3, load=False)
    for value in (10.0, 20.0, 30.0, 40.0):
        hist.record("nuclei", value)

    assert hist.observations("nuclei") == 3
    assert hist.estimate("nuclei") == 30.0   # mean of 20, 30, 40


def test_corrupt_history_file_is_ignored_not_fatal(tmp_path):
    path = tmp_path / "timings.json"
    path.write_text("{not json at all")

    hist = TimingHistory(path=str(path))
    assert hist.estimate("nuclei") is None


def test_resume_drops_completed_units_from_the_estimate(tmp_path):
    """(--resume) work already done is not work still to wait for."""
    est = ScanEstimator(history=history(tmp_path, nmap=[60.0], nuclei=[120.0]),
                        clock=Clock())
    est.plan([("nmap", TOOL, 300.0), ("nuclei", TOOL, 600.0)])

    est.skip("nmap")

    assert est.remaining() == 120.0
    assert est.completed == 1
    est.start("nuclei")
    assert est.snapshot()["position"] == 2


def test_no_tools_run_leaves_module_timing_only(tmp_path):
    """--no-tools: modules still get a phase ETA; no tool line is invented."""
    est = ScanEstimator(history=history(tmp_path), clock=Clock())
    est.plan([("headers", MODULE, 30.0), ("xss", MODULE, 30.0)])
    est.start("headers")

    line = est.line()
    assert "[1/2] running headers" in line
    assert est.remaining() == 60.0


def test_line_matches_the_documented_shape(tmp_path):
    clock = Clock()
    est = ScanEstimator(history=history(tmp_path, nuclei=[220.0]), clock=clock)
    est.plan([(f"tool{i}", TOOL, 60.0) for i in range(11)]
             + [("nuclei", TOOL, 600.0)]
             + [(f"later{i}", TOOL, 65.0) for i in range(7)])
    for i in range(11):
        est.skip(f"tool{i}")
    est.start("nuclei")
    clock.advance(134)

    line = est.line()
    assert line.startswith("[12/19] running nuclei ...")
    assert "elapsed 2m14s / est. 3m40s" in line
    assert "scan ETA: ~9m remaining" in line


def test_duration_formatting():
    assert format_duration(45) == "45s"
    assert format_duration(134) == "2m14s"
    assert format_duration(3900) == "1h05m"
    assert format_duration(None) == "?"
    assert format_eta(500) == "~8m"
    assert format_eta(30) == "~30s"
