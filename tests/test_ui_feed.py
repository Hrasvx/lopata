"""The live findings feed: a window that is redrawn, not a log that grows."""

from __future__ import annotations

import pytest
from rich.console import Console

import lopata.core.ui as uimod
from lopata.core.models import (Confidence, Finding, FindingType, Severity)
from lopata.core.timing import TOOL, ScanEstimator, TimingHistory
from lopata.core.ui import BANNER, FEED_SIZE, WATERMARK


class _TerminalConsole(Console):
    """A recording console that claims to be a terminal, so the rich path runs
    under pytest instead of falling back to plain printing."""

    @property
    def is_terminal(self) -> bool:
        return True


@pytest.fixture
def ui(monkeypatch, tmp_path):
    monkeypatch.setattr(
        uimod, "Console",
        lambda *a, **k: _TerminalConsole(force_terminal=True, width=100,
                                         record=True))
    estimator = ScanEstimator(
        history=TimingHistory(path=str(tmp_path / "t.json"), load=False))
    estimator.plan([("nuclei", TOOL, 600.0)])
    return uimod.LopataUI(enabled=True, estimator=estimator)


def finding(name="Reflected XSS", severity=Severity.HIGH,
            confidence=Confidence.MEDIUM) -> Finding:
    return Finding(name=name, severity=severity,
                   location="https://example.test/search?q=1 [param: q]",
                   description="d", remediation="r",
                   ftype=FindingType.POTENTIAL_VULN, confidence=confidence)


def rendered(ui) -> str:
    """The live region as it would appear on screen right now."""
    ui.console.print(ui._renderable())
    return ui.console.export_text()


def test_findings_do_not_accumulate_in_the_scrollback(ui, monkeypatch):
    """The whole point: a finding updates the live region and prints nothing.

    Asserting on the recorded console text cannot show this — a recording
    keeps every frame the live region ever drew. What matters is that no
    finding is ever written *above* the live region, so this watches
    console.print itself.
    """
    printed = []
    monkeypatch.setattr(ui.console, "print",
                        lambda *a, **k: printed.append(a))

    for i in range(40):
        ui.on_finding(finding(name=f"Finding {i}"))

    assert printed == []
    assert len(ui._feed) == FEED_SIZE      # a window, not a growing log
    assert ui._found == 40                 # but nothing was lost from the count


def test_the_feed_shows_the_newest_findings_first(ui):
    for i in range(FEED_SIZE + 3):
        ui.on_finding(finding(name=f"Finding {i}"))

    text = rendered(ui)
    newest, oldest_kept = "Finding 8", "Finding 3"
    assert text.index(newest) < text.index(oldest_kept)
    assert "Finding 2" not in text              # rolled out of the window
    assert "3 earlier finding(s)" in text       # but still accounted for


def test_counters_track_every_finding_not_just_the_visible_ones(ui):
    for i in range(20):
        ui.on_finding(finding(name=f"F{i}", severity=Severity.LOW))
    ui.on_finding(finding(severity=Severity.CRITICAL))

    assert ui.counts[Severity.LOW] == 20
    assert ui.counts[Severity.CRITICAL] == 1
    assert "TOTAL: 21" in rendered(ui)


def test_a_finding_occupies_exactly_one_line(ui):
    ui.console.width = 60          # narrow enough to force truncation
    ui.on_finding(finding(name="A very long finding name " * 4,
                          confidence=Confidence.CONFIRMED))

    body = [line for line in rendered(ui).splitlines()
            if "very long finding" in line]
    assert len(body) == 1


def test_severity_and_type_survive_truncation_on_a_narrow_terminal(ui):
    ui.console.width = 60
    ui.on_finding(finding(severity=Severity.CRITICAL))

    row = [line for line in rendered(ui).splitlines()
           if "Reflected XSS" in line]
    assert len(row) == 1
    assert "CRIT" in row[0] and "POSSIBLE" in row[0]
    assert "…" in row[0]           # the location is what got cut


def test_watermark_is_present_in_the_banner_and_the_live_region(ui):
    assert "hrasvx" in BANNER
    ui.banner("example.test", "1.2.0")
    assert "hrasvx" in ui.console.export_text()
    assert WATERMARK in rendered(ui)


def test_finished_phases_are_removed_from_the_progress_display(ui):
    ui.start(2)
    phase = ui.phase("recon: nmap", total=1)
    assert "recon: nmap" in rendered(ui)

    phase.done()
    assert "recon: nmap" not in rendered(ui)
    phase.done()                                # idempotent
    phase.step()                                # and inert afterwards


def test_plain_mode_still_prints_one_line_per_finding(capsys):
    plain = uimod.LopataUI(enabled=False)
    plain.on_finding(finding())

    out = capsys.readouterr().out
    assert "Reflected XSS" in out
    assert plain.counts[Severity.HIGH] == 1
