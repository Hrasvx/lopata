from __future__ import annotations

import threading
from collections import Counter, deque

from .models import Confidence, Finding, FindingType, Severity
from .timing import ScanEstimator, format_duration, format_eta

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (BarColumn, Progress, SpinnerColumn,
                               TextColumn, TimeElapsedColumn)
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    _RICH = True
except ImportError:
    _RICH = False

BANNER = r"""
   __                  __
  / /___  ____  ____ _/ /_____ _
 / / __ \/ __ \/ __ `/ __/ __ `/    web vuln scanner
/ / /_/ / /_/ / /_/ / /_/ /_/ /
\_\____/ .___/\__,_/\__/\__,_/
       /_/            by hrasvx
"""

# Sits at the foot of the live region for the whole scan.
WATERMARK = "lopata · hrasvx"

FEED_SIZE = 6

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]
_CONF_PLAIN = {
    Confidence.CONFIRMED: "(confirmed)",
    Confidence.HIGH: "(high confidence)",
    Confidence.MEDIUM: "",
    Confidence.LOW: "(lead)",
    Confidence.INFORMATIONAL: "(inventory)",
}

_TYPE_TAG = {
    FindingType.CONFIRMED_VULN: "VULN",
    FindingType.POTENTIAL_VULN: "POSSIBLE",
    FindingType.MISCONFIGURATION: "MISCONFIG",
    FindingType.EXPOSURE: "EXPOSURE",
    FindingType.INVENTORY: "INVENTORY",
    FindingType.INFORMATIONAL: "INFO",
}

_SEV_UI = {
    Severity.CRITICAL: ("CRIT", "bold white on red"),
    Severity.HIGH: ("HIGH", "bold red"),
    Severity.MEDIUM: ("MED ", "yellow"),
    Severity.LOW: ("LOW ", "cyan"),
    Severity.INFO: ("INFO", "dim"),
}


class LopataUI:

    def __init__(self, enabled: bool = True,
                 estimator: ScanEstimator | None = None) -> None:
        self.enabled = enabled and _RICH
        self.counts: Counter = Counter()
        self._lock = threading.Lock()
        self._live = None
        self._progress = None
        self._overall = None
        # Rolling window of the most recent findings, redrawn in place.
        self._feed: deque = deque(maxlen=FEED_SIZE)
        self._found = 0
        self.estimator = estimator
        self._active_unit: str | None = None
        if self.enabled:
            self.console = Console()
            self.enabled = self.console.is_terminal
        if self.enabled:
            self._progress = Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[bold]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=self.console,
                transient=False,
            )

    def banner(self, target: str, version: str) -> None:
        if not self.enabled:
            print(BANNER)
            print(f"lopata v{version}  ->  target: {target}\n")
            return
        self.console.print(Text(BANNER, style="bold cyan"))
        self.console.print(
            f"[bold white]lopata[/] [dim]v{version}[/]   target: "
            f"[bold]{target}[/]\n")

    def start(self, phases: int) -> None:
        if not self.enabled:
            return
        self._overall = self._progress.add_task("Overall", total=phases)
        self._live = Live(get_renderable=self._renderable, console=self.console,
                          refresh_per_second=8, vertical_overflow="visible")
        self._live.start()

    def _renderable(self):
        """The whole live region, rebuilt on every refresh.

        Everything that changes during a scan lives in here so it can be
        redrawn in place. The only things that reach the scrollback are the
        section rules and notes — structure and narrative, both low-volume.
        """
        parts = [self._summary_panel(), self._progress]
        eta = self._eta_line()
        if eta:
            parts.append(Text("  " + eta, style="cyan", no_wrap=True,
                              overflow="ellipsis"))
        feed = self._feed_panel()
        if feed is not None:
            parts.append(feed)
        parts.append(Text(WATERMARK, style="dim", justify="right"))
        return Group(*parts)

    def _eta_line(self) -> str:
        return self.estimator.line() if self.estimator is not None else ""

    def _feed_panel(self):
        """The rolling findings window — the newest first, oldest dropped."""
        with self._lock:
            rows = list(self._feed)
            hidden = self._found - len(rows)
        if not rows:
            return None
        lines = []
        for finding in reversed(rows):
            label, style = _SEV_UI[finding.severity]
            line = Text(no_wrap=True, overflow="ellipsis")
            line.append(f" {label.strip():<4} ", style=style)
            line.append(f" {_TYPE_TAG[finding.ftype]:<9} ", style="bold")
            line.append(finding.name)
            qualifier = _CONF_PLAIN[finding.confidence]
            if qualifier:
                line.append(f"  {qualifier}", style="dim italic")
            line.append(f"  {finding.location}", style="dim")
            lines.append(line)
        if hidden > 0:
            lines.append(Text(f"  … {hidden} earlier finding(s) — all of them "
                              "are in the report", style="dim italic",
                              no_wrap=True, overflow="ellipsis"))
        return Panel(Group(*lines), title="[bold]latest", title_align="left",
                     border_style="grey37", padding=(0, 1))

    def stop(self) -> None:
        if self._live is not None:
            self._refresh()
            self._live.stop()
            self._live = None

    def section(self, title: str) -> None:
        if not self.enabled:
            print(f"\n=== {title} ===")
            return
        self._print(Rule(f"[bold cyan]{title}", style="cyan"))

    def phase(self, description: str, total: int = 1):
        if not self.enabled:
            print(f"[*] {description}")
            return _NullPhase()
        task_id = self._progress.add_task(description, total=max(total, 1))
        return _Phase(self._progress, task_id, self)

    def advance_overall(self) -> None:
        if self.enabled and self._overall is not None:
            self._progress.advance(self._overall)
            self._refresh()

    def on_finding(self, finding: Finding) -> None:
        """Show a finding without growing the scrollback.

        A busy target produces hundreds of these. Printing each one buries the
        progress display and the ETA under a wall the user cannot scroll back
        through anyway, so the live feed keeps the newest few and redraws in
        place; the counters, the final summary and the report keep the rest.
        """
        with self._lock:
            self.counts[finding.severity] += 1
            self._found += 1
            if self.enabled:
                self._feed.append(finding)
        if self.enabled:
            self._refresh()
            return
        # Plain mode has no live region to redraw, so one line each it is.
        tag = _SEV_UI[finding.severity][0].strip()
        conf = finding.confidence.label.lower()
        print(f"    [{tag}] {_TYPE_TAG[finding.ftype]}: "
              f"{finding.name} @ {finding.location} ({conf})")

    def note(self, message: str, style: str = "dim") -> None:
        if not self.enabled:
            print(f"    {message}")
            return
        self._print(Text(f"    {message}", style=style))

    def _summary_panel(self):
        with self._lock:
            counts, total = dict(self.counts), self._found
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="left")
        cells = []
        for sev in _SEV_ORDER:
            label, style = _SEV_UI[sev]
            count = counts.get(sev, 0)
            cells.append(Text(f"{label.strip()}: {count}",
                              style=style if count else "dim"))
        cells.append(Text(f"TOTAL: {total}", style="bold white"))
        table.add_row(*cells)
        return Panel(table, title="[bold]findings", title_align="left",
                     border_style="cyan", padding=(0, 1))


    def begin_unit(self, name: str) -> None:
        if self.estimator is None:
            return
        self.estimator.start(name)
        self._active_unit = name
        if not self.enabled:
            print(f"    {self.estimator.line()}")
        else:
            self._refresh()

    def end_unit(self, name: str | None = None,
                 record: bool = True) -> float | None:
        """Close out the running unit and fold its duration into the history.

        ``record=False`` for a unit that did not finish normally — a timed-out
        tool's duration is a property of its budget, not of the work, and
        would poison future estimates.
        """
        if self.estimator is None:
            return None
        name = name or self._active_unit
        if not name:
            return None
        duration = self.estimator.finish(name, record=record)
        self._active_unit = None
        if not self.enabled:
            if duration:
                print(f"    {name} finished in {format_duration(duration)}"
                      "  |  scan ETA: "
                      f"{format_eta(self.estimator.remaining())} remaining")
        else:
            self._refresh()
        return duration

    def on_tool_retry(self, tool_name: str, attempt: int, timeout: float) -> None:
        """RetrySupervisor callback: a longer timeout is now in force, so the
        ETA widens to match instead of promising the original estimate."""
        if self.estimator is None:
            return
        self.estimator.retry(tool_name, timeout)
        self.note(f"{tool_name}: attempt {attempt} running with a "
                  f"{format_duration(timeout)} timeout")

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.refresh()

    def _print(self, renderable, extra: str = "") -> None:
        if self._live is not None:
            self._refresh()
            if extra:
                self.console.print(renderable, extra)
            else:
                self.console.print(renderable)
        else:
            self.console.print(renderable, extra) if extra else self.console.print(renderable)

    def final_summary(self, findings: list[Finding], duration: float,
                      report_path: str, json_path: str | None,
                      scores: dict | None = None) -> None:
        scores = scores or {}
        categories = scores.get("categories") or {}
        counts = Counter(f.severity for f in findings)
        confirmed = sum(1 for f in findings
                        if f.confidence == Confidence.CONFIRMED)
        actionable = sum(1 for f in findings
                         if f.severity >= Severity.MEDIUM
                         and f.confidence >= Confidence.MEDIUM)

        banner = (scores.get("scan_completeness") or {}).get("banner", "")

        if not self.enabled:
            print("\n=== SCAN SUMMARY ===")
            if banner:
                print(f"  ! {banner}")
            for sev in _SEV_ORDER:
                print(f"  {_SEV_UI[sev][0].strip():<5} {counts.get(sev, 0)}")
            print(f"  TOTAL {len(findings)}   ({duration:.1f}s)")
            print(f"  {actionable} actionable, {confirmed} confirmed")
            if scores:
                print(f"  score: {scores.get('overall')}/100 "
                      f"(grade {scores.get('grade')})")
                for area, data in categories.items():
                    score = data.get("score")
                    print(f"    {area:<28} "
                          + (f"{score}/100" if score is not None else "not assessed"))
            print(f"  report: {report_path}")
            if json_path:
                print(f"  json:   {json_path}")
            return

        table = Table(show_header=True, header_style="bold cyan",
                      title="[bold]scan summary", title_style="bold white")
        table.add_column("severity")
        table.add_column("count", justify="right")
        for sev in _SEV_ORDER:
            label, style = _SEV_UI[sev]
            table.add_row(Text(label.strip(), style=style),
                          str(counts.get(sev, 0)))
        table.add_row(Text("TOTAL", style="bold white"),
                      Text(str(len(findings)), style="bold white"))

        renderables = [table]
        if categories:
            score_table = Table(show_header=True, header_style="bold cyan",
                                title="[bold]security score",
                                title_style="bold white")
            score_table.add_column("category")
            score_table.add_column("score", justify="right")
            score_table.add_column("grade", justify="center")
            for area, data in categories.items():
                score = data.get("score")
                grade = data.get("grade", "—")
                style = _grade_style(grade)
                score_table.add_row(
                    area,
                    Text(f"{score}/100" if score is not None else "—", style=style),
                    Text(grade, style=style))
            score_table.add_row(
                Text("OVERALL", style="bold white"),
                Text(f"{scores.get('overall')}/100", style="bold white"),
                Text(str(scores.get("grade", "—")),
                     style=_grade_style(scores.get("grade", "—"))))
            renderables.append(score_table)

        self.console.print()
        if banner:
            self.console.print(Panel(Text(banner, style="yellow"),
                                     border_style="yellow", padding=(0, 1)))
        for renderable in renderables:
            self.console.print(renderable)
        self.console.print(
            f"[dim]completed in {duration:.1f}s — {actionable} actionable "
            f"finding(s), {confirmed} confirmed[/]")
        self.console.print(f"[green]✓[/] report: [bold]{report_path}[/]")
        if json_path:
            self.console.print(f"[green]✓[/] json:   [bold]{json_path}[/]")


def _grade_style(grade: str) -> str:
    return {"A": "bold green", "B": "green", "C": "yellow",
            "D": "red", "F": "bold red"}.get(grade, "dim")


class _Phase:
    """One phase's progress bar, retired from the display when it finishes.

    Leaving finished phases on screen grows the live region by a line per
    phase until it fills the terminal. The Overall bar and the ETA already say
    how far along the scan is, and the section rules in the scrollback record
    what ran, so a finished phase has nothing left to show.
    """

    def __init__(self, progress, task_id, ui):
        self._p = progress
        self._t = task_id
        self._ui = ui
        self._done = False

    def step(self, n: int = 1) -> None:
        if self._done:
            return
        self._p.advance(self._t, n)
        self._ui._refresh()

    def set_total(self, total: int) -> None:
        if self._done:
            return
        self._p.update(self._t, total=max(total, 1))
        self._ui._refresh()

    def done(self) -> None:
        if self._done:
            return
        self._done = True
        try:
            self._p.remove_task(self._t)
        except KeyError:
            pass
        self._ui._refresh()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.done()
        return False


class _NullPhase:
    def step(self, n: int = 1) -> None: ...
    def set_total(self, total: int) -> None: ...
    def done(self) -> None: ...
    def __enter__(self): return self
    def __exit__(self, *exc): return False
