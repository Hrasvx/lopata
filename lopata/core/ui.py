from __future__ import annotations

import threading
from collections import Counter

from .models import Confidence, Finding, Severity

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
       /_/
"""

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]
_SEV_UI = {
    Severity.CRITICAL: ("CRIT", "bold white on red"),
    Severity.HIGH: ("HIGH", "bold red"),
    Severity.MEDIUM: ("MED ", "yellow"),
    Severity.LOW: ("LOW ", "cyan"),
    Severity.INFO: ("INFO", "dim"),
}


class LopataUI:

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and _RICH
        self.counts: Counter = Counter()
        self._lock = threading.Lock()
        self._live = None
        self._progress = None
        self._overall = None
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
        group = Group(self._summary_panel(), self._progress)
        self._live = Live(group, console=self.console, refresh_per_second=8,
                          vertical_overflow="visible")
        self._live.start()

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
        with self._lock:
            self.counts[finding.severity] += 1
            if not self.enabled:
                tag = _SEV_UI[finding.severity][0].strip()
                conf = finding.confidence.label.lower()
                print(f"    [{tag}] {finding.resolved_category()}: "
                      f"{finding.name} @ {finding.location} ({conf})")
                return
            label, style = _SEV_UI[finding.severity]
            conf = finding.confidence
            conf_tag = {
                Confidence.CONFIRMED: "[green](confirmed)[/]",
                Confidence.FIRM: "",
                Confidence.TENTATIVE: "[dim](lead)[/]",
            }[conf]
            line = Text.assemble(
                ("  "),
                (f" {label} ", style),
                (f" {finding.resolved_category()}", "bold"),
                (f" — {finding.name} ", "default"),
                (f"@ {finding.location}", "dim"),
            )
            self._print(line, extra=conf_tag)

    def note(self, message: str, style: str = "dim") -> None:
        if not self.enabled:
            print(f"    {message}")
            return
        self._print(Text(f"    {message}", style=style))

    def _summary_panel(self):
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="left")
        total = sum(self.counts.values())
        cells = []
        for sev in _SEV_ORDER:
            label, style = _SEV_UI[sev]
            cells.append(Text(f"{label.strip()}: {self.counts.get(sev, 0)}", style=style))
        cells.append(Text(f"TOTAL: {total}", style="bold white"))
        table.add_row(*cells)
        return Panel(table, title="[bold]findings", border_style="cyan",
                     padding=(0, 1))

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(Group(self._summary_panel(), self._progress),
                             refresh=True)

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
                      report_path: str, json_path: str | None) -> None:
        if not self.enabled:
            print("\n=== SCAN SUMMARY ===")
            for sev in _SEV_ORDER:
                print(f"  {_SEV_UI[sev][0].strip():<5} {self.counts.get(sev, 0)}")
            print(f"  TOTAL {len(findings)}   ({duration:.1f}s)")
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
                          str(self.counts.get(sev, 0)))
        table.add_row(Text("TOTAL", style="bold white"),
                      Text(str(len(findings)), style="bold white"))
        self.console.print()
        self.console.print(table)
        self.console.print(f"[dim]completed in {duration:.1f}s[/]")
        self.console.print(f"[green]✓[/] report: [bold]{report_path}[/]")
        if json_path:
            self.console.print(f"[green]✓[/] json:   [bold]{json_path}[/]")


class _Phase:

    def __init__(self, progress, task_id, ui):
        self._p = progress
        self._t = task_id
        self._ui = ui

    def step(self, n: int = 1) -> None:
        self._p.advance(self._t, n)
        self._ui._refresh()

    def set_total(self, total: int) -> None:
        self._p.update(self._t, total=max(total, 1))
        self._ui._refresh()

    def done(self) -> None:
        task = self._p.tasks[self._t] if self._t < len(self._p.tasks) else None
        if task is not None:
            self._p.update(self._t, completed=task.total)
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
