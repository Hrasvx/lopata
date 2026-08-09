"""Scan timing history and ETA estimation.

A 40-minute scan behind a spinner tells the user nothing. This module keeps a
small rolling history of how long each tool and module actually took on past
runs, and turns it into a per-unit and whole-scan estimate that
:mod:`lopata.core.ui` renders.

Everything here is deterministic and console-only: the estimator never touches
the structured logging path used by ``--logfile``, and it degrades to a clearly
marked fallback when a tool has no history yet rather than inventing precision
it does not have.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

WINDOW = 5

# Used for a unit we have never timed and that carries no configured budget.
DEFAULT_ESTIMATE_S = 60.0

TOOL = "tool"
MODULE = "module"


def history_path() -> str:
    """Cache location for the timing history, XDG-aware."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache")
    return os.path.join(base, "lopata", "timings.json")


def format_duration(seconds: Optional[float]) -> str:
    """Compact, human duration: ``45s``, ``2m14s``, ``1h04m``."""
    if seconds is None:
        return "?"
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def format_eta(seconds: Optional[float]) -> str:
    """Coarser rendering for the whole-scan ETA — minutes, not seconds, so it
    does not claim accuracy the estimate cannot support."""
    if seconds is None:
        return "unknown"
    if seconds < 60:
        return f"~{max(int(round(seconds)), 1)}s"
    minutes = int(round(seconds / 60.0))
    if minutes < 60:
        return f"~{max(minutes, 1)}m"
    hours, minutes = divmod(minutes, 60)
    return f"~{hours}h{minutes:02d}m"


class TimingHistory:
    """Rolling per-unit duration history, persisted as JSON.

    Every read and write is best-effort: a corrupt or unwritable cache costs
    the ETA its precision, never the scan.
    """

    def __init__(self, path: Optional[str] = None, window: int = WINDOW,
                 load: bool = True) -> None:
        self.path = path if path is not None else history_path()
        self.window = max(1, int(window))
        self._data: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        if load:
            self.load()

    def load(self) -> "TimingHistory":
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return self
        if not isinstance(raw, dict):
            return self
        for name, values in (raw.get("durations") or {}).items():
            if not isinstance(values, list):
                continue
            cleaned = []
            for value in values[-self.window:]:
                try:
                    seconds = float(value)
                except (TypeError, ValueError):
                    continue
                if seconds > 0:
                    cleaned.append(seconds)
            if cleaned:
                self._data[str(name)] = cleaned
        return self

    def save(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "durations": self._data}, fh)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False

    def record(self, name: str, duration_s: float) -> None:
        if not name or duration_s is None or duration_s <= 0:
            return
        with self._lock:
            series = self._data.setdefault(name, [])
            series.append(float(duration_s))
            del series[:-self.window]

    def estimate(self, name: str) -> Optional[float]:
        """Rolling average of the last N runs, or None with no history."""
        with self._lock:
            series = list(self._data.get(name) or [])
        if not series:
            return None
        return sum(series) / len(series)

    def observations(self, name: str) -> int:
        return len(self._data.get(name) or [])


@dataclass
class Unit:
    """One thing the scan will spend time on: a tool or a module."""

    name: str
    kind: str = TOOL
    fallback_s: float = DEFAULT_ESTIMATE_S   # configured budget, used with no history
    estimate_s: float = DEFAULT_ESTIMATE_S   # what the ETA actually uses
    from_history: bool = False
    started_at: Optional[float] = None
    duration_s: Optional[float] = None
    done: bool = False
    skipped: bool = False                    # completed before a --resume
    attempt: int = 1

    @property
    def running(self) -> bool:
        return self.started_at is not None and not self.done


class ScanEstimator:
    """Tracks scan progress and answers "how much longer?".

    The estimate for a unit is the rolling average of its past runs; with no
    history it falls back to the configured timeout for that tool, flagged so
    the UI can say "estimated (no history yet)" instead of pretending to know.
    """

    def __init__(self, history: Optional[TimingHistory] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.history = history
        self._clock = clock
        self._units: list[Unit] = []
        self._index: dict[str, Unit] = {}
        self._current: Optional[Unit] = None
        self._lock = threading.RLock()


    def plan(self, units) -> None:
        """Declare the units this scan will run, in order.

        ``units`` is a sequence of ``(name, kind, fallback_seconds)`` tuples or
        :class:`Unit` instances.
        """
        with self._lock:
            for entry in units:
                unit = entry if isinstance(entry, Unit) else Unit(
                    name=entry[0],
                    kind=entry[1] if len(entry) > 1 else TOOL,
                    fallback_s=float(entry[2]) if len(entry) > 2 and entry[2]
                    else DEFAULT_ESTIMATE_S)
                estimate = self.history.estimate(unit.name) if self.history else None
                unit.from_history = estimate is not None
                unit.estimate_s = estimate if estimate is not None else unit.fallback_s
                if unit.name in self._index:
                    continue
                self._units.append(unit)
                self._index[unit.name] = unit

    @property
    def units(self) -> list[Unit]:
        return list(self._units)

    def get(self, name: str) -> Optional[Unit]:
        return self._index.get(name)


    def skip(self, name: str) -> None:
        """Mark a unit as already finished before this run (``--resume``), so
        it neither shows an ETA nor inflates the remaining estimate."""
        with self._lock:
            unit = self._index.get(name)
            if unit is None:
                return
            unit.skipped = True
            unit.done = True

    def start(self, name: str) -> Optional[Unit]:
        with self._lock:
            unit = self._index.get(name)
            if unit is None:
                unit = Unit(name=name)
                estimate = self.history.estimate(name) if self.history else None
                unit.from_history = estimate is not None
                unit.estimate_s = estimate if estimate is not None else unit.fallback_s
                self._units.append(unit)
                self._index[name] = unit
            unit.started_at = self._clock()
            unit.done = False
            self._current = unit
            return unit

    def retry(self, name: str, timeout_s: float) -> None:
        """A retry is running with a bigger budget — the old estimate is stale.

        The ETA switches to the new timeout, because that is now the only
        bound we have on how long this attempt can take.
        """
        with self._lock:
            unit = self._index.get(name)
            if unit is None or not timeout_s:
                return
            unit.attempt += 1
            unit.estimate_s = float(timeout_s)
            unit.from_history = False
            unit.started_at = self._clock()

    def finish(self, name: str, record: bool = True) -> Optional[float]:
        """Close a unit out and fold its real duration into the history."""
        with self._lock:
            unit = self._index.get(name)
            if unit is None:
                return None
            duration = (self._clock() - unit.started_at
                        if unit.started_at is not None else None)
            unit.duration_s = duration
            unit.done = True
            if self._current is unit:
                self._current = None
        if record and duration and duration > 0 and self.history is not None:
            self.history.record(name, duration)
        return duration


    @property
    def total(self) -> int:
        return len(self._units)

    @property
    def completed(self) -> int:
        return sum(1 for u in self._units if u.done)

    def position(self) -> int:
        """1-based index of the running unit, for ``[12/19]``."""
        done = self.completed
        return min(done + 1, self.total) if self._current is not None else done

    def elapsed(self) -> Optional[float]:
        unit = self._current
        if unit is None or unit.started_at is None:
            return None
        return self._clock() - unit.started_at

    def remaining(self) -> float:
        """Estimated seconds left: what is left of the running unit plus the
        full estimate of everything not started yet."""
        with self._lock:
            total = 0.0
            for unit in self._units:
                if unit.done:
                    continue
                if unit is self._current and unit.started_at is not None:
                    spent = self._clock() - unit.started_at
                    total += max(unit.estimate_s - spent, 0.0)
                else:
                    total += unit.estimate_s
            return total

    def snapshot(self) -> dict:
        """Everything the console line needs, computed at render time."""
        unit = self._current
        return {
            "position": self.position(),
            "total": self.total,
            "name": unit.name if unit else "",
            "kind": unit.kind if unit else "",
            "attempt": unit.attempt if unit else 1,
            "elapsed": self.elapsed(),
            "estimate": unit.estimate_s if unit else None,
            "from_history": bool(unit.from_history) if unit else False,
            "remaining": self.remaining(),
        }

    def line(self) -> str:
        """The one-line progress form, e.g.::

            [12/19] running nuclei ...  elapsed 2m14s / est. 3m40s   |  scan ETA: ~9m remaining
        """
        snap = self.snapshot()
        if not snap["name"]:
            if snap["total"] and snap["position"] >= snap["total"]:
                return "all phases complete"
            state = "starting" if snap["position"] == 0 else "between phases"
            return (f"[{snap['position']}/{snap['total']}] {state}  |  "
                    f"scan ETA: {format_eta(snap['remaining'])} remaining")
        est = format_duration(snap["estimate"])
        if not snap["from_history"]:
            est += " (estimated, no history yet)"
        attempt = f" (attempt {snap['attempt']})" if snap["attempt"] > 1 else ""
        return (f"[{snap['position']}/{snap['total']}] running {snap['name']}{attempt} ..."
                f"  elapsed {format_duration(snap['elapsed'])} / est. {est}"
                f"   |  scan ETA: {format_eta(snap['remaining'])} remaining")

    def save_history(self) -> None:
        if self.history is not None:
            self.history.save()
