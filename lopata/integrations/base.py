from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from urllib.parse import urlparse

from ..core.models import ToolInfo
from ..core.retry import supervise
from ..core.tool_status import ToolRunStatus, ToolStatus


def which(*names: str) -> str | None:
    venv_bin = os.path.dirname(sys.executable)
    for name in names:
        path = shutil.which(name)
        if path:
            return path
        local = os.path.join(venv_bin, name)
        if os.path.isfile(local) and os.access(local, os.X_OK):
            return local
    return None


def mark_skipped(ctx, tool: str, note: str = "") -> None:
    """Record that a tool never ran, so the run-level completeness figures see
    it. Safe to call more than once — an already-recorded status wins."""
    registry = getattr(ctx, "tool_status", None)
    if registry is not None:
        registry.mark_unrun(tool, note)


def detect(ctx, key: str, binaries: tuple[str, ...], version_cmd) -> ToolInfo:
    if key in ctx.tools:
        return ctx.tools[key]

    enabled = ctx.config.get("tools", {}).get(key, True)
    if not enabled:
        info = ToolInfo(name=key, available=False, note="disabled in config")
        ctx.tools[key] = info
        mark_skipped(ctx, key, info.note)
        return info

    path = which(*binaries)
    if not path:
        info = ToolInfo(name=key, available=False,
                        note=f"not installed ({' / '.join(binaries)})")
        ctx.tools[key] = info
        mark_skipped(ctx, key, info.note)
        ctx.logger and ctx.logger.info("[-] %s not found; skipping", key)
        return info

    version = ""
    try:
        out = subprocess.run(version_cmd(path), capture_output=True, text=True,
                             timeout=15)
        version = _first_version_line(out.stdout + out.stderr)
    except Exception:
        pass
    info = ToolInfo(name=key, available=True, version=version, path=path)
    ctx.tools[key] = info
    return info


def run_tool(argv: list[str], timeout: int, logger=None, ctx=None,
             tool: str | None = None) -> subprocess.CompletedProcess | None:
    """Run an external tool, under retry supervision when the scan has one.

    Every invocation leaves a :class:`~lopata.core.tool_status.ToolRunStatus`
    on ``ctx``, so a timeout is never silently swallowed: the orchestrator can
    see that the tool did not finish, the correlation pass can cap findings
    that rested on it alone, and the report can say so out loud.

    ``tool`` is the integration's registry key (``sslscan``, not ``ssl_tls``);
    it defaults to the binary name.
    """
    name = tool or os.path.basename(argv[0])
    logger = logger or (getattr(ctx, "logger", None) if ctx else None)

    def attempt(attempt_timeout: float):
        started = time.monotonic()
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=attempt_timeout)
        except subprocess.TimeoutExpired as exc:
            logger and logger.warning("tool timed out after %.0fs: %s",
                                      attempt_timeout, " ".join(argv[:2]))
            return None, ToolRunStatus(
                tool_name=name, status=ToolStatus.TIMED_OUT,
                duration_s=time.monotonic() - started,
                stderr_tail=_decode(exc.stderr),
                note=f"exceeded its {attempt_timeout:.0f}s budget")
        except Exception as exc:
            logger and logger.warning("tool failed: %s (%s)", argv[0], exc)
            return None, ToolRunStatus(
                tool_name=name, status=ToolStatus.FAILED,
                duration_s=time.monotonic() - started,
                stderr_tail=str(exc), note=exc.__class__.__name__)

        status = (ToolStatus.FAILED if proc.returncode is not None
                  and proc.returncode < 0 else ToolStatus.COMPLETED)
        return proc, ToolRunStatus(
            tool_name=name, status=status,
            duration_s=time.monotonic() - started,
            exit_code=proc.returncode, stderr_tail=_decode(proc.stderr),
            note="killed by signal" if status is ToolStatus.FAILED else "")

    proc, _status = supervise(ctx, name, attempt, timeout)
    return proc


def _decode(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


@contextmanager
def temp_output(suffix: str = ".json"):
    """Give a tool a private directory to write its report into.

    Several tools do not honour "-" as "write to stdout" (nikto and testssl.sh
    both take it as a literal filename and litter the working directory), and
    they disagree about whether they append their own extension to the path
    they were given — nikto will happily produce "out.json.json". Handing over
    an empty directory and reading back whatever appeared in it sidesteps all
    of that, and cleans up afterwards either way.

    Yields ``(path, read)`` where ``read()`` returns the file contents, or ""
    if the tool wrote nothing.
    """
    directory = tempfile.mkdtemp(prefix="lopata-")
    path = os.path.join(directory, "output" + suffix)

    def read() -> str:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            return ""
        for name in names:
            candidate = os.path.join(directory, name)
            try:
                if os.path.getsize(candidate) == 0:
                    continue
                with open(candidate, "r", encoding="utf-8",
                          errors="replace") as fh:
                    return fh.read()
            except OSError:
                continue
        return ""

    try:
        yield path, read
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@contextmanager
def temp_input(text: str, suffix: str = ".txt"):
    """Write ``text`` to a private temp file and yield its path.

    Several of the newer tools (nuclei, ffuf, dalfox) take a list of targets or
    a wordlist from a file rather than stdin; this hands them one and removes it
    afterwards regardless of outcome.
    """
    directory = tempfile.mkdtemp(prefix="lopata-in-")
    path = os.path.join(directory, "input" + suffix)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def host_of(target: str) -> str:
    return urlparse(target).hostname or target


def _first_version_line(text: str) -> str:
    import re
    for line in text.splitlines():
        line = line.strip()
        if re.search(r"\d+\.\d+", line):
            return line[:80]
    return text.strip().splitlines()[0][:80] if text.strip() else ""
