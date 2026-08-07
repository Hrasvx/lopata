from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from urllib.parse import urlparse

from ..core.models import ToolInfo


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


def detect(ctx, key: str, binaries: tuple[str, ...], version_cmd) -> ToolInfo:
    if key in ctx.tools:
        return ctx.tools[key]

    enabled = ctx.config.get("tools", {}).get(key, True)
    if not enabled:
        info = ToolInfo(name=key, available=False, note="disabled in config")
        ctx.tools[key] = info
        return info

    path = which(*binaries)
    if not path:
        info = ToolInfo(name=key, available=False,
                        note=f"not installed ({' / '.join(binaries)})")
        ctx.tools[key] = info
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


def run_tool(argv: list[str], timeout: int, logger=None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger and logger.warning("tool timed out: %s", " ".join(argv[:2]))
    except Exception as exc:
        logger and logger.warning("tool failed: %s (%s)", argv[0], exc)
    return None


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


def host_of(target: str) -> str:
    return urlparse(target).hostname or target


def _first_version_line(text: str) -> str:
    import re
    for line in text.splitlines():
        line = line.strip()
        if re.search(r"\d+\.\d+", line):
            return line[:80]
    return text.strip().splitlines()[0][:80] if text.strip() else ""
