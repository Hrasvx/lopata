"""Feature 3 x Feature 1: an absent tool is a recorded gap, never an error.

Every integration must survive its binary (or, for ZAP, its API) being
missing: no exception, no findings invented, and a `skipped_missing` status so
the run-level completeness figures can account for it.
"""

from __future__ import annotations

import pytest

from lopata.core.tool_status import ToolStatus
from lopata.integrations import INTEGRATIONS

TOOL_KEYS = {name: name for name in INTEGRATIONS}
TOOL_KEYS["sslscan"] = "sslscan"

NEW_INTEGRATIONS = ["nuclei", "dalfox", "sqlmap", "arjun", "ffuf", "gitleaks",
                    "zap"]


@pytest.fixture(autouse=True)
def no_binaries(monkeypatch):
    """Pretend nothing is installed and no ZAP daemon is listening."""
    import shutil

    from lopata.integrations import base, zap
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(base, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(zap, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(zap, "_get", lambda *_a, **_k: None)


@pytest.mark.parametrize("name", NEW_INTEGRATIONS)
def test_new_integration_reports_skipped_missing(name, ctx):
    plugin = INTEGRATIONS[name]

    info = plugin.available(ctx)
    assert info.available is False
    plugin.run(ctx, None)          # must not raise

    status = ctx.tool_status.get(TOOL_KEYS[name])
    assert status is not None, f"{name} left no status behind"
    assert status.status is ToolStatus.SKIPPED_MISSING
    assert ctx.findings == []


@pytest.mark.parametrize("name", sorted(INTEGRATIONS))
def test_every_integration_survives_a_bare_system(name, ctx):
    """The same contract for the pre-existing integrations."""
    INTEGRATIONS[name].run(ctx, None)
    assert ctx.findings == []


@pytest.mark.parametrize("name", sorted(INTEGRATIONS))
def test_disabled_in_config_is_recorded_too(name, ctx):
    ctx.config["tools"] = {n: False for n in INTEGRATIONS}
    INTEGRATIONS[name].run(ctx, None)

    status = ctx.tool_status.get(TOOL_KEYS[name])
    assert status is not None
    assert status.status is ToolStatus.SKIPPED_MISSING


def test_zap_skips_cleanly_when_autostart_is_off(ctx):
    ctx.config["zap_autostart"] = False
    INTEGRATIONS["zap"].run(ctx, None)

    status = ctx.tool_status.get("zap")
    assert status.status is ToolStatus.SKIPPED_MISSING
    assert "not reachable" in (status.note or "")


def test_gitleaks_is_not_applicable_without_client_side_assets(ctx,
                                                               monkeypatch):
    """A pure HTTP run with nothing fetchable is "N/A", not a failure."""
    from lopata.integrations import gitleaks

    monkeypatch.setattr(gitleaks, "available",
                        lambda _ctx: _AvailableTool("gitleaks"))
    monkeypatch.setattr(gitleaks, "_collect_corpus", lambda _ctx: {})

    gitleaks.run(ctx, None)

    status = ctx.tool_status.get("gitleaks")
    assert status.status is ToolStatus.SKIPPED_MISSING
    assert "nothing" in status.note or "no local repo" in status.note


class _AvailableTool:
    def __init__(self, name):
        self.name = name
        self.available = True
        self.version = "test"
        self.path = f"/usr/bin/{name}"
        self.note = ""
