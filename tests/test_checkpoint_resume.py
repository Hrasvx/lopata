"""Resume support for the status registry and the retry budget."""

from __future__ import annotations

import requests
from conftest import completed, make_finding, timed_out

from lopata.core import checkpoint as ckpt
from lopata.core.config import load_config
from lopata.core.models import Confidence, ScanContext
from lopata.core.retry import RetryPolicy, RetrySupervisor
from lopata.core.tool_status import ToolStatus


def _fresh_ctx():
    return ScanContext(target="https://example.test",
                       session=requests.Session(), config=load_config(None))


def test_tool_status_and_attempts_survive_a_checkpoint(tmp_path):
    path = str(tmp_path / "cp.json")
    ctx = _fresh_ctx()
    ctx.tool_status.expect(["nmap", "dalfox"])
    ctx.tool_status.record(completed("nmap"))
    ctx.tool_status.record(timed_out("dalfox", attempts=1))
    ctx.retry_supervisor = RetrySupervisor(
        RetryPolicy(max_attempts=3), resumed_attempts={"dalfox": 1})

    ckpt.save(ctx, path, ["tool:nmap"])

    resumed = _fresh_ctx()
    assert ckpt.load(resumed, path) == ["tool:nmap"]
    assert resumed.tool_status.get("nmap").status is ToolStatus.COMPLETED
    assert resumed.tool_status.get("dalfox").status is ToolStatus.TIMED_OUT
    assert resumed.tool_status.expected == ["nmap", "dalfox"]
    assert ckpt.resumed_attempts(path) == {"dalfox": 1}


def test_findings_keep_their_coverage_flags_across_a_resume(tmp_path):
    path = str(tmp_path / "cp.json")
    ctx = _fresh_ctx()
    finding = make_finding(confidence=Confidence.LOW)
    finding.contributing_tools = ["dalfox"]
    finding.incomplete_coverage = True
    ctx.findings.append(finding)

    ckpt.save(ctx, path, [])
    resumed = _fresh_ctx()
    ckpt.load(resumed, path)

    restored = resumed.findings[0]
    assert restored.contributing_tools == ["dalfox"]
    assert restored.incomplete_coverage is True


def test_a_checkpoint_from_an_older_version_is_ignored(tmp_path):
    path = tmp_path / "cp.json"
    path.write_text('{"version": 1, "target": "https://example.test", '
                    '"completed_modules": ["tool:nmap"]}')

    ctx = _fresh_ctx()
    assert ckpt.load(ctx, str(path)) == []
    assert ckpt.resumed_attempts(str(path)) == {}
