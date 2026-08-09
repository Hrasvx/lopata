"""sqlmap integration — deeper confirmation of SQL-injection leads.

sqlmap is exhaustive and slow, so it is not pointed at every endpoint. It runs
in the post-discovery phase against the parameters lopata's own ``modules/sqli``
already flagged as leads — to confirm them independently and add the depth
(back-end DBMS, working technique) that lopata's own payload set does not
attempt. A confirmation is emitted at the *same* injection-point location the
sqli module used, so the correlation pass merges the two into one finding with
two sources; a negative result becomes a passed check rather than being
discarded.

Set ``sqlmap_probe_leadless: true`` to also test a small sample of crawler
parameters when the sqli module found nothing — off by default to stay quiet.
"""

from __future__ import annotations

import re

from ..core.correlate import injection_point, signature
from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from ._shared import injectable_targets
from .base import detect, run_tool

MODULE_NAME = "sqlmap"
CATEGORY = "SQL Injection"
PHASE = "post"

_VULN_SIGN = re.compile(
    r"parameter '[^']+' (?:is|appears to be) .*injectable"
    r"|is vulnerable\b|identified the following injection point", re.I)
_NOT_VULN = re.compile(
    r"all tested parameters (?:do not appear to be|appear to be not) injectable"
    r"|does not (?:seem|appear) to be injectable", re.I)
_DBMS = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_TYPE_LINE = re.compile(r"^\s*Type:\s*(.+)$", re.M)

_STEPS = [
    "Replace string concatenation with parameterised queries (prepared "
    "statements) — bind every user-supplied value, without exception.",
    "Map any dynamic identifier through a fixed allow-list.",
    "Reduce the database account's privileges to the minimum the app needs.",
    "Audit the codebase for the same pattern elsewhere.",
]
_REFS = ["https://cheatsheetseries.owasp.org/cheatsheets/"
         "SQL_Injection_Prevention_Cheat_Sheet.html"]


def available(ctx):
    return detect(ctx, "sqlmap", ("sqlmap", "sqlmap.py"),
                  lambda p: [p, "--version"])


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)

    targets = _leads(ctx)
    if not targets and ctx.config.get("sqlmap_probe_leadless", False):
        targets = injectable_targets(ctx, 3)
    max_targets = int(ctx.config.get("sqlmap_max_targets", 10))
    targets = targets[:max_targets]
    if phase:
        phase.set_total(max(len(targets), 1))

    budget = int(ctx.config.get("sqlmap_timeout", 300))
    per_call = max(30, budget // max(len(targets), 1))

    for target in targets:
        _run_one(ctx, info, target, per_call)
        phase and phase.step()
    phase and phase.done()


def _leads(ctx) -> list[dict]:
    """Injectable targets whose injection point a sqli finding already named."""
    lead_keys = set()
    for f in ctx.findings:
        if f.module == "sqli" or signature(f) == "sqli":
            point = injection_point(f.location)
            if point is not None:
                lead_keys.add(point)
    if not lead_keys:
        return []
    out = []
    for t in injectable_targets(ctx, 200):
        loc = f"{t['url']} [{t['method']} param: {t['param']}]"
        if injection_point(loc) in lead_keys:
            out.append(t)
    return out


def _run_one(ctx, info, target, timeout) -> None:
    argv = [info.path, "-u", target["url"], "-p", target["param"],
            "--batch", "--smart", "--level", "1", "--risk", "1",
            "--flush-session", "--disable-coloring", "--technique", "BEUST",
            "--timeout", str(int(ctx.timeout) + 3), "--retries", "1", "-v", "0"]
    if target["method"] == "POST":
        data = target["data"] or {}
        data = dict(data)
        data.setdefault(target["param"], "1")
        argv += ["--method", "POST", "--data",
                 "&".join(f"{k}={v}" for k, v in data.items())]
    proc = run_tool(argv, timeout=timeout, logger=ctx.logger,
    ctx=ctx, tool="sqlmap")
    if proc is None:
        return
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    ctx.add_raw_output(f"sqlmap:{target['param']}", out)

    loc = f"{target['url']} [{target['method']} param: {target['param']}]"
    if _VULN_SIGN.search(out) and not _NOT_VULN.search(out):
        ctx.add_finding(_confirmed(target, loc, out))
    elif _NOT_VULN.search(out):
        ctx.add_passed(PassedCheck(
            name="SQL injection re-test (sqlmap)",
            detail=f"`{target['param']}` on {target['url']} was exercised by "
                   "sqlmap and found not injectable",
            source=MODULE_NAME, location=loc, score_area=AREA_WEBAPP))


def _confirmed(target, loc, out) -> Finding:
    dbms = _DBMS.search(out)
    techniques = _TYPE_LINE.findall(out)
    dbms_txt = dbms.group(1).strip() if dbms else "unknown"
    tech_txt = "; ".join(t.strip() for t in techniques[:4]) or "confirmed by sqlmap"

    finding = Finding(
        name="SQL injection (confirmed by sqlmap)",
        severity=Severity.INFO, location=loc,
        description=(
            f"sqlmap independently exercised `{target['param']}` and confirmed "
            f"it is injectable. Back-end DBMS: {dbms_txt}. Technique(s): "
            f"{tech_txt}.\n\nThis corroborates lopata's own SQL-injection check "
            "on the same parameter; where both agree the finding carries two "
            "independent sources."
        ),
        remediation=_STEPS[0],
        ftype=FindingType.CONFIRMED_VULN,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"`{target['param']}` is injectable (sqlmap, DBMS: {dbms_txt}).",
        risk="User-supplied input reaches the SQL query as code. The database "
             "cannot distinguish the query structure from the attacker's addition.",
        impact="Read access to every table the app's database user can reach — "
               "typically all of them, including credentials and personal data — "
               "and, with sufficient privileges, file access or command execution "
               "on the database host.",
        remediation_steps=_STEPS,
        verification="Re-run sqlmap against the same parameter after "
                     "parameterising the query; it should report it not injectable.",
        references=_REFS,
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=(f"DBMS: {dbms_txt}\n" + "\n".join(techniques[:6]))[:1000],
        request=f"{target['method']} {target['url']}  param={target['param']}",
        verified_by="sqlmap reproduced the injection with a working technique",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.TOTAL, exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
        notes=["independently confirmed by sqlmap; where lopata's own check "
               "agrees this becomes a multi-source Confirmed finding"],
    ))
    return finding


def register():
    from ..core.plugins import integration
    return integration('sqlmap', run, available, phase='post', order=110)
