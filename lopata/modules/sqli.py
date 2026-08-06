from __future__ import annotations

import re
import time
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


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    targets = _targets(ctx)
    if phase:
        phase.set_total(max(len(targets), 1))
    with ThreadPoolExecutor(max_workers=max(ctx.threads // 2, 1)) as pool:
        futures = [pool.submit(_test_param, ctx, url, param)
                   for url, param in targets]
        for fut in as_completed(futures):
            for f in fut.result():
                ctx.add_finding(f)
            phase and phase.step()
    phase and phase.done()


def _targets(ctx) -> list[tuple[str, str]]:
    out = []
    for url in ctx.discovered_urls:
        for param in parse_qs(urlparse(url).query).keys():
            out.append((url, param))
    for form in ctx.forms:
        if form.get("method") == "get":
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    out.append((form.get("action", ctx.target), inp["name"]))
    return out


def _inject(url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _get(ctx, url):
    try:
        r = ctx.session.get(url, timeout=ctx.timeout + SLEEP_SECONDS + 2)
        return r.text, r.elapsed.total_seconds()
    except requests.RequestException:
        return None, None


def _test_param(ctx, url, param) -> list[Finding]:
    findings: list[Finding] = []
    clean_url = _inject(url, param, "lopata1")
    clean_body, _ = _get(ctx, clean_url)
    if clean_body is None:
        return findings

    badinput_body, _ = _get(ctx, _inject(url, param, "lopata_$$$_%%%"))
    refs = [b for b in (clean_body, badinput_body) if b]

    loc = f"{url} [param: {param}]"


    for payload in ERROR_PAYLOADS:
        body, _ = _get(ctx, _inject(url, param, "lopata" + payload))
        if body is None:
            continue
        m = _ERROR_SIGNS.search(body)
        if m and not any(_ERROR_SIGNS.search(r) for r in refs):
            findings.append(Finding(
                name="SQL injection (error-based)",
                severity=Severity.HIGH, location=loc,
                description=f"Injecting {payload!r} into '{param}' triggers a "
                            "database error absent from the clean and bad-input "
                            "responses, indicating the input reaches a SQL query.",
                remediation="Use parameterised queries / prepared statements; "
                            "never build SQL by string concatenation.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=body[max(0, m.start() - 20):m.start() + 120].replace("\n", " "),
                request=f"GET {_inject(url, param, 'lopata' + payload)}",
                confidence=Confidence.CONFIRMED))
            return findings


    if _boolean_blind(ctx, url, param, clean_body):
        findings.append(Finding(
            name="SQL injection (boolean-based blind)",
            severity=Severity.HIGH, location=loc,
            description=f"A TRUE condition on '{param}' returns a page matching "
                        "the normal response while a FALSE condition returns a "
                        "materially different one — reproducibly — indicating "
                        "boolean-based blind SQLi.",
            remediation="Use parameterised queries; validate and type-check input.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=f"TRUE ~ clean, FALSE diverges (confirmed on retry)",
            request=f"GET {_inject(url, param, BOOL_TRUE)}",
            confidence=Confidence.CONFIRMED))
        return findings


    tf = _time_blind(ctx, url, param)
    if tf:
        findings.append(tf.finding(loc, param, url))
    return findings


def _boolean_blind(ctx, url, param, clean_body) -> bool:
    def pair():
        t, _ = _get(ctx, _inject(url, param, BOOL_TRUE))
        f, _ = _get(ctx, _inject(url, param, BOOL_FALSE))
        return t, f

    t1, f1 = pair()
    if t1 is None or f1 is None:
        return False
    sim_true = similarity(clean_body, t1)
    sim_false = similarity(clean_body, f1)
    sim_tf = similarity(t1, f1)

    hit = sim_true >= 0.95 and sim_false <= 0.90 and sim_tf <= 0.90
    if not hit:
        return False

    t2, f2 = pair()
    if t2 is None or f2 is None:
        return False
    return (similarity(clean_body, t2) >= 0.95
            and similarity(clean_body, f2) <= 0.90)


class _TimeHit:
    def __init__(self, payload, delay, control):
        self.payload, self.delay, self.control = payload, delay, control

    def finding(self, loc, param, url):
        return Finding(
            name="SQL injection (time-based blind)",
            severity=Severity.HIGH, location=loc,
            description=f"A time-delay payload on '{param}' delayed the response "
                        f"to {self.delay:.1f}s (control {self.control:.1f}s), "
                        "reproducibly, indicating time-based blind SQLi.",
            remediation="Use parameterised queries; do not interpolate input into "
                        "SQL.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=f"delay={self.delay:.1f}s vs control={self.control:.1f}s",
            request=f"GET {_inject(url, param, self.payload)}",
            confidence=Confidence.CONFIRMED)


def _time_blind(ctx, url, param) -> "_TimeHit | None":
    control_body, control_t = _get(ctx, _inject(url, param, TIME_CONTROL))
    if control_t is None:
        return None
    for payload in TIME_PAYLOADS:
        _, t1 = _get(ctx, _inject(url, param, payload))
        if t1 is None or t1 < SLEEP_SECONDS * 0.8:
            continue

        _, t2 = _get(ctx, _inject(url, param, payload))
        _, c2 = _get(ctx, _inject(url, param, TIME_CONTROL))
        if (t2 is not None and t2 >= SLEEP_SECONDS * 0.8
                and c2 is not None and c2 < SLEEP_SECONDS * 0.5):
            return _TimeHit(payload, (t1 + t2) / 2, (control_t + c2) / 2)
    return None
