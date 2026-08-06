from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "xss"
CATEGORY = "XSS"


def _marker() -> tuple[str, str]:
    tok = uuid.uuid4().hex[:10]
    return f"lop{tok}<x>\"'", tok


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    reflected_targets = _param_targets(ctx)
    total = len(reflected_targets) + len([f for f in ctx.forms
                                          if f.get("method") == "get"])
    if phase:
        phase.set_total(max(total, 1))

    with ThreadPoolExecutor(max_workers=ctx.threads) as pool:
        futures = [pool.submit(_test_reflected, ctx, url, param)
                   for url, param in reflected_targets]
        for fut in as_completed(futures):
            f = fut.result()
            if f:
                ctx.add_finding(f)
            phase and phase.step()

    _test_stored(ctx, phase)
    phase and phase.done()


def _param_targets(ctx) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for url in ctx.discovered_urls:
        for param in parse_qs(urlparse(url).query).keys():
            targets.append((url, param))

    for form in ctx.forms:
        if form.get("method") != "get":
            continue
        for inp in form.get("inputs", []):
            if inp.get("name"):
                targets.append((form.get("action", ctx.target), inp["name"]))

    if not targets:
        targets.append((ctx.target + "/?q=1", "q"))
    return targets


def _inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


_CTX_LABELS = {
    "html": "HTML body",
    "script": "inline <script>",
    "event": "an event-handler attribute",
    "attribute": "an HTML attribute",
    "rcdata": "a <textarea>/<title>",
    "comment": "an HTML comment",
}


def _context(body: str, idx: int) -> str:
    prefix = body[:idx]
    low = prefix.lower()
    so, sc = low.rfind("<script"), low.rfind("</script")
    if so != -1 and so > sc:
        return "script"
    for tag in ("textarea", "title"):
        to, tc = low.rfind("<" + tag), low.rfind("</" + tag)
        if to != -1 and to > tc:
            return "rcdata"
    cs, ce = prefix.rfind("<!--"), prefix.rfind("-->")
    if cs != -1 and cs > ce:
        return "comment"
    lt, gt = prefix.rfind("<"), prefix.rfind(">")
    if lt > gt:
        if re.search(r"\bon\w+\s*=\s*[\"']?[^\"'>]*$", prefix[lt:], re.I):
            return "event"
        return "attribute"
    return "html"


def _classify(context: str, dq: bool, sq: bool):
    if context in ("html", "script", "event"):
        return Severity.HIGH, Confidence.CONFIRMED, True
    if context == "attribute":
        if dq or sq:
            return Severity.HIGH, Confidence.CONFIRMED, True
        return Severity.MEDIUM, Confidence.TENTATIVE, False
    return Severity.MEDIUM, Confidence.TENTATIVE, False


def _test_reflected(ctx, url, param) -> Finding | None:
    payload, tok = _marker()
    canary = f"lop{tok}"

    try:
        clean = ctx.session.get(_inject(url, param, f"{canary}clean"),
                                timeout=ctx.timeout).text
        test = ctx.session.get(_inject(url, param, payload),
                               timeout=ctx.timeout).text
    except requests.RequestException:
        return None

    idx = test.find(canary)
    if idx == -1:
        return None

    raw_signature = f"{tok}<x>"
    baseline_body = getattr(getattr(ctx, "baseline", None), "root", None)
    refs = [clean] + ([baseline_body.body] if baseline_body is not None else [])
    if any(raw_signature in r for r in refs):
        return None

    after = test[idx + len(canary): idx + len(canary) + 8]
    angle = "<x>" in after
    dq, sq = '"' in after, "'" in after
    if not angle:
        return None

    context = _context(test, idx)
    severity, confidence, exploitable = _classify(context, dq, sq)

    if not _retry_confirm(ctx, url, param):
        return None

    snippet = test[max(0, idx - 30): idx + len(canary) + 12].replace("\n", " ")
    label = _CTX_LABELS.get(context, context)
    if exploitable:
        name = "Reflected XSS"
        desc = (f"Input to '{param}' is reflected unencoded in {label} context "
                "(raw '<' and '>'"
                + (", plus a quote," if (dq or sq) else "")
                + " survive), allowing script injection in the victim's browser.")
    else:
        name = "Reflected input (possible XSS)"
        desc = (f"Input to '{param}' is reflected unencoded in {label} context. "
                "Raw angle brackets survive, but reaching script execution needs a "
                "break-out sequence not verified here — confirm manually.")

    return Finding(
        name=name,
        severity=severity,
        location=f"{url} [param: {param}]",
        description=desc,
        remediation="Context-aware output encoding on all reflected input; apply "
                    "a restrictive CSP as defence in depth.",
        module=MODULE_NAME, category=CATEGORY,
        evidence=f"[{context}] {snippet}",
        request=f"GET {_inject(url, param, payload)}",
        confidence=confidence,
    )


def _retry_confirm(ctx, url, param, attempts: int = 2) -> bool:
    for _ in range(attempts):
        payload, tok = _marker()
        try:
            body = ctx.session.get(_inject(url, param, payload),
                                   timeout=ctx.timeout).text
        except requests.RequestException:
            return False
        if f"{tok}<x>" not in body:
            return False
    return True


def _test_stored(ctx, phase) -> None:
    payload, tok = _marker()
    raw_signature = f"{tok}<x>"
    submitted = 0
    for form in ctx.forms:
        if form.get("method") != "post":
            continue
        data = {}
        for inp in form.get("inputs", []):
            name = inp.get("name")
            if not name:
                continue
            itype = inp.get("type", "text")
            if itype in ("submit", "button", "file", "image"):
                continue
            if itype == "email":
                data[name] = f"lop{tok}@example.com"
            elif itype in ("text", "search", "textarea", "url", ""):
                data[name] = payload
            else:
                data[name] = inp.get("value") or "1"
        if not data:
            continue
        try:
            ctx.session.post(form["action"], data=data, timeout=ctx.timeout,
                             allow_redirects=True)
            submitted += 1
        except requests.RequestException:
            continue

    if submitted == 0:
        return

    pages = set(ctx.discovered_urls) | {f["page"] for f in ctx.forms} | {ctx.target + "/"}
    for page in pages:
        try:
            body = ctx.session.get(page, timeout=ctx.timeout).text
        except requests.RequestException:
            continue
        if raw_signature in body:
            ctx.add_finding(Finding(
                name="Stored XSS",
                severity=Severity.CRITICAL,
                location=page,
                description="An inert marker submitted via a form persisted and "
                            "was rendered unencoded on this page, indicating "
                            "stored XSS.",
                remediation="Encode output on render and validate/sanitise input "
                            "on storage; apply a restrictive CSP.",
                module=MODULE_NAME, category=CATEGORY,
                evidence=raw_signature,
                confidence=Confidence.CONFIRMED))
            return
