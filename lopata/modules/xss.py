from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

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
    """Reflection alone is not XSS — what matters is whether the characters
    needed to break out of the surrounding context survived encoding."""
    if context in ("html", "script", "event"):
        return Confidence.CONFIRMED, True
    if context == "attribute":
        if dq or sq:
            # A surviving quote is what turns attribute reflection into
            # execution; without it, the payload stays inside the value.
            return Confidence.CONFIRMED, True
        return Confidence.MEDIUM, False
    return Confidence.MEDIUM, False


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
    confidence, exploitable = _classify(context, dq, sq)

    if not _retry_confirm(ctx, url, param):
        return None

    snippet = test[max(0, idx - 30): idx + len(canary) + 12].replace("\n", " ")
    label = _CTX_LABELS.get(context, context)

    if exploitable:
        name = "Reflected cross-site scripting"
        ftype = FindingType.CONFIRMED_VULN
        description = (
            f"Input supplied in `{param}` is reflected into the response inside "
            f"{label} with no output encoding: raw `<` and `>` survive"
            + (", and so does a quote character" if (dq or sq) else "")
            + ". lopata confirmed the reflection three times with a fresh random "
              "marker each time, and checked that the marker does not appear in "
              "the clean or baseline responses, so this is not an artefact of "
              "page content."
        )
        impact = (
            "An attacker who gets a victim to follow a crafted link executes "
            "JavaScript in the victim's session on this origin: reading and "
            "exfiltrating session cookies (unless HttpOnly), performing any "
            "action the user can perform, rewriting the page to capture "
            "credentials, and pivoting to any API the origin can reach."
        )
        impact_level = Impact.SERIOUS
        exploitability = Exploitability.EASY
    else:
        name = "Unencoded input reflection (possible XSS)"
        ftype = FindingType.POTENTIAL_VULN
        description = (
            f"Input supplied in `{param}` is reflected into {label} with angle "
            "brackets intact, but the characters needed to break out of the "
            "surrounding context were encoded or absent. That means the "
            "reflection is real and unencoded, while script execution has not "
            "been demonstrated — a manual attempt with a context-appropriate "
            "payload is needed to settle it."
        )
        impact = (
            "If a break-out sequence exists that lopata did not try, the impact "
            "is that of reflected XSS: full script execution in the victim's "
            "session. If not, the reflection is inert."
        )
        impact_level = Impact.LIMITED
        exploitability = Exploitability.MODERATE

    finding = Finding(
        name=name,
        severity=Severity.INFO,
        location=f"{url} [param: {param}]",
        description=description,
        remediation="Encode output for the context it lands in, at the point of "
                    "rendering.",
        ftype=ftype,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"`{param}` is reflected unencoded into {label}.",
        risk=(
            "The application places attacker-controlled text into the page "
            "without encoding it for the context it lands in. The browser cannot "
            "distinguish that text from the developer's own markup."
        ),
        impact=impact,
        remediation_steps=[
            f"Encode on output for the {label} context specifically — HTML-entity "
            "encoding is not sufficient inside a script block or an event "
            "handler attribute.",
            "Use the template engine's automatic contextual escaping rather than "
            "string concatenation; if it is disabled for this value, find out why.",
            "Never place user input directly into a <script> block; pass it "
            "through a JSON-encoded data attribute instead.",
            "Add a Content-Security-Policy without 'unsafe-inline' so that a "
            "missed case cannot execute.",
            "Validate input at the boundary as defence in depth — but encode on "
            "output, because that is where the context is known.",
        ],
        verification=(
            f"Request the URL with `{param}` set to a harmless marker and view "
            "the page source: the marker should appear entity-encoded "
            "(`&lt;`/`&gt;`) rather than as raw markup."
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=f"[{context} context] {snippet}",
        request=f"GET {_inject(url, param, payload)}",
        response=f"marker reflected at offset {idx} in {label}",
        verified_by="lopata reproduced the reflection with three independent "
                    "random markers",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact_level,
        exploitability=exploitability,
        auth=AuthRequirement.NONE,
        exposure=Exposure.PUBLIC,
        confidence=confidence,
        notes=["reflected XSS requires the victim to follow an attacker-supplied "
               "link, which bounds it below stored XSS"],
    ))
    return finding


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
            finding = Finding(
                name="Stored cross-site scripting",
                severity=Severity.INFO,
                location=page,
                description=(
                    "An inert marker submitted through a form on this site was "
                    "persisted and later rendered back unencoded on this page. "
                    "The marker contained angle brackets, and they survived "
                    "both storage and rendering.\n\n"
                    "Stored XSS is the most severe variant: no crafted link is "
                    "needed, and the payload executes for every user who views "
                    "the affected page, including administrators."
                ),
                remediation="Encode on output at render time, and validate on "
                            "input at storage time.",
                ftype=FindingType.CONFIRMED_VULN,
                module=MODULE_NAME, category=CATEGORY,
                summary="Submitted markup is stored and rendered unencoded.",
                risk=(
                    "Any visitor to this page executes attacker-supplied script "
                    "in their own session, with no interaction beyond viewing "
                    "the page. Payloads persist until the stored data is cleaned."
                ),
                impact=(
                    "Session theft and full account takeover for every viewer, "
                    "including staff and administrators — which typically means "
                    "the highest-privileged account in the application is "
                    "compromised within a working day. Self-propagating payloads "
                    "in shared content are a routine outcome."
                ),
                remediation_steps=[
                    "Encode all stored content on output, using the encoding "
                    "appropriate to where it is rendered.",
                    "If the field is meant to accept rich text, run it through a "
                    "vetted HTML sanitiser (DOMPurify, Bleach) with an "
                    "allow-list — never a regex-based filter.",
                    "Audit stored data for payloads already present before "
                    "deploying the fix.",
                    "Add a Content-Security-Policy without 'unsafe-inline'.",
                    "Set HttpOnly on session cookies to blunt token theft.",
                ],
                verification=(
                    "Submit a harmless marker containing angle brackets through "
                    "the same form and confirm it renders as visible text, "
                    "entity-encoded in the page source."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
                effort=Effort.MODERATE,
                score_area=AREA_WEBAPP,
                evidence=f"marker {raw_signature} found rendered on {page}",
                request="POST to the discovered form(s), then GET " + page,
                response="marker present unencoded in the response body",
                verified_by="lopata submitted the marker and re-fetched the page "
                            "to observe it rendered",
                sources=[MODULE_NAME],
            )
            apply(finding, SeverityFactors(
                impact=Impact.TOTAL,
                exploitability=Exploitability.EASY,
                auth=AuthRequirement.NONE,
                exposure=Exposure.PUBLIC,
                confidence=Confidence.CONFIRMED,
                notes=["no user interaction is required beyond viewing the "
                       "affected page"],
            ))
            ctx.add_finding(finding)
            return
