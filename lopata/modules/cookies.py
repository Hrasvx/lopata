"""Cookie attribute audit.

Cookies are graded by what they appear to be for: a missing HttpOnly on a
session cookie is a different problem from the same gap on a UI preference
cookie, and reporting them at the same severity trains readers to ignore both.
All gaps on one cookie are reported as a single finding, since they share one
fix at one line of code.
"""

from __future__ import annotations

import requests

from ..core.models import (AREA_HTTP, Confidence, Effort, Finding, FindingType,
                           PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "cookies"
CATEGORY = "Cookies"

_SESSION_HINTS = ("sess", "sid", "auth", "token", "login", "jwt", "remember",
                  "identity", "csrf")


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException:
        return
    phase and phase.done()

    is_https = ctx.target.startswith("https")
    raw = (resp.raw.headers.getlist("Set-Cookie")
           if hasattr(resp.raw, "headers") else [])
    if not raw:
        combined = resp.headers.get("Set-Cookie")
        raw = [combined] if combined else []

    if not raw:
        return

    seen = set()
    clean = []
    for line in raw:
        name = line.split("=", 1)[0].strip()
        if not name or name in seen:
            continue
        seen.add(name)
        if not _audit(ctx, name, _parse_attrs(line), is_https, resp.url, line):
            clean.append(name)

    if clean:
        ctx.add_passed(PassedCheck(
            name=f"{len(clean)} cookie(s) carry correct security attributes",
            detail="Secure, HttpOnly and SameSite are set as appropriate on: "
                   + ", ".join(clean),
            source=MODULE_NAME, location=resp.url, score_area=AREA_HTTP))


def _parse_attrs(set_cookie: str) -> dict:
    attrs = {"secure": False, "httponly": False, "samesite": None}
    for part in [p.strip() for p in set_cookie.split(";")[1:]]:
        low = part.lower()
        if low == "secure":
            attrs["secure"] = True
        elif low == "httponly":
            attrs["httponly"] = True
        elif low.startswith("samesite"):
            attrs["samesite"] = (part.split("=", 1)[1].strip().lower()
                                 if "=" in part else "")
    return attrs


def _audit(ctx, name, attrs, is_https, url, raw_line) -> bool:
    """Report every attribute gap on this cookie as one finding. Returns True
    if anything was reported."""
    session_like = any(hint in name.lower() for hint in _SESSION_HINTS)
    problems: list[str] = []
    steps: list[str] = []
    impacts: list[str] = []

    if is_https and not attrs["secure"]:
        problems.append("`Secure` is missing, so the browser will send this "
                        "cookie over a plaintext HTTP connection")
        steps.append("Add the `Secure` attribute — mandatory for any cookie on "
                     "an HTTPS site.")
        impacts.append("an attacker who can trigger a single http:// request to "
                       "the domain (an image tag is enough) captures the cookie "
                       "in cleartext")

    if not attrs["httponly"]:
        problems.append("`HttpOnly` is missing, so any JavaScript running on "
                        "the page can read the cookie value")
        steps.append("Add `HttpOnly` unless client-side script genuinely needs "
                     "to read this cookie.")
        impacts.append("any XSS flaw anywhere on the origin escalates directly "
                       "to session theft, and the theft is silent")

    samesite = attrs["samesite"]
    if samesite in (None, ""):
        problems.append("`SameSite` is not set, so the cookie is attached to "
                        "cross-site requests")
        steps.append("Set `SameSite=Lax` (or `Strict` for purely first-party "
                     "sessions).")
        impacts.append("cross-site requests carry the user's session, which is "
                       "the precondition for CSRF")
    elif samesite == "none" and not attrs["secure"]:
        problems.append("`SameSite=None` is set without `Secure`, a combination "
                        "browsers reject outright")
        steps.append("Add `Secure` whenever `SameSite=None` is used, or the "
                     "cookie will simply be dropped.")
        impacts.append("the cookie is discarded by current browsers, which "
                       "usually breaks the feature it was added for")

    if not problems:
        return False

    if session_like:
        impact_level = Impact.SERIOUS
        role = ("This cookie's name suggests it carries authentication or "
                "session state, which is what makes the gap material.")
    else:
        impact_level = Impact.INFORMATION
        role = ("This cookie does not appear to carry session state, so the "
                "practical impact is limited — but the attributes cost nothing "
                "to add and prevent it from becoming a problem later.")

    finding = Finding(
        name=f"Cookie '{name}' missing security attributes "
             f"({len(problems)} issue(s))",
        severity=Severity.INFO, location=url,
        description=(
            f"The cookie `{name}` is set without protective attributes:\n\n"
            + "\n".join(f"  • {p}." for p in problems)
            + "\n\n" + role
        ),
        remediation=steps[0],
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{name}: " + ", ".join(
            p.split("`")[1] for p in problems if "`" in p) + " not set.",
        risk="Cookie attributes are the browser-side controls that keep a "
             "session token confined to the context it was issued for. "
             + role,
        impact="If exploited, " + "; ".join(impacts) + ".",
        remediation_steps=steps + [
            "Set the attributes where the cookie is issued (framework session "
            "config is usually the single right place), not per-response.",
            "Consider a `__Host-` name prefix, which browsers enforce as "
            "Secure, path=/ and host-only.",
        ],
        verification=f"`curl -sI <url> | grep -i 'set-cookie: {name}'` should "
                     "show every required attribute on the same line.",
        references=[
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
            "https://owasp.org/www-community/controls/SecureCookieAttribute",
        ],
        effort=Effort.TRIVIAL,
        score_area=AREA_HTTP,
        evidence=_redact(raw_line),
        verified_by="lopata read the Set-Cookie header from the live response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact_level,
        exploitability=Exploitability.DIFFICULT,
        auth=AuthRequirement.USER,
        exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
        notes=["the attribute gap is directly observed; exploiting it requires "
               "a second flaw (XSS, or a network position)"],
    ))
    ctx.add_finding(finding)
    return True


def _redact(set_cookie: str) -> str:
    """Never print a live session value into a report."""
    if "=" not in set_cookie:
        return set_cookie[:120]
    name, rest = set_cookie.split("=", 1)
    attrs = ";".join(rest.split(";")[1:])
    return f"{name}=<redacted>;{attrs}"[:200]
