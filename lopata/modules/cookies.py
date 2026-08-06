from __future__ import annotations

import requests

from ..core.models import Confidence, Finding, Severity

MODULE_NAME = "cookies"
CATEGORY = "Cookies"


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException:
        return
    phase and phase.done()

    is_https = ctx.target.startswith("https")
    raw = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
    if not raw:

        combined = resp.headers.get("Set-Cookie")
        raw = [combined] if combined else []

    seen = set()
    for line in raw:
        name = line.split("=", 1)[0].strip()
        if name in seen:
            continue
        seen.add(name)
        attrs = _parse_attrs(line)
        _audit(ctx, name, attrs, is_https, resp.url, line)


def _parse_attrs(set_cookie: str) -> dict:
    attrs = {"secure": False, "httponly": False, "samesite": None}
    parts = [p.strip() for p in set_cookie.split(";")[1:]]
    for p in parts:
        low = p.lower()
        if low == "secure":
            attrs["secure"] = True
        elif low == "httponly":
            attrs["httponly"] = True
        elif low.startswith("samesite"):
            attrs["samesite"] = p.split("=", 1)[1].strip().lower() if "=" in p else ""
    return attrs


def _audit(ctx, name, attrs, is_https, url, raw_line) -> None:
    session_like = any(k in name.lower() for k in
                       ("sess", "sid", "auth", "token", "login", "jwt"))
    base_sev = Severity.MEDIUM if session_like else Severity.LOW

    if is_https and not attrs["secure"]:
        ctx.add_finding(Finding(
            name=f"Cookie '{name}' missing Secure",
            severity=base_sev, location=url,
            description="Cookie set over HTTPS without the Secure flag can be "
                        "sent over plaintext HTTP and intercepted.",
            remediation="Add the Secure attribute to all cookies on HTTPS sites.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=_redact(raw_line), confidence=Confidence.FIRM))

    if not attrs["httponly"]:
        ctx.add_finding(Finding(
            name=f"Cookie '{name}' missing HttpOnly",
            severity=base_sev, location=url,
            description="Without HttpOnly the cookie is readable by JavaScript, "
                        "so an XSS flaw can steal it.",
            remediation="Add HttpOnly to cookies that need not be read by JS "
                        "(session/auth cookies especially).",
            module=MODULE_NAME, category=CATEGORY,
            evidence=_redact(raw_line), confidence=Confidence.FIRM))

    if attrs["samesite"] in (None, ""):
        ctx.add_finding(Finding(
            name=f"Cookie '{name}' missing SameSite",
            severity=Severity.LOW, location=url,
            description="No SameSite attribute; the cookie is sent on cross-site "
                        "requests, enabling CSRF.",
            remediation="Set SameSite=Lax (or Strict) unless cross-site use is "
                        "required (then SameSite=None; Secure).",
            module=MODULE_NAME, category=CATEGORY,
            evidence=_redact(raw_line), confidence=Confidence.FIRM))
    elif attrs["samesite"] == "none" and not attrs["secure"]:
        ctx.add_finding(Finding(
            name=f"Cookie '{name}' SameSite=None without Secure",
            severity=Severity.MEDIUM, location=url,
            description="SameSite=None requires Secure; without it browsers "
                        "reject the cookie and cross-site protection is lost.",
            remediation="Add Secure whenever using SameSite=None.",
            module=MODULE_NAME, category=CATEGORY,
            evidence=_redact(raw_line), confidence=Confidence.FIRM))


def _redact(set_cookie: str) -> str:
    if "=" not in set_cookie:
        return set_cookie[:120]
    name, rest = set_cookie.split("=", 1)
    attrs = ";".join(rest.split(";")[1:])
    return f"{name}=<redacted>;{attrs}"[:200]
