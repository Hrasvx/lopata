from __future__ import annotations

import re

from ..core.models import (AREA_WEBAPP, Confidence, Effort, Finding,
                           FindingType, PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "csrf"
CATEGORY = "CSRF"

_TOKEN_HINTS = re.compile(
    r"csrf|xsrf|authenticity_token|__requestverificationtoken|nonce|_token",
    re.I,
)


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    post_forms = [f for f in ctx.forms if f.get("method") == "post"]
    if phase:
        phase.set_total(max(len(post_forms), 1))

    protected = 0
    for form in post_forms:
        if not _check_form(ctx, form):
            protected += 1
        phase and phase.step()
    phase and phase.done()

    if protected:
        ctx.add_passed(PassedCheck(
            name=f"{protected} of {len(post_forms)} POST form(s) carry an "
                 "anti-CSRF token",
            detail="A token-shaped hidden field was present in the form markup.",
            source=MODULE_NAME, location=ctx.target, score_area=AREA_WEBAPP))


def _check_form(ctx, form) -> bool:
    """Returns True if a finding was raised for this form."""
    inputs = form.get("inputs", [])
    names = [i.get("name", "") for i in inputs]
    has_token_field = any(_TOKEN_HINTS.search(n or "") for n in names)
    has_hidden_tokenish = any(
        i.get("type") == "hidden" and _looks_like_token(i.get("value", ""))
        for i in inputs
    )


    if has_token_field or has_hidden_tokenish:
        return False

    action = form.get("action", form.get("page", ctx.target))
    sensitive = [k for k in ("password", "email", "amount", "delete", "update",
                             "transfer", "role", "admin", "token")
                 if k in " ".join(names).lower()]

    finding = Finding(
        name="POST form without an anti-CSRF token",
        severity=Severity.INFO, location=action,
        description=(
            "This POST form contains no field that looks like an anti-CSRF "
            "token, and no hidden field carrying a token-shaped value.\n\n"
            "This is a markup observation, not a proven vulnerability: the "
            "endpoint may verify the Origin/Referer header, may require a "
            "custom header that cross-site form posts cannot set, or may not "
            "rely on cookie authentication at all. Any of those defences would "
            "make it safe, and none of them is visible in the HTML."
            + (f"\n\nThe field names ({', '.join(sensitive)}) suggest this form "
               "performs a sensitive action, which is why it is worth checking "
               "by hand." if sensitive else "")
        ),
        remediation="Issue a per-session CSRF token in the form and verify it "
                    "server-side on every state-changing request.",
        ftype=FindingType.POTENTIAL_VULN,
        module=MODULE_NAME, category=CATEGORY,
        summary="No anti-CSRF token field is present in this POST form.",
        risk=(
            "If the endpoint authenticates with cookies alone and does not "
            "check request origin, any website the victim visits can submit "
            "this form on their behalf — the browser attaches the session "
            "cookie automatically."
        ),
        impact=(
            "State changes performed as the victim without their knowledge: "
            + (", ".join(sensitive) + " operations in this case."
               if sensitive else
               "whatever action this form performs.")
            + " CSRF requires no flaw in the victim's browser and leaves no "
              "trace distinguishable from a legitimate request in most logs."
        ),
        remediation_steps=[
            "Use the framework's built-in CSRF protection rather than a custom "
            "implementation — most already ship one that is off by default.",
            "Emit a per-session, unpredictable token as a hidden field and "
            "reject any POST whose token is missing or wrong.",
            "Set session cookies `SameSite=Lax` as defence in depth; it blocks "
            "the cross-site POST outright in current browsers.",
            "Verify the Origin header server-side for state-changing requests.",
        ],
        verification=(
            "Build a minimal HTML page on another origin that auto-submits this "
            "form, visit it while logged in, and confirm the server rejects the "
            "request."
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        effort=Effort.MODERATE,
        score_area=AREA_WEBAPP,
        evidence=f"form action={action} method=post; fields: "
                 + ", ".join(n for n in names if n)[:200],
        request=f"POST {action}",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.LIMITED if sensitive else Impact.INFORMATION,
        exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.USER,
        exposure=Exposure.PUBLIC,
        # Absence of a token in markup is observed; that the endpoint is
        # actually forgeable is not.
        confidence=Confidence.MEDIUM,
        notes=["based on form markup only — server-side origin checks would "
               "not be visible to this test"],
    ))
    ctx.add_finding(finding)
    return True


def _looks_like_token(value: str) -> bool:
    return len(value) >= 16 and bool(re.search(r"[A-Za-z0-9_\-]{16,}", value))


def register():
    from ..core.plugins import web_module
    return web_module('csrf', run, requires_crawl=True, order=100)
