from __future__ import annotations

import re

from ..core.models import Confidence, Finding, Severity

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

    for form in post_forms:
        _check_form(ctx, form)
        phase and phase.step()
    phase and phase.done()


def _check_form(ctx, form) -> None:
    inputs = form.get("inputs", [])
    names = [i.get("name", "") for i in inputs]
    has_token_field = any(_TOKEN_HINTS.search(n or "") for n in names)
    has_hidden_tokenish = any(
        i.get("type") == "hidden" and _looks_like_token(i.get("value", ""))
        for i in inputs
    )


    if has_token_field or has_hidden_tokenish:
        return

    action = form.get("action", form.get("page", ctx.target))
    is_auth_like = any(k in " ".join(names).lower()
                       for k in ("password", "email", "amount", "delete",
                                 "update", "transfer", "role"))
    severity = Severity.MEDIUM if is_auth_like else Severity.LOW
    ctx.add_finding(Finding(
        name="Form without anti-CSRF token",
        severity=severity, location=action,
        description=(
            "A POST form on this page has no detectable anti-CSRF token field. "
            "If the endpoint relies on cookies for auth and doesn't otherwise "
            "verify request origin, it may be forgeable cross-site."
        ),
        remediation="Include a per-session, unpredictable CSRF token in every "
                    "state-changing form and verify it server-side; set session "
                    "cookies SameSite=Lax/Strict as defence in depth.",
        module=MODULE_NAME, category=CATEGORY,
        evidence=f"fields: {', '.join(n for n in names if n)[:200]}",
        request=f"form action={action} method=post",
        confidence=Confidence.FIRM))


def _looks_like_token(value: str) -> bool:
    return len(value) >= 16 and bool(re.search(r"[A-Za-z0-9_\-]{16,}", value))
