"""Optional headless verification of XSS payloads.

This is what separates "the payload is reflected unencoded" (strong evidence,
but still an inference) from "the payload executed" (reproduction). Only the
latter earns Confirmed in lopata's confidence model, mirroring the bar the SQLi
module clears with its error/boolean/time oracles.

Playwright + a Chromium build are optional: if either is missing, ``available``
returns False and the XSS engine simply reports at High confidence instead of
Confirmed. Nothing here ever raises into the caller.

Authenticated verification: the browser context is seeded with the main
scanner's session — the cookies from ``--auth-cookie`` / config auth *and*
anything captured while crawling — bridged into a Playwright ``storage_state``.
A ``storage_state.json`` (from ``playwright codegen`` or a prior login) can be
imported on top, and the effective state exported for reuse. Without this,
DOM/stored-XSS checks would run logged-out and miss sinks that only render for
authenticated users.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

_CHECKED = False
_AVAILABLE = False

_VALID_SAMESITE = {"Strict", "Lax", "None"}


def available() -> bool:
    """True only if Playwright and a usable browser are actually installed."""
    global _CHECKED, _AVAILABLE
    if _CHECKED:
        return _AVAILABLE
    _CHECKED = True
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        _AVAILABLE = False
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        _AVAILABLE = True
    except Exception:
        _AVAILABLE = False
    return _AVAILABLE



def _samesite(cookie) -> str:
    rest = getattr(cookie, "_rest", None) or {}
    raw = ""
    for key, value in rest.items():
        if str(key).lower() == "samesite":
            raw = str(value or "")
            break
    normalized = raw.capitalize() if raw else ""
    if normalized == "None":
        normalized = "None"
    return normalized if normalized in _VALID_SAMESITE else "Lax"


def _to_pw_cookie(cookie, default_domain: str) -> dict | None:
    if not cookie.name:
        return None
    domain = cookie.domain or default_domain
    if not domain:
        return None
    secure = bool(cookie.secure)
    same_site = _samesite(cookie)
    if same_site == "None" and not secure:
        same_site = "Lax"
    pw = {
        "name": cookie.name,
        "value": cookie.value or "",
        "domain": domain,
        "path": cookie.path or "/",
        "secure": secure,
        "httpOnly": bool(cookie.has_nonstandard_attr("HttpOnly")),
        "sameSite": same_site,
    }
    if cookie.expires:
        pw["expires"] = int(cookie.expires)
    return pw


def build_storage_state(cookies, target_url: str,
                        storage_state_path: str | None = None) -> dict:
    """Merge an imported storage_state.json with the live session cookies.

    ``cookies`` is a ``requests`` cookie jar. Cookies with no domain of their
    own (the common case for ``--auth-cookie``) inherit the target host. Live
    session cookies win over imported ones on a (name, domain, path) clash,
    since they reflect the current authenticated run.
    """
    state: dict = {"cookies": [], "origins": []}
    if storage_state_path:
        try:
            with open(storage_state_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                state["cookies"] = list(loaded.get("cookies", []) or [])
                state["origins"] = list(loaded.get("origins", []) or [])
        except Exception:
            pass

    default_domain = (urlparse(target_url).hostname or "")
    index = {(c.get("name"), c.get("domain"), c.get("path", "/")): i
             for i, c in enumerate(state["cookies"])}
    for cookie in (cookies or []):
        pw = _to_pw_cookie(cookie, default_domain)
        if pw is None:
            continue
        key = (pw["name"], pw["domain"], pw["path"])
        if key in index:
            state["cookies"][index[key]] = pw
        else:
            index[key] = len(state["cookies"])
            state["cookies"].append(pw)
    return state


def export_storage_state(state: dict, path: str) -> bool:
    """Write a storage_state dict to ``path`` for reuse on a later run."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state or {"cookies": [], "origins": []}, fh, indent=2)
        return True
    except Exception:
        return False



def verify_execution(url: str, token: str, timeout: float = 8.0,
                     insecure: bool = False, storage_state: dict | None = None
                     ) -> bool:
    """Navigate to ``url`` and return True iff our payload actually ran.

    The payload is built to signal execution two ways — an ``alert(token)`` we
    catch via the dialog handler, and a ``window.__lopata_xss = token`` we read
    back — so it works whether it landed in HTML, an attribute, or a script
    context. ``storage_state`` (from :func:`build_storage_state`) seeds the
    context with the scanner's authenticated cookies.
    """
    if not available():
        return False
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except Exception:
        return False

    fired = {"hit": False}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True,
                                         args=["--no-sandbox"])
            try:
                context = browser.new_context(
                    ignore_https_errors=insecure,
                    storage_state=storage_state or None)
            except Exception:
                context = browser.new_context(ignore_https_errors=insecure)
            page = context.new_page()

            def on_dialog(dialog):
                if token in (dialog.message or ""):
                    fired["hit"] = True
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", on_dialog)
            try:
                page.goto(url, timeout=int(timeout * 1000),
                          wait_until="load")
                page.wait_for_timeout(600)
                if not fired["hit"]:
                    val = page.evaluate("window.__lopata_xss || ''")
                    if val and token in str(val):
                        fired["hit"] = True
            except PWTimeout:
                pass
            except Exception:
                pass
            finally:
                context.close()
                browser.close()
    except Exception:
        return False
    return fired["hit"]
