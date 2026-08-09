"""HTTP response security headers.

Each header gets a full write-up rather than a one-liner, because "add a CSP"
is not actionable advice. Headers that are present and well-configured are
recorded as passed checks so the report shows what was verified, not only what
was missing.
"""

from __future__ import annotations

import re

import requests

from ..core.models import (AREA_HTTP, AREA_TLS, Confidence, Effort, Finding,
                           FindingType, PassedCheck, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "headers"
CATEGORY = "Security Headers"


class _Check:

    __slots__ = ("header", "title", "impact", "exploit", "risk", "consequence",
                 "steps", "verify", "refs", "https_only", "effort")

    def __init__(self, header, title, impact, exploit, risk, consequence,
                 steps, verify, refs=(), https_only=False,
                 effort=Effort.TRIVIAL):
        self.header = header
        self.title = title
        self.impact = impact
        self.exploit = exploit
        self.risk = risk
        self.consequence = consequence
        self.steps = list(steps)
        self.verify = verify
        self.refs = list(refs)
        self.https_only = https_only
        self.effort = effort


CHECKS = [
    _Check(
        "content-security-policy", "Content-Security-Policy",
        Impact.LIMITED, Exploitability.MODERATE,
        "Without a Content-Security-Policy the browser will execute any script "
        "that appears in the page, from any origin. CSP is the control that "
        "turns an HTML-injection bug from a full account takeover into a "
        "blocked console message — it is the difference between a Critical XSS "
        "and a Low one.",
        "Any injection flaw anywhere in the application — including in a "
        "third-party script you do not control — escalates to full execution in "
        "the user's session: session token theft, silent form submission, and "
        "credential capture through injected UI.",
        ["Start in report-only mode: `Content-Security-Policy-Report-Only: "
         "default-src 'self'; report-uri /csp-report` and collect violations "
         "for a week.",
         "Move inline scripts into files, or attach a per-response nonce "
         "(`script-src 'nonce-<random>'`).",
         "Enforce with `default-src 'self'; object-src 'none'; base-uri 'none'; "
         "frame-ancestors 'none'`.",
         "Never add 'unsafe-inline' or 'unsafe-eval' to script-src — they "
         "disable the protection you are adding."],
        "`curl -sI <url> | grep -i content-security-policy` should return the "
        "policy, and the browser console should show no CSP violations during "
        "normal use.",
        ["https://developer.mozilla.org/docs/Web/HTTP/CSP",
         "https://csp-evaluator.withgoogle.com/"],
        effort=Effort.MODERATE,
    ),
    _Check(
        "strict-transport-security", "Strict-Transport-Security",
        Impact.LIMITED, Exploitability.DIFFICULT,
        "The site is served over HTTPS but does not tell browsers to insist on "
        "it. A user's first request — typed into the address bar, or following "
        "an http:// link — travels in cleartext and can be intercepted before "
        "any redirect happens.",
        "An attacker on the same network (public Wi-Fi, a compromised router) "
        "can strip TLS from that first request, proxy the session in cleartext "
        "and capture credentials and session cookies without any browser "
        "warning.",
        ["Confirm HTTPS works correctly on every hostname, including "
         "subdomains, before enabling this.",
         "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
         "on all HTTPS responses.",
         "Once verified stable, add `preload` and submit the domain at "
         "hstspreload.org so browsers enforce it on the very first visit."],
        "`curl -sI https://<host>/ | grep -i strict-transport` should show a "
        "max-age of at least 31536000.",
        ["https://hstspreload.org/"],
        https_only=True,
    ),
    _Check(
        "x-content-type-options", "X-Content-Type-Options",
        Impact.INFORMATION, Exploitability.MODERATE,
        "Browsers are free to ignore the declared Content-Type and guess based "
        "on the bytes they receive.",
        "A file uploaded as a harmless type — an image, a text file — can be "
        "sniffed as HTML or JavaScript and executed in the site's origin, "
        "turning any upload feature into stored XSS.",
        ["Send `X-Content-Type-Options: nosniff` on every response.",
         "Serve user-uploaded content from a separate origin with an explicit "
         "`Content-Disposition: attachment` where practical."],
        "`curl -sI <url> | grep -i x-content-type-options` should return "
        "`nosniff`.",
        [],
    ),
    _Check(
        "referrer-policy", "Referrer-Policy",
        Impact.INFORMATION, Exploitability.DIFFICULT,
        "Without an explicit policy, browsers send the full URL of the current "
        "page to every third party the page links to or loads a resource from.",
        "Session identifiers, password-reset tokens, internal object IDs and "
        "search terms embedded in URLs leak to analytics providers, ad "
        "networks and any external site a user clicks through to.",
        ["Send `Referrer-Policy: strict-origin-when-cross-origin` as a baseline.",
         "Use `no-referrer` on pages whose URLs contain tokens.",
         "Separately: stop putting secrets in URLs — they are logged by "
         "proxies, browsers and your own web server."],
        "`curl -sI <url> | grep -i referrer-policy` should return the policy.",
        [],
    ),
    _Check(
        "permissions-policy", "Permissions-Policy",
        Impact.INFORMATION, Exploitability.DIFFICULT,
        "Powerful browser features — camera, microphone, geolocation, payment "
        "APIs — are not explicitly denied, so any script running on the page, "
        "including embedded third-party code, may request them.",
        "A compromised third-party script or an injected iframe can prompt for "
        "device access under this site's identity, which users are far more "
        "likely to grant than they would for an unknown origin.",
        ["Send `Permissions-Policy: geolocation=(), camera=(), microphone=(), "
         "payment=(), usb=()`, then re-enable only what the application uses.",
         "Constrain embedded iframes further with the `allow` attribute."],
        "`curl -sI <url> | grep -i permissions-policy` should return the policy.",
        [],
    ),
    _Check(
        "cross-origin-opener-policy", "Cross-Origin-Opener-Policy",
        Impact.INFORMATION, Exploitability.DIFFICULT,
        "Pages opened by, or opening, this document share a browsing context "
        "group, which keeps cross-origin window references alive.",
        "Cross-window scripting attacks (tabnabbing, and reference-based "
        "probing of window.opener) remain possible, and the page cannot be "
        "cross-origin isolated.",
        ["Send `Cross-Origin-Opener-Policy: same-origin`.",
         "Use `same-origin-allow-popups` only if the app depends on popup "
         "callbacks such as OAuth flows."],
        "In devtools, `crossOriginIsolated` and the response headers should "
        "reflect the policy.",
        [],
    ),
    _Check(
        "cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy",
        Impact.INFORMATION, Exploitability.THEORETICAL,
        "The document does not require embedded resources to opt in to being "
        "loaded cross-origin.",
        "The page cannot be cross-origin isolated, which leaves it exposed to "
        "speculative-execution side-channel reads of cross-origin data and "
        "blocks access to high-resolution timers and SharedArrayBuffer.",
        ["Send `Cross-Origin-Embedder-Policy: require-corp` (or "
         "`credentialless`).",
         "Ensure every cross-origin resource the page loads sends "
         "`Cross-Origin-Resource-Policy: cross-origin`, or it will be blocked.",
         "Roll this out with COOP together — isolation requires both."],
        "`self.crossOriginIsolated` should evaluate to true in the page console.",
        [],
        effort=Effort.MODERATE,
    ),
]

_CORP = _Check(
    "cross-origin-resource-policy", "Cross-Origin-Resource-Policy",
    Impact.INFORMATION, Exploitability.THEORETICAL,
    "Responses do not declare who may embed them as a subresource.",
    "Other origins can pull this content into their own pages, which enables "
    "side-channel leaks of response contents in browsers without full site "
    "isolation.",
    ["Send `Cross-Origin-Resource-Policy: same-origin` on responses that are "
     "not meant to be embedded elsewhere.",
     "Use `cross-origin` explicitly for assets that must be shared, such as a "
     "public CDN."],
    "`curl -sI <url> | grep -i cross-origin-resource-policy`.",
    [],
)


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    try:
        resp = ctx.session.get(ctx.target + "/", timeout=ctx.timeout)
    except requests.RequestException as exc:
        ctx.logger and ctx.logger.warning("headers: request failed: %s", exc)
        return
    phase and phase.done()

    present = {k.lower(): v for k, v in resp.headers.items()}
    is_https = ctx.target.startswith("https")
    if not is_https:
        _plaintext_http(ctx, resp.url)

    checks = list(CHECKS)
    # CORP only makes sense to demand once the site is isolating itself.
    if "cross-origin-embedder-policy" in present:
        checks.append(_CORP)

    for check in checks:
        if check.https_only and not is_https:
            continue
        value = present.get(check.header)
        if value is None:
            _missing(ctx, check, resp.url)
        else:
            ctx.add_passed(PassedCheck(
                name=f"{check.title} is set",
                detail=f"{check.title}: {value[:160]}",
                source=MODULE_NAME, location=resp.url, score_area=AREA_HTTP))
            _quality(ctx, check, value, resp.url)

    _info_leak_headers(ctx, present, resp.url)


def _plaintext_http(ctx, url: str) -> None:
    """No TLS at all.

    Lives here rather than in the TLS integration because it requires no
    external tool — a plaintext target must still be reported when the scan
    runs with --no-tools.
    """
    finding = Finding(
        name="Site served over plaintext HTTP",
        severity=Severity.INFO, location=url,
        description=(
            "The target was reached over HTTP with no transport encryption. "
            "Every request and response — credentials, session cookies, form "
            "contents, personal data — travels in cleartext and can be read or "
            "silently modified by anything on the network path.\n\n"
            "No amount of application-level hardening compensates for this: the "
            "security headers, cookie flags and CSRF tokens elsewhere in this "
            "report all assume the connection itself cannot be read."
        ),
        remediation="Obtain a certificate and serve the site over HTTPS only.",
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category="TLS/SSL",
        summary="No transport encryption is in use.",
        risk="Without TLS there is no confidentiality, no integrity and no "
             "authentication of the server. A shared network, a compromised "
             "router or a hostile ISP can read every session and inject "
             "content into responses.",
        impact="Session hijacking and credential theft by any party on the "
               "network path, and injection of arbitrary content into pages "
               "the user believes came from you. Browsers additionally mark "
               "the site Not Secure, and several web APIs refuse to run.",
        remediation_steps=[
            "Obtain a certificate — Let's Encrypt issues them free and certbot "
            "automates renewal.",
            "Serve the application on 443 with TLS 1.2 and 1.3 only.",
            "Redirect all HTTP traffic to HTTPS with a permanent redirect.",
            "Add `Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains` once HTTPS is confirmed working everywhere.",
            "Update hard-coded http:// URLs in the application so the redirect "
            "is a safety net rather than the normal path.",
        ],
        verification="`curl -I http://<host>/` should return a 301 to the "
                     "https URL, and `openssl s_client -connect <host>:443` "
                     "should complete a handshake.",
        references=["https://letsencrypt.org/getting-started/"],
        effort=Effort.EASY,
        score_area=AREA_TLS,
        evidence=f"scanned over plaintext HTTP: {url}",
        verified_by="lopata completed the request over an unencrypted connection",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.SERIOUS, exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.CONFIRMED,
        notes=["exploitation requires a position on the network path between "
               "the user and the server"],
    ))
    ctx.add_finding(finding)


def _missing(ctx, check: _Check, url: str) -> None:
    finding = Finding(
        name=f"Missing security header: {check.title}",
        severity=Severity.INFO, location=url,
        description=check.risk,
        remediation=check.steps[0],
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{check.title} is absent from responses.",
        risk=check.risk,
        impact=check.consequence,
        remediation_steps=check.steps,
        verification=check.verify,
        references=check.refs,
        effort=check.effort,
        score_area=AREA_HTTP,
        evidence=f"{check.header} not present in the response to GET {url}",
        verified_by="lopata inspected the response headers directly",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=check.impact, exploitability=check.exploit,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
        notes=["a missing hardening header is a defence-in-depth gap, not an "
               "exploitable flaw on its own"],
    ))
    ctx.add_finding(finding)


_HSTS_MAXAGE = re.compile(r"max-age\s*=\s*(\d+)")


def _quality(ctx, check: _Check, value: str, url: str) -> None:
    low = value.lower()

    if check.header == "strict-transport-security":
        match = _HSTS_MAXAGE.search(low)
        age = int(match.group(1)) if match else 0
        problems = []
        if age < 15552000:
            problems.append(f"max-age is {age}s (under the 180-day minimum "
                            "browsers require for preloading)")
        if "includesubdomains" not in low:
            problems.append("includeSubDomains is absent, so subdomains stay "
                            "downgradeable")
        if problems:
            _weak(ctx, "Weak HSTS policy", url, value,
                  "; ".join(problems),
                  "Set `Strict-Transport-Security: max-age=31536000; "
                  "includeSubDomains` and consider adding `preload`.",
                  ["Raise max-age to 31536000 (one year).",
                   "Add includeSubDomains once every subdomain serves HTTPS.",
                   "Submit to hstspreload.org after verifying stability."],
                  Impact.INFORMATION, check)

    elif check.header == "content-security-policy":
        problems = []
        if "unsafe-inline" in low and "script-src" in low:
            problems.append("'unsafe-inline' in script-src permits injected "
                            "inline scripts, which is precisely what CSP exists "
                            "to stop")
        if "unsafe-eval" in low:
            problems.append("'unsafe-eval' allows string-to-code evaluation")
        if re.search(r"(default-src|script-src)[^;]*\*(?!\.)", low):
            problems.append("a wildcard source allows scripts from any origin")
        if "object-src" not in low and "default-src 'none'" not in low:
            problems.append("object-src is not restricted, leaving plugin "
                            "content as a bypass route")
        if problems:
            _weak(ctx, "Weak Content-Security-Policy", url, value,
                  "; ".join(problems),
                  "Remove unsafe-* keywords and wildcards; use nonces or hashes "
                  "for the inline scripts you genuinely need.",
                  ["Enumerate inline scripts and give each a per-response nonce.",
                   "Delete 'unsafe-inline' and 'unsafe-eval' from script-src.",
                   "Add `object-src 'none'` and `base-uri 'none'`.",
                   "Validate the result with Google's CSP Evaluator."],
                  Impact.LIMITED, check)

    elif check.header == "x-content-type-options":
        if "nosniff" not in low:
            _weak(ctx, "Ineffective X-Content-Type-Options value", url, value,
                  f"the only meaningful value is `nosniff`; {value!r} is ignored",
                  "Set the header to exactly `nosniff`.",
                  ["Set `X-Content-Type-Options: nosniff`."],
                  Impact.INFORMATION, check)

    elif check.header == "referrer-policy":
        if low.strip() in ("unsafe-url", "no-referrer-when-downgrade", ""):
            _weak(ctx, "Permissive Referrer-Policy", url, value,
                  f"{value!r} still sends full URLs to third parties",
                  "Use `strict-origin-when-cross-origin` or stricter.",
                  ["Set `Referrer-Policy: strict-origin-when-cross-origin`."],
                  Impact.INFORMATION, check)


def _weak(ctx, name, url, value, problem, remediation, steps, impact, check) -> None:
    finding = Finding(
        name=name, severity=Severity.INFO, location=url,
        description=(
            f"The header is present but weakened: {problem}.\n\n"
            f"Observed value: {value[:300]}"
        ),
        remediation=remediation,
        ftype=FindingType.MISCONFIGURATION,
        module=MODULE_NAME, category=CATEGORY,
        summary=problem[:180],
        risk=f"The control is configured in a way that substantially reduces "
             f"its effect. {check.risk}",
        impact=check.consequence,
        remediation_steps=steps,
        verification=check.verify,
        references=check.refs,
        effort=check.effort,
        score_area=AREA_HTTP,
        evidence=f"{check.header}: {value}"[:400],
        verified_by="lopata parsed the header value from the live response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=impact, exploitability=check.exploit,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
    ))
    ctx.add_finding(finding)


_LEAKY = {
    "server": ("Server", "the web server software and often its exact version"),
    "x-powered-by": ("X-Powered-By", "the backend runtime and version"),
    "x-aspnet-version": ("X-AspNet-Version", "the exact ASP.NET version"),
    "x-aspnetmvc-version": ("X-AspNetMvc-Version", "the exact ASP.NET MVC version"),
    "x-generator": ("X-Generator", "the CMS and usually its version"),
    "x-drupal-cache": ("X-Drupal-Cache", "that the site runs Drupal"),
    "x-runtime": ("X-Runtime", "backend processing time, useful for timing attacks"),
}

_VERSIONED = re.compile(r"\d+\.\d+")


def _info_leak_headers(ctx, present, url) -> None:
    leaks = [(title, present[header], what)
             for header, (title, what) in _LEAKY.items()
             if header in present and present[header].strip()]
    if not leaks:
        ctx.add_passed(PassedCheck(
            name="No version-disclosing response headers",
            detail="Server, X-Powered-By and related banners are absent or generic.",
            source=MODULE_NAME, location=url, score_area=AREA_HTTP))
        return

    detail = "\n".join(f"  {title}: {value}" for title, value, _ in leaks)
    precise = [t for t, v, _ in leaks if _VERSIONED.search(v)]

    finding = Finding(
        name="Software version disclosure in response headers",
        severity=Severity.INFO, location=url,
        description=(
            "The server volunteers details about the software behind it:\n\n"
            + detail + "\n\n"
            + (f"{len(precise)} of these include a precise version number, which "
               "is what makes the disclosure useful to an attacker: it turns "
               "'try every exploit' into 'try the two that apply'."
               if precise else
               "No exact versions are exposed, which limits the value of this "
               "to an attacker.")
        ),
        remediation="Suppress or genericise version-bearing response headers.",
        ftype=FindingType.INFORMATIONAL,
        module=MODULE_NAME, category="Information Disclosure",
        summary=f"{len(leaks)} response header(s) disclose software details.",
        risk="Version banners let an attacker check exploit applicability "
             "offline, without generating requests that your monitoring could "
             "detect.",
        impact="No direct compromise. It shortens reconnaissance and makes the "
               "host a more attractive target for opportunistic scanning.",
        remediation_steps=[
            "Apache: `ServerTokens Prod` and `ServerSignature Off`.",
            "nginx: `server_tokens off;`.",
            "PHP: `expose_php = Off` in php.ini.",
            "Remove X-Powered-By and X-Generator at the reverse proxy "
            "(`proxy_hide_header` / `Header unset`).",
        ],
        verification="`curl -sI <url>` should show a bare product name at most, "
                     "with no version and no X-Powered-By.",
        effort=Effort.TRIVIAL,
        score_area=AREA_HTTP,
        evidence=detail[:400],
        verified_by="lopata read the headers from the live response",
        sources=[MODULE_NAME],
    )
    apply(finding, SeverityFactors(
        impact=Impact.INFORMATION,
        exploitability=Exploitability.NONE,
        auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
        confidence=Confidence.HIGH,
    ))
    ctx.add_finding(finding)


def register():
    from ..core.plugins import web_module
    return web_module('headers', run, requires_crawl=False, order=30)
