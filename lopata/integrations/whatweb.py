"""whatweb / wappalyzer integration.

Feeds the technology registry rather than emitting findings. Fingerprints are
inventory: the Technology Summary section presents them, and the patch-review
logic decides whether any of them is worth reporting on.
"""

from __future__ import annotations

import json

from ..core.models import Confidence, Technology
from .base import detect, run_tool

MODULE_NAME = "whatweb"
CATEGORY = "Technology Fingerprint"

# whatweb plugin names mapped onto the categories the report groups by.
_CATEGORIES = {
    "CMS": ("wordpress", "joomla", "drupal", "typo3", "magento", "shopify",
            "ghost", "prestashop", "opencart", "umbraco", "sitecore",
            "contentful", "craftcms", "concrete5", "silverstripe"),
    "Framework": ("laravel", "symfony", "django", "rails", "ruby-on-rails",
                  "express", "spring", "asp.net", "codeigniter", "flask",
                  "next.js", "nuxt.js", "angular", "react", "vue.js", "svelte",
                  "struts", "zend", "yii", "phalcon"),
    "Web Server": ("apache", "nginx", "iis", "lighttpd", "caddy", "openresty",
                   "litespeed", "tomcat", "jetty", "gunicorn", "uwsgi"),
    "Language": ("php", "python", "ruby", "java", "perl", "asp", "node.js",
                 "jsp", "coldfusion"),
    "CDN / Proxy": ("cloudflare", "cloudfront", "akamai", "fastly", "varnish",
                    "incapsula", "sucuri", "keycdn", "stackpath", "bunnycdn"),
    "WAF": ("mod_security", "modsecurity", "cloudflare-waf", "wordfence",
            "sucuri-waf", "imperva", "barracuda", "f5-big-ip"),
    "JavaScript Library": ("jquery", "bootstrap", "modernizr", "lodash",
                           "underscore", "moment.js", "d3", "backbone",
                           "ember", "prototype", "requirejs", "handlebars"),
    "Analytics": ("google-analytics", "matomo", "piwik", "hotjar", "segment",
                  "mixpanel", "gtm", "google-tag-manager"),
}

_NOISE = {"country", "ip", "title", "http_server_header", "uncommonheaders",
          "html5", "script", "meta-author", "email", "cookies", "x-ua-compatible"}


def classify(name: str) -> str:
    key = name.strip().lower().replace(" ", "-")
    for category, members in _CATEGORIES.items():
        for member in members:
            if member in key:
                return category
    return "Other"


def available(ctx):
    info = detect(ctx, "whatweb", ("whatweb",), lambda p: [p, "--version"])
    if info.available:
        info.note = "whatweb"
        return info
    if ctx.config.get("tools", {}).get("whatweb", True):
        from .base import which
        path = which("wappalyzer")
        if path:
            info.available = True
            info.path = path
            info.note = "wappalyzer"
            ctx.tools["whatweb"] = info
    return info


def run(ctx, phase=None) -> None:
    info = available(ctx)
    if not info.available:
        return
    ctx.modules_run.append(MODULE_NAME)
    if info.note == "wappalyzer":
        entries = _run_wappalyzer(ctx, info)
    else:
        entries = _run_whatweb(ctx, info)
    phase and phase.done()

    for name, version, evidence in entries:
        if name.strip().lower() in _NOISE:
            continue
        ctx.add_technology(Technology(
            name=name.strip(), version=version.strip(),
            category=classify(name), sources=[MODULE_NAME],
            # A fingerprint is an observation about what is running; it is not
            # a claim that anything is wrong, so it never carries more than
            # medium confidence on its own.
            confidence=Confidence.MEDIUM,
            evidence=evidence[:200],
        ))


def _run_whatweb(ctx, info) -> list[tuple[str, str, str]]:
    argv = [info.path, "--log-json=-", "--no-errors", "-a",
            str(ctx.config.get("whatweb_aggression", 1)), ctx.target]
    proc = run_tool(argv, timeout=int(ctx.config.get("whatweb_timeout", 90)),
                    logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return []
    ctx.add_raw_output("whatweb", proc.stdout)

    out: list[tuple[str, str, str]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for name, meta in (obj.get("plugins") or {}).items():
            version = ""
            evidence = name
            if isinstance(meta, dict):
                versions = meta.get("version") or []
                if versions:
                    version = "/".join(str(v) for v in versions)
                strings = meta.get("string") or []
                if strings:
                    evidence = f"{name}: {'; '.join(str(s) for s in strings[:2])}"
            out.append((name, version, evidence))
    return out


def _run_wappalyzer(ctx, info) -> list[tuple[str, str, str]]:
    proc = run_tool([info.path, ctx.target], timeout=90, logger=ctx.logger)
    if proc is None or not proc.stdout.strip():
        return []
    ctx.add_raw_output("wappalyzer", proc.stdout)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    out = []
    for tech in data.get("technologies", []):
        name = tech.get("name")
        if not name:
            continue
        categories = tech.get("categories") or []
        label = categories[0].get("name", "") if categories else ""
        out.append((name, str(tech.get("version") or ""),
                    f"wappalyzer: {label}".strip(": ")))
    return out


def register():
    from ..core.plugins import integration
    return integration('whatweb', run, available, phase='recon', order=40)
