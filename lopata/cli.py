# lopata — CLI defensive web vulnerability scanner. Made by hrasvx.
from __future__ import annotations

import argparse
import datetime
import os
import sys
import time
import requests

from . import __version__
from .core import baseline as baseline_mod
from .core import checkpoint as ckpt
from .core import correlate as correlate_mod
from .core import scoring
from .core.config import load_config, tool_base_timeout
from .core.http import (ANON_USER_AGENT, build_session, normalize_target,
                        parse_auth_args)
from .core.logging_setup import get_logger
from .core.models import Confidence, ScanContext, Severity
from .core.retry import RetryPolicy, RetrySupervisor
from .core.timing import MODULE, TOOL, ScanEstimator, TimingHistory
from .core.tool_status import ToolStatus
from .core.ui import LopataUI
from .integrations import INTEGRATIONS, phase_of
from .modules import MODULES
from .report import (default_report_name, generate_html_report,
                     generate_report, write_json, write_sarif)

DISCLAIMER = (
    "lopata is for AUTHORIZED testing ONLY. Use it exclusively against "
    "systems you own or have explicit written permission to test. Unauthorized "
    "scanning may be illegal and unethical."
)

EPILOG = f"""\
examples:
  lopata example.com
  lopata https://example.com --json -o report.pdf
  lopata example.com --modules headers,cookies,xss --no-tools
  lopata example.com --config profile.yaml --auth-cookie "session=abc123"
  lopata example.com --resume            # continue an interrupted scan

{DISCLAIMER}
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lopata",
        description="lopata — CLI defensive web vulnerability scanner (authorized use only).",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", help="Target URL or domain (e.g. example.com).")
    p.add_argument("-o", "--output", default=None,
                   help="Report path (default: lopata_report_<target>_<ts>.<ext>). "
                        "A .html/.htm extension selects the HTML format unless "
                        "--export says otherwise.")
    p.add_argument("--export", choices=["pdf", "html"], default=None,
                   help="Report format (default: pdf). Inferred from the -o "
                        "extension when -o is given without --export; an explicit "
                        "--export always wins.")
    p.add_argument("--json", action="store_true",
                   help="Also write machine-readable JSON next to the report "
                        "(independent of --export).")
    p.add_argument("--sarif-out", default=None, metavar="PATH",
                   help="Also write a SARIF 2.1.0 log to PATH for CI / GitHub "
                        "code-scanning upload (independent of --export).")
    p.add_argument("--blind-xss-listen", action="store_true",
                   help="Start the built-in blind-XSS listener: plants unique "
                        "per-injection tokens and confirms any out-of-band "
                        "callback in the report.")
    p.add_argument("--blind-xss-callback", default=None, metavar="URL",
                   help="Advertise this callback base URL in blind-XSS payloads "
                        "(e.g. a public tunnel in front of the listener, or an "
                        "external service). Implies the listener unless the URL "
                        "is fully external.")
    p.add_argument("--blind-xss-wait", type=float, default=None, metavar="SECONDS",
                   help="Hold the scan open this long after planting to catch "
                        "late blind-XSS callbacks (default: 0).")
    p.add_argument("--modules", default=None,
                   help="Comma-separated web modules to run. "
                        f"Choices: {', '.join(MODULES)}. Default: all.")
    p.add_argument("--tools", default=None,
                   help="Comma-separated external tools to use. "
                        f"Choices: {', '.join(INTEGRATIONS)}. Default: all available.")
    p.add_argument("--no-tools", action="store_true",
                   help="Skip all external tools (web-layer modules only).")
    p.add_argument("--no-retry", action="store_true",
                   help="Do not retry tools that time out or fail — one "
                        "attempt each, the pre-1.3 behaviour. Findings left "
                        "resting on a tool that did not finish are still "
                        "capped and flagged.")
    p.add_argument("--max-tool-timeout", type=float, default=None,
                   metavar="SECONDS",
                   help="Ceiling on how large a retried tool's timeout may "
                        "grow (base_timeout * multiplier^attempts is clamped "
                        "to this).")
    p.add_argument("--config", default=None, help="YAML scan-profile path.")
    p.add_argument("--auth-header", action="append", metavar="'Name: value'",
                   help="Add a request header for authenticated scans (repeatable).")
    p.add_argument("--auth-cookie", default=None, metavar="'a=1; b=2'",
                   help="Session cookies for authenticated scans.")
    p.add_argument("--threads", type=int, default=None,
                   help="Concurrent worker threads (default: 10).")
    p.add_argument("--timeout", type=float, default=None,
                   help="Per-request timeout in seconds (default: 10).")
    p.add_argument("--max-pages", type=int, default=None,
                   help="Crawl page cap (default: 100).")
    p.add_argument("--insecure", action="store_true",
                   help="Do not verify TLS certs while crawling "
                        "(the TLS module still reports cert problems).")
    p.add_argument("--proxy", default=None, metavar="URL",
                   help="Route lopata's own HTTP(S) traffic through a proxy, "
                        "e.g. http://127.0.0.1:8080 (Burp/ZAP) or "
                        "socks5h://127.0.0.1:9050 (Tor). Omit for a direct "
                        "connection. External tools are unaffected.")
    p.add_argument("--user-agent", default=None, metavar="STRING",
                   help="Override the User-Agent sent by both HTTP layers "
                        "(default self-identifies as lopata).")
    p.add_argument("--anonymous", action="store_true",
                   help="Do not self-identify: send a generic browser "
                        "User-Agent. Requires --proxy (or proxy: in config), "
                        "since without one your real IP still leaks.")
    p.add_argument("--resume", action="store_true",
                   help="Resume from a checkpoint if one exists for this target.")
    p.add_argument("--checkpoint", default=None,
                   help="Explicit checkpoint file path.")
    p.add_argument("--logfile", default=None,
                   help="Write a detailed log to this file.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose logging.")
    p.add_argument("--min-severity", default=None,
                   choices=["info", "low", "medium", "high", "critical"],
                   help="Only report findings at or above this severity.")
    p.add_argument("--min-confidence", default=None,
                   choices=["informational", "low", "medium", "high",
                            "confirmed"],
                   help="Only report findings at or above this confidence.")
    p.add_argument("--category", default=None, metavar="NAME[,NAME...]",
                   help="Only report findings in these categories "
                        "(case-insensitive substring match).")
    p.add_argument("--only-vulns", action="store_true",
                   help="Report only confirmed and potential vulnerabilities, "
                        "omitting misconfigurations, exposures and inventory.")
    p.add_argument("--no-correlate", action="store_true",
                   help="Skip the correlation pass (keeps every raw "
                        "observation separate; useful when debugging).")
    p.add_argument("--no-ui", action="store_true",
                   help="Disable the rich live UI (plain output).")
    p.add_argument("--version", action="version", version=f"lopata {__version__}")
    return p


def _select_web_modules(requested) -> list[str]:
    if not requested:
        return list(MODULES)
    if isinstance(requested, str):
        requested = requested.split(",")
    chosen = [str(m).strip().lower() for m in requested if str(m).strip()]
    unknown = [m for m in chosen if m not in MODULES]
    if unknown:
        raise SystemExit(f"unknown module(s): {', '.join(unknown)}. "
                         f"valid: {', '.join(MODULES)}")
    if any(MODULES[m][1] for m in chosen) and "crawler" not in chosen:
        chosen.insert(0, "crawler")
    return [m for m in MODULES if m in chosen]


def _select_tools(args, cfg) -> list[str]:
    if args.no_tools:
        return []
    if args.tools:
        chosen = [t.strip().lower() for t in args.tools.split(",") if t.strip()]
        unknown = [t for t in chosen if t not in INTEGRATIONS]
        if unknown:
            raise SystemExit(f"unknown tool(s): {', '.join(unknown)}. "
                             f"valid: {', '.join(INTEGRATIONS)}")
        return [t for t in INTEGRATIONS if t in chosen]
    return list(INTEGRATIONS)



def _run_tool_phase(ctx, ui, logger, names, completed, cp_path,
                    label: str = "recon") -> None:
    """Run a set of external-tool integrations, sharing the checkpoint and UI
    bookkeeping. Used for both the recon phase (before the crawler) and the
    post-discovery phase (after the web modules), which differ only in when
    they run and what surface they consume.

    Every integration leaves a ToolRunStatus behind, whether it ran, was
    skipped, or blew up — a tool that contributes nothing must be visible as a
    gap rather than as silence.
    """
    for name in names:
        key = f"tool:{name}"
        if key in completed:
            ui.advance_overall()
            continue
        module = INTEGRATIONS[name]
        info = module.available(ctx)
        if not info.available:
            ui.note(f"{label}: {name} — skipped ({info.note or 'not available'})")
            ctx.tool_status.mark_unrun(name, info.note or "not available")
            completed.append(key)
            ckpt.save(ctx, cp_path, completed)
            ui.advance_overall()
            continue
        ph = ui.phase(f"{label}: {name}", total=1)
        ui.begin_unit(name)
        try:
            module.run(ctx, ph)
        except Exception as exc:
            logger.warning("integration '%s' failed: %s", name, exc)
            ctx.tool_status.mark(name, ToolStatus.FAILED,
                                 stderr_tail=str(exc),
                                 note=f"integration raised {exc.__class__.__name__}")
        # an integration that invoked nothing still owes the run a status
        ctx.tool_status.mark_unrun(name, "ran but had nothing to scan here")
        status = ctx.tool_status.get(name)
        ui.end_unit(name, record=bool(status and status.completed))
        ph.done()
        completed.append(key)
        ckpt.save(ctx, cp_path, completed)
        ui.advance_overall()


def _resolve_export(args) -> str:
    """Decide the report format: pdf (default) or html.

    An explicit --export always wins. Otherwise, if -o carries a recognisable
    extension we infer from it, so `-o report.html` produces HTML without a
    second flag. Anything else falls back to pdf.
    """
    if args.export:
        return args.export
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext in (".html", ".htm"):
            return "html"
        if ext == ".pdf":
            return "pdf"
    return "pdf"


def _apply_filters(ctx, args) -> int:
    """Drop findings the user asked not to see.

    Filtering happens after scoring, so hiding low-severity noise never
    flatters the score — the numbers still reflect everything that was found.
    """
    findings = ctx.findings
    keep = list(findings)

    if args.min_severity:
        floor = Severity.from_name(args.min_severity)
        keep = [f for f in keep if f.severity >= floor]
    if args.min_confidence:
        floor = Confidence[args.min_confidence.upper()]
        keep = [f for f in keep if f.confidence >= floor]
    if args.category:
        wanted = [c.strip().lower() for c in args.category.split(",") if c.strip()]
        keep = [f for f in keep
                if any(w in f.resolved_category().lower() for w in wanted)]
    if args.only_vulns:
        keep = [f for f in keep if f.is_vulnerability]

    dropped = len(findings) - len(keep)
    ctx.findings = keep
    return dropped


def run_scan(args) -> int:
    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.threads is not None:
        cfg["threads"] = args.threads
    if args.timeout is not None:
        cfg["timeout"] = args.timeout
    if args.max_pages is not None:
        cfg["max_pages"] = args.max_pages
    if args.insecure:
        cfg["verify_tls"] = False
    if args.proxy:
        cfg["proxy"] = args.proxy
    if args.user_agent:
        cfg["user_agent"] = args.user_agent
    if args.anonymous:
        if not cfg.get("proxy"):
            print("--anonymous requires --proxy (or proxy: in config): without "
                  "a proxy your real IP still reaches the target.",
                  file=sys.stderr)
            return 2
        # An explicit --user-agent wins; otherwise wera a generic browser string.
        if not cfg.get("user_agent"):
            cfg["user_agent"] = ANON_USER_AGENT
    if args.modules:
        cfg["modules"] = args.modules
    if args.blind_xss_listen:
        cfg["xss_blind_listener"] = True
    if args.blind_xss_callback:
        cfg["xss_blind_callback"] = args.blind_xss_callback
    if args.blind_xss_wait is not None:
        cfg["xss_blind_wait"] = args.blind_xss_wait

    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        print(f"invalid target: {exc}", file=sys.stderr)
        return 2

    estimator = ScanEstimator(history=TimingHistory())
    ui = LopataUI(enabled=not args.no_ui, estimator=estimator)
    ui.banner(target, __version__)
    print(f"! {DISCLAIMER}\n")

    logger = get_logger(logfile=args.logfile, verbose=args.verbose)
    notes = getattr(logger, "_note_collector", None)

    auth_headers, auth_cookies = {}, {}
    try:
        cfg_auth = cfg.get("auth", {}) or {}
        cfg_h, cfg_c = parse_auth_args(cfg_auth.get("headers"), cfg_auth.get("cookie"))
        cli_h, cli_c = parse_auth_args(args.auth_header, args.auth_cookie)
        auth_headers.update(cfg_h)
        auth_headers.update(cli_h)
        auth_cookies.update(cfg_c)
        auth_cookies.update(cli_c)
    except ValueError as exc:
        print(f"auth error: {exc}", file=sys.stderr)
        return 2

    session = build_session(
        timeout=cfg["timeout"], verify_tls=cfg["verify_tls"],
        auth_headers=auth_headers or None, auth_cookies=auth_cookies or None,
        proxy=cfg.get("proxy"), user_agent=cfg.get("user_agent"))

    ctx = ScanContext(
        target=target, session=session, config=cfg,
        threads=int(cfg["threads"]), timeout=float(cfg["timeout"]),
        max_pages=int(cfg["max_pages"]), verbose=args.verbose,
        logger=logger, ui=ui)

    try:
        session.get(target + "/", timeout=ctx.timeout)
    except requests.exceptions.SSLError as exc:
        print(f"TLS error reaching target: {exc}\n"
              "Re-run with --insecure to continue (TLS module still reports it).",
              file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"target appears unreachable: {exc}", file=sys.stderr)
        return 1

    blind_listener = None
    if cfg.get("xss_blind_listener"):
        try:
            from .core.blind_listener import BlindXSSListener
            blind_listener = BlindXSSListener(
                host=str(cfg.get("xss_blind_listen_host", "0.0.0.0")),
                port=int(cfg.get("xss_blind_listen_port", 0) or 0),
                callback_base=cfg.get("xss_blind_callback"),
                logger=logger).start()
            ctx.blind_listener = blind_listener
            ui.note(f"blind-XSS listener active; callback {blind_listener.base_url}")
        except Exception as exc:
            logger.warning("could not start blind-XSS listener: %s", exc)
            blind_listener = None

    web_modules = _select_web_modules(cfg.get("modules"))
    tools = _select_tools(args, cfg)
    recon_tools = [t for t in tools if phase_of(t) == "recon"]
    post_tools = [t for t in tools if phase_of(t) == "post"]

    cp_path = ckpt.checkpoint_path(target, args.checkpoint)
    completed: list[str] = []
    resumed_attempts: dict = {}
    if args.resume:
        completed = ckpt.load(ctx, cp_path)
        resumed_attempts = ckpt.resumed_attempts(cp_path)
        if completed:
            logger.info("resuming; %d phase(s) already done", len(completed))
        if resumed_attempts:
            logger.info("resuming mid-retry; attempts already spent: %s",
                        ", ".join(f"{t}={n}" for t, n in
                                  sorted(resumed_attempts.items())))

    # a tool switched off in the profile must not count against completeness
    cfg_tools = cfg.get("tools", {}) or {}
    expected_tools = [t for t in tools if cfg_tools.get(t, True)]
    ctx.tool_status.expect(expected_tools)

    # retry supervision wraps every external invocation
    policy = RetryPolicy.from_config(cfg, no_retry=args.no_retry,
                                     max_tool_timeout=args.max_tool_timeout)
    ctx.retry_supervisor = RetrySupervisor(
        policy, logger=logger, ui=ui, resumed_attempts=resumed_attempts)
    if policy.enabled:
        logger.info("retry: up to %d attempt(s) per tool, timeout x%.1f each",
                    policy.max_attempts, policy.timeout_multiplier)

    estimator.plan(
        [(t, TOOL, tool_base_timeout(cfg, t)) for t in recon_tools]
        + [("baseline", MODULE, 15.0)]
        + [(m, MODULE, 30.0) for m in web_modules]
        + [(t, TOOL, tool_base_timeout(cfg, t)) for t in post_tools]
        + [("correlate", MODULE, 5.0)])
    # work finished before an interruption is dropped from the estimate
    for done_key in completed:
        estimator.skip(done_key.split(":", 1)[-1])

    # tools + baseline + web modules + correlation
    phase_count = len(tools) + len(web_modules) + 2
    ui.start(phase_count)
    started = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.perf_counter()


    if recon_tools:
        ui.section("recon — external tools")
    _run_tool_phase(ctx, ui, logger, recon_tools, completed, cp_path)


    ui.section("baseline & web-layer analysis")
    bph = ui.phase("learning not-found baseline", total=1)
    ui.begin_unit("baseline")
    ctx.baseline = baseline_mod.build_baseline(ctx)
    ui.end_unit("baseline")
    bph.done()
    ui.advance_overall()
    for name in web_modules:
        key = f"mod:{name}"
        if key in completed:
            ui.advance_overall()
            continue
        module, _ = MODULES[name]
        ph = ui.phase(f"module: {name}", total=1)
        ui.begin_unit(name)
        try:
            module.run(ctx, ph)
        except Exception as exc:
            logger.warning("module '%s' failed: %s", name, exc)
            if args.verbose:
                import traceback
                logger.debug(traceback.format_exc())
        ui.end_unit(name)
        ph.done()
        completed.append(key)
        ckpt.save(ctx, cp_path, completed)
        ui.advance_overall()

    if post_tools:
        ui.section("verification — surface-aware tools")
    _run_tool_phase(ctx, ui, logger, post_tools, completed, cp_path,
                    label="verify")

    ui.begin_unit("correlate")
    if not args.no_correlate:
        cph = ui.phase("correlating findings", total=1)
        raw_count = len(ctx.findings)
        try:
            correlate_mod.correlate(ctx, logger)
        except Exception as exc:
            logger.warning("correlation failed: %s", exc)
        cph.done()
        if raw_count != len(ctx.findings):
            ui.note(f"correlation: {raw_count} observation(s) -> "
                    f"{len(ctx.findings)} finding(s)")

    # coverage capping runs even with --no-correlate
    try:
        capped = correlate_mod.apply_tool_coverage(ctx, logger=logger)
        if capped:
            ui.note(f"{capped} finding(s) capped to Low confidence — their "
                    "only evidence came from a tool that did not finish")
    except Exception as exc:
        logger.warning("tool-coverage pass failed: %s", exc)
    ui.end_unit("correlate")
    ui.advance_overall()

    if blind_listener is not None:
        try:
            wait = float(cfg.get("xss_blind_wait", 0) or 0)
            if wait > 0:
                ui.note(f"holding {wait:.0f}s for blind-XSS callbacks…")
                time.sleep(wait)
            from .core.blind_listener import correlate_hits
            confirmed = correlate_hits(ctx, blind_listener)
            total_hits = len(blind_listener.hits())
            if confirmed:
                ui.note(f"blind-XSS: {confirmed} out-of-band callback(s) "
                        "CONFIRMED and added to the report")
            elif total_hits:
                ui.note(f"blind-XSS: {total_hits} callback(s) received but none "
                        "matched a planted token")
        except Exception as exc:
            logger.warning("blind-XSS correlation failed: %s", exc)
        finally:
            blind_listener.stop()

    # tear down anything a tool spawned (e.g. a ZAP daemon we started)
    ctx.run_cleanups()

    try:
        scoring.compute(ctx)
    except Exception as exc:
        logger.warning("scoring failed: %s", exc)

    banner = (ctx.scores.get("scan_completeness") or {}).get("banner", "")
    if banner:
        logger.warning("%s", banner)
        ui.note(banner, style="yellow")

    dropped = _apply_filters(ctx, args)
    if dropped:
        ui.note(f"{dropped} finding(s) hidden by report filters")

    duration = time.perf_counter() - t0
    finished = datetime.datetime.now(datetime.timezone.utc)
    ui.stop()
    # Feed this run's real durations back for the next scan's ETA.
    estimator.save_history()


    export_fmt = _resolve_export(args)
    out = args.output or default_report_name(target, export_fmt)
    if os.path.isdir(out):
        out = os.path.join(out, default_report_name(target, export_fmt))
    parent = os.path.dirname(os.path.abspath(out))
    os.makedirs(parent, exist_ok=True)

    meta = {
        "started_at": started, "finished_at": finished,
        "duration_seconds": duration,
        "notes": notes.records if notes else [],
    }
    json_path = None
    renderer = generate_html_report if export_fmt == "html" else generate_report
    label = export_fmt.upper()
    try:
        renderer(ctx, out, meta)
    except Exception as exc:
        logger.error("failed to write %s: %s", label, exc)
        print(f"failed to write {label} report: {exc}", file=sys.stderr)
        return 1

    if args.json:
        json_path = os.path.splitext(out)[0] + ".json"
        try:
            write_json(ctx, json_path, meta, __version__)
        except Exception as exc:
            logger.error("failed to write JSON: %s", exc)
            json_path = None

    if args.sarif_out:
        sarif_path = args.sarif_out
        parent = os.path.dirname(os.path.abspath(sarif_path))
        os.makedirs(parent, exist_ok=True)
        try:
            write_sarif(ctx, sarif_path, meta, __version__)
            ui.note(f"SARIF written to {os.path.abspath(sarif_path)}")
        except Exception as exc:
            logger.error("failed to write SARIF: %s", exc)

    ui.final_summary(ctx.findings, duration, os.path.abspath(out),
                     os.path.abspath(json_path) if json_path else None,
                     ctx.scores)

    ckpt.clear(cp_path)
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        print("\ninterrupted — checkpoint saved; re-run with --resume.",
              file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
