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
from .core.config import load_config
from .core.http import build_session, normalize_target, parse_auth_args
from .core.logging_setup import get_logger
from .core.models import ScanContext
from .core.ui import LopataUI
from .integrations import INTEGRATIONS
from .modules import MODULES
from .report import default_report_name, generate_report, write_json

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
                   help="PDF report path (default: lopata_report_<target>_<ts>.pdf).")
    p.add_argument("--json", action="store_true",
                   help="Also write machine-readable JSON next to the PDF.")
    p.add_argument("--modules", default=None,
                   help="Comma-separated web modules to run. "
                        f"Choices: {', '.join(MODULES)}. Default: all.")
    p.add_argument("--tools", default=None,
                   help="Comma-separated external tools to use. "
                        f"Choices: {', '.join(INTEGRATIONS)}. Default: all available.")
    p.add_argument("--no-tools", action="store_true",
                   help="Skip all external tools (web-layer modules only).")
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
    p.add_argument("--resume", action="store_true",
                   help="Resume from a checkpoint if one exists for this target.")
    p.add_argument("--checkpoint", default=None,
                   help="Explicit checkpoint file path.")
    p.add_argument("--logfile", default=None,
                   help="Write a detailed log to this file.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose logging.")
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
    if args.modules:
        cfg["modules"] = args.modules

    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        print(f"invalid target: {exc}", file=sys.stderr)
        return 2

    ui = LopataUI(enabled=not args.no_ui)
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
        auth_headers=auth_headers or None, auth_cookies=auth_cookies or None)

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

    web_modules = _select_web_modules(cfg.get("modules"))
    tools = _select_tools(args, cfg)

    cp_path = ckpt.checkpoint_path(target, args.checkpoint)
    completed: list[str] = []
    if args.resume:
        completed = ckpt.load(ctx, cp_path)
        if completed:
            logger.info("resuming; %d phase(s) already done", len(completed))

    phase_count = len(tools) + len(web_modules) + 1
    ui.start(phase_count)
    started = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.perf_counter()


    if tools:
        ui.section("recon — external tools")
    for name in tools:
        key = f"tool:{name}"
        if key in completed:
            ui.advance_overall()
            continue
        module = INTEGRATIONS[name]
        ph = ui.phase(f"recon: {name}", total=1)
        try:
            module.run(ctx, ph)
        except Exception as exc:
            logger.warning("integration '%s' failed: %s", name, exc)
        ph.done()
        completed.append(key)
        ckpt.save(ctx, cp_path, completed)
        ui.advance_overall()


    ui.section("baseline & web-layer analysis")
    bph = ui.phase("learning not-found baseline", total=1)
    ctx.baseline = baseline_mod.build_baseline(ctx)
    bph.done()
    ui.advance_overall()
    for name in web_modules:
        key = f"mod:{name}"
        if key in completed:
            ui.advance_overall()
            continue
        module, _ = MODULES[name]
        ph = ui.phase(f"module: {name}", total=1)
        try:
            module.run(ctx, ph)
        except Exception as exc:
            logger.warning("module '%s' failed: %s", name, exc)
            if args.verbose:
                import traceback
                logger.debug(traceback.format_exc())
        ph.done()
        completed.append(key)
        ckpt.save(ctx, cp_path, completed)
        ui.advance_overall()

    duration = time.perf_counter() - t0
    finished = datetime.datetime.now(datetime.timezone.utc)
    ui.stop()


    out = args.output or default_report_name(target)
    if os.path.isdir(out):
        out = os.path.join(out, default_report_name(target))
    parent = os.path.dirname(os.path.abspath(out))
    os.makedirs(parent, exist_ok=True)

    meta = {
        "started_at": started, "finished_at": finished,
        "duration_seconds": duration,
        "notes": notes.records if notes else [],
    }
    json_path = None
    try:
        generate_report(ctx, out, meta)
    except Exception as exc:
        logger.error("failed to write PDF: %s", exc)
        print(f"failed to write PDF report: {exc}", file=sys.stderr)
        return 1

    if args.json:
        json_path = os.path.splitext(out)[0] + ".json"
        try:
            write_json(ctx, json_path, meta, __version__)
        except Exception as exc:
            logger.error("failed to write JSON: %s", exc)
            json_path = None

    ui.final_summary(ctx.findings, duration, os.path.abspath(out),
                     os.path.abspath(json_path) if json_path else None)

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
