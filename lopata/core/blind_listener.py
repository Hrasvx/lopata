"""Built-in out-of-band listener for blind XSS.

Blind XSS fires in a context lopata never sees — an admin panel, a log viewer,
a support desk rendering attacker-controlled text hours later. The only signal
is an HTTP callback from that context. This module runs a small server that:

* mints a unique token per injection point and remembers *where* it was planted
  (which URL, form fields or header);
* records any request that arrives carrying one of those tokens, from any host;
* correlates a hit back to its injection point and, before the report is
  written, promotes the planted "lead" to a CONFIRMED finding.

It runs in a background thread alongside the scan. Because a real callback can
arrive long after the payload is planted, ``xss_blind_wait`` lets the operator
hold the scan open for a grace period before the report is finalised; anything
that arrives during the scan window is captured regardless.

Reachability is the operator's concern, as with any OOB technique: the target's
backend must be able to reach the advertised callback URL. Bind address and the
advertised URL are configured separately so the listener can sit behind a tunnel
or NAT (set ``xss_blind_callback`` to the public URL, still enable the listener).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

_GIF_1x1 = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c000000"
    "00010001000002024401003b")


@dataclass
class Hit:
    """One recorded callback."""

    token: str
    remote_addr: str
    path: str
    method: str
    user_agent: str
    at: float
    context: dict = field(default_factory=dict)


def _first_segment(path: str) -> str:
    return urlparse(path).path.strip("/").split("/")[0]


class BlindXSSListener:
    """Background HTTP server that catches and correlates blind-XSS callbacks."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0,
                 callback_base: str | None = None, logger=None) -> None:
        self._host = host
        self._port = port
        self._callback_base = callback_base
        self._logger = logger
        self._tokens: dict[str, dict] = {}
        self._hits: list[Hit] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "BlindXSSListener":
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep the scan output clean
                pass

            def _record(self):
                token = _first_segment(self.path)
                with listener._lock:
                    context = listener._tokens.get(token)
                    listener._hits.append(Hit(
                        token=token,
                        remote_addr=self.client_address[0],
                        path=self.path,
                        method=self.command,
                        user_agent=self.headers.get("User-Agent", ""),
                        at=time.time(),
                        context=dict(context) if context else {}))
                if listener._logger:
                    listener._logger.warning(
                        "blind-xss callback: token=%s from=%s %s %s",
                        token, self.client_address[0], self.command, self.path)

            def _respond(self):
                if self.path.lower().endswith((".png", ".gif", ".jpg", ".jpeg")):
                    body, ctype = _GIF_1x1, "image/gif"
                else:
                    body, ctype = b"", "application/javascript"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self):
                self._record()
                self._respond()

            def do_POST(self):
                self._record()
                self._respond()

        self._server = ThreadingHTTPServer((self._host, self._port), Handler)
        self._port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        return self._port

    @property
    def base_url(self) -> str:
        """The callback base advertised in payloads."""
        if self._callback_base:
            return self._callback_base.rstrip("/")
        host = self._host if self._host not in ("0.0.0.0", "::", "") else "127.0.0.1"
        return f"http://{host}:{self._port}"

    def register_token(self, token: str, context: dict) -> None:
        with self._lock:
            self._tokens[token] = dict(context)

    def hits(self) -> list[Hit]:
        with self._lock:
            return list(self._hits)

    def matched_hits(self) -> list[Hit]:
        """Hits whose token we planted (i.e. correlatable to an injection)."""
        with self._lock:
            return [h for h in self._hits if h.context]

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


_OWASP_REF = ("https://cheatsheetseries.owasp.org/cheatsheets/"
              "Cross_Site_Scripting_Prevention_Cheat_Sheet.html")


def correlate_hits(ctx, listener: BlindXSSListener) -> int:
    """Fold caught callbacks into ctx.findings as CONFIRMED blind XSS.

    Returns the number of confirmed findings added (deduplicated by token — the
    payload plants two beacons, script and image, so a single injection usually
    produces two hits for one token).
    """
    from .models import (AREA_WEBAPP, Confidence, Effort, Finding, FindingType,
                         Severity)
    from .severity import (AuthRequirement, Exploitability, Exposure, Impact,
                           SeverityFactors, apply)

    added = 0
    seen: set[str] = set()
    for hit in listener.matched_hits():
        if hit.token in seen:
            continue
        seen.add(hit.token)
        context = hit.context
        location = context.get("url") or ctx.target
        where = context.get("where", "an injected sink")
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(hit.at))

        finding = Finding(
            name="Blind XSS confirmed (out-of-band callback fired)",
            severity=Severity.INFO,
            location=location,
            description=(
                f"A blind-XSS payload planted in {where} executed in a context "
                f"lopata does not observe directly and called back to the "
                f"listener at {when} from {hit.remote_addr}. The callback carried "
                f"the unique token planted at this exact injection point, so the "
                "execution is reproduced, not inferred: attacker-controlled text "
                "submitted here is rendered and run somewhere a privileged user "
                "sees it (an admin, log or support view)."),
            remediation="Encode on output in the back-office view that rendered "
                        "the payload, and add a Content-Security-Policy without "
                        "'unsafe-inline'.",
            ftype=FindingType.CONFIRMED_VULN,
            module="xss", category="XSS",
            summary=f"Blind XSS in {where} fired an out-of-band callback.",
            risk="Blind XSS executes in privileged internal contexts that normal "
                 "scanning cannot reach; a fired callback proves such a context "
                 "rendered attacker input without encoding it.",
            impact="Script execution in a privileged user's session on this "
                   "origin — typically an administrator or support agent — "
                   "enabling session theft, actions as that user, and reaching "
                   "any API their session can.",
            remediation_steps=[
                "Identify the back-office view that rendered the payload (the "
                "callback's timing and the injection point below localise it).",
                f"Encode on output in that view for the context it lands in "
                f"({where} was the entry point).",
                "Add a Content-Security-Policy without 'unsafe-inline'.",
                "Audit other sinks that display the same user-supplied data.",
            ],
            verification=(f"Re-plant the payload at {location} and confirm the "
                          "listener no longer receives a callback once output is "
                          "encoded."),
            references=[_OWASP_REF],
            effort=Effort.MODERATE,
            score_area=AREA_WEBAPP,
            evidence=(f"token={hit.token} callback_from={hit.remote_addr} "
                      f"method={hit.method} path={hit.path} "
                      f"user_agent={hit.user_agent} at={when}")[:900],
            confidence=Confidence.CONFIRMED,
            verified_by="lopata's blind-XSS listener received the out-of-band "
                        "callback carrying this injection's unique token",
            sources=["xss"])
        apply(finding, SeverityFactors(
            impact=Impact.SERIOUS, exploitability=Exploitability.EASY,
            auth=AuthRequirement.NONE, exposure=Exposure.PUBLIC,
            confidence=Confidence.CONFIRMED,
            notes=["confirmed by an out-of-band callback carrying the unique "
                   "per-injection token"]))
        ctx.add_finding(finding)
        added += 1
    return added
