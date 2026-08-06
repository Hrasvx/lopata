from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urljoin

import requests


_NORMALIZE = [
    (re.compile(r"[0-9a-f]{16,}", re.I), "HEX"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?\b"), "TS"),
    (re.compile(r"csrf[_-]?token[\"'=:\s]+[\w\-\.]+", re.I), "CSRF"),
    (re.compile(r"nonce=[\"']?[\w\-]+", re.I), "NONCE"),
    (re.compile(r"\d+"), "N"),
    (re.compile(r"\s+"), " "),
]


def normalize_body(text: str, cap: int = 20000) -> str:
    text = text[:cap]
    for pattern, repl in _NORMALIZE:
        text = pattern.sub(repl, text)
    return text.strip()


def content_hash(text: str) -> str:
    return hashlib.sha256(normalize_body(text).encode("utf-8", "replace")).hexdigest()


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, normalize_body(a), normalize_body(b)).ratio()


@dataclass
class ResponseSnapshot:

    status: int
    length: int
    body: str
    hashed: str

    @classmethod
    def capture(cls, resp: requests.Response) -> "ResponseSnapshot":
        body = resp.text or ""
        return cls(
            status=resp.status_code,
            length=len(resp.content or b""),
            body=body,
            hashed=content_hash(body),
        )


@dataclass
class Baseline:

    not_found: ResponseSnapshot | None = None
    root: ResponseSnapshot | None = None
    threshold: float = 0.92

    def looks_like_not_found(self, snap: ResponseSnapshot) -> bool:
        nf = self.not_found
        if nf is None:
            return False
        if snap.status == nf.status and snap.hashed == nf.hashed:
            return True

        if snap.status == nf.status and similarity(snap.body, nf.body) >= self.threshold:
            return True
        return False


def build_baseline(ctx) -> Baseline:
    session, timeout = ctx.session, ctx.timeout
    bl = Baseline(threshold=float(ctx.config.get("baseline_threshold", 0.92)))
    probe = urljoin(ctx.target + "/", "lopata-nonexistent-a9f3c1e7b2/")
    try:
        r = session.get(probe, timeout=timeout, allow_redirects=False)
        bl.not_found = ResponseSnapshot.capture(r)
    except requests.RequestException:
        pass
    try:
        r = session.get(ctx.target + "/", timeout=timeout)
        bl.root = ResponseSnapshot.capture(r)
    except requests.RequestException:
        pass
    return bl


def differs_from_all(candidate: str, references: list[str], max_similarity: float = 0.98) -> bool:
    for ref in references:
        if similarity(candidate, ref) >= max_similarity:
            return False
    return True
