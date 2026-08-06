from __future__ import annotations

import logging
from datetime import datetime, timezone


class NoteCollector(logging.Handler):

    def __init__(self) -> None:
        super().__init__()
        self.records: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        })


def get_logger(logfile: str | None = None, verbose: bool = False,
               quiet_console: bool = True) -> logging.Logger:
    logger = logging.getLogger("lopata")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else
                     (logging.WARNING if quiet_console else logging.INFO))
    console.setFormatter(fmt)
    logger.addHandler(console)

    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        logger.addHandler(fh)

    notes = NoteCollector()
    notes.setLevel(logging.DEBUG)
    logger.addHandler(notes)
    logger._note_collector = notes
    return logger
