"""Output plumbing: JSON vs human renderings, and a log filter that cannot leak secrets.

Every free-text string the CLI prints passes through the domain redactor. That is a
deliberate belt-and-braces control: layers are supposed to redact before persistence, and
this catches anything that slips through before it reaches a terminal or a CI log.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from ..domain.redaction import PLACEHOLDER, redact

LOG_FORMAT = "%(levelname)s %(name)s: %(message)s"


class RedactingFilter(logging.Filter):
    """Log filter that replaces detected secrets with the redaction placeholder."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Drop non-JSON records and redact secrets before a handler sees them."""
        if isinstance(record.msg, str) and PLACEHOLDER not in record.msg:
            # redact() is a no-op when nothing is detected, so one pass is enough.
            record.msg = redact(record.msg).text
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (redact(v).text if isinstance(v, str) else v) for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    redact(a).text if isinstance(a, str) else a for a in record.args
                )
        return True


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts the fully interpolated message."""

    def format(self, record: logging.LogRecord) -> str:
        """Render the record and return it with any secret material removed."""
        rendered = super().format(record)
        return redact(rendered).text


def configure_logging(level: str, *, stream: Any = None) -> logging.Logger:
    """Configure the ``openmedic`` logger on stderr with secret redaction enabled."""
    logger = logging.getLogger("openmedic")
    logger.setLevel(getattr(logging, level.upper(), logging.WARNING))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(RedactingFormatter(LOG_FORMAT))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    return logger


class Output:
    """Renderer that switches between machine-readable JSON and human text."""

    def __init__(self, *, json_mode: bool = False, color: bool = True, stream: Any = None) -> None:
        self.json_mode = json_mode
        self.color = color
        self._stream = stream if stream is not None else sys.stdout

    def emit(self, human: str, payload: dict[str, object] | None = None) -> None:
        """Write either the human rendering or the JSON payload.

        In JSON mode **only** the payload is written, so stdout stays machine-parseable.
        Human diagnostics belong on stderr.
        """
        if self.json_mode:
            if payload is None:
                payload = {"message": human}
            self._stream.write(json.dumps(payload, indent=2, sort_keys=False, default=str) + "\n")
        else:
            self._stream.write(human if human.endswith("\n") else human + "\n")
        self._stream.flush()

    def error(self, message: str, payload: dict[str, object] | None = None) -> None:
        """Write to stderr so an error never pollutes a machine-readable stdout."""
        text = (
            message
            if self.json_mode or not payload
            else f"{message}\n{json.dumps(payload, indent=2, default=str)}"
        )
        if self.json_mode and payload is None:
            text = json.dumps({"error": message}, indent=2, default=str)
        sys.stderr.write(text + "\n")
        sys.stderr.flush()


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences so output is plain ASCII when color is disabled."""
    import re

    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
