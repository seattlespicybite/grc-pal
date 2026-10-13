"""Structured logging and request tracing.

Every request gets a request ID (an incoming X-Request-ID is reused when well formed, so a
front door or load balancer can correlate). The ID is echoed in the response header, written
to every log line and audit record, and shown on error pages so a user can quote it.
Logs go to stdout as one JSON object per line, which Azure Container Apps ships to Log
Analytics (or any log collector) without parsing rules.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import sys
import time
import uuid

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
current_actor: contextvars.ContextVar[str] = contextvars.ContextVar("current_actor", default="-")
_INCOMING_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
log = logging.getLogger("grcpal")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id.get(),
            "actor": current_actor.get(),
            "tenant": os.getenv("GRCPAL_TENANT", "default"),
        }
        for key, value in getattr(record, "fields", {}).items():
            entry[key] = value
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging() -> None:
    root = logging.getLogger("grcpal")
    if any(getattr(h, "_grcpal", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if os.getenv("GRCPAL_LOG_FORMAT", "json") == "json"
                         else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler._grcpal = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(os.getenv("GRCPAL_LOG_LEVEL", "INFO").upper())
    root.propagate = False


def new_request_id(incoming: str | None) -> str:
    return incoming if incoming and _INCOMING_ID.match(incoming) else uuid.uuid4().hex[:16]


def event(msg: str, level: int = logging.INFO, **fields) -> None:
    log.log(level, msg, extra={"fields": fields})
