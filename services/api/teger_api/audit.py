"""Structured audit logging.

Events are JSON lines on the ``teger.audit`` logger. They carry identifiers, tenant,
outcome and verdict metadata only — never submitted content, URLs' paths/queries,
sender addresses, or credentials.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone

_SAFE_SCALARS = (str, int, float, bool, type(None))

logger = logging.getLogger("teger.audit")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


def configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False


class AuditLog:
    def __init__(self, per_tenant_buffer: int = 200):
        self._buffers: dict[str, deque[dict]] = {}
        self._size = per_tenant_buffer
        self._lock = threading.Lock()

    def emit(self, event: str, *, request_id: str, outcome: str, tenant_id: str | None = None,
             key_id: str | None = None, **details) -> dict:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "outcome": outcome,
            "request_id": request_id,
            "tenant_id": tenant_id,
            "key_id": key_id,
            # Only flat, scalar details are allowed to keep accidental content out.
            "details": {k: v for k, v in details.items() if isinstance(v, _SAFE_SCALARS)},
        }
        logger.info(json.dumps(record, sort_keys=True))
        if tenant_id:
            with self._lock:
                self._buffers.setdefault(tenant_id, deque(maxlen=self._size)).appendleft(record)
        return record

    def recent(self, tenant_id: str, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self._buffers.get(tenant_id, ()))[:limit]
