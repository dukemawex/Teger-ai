"""Sliding-window rate limiter.

In-process only: limits are per worker and reset on restart. Replace with a shared
store (e.g. Redis) before running more than one instance.
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 50_000, clock=time.monotonic):
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        with self._lock:
            if len(self._hits) >= self.max_keys:
                self._prune(now)
            window = self._hits.setdefault(key, deque())
            while window and now - window[0] >= self.window:
                window.popleft()
            if len(window) >= self.limit:
                return False, max(1, math.ceil(self.window - (now - window[0])))
            window.append(now)
            return True, 0

    def _prune(self, now: float) -> None:
        for key in [k for k, w in self._hits.items() if not w or now - w[-1] >= self.window]:
            del self._hits[key]
