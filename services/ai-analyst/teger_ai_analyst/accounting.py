"""Token and cost accounting.

Prices are list prices in USD per million tokens, used only to *estimate* spend.
Reconcile against the Anthropic invoice; unknown models report no estimate.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

# model: (input, output, cache_read, cache_write_5m). Cache-write prices assume the
# standard 1.25x input multiplier for 5-minute cache writes. Only models whose full
# price list was verified are included.
PRICES_PER_MTOK: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),
    "claude-fable-5-1": (10.00, 50.00, 0.25, 12.50),
}


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int,
                      cache_read: int = 0, cache_write: int = 0) -> float | None:
    prices = PRICES_PER_MTOK.get(model)
    if prices is None:
        return None
    p_in, p_out, p_read, p_write = prices
    total = (input_tokens * p_in + output_tokens * p_out + cache_read * p_read + cache_write * p_write) / 1_000_000
    return round(total, 6)


@dataclass
class TenantUsage:
    day: str
    tokens: int = 0
    requests: int = 0
    estimated_cost_usd: float = 0.0


class UsageLedger:
    """In-process per-tenant daily usage with a hard token budget."""

    def __init__(self, daily_token_budget: int):
        self.daily_token_budget = daily_token_budget
        self._usage: dict[str, TenantUsage] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _today() -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def _get(self, tenant_id: str) -> TenantUsage:
        today = self._today()
        usage = self._usage.get(tenant_id)
        if usage is None or usage.day != today:
            usage = self._usage[tenant_id] = TenantUsage(day=today)
        return usage

    def has_budget(self, tenant_id: str) -> bool:
        with self._lock:
            return self._get(tenant_id).tokens < self.daily_token_budget

    def record(self, tenant_id: str, tokens: int, cost: float | None) -> TenantUsage:
        with self._lock:
            usage = self._get(tenant_id)
            usage.tokens += tokens
            usage.requests += 1
            usage.estimated_cost_usd += cost or 0.0
            return TenantUsage(usage.day, usage.tokens, usage.requests, round(usage.estimated_cost_usd, 6))

    def snapshot(self, tenant_id: str) -> TenantUsage:
        with self._lock:
            u = self._get(tenant_id)
            return TenantUsage(u.day, u.tokens, u.requests, round(u.estimated_cost_usd, 6))
