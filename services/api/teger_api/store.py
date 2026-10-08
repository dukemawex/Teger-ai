"""Tenant-isolated, bounded, in-memory analysis store.

Every read is keyed by (tenant_id, analysis_id); there is no API to read across
tenants. Data is lost on restart — persistent storage is on the roadmap.
"""
from __future__ import annotations

import threading
from collections import OrderedDict

from teger_contracts import AnalysisSummary, ThreatVerdict


class AnalysisStore:
    def __init__(self, max_per_tenant: int = 500):
        self.max_per_tenant = max_per_tenant
        self._data: dict[str, OrderedDict[str, ThreatVerdict]] = {}
        self._lock = threading.Lock()

    def put(self, tenant_id: str, verdict: ThreatVerdict) -> None:
        with self._lock:
            bucket = self._data.setdefault(tenant_id, OrderedDict())
            bucket[verdict.analysis_id] = verdict
            while len(bucket) > self.max_per_tenant:
                bucket.popitem(last=False)

    def get(self, tenant_id: str, analysis_id: str) -> ThreatVerdict | None:
        with self._lock:
            return self._data.get(tenant_id, {}).get(analysis_id)

    def list(self, tenant_id: str, limit: int = 50) -> list[AnalysisSummary]:
        with self._lock:
            items = list(reversed(self._data.get(tenant_id, OrderedDict()).values()))[:limit]
        return [
            AnalysisSummary(
                analysis_id=v.analysis_id, created_at=v.created_at, verdict=v.verdict, risk_score=v.risk_score,
                recommended_action=v.recommended_action, content_type=v.content_type,
                url_host=v.url.host if v.url else None, evidence_count=len(v.evidence),
                mock_intelligence_used=v.mock_intelligence_used,
            )
            for v in items
        ]
