"""Honest module status for clients and the dashboard.

Statuses: operational (tested and in production), experimental (implemented and
tested here, not in production), planned (contract or design only), unavailable.
Update this file whenever a module's real state changes.
"""
from __future__ import annotations


def capabilities(reputation_provider: str, ai_available: bool, byok_allowed: bool = False) -> dict:
    reputation = {
        "none": ("unavailable", "No reputation provider configured; URL verdicts may be 'unknown'."),
        "mock": ("experimental", "MOCK fixture provider: offline test data, not live intelligence."),
    }[reputation_provider]
    return {
        "ai": {"server_key": ai_available, "byok_allowed": byok_allowed},
        "modules": [
            {"id": "threat_analysis_api", "name": "Threat analysis API (v1)", "status": "experimental",
             "detail": "Deterministic URL and message analysis. Not yet deployed to production."},
            {"id": "url_reputation", "name": "URL reputation", "status": reputation[0], "detail": reputation[1]},
            {"id": "ai_explanations", "name": "Teger Intelligence (Claude explanations)",
             "status": "experimental" if (ai_available or byok_allowed) else "unavailable",
             "detail": _ai_detail(ai_available, byok_allowed)},
            {"id": "browser_message_scan", "name": "Teger Shield: Gmail/Slack message scan", "status": "operational",
             "detail": "Chrome extension v0.2 private beta, served by the legacy backend."},
            {"id": "browser_url_protection", "name": "Teger Shield: URL blocking", "status": "planned",
             "detail": "Scheduled for milestone M2."},
            {"id": "email_protection", "name": "Teger Mail", "status": "experimental",
             "detail": "Message text analysis via the v1 API. No mailbox integration or SPF/DKIM/DMARC checks."},
            {"id": "endpoint_protection", "name": "Teger Guard (Windows)", "status": "planned",
             "detail": "Contracts only; no agent exists."},
            {"id": "mobile_protection", "name": "Teger Mobile (Android)", "status": "planned",
             "detail": "Contracts only; no app exists."},
            {"id": "device_inventory", "name": "Device inventory", "status": "unavailable",
             "detail": "Requires endpoint or mobile agents."},
            {"id": "enterprise_policy", "name": "Teger Enterprise policy distribution", "status": "planned",
             "detail": "Contract only. Tenant-scoped API keys exist."},
        ]
    }


def _ai_detail(server_key: bool, byok: bool) -> str:
    if server_key and byok:
        return "Consent-gated, explanation-only. Teger's key or bring your own Anthropic key."
    if byok:
        return "Consent-gated, explanation-only. Bring your own Anthropic key."
    if server_key:
        return "Consent-gated, explanation-only."
    return "Not configured on this server."
