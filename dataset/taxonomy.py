"""Shared taxonomy of social-engineering tactics.

This is the single vocabulary used by BOTH the open dataset and the analyzer, so a
detected tactic maps directly to documented patterns. Names are stable slugs; add
new tactics here and nowhere else.
"""
from __future__ import annotations

TACTICS: dict[str, str] = {
    "artificial_urgency": "Manufactured time pressure to force a fast, unconsidered action.",
    "authority_spoofing": "Impersonating a trusted authority (IT, bank, executive, government).",
    "emotional_anchoring": "Exploiting fear, greed, curiosity, or sympathy to bypass judgment.",
    "pretexting": "A fabricated backstory that makes the request seem legitimate.",
    "credential_harvesting": "Driving the target to enter credentials on an attacker surface.",
    "payment_redirection": "Redirecting a payment/invoice to an attacker-controlled account.",
    "reciprocity_bait": "Offering a fake favor/reward to create a sense of obligation.",
    "trust_transfer": "Riding on a known brand, contact, or prior thread to borrow trust.",
    "consequence_threat": "Threatening account loss, fines, or exposure to coerce action.",
    "attachment_lure": "Weaponized attachment framed as an invoice, resume, or document.",
    "link_manipulation": "Disguised or look-alike links (homoglyphs, subdomains, shorteners).",
    "context_injection": "Text crafted to be absorbed by an AI assistant reading the message.",
}

SEVERITY = ("low", "medium", "high", "critical")
SOURCE_TYPES = ("email", "sms", "chat", "web", "voice", "synthetic")


def is_valid_tactic(slug: str) -> bool:
    return slug in TACTICS
