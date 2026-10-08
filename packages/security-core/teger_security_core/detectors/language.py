"""Deterministic language detectors for credential harvesting and social engineering.

Rules are regular expressions mapped to the shared tactic taxonomy in
``dataset/taxonomy.py``. Each produces a redacted excerpt so the user can see exactly
what triggered it. Extends the v0.2 signals in ``backend/signals.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from teger_contracts import Severity

from ..redaction import excerpt
from .base import AnalysisSubject, DetectorOutcome, Finding, FindingCollector


@dataclass(frozen=True)
class Rule:
    category: str
    tactic: str
    severity: Severity
    description: str
    pattern: re.Pattern[str]


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


CREDENTIAL_RULES: tuple[Rule, ...] = (
    Rule("secret_phrase_request", "credential_harvesting", Severity.CRITICAL,
         "Asks for a wallet seed / recovery phrase or private key, which no legitimate service requests.",
         _rx(r"\b(seed|recovery|secret|mnemonic)\s+(phrase|words)\b|\bprivate\s+key\b")),
    Rule("credential_request", "credential_harvesting", Severity.HIGH,
         "Asks the recipient to send or confirm a password, PIN or one-time code.",
         _rx(r"\b(send|share|provide|confirm|reply with|give|tell|enter|read)\b[^.\n]{0,40}"
             r"\b(password|passcode|pin|otp|one[- ]time (?:code|password)|verification code|"
             r"security code|2fa code|mfa code|login credentials?)\b")),
    Rule("account_verification_lure", "credential_harvesting", Severity.MEDIUM,
         "Pushes the recipient to log in or 'verify' an account through a link.",
         _rx(r"\b(verify|validate|confirm|re-?activate|unlock|update)\s+(your\s+)?"
             r"(account|identity|login|credentials|mailbox|billing (?:info|information|details))\b|"
             r"\b(log ?in|sign ?in)\s+(here|below|now|to (?:verify|confirm|restore|avoid))\b")),
    Rule("mfa_fatigue", "credential_harvesting", Severity.HIGH,
         "Asks the recipient to approve a sign-in prompt they did not start.",
         _rx(r"\b(approve|accept|tap yes on)\b[^.\n]{0,30}\b(sign-?in|login|push|mfa|authenticator)\b")),
)

SOCIAL_RULES: tuple[Rule, ...] = (
    Rule("urgent_language", "artificial_urgency", Severity.MEDIUM,
         "Creates time pressure to rush a decision.",
         _rx(r"\b(urgent(ly)?|immediately|right now|asap|within \d+ (?:minutes?|hours?)|final (?:notice|warning)|"
             r"act now|expires? (?:today|tonight|in \d+)|last chance|before end of day)\b")),
    Rule("consequence_threat", "consequence_threat", Severity.MEDIUM,
         "Threatens account loss, penalties or legal action to coerce compliance.",
         _rx(r"\b(account|mailbox|access)\s+(will be|has been|is)\s+(suspended|locked|closed|terminated|deleted|"
             r"disabled|deactivated)|\b(legal action|arrest|penalt(?:y|ies)|fined?|lawsuit|prosecut\w*)\b")),
    Rule("gift_card_request", "payment_redirection", Severity.HIGH,
         "Requests gift cards or their codes, a hallmark of executive-impersonation scams.",
         _rx(r"\bgift\s?cards?\b|\b(itunes|google play|steam|amazon)\s+cards?\b")),
    Rule("payment_change_request", "payment_redirection", Severity.HIGH,
         "Announces changed bank details or asks to pay a new account.",
         _rx(r"\b(new|updated|changed?|different)\s+(bank|banking|account|wire|payment)\s+"
             r"(details?|information|info|instructions|account)\b|\bbank(?:ing)? details have changed\b")),
    Rule("financial_request", "payment_redirection", Severity.MEDIUM,
         "Requests a payment, transfer or crypto transaction.",
         _rx(r"\b(wire transfer|bank transfer|send (?:money|funds|payment)|outstanding invoice|"
             r"pay(?:ment)? (?:now|immediately|today)|bitcoin|btc|usdt|crypto(?:currency)? wallet)\b")),
    Rule("authority_claim", "authority_spoofing", Severity.LOW,
         "Invokes an executive, IT, bank or government authority.",
         _rx(r"\b(ceo|cfo|chief executive|managing director|finance director|it (?:helpdesk|support|department)|"
             r"system administrator|tax (?:office|authority)|irs|hmrc|police|federal|government)\b")),
    Rule("secrecy_or_bypass", "pretexting", Severity.MEDIUM,
         "Asks for secrecy or to bypass normal verification and approval.",
         _rx(r"\b(keep (?:this|it) (?:between us|confidential|quiet)|do not (?:tell|call|discuss)|don'?t (?:tell|call)|"
             r"bypass|skip (?:the )?(?:approval|process|verification)|i'?m in a meeting|can'?t talk)\b")),
    Rule("reward_bait", "reciprocity_bait", Severity.MEDIUM,
         "Offers an unexpected prize, refund or windfall.",
         _rx(r"\b(you(?:'ve| have)? won|winner|lottery|prize|inheritance|unclaimed (?:funds|refund)|"
             r"refund of|cash reward|claim your (?:reward|prize|refund))\b")),
    Rule("emotional_pressure", "emotional_anchoring", Severity.LOW,
         "Uses fear, sympathy or embarrassment to short-circuit judgment.",
         _rx(r"\b(i'?m (?:stuck|stranded)|emergency|please help me|i'?m begging|embarrassing|compromising "
             r"(?:video|photos?)|we have (?:your|recorded))\b")),
    Rule("attachment_lure", "attachment_lure", Severity.MEDIUM,
         "Pressures the recipient to open an attachment or enable document content.",
         _rx(r"\b(enable (?:macros|content|editing)|open the attached|see (?:the )?attached (?:invoice|document|file|"
             r"payment)|download the (?:attached|invoice|document))\b")),
    Rule("ai_instruction_injection", "context_injection", Severity.HIGH,
         "Contains instructions aimed at an AI assistant reading the message.",
         _rx(r"\b(ignore (?:all |any )?(?:previous|prior|above) instructions|disregard (?:the|your) "
             r"(?:system|previous) (?:prompt|instructions)|you are (?:now )?an? (?:ai|assistant|language model)|"
             r"system prompt|(?:mark|classify|label) this (?:email|message) as (?:safe|legitimate|benign))\b")),
)


def _apply(rules: tuple[Rule, ...], text: str, collector: FindingCollector) -> None:
    for rule in rules:
        match = rule.pattern.search(text)
        if match:
            collector.add(Finding(
                rule.category, rule.severity, rule.description,
                excerpt(text, match.start(), match.end()), rule.tactic,
            ))


class CredentialHarvestingDetector:
    name = "credential_harvesting"
    version = "1.0.0"

    def is_required(self, subject: AnalysisSubject) -> bool:
        return bool(subject.text)

    def run(self, subject: AnalysisSubject) -> DetectorOutcome:
        collector = FindingCollector()
        _apply(CREDENTIAL_RULES, subject.text, collector)
        return collector.outcome()


class SocialEngineeringDetector:
    name = "social_engineering"
    version = "1.0.0"

    def is_required(self, subject: AnalysisSubject) -> bool:
        return bool(subject.text)

    def run(self, subject: AnalysisSubject) -> DetectorOutcome:
        collector = FindingCollector()
        _apply(SOCIAL_RULES, subject.text, collector)
        return collector.outcome()
