import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from signals import extract_signals  # noqa: E402


def test_extracts_urgency_authority_and_financial_signals():
    signals = extract_signals(
        "I am the CFO. Urgent: buy gift cards immediately and send the codes.",
        "Gmail",
    )

    assert "authority_claim" in signals
    assert "urgent_language" in signals
    assert "financial_request" in signals


def test_flags_suspicious_url_shape():
    signals = extract_signals(
        "Verify your account now: https://accounts-login-secure.example.com/verify",
        "Email",
    )

    assert "contains_url" in signals
    assert "suspicious_url_shape" in signals


def test_benign_message_has_no_obvious_signal():
    signals = extract_signals(
        "Thanks for the meeting notes. I will review them tomorrow.",
        "Email",
    )

    assert signals == []
