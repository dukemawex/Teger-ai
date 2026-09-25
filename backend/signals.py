import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

SIGNAL_PATTERNS = {
    "urgent_language": re.compile(
        r"\b(urgent|immediately|right now|within \d+ (?:minutes?|hours?)|final notice|act now)\b",
        re.IGNORECASE,
    ),
    "credential_request": re.compile(
        r"\b(password|passcode|otp|one[- ]time code|verification code|login credentials?|security code)\b",
        re.IGNORECASE,
    ),
    "financial_request": re.compile(
        r"\b(gift cards?|wire transfer|bank details?|payment|invoice|send (?:money|funds)|crypto|bitcoin)\b",
        re.IGNORECASE,
    ),
    "authority_claim": re.compile(
        r"\b(ceo|cfo|chief executive|finance director|hr|it helpdesk|administrator|bank|government|tax office)\b",
        re.IGNORECASE,
    ),
    "secrecy_or_bypass": re.compile(
        r"\b(confidential|do not tell|keep this between us|bypass|skip approval|don't call|do not call)\b",
        re.IGNORECASE,
    ),
}


def extract_signals(content: str, context: str = "") -> list[str]:
    text = f"{context}\n{content}"
    signals = [name for name, pattern in SIGNAL_PATTERNS.items() if pattern.search(text)]

    urls = URL_RE.findall(content)
    if urls:
        signals.append("contains_url")
        suspicious_domains = []
        for url in urls[:10]:
            host = (urlparse(url).hostname or "").lower()
            if host and (
                host.count("-") >= 2
                or host.count(".") >= 3
                or any(token in host for token in ("verify", "secure", "login", "account"))
            ):
                suspicious_domains.append(host)
        if suspicious_domains:
            signals.append("suspicious_url_shape")

    return sorted(set(signals))
