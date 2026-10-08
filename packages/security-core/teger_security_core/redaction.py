"""Sensitive-data redaction.

Applied to evidence excerpts and to any content sent to a cloud AI provider. Email
local-parts are redacted but domains are kept, because the sending domain is often the
key phishing evidence. Redaction is best-effort pattern matching, not a DLP guarantee.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _iban_ok(candidate: str) -> bool:
    rearranged = candidate[4:] + candidate[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}")
_API_KEY = re.compile(
    r"\b(?:sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}|tgr_[A-Za-z0-9]{8,}_[A-Za-z0-9_-]{16,})"
)
_SECRET_WORDS = r"(?i)\b(password|passwd|pwd|passcode|pin|secret|api[_ -]?key|token)"
_SECRET_ASSIGNMENT = re.compile(_SECRET_WORDS + r"(\s*[:=]\s*)((?!\[REDACTED)[^\s,;]{3,})")
# After "is", only redact values that look secret-like (contain a digit or symbol) so
# prose such as "your password is required" survives as evidence.
_SECRET_IS = re.compile(_SECRET_WORDS + r"(\s+is\s+)((?=[^\s,;]*[\d!@#$%^&*])[^\s,;]{3,})")
_SECRET_QUERY = re.compile(
    r"(?i)([?&](?:token|access_token|id_token|key|api_key|code|session|sid|auth|password|pwd|sig)=)[^&#\s]+"
)
_OTP = re.compile(r"(?i)\b((?:code|otp|pin|passcode|verification)\D{0,20}?)(\d{4,8})\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_US_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE = re.compile(r"(?<![\w/])\+?\d[\d\s().-]{7,}\d(?![\w/])")


def redact(text: str) -> RedactionResult:
    if not text:
        return RedactionResult(text or "", {})
    counts: Counter[str] = Counter()

    def sub(pattern: re.Pattern[str], label: str, replacement, value: str) -> str:
        def _repl(match: re.Match[str]) -> str:
            out = replacement(match) if callable(replacement) else replacement
            if out != match.group(0):
                counts[label] += 1
            return out

        return pattern.sub(_repl, value)

    out = text
    out = sub(_PRIVATE_KEY, "private_key", "[REDACTED_PRIVATE_KEY]", out)
    out = sub(_JWT, "token", "[REDACTED_TOKEN]", out)
    out = sub(_BEARER, "token", lambda m: f"{m.group(1)} [REDACTED_TOKEN]", out)
    out = sub(_API_KEY, "api_key", "[REDACTED_API_KEY]", out)
    out = sub(_SECRET_QUERY, "url_secret", lambda m: f"{m.group(1)}[REDACTED]", out)
    for pattern in (_SECRET_ASSIGNMENT, _SECRET_IS):
        out = sub(pattern, "secret", lambda m: f"{m.group(1)}{m.group(2)}[REDACTED_SECRET]", out)
    out = sub(_EMAIL, "email", lambda m: f"[REDACTED]@{m.group(1)}", out)
    out = sub(
        _IBAN, "iban",
        lambda m: "[REDACTED_IBAN]" if _iban_ok(m.group(0).replace(" ", "")) else m.group(0),
        out,
    )

    def _card(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return "[REDACTED_CARD]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else match.group(0)

    out = sub(_CARD, "card", _card, out)
    out = sub(_US_SSN, "national_id", "[REDACTED_ID]", out)
    out = sub(_OTP, "otp", lambda m: f"{m.group(1)}[REDACTED_CODE]", out)

    def _phone(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return "[REDACTED_PHONE]" if 9 <= len(digits) <= 15 else match.group(0)

    out = sub(_PHONE, "phone", _phone, out)
    return RedactionResult(out, dict(counts))


def excerpt(text: str, start: int, end: int, radius: int = 40, max_len: int = 160) -> str:
    """Return a redacted, single-line excerpt around ``text[start:end]``."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = " ".join(text[lo:hi].split())
    snippet = redact(snippet).text
    if len(snippet) > max_len:
        snippet = snippet[: max_len - 1] + "…"
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) and not snippet.endswith("…") else ""
    return f"{prefix}{snippet}{suffix}"
