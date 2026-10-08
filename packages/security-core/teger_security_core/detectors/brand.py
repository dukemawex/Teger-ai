"""Brand-impersonation indicators: look-alike domains, brand names on untrusted hosts,
and sender / link mismatches against the brand a message claims to be from."""
from __future__ import annotations

import re
import unicodedata
from email.utils import parseaddr

from teger_contracts import Severity

from ..brands import BRANDS, Brand, is_official_domain
from ..urls import ParsedUrl, registrable_domain
from .base import AnalysisSubject, DetectorOutcome, Finding, FindingCollector

# Characters commonly substituted for Latin letters in look-alike domains.
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ԁ": "d", "ѕ": "s", "ɡ": "g", "ν": "v", "ο": "o", "α": "a", "ı": "i", "ӏ": "l", "ρ": "p", "κ": "k",
})
_MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def skeleton(label: str) -> str:
    decomposed = unicodedata.normalize("NFKD", label.lower())
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    out = stripped.translate(_CONFUSABLES).replace("-", "")
    for src, dst in _MULTI_CONFUSABLES:
        out = out.replace(src, dst)
    return out


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        # one substitution, or one adjacent transposition
        return len(diffs) == 1 or (
            len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
        )
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return True
    return False


def _domain_label(url: ParsedUrl) -> str:
    host = url.unicode_host or url.host
    reg = registrable_domain(host) or host
    return reg.split(".")[0]


def _brand_mentioned(brand: Brand, text: str) -> bool:
    lowered = text.lower()
    names = {brand.name.lower(), *brand.keywords}
    return any(re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", lowered) for n in names)


def _token_match(keyword: str, tokens: list[str]) -> bool:
    # Exact token, or prefix/suffix for long keywords ("paypalsupport"). Short brand
    # names ("dhl", "slack") must match a whole token to avoid hits like "slackline".
    return any(
        token == keyword or (len(keyword) >= 6 and (token.startswith(keyword) or token.endswith(keyword)))
        for token in tokens
    )


def _inspect_url(url: ParsedUrl, collector: FindingCollector) -> None:
    if url.is_ip_literal or is_official_domain(url.registrable_domain):
        return
    raw_label = _domain_label(url).lower()
    label_skeleton = skeleton(raw_label)
    host_tokens = [skeleton(t) for t in re.split(r"[.-]", (url.unicode_host or url.host).lower()) if t]
    path_tokens = [t for t in re.split(r"[^a-z0-9]+", url.path.lower()) if t]
    shown_host = url.unicode_host or url.host
    for brand in BRANDS:
        for keyword in brand.keywords:
            if raw_label != keyword and label_skeleton == keyword:
                collector.add(Finding(
                    "brand_homoglyph_domain", Severity.CRITICAL,
                    f"Domain imitates {brand.name} by substituting look-alike characters.",
                    f"{shown_host} ({url.host})" if url.unicode_host else shown_host, "link_manipulation",
                ))
            elif len(keyword) >= 6 and raw_label != keyword and _edit_distance_le1(label_skeleton, keyword):
                collector.add(Finding(
                    "brand_typosquat_domain", Severity.HIGH,
                    f"Domain is one character away from {brand.name}'s name.", shown_host, "link_manipulation",
                ))
            elif _token_match(keyword, host_tokens):
                collector.add(Finding(
                    "brand_name_on_untrusted_domain", Severity.HIGH,
                    f"Domain uses the name '{keyword}' but is not an official {brand.name} domain.",
                    shown_host, "trust_transfer",
                ))
            elif keyword in path_tokens:
                collector.add(Finding(
                    "brand_name_in_path", Severity.MEDIUM,
                    f"Link path mentions {brand.name} on a domain {brand.name} does not use.",
                    f"{url.host}{url.path[:60]}", "trust_transfer",
                ))


def _inspect_sender(subject: AnalysisSubject, collector: FindingCollector) -> None:
    display, address = parseaddr(subject.sender or "")
    sender_domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    sender_reg = registrable_domain(sender_domain) if sender_domain else None

    embedded = _EMAIL_IN_TEXT.search(display or "")
    if embedded and sender_reg and registrable_domain(embedded.group(1).lower()) != sender_reg:
        collector.add(Finding(
            "display_name_address_mismatch", Severity.HIGH,
            "Sender display name shows a different email domain than the actual sending address.",
            f"display shows @{embedded.group(1).lower()}, sent from @{sender_domain}", "authority_spoofing",
        ))

    for brand in BRANDS:
        claims_in_name = bool(display) and _brand_mentioned(brand, display)
        if sender_reg and claims_in_name and sender_reg not in brand.domains:
            collector.add(Finding(
                "sender_brand_mismatch", Severity.HIGH,
                f"Sender name claims to be {brand.name}, but the address is from {sender_domain}.",
                f"@{sender_domain}", "authority_spoofing",
            ))
        if _brand_mentioned(brand, subject.text) and subject.urls:
            off_brand = [u for u in subject.urls if not u.is_ip_literal and u.registrable_domain not in brand.domains]
            if off_brand and len(off_brand) == len(subject.urls):
                collector.add(Finding(
                    "brand_link_mismatch", Severity.MEDIUM,
                    f"Message refers to {brand.name}, but none of its links go to an official {brand.name} domain.",
                    off_brand[0].host, "trust_transfer",
                ))


class BrandImpersonationDetector:
    name = "brand_impersonation"
    version = "1.0.0"

    def is_required(self, subject: AnalysisSubject) -> bool:
        return bool(subject.urls or subject.sender)

    def run(self, subject: AnalysisSubject) -> DetectorOutcome:
        collector = FindingCollector()
        for url in subject.urls:
            _inspect_url(url, collector)
        _inspect_sender(subject, collector)
        return collector.outcome()
