"""Structural URL heuristics (no network I/O)."""
from __future__ import annotations

import unicodedata

from teger_contracts import Severity

from ..brands import is_official_domain
from ..netguard import is_private_target
from ..urls import ParsedUrl
from .base import AnalysisSubject, DetectorOutcome, Finding, FindingCollector

# Heuristic lists. They raise suspicion; none of them alone makes a URL malicious.
SUSPICIOUS_TLDS = frozenset(
    {"zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "rest", "cam", "country", "support"}
)
URL_SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
     "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly"}
)
REDIRECT_PARAMS = frozenset(
    {"url", "u", "redirect", "redirect_url", "redirect_uri", "redir", "next", "return", "returnurl",
     "return_to", "target", "dest", "destination", "continue", "goto", "out", "link"}
)
DECEPTIVE_HOST_TOKENS = ("login", "signin", "verify", "secure", "account", "update", "wallet", "support", "auth")
CREDENTIAL_PATH_TOKENS = ("login", "signin", "sign-in", "logon", "verify", "password", "account", "auth", "webscr")


def _scripts(text: str) -> set[str]:
    scripts = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0] if name else "UNKNOWN")
    return scripts


def _host_label(url: ParsedUrl) -> str:
    return url.unicode_host or url.host


def inspect_url(url: ParsedUrl, collector: FindingCollector) -> None:
    host = _host_label(url)

    if is_private_target(url):
        collector.add(Finding(
            "private_network_target", Severity.MEDIUM,
            "Link points to a private, loopback or internal network address. Teger never fetches it.",
            host, "link_manipulation",
        ))
    if url.nonstandard_ip_encoding:
        collector.add(Finding(
            "obfuscated_ip_host", Severity.HIGH,
            "Host is an IP address written in an unusual numeric form to disguise the destination.",
            host, "link_manipulation",
        ))
    elif url.is_ip_literal:
        collector.add(Finding(
            "ip_literal_host", Severity.MEDIUM,
            "Link uses a raw IP address instead of a domain name.", host, "link_manipulation",
        ))
    if url.had_userinfo:
        collector.add(Finding(
            "userinfo_in_url", Severity.HIGH,
            "Link contains text before an '@', a trick that makes the real destination look like a trusted site.",
            host, "link_manipulation",
        ))
    if url.unicode_host:
        if len(_scripts(url.unicode_host.replace(".", ""))) > 1:
            collector.add(Finding(
                "mixed_script_host", Severity.HIGH,
                "Domain mixes alphabets (e.g. Latin and Cyrillic), a common look-alike technique.",
                f"{url.unicode_host} ({url.host})", "link_manipulation",
            ))
        else:
            collector.add(Finding(
                "internationalized_host", Severity.LOW,
                "Domain uses internationalized (punycode) characters.",
                f"{url.unicode_host} ({url.host})", "link_manipulation",
            ))
    if url.registrable_domain in URL_SHORTENERS:
        collector.add(Finding(
            "url_shortener", Severity.LOW, "Link uses a URL shortener that hides the final destination.",
            host, "link_manipulation",
        ))

    if not url.is_ip_literal:
        tld = url.host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            collector.add(Finding(
                "high_abuse_tld", Severity.LOW, f"Domain uses the '.{tld}' top-level domain, frequently abused.",
                host,
            ))
        labels = url.host.split(".")
        if len(labels) >= 5:
            collector.add(Finding(
                "excessive_subdomains", Severity.LOW, "Domain has an unusually deep chain of subdomains.", host,
                "link_manipulation",
            ))
        if (url.unicode_host or url.host).replace("xn--", "").count("-") >= 3:
            collector.add(Finding(
                "hyphenated_host", Severity.LOW, "Domain contains many hyphens, typical of throwaway phishing hosts.",
                host,
            ))
        registrable = url.registrable_domain or url.host
        subdomain_part = url.host[: -len(registrable)]
        if not is_official_domain(url.registrable_domain) and (
            any(token in subdomain_part for token in DECEPTIVE_HOST_TOKENS)
            or ("-" in registrable and any(token in registrable for token in DECEPTIVE_HOST_TOKENS))
        ):
            collector.add(Finding(
                "deceptive_host_keyword", Severity.LOW,
                "Domain contains security/login wording often used to look official.", host, "link_manipulation",
            ))

    if url.port is not None:
        collector.add(Finding("non_standard_port", Severity.LOW, f"Link uses non-standard port {url.port}.", host))

    for name, value in url.query_params:
        lowered = value.strip().lower()
        if name.lower() in REDIRECT_PARAMS and (lowered.startswith(("http://", "https://", "//"))):
            collector.add(Finding(
                "embedded_redirect", Severity.MEDIUM,
                f"Link carries another URL in its '{name}' parameter, a common open-redirect lure.",
                host, "link_manipulation",
            ))
            break

    path = url.path.lower()
    if url.scheme == "http" and any(token in path for token in CREDENTIAL_PATH_TOKENS):
        collector.add(Finding(
            "credential_path_without_tls", Severity.MEDIUM,
            "Login-style page served without HTTPS.", host, "credential_harvesting",
        ))
    if len(url.normalized) > 200:
        collector.add(Finding("very_long_url", Severity.LOW, "Link is unusually long.", host, weight=4))


class UrlHeuristicsDetector:
    name = "url_heuristics"
    version = "1.0.0"

    def is_required(self, subject: AnalysisSubject) -> bool:
        return bool(subject.urls)

    def run(self, subject: AnalysisSubject) -> DetectorOutcome:
        collector = FindingCollector()
        for url in subject.urls:
            inspect_url(url, collector)
        return collector.outcome()
