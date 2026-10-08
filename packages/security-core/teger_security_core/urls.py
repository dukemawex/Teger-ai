"""URL normalization and validation.

Normalization is purely syntactic: nothing here performs DNS resolution or network I/O.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlsplit

import idna

from teger_contracts import NormalizedUrl
from teger_contracts.analysis import URL_MAX_LENGTH

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}

_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_DANGEROUS_SCHEME = re.compile(
    r"^\s*(javascript|vbscript|data|file|blob|about|filesystem|jar|view-source|mailto|ftp|gopher|ws|wss)\s*:",
    re.IGNORECASE,
)
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'`)\]}]+", re.IGNORECASE)
_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_SAFE = _PATH_SAFE + "?"

# Multi-label public suffixes we recognise without shipping the full Public Suffix
# List. Registrable-domain results are an approximation; see docs/security/threat-model.md.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "co.za", "org.za", "gov.za",
        "com.ng", "org.ng", "gov.ng", "edu.ng", "co.ke", "or.ke",
        "com.br", "com.mx", "com.ar", "com.co",
        "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in",
        "com.cn", "com.hk", "com.sg", "com.my", "com.tr", "com.sa", "com.eg", "com.gh",
        "co.id", "co.il", "co.th",
    }
)


class UrlValidationError(ValueError):
    """Raised for URLs Teger refuses to analyze. Messages are safe to return to clients."""


@dataclass(frozen=True)
class ParsedUrl:
    normalized: str
    scheme: str
    host: str
    unicode_host: str | None
    port: int | None
    path: str
    query: str
    is_ip_literal: bool
    nonstandard_ip_encoding: bool
    had_userinfo: bool
    registrable_domain: str | None
    query_params: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        return ipaddress.ip_address(self.host) if self.is_ip_literal else None

    @property
    def effective_port(self) -> int:
        return self.port or DEFAULT_PORTS[self.scheme]

    def to_contract(self) -> NormalizedUrl:
        return NormalizedUrl(
            normalized=self.normalized,
            scheme=self.scheme,
            host=self.host,
            unicode_host=self.unicode_host,
            registrable_domain=self.registrable_domain,
            port=self.port,
            is_ip_literal=self.is_ip_literal,
            had_userinfo=self.had_userinfo,
        )


def parse_legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse inet_aton-style IPv4 forms browsers and resolvers accept.

    Examples: ``2130706433``, ``0x7f000001``, ``0177.0.0.1``, ``127.1``.
    Returns ``None`` when ``host`` is not purely numeric.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    values = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                values.append(int(part[2:] or "0", 16))
            elif len(part) > 1 and part.startswith("0"):
                values.append(int(part, 8))
            else:
                if not part.isdigit():
                    return None
                values.append(int(part, 10))
        except ValueError:
            return None
    # Every part except the last is one octet; the last fills the remaining bytes.
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(values)):
        return None
    number = 0
    for v in head:
        number = number * 256 + v
    number = number * 256 ** (5 - len(values)) + last
    return ipaddress.IPv4Address(number)


def registrable_domain(host: str) -> str | None:
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _encode_host(raw_host: str) -> tuple[str, str | None]:
    host = raw_host.rstrip(".")
    if not host:
        raise UrlValidationError("URL host is empty.")
    if host.isascii():
        # ASCII hosts skip IDNA mapping so DNS-legal underscores are not rejected;
        # punycode labels are still validated by the decode step below.
        ascii_host = host.lower()
    else:
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError:
            raise UrlValidationError("URL host is not a valid domain name.") from None
    if len(ascii_host) > 253:
        raise UrlValidationError("URL host is too long.")
    labels = ascii_host.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise UrlValidationError("URL host is not a valid domain name.")
    unicode_host = None
    if any(label.startswith("xn--") for label in labels):
        try:
            unicode_host = idna.decode(ascii_host)
        except idna.IDNAError:
            raise UrlValidationError("URL host has invalid punycode.") from None
    return ascii_host, unicode_host


def normalize_url(raw: str) -> ParsedUrl:
    if not isinstance(raw, str):
        raise UrlValidationError("URL must be a string.")
    candidate = raw.strip()
    if not candidate:
        raise UrlValidationError("URL is empty.")
    if len(candidate) > URL_MAX_LENGTH:
        raise UrlValidationError("URL is too long.")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in candidate):
        raise UrlValidationError("URL contains whitespace or control characters.")
    if _DANGEROUS_SCHEME.match(candidate):
        raise UrlValidationError("Only http and https URLs can be analyzed.")
    if not _HAS_SCHEME.match(candidate):
        candidate = "http://" + candidate.lstrip("/")

    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError:
        raise UrlValidationError("URL is malformed.") from None

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlValidationError("Only http and https URLs can be analyzed.")

    raw_host = parts.hostname or ""
    had_userinfo = parts.username is not None or "@" in parts.netloc

    is_ip = False
    nonstandard_ip = False
    unicode_host: str | None = None
    try:
        ip = ipaddress.ip_address(raw_host)
        host = ip.compressed
        is_ip = True
    except ValueError:
        legacy = parse_legacy_ipv4(raw_host)
        if legacy is not None:
            host = legacy.compressed
            is_ip = True
            nonstandard_ip = raw_host != host
        else:
            host, unicode_host = _encode_host(raw_host)

    if port == DEFAULT_PORTS[scheme]:
        port = None

    path = quote(parts.path or "/", safe=_PATH_SAFE)
    query = quote(parts.query, safe=_QUERY_SAFE)
    host_part = f"[{host}]" if is_ip and ":" in host else host
    port_part = f":{port}" if port else ""
    normalized = f"{scheme}://{host_part}{port_part}{path}" + (f"?{query}" if query else "")

    return ParsedUrl(
        normalized=normalized,
        scheme=scheme,
        host=host,
        unicode_host=unicode_host,
        port=port,
        path=path,
        query=query,
        is_ip_literal=is_ip,
        nonstandard_ip_encoding=nonstandard_ip,
        had_userinfo=had_userinfo,
        registrable_domain=None if is_ip else registrable_domain(host),
        query_params=tuple(parse_qsl(parts.query, keep_blank_values=True)[:50]),
    )


def extract_urls(text: str, limit: int = 10) -> list[ParsedUrl]:
    """Extract and normalize up to ``limit`` distinct http(s) URLs from free text.

    Invalid URLs are skipped; message text is attacker-controlled and may contain junk.
    """
    seen: set[str] = set()
    results: list[ParsedUrl] = []
    for match in _URL_IN_TEXT.finditer(text or ""):
        raw = match.group(0).rstrip(".,;:!?")
        try:
            parsed = normalize_url(raw)
        except UrlValidationError:
            continue
        if parsed.normalized in seen:
            continue
        seen.add(parsed.normalized)
        results.append(parsed)
        if len(results) >= limit:
            break
    return results
