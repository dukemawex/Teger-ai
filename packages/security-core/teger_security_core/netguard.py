"""Outbound-destination guard (SSRF defense).

The v1 API performs static analysis only and never fetches submitted URLs. Any future
component that does fetch (e.g. a sandboxed scan-worker) MUST:

1. call :func:`check_destination` and connect only to the returned, validated IPs
   (pinning them defeats DNS rebinding between check and connect);
2. disable automatic redirects and pass every ``Location`` through
   :func:`validate_redirect`;
3. enforce its own response size and time limits.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from urllib.parse import urljoin

from .urls import ParsedUrl, UrlValidationError, normalize_url

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Iterable[str]]

ALLOWED_FETCH_PORTS = frozenset({80, 443})
MAX_REDIRECTS = 5

_FORBIDDEN_HOST_SUFFIXES = (
    ".localhost", ".local", ".internal", ".intranet", ".corp", ".home.arpa", ".lan", ".localdomain",
)
_FORBIDDEN_HOSTS = frozenset({"localhost", "metadata", "instance-data"})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class DestinationBlocked(Exception):
    """The destination is not a public internet address. ``reason`` is client-safe."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_forbidden_ip(ip: IPAddress) -> bool:
    """True for anything that is not a globally routable unicast address.

    Covers RFC1918, loopback, link-local (incl. 169.254.169.254 cloud metadata),
    CGNAT 100.64/10, unique-local and site-local IPv6, multicast, reserved,
    unspecified, documentation ranges, and IPv4 embedded in IPv6 transition formats.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            return True
        embedded = _embedded_ipv4(ip)
        if embedded is not None and is_forbidden_ip(embedded):
            return True
        if ip.is_site_local:
            return True
    return (not ip.is_global) or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def is_forbidden_hostname(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in _FORBIDDEN_HOSTS or "." not in host:
        return True
    return host.endswith(_FORBIDDEN_HOST_SUFFIXES)


def is_private_target(url: ParsedUrl) -> bool:
    """Syntactic check only (no DNS). Used by detectors to flag internal targets."""
    if url.is_ip_literal:
        return is_forbidden_ip(ipaddress.ip_address(url.host))
    return is_forbidden_hostname(url.host)


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def check_destination(
    url: str | ParsedUrl,
    resolver: Resolver = _default_resolver,
    allowed_ports: frozenset[int] = ALLOWED_FETCH_PORTS,
) -> list[IPAddress]:
    """Validate that ``url`` resolves only to public addresses. Returns the IPs to pin."""
    try:
        parsed = url if isinstance(url, ParsedUrl) else normalize_url(url)
    except UrlValidationError as exc:
        raise DestinationBlocked(str(exc)) from None

    if parsed.had_userinfo:
        raise DestinationBlocked("URLs with embedded credentials are not fetched.")
    if parsed.effective_port not in allowed_ports:
        raise DestinationBlocked("Destination port is not allowed.")

    if parsed.is_ip_literal:
        ip = ipaddress.ip_address(parsed.host)
        if is_forbidden_ip(ip):
            raise DestinationBlocked("Destination is a private or reserved address.")
        return [ip]

    if is_forbidden_hostname(parsed.host):
        raise DestinationBlocked("Destination is an internal hostname.")

    try:
        answers = list(resolver(parsed.host, parsed.effective_port))
    except (OSError, UnicodeError):
        raise DestinationBlocked("Destination could not be resolved.") from None
    if not answers:
        raise DestinationBlocked("Destination could not be resolved.")

    ips: list[IPAddress] = []
    for answer in answers:
        if "%" in answer:
            # Scoped (link-local) IPv6 answers are never public.
            raise DestinationBlocked("Destination resolves to a private or reserved address.")
        try:
            ip = ipaddress.ip_address(answer)
        except ValueError:
            raise DestinationBlocked("Destination resolved to an invalid address.") from None
        if is_forbidden_ip(ip):
            # Any private answer blocks the whole destination: mixed records are a
            # classic rebinding setup.
            raise DestinationBlocked("Destination resolves to a private or reserved address.")
        ips.append(ip)
    return ips


def validate_redirect(
    current_url: str,
    location: str,
    hops_taken: int,
    resolver: Resolver = _default_resolver,
    max_redirects: int = MAX_REDIRECTS,
) -> tuple[ParsedUrl, list[IPAddress]]:
    """Validate one redirect hop. Refuses HTTPS→HTTP downgrades and private targets."""
    if hops_taken >= max_redirects:
        raise DestinationBlocked("Too many redirects.")
    if not location or not location.strip():
        raise DestinationBlocked("Redirect has no location.")
    target = urljoin(current_url, location.strip())
    try:
        parsed = normalize_url(target)
        current = normalize_url(current_url)
    except UrlValidationError as exc:
        raise DestinationBlocked(str(exc)) from None
    if current.scheme == "https" and parsed.scheme != "https":
        raise DestinationBlocked("Redirect downgrades HTTPS to HTTP.")
    return parsed, check_destination(parsed, resolver=resolver)
