"""Destination fetching for investigations.

Three implementations share one interface (:class:`Fetcher`):

* :class:`FixtureFetcher` — demo mode. Serves inert, local fixture responses; never
  touches the network. Redirect hops still go through the same syntactic rules.
* :class:`UnavailableFetcher` — live mode without a configured fetch worker. Every call
  reports ``unavailable``; nothing is fabricated.
* :class:`RemoteFetcher` — live mode. Delegates to the separate fetch worker process
  (``teger_investigator.worker``), which runs :class:`IsolatedHttpFetcher`.

:class:`IsolatedHttpFetcher` is only meant to run inside that worker. It validates every
hop at connection time (DNS answers checked, then the socket is pinned to a validated IP),
never follows redirects automatically, never sends cookies or credentials, never fetches
subresources or executes scripts, and caps time, size and hops. Application-level checks
are not a substitute for network egress restrictions on the worker; see
docs/deployment.md.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urljoin

from teger_security_core.netguard import (
    ALLOWED_FETCH_PORTS,
    DestinationBlocked,
    is_forbidden_hostname,
    is_forbidden_ip,
)
from teger_security_core.urls import ParsedUrl, UrlValidationError, normalize_url

MAX_HOPS = 5
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "TegerInspector/0.1 (+https://www.tegerai.tech; no-js; no-subresources)"


@dataclass(frozen=True)
class Hop:
    url: str
    status: int | None
    location: str | None = None


@dataclass(frozen=True)
class FetchChain:
    """Result of resolving a URL hop by hop. ``final_*`` describe the last hop fetched."""

    requested_url: str
    hops: tuple[Hop, ...]
    final_url: str | None
    final_status: int | None = None
    content_type: str | None = None
    body: str | None = None  # decoded text, already size-capped; attacker-controlled
    truncated: bool = False
    error: str | None = None  # client-safe failure reason
    error_kind: str | None = None  # blocked | timeout | unreachable | too_many_redirects | invalid
    provider: str = "fixture"

    @property
    def ok(self) -> bool:
        return self.error is None and self.final_status is not None


class Fetcher(Protocol):
    name: str
    available: bool

    def fetch_chain(self, url: str) -> FetchChain: ...


def check_hop_syntax(url: str, previous: str | None = None) -> ParsedUrl:
    """Syntactic rules applied to every hop (fixture and live)."""
    try:
        parsed = normalize_url(url)
    except UrlValidationError as exc:
        raise DestinationBlocked(str(exc)) from None
    if parsed.had_userinfo:
        raise DestinationBlocked("URLs with embedded credentials are not fetched.")
    if parsed.effective_port not in ALLOWED_FETCH_PORTS:
        raise DestinationBlocked("Destination port is not allowed.")
    if parsed.nonstandard_ip_encoding:
        raise DestinationBlocked("Ambiguous IP address encodings are not fetched.")
    if parsed.is_ip_literal and is_forbidden_ip(ipaddress.ip_address(parsed.host)):
        raise DestinationBlocked("Destination is a private or reserved address.")
    if not parsed.is_ip_literal and is_forbidden_hostname(parsed.host):
        raise DestinationBlocked("Destination is an internal hostname.")
    if previous is not None and normalize_url(previous).scheme == "https" and parsed.scheme != "https":
        raise DestinationBlocked("Redirect downgrades HTTPS to HTTP.")
    return parsed


# ------------------------------------------------------------------ fixtures (demo)

@dataclass(frozen=True)
class FixtureResponse:
    status: int = 200
    body: str = ""
    location: str | None = None
    content_type: str = "text/html; charset=utf-8"
    behaviour: str | None = None  # "timeout" | "unreachable"


@dataclass
class FixtureFetcher:
    """Serves inert fixture responses keyed by exact normalized URL. No network I/O."""

    responses: dict[str, FixtureResponse]
    name: str = "fixture"
    available: bool = True
    requested: list[str] = field(default_factory=list)

    def fetch_chain(self, url: str) -> FetchChain:
        hops: list[Hop] = []
        current, previous = url, None
        for _ in range(MAX_HOPS + 1):
            try:
                parsed = check_hop_syntax(current, previous)
            except DestinationBlocked as exc:
                return FetchChain(url, tuple(hops), None, error=exc.reason, error_kind="blocked")
            self.requested.append(parsed.normalized)
            response = self.responses.get(parsed.normalized)
            if response is None or response.behaviour == "unreachable":
                hops.append(Hop(parsed.normalized, None))
                return FetchChain(url, tuple(hops), parsed.normalized, error="Destination could not be reached.",
                                  error_kind="unreachable")
            if response.behaviour == "timeout":
                hops.append(Hop(parsed.normalized, None))
                return FetchChain(url, tuple(hops), parsed.normalized, error="Destination timed out.",
                                  error_kind="timeout")
            if 300 <= response.status < 400 and response.location:
                hops.append(Hop(parsed.normalized, response.status, response.location))
                previous, current = parsed.normalized, urljoin(parsed.normalized, response.location)
                continue
            hops.append(Hop(parsed.normalized, response.status))
            body = response.body[:MAX_BODY_BYTES]
            return FetchChain(url, tuple(hops), parsed.normalized, response.status, response.content_type, body,
                              truncated=len(response.body) > MAX_BODY_BYTES)
        return FetchChain(url, tuple(hops), None, error="Too many redirects.", error_kind="too_many_redirects")


@dataclass
class UnavailableFetcher:
    reason: str = "Live destination inspection is not configured (no fetch worker)."
    name: str = "none"
    available: bool = False

    def fetch_chain(self, url: str) -> FetchChain:
        return FetchChain(url, (), None, error=self.reason, error_kind="unavailable", provider="none")


# ------------------------------------------------------------------ live, inside the worker

Resolver = Callable[[str, int], Iterable[str]]


def _default_resolver(host: str, port: int) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # SNI and certificate verification use the hostname; the socket uses the validated IP.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class IsolatedHttpFetcher:
    """Hop-by-hop HTTP(S) GET with connection-time destination validation.

    ``resolver`` and ``forbidden_ip`` are injectable for tests only; production uses the
    system resolver and :func:`is_forbidden_ip`.
    """

    resolver: Resolver = _default_resolver
    forbidden_ip: Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool] = is_forbidden_ip
    connect_timeout: float = 5.0
    total_deadline: float = 15.0
    max_bytes: int = MAX_BODY_BYTES
    max_hops: int = MAX_HOPS
    allowed_ports: frozenset[int] = ALLOWED_FETCH_PORTS
    ssl_context: ssl.SSLContext | None = None
    name: str = "isolated-http"
    available: bool = True

    def _validate(self, url: str, previous: str | None) -> tuple[ParsedUrl, str]:
        try:
            parsed = normalize_url(url)
        except UrlValidationError as exc:
            raise DestinationBlocked(str(exc)) from None
        if parsed.had_userinfo:
            raise DestinationBlocked("URLs with embedded credentials are not fetched.")
        if parsed.effective_port not in self.allowed_ports:
            raise DestinationBlocked("Destination port is not allowed.")
        if parsed.nonstandard_ip_encoding:
            raise DestinationBlocked("Ambiguous IP address encodings are not fetched.")
        if previous is not None and normalize_url(previous).scheme == "https" and parsed.scheme != "https":
            raise DestinationBlocked("Redirect downgrades HTTPS to HTTP.")
        if parsed.is_ip_literal:
            ip = ipaddress.ip_address(parsed.host)
            if self.forbidden_ip(ip):
                raise DestinationBlocked("Destination is a private or reserved address.")
            return parsed, str(ip)
        if is_forbidden_hostname(parsed.host):
            raise DestinationBlocked("Destination is an internal hostname.")
        try:
            answers = list(self.resolver(parsed.host, parsed.effective_port))
        except (OSError, UnicodeError):
            raise DestinationBlocked("Destination could not be resolved.") from None
        if not answers:
            raise DestinationBlocked("Destination could not be resolved.")
        pinned = None
        for answer in answers:
            if "%" in answer:
                raise DestinationBlocked("Destination resolves to a private or reserved address.")
            try:
                ip = ipaddress.ip_address(answer)
            except ValueError:
                raise DestinationBlocked("Destination resolved to an invalid address.") from None
            if self.forbidden_ip(ip):
                # Any private answer blocks the destination (classic rebinding setup).
                raise DestinationBlocked("Destination resolves to a private or reserved address.")
            pinned = pinned or str(ip)
        return parsed, pinned

    def _get(self, parsed: ParsedUrl, ip: str, timeout: float):
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if parsed.scheme == "https":
            context = self.ssl_context or ssl.create_default_context()
            conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                parsed.host, ip, parsed.effective_port, timeout, context)
        else:
            conn = _PinnedHTTPConnection(parsed.host, ip, parsed.effective_port, timeout)
        host_header = parsed.host if parsed.port is None else f"{parsed.host}:{parsed.port}"
        # No cookies, no auth, no customer headers. GET only; forms are never submitted.
        conn.request("GET", path, headers={
            "Host": host_header, "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        return conn, conn.getresponse()

    def fetch_chain(self, url: str) -> FetchChain:
        deadline = time.monotonic() + self.total_deadline
        hops: list[Hop] = []
        current, previous = url, None
        for _ in range(self.max_hops + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return FetchChain(url, tuple(hops), current, error="Destination timed out.", error_kind="timeout",
                                  provider=self.name)
            try:
                parsed, ip = self._validate(current, previous)
            except DestinationBlocked as exc:
                return FetchChain(url, tuple(hops), None, error=exc.reason, error_kind="blocked", provider=self.name)
            conn = None
            try:
                conn, response = self._get(parsed, ip, min(self.connect_timeout, remaining))
                status = response.status
                if 300 <= status < 400:
                    location = response.getheader("Location")
                    hops.append(Hop(parsed.normalized, status, location))
                    if not location:
                        return FetchChain(url, tuple(hops), parsed.normalized, status,
                                          error="Redirect has no location.",
                                          error_kind="invalid", provider=self.name)
                    previous, current = parsed.normalized, urljoin(parsed.normalized, location.strip())
                    continue
                hops.append(Hop(parsed.normalized, status))
                content_type = (response.getheader("Content-Type") or "")[:120]
                raw = response.read(self.max_bytes + 1)
                truncated = len(raw) > self.max_bytes
                body = None
                if "html" in content_type or "text" in content_type or not content_type:
                    body = raw[: self.max_bytes].decode("utf-8", errors="replace")
                return FetchChain(url, tuple(hops), parsed.normalized, status, content_type, body, truncated,
                                  provider=self.name)
            except (socket.timeout, TimeoutError):
                hops.append(Hop(parsed.normalized, None))
                return FetchChain(url, tuple(hops), parsed.normalized, error="Destination timed out.",
                                  error_kind="timeout", provider=self.name)
            except (OSError, http.client.HTTPException, ssl.SSLError):
                hops.append(Hop(parsed.normalized, None))
                return FetchChain(url, tuple(hops), parsed.normalized, error="Destination could not be reached.",
                                  error_kind="unreachable", provider=self.name)
            finally:
                if conn is not None:
                    conn.close()
        return FetchChain(url, tuple(hops), None, error="Too many redirects.", error_kind="too_many_redirects",
                          provider=self.name)


# ------------------------------------------------------------------ live, from the API process

@dataclass
class RemoteFetcher:
    """Calls the separate fetch worker. The API process itself never opens a socket to a
    submitted destination."""

    base_url: str
    token: str
    client: object | None = None  # httpx.Client-compatible; injectable for tests
    timeout: float = 25.0
    name: str = "fetch-worker"
    available: bool = True

    def _client(self):
        if self.client is None:
            import httpx
            self.client = httpx.Client(timeout=self.timeout)
        return self.client

    def fetch_chain(self, url: str) -> FetchChain:
        try:
            response = self._client().post(
                f"{self.base_url.rstrip('/')}/v1/fetch", json={"url": url},
                headers={"Authorization": f"Bearer {self.token}"},
            )
        except Exception:
            return FetchChain(url, (), None, error="The fetch worker could not be reached.", error_kind="unavailable",
                              provider=self.name)
        if response.status_code != 200:
            return FetchChain(url, (), None, error=f"The fetch worker returned an error ({response.status_code}).",
                              error_kind="unavailable", provider=self.name)
        data = response.json()
        return FetchChain(
            requested_url=url,
            hops=tuple(Hop(h["url"], h.get("status"), h.get("location")) for h in data.get("hops", [])[: MAX_HOPS + 1]),
            final_url=data.get("final_url"),
            final_status=data.get("final_status"),
            content_type=data.get("content_type"),
            body=(data.get("body") or None) and str(data["body"])[:MAX_BODY_BYTES],
            truncated=bool(data.get("truncated")),
            error=data.get("error"),
            error_kind=data.get("error_kind"),
            provider=self.name,
        )
