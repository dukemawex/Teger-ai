"""File hashing and signature-scanning adapters.

Files are only ever read as bytes and hashed. Nothing in this module executes,
unpacks, renders or detonates file content.
"""
from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from typing import BinaryIO, Protocol

from teger_contracts import DetectorStatus, ProviderMode

DEFAULT_MAX_BYTES = 100 * 1024 * 1024
_CHUNK = 1024 * 1024


class FileTooLarge(ValueError):
    pass


@dataclass(frozen=True)
class FileHashes:
    sha256: str
    sha1: str
    md5: str
    size_bytes: int


def hash_stream(stream: BinaryIO, max_bytes: int = DEFAULT_MAX_BYTES) -> FileHashes:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(usedforsecurity=False), hashlib.md5(usedforsecurity=False)
    size = 0
    while chunk := stream.read(_CHUNK):
        size += len(chunk)
        if size > max_bytes:
            raise FileTooLarge(f"File exceeds {max_bytes} bytes.")
        for h in (sha256, sha1, md5):
            h.update(chunk)
    return FileHashes(sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size)


def hash_bytes(data: bytes, max_bytes: int = DEFAULT_MAX_BYTES) -> FileHashes:
    return hash_stream(io.BytesIO(data), max_bytes)


@dataclass(frozen=True)
class SignatureResult:
    status: DetectorStatus
    mode: ProviderMode
    engine: str
    matches: tuple[str, ...] = ()
    detail: str | None = None


class SignatureAdapter(Protocol):
    engine: str
    mode: ProviderMode

    def scan(self, hashes: FileHashes) -> SignatureResult: ...


@dataclass
class HashBlocklistAdapter:
    """Exact SHA-256 match against a local blocklist ({sha256: signature_name})."""

    blocklist: dict[str, str] = field(default_factory=dict)
    engine: str = "hash-blocklist"
    mode: ProviderMode = ProviderMode.LOCAL

    def scan(self, hashes: FileHashes) -> SignatureResult:
        name = self.blocklist.get(hashes.sha256.lower())
        return SignatureResult(DetectorStatus.OK, self.mode, self.engine, (name,) if name else ())


class UnavailableSignatureAdapter:
    engine = "none"
    mode = ProviderMode.NONE

    def scan(self, hashes: FileHashes) -> SignatureResult:
        return SignatureResult(
            DetectorStatus.UNAVAILABLE, self.mode, self.engine, detail="No signature engine configured."
        )
