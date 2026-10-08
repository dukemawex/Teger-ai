import io

import pytest

from teger_contracts import DetectorStatus
from teger_security_core.files import (
    FileTooLarge, HashBlocklistAdapter, UnavailableSignatureAdapter, hash_bytes, hash_stream,
)


def test_hashes_known_value():
    h = hash_bytes(b"abc")
    assert h.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert h.md5 == "900150983cd24fb0d6963f7d28e17f72" and h.size_bytes == 3


def test_size_limit_enforced():
    with pytest.raises(FileTooLarge):
        hash_stream(io.BytesIO(b"x" * 11), max_bytes=10)


def test_blocklist_match_and_miss():
    h = hash_bytes(b"sample")
    adapter = HashBlocklistAdapter({h.sha256: "Test.Signature"})
    assert adapter.scan(h).matches == ("Test.Signature",)
    assert adapter.scan(hash_bytes(b"other")).matches == ()


def test_unavailable_engine_is_explicit():
    assert UnavailableSignatureAdapter().scan(hash_bytes(b"x")).status is DetectorStatus.UNAVAILABLE
