import pytest

from teger_security_core.urls import (
    UrlValidationError, extract_urls, normalize_url, parse_legacy_ipv4, registrable_domain,
)


@pytest.mark.parametrize("raw", [
    "javascript:alert(1)", " JavaScript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
    "ftp://example.com/x", "gopher://example.com", "vbscript:msgbox", "ws://example.com",
])
def test_rejects_non_http_schemes(raw):
    with pytest.raises(UrlValidationError):
        normalize_url(raw)


@pytest.mark.parametrize("raw", [
    "", "   ", "https://exa mple.com", "https://example.com/\x00", "https://example.com/\r\nSet-Cookie:x",
    "https://" + "a" * 2050 + ".com", "https://exa_mple..com", "https://example.com:99999/",
])
def test_rejects_malformed(raw):
    with pytest.raises(UrlValidationError):
        normalize_url(raw)


def test_normalizes_case_default_port_and_fragment():
    url = normalize_url("HTTPS://WWW.Example.COM:443/Path?q=1#frag")
    assert url.normalized == "https://www.example.com/Path?q=1"
    assert url.port is None
    assert url.registrable_domain == "example.com"


def test_bare_domain_gets_http_scheme():
    assert normalize_url("example.com/login").normalized == "http://example.com/login"


def test_userinfo_flagged_and_stripped():
    url = normalize_url("https://paypal.com@evil.test/login")
    assert url.had_userinfo
    assert url.host == "evil.test"
    assert "paypal.com@" not in url.normalized


def test_idn_host_is_punycoded():
    url = normalize_url("https://pаypal.com/")  # Cyrillic а
    assert url.host == "xn--pypal-4ve.com"
    assert url.unicode_host == "pаypal.com"


@pytest.mark.parametrize("raw,expected", [
    ("2130706433", "127.0.0.1"), ("0x7f000001", "127.0.0.1"), ("0177.0.0.1", "127.0.0.1"),
    ("127.1", "127.0.0.1"), ("0x7f.1", "127.0.0.1"), ("169.254.169.254", "169.254.169.254"),
])
def test_legacy_ipv4_forms(raw, expected):
    assert str(parse_legacy_ipv4(raw)) == expected
    url = normalize_url(f"http://{raw}/")
    assert url.is_ip_literal and url.host == expected


def test_non_numeric_host_is_not_ip():
    assert parse_legacy_ipv4("example.com") is None
    assert parse_legacy_ipv4("256.256.256.256") is None


def test_ipv6_literal():
    url = normalize_url("http://[::ffff:127.0.0.1]:8080/")
    assert url.is_ip_literal and url.port == 8080 and url.normalized.startswith("http://[")


def test_registrable_domain_multi_label_suffix():
    assert registrable_domain("login.bank.co.uk") == "bank.co.uk"
    assert registrable_domain("a.b.example.com") == "example.com"


def test_extract_urls_skips_invalid_and_dedupes():
    text = "Go to https://a.example/x. Or https://a.example/x, or javascript:alert(1) or https://b.example"
    assert [u.host for u in extract_urls(text)] == ["a.example", "b.example"]
