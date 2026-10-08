from teger_security_core.redaction import excerpt, redact


def test_redacts_email_local_part_but_keeps_domain():
    out = redact("Contact jane.doe@acme-corp.test now")
    assert out.text == "Contact [REDACTED]@acme-corp.test now"
    assert out.counts == {"email": 1}


def test_redacts_secrets_and_tokens():
    text = (
        "password: hunter2 and key sk-ant-abcdefghijklmnopqrstuv and AKIAABCDEFGHIJKLMNOP "
        "Authorization: Bearer abcdefghijklmnop123 jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcdefghijk"
    )
    out = redact(text).text
    for secret in ("hunter2", "sk-ant-", "AKIAABCDEFGHIJKLMNOP", "abcdefghijklmnop123", "eyJhbGci"):
        assert secret not in out


def test_redacts_cards_only_when_luhn_valid():
    assert "[REDACTED_CARD]" in redact("card 4111 1111 1111 1111").text
    assert "1234 5678 9012 3456" in redact("ref 1234 5678 9012 3456").text


def test_redacts_iban_phone_otp_and_url_secrets():
    out = redact("IBAN GB82 WEST 1234 5698 7654 32, call +44 20 7946 0958, code is 482913, "
                 "https://x.test/r?token=abc123&page=2").text
    assert "GB82" not in out and "7946" not in out and "482913" not in out and "abc123" not in out
    assert "page=2" in out


def test_keeps_ordinary_prose():
    text = "Your password is required to continue. The meeting is at 10:30 in room 4."
    assert redact(text).text == text


def test_excerpt_is_redacted_and_bounded():
    text = "x" * 500 + " send your password to boss@corp.test " + "y" * 500
    start = text.index("send")
    snippet = excerpt(text, start, start + 4)
    assert "boss@" not in snippet and len(snippet) <= 162
