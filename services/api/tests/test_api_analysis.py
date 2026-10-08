def post(client, keys, body, who="alice"):
    return client.post("/v1/analyses", json=body, headers=keys.header(who))


def test_url_analysis_returns_full_verdict(client, keys):
    r = post(client, keys, {"url": "https://pаypal.com/signin", "content_type": "web"})
    assert r.status_code == 201
    body = r.json()
    assert body["verdict"] == "malicious" and body["recommended_action"] == "block"
    assert body["url"]["host"] == "xn--pypal-4ve.com"
    assert body["policy_version"]
    assert {e["id"] for e in body["evidence"]} and all(e["detector"] for e in body["evidence"])
    assert {s["name"] for s in body["detection_sources"]} >= {"url_heuristics", "reputation"}
    assert body["explanation"]["status"] == "not_requested"
    assert 0 <= body["confidence"] <= 1


def test_message_analysis(client, keys):
    body = post(client, keys, {
        "content": "URGENT: Your mailbox will be suspended. Verify your account and reply with your password.",
        "sender": "IT Helpdesk <it@helpdesk-mail.example>", "content_type": "email",
    }).json()
    assert body["verdict"] in ("suspicious", "malicious")
    tactics = {e["tactic"] for e in body["evidence"]}
    assert {"artificial_urgency", "credential_harvesting"} <= tactics


def test_mock_intelligence_is_flagged(client, keys):
    body = post(client, keys, {"url": "https://phish-kit.test/login"}).json()
    assert body["verdict"] == "malicious" and body["mock_intelligence_used"] is True
    rep = next(s for s in body["detection_sources"] if s["name"] == "reputation")
    assert rep["provider_mode"] == "mock"


def test_no_provider_means_unknown_not_safe(make_client, keys):
    client = make_client(reputation_provider="none")
    body = post(client, keys, {"url": "https://www.example.org/"}).json()
    assert body["verdict"] == "unknown"
    assert body["recommended_action"] == "caution"
    assert body["intelligence_coverage"] == "partial"
    assert body["mock_intelligence_used"] is False


def test_benign_text_is_no_threat_detected(client, keys):
    body = post(client, keys, {"content": "Lunch moved to 1pm on Friday."}).json()
    assert body["verdict"] == "no_threat_detected" and body["recommended_action"] == "allow"


def test_requires_url_or_content(client, keys):
    assert post(client, keys, {}).status_code == 422
    assert post(client, keys, {"content": "   "}).status_code == 422


def test_rejects_dangerous_url_schemes(client, keys):
    for url in ("javascript:alert(document.cookie)", "file:///etc/passwd", "data:text/html,<script>"):
        r = post(client, keys, {"url": url})
        assert r.status_code == 422 and "http" in r.json()["detail"]


def test_field_limits(client, keys):
    assert post(client, keys, {"content": "x" * 20001}).status_code == 422
    assert post(client, keys, {"url": "https://a.example/" + "a" * 2050}).status_code == 422
    assert post(client, keys, {"content": "x", "content_type": "fax"}).status_code == 422


def test_validation_errors_do_not_echo_input(client, keys):
    secret = "my-password-is-Hunter2"
    r = post(client, keys, {"content": "x" * 20001 + secret})
    assert secret not in r.text
    r = post(client, keys, {"content": 123, "sender": secret * 20})
    assert secret not in r.text
