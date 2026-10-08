from teger_api.ratelimit import SlidingWindowLimiter


def test_key_rate_limit(make_client, keys):
    client = make_client(key_rate_limit_per_minute=3)
    codes = [client.post("/v1/analyses", json={"content": "x"}, headers=keys.header("alice")).status_code
             for _ in range(4)]
    assert codes == [201, 201, 201, 429]
    r = client.post("/v1/analyses", json={"content": "x"}, headers=keys.header("alice"))
    assert int(r.headers["retry-after"]) >= 1
    # Another key is unaffected.
    assert client.post("/v1/analyses", json={"content": "x"}, headers=keys.header("bob")).status_code == 201


def test_ip_rate_limit_covers_unauthenticated_attempts(make_client):
    client = make_client(ip_rate_limit_per_minute=2)
    codes = [client.post("/v1/analyses", json={"content": "x"}, headers={"Authorization": "Bearer nope"}).status_code
             for _ in range(3)]
    assert codes == [401, 401, 429]


def test_forwarded_for_ignored_unless_trusted(make_client):
    client = make_client(ip_rate_limit_per_minute=1)
    h1 = {"Authorization": "Bearer nope", "X-Forwarded-For": "1.1.1.1"}
    h2 = {"Authorization": "Bearer nope", "X-Forwarded-For": "2.2.2.2"}
    assert client.get("/v1/whoami", headers=h1).status_code == 401
    assert client.get("/v1/whoami", headers=h2).status_code == 429  # spoofed header does not reset the limit


def test_forwarded_for_used_when_trusted(make_client):
    client = make_client(ip_rate_limit_per_minute=1, trust_proxy_headers=True)
    assert client.get("/v1/whoami", headers={"X-Forwarded-For": "9.9.9.9, 1.1.1.1"}).status_code == 401
    assert client.get("/v1/whoami", headers={"X-Forwarded-For": "9.9.9.9, 2.2.2.2"}).status_code == 401


def test_window_slides():
    now = [0.0]
    limiter = SlidingWindowLimiter(2, window_seconds=60, clock=lambda: now[0])
    assert limiter.check("k")[0] and limiter.check("k")[0]
    assert limiter.check("k") == (False, 60)
    now[0] = 61
    assert limiter.check("k")[0]
