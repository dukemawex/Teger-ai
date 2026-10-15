"""Live-tool tests: the real IsolatedHttpFetcher against a local HTTP server.

The server runs on 127.0.0.1, which production policy forbids. Tests that need to reach it
inject a resolver mapping reserved test names to loopback and an IP policy that allows
loopback only; every other test uses the production policy and proves loopback, metadata
and private targets are refused.
"""
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from teger_investigator.demo import DEMO_CONTEXT
from teger_investigator.fetch import IsolatedHttpFetcher, RemoteFetcher
from teger_investigator.models import CaseInput, Mode, ToolState, Verdict
from teger_investigator.service import InvestigationService, Limits, default_run_config
from teger_investigator.store import Store
from teger_investigator.worker import create_worker

LOGIN = (b"<html><head><title>Northwind Freight - Sign in</title><link rel=stylesheet href='http://169.254.169.254/x'>"
         b"<img src='http://10.0.0.1/p.png'></head><body><h1>Northwind Freight</h1>"
         b"<form action='/collect' method='post'><input name=username><input type=password name=password></form>"
         b"</body></html>")


class Handler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        Handler.requests.append(f"{self.headers.get('Host')}{self.path}")
        assert "Cookie" not in self.headers and "Authorization" not in self.headers
        if self.path == "/go":
            self.send_response(302)
            self.send_header("Location", "http://landing.test:%d/login" % self.server.server_port)
            self.end_headers()
        elif self.path == "/to-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/to-internal-name":
            self.send_response(301)
            self.send_header("Location", "http://rebind.test:%d/" % self.server.server_port)
            self.end_headers()
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(LOGIN)
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<p>" + b"a" * 700_000 + b"</p>")
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.handle_error = lambda *a: None  # the size-cap test closes the socket mid-response on purpose
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def loopback_only(ip):
    return not ip.is_loopback


def make_resolver(port):
    def resolve(host, _port):
        if host == "rebind.test":
            return ["93.184.216.34", "10.0.0.7"]  # mixed answers: classic rebinding setup
        if host.endswith(".test"):
            return ["127.0.0.1"]
        raise OSError("no such host")
    return resolve


def lab_fetcher(server, **kw):
    port = server.server_port
    return IsolatedHttpFetcher(resolver=make_resolver(port), forbidden_ip=loopback_only,
                               allowed_ports=frozenset({port, 80, 443}), **kw)


def url(server, host, path):
    return f"http://{host}:{server.server_port}{path}"


# ------------------------------------------------------------------ SSRF under production policy

def test_production_policy_refuses_loopback_private_and_metadata(server):
    fetcher = IsolatedHttpFetcher()
    for target in [f"http://127.0.0.1:{server.server_port}/login", "http://169.254.169.254/latest/meta-data/",
                   "http://[::ffff:127.0.0.1]/", "http://10.1.2.3/", "http://localhost/", "http://2130706433/",
                   "http://user:pw@example.com/", "https://example.com:8443/", "http://metadata.internal/"]:
        chain = fetcher.fetch_chain(target)
        assert chain.error_kind == "blocked", target
    assert Handler.requests == [] or all("127.0.0.1" not in r for r in Handler.requests)


def test_redirect_to_metadata_is_blocked_at_the_hop(server):
    chain = lab_fetcher(server).fetch_chain(url(server, "start.test", "/to-metadata"))
    assert chain.error_kind == "blocked" and "private" in chain.error
    assert [h.status for h in chain.hops] == [302]


def test_dns_answer_with_any_private_address_is_blocked(server):
    chain = lab_fetcher(server).fetch_chain(url(server, "start.test", "/to-internal-name"))
    assert chain.error_kind == "blocked"


def test_no_subresources_and_size_cap(server):
    Handler.requests.clear()
    chain = lab_fetcher(server).fetch_chain(url(server, "landing.test", "/login"))
    assert chain.ok and "password" in chain.body
    assert Handler.requests == [f"landing.test:{server.server_port}/login"]  # stylesheet/img never requested
    big = lab_fetcher(server, max_bytes=1000).fetch_chain(url(server, "landing.test", "/big"))
    assert big.truncated and len(big.body) == 1000


def test_unreachable_destination_reports_failure(server):
    chain = lab_fetcher(server).fetch_chain(url(server, "nobody.invalid-tld-for-tests.test", "/"))
    # resolves to loopback on the server port but path 404s; use a closed port for unreachable instead
    assert chain.final_status == 404
    closed = IsolatedHttpFetcher(resolver=lambda h, p: ["127.0.0.1"], forbidden_ip=loopback_only,
                                 allowed_ports=frozenset({1}))
    assert closed.fetch_chain("http://closed.test:1/").error_kind == "unreachable"


# ------------------------------------------------------------------ adaptive behaviour with live tools

@pytest.fixture
def service():
    store = Store()
    for entry in DEMO_CONTEXT:
        store.add_context("t", entry)
    return InvestigationService(store, inline=True)


def live_case(service, fetcher, link):
    inp = CaseInput(sender="Northwind Freight <ar@northwind-freight.example>", subject="Statement",
                    message=f"Northwind Freight statement: please sign in to review {link}")
    case = service.create_case("t", Mode.LIVE, inp, default_run_config(fetcher, limits=Limits()), "tester")
    return service.get_case("t", case.id)


def test_live_redirect_to_login_page_leads_to_page_inspection(server, service):
    case = live_case(service, lab_fetcher(server), url(server, "nwf-statements.test", "/go"))
    tools = [t.tool for t in case.tools]
    assert tools == ["extract_message", "static_analysis", "resolve_redirects", "inspect_page", "compare_context",
                     "check_reputation", "propose_response"]
    assert any(e.kind == "form_requests_sensitive_data" for e in case.evidence)
    assert case.assessment.verdict is Verdict.MALICIOUS
    assert all(e.source.startswith(("HTTP via", "page at", "submitted", "approved", "Teger", "reputation"))
               for e in case.evidence)


def test_live_unreachable_destination_skips_inspection_and_stays_inconclusive(server, service):
    closed = IsolatedHttpFetcher(resolver=lambda h, p: ["127.0.0.1"], forbidden_ip=loopback_only,
                                 allowed_ports=frozenset({1}))
    case = live_case(service, closed, "http://files.northwind-freight.example:1/statement")
    tools = [t.tool for t in case.tools]
    assert "inspect_page" not in tools
    assert next(t for t in case.tools if t.tool == "resolve_redirects").state is ToolState.FAILED
    assert case.assessment.verdict is Verdict.INCONCLUSIVE


# ------------------------------------------------------------------ worker process boundary

def test_worker_requires_token_and_returns_chain(server):
    token = "w" * 40
    app = create_worker(token=token, fetcher=lab_fetcher(server))
    client = TestClient(app)
    assert client.post("/v1/fetch", json={"url": "http://x.test/"}).status_code == 401
    assert client.post("/v1/fetch", json={"url": "http://x.test/"},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    remote = RemoteFetcher("http://testserver", token, client=client)
    chain = remote.fetch_chain(url(server, "start.test", "/go"))
    assert chain.ok and chain.final_url.endswith("/login") and len(chain.hops) == 2
    blocked = remote.fetch_chain("http://169.254.169.254/")
    assert blocked.error_kind == "blocked"


def test_worker_refuses_weak_token():
    with pytest.raises(RuntimeError):
        create_worker(token="short")


def test_remote_fetcher_reports_unreachable_worker():
    chain = RemoteFetcher("http://127.0.0.1:1", "t" * 40, timeout=0.5).fetch_chain("https://example.com/")
    assert chain.error_kind == "unavailable" and not chain.ok


def test_ip_policy_default_is_strict():
    assert IsolatedHttpFetcher().forbidden_ip(ipaddress.ip_address("127.0.0.1"))
