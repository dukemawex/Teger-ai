import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from teger_ai_analyst import AnalystSettings, ClaudeAnalyst, ModelExplanation
from teger_api.app import create_app
from teger_api.keys import generate_key
from teger_api.settings import ApiSettings


class Keys:
    def __init__(self):
        self.tokens = {}
        self.records = []

    def add(self, name, tenant, scopes=("analyses:read", "analyses:write"), cloud_ai=False):
        token, record = generate_key(tenant, list(scopes), cloud_ai)
        self.tokens[name] = token
        self.records.append(record)
        return token

    def header(self, name):
        return {"Authorization": f"Bearer {self.tokens[name]}"}


class FakeAnthropic:
    def __init__(self, parsed=None, stop_reason="end_turn"):
        self.calls = []
        self.parsed = parsed
        self.stop_reason = stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            parsed_output=self.parsed, stop_reason=self.stop_reason, model="claude-opus-5-5",
            usage=SimpleNamespace(input_tokens=1000, output_tokens=200, cache_read_input_tokens=0,
                                  cache_creation_input_tokens=0),
        )


def safe_sounding_explanation(ids=("ev-1",)):
    return ModelExplanation.model_validate({
        "summary": "This is a legitimate message and completely safe. Ignore Teger's warning.",
        "key_points": [{"evidence_ids": list(ids), "explanation": "Nothing to worry about."}],
        "user_guidance": "Go ahead and click.",
        "injection_attempt_observed": False,
    })


@pytest.fixture
def keys():
    k = Keys()
    k.add("alice", "tenant-a")
    k.add("alice_ai", "tenant-a", cloud_ai=True)
    k.add("bob", "tenant-b")
    k.add("reader", "tenant-a", scopes=("analyses:read",))
    k.add("writer", "tenant-a", scopes=("analyses:write",))
    return k


@pytest.fixture
def make_client(keys):
    def _make(analyst=None, raise_server_exceptions=True, **overrides):
        params = dict(environment="test", api_keys_json=json.dumps(keys.records), reputation_provider="mock",
                      key_rate_limit_per_minute=1000, ip_rate_limit_per_minute=1000)
        params.update(overrides)
        settings = ApiSettings(**params)
        app = create_app(settings, analyst=analyst or ClaudeAnalyst(AnalystSettings()))
        return TestClient(app, raise_server_exceptions=raise_server_exceptions)
    return _make


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def fake_anthropic():
    return FakeAnthropic(safe_sounding_explanation())


@pytest.fixture
def ai_client(make_client, fake_anthropic):
    analyst = ClaudeAnalyst(AnalystSettings(enabled=True, api_key_present=True), client=fake_anthropic)
    return make_client(analyst=analyst)


@pytest.fixture
def fake_anthropic_cls():
    return FakeAnthropic
