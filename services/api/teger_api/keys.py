"""Tenant-scoped API keys.

Token format: ``tgr_<key_id>_<secret>``. Only the SHA-256 digest of the 256-bit random
secret is stored. Generate a key with::

    python -m teger_api.keys --tenant acme --scopes analyses:read,analyses:write
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

SCOPES = frozenset({"analyses:read", "analyses:write"})
_KEY_ID = re.compile(r"^[a-z0-9]{12}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_TOKEN = re.compile(r"^tgr_([a-z0-9]{12})_([A-Za-z0-9_-]{32,128})$")


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    key_id: str
    scopes: frozenset[str]
    cloud_ai_allowed: bool


@dataclass(frozen=True)
class ApiKeyRecord:
    key_id: str
    tenant_id: str
    scopes: frozenset[str]
    secret_sha256: str
    cloud_ai_allowed: bool = False
    label: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ApiKeyRecord":
        key_id, tenant = str(data["key_id"]), str(data["tenant_id"])
        scopes = frozenset(data.get("scopes", []))
        digest = str(data["secret_sha256"]).lower()
        if not _KEY_ID.match(key_id) or not _TENANT.match(tenant):
            raise ValueError("Invalid key_id or tenant_id in API key configuration.")
        if not scopes <= SCOPES:
            raise ValueError(f"Unknown scopes in API key configuration: {sorted(scopes - SCOPES)}")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("secret_sha256 must be 64 lowercase hex characters.")
        return cls(
            key_id, tenant, scopes, digest, bool(data.get("cloud_ai_allowed", False)), str(data.get("label", ""))
        )


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class ApiKeyStore:
    def __init__(self, records: list[ApiKeyRecord] | None = None):
        self._by_id: dict[str, ApiKeyRecord] = {}
        for record in records or []:
            if record.key_id in self._by_id:
                raise ValueError("Duplicate key_id in API key configuration.")
            self._by_id[record.key_id] = record

    def __len__(self) -> int:
        return len(self._by_id)

    @classmethod
    def from_config(cls, inline_json: str = "", file_path: str = "") -> "ApiKeyStore":
        raw = inline_json.strip()
        if not raw and file_path:
            raw = Path(file_path).read_text()
        if not raw:
            return cls([])
        return cls([ApiKeyRecord.from_dict(item) for item in json.loads(raw)])

    def authenticate(self, token: str) -> Principal | None:
        match = _TOKEN.match(token or "")
        # Always hash so timing does not reveal whether the key_id exists.
        presented = _digest(match.group(2) if match else token or "")
        record = self._by_id.get(match.group(1)) if match else None
        expected = record.secret_sha256 if record else _digest("teger-no-such-key")
        if not hmac.compare_digest(presented, expected) or record is None:
            return None
        return Principal(record.tenant_id, record.key_id, record.scopes, record.cloud_ai_allowed)


def generate_key(tenant_id: str, scopes: list[str], cloud_ai_allowed: bool = False,
                 label: str = "") -> tuple[str, dict]:
    """Return (token to hand to the client once, record to store)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    key_id = "".join(secrets.choice(alphabet) for _ in range(12))
    secret = secrets.token_urlsafe(32)
    record = {
        "key_id": key_id, "tenant_id": tenant_id, "scopes": sorted(scopes),
        "secret_sha256": _digest(secret), "cloud_ai_allowed": cloud_ai_allowed, "label": label,
    }
    ApiKeyRecord.from_dict(record)  # validate
    return f"tgr_{key_id}_{secret}", record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Teger API key.")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--scopes", default="analyses:read,analyses:write")
    parser.add_argument("--cloud-ai-allowed", action="store_true")
    parser.add_argument("--label", default="")
    args = parser.parse_args(argv)
    token, record = generate_key(args.tenant, args.scopes.split(","), args.cloud_ai_allowed, args.label)
    print("Token (shown once, give to the client):")
    print(token)
    print("\nRecord (add to TEGER_API_KEYS JSON array or TEGER_API_KEYS_FILE):")
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
