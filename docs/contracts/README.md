# Module Contracts

Source of truth: `packages/contracts/teger_contracts/` (Pydantic v2).
Generated JSON Schemas: `packages/contracts/schemas/*.schema.json`
(regenerate with `python -m teger_contracts.export_schemas`; CI runs `--check`).

| Contract | Module | Implemented by | Status |
|---|---|---|---|
| `AnalysisRequest` / `ThreatVerdict` | v1 threat analysis | `services/api` `POST /v1/analyses` | Experimental |
| `WindowsEndpointEvent` | Teger Guard telemetry | — | Planned |
| `FileScanRequest` / `FileScanResult` | File scanning (hash-first) | `packages/security-core` hash adapters only; no endpoint | Planned |
| `QuarantineRequest` / `QuarantineResult` | Quarantine / restore | — | Planned |
| `EmailMessageAnalysisRequest` | Teger Mail | — | Planned |
| `AndroidSecurityEvent` | Teger Mobile | — | Planned |
| `EnterprisePolicyBundle` | Teger Enterprise policy distribution | — | Planned |

## Design rules

- Every contract carries `schema_version` and `tenant_id`; unknown fields are rejected.
- Hashes are lowercase SHA-256 hex. Paths and free text are length-bounded.
- **Quarantine/restore** commands must be signed, time-limited, and name a human
  approver. Deletion is intentionally not representable. Agents must reject unsigned,
  expired, or replayed commands. No agent implements these commands yet.
- **Policy bundles** are signed and monotonically versioned; clients must refuse
  rollbacks. `cloud_ai_allowed` defaults to `false`.
- **File scans** are hash-first; uploading content requires `content_upload_consent`.
  Files are never executed on Teger infrastructure or developer hosts.
- Endpoint paths replace the user profile directory with `%USERPROFILE%`.
