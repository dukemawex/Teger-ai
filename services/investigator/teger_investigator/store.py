"""SQLite persistence for cases, events, approvals, trusted context and activity.

Every query is scoped by tenant. Demo visitors get tenants of the form ``demo:<id>``,
which cannot collide with API-key tenants (those cannot contain ':').

``path=":memory:"`` is for tests and throwaway development only. Production needs a path
on durable storage (see docs/deployment.md); an ephemeral container filesystem is not
durable.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import ActionState, Case, CaseEvent, CaseSummary, ContextEntry, ProposedAction

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE cases (
        tenant TEXT NOT NULL, id TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
        version INTEGER NOT NULL, verdict TEXT, title TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, data TEXT NOT NULL,
        PRIMARY KEY (tenant, id)
    );
    CREATE INDEX cases_by_tenant ON cases (tenant, created_at DESC);
    CREATE TABLE case_events (
        tenant TEXT NOT NULL, case_id TEXT NOT NULL, seq INTEGER NOT NULL, ts TEXT NOT NULL,
        type TEXT NOT NULL, message TEXT NOT NULL, data TEXT NOT NULL,
        PRIMARY KEY (tenant, case_id, seq)
    );
    CREATE TABLE actions (
        tenant TEXT NOT NULL, id TEXT NOT NULL, case_id TEXT NOT NULL, state TEXT NOT NULL,
        idempotency_key TEXT, data TEXT NOT NULL,
        PRIMARY KEY (tenant, id)
    );
    CREATE INDEX actions_by_case ON actions (tenant, case_id);
    CREATE TABLE context_entries (
        tenant TEXT NOT NULL, id TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL,
        PRIMARY KEY (tenant, id)
    );
    CREATE TABLE blocklist (
        tenant TEXT NOT NULL, domain TEXT NOT NULL, added_by TEXT NOT NULL, added_at TEXT NOT NULL,
        case_id TEXT, action_id TEXT, PRIMARY KEY (tenant, domain)
    );
    CREATE TABLE activity (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, ts TEXT NOT NULL, type TEXT NOT NULL,
        case_id TEXT, action_id TEXT, actor TEXT NOT NULL, message TEXT NOT NULL
    );
    CREATE INDEX activity_by_tenant ON activity (tenant, seq DESC);
    CREATE TABLE demo_sessions (tenant TEXT PRIMARY KEY, created_at TEXT NOT NULL);
    """,
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ConflictError(Exception):
    """A state transition lost a race or no longer applies."""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._migrate()

    @property
    def durable(self) -> bool:
        return self.path != ":memory:"

    def _migrate(self) -> None:
        self._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = self._conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        current = row["v"] or 0
        for index, script in enumerate(MIGRATIONS[current:], start=current + 1):
            self._conn.execute("BEGIN")
            try:
                for statement in filter(str.strip, script.split(";")):
                    self._conn.execute(statement)
                self._conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def schema_version(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()["v"] or 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ cases

    def save_case(self, tenant: str, case: Case) -> None:
        data = case.model_dump_json(exclude={"actions"})
        verdict = case.assessment.verdict.value if case.assessment else None
        with self._lock:
            self._conn.execute(
                "INSERT INTO cases (tenant, id, mode, status, version, verdict, title, created_at, updated_at, data) "
                "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant, id) DO UPDATE SET status=excluded.status, "
                "version=excluded.version, verdict=excluded.verdict, title=excluded.title, "
                "updated_at=excluded.updated_at, data=excluded.data",
                (tenant, case.id, case.mode.value, case.status.value, case.version, verdict, case.title,
                 case.created_at.isoformat(), case.updated_at.isoformat(), data),
            )

    def get_case(self, tenant: str, case_id: str) -> Case | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM cases WHERE tenant=? AND id=?", (tenant, case_id)).fetchone()
            if row is None:
                return None
            case = Case.model_validate_json(row["data"])
            return case.model_copy(update={"actions": self.list_actions(tenant, case_id)})

    def list_cases(self, tenant: str, limit: int = 50) -> list[CaseSummary]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT c.id, c.mode, c.title, c.status, c.verdict, c.created_at, c.updated_at, "
                "(SELECT COUNT(*) FROM actions a WHERE a.tenant=c.tenant AND a.case_id=c.id AND a.state='proposed') "
                "AS pending FROM cases c WHERE c.tenant=? ORDER BY c.created_at DESC LIMIT ?",
                (tenant, limit),
            ).fetchall()
        return [CaseSummary(id=r["id"], mode=r["mode"], title=r["title"], status=r["status"], verdict=r["verdict"],
                            created_at=r["created_at"], updated_at=r["updated_at"], pending_approvals=r["pending"])
                for r in rows]

    # ------------------------------------------------------------------ events

    def append_event(self, tenant: str, case_id: str, type_: str, message: str, data: dict | None = None) -> CaseEvent:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS s FROM case_events WHERE tenant=? AND case_id=?", (tenant, case_id)
            ).fetchone()
            event = CaseEvent(seq=row["s"] + 1, ts=utcnow(), type=type_, message=message[:300], data=data or {})
            self._conn.execute(
                "INSERT INTO case_events (tenant, case_id, seq, ts, type, message, data) VALUES (?,?,?,?,?,?,?)",
                (tenant, case_id, event.seq, event.ts.isoformat(), event.type, event.message,
                 json.dumps(event.data, default=str)),
            )
        return event

    def events(self, tenant: str, case_id: str, after: int = 0, limit: int = 500) -> list[CaseEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, type, message, data FROM case_events WHERE tenant=? AND case_id=? AND seq>? "
                "ORDER BY seq LIMIT ?", (tenant, case_id, after, limit)).fetchall()
        return [CaseEvent(seq=r["seq"], ts=r["ts"], type=r["type"], message=r["message"], data=json.loads(r["data"]))
                for r in rows]

    # ------------------------------------------------------------------ actions

    def put_action(self, tenant: str, action: ProposedAction) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO actions (tenant, id, case_id, state, idempotency_key, data) VALUES (?,?,?,?,NULL,?)",
                (tenant, action.id, action.case_id, action.state.value, action.model_dump_json()),
            )

    def get_action(self, tenant: str, action_id: str) -> tuple[ProposedAction, str | None] | None:
        with self._lock:
            row = self._conn.execute("SELECT data, idempotency_key FROM actions WHERE tenant=? AND id=?",
                                     (tenant, action_id)).fetchone()
        if row is None:
            return None
        return ProposedAction.model_validate_json(row["data"]), row["idempotency_key"]

    def list_actions(self, tenant: str, case_id: str) -> list[ProposedAction]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM actions WHERE tenant=? AND case_id=? ORDER BY rowid",
                                      (tenant, case_id)).fetchall()
        return [ProposedAction.model_validate_json(r["data"]) for r in rows]

    def transition_action(self, tenant: str, action: ProposedAction, expected: ActionState,
                          idempotency_key: str | None = None) -> None:
        """Compare-and-set on the action state; raises ConflictError if it changed meanwhile."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE actions SET state=?, data=?, idempotency_key=COALESCE(?, idempotency_key) "
                "WHERE tenant=? AND id=? AND state=?",
                (action.state.value, action.model_dump_json(), idempotency_key, tenant, action.id, expected.value),
            )
            if cursor.rowcount != 1:
                raise ConflictError("The action changed state; reload and try again.")

    def supersede_open_actions(self, tenant: str, case_id: str) -> int:
        """Expire proposals bound to an older case version (e.g. after a retry)."""
        count = 0
        for action in self.list_actions(tenant, case_id):
            if action.state is ActionState.PROPOSED:
                updated = action.model_copy(update={"state": ActionState.EXPIRED,
                                                    "decision_note": "Superseded by a newer investigation run."})
                try:
                    self.transition_action(tenant, updated, ActionState.PROPOSED)
                    count += 1
                except ConflictError:
                    pass
        return count

    # ------------------------------------------------------------------ trusted context

    def add_context(self, tenant: str, entry: ContextEntry) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO context_entries (tenant, id, revoked, data) VALUES (?,?,0,?)",
                               (tenant, entry.id, entry.model_dump_json()))

    def list_context(self, tenant: str, include_revoked: bool = False) -> list[ContextEntry]:
        with self._lock:
            sql = "SELECT data FROM context_entries WHERE tenant=?" + ("" if include_revoked else " AND revoked=0")
            rows = self._conn.execute(sql + " ORDER BY rowid", (tenant,)).fetchall()
        return [ContextEntry.model_validate_json(r["data"]) for r in rows]

    def revoke_context(self, tenant: str, entry_id: str) -> ContextEntry | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM context_entries WHERE tenant=? AND id=? AND revoked=0",
                                     (tenant, entry_id)).fetchone()
            if row is None:
                return None
            entry = ContextEntry.model_validate_json(row["data"]).model_copy(update={"revoked": True})
            self._conn.execute("UPDATE context_entries SET revoked=1, data=? WHERE tenant=? AND id=?",
                               (entry.model_dump_json(), tenant, entry_id))
            return entry

    # ------------------------------------------------------------------ blocklist & activity

    def add_blocklist(self, tenant: str, domain: str, actor: str, case_id: str, action_id: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO blocklist (tenant, domain, added_by, added_at, case_id, action_id) "
                "VALUES (?,?,?,?,?,?)", (tenant, domain, actor, utcnow().isoformat(), case_id, action_id))
            return cursor.rowcount == 1

    def blocklist(self, tenant: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT domain, added_by, added_at, case_id, action_id FROM blocklist "
                                      "WHERE tenant=? ORDER BY added_at DESC", (tenant,)).fetchall()
        return [dict(r) for r in rows]

    def add_activity(self, tenant: str, type_: str, actor: str, message: str, case_id: str | None = None,
                     action_id: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO activity (tenant, ts, type, case_id, action_id, actor, message) VALUES (?,?,?,?,?,?,?)",
                (tenant, utcnow().isoformat(), type_, case_id, action_id, actor[:120], message[:400]))

    def activity(self, tenant: str, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT seq, ts, type, case_id, action_id, actor, message FROM activity "
                                      "WHERE tenant=? ORDER BY seq DESC LIMIT ?", (tenant, limit)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ demo sessions

    def touch_demo_session(self, tenant: str) -> bool:
        """Registers a demo tenant. Returns True when it is new (needs seeding)."""
        with self._lock:
            cursor = self._conn.execute("INSERT OR IGNORE INTO demo_sessions (tenant, created_at) VALUES (?,?)",
                                        (tenant, utcnow().isoformat()))
            return cursor.rowcount == 1

    def delete_tenant(self, tenant: str) -> None:
        with self._lock:
            for table in ("cases", "case_events", "actions", "context_entries", "blocklist", "activity",
                          "demo_sessions"):
                self._conn.execute(f"DELETE FROM {table} WHERE tenant=?", (tenant,))  # noqa: S608 (fixed names)

    def purge_demo_sessions(self, older_than: timedelta = timedelta(hours=24)) -> int:
        cutoff = (utcnow() - older_than).isoformat()
        with self._lock:
            rows = self._conn.execute("SELECT tenant FROM demo_sessions WHERE created_at < ?", (cutoff,)).fetchall()
        for row in rows:
            self.delete_tenant(row["tenant"])
        return len(rows)
