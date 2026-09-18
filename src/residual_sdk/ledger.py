"""Append-only SQLite evidence ledger with attestation issuance.

Implements the MS-00/MS-08-style discipline required of a reference backend:
  * events: append-only, hash-chained (genesis '0'*64), UNIQUE event_id for
    idempotent admission (I-4), exactly-one-terminal per run (I-1),
    hash-chain verification at open (I-6, fail closed on corruption);
  * attestations: append-only table per ATTESTATION-VERSIONING §4.1,
    admitted as events with event_id = attestation_id (AT-3);
  * all state+event writes in a single BEGIN IMMEDIATE transaction (I-2).

The ``transport`` hook simulates the core link: raising from ``ping()`` or
``commit()`` surfaces as CoreUnreachableError / LedgerWriteError at the
backend boundary.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid

from .attestation import GENESIS_HASH, build_attestation, canonical_json, sha256_hex
from .errors import AttestationError, CoreUnreachableError, LedgerWriteError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  run_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  digest TEXT UNIQUE NOT NULL,
  prev_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attestations (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  attestation_id TEXT UNIQUE NOT NULL,
  spec_version TEXT NOT NULL,
  spec_head_sha TEXT NOT NULL,
  gate_version TEXT NOT NULL,
  gate_set_hash TEXT NOT NULL,
  impl_repo TEXT NOT NULL,
  impl_commit_sha TEXT NOT NULL,
  impl_tree_sha TEXT NOT NULL,
  evidence_manifest_hash TEXT NOT NULL,
  verdicts_json TEXT NOT NULL,
  issuer TEXT NOT NULL,
  issued_ns INTEGER NOT NULL,
  prev_attestation_hash TEXT NOT NULL,
  digest TEXT UNIQUE NOT NULL,
  prev_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS attest_no_update BEFORE UPDATE ON attestations
BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS attest_no_delete BEFORE DELETE ON attestations
BEGIN SELECT RAISE(ABORT, 'append-only'); END;
"""

_VALID_OUTCOMES = frozenset({"success", "error", "aborted"})


class LocalTransport:
    """Default 'core link': always healthy. Tests/chaos drivers subclass it."""

    def ping(self) -> bool:
        return True

    def commit(self) -> None:
        return None


class GateSet:
    """Versioned gate definitions. Gate verdicts are never coerced.

    ``blocked_modules``: on_module_call returns BLOCKED for these modules.
    ``require_module_call``: run completing with zero module calls -> FAIL.
    """

    VERSION = "G0@1.0.0"

    def __init__(self, blocked_modules: set[str] | None = None, require_module_call: bool = True):
        self.blocked_modules = set(blocked_modules or ())
        self.require_module_call = require_module_call

    def definitions(self) -> list[dict]:
        return [
            {"gate_id": "G0-BLOCKED-MODULE", "blocked_modules": sorted(self.blocked_modules)},
            {"gate_id": "G0-MODULE-CALL-REQUIRED", "enabled": self.require_module_call},
        ]

    @property
    def hash(self) -> str:
        return sha256_hex(canonical_json(self.definitions()))

    def check_module(self, module: str) -> str:
        return "BLOCKED" if module in self.blocked_modules else "PASS"

    def check_completion(self, module_call_count: int) -> str:
        if self.require_module_call and module_call_count == 0:
            return "FAIL"
        return "PASS"


class SQLiteResidualBackend:
    """Reference ResidualBackend over a local SQLite ledger."""

    def __init__(
        self,
        db_path: str = ":memory:",
        *,
        spec_version: str = "1.0.0",
        spec_head_sha: str = "5d4fd9a7e364311e62e869e327710511c4dd623c",
        impl_repo: str = "ninja-ops-guy/residual-sdk",
        impl_commit_sha: str = "0" * 40,
        impl_tree_sha: str = "0" * 40,
        issuer: str = "residual-sdk/sqlite-backend",
        gate_set: GateSet | None = None,
        transport: LocalTransport | None = None,
    ):
        self._lock = threading.RLock()
        self.transport = transport or LocalTransport()
        self.spec_version = spec_version
        self.spec_head_sha = spec_head_sha
        self.impl_repo = impl_repo
        self.impl_commit_sha = impl_commit_sha
        self.impl_tree_sha = impl_tree_sha
        self.issuer = issuer
        self.gate_set = gate_set or GateSet()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._terminal: dict[str, str] = {}
        self._verdicts: dict[str, dict[str, str]] = {}
        self._module_calls: dict[str, int] = {}
        self._verify_event_chain()  # I-6: fail closed on corruption at open

    # -- internals ---------------------------------------------------------

    def _verify_event_chain(self) -> None:
        rows = self._conn.execute(
            "SELECT seq, event_id, run_id, domain, kind, payload_json, digest, prev_hash"
            " FROM events ORDER BY seq"
        ).fetchall()
        prev = GENESIS_HASH
        for seq, event_id, run_id, domain, kind, payload_json, digest, prev_hash in rows:
            body = {
                "domain": domain,
                "event_id": event_id,
                "kind": kind,
                "payload": json.loads(payload_json),
                "prev_hash": prev,
                "run_id": run_id,
                "seq": seq,
            }
            if prev_hash != prev or sha256_hex(canonical_json(body)) != digest:
                raise LedgerWriteError(
                    f"hash-chain verification failed at seq {seq}; ledger corrupt (fail-closed open)"
                )
            prev = digest

    def _append_event(self, run_id: str, domain: str, kind: str, payload: dict, event_id: str | None = None) -> str:
        event_id = event_id or str(uuid.uuid4())
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                prev_row = self._conn.execute(
                    "SELECT seq, digest FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev = prev_row[1] if prev_row else GENESIS_HASH
                seq = (prev_row[0] if prev_row else 0) + 1
                body = {
                    "domain": domain,
                    "event_id": event_id,
                    "kind": kind,
                    "payload": payload,
                    "prev_hash": prev,
                    "run_id": run_id,
                    "seq": seq,
                }
                digest = sha256_hex(canonical_json(body))
                self._conn.execute(
                    "INSERT INTO events(event_id, run_id, domain, kind, payload_json, digest, prev_hash)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (event_id, run_id, domain, kind,
                     canonical_json(payload).decode(), digest, prev),
                )
                self.transport.commit()  # commit-before-ack (CBA)
                self._conn.commit()
                return digest
            except sqlite3.IntegrityError:
                self._conn.rollback()
                # Idempotent admission (I-4): duplicate event_id resolves to original.
                row = self._conn.execute(
                    "SELECT digest FROM events WHERE event_id=?", (event_id,)
                ).fetchone()
                if row is None:
                    raise LedgerWriteError(f"integrity error admitting event {event_id}")
                return row[0]
            except Exception as exc:  # I-2: any partial failure -> rollback
                self._conn.rollback()
                raise LedgerWriteError(f"ledger write failed for event {event_id}: {exc}") from exc

    def _record_verdict(self, run_id: str, gate_id: str, verdict: str) -> None:
        self._verdicts.setdefault(run_id, {})[gate_id] = verdict

    # -- ResidualBackend interface -----------------------------------------

    def on_run_start(self, run_id: str, spec_id: str, metadata: dict | None = None) -> None:
        try:
            if not self.transport.ping():
                raise CoreUnreachableError("core ping returned not-ready")
        except CoreUnreachableError:
            raise
        except Exception as exc:
            raise CoreUnreachableError(f"core unreachable: {exc}") from exc
        with self._lock:
            if run_id in self._terminal:
                raise LedgerWriteError(f"run {run_id} already terminal (I-1)")
            self._module_calls[run_id] = 0
            self._append_event(run_id, "run", "run.started",
                               {"spec_id": spec_id, "metadata": metadata or {}})

    def on_module_call(self, run_id: str, module: str, call_id: str, inputs_digest: str) -> str:
        with self._lock:
            if run_id in self._terminal:
                raise LedgerWriteError(f"run {run_id} already terminal (I-1)")
            if run_id not in self._module_calls:
                raise LedgerWriteError(f"module call before run start for {run_id}")
            verdict = self.gate_set.check_module(module)
            self._module_calls[run_id] += 1
            self._append_event(
                run_id, "module", "module.called",
                {"module": module, "call_id": call_id, "inputs_digest": inputs_digest,
                 "verdict": verdict},
            )
            if verdict != "PASS":
                self._record_verdict(run_id, "G0-BLOCKED-MODULE", verdict)
                self._append_event(run_id, "gate", "gate.fired",
                                   {"gate_id": "G0-BLOCKED-MODULE", "module": module,
                                    "verdict": verdict})
            return verdict

    def on_run_complete(self, run_id: str, outcome: str) -> None:
        if outcome not in _VALID_OUTCOMES:
            raise LedgerWriteError(f"invalid outcome {outcome!r}")
        with self._lock:
            if run_id in self._terminal:
                raise LedgerWriteError(f"run {run_id} already terminal (I-1)")
            completion_verdict = self.gate_set.check_completion(self._module_calls.get(run_id, 0))
            self._record_verdict(run_id, "G0-MODULE-CALL-REQUIRED", completion_verdict)
            if completion_verdict != "PASS":
                self._append_event(run_id, "gate", "gate.fired",
                                   {"gate_id": "G0-MODULE-CALL-REQUIRED",
                                    "verdict": completion_verdict})
                outcome = "aborted"
            self._append_event(run_id, "run", "run.completed", {"outcome": outcome})
            self._terminal[run_id] = outcome
            self._issue_attestation(run_id)

    def _issue_attestation(self, run_id: str) -> None:
        verdicts = dict(self._verdicts.get(run_id, {}))
        for gate in self.gate_set.definitions():
            verdicts.setdefault(gate["gate_id"], "PASS")
        events = self._conn.execute(
            "SELECT event_id, kind, payload_json FROM events WHERE run_id=? ORDER BY seq",
            (run_id,),
        ).fetchall()
        manifest = {"run_id": run_id, "events": [
            {"event_id": e, "kind": k, "payload": json.loads(p)} for e, k, p in events
        ]}
        prev_row = self._conn.execute(
            "SELECT attestation_id FROM attestations WHERE impl_repo=? ORDER BY seq DESC LIMIT 1",
            (self.impl_repo,),
        ).fetchone()
        token = build_attestation(
            spec_version=self.spec_version,
            spec_head_sha=self.spec_head_sha,
            gate_version=self.gate_set.VERSION,
            gate_set_hash=self.gate_set.hash,
            impl_repo=self.impl_repo,
            impl_commit_sha=self.impl_commit_sha,
            impl_tree_sha=self.impl_tree_sha,
            evidence_manifest_hash=sha256_hex(canonical_json(manifest)),
            verdicts=verdicts,
            issuer=self.issuer,
            prev_attestation_hash=prev_row[0] if prev_row else GENESIS_HASH,
            issued_ns=time.time_ns(),
        )
        digest = sha256_hex(canonical_json(token))
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                prev2 = self._conn.execute(
                    "SELECT digest FROM attestations ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                self._conn.execute(
                    "INSERT INTO attestations(attestation_id, spec_version, spec_head_sha,"
                    " gate_version, gate_set_hash, impl_repo, impl_commit_sha, impl_tree_sha,"
                    " evidence_manifest_hash, verdicts_json, issuer, issued_ns,"
                    " prev_attestation_hash, digest, prev_hash)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (token["attestation_id"], token["spec_version"], token["spec_head_sha"],
                     token["gate_version"], token["gate_set_hash"], self.impl_repo,
                     self.impl_commit_sha, self.impl_tree_sha, token["evidence_manifest_hash"],
                     canonical_json(token["verdicts"]).decode(), self.issuer, token["issued_ns"],
                     token["prev_attestation_hash"], digest,
                     prev2[0] if prev2 else GENESIS_HASH),
                )
                self.transport.commit()
                self._conn.commit()
            except Exception as exc:
                self._conn.rollback()
                raise LedgerWriteError(f"attestation write failed: {exc}") from exc
        # AT-3: admission as event with event_id = attestation_id (idempotent).
        self._append_event(run_id, "attestation", "attestation.issued",
                           {"attestation_id": token["attestation_id"]},
                           event_id=token["attestation_id"])

    def get_attestation(self, run_id: str) -> dict:
        row = self._conn.execute(
            "SELECT payload_json FROM events WHERE run_id=? AND kind='attestation.issued'"
            " ORDER BY seq DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if row is None:
            raise AttestationError(f"no attestation for run {run_id}")
        att_id = json.loads(row[0])["attestation_id"]
        r = self._conn.execute(
            "SELECT spec_version, spec_head_sha, gate_version, gate_set_hash, impl_repo,"
            " impl_commit_sha, impl_tree_sha, evidence_manifest_hash, verdicts_json, issuer,"
            " issued_ns, prev_attestation_hash FROM attestations WHERE attestation_id=?",
            (att_id,),
        ).fetchone()
        token = {
            "attestation_id": att_id,
            "spec_version": r[0],
            "spec_head_sha": r[1],
            "gate_version": r[2],
            "gate_set_hash": r[3],
            "implementation": {"repo": r[4], "commit_sha": r[5], "tree_sha": r[6]},
            "evidence_manifest_hash": r[7],
            "verdicts": json.loads(r[8]),
            "issuer": r[9],
            "issued_ns": r[10],
            "prev_attestation_hash": r[11],
        }
        return token

    # -- introspection (for adapters/tests) ---------------------------------

    def events(self, run_id: str | None = None) -> list[dict]:
        q = "SELECT seq, event_id, run_id, domain, kind, payload_json, digest, prev_hash FROM events"
        if run_id is not None:
            rows = self._conn.execute(q + " WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        else:
            rows = self._conn.execute(q + " ORDER BY seq").fetchall()
        return [
            {"seq": s, "event_id": e, "run_id": r, "domain": d, "kind": k,
             "payload": json.loads(p), "digest": dg, "prev_hash": ph}
            for s, e, r, d, k, p, dg, ph in rows
        ]

    def close(self) -> None:
        self._conn.close()


__all__ = ["SQLiteResidualBackend", "GateSet", "LocalTransport", "GENESIS_HASH",
           "canonical_json", "sha256_hex"]
