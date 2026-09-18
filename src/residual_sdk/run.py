"""Run lifecycle API: context manager + manual event emission.

Quickstart:

    import residual_sdk as residual

    backend = residual.SQLiteResidualBackend("evidence.db")
    with residual.run("my-spec@1.0.0", backend=backend) as run:
        run.module_call("llm:gpt-4o", inputs={"prompt": "..."})
    print(run.attestation)

Fail-closed semantics (INTEGRATION-CONTRACTS failure semantics):
  * backend unreachable at run start -> CoreUnreachableError, workload never runs;
  * a gate verdict of FAIL/UNKNOWN/BLOCKED aborts the run (GateFiredError);
  * ledger write failure -> LedgerWriteError, run aborted, no attestation;
  * exceptions inside the `with` body still produce a terminal event
    (outcome='error') with the recorded verdicts; the original exception
    propagates unchanged.
"""

from __future__ import annotations

import uuid

from .attestation import canonical_json, sha256_hex
from .backend import ResidualBackend
from .errors import AttestationError, GateFiredError
from .ledger import SQLiteResidualBackend


class Run:
    """Handle for one attested run. Created by :func:`run`."""

    def __init__(self, spec_id: str, backend: ResidualBackend, run_id: str | None = None,
                 metadata: dict | None = None):
        self.spec_id = spec_id
        self.backend = backend
        self.run_id = run_id or str(uuid.uuid4())
        self.metadata = metadata or {}
        self._started = False
        self._terminal = False
        self._attestation: dict | None = None

    def __enter__(self) -> "Run":
        self.backend.on_run_start(self.run_id, self.spec_id, self.metadata)
        self._started = True
        return self

    def module_call(self, module: str, inputs=None, call_id: str | None = None) -> str:
        """Emit a module call event; aborts the run if a gate fires.

        Returns the gate verdict (always "PASS" on return — anything else raises).
        """
        if not self._started or self._terminal:
            raise AttestationError("module_call outside of an active run")
        digest = sha256_hex(canonical_json(inputs if inputs is not None else {}))
        verdict = self.backend.on_module_call(
            self.run_id, module, call_id or str(uuid.uuid4()), digest
        )
        if verdict != "PASS":
            self._abort(f"gate verdict {verdict} on module {module!r}",
                        gate_id="G0-BLOCKED-MODULE", verdict=verdict, module=module)
        return verdict

    def emit_event(self, kind: str, payload: dict) -> None:
        """Manual event emission: recorded as a module-scoped custom event."""
        if not self._started or self._terminal:
            raise AttestationError("emit_event outside of an active run")
        self.backend.on_module_call(
            self.run_id, f"custom:{kind}", str(uuid.uuid4()),
            sha256_hex(canonical_json(payload)),
        )

    def _abort(self, reason: str, *, gate_id: str, verdict: str, module: str | None = None) -> None:
        if not self._terminal:
            self._terminal = True
            try:
                self.backend.on_run_complete(self.run_id, "aborted")
            finally:
                self._capture_attestation()
        raise GateFiredError(gate_id, verdict, module)

    def _capture_attestation(self) -> None:
        try:
            self._attestation = self.backend.get_attestation(self.run_id)
        except AttestationError:
            self._attestation = None

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._terminal:
            return False  # GateFiredError / original exception propagates
        self._terminal = True
        outcome = "success" if exc_type is None else "error"
        self.backend.on_run_complete(self.run_id, outcome)
        self._capture_attestation()
        return False  # never suppress user exceptions

    @property
    def attestation(self) -> dict:
        """The attestation token for this run (available after exit/abort)."""
        if self._attestation is None:
            raise AttestationError(f"no attestation for run {self.run_id}")
        return self._attestation


def run(spec_id: str, *, backend: ResidualBackend | None = None,
        run_id: str | None = None, metadata: dict | None = None) -> Run:
    """Open an attested run. Defaults to an in-memory SQLite backend."""
    return Run(spec_id, backend or SQLiteResidualBackend(":memory:"), run_id, metadata)
