"""ResidualBackend abstract interface.

This is the SDK-side mirror of adapters/interface.md in ninja-ops-guy/residual-spec
(branch lane/1-adapters). Every framework adapter drives a ResidualBackend;
the backend owns the evidence ledger and attestation issuance.

Contract (normative, mirrors the spec):
  * on_run_start MUST be called before any on_module_call for that run_id.
  * on_module_call returns a gate verdict: PASS | FAIL | UNKNOWN | BLOCKED.
    UNKNOWN/BLOCKED is never coerced to PASS (INTEGRATION-CONTRACTS invariant 8).
  * on_run_complete is terminal; exactly once per run (success or abort).
  * get_attestation returns the token (ATTESTATION-VERSIONING §2) or raises.
  * All failures are fail-closed: unreachable core -> CoreUnreachableError;
    ledger write failure -> LedgerWriteError; no attestation on aborted runs
    unless the abort verdicts are recorded (FAIL/UNKNOWN/BLOCKED verbatim).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

VALID_VERDICTS = frozenset({"PASS", "FAIL", "UNKNOWN", "BLOCKED"})


class ResidualBackend(ABC):
    """Abstract adapter target: the RESIDUAL core as seen by a framework."""

    @abstractmethod
    def on_run_start(self, run_id: str, spec_id: str, metadata: dict[str, Any] | None = None) -> None:
        """Record the start of an agent run.

        MUST raise CoreUnreachableError if the core cannot be reached
        (fail-closed: the caller must not proceed with the workload).
        """

    @abstractmethod
    def on_module_call(
        self,
        run_id: str,
        module: str,
        call_id: str,
        inputs_digest: str,
    ) -> str:
        """Record a module (tool/LLM/sub-agent) call and return its gate verdict.

        Returns one of PASS | FAIL | UNKNOWN | BLOCKED.
        MUST raise LedgerWriteError if the evidence ledger write fails.
        """

    @abstractmethod
    def on_run_complete(self, run_id: str, outcome: str) -> None:
        """Record the terminal outcome of a run.

        ``outcome`` is one of: ``success``, ``error``, ``aborted``.
        Exactly one terminal event per run (MS-00 I-1).
        MUST raise LedgerWriteError if the evidence ledger write fails.
        """

    @abstractmethod
    def get_attestation(self, run_id: str) -> dict[str, Any]:
        """Return the attestation token for a completed run.

        The token MUST conform to specs/ATTESTATION-VERSIONING.md §2.
        MUST raise AttestationError if no attestation exists for the run.
        """
