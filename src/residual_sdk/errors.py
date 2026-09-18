"""RESIDUAL SDK exception hierarchy.

Fail-closed posture (per specs/INTEGRATION-CONTRACTS.md failure semantics):
UNKNOWN is neither PASS nor FAIL, and absence (timeout / unreachable core /
ledger write failure) is evidence — never silently treated as success.
"""


class ResidualError(Exception):
    """Base class for all residual-sdk errors."""


class CoreUnreachableError(ResidualError):
    """The RESIDUAL core / backend transport could not be reached.

    Raised before any run event is recorded. The caller's workload MUST NOT
    proceed: no attestation exists, no partial run state is trusted.
    """


class LedgerWriteError(ResidualError):
    """A write to the append-only evidence ledger failed.

    Fail-closed: the run is aborted and no attestation is issued. A run whose
    evidence is not durably recorded is treated as never having run.
    """


class GateFiredError(ResidualError):
    """A qualification gate returned a non-PASS verdict during the run.

    Attributes:
        gate_id: identifier of the gate that fired.
        verdict: one of ``FAIL``, ``UNKNOWN``, ``BLOCKED`` (never ``PASS``).
        module: the module call that triggered the gate, if any.
    """

    def __init__(self, gate_id: str, verdict: str, module: str | None = None):
        if verdict == "PASS":
            raise ValueError("GateFiredError cannot carry a PASS verdict")
        self.gate_id = gate_id
        self.verdict = verdict
        self.module = module
        super().__init__(
            f"gate {gate_id!r} fired with verdict {verdict}"
            + (f" on module {module!r}" if module else "")
        )


class AttestationError(ResidualError):
    """Attestation issuance or verification failed."""


class AdapterError(ResidualError):
    """An adapter (framework binding) violated the adapter contract."""
