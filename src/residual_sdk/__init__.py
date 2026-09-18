"""residual-sdk: framework-agnostic RESIDUAL attestation SDK."""

from .attestation import (
    GENESIS_HASH,
    TOKEN_SCHEMA_VERSION,
    VALID_VERDICTS,
    VerificationReport,
    build_attestation,
    canonical_json,
    compute_attestation_id,
    sha256_hex,
    verify_attestation,
)
from .backend import ResidualBackend
from .errors import (
    AdapterError,
    AttestationError,
    CoreUnreachableError,
    GateFiredError,
    LedgerWriteError,
    ResidualError,
)
from .ledger import GateSet, LocalTransport, SQLiteResidualBackend
from .run import Run, run

__version__ = "1.0.0"

__all__ = [
    "run", "Run", "ResidualBackend", "SQLiteResidualBackend", "GateSet", "LocalTransport",
    "build_attestation", "verify_attestation", "compute_attestation_id", "canonical_json",
    "sha256_hex", "VerificationReport", "VALID_VERDICTS", "GENESIS_HASH",
    "TOKEN_SCHEMA_VERSION",
    "ResidualError", "CoreUnreachableError", "LedgerWriteError", "GateFiredError",
    "AttestationError", "AdapterError",
]
