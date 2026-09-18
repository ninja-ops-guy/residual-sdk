"""Attestation token build/verify helpers.

Implements the token record defined in specs/ATTESTATION-VERSIONING.md §2
(residual-spec, lane/3-governance). Tokens are content-addressed and
immutable; UNKNOWN/BLOCKED verdicts are never coerced to PASS.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field

from .errors import AttestationError

VALID_VERDICTS = frozenset({"PASS", "FAIL", "UNKNOWN", "BLOCKED"})
GENESIS_HASH = "0" * 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_FIELDS = (
    "attestation_id",
    "spec_version",
    "spec_head_sha",
    "gate_version",
    "gate_set_hash",
    "implementation",
    "evidence_manifest_hash",
    "verdicts",
    "issued_ns",
    "issuer",
    "prev_attestation_hash",
)

TOKEN_SCHEMA_VERSION = "1.0.0"


def canonical_json(obj) -> bytes:
    """Canonical JSON encoding: sorted keys, minimal separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_attestation_id(token: dict) -> str:
    """sha256 of the canonical form of the token minus ``attestation_id``."""
    body = {k: v for k, v in token.items() if k != "attestation_id"}
    return sha256_hex(canonical_json(body))


def build_attestation(
    *,
    spec_version: str,
    spec_head_sha: str,
    gate_version: str,
    gate_set_hash: str,
    impl_repo: str,
    impl_commit_sha: str,
    impl_tree_sha: str,
    evidence_manifest_hash: str,
    verdicts: dict[str, str],
    issuer: str,
    prev_attestation_hash: str = GENESIS_HASH,
    issued_ns: int | None = None,
) -> dict:
    """Construct an attestation token, computing its content address.

    Raises AttestationError if any verdict is outside the allowed vocabulary.
    """
    for gate, verdict in verdicts.items():
        if verdict not in VALID_VERDICTS:
            raise AttestationError(
                f"verdict for gate {gate!r} is {verdict!r}; must be one of {sorted(VALID_VERDICTS)}"
            )
    if not _HEX64.match(gate_set_hash):
        raise AttestationError("gate_set_hash must be 64 lowercase hex chars")
    if not _HEX64.match(prev_attestation_hash):
        raise AttestationError("prev_attestation_hash must be 64 lowercase hex chars")
    if not _HEX40.match(spec_head_sha):
        raise AttestationError("spec_head_sha must be a 40-hex git commit SHA")
    token = {
        "spec_version": spec_version,
        "spec_head_sha": spec_head_sha,
        "gate_version": gate_version,
        "gate_set_hash": gate_set_hash,
        "implementation": {
            "repo": impl_repo,
            "commit_sha": impl_commit_sha,
            "tree_sha": impl_tree_sha,
        },
        "evidence_manifest_hash": evidence_manifest_hash,
        "verdicts": dict(verdicts),
        "issued_ns": issued_ns if issued_ns is not None else time.time_ns(),
        "issuer": issuer,
        "prev_attestation_hash": prev_attestation_hash,
    }
    token["attestation_id"] = compute_attestation_id(token)
    return token


@dataclass
class VerificationReport:
    """Result of verifying an attestation token.

    ``ok`` is True only if every check passed. Individual check outcomes are
    kept verbatim — UNKNOWN/BLOCKED-style ambiguity surfaces as a failed check,
    never silently as success.
    """

    ok: bool
    checks: dict[str, bool] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


def verify_attestation(
    token: dict,
    *,
    known_spec_head_shas: set[str] | None = None,
    expected_gate_set_hash: str | None = None,
) -> VerificationReport:
    """Verify an attestation token per ATTESTATION-VERSIONING.md §2 rule 4.

    Checks performed:
      1. all required fields present;
      2. ``attestation_id`` recomputes over the canonical body;
      3. verdict vocabulary is exactly PASS|FAIL|UNKNOWN|BLOCKED, verbatim;
      4. hash/commit field formats (64-hex / 40-hex);
      5. optional: ``spec_head_sha`` is in a caller-supplied known set
         (stand-in for the ancestor-of-tagged-release check, which requires
         spec-repo access and is out of scope for offline verification);
      6. optional: ``gate_set_hash`` matches a caller-recomputed value.

    Lineage walking (``prev_attestation_hash`` chain) requires access to the
    issuing ledger and is NOT performed by this helper.
    """
    checks: dict[str, bool] = {}
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = ""):
        checks[name] = bool(ok)
        if not ok:
            failures.append(f"{name}: {detail}" if detail else name)

    missing = [f for f in REQUIRED_FIELDS if f not in token]
    check("required_fields", not missing, f"missing {missing}")
    if missing:
        return VerificationReport(ok=False, checks=checks, failures=failures)

    recomputed = compute_attestation_id(token)
    check(
        "content_address",
        recomputed == token["attestation_id"],
        f"recomputed {recomputed} != claimed {token['attestation_id']}",
    )

    verdicts = token["verdicts"]
    vocab_ok = isinstance(verdicts, dict) and all(v in VALID_VERDICTS for v in verdicts.values())
    check("verdict_vocabulary", vocab_ok, f"verdicts={verdicts}")

    impl = token["implementation"]
    fmt_ok = (
        _HEX64.match(token["gate_set_hash"]) is not None
        and _HEX64.match(token["prev_attestation_hash"]) is not None
        and _HEX64.match(token["evidence_manifest_hash"]) is not None
        and _HEX40.match(token["spec_head_sha"]) is not None
        and _HEX40.match(impl.get("commit_sha", "")) is not None
        and _HEX40.match(impl.get("tree_sha", "")) is not None
    )
    check("field_formats", fmt_ok)

    if known_spec_head_shas is not None:
        check(
            "spec_head_known",
            token["spec_head_sha"] in known_spec_head_shas,
            f"{token['spec_head_sha']} not in known set",
        )
    if expected_gate_set_hash is not None:
        check(
            "gate_set_hash_match",
            token["gate_set_hash"] == expected_gate_set_hash,
        )
    return VerificationReport(ok=all(checks.values()), checks=checks, failures=failures)
