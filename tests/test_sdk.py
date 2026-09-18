import pytest

import residual_sdk as residual
from residual_sdk import (
    CoreUnreachableError,
    GateFiredError,
    LedgerWriteError,
    SQLiteResidualBackend,
    verify_attestation,
)


class DeadTransport(residual.LocalTransport):
    def ping(self):
        raise ConnectionRefusedError("no route to core")


class FailingCommitTransport(residual.LocalTransport):
    def commit(self):
        raise OSError("disk full")


def test_happy_path_attestation_verifies():
    backend = SQLiteResidualBackend(":memory:")
    with residual.run("spec@1.0.0", backend=backend) as run:
        run.module_call("llm:test", inputs={"prompt": "hi"})
    token = run.attestation
    report = verify_attestation(token)
    assert report.ok, report.failures
    assert token["verdicts"]["G0-BLOCKED-MODULE"] == "PASS"
    kinds = [e["kind"] for e in backend.events(run.run_id)]
    assert kinds == ["run.started", "module.called", "run.completed", "attestation.issued"]


def test_core_unreachable_fails_closed_no_events():
    backend = SQLiteResidualBackend(":memory:", transport=DeadTransport())
    with pytest.raises(CoreUnreachableError):
        with residual.run("spec@1.0.0", backend=backend):
            pytest.fail("workload must not run when core is unreachable")
    assert backend.events() == []


def test_ledger_write_failure_aborts_no_attestation():
    backend = SQLiteResidualBackend(":memory:", transport=FailingCommitTransport())
    r = residual.run("spec@1.0.0", backend=backend)
    with pytest.raises(LedgerWriteError):
        with r as run:
            run.module_call("llm:test")
    assert backend.events() == []
    with pytest.raises(residual.AttestationError):
        _ = r.attestation


def test_gate_fires_blocked_module_aborts_run():
    backend = SQLiteResidualBackend(
        ":memory:", gate_set=residual.GateSet(blocked_modules={"tool:shell"})
    )
    with pytest.raises(GateFiredError) as ei:
        with residual.run("spec@1.0.0", backend=backend) as run:
            run.module_call("tool:shell")
    assert ei.value.verdict == "BLOCKED"
    token = run.attestation
    assert token["verdicts"]["G0-BLOCKED-MODULE"] == "BLOCKED"
    kinds = [e["kind"] for e in backend.events(run.run_id)]
    assert "gate.fired" in kinds and "attestation.issued" in kinds
    completed = [e for e in backend.events(run.run_id) if e["kind"] == "run.completed"]
    assert completed[0]["payload"]["outcome"] == "aborted"


def test_empty_run_completion_gate_fails():
    backend = SQLiteResidualBackend(":memory:")  # require_module_call default True
    with residual.run("spec@1.0.0", backend=backend) as run:
        pass
    assert run.attestation["verdicts"]["G0-MODULE-CALL-REQUIRED"] == "FAIL"


def test_unknown_verdict_never_coerced():
    with pytest.raises(residual.AttestationError):
        residual.build_attestation(
            spec_version="1.0.0",
            spec_head_sha="a" * 40,
            gate_version="G0@1.0.0",
            gate_set_hash="b" * 64,
            impl_repo="r",
            impl_commit_sha="c" * 40,
            impl_tree_sha="d" * 40,
            evidence_manifest_hash="e" * 64,
            verdicts={"G0": "PROBABLY_FINE"},
            issuer="test",
        )


def test_verify_detects_tampered_token():
    backend = SQLiteResidualBackend(":memory:")
    with residual.run("spec@1.0.0", backend=backend) as run:
        run.module_call("llm:test")
    token = dict(run.attestation)
    token["verdicts"] = {**token["verdicts"], "G0-MODULE-CALL-REQUIRED": "FAIL"}
    report = verify_attestation(token)
    assert not report.ok
    assert report.checks["content_address"] is False


def test_exception_in_body_still_terminates_run():
    backend = SQLiteResidualBackend(":memory:")
    with pytest.raises(RuntimeError):
        with residual.run("spec@1.0.0", backend=backend) as run:
            run.module_call("llm:test")
            raise RuntimeError("user bug")
    completed = [e for e in backend.events(run.run_id) if e["kind"] == "run.completed"]
    assert completed[0]["payload"]["outcome"] == "error"


def test_manual_event_emission():
    backend = SQLiteResidualBackend(":memory:")
    with residual.run("spec@1.0.0", backend=backend) as run:
        run.emit_event("human_checkpoint", {"approved": True})
    modules = [e for e in backend.events(run.run_id) if e["kind"] == "module.called"]
    assert modules[0]["payload"]["module"] == "custom:human_checkpoint"
