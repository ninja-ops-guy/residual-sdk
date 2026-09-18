"""Runs the canonical adapter conformance suite against SQLiteResidualBackend.

Vendored suite: tests/vendor/adapter_conformance_suite.py
SHA-256: b8e14c9babc0eb4c7e07b04768afdda6e49c7a404e6e4ba1fc4f700f276b290e
(canonical source: residual-spec conformance/adapters/, ADAPTERS-CONFORMANCE 1.0.0)
"""

import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "vendor"))

from adapter_conformance_suite import AdapterConformanceTests, AdapterHandle

from residual_sdk import (
    CoreUnreachableError,
    GateSet,
    LedgerWriteError,
    SQLiteResidualBackend,
)


class _ChaosTransport:
    def __init__(self):
        self.reachable = True
        self.writable = True

    def ping(self):
        if not self.reachable:
            raise ConnectionRefusedError("core unreachable")
        return True

    def commit(self):
        if not self.writable:
            raise OSError("ledger commit failed")


class SDKHandle(AdapterHandle):
    core_unreachable_exc = CoreUnreachableError
    ledger_write_exc = LedgerWriteError
    gate_fired_exc = LedgerWriteError  # sdk surfaces terminal-violations as ledger errors

    def __init__(self):
        self.transport = _ChaosTransport()
        self.blocked: set[str] = set()
        self._new_backend()

    def _new_backend(self):
        self.backend = SQLiteResidualBackend(
            ":memory:",
            gate_set=GateSet(blocked_modules=self.blocked),
            transport=self.transport,
        )

    # -- suite driving -------------------------------------------------------
    def start_run(self, run_id, spec_id):
        self.backend.on_run_start(run_id, spec_id)

    def module_call(self, run_id, module):
        return self.backend.on_module_call(run_id, module, f"call-{module}", "0" * 64)

    def complete_run(self, run_id, outcome="success"):
        self.backend.on_run_complete(run_id, outcome)

    def events(self, run_id):
        return self.backend.events(run_id)

    def get_attestation(self, run_id):
        return self.backend.get_attestation(run_id)

    # -- chaos ---------------------------------------------------------------
    def break_core(self):
        self.transport.reachable = False

    def heal_core(self):
        self.transport.reachable = True

    def break_ledger(self):
        self.transport.writable = False

    def heal_ledger(self):
        self.transport.writable = True

    def block_module(self, module):
        # gates are fixed at backend construction; rebuild with the module blocked
        self.blocked.add(module)
        self._new_backend()

    def try_mutate_ledger(self):
        self.backend._conn.execute("UPDATE events SET kind='x'")
        self.backend._conn.execute("DELETE FROM events")


class TestSDKConformance(AdapterConformanceTests):
    def make_handle(self):
        return SDKHandle()


class MutantCoercingBackend(SQLiteResidualBackend):
    """Deliberately non-compliant: coerces non-PASS verdicts to PASS."""

    def _issue_attestation(self, run_id):
        super()._issue_attestation(run_id)
        # retroactive coercion in stored token (would also break append-only
        # in a real ledger; here we corrupt the read path instead)
        orig_get = self.get_attestation

        def coerced(rid):
            tok = orig_get(rid)
            tok["verdicts"] = {g: "PASS" for g in tok["verdicts"]}
            return tok

        self.get_attestation = coerced  # type: ignore[method-assign]


class MutantSDKHandle(SDKHandle):
    def _new_backend(self):
        self.backend = MutantCoercingBackend(
            ":memory:",
            gate_set=GateSet(blocked_modules=self.blocked),
            transport=self.transport,
        )


class TestMutantRejected(unittest.TestCase):
    """Mutation evidence: a verdict-coercing SDK variant MUST fail the suite."""

    def test_mutant_detected(self):
        class Bound(AdapterConformanceTests):
            def make_handle(self):
                return MutantSDKHandle()

        result = unittest.TestResult()
        unittest.TestLoader().loadTestsFromTestCase(Bound).run(result)
        failed = {t._testMethodName for t, _ in result.failures + result.errors}
        self.assertGreater(result.testsRun, 0)
        self.assertIn("test_verdict_not_coerced", failed,
                      f"coercing mutant not detected; failures={failed}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
