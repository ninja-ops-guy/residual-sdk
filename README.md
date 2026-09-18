# residual-sdk

Framework-agnostic Python SDK for RESIDUAL run attestation. Implements the
adapter contract in `ninja-ops-guy/residual-spec` `adapters/interface.md`
(branch `lane/1-adapters`) against the attestation token format of
`specs/ATTESTATION-VERSIONING.md`.

## Quickstart (<20 lines to first attestation)

```python
import residual_sdk as residual

backend = residual.SQLiteResidualBackend("evidence.db")

with residual.run("my-agent-spec@1.0.0", backend=backend) as run:
    run.module_call("llm:gpt-4o", inputs={"prompt": "summarize Q3"})

token = run.attestation
report = residual.verify_attestation(token)
assert report.ok, report.failures
print(token["attestation_id"], token["verdicts"])
```

Manual emission API: `run.emit_event(kind, payload)` inside the context
manager. `ResidualBackend` (ABC) is the integration point for custom cores;
`SQLiteResidualBackend` is the reference backend (append-only, hash-chained,
idempotent admission, attestation issuance per ATTESTATION-VERSIONING §4.1).

## What the attestation proves / does not prove

**Proves** (given a verifying consumer):
- A specific backend, bound to `spec_head_sha` + `gate_set_hash`, recorded
  this exact ordered event stream for this run, and the stated gates produced
  the stated verdicts (verbatim — UNKNOWN/BLOCKED are never coerced).
- The token is content-addressed and immutable; tampering breaks
  `attestation_id` recomputation (`verify_attestation`).

**Does NOT prove**:
- That the recorded events reflect reality (garbage in, attested garbage —
  the SDK attests the record, not the world).
- Lineage continuity (`prev_attestation_hash` walking) or spec-ancestor
  checks — those require spec-repo access; `verify_attestation` covers only
  offline checks (content address, vocabulary, formats, optional known-set
  membership).
- Anything about runs whose ledger writes failed: those abort fail-closed
  with NO attestation.
- Crash durability of the in-memory backend (use a file path for WAL-backed
  durability).

## Error semantics (fail-closed)

| Failure | Behavior |
|---|---|
| Core unreachable at run start | `CoreUnreachableError`; workload must not run; zero events |
| Gate fires (FAIL/UNKNOWN/BLOCKED) | `GateFiredError`; run aborted; attestation records verdict verbatim |
| Ledger write fails | `LedgerWriteError`; rollback; NO attestation |
| Corrupt ledger at open | `LedgerWriteError` at backend construction (hash-chain verify, MS-00 I-6) |

## Troubleshooting

- `CoreUnreachableError` on `with residual.run(...)`: your backend's
  transport ping failed; nothing was recorded — fix connectivity, retry.
- `AttestationError: no attestation for run ...`: the run aborted or a
  ledger write failed; absence of attestation is the intended fail-closed
  signal, not a bug.
- `GateFiredError`: inspect `run.attestation["verdicts"]` and the
  `gate.fired` event payload for the gate/module/verdict.
- `LedgerWriteError: run ... already terminal`: you completed the run twice
  (exactly-one-terminal invariant, MS-00 I-1).

## Migration from direct core use

If you currently drive `residual-agent-harness` core APIs directly:

1. Keep your core; wrap it in a thin `ResidualBackend` subclass mapping
   `on_run_start/on_module_call/on_run_complete/get_attestation` to your
   existing calls. The four methods are the entire surface.
2. Replace ad-hoc verdict strings with the vocabulary
   `PASS | FAIL | UNKNOWN | BLOCKED` — anything else raises at issuance.
3. Move token construction to `build_attestation` (content addressing and
   field validation are built in); verify with `verify_attestation`.
4. Run the conformance suite (`conformance/adapters/` in residual-spec,
   vendored at `tests/vendor/`) against your backend by subclassing
   `AdapterConformanceTests` — see `tests/test_conformance_binding.py`.

## Tests

```
pip install -e . pytest
python3 -m pytest tests/ -q     # 20 passed (incl. conformance binding + mutant rejection)
```

CI YAML is not in the tree (token workflow-scope limitation); see RELEASES.md.
