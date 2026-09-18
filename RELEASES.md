# Releases

## 1.0.0 (tag intent: `v1.0.0`)

No git-tag creation tool was available to the authoring agent; per swarm
convention the tag intent is recorded here instead. Intended tag:
`v1.0.0` on the commit that lands this file on the default branch.

- Initial release: `run()` context manager, manual `emit_event`,
  `ResidualBackend` ABC, `SQLiteResidualBackend` reference backend,
  `build_attestation` / `verify_attestation`, fail-closed error hierarchy.
- Passes ADAPTERS-CONFORMANCE 1.0.0 (residual-spec `conformance/adapters/`,
  vendored suite SHA-256 b8e14c9babc0eb4c7e07b04768afdda6e49c7a404e6e4ba1fc4f700f276b290e).
- Mutation-verified: verdict-coercing backend mutant fails
  `test_verdict_not_coerced` (see tests/test_conformance_binding.py).

Suggested CI (not in tree — workflow-scope token limitation):

```yaml
name: tests
on: [push, pull_request]
jobs:
  pytest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e . pytest && python3 -m pytest tests/ -q
```
