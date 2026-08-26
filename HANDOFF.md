# Handoff

## Goal

Validate `kdiag 0.7.1` on the target Deckhouse cluster after the PATH, command-status, ledger, and Node-identity fixes.

## Changed files

- `src/kdiag/runner.py`, `src/kdiag/node.py`, `src/kdiag/orchestrator.py` -> Deckhouse safe PATH, clear unavailable-command errors, and persisted etcd collection mode.
- `src/kdiag/node_identity.py`, `src/kdiag/normalize.py`, `src/kdiag/rules.py` -> unambiguous inventory hostname/FQDN to Kubernetes Node matching, plus cautious findings for kube-apiserver authentication-config read failures and kernel/security-agent ptrace alerts.
- `src/kdiag/report.py`, `src/kdiag/util.py` -> per-rule evidence dependencies for `unknown` and compact component-balanced unknown fingerprints with readable angle-bracket placeholders.
- `src/kdiag/__init__.py`, `src/kdiag/rule_catalog.py` -> application `0.7.1`, rule pack `2026.08.8`, 98 rules.
- `tests/test_{runner,report,normalize,rules,node_smoke}.py` -> regression coverage for the fixes.
- `README*.md`, `docs/UserGuide*.md`, `docs/autonomous-rule-pack.md`, implementation plan, and `CHANGELOG*.md` -> release documentation.
- `dist/kdiag.pyz` -> rebuilt artifact; SHA-256 `883e9bd2a7a911338fd4fc481b64f33e58788b45d12efb32795cc65f7abf8bdd`.

## Current failure

None. A target-cluster canary has not been rerun.

## Current hypothesis

Deckhouse runtime tools in `/opt/deckhouse/bin` will now be collected; remaining `unsupported` entries should indicate genuinely absent userspace clients. Ledger `unknown` entries should be limited to rules whose declared evidence is missing.

## Test results

- `env PYTHONPATH=src python3.8 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3.8 -m unittest discover -s tests -v` -> 97 tests passed.
- `python3.8 scripts/build.py` -> passed.
- `python3.8 dist/kdiag.pyz --version` -> `0.7.1`.
- `python3.8 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.8`.
- `python3.8 dist/kdiag.pyz rules list` -> 98 rules.

## Suggested skills

- `karpathy-guidelines` for small, regression-tested follow-up fixes after the Deckhouse canary.

## Next step

Run one bounded snapshot against the same Deckhouse inventory and compare command coverage plus ledger counts with the 0.7.0 report.
