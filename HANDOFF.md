# Handoff

## Goal

Validate `kdiag 0.9.0` on Deckhouse CSE Pro 1.74/Kubernetes 1.31 and apply only evidence-backed fixes from the next real snapshot.

## Implemented state

- Release details and exact behavior: `CHANGELOG-ru.md`, section `0.9.0`.
- Operator workflow and configuration: `README-ru.md`, `docs/UserGuide-ru.md`, `config/snapshot.example.json`.
- Authentication-config transient-race rationale: `docs/a.md`.
- Main implementation: `src/kdiag/{config,cli,orchestrator,kubernetes,node,rules,message_insights,report,rule_catalog}.py`.
- Regression coverage: `tests/test_{cli_progress,config,kubernetes,message_insights,node_config,node_etcd,report,rules}.py`.
- Built artifact: `dist/kdiag.pyz`; SHA-256 `80d9009930e5fdfd9948d44f930a2c32f0b97009675b072cb11be9240fefa5c4`.

## Current failure

None. Target-cluster canary has not been run.

## Current hypothesis

Deckhouse aliases and container-local CLIs should no longer create false missing evidence. Known success messages and a single authentication-config race should stay out of the operator report; repeated or structurally correlated failures should remain visible. This is verified synthetically, not yet against the user's next snapshot.

## Test results

- `env PYTHONPATH=src python3 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3 -m unittest discover -s tests -v` -> 115 tests passed.
- `python3 scripts/build.py` -> passed.
- `python3 dist/kdiag.pyz --version` -> `0.9.0`.
- `python3 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.12`.
- `python3 dist/kdiag.pyz rules list --json` -> 98 rules.

## Suggested skills

- `karpathy-guidelines` for targeted fixes after the Deckhouse canary.

## Next step

Run `python3 dist/kdiag.pyz snapshot -i inventory.ini --config config/snapshot.json -o kdiag-data`, then inspect the generated `report.md` and retain the collection for regression fixtures.
