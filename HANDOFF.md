# Handoff

## Goal

Validate `kdiag 0.8.0` offline message-insight cards and corrected Deckhouse DNS smoke filtering on the target cluster.

## Changed files

- `src/kdiag/message_insights.py` -> embedded offline catalogue and local Pod/Event/readyz/EndpointSlice/journal correlations for routine, observe, actionable, and security messages.
- `src/kdiag/normalize.py` -> bounded occurrence/time/Node/Pod context for known messages and suppression of the actual `smoke-mini-*` Deckhouse probe only.
- `src/kdiag/report.py` -> message-insight JSON/Markdown output with decision conditions, counter-evidence, missing checks, and explicit frequency-estimate ranges.
- `src/kdiag/kubernetes.py` -> allowlisted `imagePullSecrets` names for local pull-failure triage; Secret objects/content remain excluded.
- `src/kdiag/__init__.py`, `src/kdiag/rule_catalog.py` -> application `0.8.0`, rule pack `2026.08.10`, 98 rules.
- `tests/test_{message_insights,report,kubernetes,rules}.py` -> regression coverage for catalogue, enrichment, rendering, projection, and DNS suppression.
- `README*.md`, `docs/UserGuide*.md`, `docs/autonomous-rule-pack.md`, implementation plan, and `CHANGELOG*.md` -> release documentation.
- `dist/kdiag.pyz` -> rebuilt artifact; SHA-256 `78c5abf51e22001b497eb7475531b41ad6d86156e83d9f1b1ea649a059559bff`.

## Current failure

None. A target-cluster canary has not been rerun.

## Current hypothesis

Known screenshot templates should now appear as bounded offline triage cards rather than opaque unknown heavy hitters. `smoke-mini-*` errors should remain only in raw confidential logs. Missing Kubernetes sources should be reported as missing checks rather than inferred health.

## Test results

- `python3.8 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3.8 -m unittest discover -s tests -v` -> 104 tests passed.
- `python3.8 scripts/build.py` -> passed.
- `python3.8 dist/kdiag.pyz --version` -> `0.8.0`.
- `python3.8 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.10`.
- `python3.8 dist/kdiag.pyz rules list` -> 98 rules.

## Suggested skills

- `karpathy-guidelines` for small, regression-tested follow-up fixes after the Deckhouse canary.

## Next step

Run one bounded snapshot against the same Deckhouse inventory and inspect `Офлайн-разбор сообщений`, `message_insights`, and the `dns_smoke_events_suppressed` counter.
