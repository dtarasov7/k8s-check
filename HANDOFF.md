# Handoff

## Goal

After validating `kdiag 0.9.1` Cilium/etcd collection on real vanilla and Deckhouse clusters, evolve the snapshot into a tool that separates routine checks from incident analysis and ranks evidence-backed root-cause hypotheses.

## Changed files

- `src/kdiag/node.py` -> CRI Pod-aware Cilium discovery, absolute container CLI paths, equivalent-host-error replacement, and etcdctl fallback through the exact running container rootfs.
- `tests/test_node_config.py`, `tests/test_node_etcd.py` -> vanilla/Deckhouse Cilium and failed-etcd-exec regressions.
- `src/kdiag/__init__.py`, `CHANGELOG*.md`, `README*.md`, `docs/UserGuide*.md`, `docs/k8s-diagnostic-system-implementation-plan-no-llm.md`, `dist/kdiag.pyz` -> patch release `0.9.1` and documentation.
- Existing roadmap for snapshot, baseline, and continuous collection -> see `docs/k8s-diagnostic-system-implementation-plan-no-llm.md`.
- Existing LLM roadmap and privacy boundary -> see `docs/k8s-diagnostic-system-llm-implementation-plan.md` and `diagramms/llm-data-boundary-ru.puml`.

## Current failure

No local runtime failure. Real-cluster validation is still required for Cilium 1.14 (`kube-system/cilium-*`), Deckhouse Cilium 1.17 (`d8-cni-cilium/agent-*`), and Deckhouse etcd with rejected `crictl exec`.

## Current hypothesis

The smallest coherent next increment is one collection pipeline with explicit `--purpose check|incident` metadata and an optional incident window. `check` should emphasize active faults/configuration defects; `incident` should add temporal relevance and distinguish likely cause, consequence, concurrent issue, and unrelated history. Do not call a successful snapshot a baseline; baseline needs an explicit approval lifecycle.

Current limitations established by code review:

- correlation is eight fixed category pairs in a 15-minute window, scoped mostly to one node or Pod (`src/kdiag/normalize.py`);
- findings are ordered by severity/rule ID, not causal likelihood (`src/kdiag/rules.py`);
- Prometheus collects only alerts and runtime information, not range-query metric history (`src/kdiag/kubernetes.py`);
- the external LLM profile is reversible pseudonymization with fail-closed DLP, not guaranteed anonymity (`src/kdiag/llm_export.py`);
- rule metadata declares Kubernetes 1.24-1.31, so unbounded `1.24+` support is not yet an honest claim (`src/kdiag/rule_catalog.py`);
- Deckhouse adaptations are synthetic-test verified, but the target-cluster canary is still pending;
- Kubernetes API audit logs remain intentionally outside the snapshot scope.

## Test results

- `env PYTHONPATH=src python3 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3 -m unittest discover -s tests -q` -> 119 tests passed.
- `python3 scripts/build.py` -> passed; `dist/kdiag.pyz` SHA-256 `d557d85e7bc21483a8671d3d09af019844e541661d9f26e94f6fb562ff2919be`.
- `python3 dist/kdiag.pyz --version` -> `0.9.1`.
- `python3 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.12`; 98 rules.

## Suggested skills

- `karpathy-guidelines` for a minimal, test-driven implementation of purpose/window semantics.
- `create-plan` if the user asks to plan the broader Prometheus, causal-graph, baseline, and compatibility work before coding.

## Next step

Run `python3 dist/kdiag.pyz snapshot -i inventory.ini --config config/snapshot.json -o kdiag-data` on a target cluster and inspect Cilium command coverage plus `facts.etcd.transport` before starting purpose/window work.
