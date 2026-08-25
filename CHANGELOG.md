# Changelog

All notable changes to `kdiag` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `collection.collect_cgroup=false` and `--skip-cgroup`: direct cgroup facts are not collected, cgroup events/correlations and related findings are suppressed, and the selected mode is recorded in collections and reports.
- Added disableable `--progress off|summary|detail` execution visualization on `stderr`, covering phases, per-node state, node evidence categories, and Kubernetes API source statuses.
- Added Deckhouse `containerd-deckhouse.service` support alongside vanilla `containerd.service` and `crio.service`; expanded the rule-pack scope to Kubernetes 1.24–1.31.

### Fixed

- Runtime units with `LoadState=not-found` no longer produce `runtime_unavailable` or `node.runtime_inactive`; an inactive alternative runtime is ignored while another loaded runtime is working.
- Static systemd state no longer gains artificial temporal causality in 15-minute correlations; temporal correlation now requires an actual timestamped event.

### Documentation

- Added step-by-step creation of a dedicated kubeconfig for the `kdiag-reader` ServiceAccount, including a short-lived TokenRequest, embedded CA, `0600` file mode, token renewal, and RBAC verification.
- Added a separate guide with exact read-only commands for manual node cgroup checks and a sanitized result template.

## [0.6.0] - 2026-08-24

### Added

- Added `kdiag llm analyze-local` for verified prepared local packages and OpenAI-compatible chat-completions services on literal loopback addresses.
- Added bounded response handling, evidence-ID/contract validation, mutating-command rejection, Markdown rendering, and SHA-256 manifests for local analysis results.
- Added a hardened llama.cpp systemd deployment example with loopback/offline defaults, an unprivileged service identity, disabled logging/UI/agent mode, and bilingual installation guidance for RED OS.

### Security

- The local client disables proxies and redirects, never sends collection paths, rejects non-loopback endpoints, and does not execute model suggestions.
- New local packages use `prepared/` instead of the misleading `export/`; `analyze-local` remains compatible with legacy local `export/` packages created by version 0.5.0.

## [0.5.0] - 2026-08-24

### Added

- Added the first optional LLM integration stage: minimized, size-bounded incident packages and versioned prompts for `fast-triage` and `deep-analysis`.
- Added a fail-closed external profile with incident-local pseudonyms, outbound DLP, a private `0600` token map, export manifest validation, and exact restoration of known tokens in a manually saved response.
- Added `kdiag llm prepare`, `llm validate-export`, and `llm import-response`; no model runtime, browser automation, or external network client is included.
- Added response-contract checks for evidence IDs and mutating commands; raw external responses remain preserved as untrusted audit input.

### Security

- External packages remove known internal host, Kubernetes object, account, IP/MAC/CIDR, DNS, URL, UID, host-path, and endpoint-port values while retaining diagnostic component names and versions.

## [0.4.0] - 2026-08-24

### Added

- English project README corresponding to the Russian README.
- English and Russian PlantUML architecture diagrams covering system context, components, snapshot execution, and the evidence-processing pipeline.
- English and Russian changelogs.
- Expanded the autonomous rule pack to 93 checks: Pod/init-container lifecycle, rollout failures, PDB state, CRI readiness and inventory, resolver/CoreDNS failures, Prometheus health, version skew, kubelet certificate rotation, and etcd lag/capacity/fragmentation/version drift.
- Added read-only Cilium service-map comparison for kube-proxy-free clusters. Missing kube-proxy is accepted when Cilium replacement is enabled; only an explicitly disabled replacement is a fact finding.
- Added prioritized current/previous logs for unhealthy system and init containers, bounded CoreDNS configuration projection, and concrete evidence references for the new findings.

## [0.3.0] - 2026-08-24

### Added

- One-time, bounded Kubernetes and RED OS emergency snapshot collection.
- Parallel node collection over `scp`, `ssh`, and non-interactive `sudo` using a standard-library-only Python zip application.
- Read-only Kubernetes collection for core, workload, discovery, control-plane, storage, networking, and selected Cilium resources.
- Bounded system and explicitly allowlisted application Pod logs.
- Optional, non-fatal Prometheus evidence collection.
- Read-only stacked-etcd status, health, and alarm collection for standard kubeadm layouts.
- Offline event normalization, 15-minute scoped correlation, unknown-message fingerprints, and a versioned deterministic rule pack.
- Findings classified as facts, correlations, or hypotheses with evidence and recommendations.
- JSON, gzip/JSON, and Markdown outputs with a coverage matrix.
- SHA-256 collection manifest generation and verification.
- Commands for rebuilding reports, listing and explaining rules, and running the built-in synthetic self-test.
- Dedicated read-only Kubernetes RBAC example and bilingual user guides.

### Security

- Kubernetes Secrets, `pods/exec`, mutation verbs, automatic remediation, and private-key contents are excluded from collection.
- Application namespaces require an explicit log allowlist.
- Command execution uses fixed argument lists, bounded output, timeouts, and strict SSH host-key checking.
