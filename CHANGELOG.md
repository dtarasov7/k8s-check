# Changelog

All notable changes to `kdiag` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-08-26

### Added

- Added a deterministic offline message-insight catalogue for common Deckhouse/Kubernetes log templates. Cards classify routine, observe, actionable, and security messages and provide an explanation, decision condition, recommendation, bounded examples, occurrence range, timestamps/rate, affected Node/Pod scope, local correlations, counter-evidence, and missing checks.
- Message insights correlate locally available Pod readiness/restarts, Events, API readyz, EndpointSlice readiness, and categorized journal errors. Pod `imagePullSecrets` names are retained by the allowlist projection, while Secret objects and contents remain uncollected.

### Fixed

- Corrected the Deckhouse DNS smoke-query suppression to the actual `smoke-mini-*` name. Suppression affects only derived normalized events/findings; confidential raw evidence remains unchanged.
- Approximate fingerprint counts are now displayed as a guaranteed minimum and estimated upper bound with an explicit algorithmic error explanation instead of the ambiguous `max error` label.

### Documentation

- Documented the offline triage-card contract and its limits: cards are not findings, do not require an LLM or network access, and cannot supply missing source evidence or product/version knowledge absent from the embedded catalogue.

## [0.7.2] - 2026-08-26

### Fixed

- Kubernetes bundles with aggregate status `unreachable` are now loaded during report generation, preserving per-source statuses such as `failed` or `timeout` and errors such as `forbidden` instead of incorrectly reporting every dependent source as `missing`.
- Rule-ledger gaps now include their status, group the same unavailable node command across nodes, and summarize the most common causes of `unknown`. Rules that depend on an intentionally disabled Kubernetes collector are `not_applicable`.
- CoreDNS error events for the intentional `smoke-mini-*` DNS probe are suppressed from normalized derived output and findings. Original log evidence remains unchanged in the confidential collection bundle.

## [0.7.1] - 2026-08-26

### Added

- Added cautious fact findings for repeated kube-apiserver authentication-config read failures and kernel/security-agent ptrace alerts. Both retain bounded excerpts and explicitly avoid claiming API impact, malicious intent, or causality without additional evidence.

### Fixed

- Added Deckhouse `/opt/deckhouse/bin` to the collector's deterministic safe `PATH`, allowing the packaged `crictl`, `containerd`, and `runc` binaries to be discovered without inheriting an uncontrolled login environment.
- Missing executables such as optional `nft` and `conntrack` clients are now reported as unavailable commands instead of exposing Python's misleading “No such file or directory” wording.
- Rule-ledger `unknown` status is now calculated from each rule's declared evidence dependencies. Truncated Pod logs or one failed Kubernetes source no longer make unrelated Node, Kubernetes, DNS, storage, or Cilium rules unknown.
- Inventory aliases, collected hostname/FQDN values, Kubernetes Node names, and the `kubernetes.io/hostname` label are matched using unambiguous exact or short-name identities. This removes false inventory mismatches and restores Node-scoped correlations when inventory uses short names and Kubernetes uses FQDNs.
- The selected etcd collection mode is now retained in node/collection/report metadata so disabled etcd rules are represented as `not_applicable` rather than `unknown` or `not_matched`.
- Unknown-fingerprint heavy hitters are now shown as a compact component-balanced list with bounded code-formatted templates. Angle-bracket placeholders render as readable `<n>`, `<ipv6>`, and similar tokens instead of literal HTML entities.

### Documentation

- Documented that Kubernetes API audit logs, including Deckhouse-specific backends, remain intentionally out of scope until an explicit bounded and redacted collection mode is designed.

## [0.7.0] - 2026-08-26

### Added

- Added per-node-command, node/Kubernetes Pod-log, and Kubernetes-source coverage plus a 96-rule evaluation ledger with matched, not-matched, unknown, and not-applicable states.
- Added bounded evidence cards, independent scoped correlation episodes with timing, fair event limiting, deduplication, source drop counters, inventory/Node mismatch detection, and normalization-truncation findings.
- Added Deckhouse CSE Pro 1.74 discovery for Cilium/CoreDNS ConfigMaps and log namespaces with vanilla fallbacks; kube-proxy remains optional.
- Local and external LLM packages now contain bounded status/value/excerpt/timestamp evidence fragments; external fragments are pseudonymized and DLP-checked while token/evidence maps remain private.
- CoreDNS resolution findings now list up to 20 unique failed query names with query type and occurrence count; source line references remain as evidence.
- Added `collection.collect_cgroup=false` and `--skip-cgroup`: direct cgroup facts are not collected, cgroup events/correlations and related findings are suppressed, and the selected mode is recorded in collections and reports.
- Added disableable `--progress off|summary|detail` execution visualization on `stderr`, covering phases, per-node state, node evidence categories, and Kubernetes API source statuses.
- Added Deckhouse `containerd-deckhouse.service` support alongside vanilla `containerd.service` and `crio.service`; expanded the rule-pack scope to Kubernetes 1.24–1.31.

### Fixed

- Removed false positives from old rotated kubelet client certificates, normal StatefulSet rollout revision drift, active Job retries, empty CoreDNS container-status arrays, filtered Service selectors, absent Cilium source coverage, empty-but-collected Cilium service maps, per-interface IPv6 disables, and version-skew boundary selection.
- All inferred timestamps are excluded from causal correlation, and `collect_cgroup=false` suppresses complete cgroup-derived events including EROFS/read-only labels.
- Read-only EROFS/container snapshot mounts below the containerd data directory are no longer reported as full runtime filesystems; the check now evaluates only separate backing mount points for runtime, kubelet, and logs.
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
