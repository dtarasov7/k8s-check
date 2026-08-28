# Changelog

All notable changes to `kdiag` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-08-27

### Added

- A separate baseline workflow: create a candidate from a verified collection, explicitly approve it with an author, then compare new collections with source awareness.
- SHA-256 for the stable profile and the complete canonical approved document; changing the profile, approval metadata, or byte representation fails validation.
- `new_problem`, `removed`, `added`, `changed`, `resolved`, and `unverifiable` difference classes, machine-readable `baseline-comparison.json`, and Russian `baseline-comparison.md` with recommended actions.
- `snapshot --baseline`, reusing the same comparison module and adding comparison outputs to the collection manifest.

### Security

- Approval is blocked by active critical findings and material gaps in required sources; exceptions require explicit `--override-unsafe` and retain their reasons.
- Approved baselines are never overwritten, candidates are rejected for comparison, and an unavailable current source never produces false `removed` objects.
- Timestamps, UIDs, IPs/PIDs, Lease times, individual logs, dynamic Jobs/ReplicaSets, and generated Pod suffixes are excluded. There is no external storage or automatic norm learning.

## [0.10.0] - 2026-08-27

### Added

- `--purpose check|incident` with a required explicit incident window through `--incident-since` or absolute start/end values. The window is applied to journald, Kubernetes Pod logs, and Prometheus.
- Finding states `active`, `resolved`, and `unknown`, plus `possible_cause`, `consequence`, and `configuration_risk` roles. Routine reports hide resolved historical findings while retaining them in JSON.
- Six fixed bounded Prometheus `query_range` diagnostics for API, etcd, restarts, networking, and CPU in incident mode.
- A bounded Kubernetes/storage/infrastructure causal topology, `may_explain` links, and deterministic ranking of possible causes.
- `causal-graph.json`; ranked hypotheses and range signals are included in local and pseudonymized LLM packages.

### Changed

- Reports state the run purpose and window and show Russian finding states/roles, ranking, graph summary, and metric changes. Hypothesis scores are documented as investigation order, not probability.
- New collections use kind `diagnostic_collection`; schema_version remains 1.
- Exact-timestamp normalized records outside the incident window are excluded before rule and message-card evaluation; raw Kubernetes Events and Pod logs are not rewritten. Rule pack: `2026.08.14`.

## [0.9.2] - 2026-08-27

### Changed

- Removed the direct `crio --version` probe. CRI-O remains supported through `crio.service` and CRI evidence, while an optional missing host binary no longer adds collection noise.
- Routine success/info records from kubelet, StatefulSet, kube-apiserver policy refresh, cert-manager, kube-rbac-proxy, CoreDNS kubeforward, and control-plane-manager are classified locally and hidden. They are shown only with a correlated failure or guaranteed abnormal volume: at least 1,000 records, or at least 100 records with a lower-bound rate of 100 records/hour.
- Historical Deckhouse authentication-config read errors are omitted when the file is currently present and readable, API `readyz` passes, and all collected kube-apiserver Pods are ready.

### Fixed

- When `crictl exec` fails or CRI inventory is unavailable, `cilium-dbg`/`cilium` is resolved only from standard paths in the rootfs of the exact running `cilium-agent` process; a successful read-only result supersedes host-probe failures.
- `etcdctl` discovery accepts both object and JSON-string PID forms from `crictl inspect`, and falls back to standard paths in the rootfs of the exact running `etcd` process when CRI is unavailable.
- Deckhouse DNS discovery now tries the actual `kube-system/d8-kube-dns` ConfigMap first while retaining legacy Deckhouse and vanilla fallbacks.

## [0.9.1] - 2026-08-27

### Fixed

- Cilium discovery now associates CRI containers with Pod sandboxes and recognizes vanilla `kube-system/cilium-*` Pods and Deckhouse `d8-cni-cilium/agent-*` Pods with the `cilium-agent` container. Container CLI lookup tries names and standard absolute paths for `cilium`, `cilium-dbg`, and `cilium-debug`; a successful fallback no longer leaves equivalent missing-host-binary failures in the report.
- If `crictl exec` into etcd is unavailable, read-only checks are retried with the binary from that exact running container rootfs through a validated `/proc/<pid>/root` path. A host `etcdctl` in `PATH` remains a fallback; unsafe broad searches across arbitrary image layers are not used.

## [0.9.0] - 2026-08-27

### Added

- Prometheus collection now supports HTTP Basic authentication through `prometheus.username` and `prometheus.password`. CLI users can pass the password through `--prometheus-password-file`, so the secret does not appear in the process command line; credentials are never written to collection artifacts.
- Cilium status and service-map collection falls back to `crictl exec` in the already running `cilium-agent` container when `cilium`, `cilium-dbg`, or `cilium-debug` is unavailable on the host.

### Changed

- Deckhouse discovery recognizes the `d8-kube-dns` and `node-local-dns` ConfigMaps, the `d8-kube-dns` backend and legacy redirect Services, the `kube-dns` ExternalName alias, Deckhouse DNS Pod names, and the `d8-cni-cilium/cilium-configmap` name while retaining vanilla and legacy fallbacks.
- Stacked etcd inspection now prefers `etcdctl` inside the running etcd container and uses a host binary only as a fallback.
- Known successful kubelet, StatefulSet, cert-manager, kube-rbac-proxy, and DNS-cleaner messages are hidden from the operator report. A routine message is shown only when offline correlation finds an unhealthy related Pod or another explicit problem.
- A single Deckhouse authentication-config read error is treated as a normal reconciliation race and omitted from findings. Only repeated records are reported and correlated with current file metadata, API readyz, and kube-apiserver readiness.

### Fixed

- Added actionable offline explanations for control-plane checksum mismatch and insufficient kubelet image garbage collection instead of leaving them as unexplained unknown fingerprints.

## [0.8.1] - 2026-08-27

### Changed

- Reworked `report.md` as an operator-facing Russian report: technical English labels were replaced, findings now lead with what was detected, what it means, what contradicts it, what remains unchecked, and what to do.
- Routine and observe message cards are no longer emitted to `report.md` or `report.json`; they remain available in confidential `normalized-events.json.gz`. Finding-backed authentication-config and ptrace cards are also hidden to avoid duplicate sections.
- Successful collection checks and identical per-node failures are compacted in Markdown. Detailed source coverage and per-rule evaluation records remain unchanged in JSON.

### Fixed

- Current journal collection now requests newest records first. When the byte limit is reached, kdiag retains the incident-nearest end of the requested window instead of its oldest records.
- The collector records metadata—not contents—for Deckhouse authentication config. The related finding distinguishes a historical/transient read error from a currently missing file using host file presence, API readyz, and kube-apiserver Pod readiness, while explicitly noting that container mount visibility is not directly checked.
- Truncated-journal findings are grouped by source and node count and recommend the exact `collection.max_command_bytes` / `collection.since_hours` controls instead of printing every node path.

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
