# Changelog

All notable changes to `kdiag` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
