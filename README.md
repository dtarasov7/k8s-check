# kdiag: One-Time Kubernetes / RED OS Emergency Snapshot

`kdiag` collects a bounded diagnostic snapshot from cluster nodes and the Kubernetes API, normalizes and correlates events, and produces local gzip/JSON bundles, deterministic findings, and a Markdown report. An optional offline command can prepare minimized input for an LLM, but LLM inference is not required for collection or deterministic analysis. Automatic remediation and persistent agents are not used.

## Implemented Features

- node discovery through an existing Ansible inventory;
- delivery of a single standard-library-only `.pyz` with the system `scp` client;
- node collector execution over `ssh` and `sudo -n`;
- best-effort collection when a node, the API, or Prometheus is unavailable;
- node evidence covering the OS, kernel, boot, packages, systemd, kubelet, CRI inventory/readiness, journals, network, sysctl, cgroups, PSI/resources, configuration hashes, certificate rotation metadata, read-only stacked-etcd status/capacity, and bounded CRI logs;
- active-runtime detection for vanilla `containerd.service`, `crio.service`, and Deckhouse `containerd-deckhouse.service`; the deterministic node `PATH` includes `/opt/deckhouse/bin`, and missing or unused alternative units are not treated as failures;
- allowlist projections of Nodes, Pods, Events, workloads, Services, EndpointSlices, APIService, Lease, PDB/PV/PVC/CSI, NetworkPolicy, and diagnostic Cilium CRDs;
- API server `/readyz?verbose` and bounded parallel Kubernetes collection with three read-only requests;
- bounded current and previous logs from system namespaces and explicitly approved application namespaces only;
- an SHA-256 manifest, JSON report, and Markdown report;
- an autonomous rule pack for Node Problem Detector signatures, Pod lifecycle/rollouts/PDB, Service/CoreDNS/EndpointSlice, Prometheus, control-plane/etcd capacity, storage/CSI, runtime/Cilium, version skew, resources, time, and certificates;
- kube-proxy-free Cilium diagnostics based on the effective replacement setting and read-only per-node Cilium service maps; absence of kube-proxy alone is not an error;
- findings classified as `fact`, `correlation`, or `hypothesis`, normalized events, and fingerprints for unknown messages;
- fully offline triage cards for recognized log templates, with routine/observe/actionable/security classification, occurrence/time/scope context, local health correlations, decision conditions, counter-evidence, and missing checks;
- per-command, per-Pod-log, and per-Kubernetes-source coverage plus a dependency-aware rule evaluation ledger with `matched`, `not_matched`, `unknown`, and `not_applicable` states;
- evidence cards with bounded excerpts, counter-evidence, missing checks, collection/correlation windows, and a correlation timeline;
- optional minimized local LLM packages with selected evidence fragments and fail-closed pseudonymized packages for a manually operated external LLM.

For detailed operating instructions, see the [English User Guide](docs/UserGuide.md) or the [Russian User Guide](docs/UserGuide-ru.md).

The architecture, coverage, and primary sources are described in the [autonomous rule pack document](docs/autonomous-rule-pack.md).

PlantUML architecture diagrams are available in the [diagramms directory](diagramms/).

The system does not modify Kubernetes objects or restart services. It temporarily copies `/tmp/kdiag-<collection>.pyz` to each node and removes that file after execution.

## Requirements

On the management server:

- Python 3.8;
- `ansible-inventory`, `ssh`, `scp`, and `kubectl`;
- an Ansible inventory for which `ansible-inventory --list --export` returns JSON;
- configured SSH keys and `known_hosts` entries;
- a dedicated read-only kubeconfig for the collector;
- a writable `--output-dir`; create it in advance with mode `0700` on the management server's local filesystem.

An example identity and permissions are provided in the [RBAC manifest](deploy/kubernetes/kdiag-rbac.yaml). It is not applied automatically. Access to `pods/log` is granted in `kube-system`, `d8-kube-dns`, and `d8-cni-cilium`; create a separate namespace-scoped Role and RoleBinding for every approved application namespace.

Step-by-step creation of a dedicated kubeconfig for the `kdiag-system/kdiag-reader` ServiceAccount, including short-lived token issuance and renewal, is documented under [Kubernetes identity and RBAC](docs/UserGuide.md#6-kubernetes-identity-and-rbac) in the User Guide.

After issuing the kubeconfig, verify the permissions of that exact identity:

```bash
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i list nodes
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i list pods --all-namespaces
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i get pods/log --namespace kube-system
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i get /readyz
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i list apiservices.apiregistration.k8s.io
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i create pods/exec --all-namespaces
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i get secrets --all-namespaces
```

The first five commands must return `yes`; the final two must return `no`. `kdiag` does not use `pods/exec`.

On cluster nodes:

- Python 3.8 at a known absolute path, `/usr/bin/python3.8` by default;
- non-interactive root access through `sudo -n` for the current SSH account;
- standard system utilities. The fixed safe `PATH` includes `/opt/deckhouse/bin` before standard system directories. A missing utility is reported as an unavailable command with status `unsupported` and does not imply that a similarly named kernel subsystem or data file is absent.

On control-plane nodes, `collect_etcd=true` uses either a host `etcdctl` or `crictl exec` in the existing static etcd Pod. It runs only `endpoint status`, `endpoint health`, and `alarm list` with standard kubeadm health-check TLS paths. Private-key contents are never read into the bundle. External or non-kubeadm etcd is reported as `not_applicable` or `unavailable`.

Broad `sudo` access makes the SSH account highly privileged independently of `kdiag`. For regular operation, use a root-owned wrapper and a narrow `sudoers` rule. The initial emergency implementation assumes an already approved access model.

## Offline Build

```bash
python3.8 scripts/build.py
python3.8 dist/kdiag.pyz --version
```

The `dist/kdiag.pyz` artifact contains only project source code; Python's standard library is not bundled. No `pip install` is required.

## Configuration

Copy the [configuration example](config/snapshot.example.json) and set a dedicated kubeconfig. Do not add passwords, SSH private keys, or Kubernetes tokens to the JSON file; configuration contains paths only.

The safe default for application namespaces is an empty list. Approve namespaces in JSON or with the repeatable `--application-namespace` option.

Stacked-etcd collection is enabled with `collection.collect_etcd=true` and can be disabled in JSON. Direct cgroup collection and related checks can be disabled with `collection.collect_cgroup=false` or `--skip-cgroup`. Optional Cilium CRDs and `CSIStorageCapacity` do not make the snapshot `partial` when a particular API version is absent, but the coverage matrix still records them.

## Running a Snapshot

```bash
python3.8 dist/kdiag.pyz snapshot \
  --inventory /path/to/inventory \
  --group k8s \
  --config /path/to/snapshot.json \
  --kubeconfig /path/to/kdiag-readonly.kubeconfig \
  --output-dir /var/lib/kdiag
```

Useful options:

- `--ssh-user USER` — default user when inventory does not specify one;
- `--remote-python /path/python3.8` — Python interpreter on the nodes;
- `--since-hours 24` — journal look-back window;
- `--parallelism 2` — number of nodes collected concurrently;
- `--progress off|summary|detail` — disable progress, show phases/nodes, or also show individual source statuses; defaults to `summary` and writes to `stderr`;
- `--skip-cgroup` — skip direct cgroup facts and suppress cgroup events/findings;
- `--skip-kubernetes` — collect node evidence only;
- `--prometheus-url URL` — optional best-effort Prometheus evidence;
- `--application-namespace NAME` — explicitly approve logs from a namespace.

`ansible_ssh_common_args` and `ansible_ssh_extra_args` are intentionally not executed. For ProxyJump or complex inventory routing, create a reviewed OpenSSH alias and use it as `ansible_host`.

Only the inventory host name, `ansible_host`, `ansible_user`, and `ansible_port` are used. The current account's key must be available to normal `ssh` through its standard location, `ssh-agent`, or a reviewed OpenSSH configuration. `ansible_ssh_private_key_file` is not copied into the command.

For analysis, an inventory alias is matched to a Kubernetes Node using the collected hostname/FQDN, Node name, and `kubernetes.io/hostname`. A unique short-name match is accepted; ambiguous short names remain unmatched and are reported instead of being guessed.

## Output

Every run creates a separate directory:

```text
<output>/<collection-id>/
  collection.json
  node-<inventory-host>.json.gz
  kubernetes.json.gz
  prometheus.json.gz
  normalized-events.json.gz
  facts.json
  findings.json
  report.json
  report.md
  manifest.json
```

`report.md` is an operator-facing Russian summary. It groups identical per-node source failures, counts successful sources instead of listing every one, and explains each issue as: what was detected, what it means, contradicting data, unavailable checks, and the next action. Complete per-source coverage and per-rule evaluation records remain in `report.json`. Rebuild derived output with:

```bash
python3.8 dist/kdiag.pyz report /var/lib/kdiag/<collection-id>
```

Verify collection completeness and the SHA-256 digest of every file with:

```bash
python3.8 dist/kdiag.pyz verify /var/lib/kdiag/<collection-id>
```

The manifest detects accidental corruption, deletion, and addition of files. It is not a digital signature and does not protect against coordinated replacement of data files together with `manifest.json`.

## Autonomous Rules

These commands do not use the network or connect to the cluster:

```bash
python3.8 dist/kdiag.pyz self-test
python3.8 dist/kdiag.pyz rules list
python3.8 dist/kdiag.pyz rules explain kubernetes.node_not_ready
```

`normalized-events.json.gz` contains deduplicated categorized events, independent scoped correlation episodes, explicit truncation/drop counters by source, offline message-insight cards, and bounded approximate heavy hitters for unknown fingerprints. Recognized cards explain common messages and correlate only data already present in the snapshot; they are not findings and do not use an LLM, network, or external API. Routine/observe cards stay in this machine-readable confidential file; only actionable/security cards without a duplicate finding enter the operator report. Original messages remain confidential; do not transfer this file outside the trusted environment without a separate redaction review.

Kubernetes API audit logs are not collected, including Deckhouse-specific audit backends. They are not exposed through a portable read-only Kubernetes API, may contain sensitive request or response data, and can be very large. Adding them safely requires a separate explicit opt-in with deployment-specific paths/backends, strict byte and time limits, and dedicated redaction; their absence from the snapshot is therefore intentional rather than a coverage error.

Snapshot exit codes:

- `0` — all nodes and the required Kubernetes source were collected;
- `1` — a partial snapshot was saved because one or more required sources were unavailable;
- `2` — configuration or preflight failed and collection did not run.

Prometheus is optional and does not affect the exit code.

## Optional LLM Incident Package

`prepare` creates data but does not install or call a model. A local package keeps operational identifiers but excludes raw bundles and full logs:

```bash
python3.8 dist/kdiag.pyz llm prepare /var/lib/kdiag/<collection-id> \
  --output-dir /secure/kdiag-llm-local \
  --profile local \
  --mode deep-analysis \
  --question "What are the most likely causes?"
```

Analyze that prepared package with a separately deployed OpenAI-compatible service bound to literal loopback:

```bash
python3.8 dist/kdiag.pyz llm analyze-local /secure/kdiag-llm-local/prepared \
  --model local-model-name \
  --output-dir /secure/kdiag-llm-local-response
```

`analyze-local` sends the prepared JSON content, not the collection path, and never executes model suggestions. The package contains bounded `status/value/excerpt/timestamp` fragments for its `EVIDENCE_NNN` identifiers instead of opaque identifiers alone. `kdiag.pyz` does not bundle or configure a model/runtime.

A hardened llama.cpp systemd deployment example is available in [deploy/systemd](deploy/systemd/README.md). New local preparations use `prepared/`; `analyze-local` also accepts legacy local `export/` directories created by kdiag 0.5.0.

For a manual external workflow, use `--profile external`. The command pseudonymizes known node, Kubernetes resource, account, address, DNS, path, UID, and endpoint-port values; retains diagnostic component names and versions; runs outbound DLP; and creates separate `export/` and `private/` directories. Review the exported files, validate them again, and transfer only the contents of `export/`:

```bash
python3.8 dist/kdiag.pyz llm validate-export /secure/kdiag-llm-external/export
python3.8 dist/kdiag.pyz llm import-response /secure/google-response.txt \
  --token-map /secure/kdiag-llm-external/private/token-map.json \
  --output-dir /secure/kdiag-llm-response
```

`private/token-map.json` contains the re-identification map and must never leave the trusted environment. The external response is untrusted; `kdiag` stores both the unchanged response and a restored copy. Browser automation and direct Google API access are intentionally absent.

## Limits and Retention

By default, a compressed node bundle is limited to 32 MiB, the Kubernetes bundle to 128 MiB, and 1 GiB of disk remains reserved before collection starts. With an initial 5 GiB allocation on the management server, do not run multiple snapshots without controlled retention.

A backup is not required to perform a snapshot. Without one, a management-server disk failure destroys previously collected bundles and baselines; this is a history-retention risk, not a one-time snapshot availability risk.

## Verification

```bash
PYTHONPATH=src python3.8 -m compileall -q src tests
PYTHONPATH=src python3.8 -m unittest discover -s tests -v
python3.8 scripts/build.py
python3.8 dist/kdiag.pyz --version
python3.8 dist/kdiag.pyz verify /var/lib/kdiag/<collection-id>
```
