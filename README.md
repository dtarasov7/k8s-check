# kdiag: One-Time Kubernetes / RED OS Emergency Snapshot

`kdiag` collects a bounded diagnostic snapshot from cluster nodes and the Kubernetes API, normalizes and correlates events, and produces local gzip/JSON bundles, deterministic findings, and a Markdown report. This implementation does not use an LLM, automatic remediation, or persistent agents.

## Implemented Features

- node discovery through an existing Ansible inventory;
- delivery of a single standard-library-only `.pyz` with the system `scp` client;
- node collector execution over `ssh` and `sudo -n`;
- best-effort collection when a node, the API, or Prometheus is unavailable;
- node evidence covering the OS, kernel, boot, packages, systemd, kubelet, CRI inventory/readiness, journals, network, sysctl, cgroups, PSI/resources, configuration hashes, certificate rotation metadata, read-only stacked-etcd status/capacity, and bounded CRI logs;
- allowlist projections of Nodes, Pods, Events, workloads, Services, EndpointSlices, APIService, Lease, PDB/PV/PVC/CSI, NetworkPolicy, and diagnostic Cilium CRDs;
- API server `/readyz?verbose` and bounded parallel Kubernetes collection with three read-only requests;
- bounded current and previous logs from system namespaces and explicitly approved application namespaces only;
- an SHA-256 manifest, JSON report, and Markdown report;
- an autonomous rule pack for Node Problem Detector signatures, Pod lifecycle/rollouts/PDB, Service/CoreDNS/EndpointSlice, Prometheus, control-plane/etcd capacity, storage/CSI, runtime/Cilium, version skew, resources, time, and certificates;
- kube-proxy-free Cilium diagnostics based on the effective replacement setting and read-only per-node Cilium service maps; absence of kube-proxy alone is not an error;
- findings classified as `fact`, `correlation`, or `hypothesis`, normalized events, and fingerprints for unknown messages.

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

An example identity and permissions are provided in the [RBAC manifest](deploy/kubernetes/kdiag-rbac.yaml). It is not applied automatically. Access to `pods/log` is granted only in `kube-system`; create a separate namespace-scoped Role and RoleBinding based on this example for every approved application namespace.

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
- standard system utilities. A missing utility is reported as `unsupported` and does not abort the snapshot.

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

Stacked-etcd collection is enabled with `collection.collect_etcd=true` and can be disabled in JSON. Optional Cilium CRDs and `CSIStorageCapacity` do not make the snapshot `partial` when a particular API version is absent, but the coverage matrix still records them.

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
- `--skip-kubernetes` — collect node evidence only;
- `--prometheus-url URL` — optional best-effort Prometheus evidence;
- `--application-namespace NAME` — explicitly approve logs from a namespace.

`ansible_ssh_common_args` and `ansible_ssh_extra_args` are intentionally not executed. For ProxyJump or complex inventory routing, create a reviewed OpenSSH alias and use it as `ansible_host`.

Only the inventory host name, `ansible_host`, `ansible_user`, and `ansible_port` are used. The current account's key must be available to normal `ssh` through its standard location, `ssh-agent`, or a reviewed OpenSSH configuration. `ansible_ssh_private_key_file` is not copied into the command.

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

`report.md` starts with a coverage matrix and explicitly shows unavailable sources. Rebuild derived output with:

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

`normalized-events.json.gz` contains categorized events, correlations, and bounded approximate heavy hitters for unknown fingerprints. Original messages remain confidential evidence; do not transfer this file outside the trusted environment without a separate redaction review.

Snapshot exit codes:

- `0` — all nodes and the required Kubernetes source were collected;
- `1` — a partial snapshot was saved because one or more required sources were unavailable;
- `2` — configuration or preflight failed and collection did not run.

Prometheus is optional and does not affect the exit code.

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
