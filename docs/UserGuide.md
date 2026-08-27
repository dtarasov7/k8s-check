# kdiag User Guide

## 1. Purpose and scope

<code>kdiag 0.8.0</code> creates a one-time emergency snapshot of a Kubernetes cluster and performs deterministic, fully offline analysis. Its current diagnostic compatibility scope is vanilla Kubernetes and Deckhouse CSE Pro 1.74 with Kubernetes 1.24–1.31, up to 20 nodes and about 1,000 Pods. This describes evidence/rule compatibility, not lifecycle support.

The program runs on a separate management server. It connects to every node over SSH, runs read-only inspection through non-interactive sudo, and queries the Kubernetes API using a dedicated kubeconfig. Prometheus is optional: the snapshot still works when Prometheus or the entire Kubernetes API is unavailable.

The current release implements only the **one-time emergency snapshot and inventory** stage. Periodic baseline collection and continuous Kubernetes/log watching are future stages.

No LLM, Internet connection, external Python package, agent, DaemonSet, or database is required. Analysis is performed by a versioned rule pack. An optional command prepares minimized LLM input after collection; it does not affect the deterministic report. The tool does not update Kubernetes, repair the cluster, restart services, change sysctl, or mutate etcd.

## 2. Operating model

The management server is both the collector and the central storage location:

~~~text
Management server
  kdiag.pyz + JSON config + Ansible inventory + dedicated kubeconfig
       |                         |
       | SSH + sudo -n           | read-only Kubernetes API calls
       v                         v
  Kubernetes nodes          Kubernetes API VIP
       |
       +-- host facts, configuration, systemd state and journals
       +-- kubelet/runtime/Cilium/KESL/kernel evidence
       +-- optional read-only local etcd health inspection

  Result: one collection directory on the management server
~~~

The workflow is:

1. Validate configuration, disk reserve, inventory, SSH, sudo, and API access.
2. Collect bounded node and Kubernetes evidence.
3. Normalize logs and structured Kubernetes states.
4. Correlate related records in a 15-minute window.
5. Run deterministic rules and create JSON and Markdown reports.
6. Generate a manifest with file sizes and SHA-256 hashes.

A node failure or unavailable API normally produces a **partial snapshot** instead of discarding evidence from healthy sources.

## 3. Safety and data classification

The collector uses read-only commands and Kubernetes verbs. Supplied RBAC does not grant Secrets, <code>pods/exec</code>, or mutation verbs. Optional etcd inspection runs only <code>endpoint status</code>, <code>endpoint health</code>, and <code>alarm list</code>; it never writes to etcd.

Standard etcd client certificate paths may be used locally, but private-key contents are not copied into the snapshot. Application Pod logs are disabled unless their namespaces are explicitly allowlisted.

The snapshot is **not anonymized**. It may contain node and object names, namespaces, image names, IP addresses, storage identifiers, Events, selected Pod logs, host journals, configuration values, and certificate subjects/expiry dates. Treat the entire result directory as confidential. Review and redact it before any external transfer.

<code>manifest.json</code> detects accidental or deliberate file changes using SHA-256. It is not a digital signature and does not prove who created the snapshot.

## 4. Requirements

### 4.1 Management server

- Python 3.8.
- <code>ssh</code>, <code>scp</code>, <code>kubectl</code>, and <code>ansible-inventory</code> in PATH.
- Ansible inventory containing all target nodes.
- SSH key access and valid known-host entries.
- Dedicated Kubernetes identity and kubeconfig.
- Initially 5 GiB of free storage; the default preserves 1 GiB as a central reserve.

Ansible is used only to resolve inventory and the host name, <code>ansible_host</code>, <code>ansible_user</code>, and <code>ansible_port</code>. kdiag does not run playbooks. Do not assume arbitrary Ansible connection plugins, <code>ansible_ssh_common_args</code>, or <code>ansible_ssh_private_key_file</code> are honored; put required routing/key settings in normal OpenSSH configuration.

### 4.2 Cluster nodes

- Python 3.8 at the configured absolute path; default <code>/usr/bin/python3.8</code>.
- SSH key access for the management account.
- Passwordless <code>sudo -n</code> to root.
- Persistent journald and standard inspection tools such as systemctl, journalctl, sysctl, df, ss, and ip.
- The target allowance is up to 5 GiB free per node; the default temporary node bundle limit is only 32 MiB.

Node commands run with a fixed safe PATH: <code>/opt/deckhouse/bin</code> followed by standard system directories. This discovers Deckhouse-packaged <code>crictl</code>, <code>containerd</code>, and <code>runc</code> without inheriting an arbitrary login PATH. If an optional CLI such as <code>nft</code> or <code>conntrack</code> is absent, its command record is <code>unsupported</code>; this says nothing by itself about nftables or conntrack kernel support.

Temporary node data is removed after a normally completed transfer. Check for leftovers after an interrupted run.

### 4.3 etcd assumptions

Read-only stacked kubeadm etcd inspection is attempted only with these standard paths:

~~~text
/etc/kubernetes/manifests/etcd.yaml
/etc/kubernetes/pki/etcd/ca.crt
/etc/kubernetes/pki/etcd/healthcheck-client.crt
/etc/kubernetes/pki/etcd/healthcheck-client.key
~~~

The collector uses host etcdctl, or crictl to invoke etcdctl inside the already running local etcd container. External etcd and non-standard layouts produce an evidence-gap result rather than an invented diagnosis.

## 5. Build, test, and offline transfer

The deliverable is <code>dist/kdiag.pyz</code>, a Python zip application containing only project code and the standard library.

~~~bash
python3.8 scripts/build.py
PYTHONPATH=src python3.8 -m unittest discover -s tests -v
python3.8 dist/kdiag.pyz self-test
sha256sum dist/kdiag.pyz
~~~

Transfer the pyz, recorded checksum, reviewed JSON configuration, RBAC manifests, and guides through the approved offline process. Verify after transfer:

~~~bash
sha256sum kdiag.pyz
python3.8 kdiag.pyz --version
python3.8 kdiag.pyz self-test
~~~

Do not rely on a checksum printed in documentation: a legitimate rebuild changes it.

## 6. Kubernetes identity and RBAC

Use a separate identity even if a super-admin is available for an initial controlled test. The supplied manifest is <code>deploy/kubernetes/kdiag-rbac.yaml</code>. It creates:

- namespace <code>kdiag-system</code> and ServiceAccount <code>kdiag-reader</code>;
- a read-only ClusterRole and ClusterRoleBinding for structural resources;
- a Role and RoleBinding for <code>pods/log</code> in <code>kube-system</code>.

Review every binding subject before applying the manifest. Do not add Secret access, pods/exec, or write verbs. Application namespace Roles are not generated automatically: create an equivalent namespaced Role and RoleBinding, bind it to <code>kdiag-system/kdiag-reader</code>, and add only the approved namespace to the configuration.

The enabled collector reads Nodes, Pods, Events, workloads, Services, EndpointSlices, PDBs, PVCs, PVs, APIService, Leases, VolumeAttachments, CSI objects, StorageClasses, NetworkPolicies, selected Cilium CRDs, allowlisted fields from the <code>cilium-config</code> and <code>coredns</code> ConfigMaps, the non-resource URL <code>/readyz</code>, and Pod logs only in approved namespaces. ConfigMap discovery tries Deckhouse locations (`d8-cni-cilium`, `d8-kube-dns`) first and then vanilla `kube-system`, recording every attempt and the selected object.

### Creating a kubeconfig for kdiag-reader

Run these commands on a protected management server using a bootstrap kubeconfig that may apply the RBAC manifest and create ServiceAccount TokenRequests. Its current context must select the target cluster. For a one-time snapshot, prefer a short-lived token over a permanent <code>kubernetes.io/service-account-token</code> Secret.

~~~bash
umask 077
install -d -m 0700 /secure/kdiag
ADMIN_KUBECONFIG=/secure/admin.kubeconfig
KDIAG_KUBECONFIG=/secure/kdiag/kdiag-reader.kubeconfig
KDIAG_CA=/secure/kdiag/kdiag-ca.crt

kubectl --kubeconfig "$ADMIN_KUBECONFIG" apply -f deploy/kubernetes/kdiag-rbac.yaml
kubectl --kubeconfig "$ADMIN_KUBECONFIG" -n kdiag-system get serviceaccount kdiag-reader

KDIAG_SERVER="$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl --kubeconfig "$ADMIN_KUBECONFIG" config view --raw --minify --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 --decode > "$KDIAG_CA"
KDIAG_TOKEN="$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" -n kdiag-system create token kdiag-reader --duration=8h)"

test -n "$KDIAG_SERVER"
test -s "$KDIAG_CA"
test -n "$KDIAG_TOKEN"

kubectl config set-cluster kdiag-cluster \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --server "$KDIAG_SERVER" \
  --certificate-authority "$KDIAG_CA" \
  --embed-certs=true
kubectl config set-credentials kdiag-reader \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --token "$KDIAG_TOKEN"
kubectl config set-context kdiag-reader@kdiag-cluster \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --cluster kdiag-cluster \
  --user kdiag-reader \
  --namespace kdiag-system
kubectl config use-context kdiag-reader@kdiag-cluster \
  --kubeconfig "$KDIAG_KUBECONFIG"
chmod 0600 "$KDIAG_KUBECONFIG"
unset KDIAG_TOKEN
~~~

The <code>test -s "$KDIAG_CA"</code> check intentionally stops the procedure when the CA cannot be obtained from the bootstrap kubeconfig. Do not replace it with <code>--insecure-skip-tls-verify</code>. The API server may issue a token with a shorter lifetime than the requested eight hours. After expiration, <code>kubectl</code> returns Unauthorized; refresh only the credentials in the existing kubeconfig before the next snapshot:

~~~bash
KDIAG_TOKEN="$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" -n kdiag-system create token kdiag-reader --duration=8h)"
test -n "$KDIAG_TOKEN"
kubectl config set-credentials kdiag-reader \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --token "$KDIAG_TOKEN"
chmod 0600 "$KDIAG_KUBECONFIG"
unset KDIAG_TOKEN
~~~

Do not copy the bootstrap kubeconfig to the regular execution server or place the token in the JSON configuration. Scheduled operation requires an approved short-lived credential refresh process before each snapshot.

~~~bash
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get nodes
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get /readyz
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get pods/log -n kube-system
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get secrets -A
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i create pods -A
~~~

The first three checks should return yes and the last two no. Create application Role/RoleBinding objects only for explicitly approved namespaces.

## 7. Inventory

Any format understood by the installed ansible-inventory is accepted. Minimal INI example:

~~~ini
[k8s_nodes]
cp01 ansible_host=10.10.0.11 ansible_user=kdiag
cp02 ansible_host=10.10.0.12 ansible_user=kdiag
worker01 ansible_host=10.10.0.21 ansible_user=kdiag
~~~

~~~bash
ansible-inventory -i inventory.ini --list
ssh cp01 true
ssh cp01 sudo -n true
~~~

Verify every connection profile. Do not place passwords or private keys in the snapshot configuration.

The inventory alias does not have to equal <code>metadata.name</code> of the Kubernetes Node. kdiag compares the alias, collected hostname/FQDN, Node name, and <code>kubernetes.io/hostname</code>. Exact matches take priority; a short-name/FQDN match is used only when it is unambiguous. Ambiguous identities remain unmatched and produce <code>inventory.node_set_mismatch</code> rather than a guessed association.

## 8. Configuration reference

Copy <code>config/snapshot.example.json</code> to an environment-specific file. The format has <code>schema_version: 1</code>. Invalid values fail preflight with exit code 2.

### 8.1 Collection

| Key | Default | Meaning |
|---|---:|---|
| <code>collection.since_hours</code> | 24 | Journal/Event look-back window. |
| <code>collection.parallelism</code> | 2 | Concurrent node collectors; low by default to limit incident-time load. |
| <code>collection.command_timeout_seconds</code> | 30 | Default node-command timeout. |
| <code>collection.max_command_bytes</code> | 1048576 | Captured bytes per command; truncation is recorded. |
| <code>collection.max_node_bundle_bytes</code> | 33554432 | Maximum compressed bundle accepted per node. |
| <code>collection.central_reserve_bytes</code> | 1073741824 | Space that must remain free centrally. |
| <code>collection.pod_log_tail_bytes</code> | 65536 | Tail bytes per direct node CRI log file. |
| <code>collection.pod_log_total_bytes</code> | 8388608 | Aggregate direct CRI logs per node. |
| <code>collection.pod_log_max_files</code> | 200 | Maximum direct CRI files per node. |
| <code>collection.collect_etcd</code> | true | Enable read-only local etcd health/status/alarm collection. |
| <code>collection.collect_cgroup</code> | true | Direct cgroup facts/process mappings and related cgroup events/findings. |

### 8.2 SSH

| Key | Default | Meaning |
|---|---:|---|
| <code>ssh.connect_timeout_seconds</code> | 10 | Connection timeout. |
| <code>ssh.remote_python</code> | /usr/bin/python3.8 | Absolute node Python path. |
| <code>ssh.user</code> | null | Optional global user override. |
| <code>ssh.port</code> | 22 | Optional global port override. |

### 8.3 Kubernetes

| Key | Default | Meaning |
|---|---:|---|
| <code>kubernetes.enabled</code> | true | Enable API collection. |
| <code>kubernetes.kubeconfig</code> | null | Dedicated kubeconfig; CLI can override. |
| <code>kubernetes.context</code> | null | Optional context. |
| <code>kubernetes.command_timeout_seconds</code> | 30 | Per-request timeout. |
| <code>kubernetes.max_wire_bytes</code> | 67108864 | Maximum raw API response. |
| <code>kubernetes.max_bundle_bytes</code> | 134217728 | Maximum compressed API bundle. |
| <code>kubernetes.system_namespaces</code> | [d8-cni-cilium, d8-kube-dns, kube-system] | Allowlist for vanilla and Deckhouse system Pod logs. |
| <code>kubernetes.application_namespaces</code> | [] | Explicit application-log allowlist; empty means none. |
| <code>kubernetes.collect_system_logs</code> | true | Collect bounded selected system logs. |
| <code>kubernetes.log_tail_lines</code> | 200 | Requested tail per container. |
| <code>kubernetes.max_log_pods</code> | 100 | Maximum Pods selected for API logs. |
| <code>kubernetes.max_log_bytes</code> | 33554432 | Aggregate API Pod-log limit. |

### 8.4 Prometheus

| Key | Default | Meaning |
|---|---:|---|
| <code>prometheus.url</code> | null | Optional base URL; null disables it. |
| <code>prometheus.timeout_seconds</code> | 3 | Short timeout so it cannot block emergency work. |
| <code>prometheus.max_response_bytes</code> | 1048576 | Maximum response size. |

Prometheus failure is non-fatal.

### 8.5 Initial 5 GiB sizing

Default compressed bundle ceilings for 20 nodes plus Kubernetes total about 768 MiB, before reports and working overhead. They are safety ceilings, not expected usage. Start with defaults and examine <code>manifest.json</code>. If useful evidence is repeatedly truncated, increase only the relevant cap and discuss central expansion. Do not remove the 1 GiB reserve to force a run onto a nearly full filesystem.

## 9. Preflight and execution

~~~bash
python3.8 dist/kdiag.pyz --version
python3.8 dist/kdiag.pyz self-test
python3.8 dist/kdiag.pyz rules list
ansible-inventory -i inventory.ini --list
df -h /var/lib/kdiag
kubectl --kubeconfig /secure/kdiag.kubeconfig get --raw='/readyz?verbose'
~~~

Also verify SSH, sudo -n, remote Python, and correct time.

Full snapshot:

~~~bash
python3.8 dist/kdiag.pyz snapshot \
  --inventory inventory.ini \
  --group k8s_nodes \
  --config config/snapshot.json \
  --kubeconfig /secure/kdiag.kubeconfig \
  --output-dir /var/lib/kdiag
~~~

By default, <code>summary</code> progress is written to <code>stderr</code>: phases, start and completion of every inventory node, Kubernetes API, Prometheus, and report generation. <code>detail</code> also lists node evidence categories and the result of each Kubernetes API source. <code>stdout</code> still contains only the collection path, preserving machine parsing:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --progress detail -o /var/lib/kdiag

python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --progress off -o /var/lib/kdiag
~~~

If cgroup checks are not applicable to the platform or produce unreliable noise, disable them for one run:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --skip-cgroup -o /var/lib/kdiag
~~~

This skips direct <code>/sys/fs/cgroup</code> and <code>/proc/&lt;pid&gt;/cgroup</code> facts and suppresses cgroup events/correlations plus <code>cgroup.*</code> and <code>security_agent.cgroup_denial</code> rules. General kubelet/runtime journals remain collected, so a raw journal line may still contain the word <code>cgroup</code>, but it does not create a cgroup finding or enter prepared LLM events as a cgroup event. The setting is recorded in <code>collection.json</code>, <code>facts.json</code>, <code>report.json</code>, and <code>report.md</code>.

Approved application namespaces are repeatable:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json \
  --application-namespace app-a \
  --application-namespace app-b \
  -o /var/lib/kdiag
~~~

Node-only capture when the API is unavailable:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --skip-kubernetes -o /var/lib/kdiag
~~~

This preserves host evidence but prevents Kubernetes structural checks.

Optional Prometheus can be set with <code>--prometheus-url http://host:9090</code>.

| Exit | Meaning | Response |
|---:|---|---|
| 0 | Collection completed. | Read the report and evidence-gap section. |
| 1 | Partial collection saved. | Preserve it, inspect source statuses, then decide whether to repeat. |
| 2 | Configuration/preflight failure. | Correct the local problem; do not assume a snapshot exists. |

Never discard a partial snapshot until its replacement covers the same incident window.

## 10. Result directory

Each run creates <code>&lt;output&gt;/&lt;collection-id&gt;/</code>:

| File | Purpose |
|---|---|
| <code>collection.json</code> | Identity, timing, version, status, source metadata. |
| <code>node-&lt;inventory-host&gt;.json.gz</code> | Per-node evidence and command statuses. |
| <code>kubernetes.json.gz</code> | API resources, readyz output, bounded Pod logs. |
| <code>prometheus.json.gz</code> | Optional bounded Prometheus evidence. |
| <code>normalized-events.json.gz</code> | Normalized records, offline message insights, fingerprints, and correlations; confidential. |
| <code>facts.json</code> | Derived facts used by rules. |
| <code>findings.json</code> | Machine-readable findings. |
| <code>report.json</code> | Combined machine-readable report. |
| <code>report.md</code> | Primary operator report. |
| <code>manifest.json</code> | File sizes and SHA-256 hashes. |

Inventory aliases and Kubernetes Node names may differ. Unambiguous hostname/FQDN and unique short-name matches are canonicalized to the Kubernetes Node name for Node-scoped correlation; ambiguous identities remain visible as a mismatch.

Coverage is recorded for every node command, node Pod-log group, Kubernetes source, and Kubernetes log entry. A collected parent bundle does not hide an inner `failed`, `timeout`, or `truncated` check. `facts.json`, `findings.json`, and `report.json` include a rule evaluation ledger: `matched`, `not_matched`, `unknown` with missing evidence, or `not_applicable`. Each rule declares its own coverage requirements, so a failed Events query affects event-dependent rules but not a Node-condition rule whose Nodes source was collected. Treat `unknown` as an explicit rule-specific evidence gap, not as a healthy result.

The Markdown ledger includes the actual missing-source status and groups the same unavailable command across nodes. Its leading cause summary explains why many rules are `unknown`; for example, one unavailable Kubernetes API snapshot can affect every rule that requires Nodes, Pods, Events, or workloads. If Kubernetes collection was intentionally disabled, dependent rules are `not_applicable` instead. Even an `unreachable` Kubernetes bundle is read to retain its per-source failure details.

The offline message-insight section is informational rather than a finding. Its embedded, versioned catalogue classifies recognized templates as `routine`, `observe`, `actionable`, or `security`; shows the occurrence range, first/last timestamps, rate, affected Nodes/Pods, explanation, decision condition, recommendation, and static reference URLs; and correlates available Pod readiness/restarts, Events, readyz, EndpointSlices, and categorized journal errors. Counter-evidence and unavailable checks are explicit. No LLM, network, or external API is used. A card cannot recover evidence that was not collected and must not be read as proof of impact or causality.

The remaining unknown-fingerprint section is also informational. It shows a component-balanced subset of at most five templates per component, limits long templates, and preserves placeholders such as `<n>` and `<ipv6>` in readable code formatting. Approximate counts are displayed as a guaranteed minimum and estimated upper bound with algorithmic error, not as severity. The complete bounded set remains in `normalized-events.json.gz`.

~~~bash
python3.8 dist/kdiag.pyz report /var/lib/kdiag/COLLECTION_ID
python3.8 dist/kdiag.pyz verify /var/lib/kdiag/COLLECTION_ID
~~~

## 11. Interpretation, normalization, and correlation

Read collection status/evidence gaps first, then facts, correlations, and hypotheses:

- **fact**: directly supported by structured state or a strong deterministic signature;
- **correlation**: at least two distinct symptoms in the same Node/Pod scope within 15 minutes; not proof of causation;
- **hypothesis**: suggestive evidence or a valid platform exception is possible; verify before action.

No finding does not mean no problem. Evidence may be outside the time window, truncated, denied, unreachable, unknown to the rule pack, or stored in a non-standard layout.

The normalizer handles journald JSON, direct CRI logs, Kubernetes Events, Node conditions, Pod/container states, selected Pod logs, and systemd states. It deduplicates records, fairly limits output across source/scope/category buckets, and excludes inferred timestamps from causal correlations. Correlation output consists of independent Pod- or Node-scoped episodes with start, end, duration, and episode ID. Truncation produces explicit per-source counters and a finding.

CoreDNS error records whose query name starts with `smoke-mini-` are treated as intentional Deckhouse smoke-probe noise and excluded from normalized events and findings. The confidential raw log bundle is not rewritten.

## 12. Detailed check catalogue

The artifact contains 98 report rules. Query the exact embedded version with:

~~~bash
python3.8 dist/kdiag.pyz rules list
python3.8 dist/kdiag.pyz rules explain kubernetes.node_not_ready
python3.8 dist/kdiag.pyz rules list --json
~~~

### 12.1 Collection integrity and inventory

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>collector.node_gap</code> | fact | Requested node bundle missing, failed, timed out, or unacceptable. | Restore SSH/sudo/Python/disk access; preserve the partial capture first. |
| <code>collector.evidence_gap</code> | fact | Required journals, Pod logs, or Kubernetes sources denied, failed, unsupported, or truncated. Optional Cilium CRD, CSIStorageCapacity, or Prometheus absence alone is excluded. | Inspect source statuses and correct only the missing permission, timeout, or cap. |
| <code>collector.normalization_truncated</code> | fact | Normalization limits omitted categorized records. | Treat dependent negative results as incomplete and adjust only the relevant limit/window. |
| <code>collector.boot_changed</code> | fact | Node boot ID changed during collection. | Split the timeline at reboot; pre/post state was not simultaneous. |
| <code>inventory.node_set_mismatch</code> | fact | Inventory snapshots and Kubernetes Node objects differ. | Check inventory aliases, cluster membership, and SSH reachability. |
| <code>collector.etcd_evidence_gap</code> | fact | Enabled etcd evidence is unavailable, partial, unsupported, or failed. | Check topology, standard paths, tools, and access; do not infer health from absence. |
| <code>inventory.mixed_kernel</code> | fact | More than one kernel release across nodes. | Compare modules, Cilium/runtime/KESL compatibility and rollout history; mixture is risk, not automatically failure. |
| <code>inventory.unsupported_version_skew</code> | fact | kube-apiserver or kubelet minor versions exceed the supported skew. | Plan version alignment using the version-skew policy; do not improvise the upgrade order. |

### 12.2 Node OS and services

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>node.kubelet_inactive</code> | fact | Collected systemd state is neither active nor activating. | Inspect kubelet status/journal and cgroup, runtime, certificate, mount prerequisites. |
| <code>node.runtime_inactive</code> | fact | No loaded vanilla containerd, Deckhouse containerd, or CRI-O unit is active. Units with LoadState=not-found and inactive alternatives beside a working runtime are ignored. | Inspect runtime journal, socket, and storage before restart. |
| <code>node.low_root_disk</code> | fact | Root filesystem has less than 10% free. | Identify growth in images, CRI logs, journal and files; do not blindly delete runtime data. |
| <code>node.low_inodes</code> | fact | Any collected filesystem is at least 95% out of inodes. | Find high-file-count directories and retention failures. |
| <code>time.not_synchronized</code> | fact | NTPSynchronized=no or chrony reports unsynchronized. | Restore time source and assess timestamp/certificate reliability. |
| <code>certificate.expiring</code> | fact | Discovered certificate expired or expires within 30 days. | Verify clock, owner, and approved rotation procedure. |
| <code>node.conntrack_full</code> | fact | Deterministic conntrack-table-full/drop log signature. | Check current/max entries and traffic cause before tuning. |
| <code>node.oom_detected</code> | fact | Kernel, CRI, or Pod log contains an OOM-kill signature. | Identify killed process/cgroup and correlate limits and pressure. |
| <code>runtime.cri_not_ready</code> | fact | CRI reports RuntimeReady=False. | Inspect runtime service/socket, cgroups, and runtime storage. |
| <code>runtime.cri_network_not_ready</code> | fact | CRI reports NetworkReady=False. | Inspect Cilium, CNI configuration, and sandbox Events on the node. |
| <code>node.swap_active</code> | fact | Swap is active while kubelet failSwapOn is not disabled. | Compare intended kubelet policy and actual swap usage before changing the node. |
| <code>node.low_runtime_disk</code> | fact | A separate backing filesystem for kubelet/runtime/log data is at least 90% used. Read-only container snapshot submounts, including EROFS layers, are ignored. | Identify the consumer on that mount; do not blindly remove runtime data. |
| <code>certificate.kubelet_rotation_broken</code> | fact | Certificate rotation is enabled but kubelet-client-current.pem or its target is invalid. | Inspect the symlink, target certificate, and kubelet journal; do not replace certificates automatically. |

### 12.3 Node Problem Detector-derived kernel signatures

These signatures are adapted from the pinned upstream Node Problem Detector configuration. They recognize messages; they do not perform hardware or filesystem repair.

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>node.task_hung</code> | fact | Kernel reports a blocked/hung task. | Preserve task stack and storage evidence before reboot. |
| <code>node.unregister_netdevice</code> | fact | Kernel waits while unregistering a network device. | Correlate Cilium/veth lifecycle, interfaces, Pod deletion, and kernel version. |
| <code>node.kernel_oops</code> | fact | Kernel oops/panic-class signature. | Preserve the full journal and compare kernel/modules across nodes. |
| <code>node.filesystem_error</code> | fact | EXT4 error or XFS forced-shutdown/error signature. | Reduce writes, assess device/filesystem health, follow filesystem procedure. |
| <code>node.filesystem_warning</code> | fact | EXT4 warning signature. | Review surrounding messages and storage health. |
| <code>node.io_error</code> | fact | Buffer I/O error signature. | Map device/path and correlate multipath/storage/filesystem evidence. |
| <code>node.hardware_error</code> | fact | Machine-check, memory, corrected/recoverable/fatal hardware signature. | Map to hardware and run approved vendor diagnostics. |

### 12.4 Kubernetes Nodes, Pods, probes, and workloads

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>kubernetes.node_not_ready</code> | fact | Node Ready is False or Unknown. | Read reason/message, Lease, kubelet/runtime/CNI evidence and Events. |
| <code>kubernetes.node_pressure</code> | fact | MemoryPressure, DiskPressure, or PIDPressure is True. | Investigate the named resource and eviction signals. |
| <code>kubernetes.network_unavailable</code> | fact | NetworkUnavailable=True. | Inspect Cilium, routes, devices, IPAM, and node logs. |
| <code>kubernetes.pod_crash_loop</code> | fact | Container state is CrashLoopBackOff. | Inspect previous/current logs, exit status, probes and dependencies. |
| <code>kubernetes.image_pull_failure</code> | fact | Container state/Event reports image pull/back-off. | Check image name, registry reachability, credential mechanism, trust, and disk. |
| <code>kubernetes.pod_oom_killed</code> | fact | Terminated container reason is OOMKilled. | Compare limit, workload demand, and node pressure. |
| <code>kubernetes.failed_scheduling</code> | fact | Event reports FailedScheduling. | Use its reason: resources, taints, affinity, volumes, and topology differ. |
| <code>kubernetes.probe_failures</code> | fact | Readiness/liveness/startup probe fails in Event/log; classifies timeout, refused, no route, address family, DNS, TLS, or HTTP where possible. | Test the exact endpoint from the proper network context and verify probe config. |
| <code>kubernetes.workload_degraded</code> | fact | Deployment/StatefulSet ready below desired; DaemonSet ready below desired scheduled; or Job failed with no success. | Inspect owned Pods and Events using kind-specific desired/ready fields. |
| <code>kubernetes.pod_waiting</code> | fact | A container has a diagnostic waiting reason not covered by image-pull or crash-loop rules. | Inspect the exact reason, current/previous logs, mounts, config, and runtime Events. |
| <code>kubernetes.init_container_failed</code> | fact | An init container waits with an error or exits nonzero. | Inspect init-container current/previous logs and the dependency it prepares. |
| <code>kubernetes.container_exit_nonzero</code> | fact | A container in a Failed Pod exited nonzero without OOMKilled/Completed. | Start from exit reason/code and previous logs. |
| <code>kubernetes.pod_evicted</code> | fact | Pod phase/reason reports eviction. | Correlate the eviction message with node pressure and QoS. |
| <code>kubernetes.pod_restart_storm</code> | fact | restartCount is at least five and the last termination is within one hour. | Inspect the latest previous log and first failure in the incident window. |
| <code>kubernetes.deployment_rollout_failed</code> | fact | Deployment reports ProgressDeadlineExceeded or ReplicaFailure. | Inspect ReplicaSets, unavailable Pods, admission, quota, and scheduling. |
| <code>kubernetes.daemonset_misscheduled</code> | fact | DaemonSet numberMisscheduled is nonzero. | Compare selectors, taints/tolerations, affinity, and node labels. |
| <code>kubernetes.statefulset_rollout_stalled</code> | fact | StatefulSet revisions differ while updated replicas remain incomplete. | Inspect the first non-updated ordinal and its storage/readiness constraints. |
| <code>kubernetes.job_failed</code> | fact | Job condition Failed=True. | Inspect failed Pods, backoffLimit, deadline, and exit codes. |
| <code>pdb.insufficient_healthy</code> | fact | currentHealthy is below desiredHealthy. | Restore workload health before maintenance; do not relax the PDB automatically. |
| <code>pdb.disruption_blocked</code> | fact | disruptionsAllowed is zero. | Treat it as maintenance context, not an outage by itself. |

### 12.5 IPv6, CNI, and Cilium

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>network.ipv6_disabled</code> | fact with correlated context | Effective net.ipv6.conf.*.disable_ipv6=1. Priority rises with same-node IPv6 Pods or address-family errors. | Compare intended Cilium address families and all-node sysctl consistency; reverse via controlled OS process. |
| <code>network.cni_unavailable</code> | hypothesis | CNI initialization, sandbox networking, plugin, or network-unavailable signatures. | Inspect same-node Cilium/runtime evidence; this may be a consequence. |
| <code>cilium.unhealthy</code> | fact | Cilium Pod/container missing, non-running, non-ready, waiting, or repeatedly failing. | Separate agent/operator scope; inspect logs, mounts/cgroups, Node and API. |
| <code>cilium.endpoint_unhealthy</code> | fact | CiliumEndpoint state is not ready or health not OK. | Map endpoint to Pod/node and inspect policy, identity, IP and agent. |
| <code>cilium.node_ipam_error</code> | fact | CiliumNode IPAM/operator status contains an explicit error. | Check pools, allocations, operator logs, and address conflicts. |
| <code>cilium.policy_import_failed</code> | fact | Cilium policy node status has ok=false or error. | Identify policy revision/node and validate policy and agent state. |
| <code>cilium.kube_proxy_replacement_disabled</code> | fact | kube-proxy Pods are absent and Cilium configuration explicitly disables replacement. | Verify effective replacement on every agent and use the approved Cilium rollout procedure. |
| <code>cilium.service_frontend_missing</code> | hypothesis | A node's read-only Cilium service map misses an expected Service ClusterIP/port. | Repeat the snapshot, then inspect service list, agent status, and watch errors. |

The cluster may intentionally run without kube-proxy. Its absence alone never produces a finding; with Cilium replacement enabled, this is the supported expected state.

### 12.6 cgroup and security agents

The <code>cgroup.*</code> rules and <code>security_agent.cgroup_denial</code> are disabled by <code>collection.collect_cgroup=false</code> or <code>--skip-cgroup</code>. The independent ptrace alert remains enabled because it does not derive from cgroup evidence. Existing collections without the recorded option preserve the previous cgroup behavior.

Exact read-only commands for checking one node manually, together with a sanitized result template, are available in the [separate guide](cgroup-manual-checks.md).

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>cgroup.controllers_missing</code> | hypothesis | On cgroup v2, cpu or io controller absent from collected hierarchy/delegation evidence. | Verify hierarchy, kernel arguments, systemd delegation, and security software. |
| <code>cgroup.driver_mismatch</code> | fact | Explicit kubelet and runtime cgroup driver values differ. | Align through the approved platform change procedure. |
| <code>cgroup.service_failure</code> | correlation | cgroup denial/failure and kubelet/runtime failure on same node within 15 minutes. | Order the timeline and inspect kernel/security audit evidence. |
| <code>security_agent.cgroup_denial</code> | correlation | KESL detected plus cgroup denial/failure in same node scope. | Record exact KESL build, kernel and denied operation; verify vendor policy/compatibility. It is not proof of cause. |
| <code>security_agent.ptrace_alert</code> | fact | Kernel/security-agent journal contains a ptrace attack message with the two involved processes. | Record both programs/PIDs and adjacent audit/KESL events; do not infer malicious intent or Kubernetes impact from the message alone. |

### 12.7 Service, EndpointSlice, and DNS

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>kubernetes.service_no_endpoints</code> | fact | Selector-based non-ExternalName Service has no EndpointSlice. | Compare selector/Pod labels and inspect controller, admission, readiness. |
| <code>kubernetes.service_no_ready_endpoints</code> | fact | Slices exist but no endpoint is ready and non-terminating. | Inspect Pod readiness and endpoint conditions, including intentional publish-not-ready use. |
| <code>kubernetes.service_port_unresolved</code> | hypothesis | Service port/target cannot be matched to EndpointSlice ports, or data is absent/inconsistent. | Compare port, targetPort, named container ports, and slice ports. |
| <code>dns.kube_dns_unavailable</code> | fact | kube-dns absent/no ready endpoints, or CoreDNS Pods absent/not Running/not fully ready. | Inspect CoreDNS, Service/Slices, Cilium, and upstream resolvers. |
| <code>dns.cluster_dns_mismatch</code> | fact | Explicit kubelet clusterDNS has no overlap with kube-dns ClusterIP values. | Check all address families/config sources, then use controlled rollout. |
| <code>dns.nameserver_limit_exceeded</code> | fact | The kubelet resolver contains more than three nameservers. | Check kubelet resolvConf and use a reviewed local caching resolver if required. |
| <code>dns.coredns_errors</code> | fact | CoreDNS logs contain SERVFAIL, forwarding-loop, or upstream-failure evidence. The report groups up to 20 extracted query names by type and occurrence count while retaining source line references. | Check the listed names for typos or nonexistent zones, then inspect forward targets, loop plugin, upstream reachability, and node resolver state. |
| <code>dns.coredns_config_empty</code> | fact | The coredns ConfigMap has no non-empty Corefile. | Restore the approved Corefile through change control. |

### 12.8 Control plane and API

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>controlplane.api_readyz_failed</code> | fact | Retrieved readyz verbose output contains failed named checks or endpoint failure. | Use the failed subcheck to select apiserver/dependency evidence. |
| <code>controlplane.authentication_config_read_error</code> | fact | kube-apiserver reports that its configured authentication file cannot be read. | Check the effective flag, mount/path, permissions, and Deckhouse reconciliation window; do not create an empty replacement file. |
| <code>controlplane.apiservice_unavailable</code> | fact | Aggregated APIService Available=False or Unknown. | Inspect reason, backing Service/endpoints, TLS and extension server. |
| <code>controlplane.node_lease_stale</code> | correlation | Node Lease absent or older than newest peer by max(120 s, 3 x leaseDurationSeconds). | Compare kubelet, API reachability, and clock; account for global API freeze. |
| <code>controlplane.static_pod_unhealthy</code> | fact | Collected etcd/apiserver/scheduler/controller-manager mirror Pod absent or unhealthy. | Map to control-plane node and inspect static manifest, kubelet, container, dependencies. |

### 12.9 etcd

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>etcd.unhealthy</code> | fact | Endpoint health false, unhealthy, timeout, or error. | Preserve member output; check quorum, network, disk latency, certificates. |
| <code>etcd.alarm_active</code> | fact | alarm list returns at least one active alarm. | Follow alarm-specific procedure; verify storage/backup before defrag/disarm. |
| <code>etcd.topology_inconsistent</code> | fact | No leader, multiple leader IDs, or multiple cluster IDs in expected peers. | Confirm timestamps/endpoints, then treat as quorum/topology incident. |
| <code>etcd.raft_apply_lag</code> | hypothesis | Applied Raft index or endpoint revision differs substantially. | Check disk fsync latency, network RTT, CPU pressure, and member logs. |
| <code>etcd.database_near_quota</code> | fact | dbSize reaches at least 80% of the configured backend quota. | Investigate keyspace growth and follow the approved compaction/defrag procedure. |
| <code>etcd.fragmentation_high</code> | hypothesis | A sufficiently large dbSize is more than twice dbSizeInUse. | Evaluate an online defrag window; kdiag does not run defrag. |
| <code>etcd.member_version_drift</code> | fact | Endpoint status reports different member versions. | Confirm whether this is a supported upgrade stage and complete alignment. |

### 12.10 Storage and CSI

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>storage.pvc_pending</code> | fact | PVC phase is Pending. | Inspect Events, class, binding mode, capacity/topology, and provisioner. |
| <code>storage.storage_class_missing</code> | fact | Explicit PVC storageClassName absent from collected StorageClasses. | Confirm spelling/lifecycle and provisioner before creating anything. |
| <code>storage.pv_failed</code> | fact | PV phase is Failed. | Inspect status, claim relation, CSI/backend; protect data first. |
| <code>storage.volume_attachment_failed</code> | fact | VolumeAttachment attached=false with attach/detach error. | Inspect driver, node, volume ID, topology, other attachments, controller logs. |
| <code>storage.csi_driver_registration_gap</code> | hypothesis | Driver used by PV/attachment missing from CSIDriver, or failed attachment driver missing from target CSINode. | Verify CSI controller/node registration; CSIDriver absence is not always invalid. |
| <code>storage.volume_operation_failure</code> | fact | Event reports FailedMount, FailedAttachVolume, or a related volume operation error. | Follow the Event reason to CSI/controller/node/storage evidence. |

### 12.11 Cross-source correlations

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>correlation.node_runtime_failure</code> | correlation | Node NotReady and kubelet/runtime failure within 15 minutes. | Order events and identify the first failing component. |
| <code>correlation.node_cni_failure</code> | correlation | Node/Pod sandbox failure and CNI/network failure within 15 minutes. | Inspect node-local Cilium/runtime state around the first event. |
| <code>correlation.memory_oom_failure</code> | correlation | MemoryPressure and OOM evidence within 15 minutes. | Distinguish node-global and workload-cgroup exhaustion. |
| <code>correlation.certificate_api_failure</code> | correlation | TLS/certificate error and API or time error within 15 minutes. | Verify clock and chain/expiry before rotating. |
| <code>correlation.conntrack_network_failure</code> | correlation | Conntrack exhaustion and network/probe failure within 15 minutes. | Verify occupancy/drops and traffic source before tuning. |
| <code>correlation.probe_network_failure</code> | correlation | Probe failure and network/DNS error occur in the same scope within 15 minutes. | Reproduce from the correct network context and identify the first event. |
| <code>correlation.storage_failure</code> | correlation | DiskPressure and filesystem/full/read-only evidence coincide on one node. | Protect data, map the affected mount/device, and order the timeline. |

### 12.12 Prometheus

| Rule | Type | What is checked | Safe first response |
|---|---|---|---|
| <code>prometheus.alert_firing</code> | fact | Optional Prometheus API returns firing alerts. | Follow the named alert and preserve its labels/annotations with cluster evidence. |
| <code>prometheus.config_reload_failed</code> | fact | Runtime information reports reloadConfigSuccess=false. | Inspect Prometheus configuration validation and reload logs. |
| <code>prometheus.corruption_detected</code> | fact | Runtime information reports a nonzero corruption counter. | Preserve storage/log evidence and follow the Prometheus recovery procedure. |

## 13. Collector troubleshooting

- **SSH fails:** verify the inventory-resolved host, OpenSSH config, host key, user/port, sudo -n, and remote Python. A working Ansible playbook is not sufficient because kdiag uses OpenSSH after inventory resolution.
- **A node utility is unsupported:** inspect the recorded command name. Deckhouse tools are searched in <code>/opt/deckhouse/bin</code>; an absent <code>nft</code> or <code>conntrack</code> executable is a missing userspace client, not proof that the kernel subsystem is absent.
- **Kubernetes Forbidden:** run auth can-i with the same kubeconfig/context and add only the missing read permission. Missing Cilium CRDs or CSIStorageCapacity can be valid; an RBAC denial is different from object absence.
- **readyz missing:** distinguish API/TLS/auth failure from missing non-resource URL permission. Absence is not the same as a failed internal readyz check.
- **etcd evidence missing:** verify the option, stacked topology, standard paths, etcdctl/crictl, container state, and sudo. Never copy a private key merely to suppress the finding.
- **truncation:** inspect counters/status first; increase the narrowest cap, reduce look-back or namespace scope only if the incident remains covered.
- **report regeneration:** use the report command on the collection and verify it afterward. Retain the original if evidentiary integrity matters.

## 14. Incident procedure

1. Record incident start and avoid changing nodes before the first capture where safe.
2. Run preflight from the management account.
3. Start a full snapshot; use node-only mode rather than waiting indefinitely for a dead API.
4. Preserve the directory and exit code.
5. Run verify and attach report, collection metadata, and manifest to the incident record.
6. Review evidence gaps before interpreting absent findings.
7. Triage facts, then correlations, then hypotheses.
8. Validate cited raw evidence and current live state.
9. Remediate through existing OS/Kubernetes/vendor procedures, one controlled step at a time.
10. Take a second snapshot and compare completeness/findings.

A backup is not required to collect. It matters before risky etcd, storage, certificate, or node remediation: confirm a recoverable backup and understood restore procedure.

## 15. Optional LLM package and manual external workflow

LLM processing is split into explicit stages. “Minimization” means selecting bounded diagnostic evidence and excluding raw bundles/full logs. “Pseudonymization” additionally replaces internal identifiers. The commands have non-overlapping responsibilities:

| Command | Creates an incident package | Pseudonymizes | Calls an LLM |
|---|---:|---:|---:|
| `llm prepare --profile local` | yes | no | no |
| `llm prepare --profile external` | yes | yes | no |
| `llm validate-export` | no | no | no |
| `llm analyze-local` | no | no | local service only |
| `llm import-response` | no | restores known external tokens | no |

The source collection remains confidential and is never given to an inference service. Both prepare profiles omit raw bundles and full logs, but include selected bounded evidence fragments with `status`, `value`, `excerpt`, and `timestamp` for their `EVIDENCE_NNN` identifiers. Fragment/event/fingerprint truncation is explicit in the package.

### 15.1 Prepare a local package

Create minimized input while retaining real operational identifiers inside the trusted environment:

~~~bash
python3.8 dist/kdiag.pyz llm prepare /var/lib/kdiag/<collection-id> \
  --output-dir /secure/llm-local \
  --profile local \
  --mode deep-analysis \
  --question "Explain the likely causes and evidence gaps"
~~~

This creates:

~~~text
/secure/llm-local/
  prepared/
    incident.local.json
    prompt.local.txt
    preview.md
    redaction-report.json
    manifest.json
  private/
    token-map.json
~~~

The local `prepared/` directory is not approved for external transfer. `incident.local.json` is the minimized incident package; `prompt.local.txt` is a separate model instruction artifact. `analyze-local` continues to accept a legacy local `export/` directory created by kdiag 0.5.0, validating it by content and manifest rather than by its directory name.

### 15.2 Analyze an already prepared local package

`analyze-local` does not read a collection and does not create another incident package. It verifies the manifest produced by `prepare --profile local`, reads `incident.local.json` and `prompt.local.txt` into the client process, and sends their contents—not file paths—to an OpenAI-compatible `/v1/chat/completions` endpoint:

~~~bash
python3.8 dist/kdiag.pyz llm analyze-local /secure/llm-local/prepared \
  --model local-model-name \
  --endpoint http://127.0.0.1:8080/v1/chat/completions \
  --timeout-seconds 180 \
  --max-output-tokens 2048 \
  --output-dir /secure/llm-local-response
~~~

Only literal loopback HTTP addresses `127.0.0.1` and `::1` are accepted. Credentials, query strings, arbitrary endpoint paths, remote hosts, and HTTPS endpoints are rejected. The inference service must run as an unprivileged identity without kubeconfig, SSH keys, collection-directory access, shell/tools, or Internet access. The model name is required because the model/runtime is deployment-specific and is not bundled with `kdiag.pyz`.

A hardened, offline llama.cpp example with a systemd unit and environment template is documented in [`deploy/systemd/README.md`](../deploy/systemd/README.md). Its pilot defaults must be tuned and benchmarked on the exact RED OS/GPU build.

The analysis directory contains:

~~~text
/secure/llm-local-response/
  response.raw.txt
  response.validated.json      # only when contract validation succeeds
  response.md
  analysis-report.json
  manifest.json
~~~

The response is always untrusted. `kdiag` validates the JSON contract and cited `EVIDENCE_NNN` identifiers and rejects responses containing mutating commands. Exit code `0` means a validated response, `1` means the service answered but the response contract was rejected, and `2` means package, endpoint, service, or I/O failure. No suggested command is executed.

### 15.3 Prepare a manual external package

For the manual Google “AI Search” workflow, prepare the external profile:

~~~bash
python3.8 dist/kdiag.pyz llm prepare /var/lib/kdiag/<collection-id> \
  --output-dir /secure/llm-external \
  --profile external \
  --mode fast-triage \
  --question "What are the most likely causes?"
python3.8 dist/kdiag.pyz llm validate-export /secure/llm-external/export
~~~

The external profile replaces node/host, namespace, Pod, Service, user/account/ServiceAccount, network-topology, path, UID, and endpoint values in findings and evidence fragments. It blocks the export when outbound DLP finds a residual IP/CIDR, MAC, DNS name, URL, e-mail, UID, absolute host path, credential pattern, private key, JWT, or canary. Component names and versions such as Kubernetes, Cilium, container runtime, etcd, CoreDNS, kernel, and RED OS are retained. Inspect `preview.md`, `incident.external.json`, `prompt.external.txt`, and `redaction-report.json`; then manually submit only the `export/` contents. Never transfer sibling `private/token-map.json`.

### 15.4 Import a manually saved external response

Save the external answer as a file and restore only known placeholders:

~~~bash
python3.8 dist/kdiag.pyz llm import-response /secure/google-response.txt \
  --token-map /secure/llm-external/private/token-map.json \
  --output-dir /secure/llm-response
~~~

The response is untrusted. The command preserves it unchanged, creates `response.restored.txt`, and reports unknown placeholders. Review every claim against cited `EVIDENCE_NNN` identifiers and the original collection before operational action.

## 16. Known limitations

- The pack recognizes documented structures and known signatures; it is not a universal root-cause engine.
- `kdiag` includes a loopback client but does not bundle, install, configure, or supervise a local model/runtime.
- Remediation is advisory and never automatic.
- Application logs need explicit namespace allowlist and RBAC.
- Node logs assume standard journald/CRI layouts.
- etcd supports standard stacked kubeadm-style local deployment only.
- Heavy-hitter counting may omit low-frequency unknown messages.
- A 15-minute window can miss slow incidents or correlate coincidences.
- Automated/synthetic tests do not replace a canary on the exact RED OS 7.x, kernel, runtime, Cilium, KESL, and Kubernetes builds.
- Baseline and continuous watch modes are not in this release.

## 17. Rule provenance and maintenance

Internet is not required at runtime. Rule metadata retains source links for engineering traceability. Kernel signatures are adapted from a pinned upstream Node Problem Detector configuration; attribution is in <code>THIRD_PARTY_NOTICES.md</code>.

For an update: pin upstream versions/licenses, define deterministic required evidence, add positive/negative/missing-source/truncation/correlation tests, classify fact/correlation/hypothesis, run all tests and self-test, record a new checksum, and transfer the exact artifact through the approved offline process.
