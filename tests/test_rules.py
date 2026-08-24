import json
import unittest
from pathlib import Path

from kdiag.normalize import normalize_evidence
from kdiag.rules import evaluate_rules


FIXTURES = Path(__file__).parent / "fixtures"


def node_snapshot(kernel, ipv6="0"):
    return {
        "host": {"kernel_release": kernel},
        "facts": {
            "boot_changed_during_collection": False,
            "root_disk": {"total_bytes": 100, "free_bytes": 50},
            "ipv6_disable": {"all": ipv6},
            "cgroup": {"mode": "v2", "controllers": ["cpu", "io", "memory", "pids"]},
            "service_states": {"kubelet.service": {"status": "collected", "properties": {"ActiveState": "active"}}},
        },
        "commands": [],
    }


class RulesTest(unittest.TestCase):
    def test_new_troubleshooting_rules_use_read_only_evidence(self):
        kubernetes = {
            "collected_at": "2026-01-01T00:10:00Z",
            "sources": {
                "nodes": {"status": "collected", "data": {"items": [{"metadata": {"name": "node-1"}, "status": {"nodeInfo": {"kubeletVersion": "v1.27.1"}, "conditions": []}}]}},
                "pods": {"status": "collected", "data": {"items": [
                    {"metadata": {"namespace": "kube-system", "name": "kube-apiserver-node-1"}, "spec": {"containers": [{"name": "kube-apiserver", "image": "registry/kube-apiserver:v1.24.17"}]}, "status": {"phase": "Running", "containerStatuses": [{"name": "kube-apiserver", "ready": True}]}},
                    {"metadata": {"namespace": "demo", "name": "failed"}, "spec": {"containers": [{"name": "app"}], "initContainers": [{"name": "init"}]}, "status": {"phase": "Failed", "reason": "Evicted", "initContainerStatuses": [{"name": "init", "restartCount": 0, "state": {"waiting": {"reason": "RunContainerError", "message": "cannot start"}}}], "containerStatuses": [{"name": "app", "restartCount": 5, "state": {"terminated": {"exitCode": 2, "reason": "Error"}}, "lastState": {"terminated": {"exitCode": 2, "finishedAt": "2026-01-01T00:09:30Z"}}}]}},
                ]}},
                "events": {"status": "collected", "data": {"items": []}},
                "workloads": {"status": "collected", "data": {"items": [
                    {"kind": "Deployment", "metadata": {"namespace": "demo", "name": "api"}, "spec": {"replicas": 2}, "status": {"conditions": [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}]}},
                    {"kind": "DaemonSet", "metadata": {"namespace": "demo", "name": "agent"}, "status": {"numberMisscheduled": 1}},
                    {"kind": "StatefulSet", "metadata": {"namespace": "demo", "name": "db"}, "spec": {"replicas": 2}, "status": {"currentRevision": "a", "updateRevision": "b", "updatedReplicas": 1}},
                    {"kind": "Job", "metadata": {"namespace": "demo", "name": "job"}, "status": {"conditions": [{"type": "Failed", "status": "True"}]}},
                ]}},
                "pdb": {"status": "collected", "data": {"items": [{"kind": "PodDisruptionBudget", "metadata": {"namespace": "demo", "name": "api"}, "status": {"expectedPods": 2, "currentHealthy": 1, "desiredHealthy": 2, "disruptionsAllowed": 0}}]}},
                "services": {"status": "collected", "data": {"items": [{"kind": "Service", "metadata": {"namespace": "demo", "name": "api"}, "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.20", "clusterIPs": ["10.96.0.20"], "ports": [{"port": 80}]}}]}},
                "cilium_config": {"status": "collected", "required": False, "data": {"data": {"kube-proxy-replacement": "false"}}},
                "coredns_config": {"status": "collected", "required": False, "data": {"corefilePresent": False}},
            },
            "logs": {"status": "collected", "entries": []},
        }
        snapshot = node_snapshot("6.1")
        snapshot["facts"].update({
            "swaps": {"status": "collected", "text": "Filename Type Size Used Priority\n/dev/zram0 partition 1 0 1\n"},
            "resolv_conf": {"status": "collected", "nameservers": ["1", "2", "3", "4"]},
            "kubelet_config": {"status": "collected", "values": {"failSwapOn": "true", "rotateCertificates": "true"}},
            "kubelet_certificate_rotation": {"status": "broken"},
            "etcd": {"status": "collected", "quota_backend_bytes": 200000000},
        })
        snapshot["commands"] = [
            {"id": "runtime_crictl_info", "status": "collected", "stdout": '{"status":{"conditions":[{"type":"RuntimeReady","status":false},{"type":"NetworkReady","status":false}]}}'},
            {"id": "df_blocks", "status": "collected", "stdout": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 100 95 5 95% /var/lib/containerd\n"},
            {"id": "cilium_debug_services", "status": "collected", "stdout": '{"services":[{"frontend":{"ip":"10.96.0.10","port":53}}]}'},
            {"id": "etcd_endpoint_health", "status": "collected", "stdout": '[{"endpoint":"a","health":true}]'},
            {"id": "etcd_alarm_list", "status": "collected", "stdout": '{"alarms":[]}'},
            {"id": "etcd_endpoint_status", "status": "collected", "stdout": '[{"Endpoint":"a","Status":{"header":{"cluster_id":"1","revision":5000},"leader":"1","version":"3.5.1","raftIndex":5000,"raftAppliedIndex":3000,"dbSize":180000000,"dbSizeInUse":50000000}},{"Endpoint":"b","Status":{"header":{"cluster_id":"1","revision":3000},"leader":"1","version":"3.5.2","raftIndex":3000,"raftAppliedIndex":3000,"dbSize":180000000,"dbSizeInUse":50000000}}]'},
        ]
        snapshot["pod_logs"] = {"status": "collected", "entries": []}
        collection = {"collection_id": "new", "ended_at": "2026-01-01T00:10:00Z", "nodes": [{"host": "node-1", "status": "collected"}]}
        normalized = {
            "events": [{"event_id": "v", "categories": ["volume_error"], "source": "kubernetes_event", "evidence": "kubernetes.json.gz#events", "namespace": "demo", "pod": "failed"}],
            "correlations": [
                {"correlation_id": "probe_network_failure", "scope": "node-1", "categories": ["probe_failure", "timeout"], "sources": ["journal"], "window_seconds": 900, "evidence": ["e1", "e2"]},
                {"correlation_id": "storage_failure", "scope": "node-1", "categories": ["disk_pressure", "disk_full"], "sources": ["journal"], "window_seconds": 900, "evidence": ["e3", "e4"]},
            ],
        }
        prometheus = {"sources": {"alerts": {"status": "collected", "data": {"alerts": [{"state": "firing", "labels": {"alertname": "Demo"}}]}}, "runtimeinfo": {"status": "collected", "data": {"reloadConfigSuccess": False, "corruptionCount": 1}}}}
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, kubernetes, normalized, prometheus)}
        expected = {
            "correlation.probe_network_failure", "correlation.storage_failure", "storage.volume_operation_failure",
            "kubernetes.init_container_failed", "kubernetes.container_exit_nonzero", "kubernetes.pod_evicted", "kubernetes.pod_restart_storm",
            "kubernetes.deployment_rollout_failed", "kubernetes.daemonset_misscheduled", "kubernetes.statefulset_rollout_stalled", "kubernetes.job_failed",
            "pdb.insufficient_healthy", "pdb.disruption_blocked", "runtime.cri_not_ready", "runtime.cri_network_not_ready", "node.swap_active", "node.low_runtime_disk",
            "dns.nameserver_limit_exceeded", "dns.coredns_config_empty", "certificate.kubelet_rotation_broken", "inventory.unsupported_version_skew",
            "prometheus.alert_firing", "prometheus.config_reload_failed", "prometheus.corruption_detected",
            "cilium.kube_proxy_replacement_disabled", "cilium.service_frontend_missing",
            "etcd.raft_apply_lag", "etcd.database_near_quota", "etcd.fragmentation_high", "etcd.member_version_drift",
        }
        self.assertFalse(expected - rule_ids, "missing rules: {0}".format(sorted(expected - rule_ids)))

    def test_mixed_kernel_and_ipv6_findings(self):
        collection = {"nodes": [{"host": "n1", "status": "collected"}, {"host": "n2", "status": "collected"}]}
        nodes = {"n1": node_snapshot("5.15", "1"), "n2": node_snapshot("6.1")}
        kubernetes = {
            "sources": {
                "pods": {"data": {"items": [{"metadata": {"namespace": "n", "name": "p"}, "status": {"podIPs": [{"ip": "fd00::1"}]}}]}},
                "events": {"data": {"items": []}},
            }
        }
        findings = evaluate_rules(collection, nodes, kubernetes)
        rule_ids = {item["rule_id"] for item in findings}
        self.assertIn("inventory.mixed_kernel", rule_ids)
        self.assertIn("network.ipv6_disabled", rule_ids)

    def test_kube_proxy_free_cilium_cluster_is_supported(self):
        kubernetes = {
            "sources": {
                "pods": {"status": "collected", "data": {"items": []}},
                "services": {"status": "collected", "data": {"items": []}},
                "cilium_config": {
                    "status": "collected",
                    "data": {"data": {"kube-proxy-replacement": "true"}},
                },
            }
        }
        findings = evaluate_rules({"nodes": []}, {}, kubernetes)
        rule_ids = {item["rule_id"] for item in findings}
        self.assertNotIn("cilium.kube_proxy_replacement_disabled", rule_ids)

    def test_missing_cilium_replacement_setting_is_not_reported_as_disabled(self):
        kubernetes = {
            "sources": {
                "pods": {"status": "collected", "data": {"items": []}},
                "services": {"status": "collected", "data": {"items": []}},
                "cilium_config": {"status": "collected", "data": {"data": {}}},
            }
        }
        findings = evaluate_rules({"nodes": []}, {}, kubernetes)
        rule_ids = {item["rule_id"] for item in findings}
        self.assertNotIn("cilium.kube_proxy_replacement_disabled", rule_ids)

    def test_extended_rule_pack_on_synthetic_incident(self):
        journal = (FIXTURES / "journal-synthetic.jsonl").read_text(encoding="utf-8")
        kubernetes = json.loads((FIXTURES / "kubernetes-synthetic.json").read_text(encoding="utf-8"))
        snapshot = node_snapshot("6.1")
        snapshot.update(
            {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [
                    {"id": "journal_services_current", "status": "collected", "stdout": journal},
                    {"id": "journal_kernel_current", "status": "collected", "stdout": ""},
                    {"id": "df_inodes", "status": "collected", "stdout": "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda 100 98 2 98% /var/lib\n"},
                    {"id": "timedatectl", "status": "collected", "stdout": "NTPSynchronized=no\n"},
                    {"id": "chrony_tracking", "status": "collected", "stdout": "Leap status     : Not synchronised\n"},
                    {"id": "installed_packages", "status": "collected", "stdout": "kesl|0|12.1|1|x86_64\n"},
                    {"id": "runtime_crictl_info", "status": "collected", "stdout": "{\"config\":{\"SystemdCgroup\":false}}"},
                ],
                "pod_logs": {"status": "collected", "entries": []},
            }
        )
        snapshot["facts"]["service_states"].update(
            {
                "kubelet.service": {"status": "collected", "properties": {"ActiveState": "failed"}},
                "containerd.service": {"status": "collected", "properties": {"ActiveState": "failed"}},
                "crio.service": {"status": "unavailable", "properties": {}},
            }
        )
        snapshot["facts"]["certificates"] = [
            {"path": "/etc/kubernetes/pki/apiserver.crt", "metadata": "notAfter=Dec 31 00:00:00 2025 GMT\n"}
        ]
        snapshot["facts"]["kubelet_config"] = {"status": "collected", "values": {"cgroupDriver": "systemd"}}
        collection = {
            "collection_id": "synthetic",
            "ended_at": "2026-01-01T00:10:00Z",
            "nodes": [{"host": "node-1", "status": "collected"}],
        }
        nodes = {"node-1": snapshot}
        normalized = normalize_evidence(collection, nodes, kubernetes)
        findings = evaluate_rules(collection, nodes, kubernetes, normalized)
        rule_ids = {item["rule_id"] for item in findings}
        expected = {
            "node.low_inodes",
            "node.kubelet_inactive",
            "node.runtime_inactive",
            "node.oom_detected",
            "node.conntrack_full",
            "kubernetes.node_not_ready",
            "kubernetes.node_pressure",
            "kubernetes.pod_crash_loop",
            "kubernetes.image_pull_failure",
            "kubernetes.pod_oom_killed",
            "kubernetes.failed_scheduling",
            "kubernetes.workload_degraded",
            "network.cni_unavailable",
            "cilium.unhealthy",
            "security_agent.cgroup_denial",
            "time.not_synchronized",
            "certificate.expiring",
            "correlation.node_runtime_failure",
            "correlation.node_cni_failure",
            "correlation.memory_oom_failure",
            "cgroup.service_failure",
            "cgroup.driver_mismatch",
            "correlation.conntrack_network_failure",
        }
        self.assertFalse(expected - rule_ids, "missing rules: {0}".format(sorted(expected - rule_ids)))
        self.assertTrue(all(item.get("source_refs") for item in findings))
        self.assertTrue(all(item.get("classification") in ("fact", "correlation", "hypothesis") for item in findings))

    def test_second_generation_rule_pack_on_structured_incident(self):
        kubernetes = json.loads((FIXTURES / "kubernetes-extended-synthetic.json").read_text(encoding="utf-8"))
        snapshot = node_snapshot("6.1")
        snapshot["ended_at"] = "2026-01-01T00:10:00Z"
        snapshot["facts"]["kubelet_config"] = {"status": "collected", "values": {"clusterDNS": ["10.97.0.10"]}}
        snapshot["facts"]["etcd"] = {"status": "collected", "transport": "crictl"}
        snapshot["commands"] = [
            {"id": "journal_services_current", "status": "collected", "stdout": ""},
            {"id": "journal_kernel_current", "status": "collected", "stdout": (FIXTURES / "journal-npd-synthetic.jsonl").read_text(encoding="utf-8")},
            {"id": "etcd_endpoint_health", "status": "collected", "stdout": '[{"endpoint":"https://node-1:2379","health":false,"error":"connection failed"}]'},
            {"id": "etcd_alarm_list", "status": "collected", "stdout": '{"alarms":[{"memberID":"1","alarm":"NOSPACE"}]}'},
            {"id": "etcd_endpoint_status", "status": "collected", "stdout": '[{"Endpoint":"a","Status":{"header":{"cluster_id":"1"},"leader":"0"}},{"Endpoint":"b","Status":{"header":{"cluster_id":"2"},"leader":"2"}}]'},
        ]
        snapshot["pod_logs"] = {"status": "collected", "entries": []}
        collection = {"collection_id": "extended", "ended_at": "2026-01-01T00:10:00Z", "nodes": [{"host": "node-1", "status": "collected"}]}
        normalized = normalize_evidence(collection, {"node-1": snapshot}, kubernetes)
        findings = evaluate_rules(collection, {"node-1": snapshot}, kubernetes, normalized)
        rule_ids = {item["rule_id"] for item in findings}
        expected = {
            "node.kernel_oops",
            "node.task_hung",
            "node.filesystem_error",
            "node.filesystem_warning",
            "node.io_error",
            "node.hardware_error",
            "node.unregister_netdevice",
            "kubernetes.service_no_endpoints",
            "kubernetes.service_no_ready_endpoints",
            "kubernetes.service_port_unresolved",
            "dns.kube_dns_unavailable",
            "dns.cluster_dns_mismatch",
            "controlplane.api_readyz_failed",
            "controlplane.apiservice_unavailable",
            "controlplane.node_lease_stale",
            "controlplane.static_pod_unhealthy",
            "etcd.unhealthy",
            "etcd.alarm_active",
            "etcd.topology_inconsistent",
            "storage.pvc_pending",
            "storage.storage_class_missing",
            "storage.pv_failed",
            "storage.volume_attachment_failed",
            "storage.csi_driver_registration_gap",
            "cilium.endpoint_unhealthy",
            "cilium.node_ipam_error",
            "cilium.policy_import_failed",
        }
        self.assertFalse(expected - rule_ids, "missing rules: {0}".format(sorted(expected - rule_ids)))

    def test_healthy_structured_evidence_does_not_trigger_extended_rules(self):
        kubernetes = {
            "collected_at": "2026-01-01T00:10:00Z",
            "sources": {
                "nodes": {"status": "collected", "data": {"items": [{"metadata": {"name": "node-1"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}},
                "pods": {"status": "collected", "data": {"items": [
                    {"metadata": {"namespace": "kube-system", "name": "coredns-ok", "labels": {"k8s-app": "kube-dns"}}, "status": {"phase": "Running", "containerStatuses": [{"name": "coredns", "ready": True}]}, "spec": {"nodeName": "node-1"}},
                    {"metadata": {"namespace": "kube-system", "name": "kube-apiserver-node-1", "labels": {"component": "kube-apiserver"}}, "status": {"phase": "Running", "containerStatuses": [{"name": "kube-apiserver", "ready": True}]}, "spec": {"nodeName": "node-1"}},
                ]}},
                "events": {"status": "collected", "data": {"items": []}},
                "services": {"status": "collected", "data": {"items": [
                    {"metadata": {"namespace": "demo", "name": "good"}, "spec": {"type": "ClusterIP", "selector": {"app": "good"}, "ports": [{"name": "http", "port": 80, "targetPort": 8080}]}},
                    {"metadata": {"namespace": "kube-system", "name": "kube-dns"}, "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.10", "clusterIPs": ["10.96.0.10"], "selector": {"k8s-app": "kube-dns"}, "ports": [{"name": "dns", "port": 53, "targetPort": 53}]}},
                    {"metadata": {"namespace": "demo", "name": "external"}, "spec": {"type": "ExternalName", "selector": {}, "ports": []}},
                ]}},
                "endpoint_slices": {"status": "collected", "data": {"items": [
                    {"metadata": {"namespace": "demo", "labels": {"kubernetes.io/service-name": "good"}}, "ports": [{"name": "http", "port": 8080}], "endpoints": [{"conditions": {"ready": True}}]},
                    {"metadata": {"namespace": "kube-system", "labels": {"kubernetes.io/service-name": "kube-dns"}}, "ports": [{"name": "dns", "port": 53}], "endpoints": [{"conditions": {"ready": True}}]},
                ]}},
                "api_readyz": {"status": "collected", "data": {"checks": [{"name": "etcd", "status": "passed"}]}},
                "api_services": {"status": "collected", "data": {"items": [{"metadata": {"name": "v1.metrics"}, "status": {"conditions": [{"type": "Available", "status": "True"}]}}]}},
                "leases": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "kube-node-lease", "name": "node-1"}, "spec": {"renewTime": "2026-01-01T00:09:59Z", "leaseDurationSeconds": 40}}]}},
                "pvc": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "demo", "name": "data"}, "spec": {"storageClassName": "default"}, "status": {"phase": "Bound"}}]}},
                "pv": {"status": "collected", "data": {"items": [{"metadata": {"name": "pv-good"}, "spec": {"csi": {"driver": "good.csi.example"}}, "status": {"phase": "Bound"}}]}},
                "storage_classes": {"status": "collected", "data": {"items": [{"metadata": {"name": "default"}}]}},
                "volume_attachments": {"status": "collected", "data": {"items": [{"metadata": {"name": "attach-good"}, "spec": {"nodeName": "node-1", "source": {"persistentVolumeName": "pv-good"}}, "status": {"attached": True}}]}},
                "csi_drivers": {"status": "collected", "data": {"items": [{"metadata": {"name": "good.csi.example"}}]}},
                "csi_nodes": {"status": "collected", "data": {"items": [{"metadata": {"name": "node-1"}, "spec": {"drivers": [{"name": "good.csi.example"}]}}]}},
                "cilium_endpoints": {"status": "collected", "required": False, "data": {"items": [{"metadata": {"namespace": "demo", "name": "app"}, "status": {"state": "ready", "health": {"overallHealth": "ok"}}}]}},
                "cilium_nodes": {"status": "collected", "required": False, "data": {"items": [{"metadata": {"name": "node-1"}, "status": {"ipam": {"operatorStatus": {"error": ""}}}}]}},
                "cilium_network_policies": {"status": "collected", "required": False, "data": {"items": [{"metadata": {"namespace": "demo", "name": "allow"}, "status": {"nodes": [{"node": "node-1", "ok": True, "error": ""}]}}]}},
            },
            "logs": {"status": "collected", "entries": []},
        }
        snapshot = node_snapshot("6.1")
        snapshot["ended_at"] = "2026-01-01T00:10:00Z"
        snapshot["facts"]["kubelet_config"] = {"status": "collected", "values": {"clusterDNS": ["10.96.0.10"]}}
        snapshot["facts"]["etcd"] = {"status": "collected"}
        snapshot["commands"] = [
            {"id": "journal_services_current", "status": "collected", "stdout": ""},
            {"id": "journal_kernel_current", "status": "collected", "stdout": ""},
            {"id": "etcd_endpoint_health", "status": "collected", "stdout": '[{"endpoint":"a","health":true}]'},
            {"id": "etcd_alarm_list", "status": "collected", "stdout": '{"alarms":[]}'},
            {"id": "etcd_endpoint_status", "status": "collected", "stdout": '[{"Endpoint":"a","Status":{"header":{"cluster_id":"1"},"leader":"1"}}]'},
        ]
        snapshot["pod_logs"] = {"status": "collected", "entries": []}
        collection = {"collection_id": "healthy", "ended_at": "2026-01-01T00:10:00Z", "nodes": [{"host": "node-1", "status": "collected"}]}
        normalized = normalize_evidence(collection, {"node-1": snapshot}, kubernetes)
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, kubernetes, normalized)}
        extended = {rule_id for rule_id in rule_ids if rule_id.startswith(("dns.", "controlplane.", "etcd.", "storage.")) or rule_id in {"kubernetes.service_no_endpoints", "kubernetes.service_no_ready_endpoints", "kubernetes.service_port_unresolved", "cilium.endpoint_unhealthy", "cilium.node_ipam_error", "cilium.policy_import_failed"} or rule_id.startswith("node.kernel_") or rule_id in {"node.task_hung", "node.filesystem_error", "node.filesystem_warning", "node.io_error", "node.hardware_error", "node.unregister_netdevice"}}
        self.assertEqual(set(), extended)


if __name__ == "__main__":
    unittest.main()
