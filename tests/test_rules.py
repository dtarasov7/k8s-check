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
    def test_empty_normalized_incident_does_not_restore_old_raw_probe_events(self):
        kubernetes = {
            "sources": {
                "events": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "reason": "Unhealthy",
                                "note": "Readiness probe failed: connection refused",
                                "lastTimestamp": "2026-08-27T09:00:00Z",
                                "regarding": {"kind": "Pod", "namespace": "demo", "name": "old-pod"},
                            }
                        ]
                    },
                }
            }
        }
        findings = evaluate_rules(
            {"collection_id": "incident", "nodes": []},
            {},
            kubernetes,
            {"events": [], "correlations": [], "stats": {}},
        )
        self.assertNotIn("kubernetes.probe_failures", {item["rule_id"] for item in findings})

    def test_truncated_journals_have_concise_actionable_collection_gap(self):
        nodes = {}
        collection_nodes = []
        for node_name in ("node-a", "node-b"):
            snapshot = node_snapshot("6.1")
            snapshot["commands"] = [
                {"id": "journal_services_current", "status": "truncated", "truncated": True},
                {"id": "journal_kernel_current", "status": "collected", "truncated": False},
            ]
            snapshot["pod_logs"] = {"status": "collected", "entries": []}
            nodes[node_name] = snapshot
            collection_nodes.append({"host": node_name, "status": "collected"})
        finding = next(
            item for item in evaluate_rules({"nodes": collection_nodes}, nodes, {})
            if item["rule_id"] == "collector.evidence_gap"
        )
        self.assertEqual("служебный журнал текущей загрузки: усечён лимитом размера (2)", finding["summary"])
        self.assertIn("collection.max_command_bytes", finding["recommendation"])
        self.assertIn("collection.since_hours", finding["recommendation"])
        self.assertNotIn("node-a/journal", finding["summary"])

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
            "kubernetes.deployment_rollout_failed", "kubernetes.daemonset_misscheduled", "kubernetes.job_failed",
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

    def test_inventory_alias_matches_kubernetes_node_fqdn(self):
        snapshot = node_snapshot("6.1")
        snapshot["host"].update({"hostname": "node-1", "fqdn": "node-1.example.test"})
        kubernetes = {
            "sources": {
                "nodes": {
                    "status": "collected",
                    "data": {"items": [{"metadata": {"name": "node-1.example.test"}, "status": {"conditions": []}}]},
                }
            }
        }
        collection = {"nodes": [{"host": "node-1", "status": "collected"}]}
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, kubernetes)}
        self.assertNotIn("inventory.node_set_mismatch", rule_ids)

    def test_resolved_controlplane_auth_config_is_hidden_but_ptrace_is_reported(self):
        normalized = {
            "events": [
                {
                    "event_id": "auth",
                    "categories": ["authentication_config_read_error"],
                    "source": "kubernetes_pod_log",
                    "component": "kube-apiserver",
                    "evidence": "kubernetes.json.gz#logs.entries[0]",
                    "message_excerpt": "Failed to read authentication config file /etc/kubernetes/deckhouse/extra0files/authentication-config.yaml: no such file or directory",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "occurrence_count": 2,
                },
                {
                    "event_id": "ptrace",
                    "categories": ["ptrace_security_alert"],
                    "source": "journal",
                    "component": "kernel",
                    "node": "node-1",
                    "evidence": "node-node-1.json.gz#commands.journal_kernel_current:line-1",
                    "message_excerpt": "ptrace attack of vendor agent was attempted by security agent",
                    "timestamp": "2026-01-01T00:01:00Z",
                },
            ],
            "correlations": [],
        }
        nodes = {
            "node-1": {
                "facts": {
                    "authentication_config_files": [
                        {
                            "path": "/etc/kubernetes/deckhouse/extra-files/authentication-config.yaml",
                            "status": "present",
                            "regular_file": True,
                            "readable": True,
                        }
                    ]
                }
            }
        }
        kubernetes = {
            "sources": {
                "api_readyz": {"status": "collected", "data": {"checks": [{"name": "etcd", "status": "passed"}]}},
                "pods": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {"namespace": "kube-system", "name": "kube-apiserver-node-1"},
                                "spec": {"containers": [{"name": "kube-apiserver"}]},
                                "status": {
                                    "phase": "Running",
                                    "containerStatuses": [{"name": "kube-apiserver", "ready": True, "restartCount": 0}],
                                },
                            }
                        ]
                    },
                },
            }
        }
        findings = evaluate_rules({"nodes": []}, nodes, kubernetes, normalized)
        rule_ids = {item["rule_id"] for item in findings}
        self.assertNotIn("controlplane.authentication_config_read_error", rule_ids)
        self.assertIn("security_agent.ptrace_alert", rule_ids)

    def test_repeated_unresolved_auth_config_error_is_reported(self):
        normalized = {
            "events": [
                {
                    "event_id": "auth",
                    "categories": ["authentication_config_read_error"],
                    "source": "kubernetes_pod_log",
                    "component": "kube-apiserver",
                    "message_excerpt": "Failed to read authentication config file: no such file or directory",
                    "occurrence_count": 2,
                }
            ],
            "correlations": [],
        }
        findings = evaluate_rules({"nodes": []}, {}, {}, normalized)
        self.assertIn("controlplane.authentication_config_read_error", {item["rule_id"] for item in findings})

    def test_one_off_auth_config_race_is_not_reported(self):
        normalized = {
            "events": [
                {
                    "event_id": "auth",
                    "categories": ["authentication_config_read_error"],
                    "source": "kubernetes_pod_log",
                    "component": "kube-apiserver",
                    "message_excerpt": "Failed to read authentication config file: no such file or directory",
                    "occurrence_count": 1,
                }
            ],
            "correlations": [],
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, {}, normalized)}
        self.assertNotIn("controlplane.authentication_config_read_error", rule_ids)

    def test_runtime_service_detection_supports_deckhouse_and_ignores_not_found(self):
        snapshot = node_snapshot("6.1")
        snapshot["facts"]["service_states"].update(
            {
                "containerd.service": {
                    "status": "collected",
                    "properties": {"LoadState": "not-found", "ActiveState": "inactive"},
                },
                "containerd-deckhouse.service": {
                    "status": "collected",
                    "properties": {"LoadState": "loaded", "ActiveState": "active"},
                },
                "crio.service": {
                    "status": "collected",
                    "properties": {"LoadState": "not-found", "ActiveState": "inactive"},
                },
            }
        )
        collection = {"nodes": [{"host": "node-1", "status": "collected"}]}
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, {})}
        self.assertNotIn("node.runtime_inactive", rule_ids)

        snapshot["facts"]["service_states"]["containerd-deckhouse.service"]["properties"]["ActiveState"] = "failed"
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, {})}
        self.assertIn("node.runtime_inactive", rule_ids)

    def test_kubernetes_131_versions_are_in_scope(self):
        kubernetes = {
            "sources": {
                "nodes": {
                    "status": "collected",
                    "data": {"items": [{"metadata": {"name": "node-1"}, "status": {"nodeInfo": {"kubeletVersion": "v1.31.14"}}}]},
                },
                "pods": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {"namespace": "kube-system", "name": "kube-apiserver-node-1"},
                                "spec": {"containers": [{"name": "kube-apiserver", "image": "registry/kube-apiserver:v1.31.14"}]},
                                "status": {"phase": "Running", "containerStatuses": [{"name": "kube-apiserver", "ready": True}]},
                            }
                        ]
                    },
                },
            }
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, kubernetes)}
        self.assertNotIn("inventory.unsupported_version_skew", rule_ids)

    def test_version_skew_uses_newest_and_oldest_apiserver_boundaries(self):
        def evidence(kubelet_version):
            return {
                "sources": {
                    "nodes": {"status": "collected", "data": {"items": [{"metadata": {"name": "node-1"}, "status": {"nodeInfo": {"kubeletVersion": kubelet_version}}}]}},
                    "pods": {
                        "status": "collected",
                        "data": {
                            "items": [
                                {"metadata": {"namespace": "kube-system", "name": "kube-apiserver-a"}, "spec": {"containers": [{"name": "kube-apiserver", "image": "kube-apiserver:v1.30.9"}]}},
                                {"metadata": {"namespace": "kube-system", "name": "kube-apiserver-b"}, "spec": {"containers": [{"name": "kube-apiserver", "image": "kube-apiserver:v1.31.4"}]}},
                            ]
                        },
                    },
                }
            }

        allowed = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, evidence("v1.28.12"))}
        self.assertIn("inventory.mixed_apiserver_versions", allowed)
        self.assertNotIn("inventory.unsupported_version_skew", allowed)
        unsupported = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, evidence("v1.27.16"))}
        self.assertIn("inventory.unsupported_version_skew", unsupported)

    def test_erofs_snapshot_mounts_are_not_runtime_filesystems(self):
        snapshot = node_snapshot("6.1")
        snapshot["commands"] = [
            {
                "id": "df_blocks",
                "status": "collected",
                "stdout": (
                    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    "erofs 1024 1024 0 100% "
                    "/var/lib/containerd/io.containerd.snapshotter.v1.erofs/"
                    "snapshots/42/k8s.mountpoints/rootfs\n"
                ),
            }
        ]
        collection = {"nodes": [{"host": "node-1", "status": "collected"}]}
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, {})}
        self.assertNotIn("node.low_runtime_disk", rule_ids)

        snapshot["commands"][0]["stdout"] += "/dev/vdb 100 95 5 95% /var/lib\n"
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, {})}
        self.assertIn("node.low_runtime_disk", rule_ids)

    def test_coredns_finding_summarizes_failed_queries(self):
        kubernetes = {
            "collected_at": "2026-01-01T00:10:00Z",
            "sources": {},
            "logs": {
                "entries": [
                    {
                        "namespace": "kube-system",
                        "pod": "coredns-test",
                        "container": "coredns",
                        "text": "\n".join(
                            (
                                "2026-01-01T00:00:01Z [ERROR] plugin/errors: 2 misspelled.svc.cluster.local. A: read udp: i/o timeout",
                                "2026-01-01T00:00:02Z [ERROR] plugin/errors: 2 misspelled.svc.cluster.local. A: read udp: i/o timeout",
                                '2026-01-01T00:00:03Z [INFO] client - 42 "AAAA IN wrong-name.example. udp 50 false 1232" SERVFAIL',
                                "2026-01-01T00:00:04Z plugin/loop: Loop detected for zone .",
                                "2026-01-01T00:00:05Z [ERROR] plugin/errors: 2 smoke-mini-a.d8-system.svc.cluster.local. A: read udp: i/o timeout",
                                '2026-01-01T00:00:06Z [INFO] client - 42 "AAAA IN real-service.demo.svc.cluster.local. udp 50 false 1232" SERVFAIL',
                            )
                        ),
                    }
                ]
            },
        }
        normalized = normalize_evidence({"collection_id": "dns"}, {}, kubernetes)
        self.assertEqual(1, normalized["stats"]["dns_smoke_events_suppressed"])
        findings = evaluate_rules({"nodes": []}, {}, kubernetes, normalized)
        finding = next(item for item in findings if item["rule_id"] == "dns.coredns_errors")
        self.assertIn("misspelled.svc.cluster.local [A] ×2", finding["summary"])
        self.assertIn("wrong-name.example [AAAA] ×1", finding["summary"])
        self.assertIn("из 4/5 событий", finding["summary"])
        self.assertNotIn("smoke-mini-", json.dumps(finding))
        self.assertEqual(5, finding["event_count"])
        self.assertTrue(any("line-1" in value for value in finding["evidence"]))

    def test_disabled_cgroup_checks_produce_no_cgroup_findings(self):
        snapshot = node_snapshot("6.1")
        snapshot["facts"]["cgroup"] = {"mode": "v2", "controllers": []}
        snapshot["facts"]["kubelet_config"] = {"values": {"cgroupDriver": "systemd"}}
        snapshot["commands"] = [
            {"id": "installed_packages", "stdout": "kesl|12.1"},
            {"id": "journal_services_current", "stdout": "cgroup permission denied"},
            {"id": "runtime_crictl_info", "stdout": '{"SystemdCgroup":false}'},
        ]
        normalized = {
            "events": [],
            "correlations": [
                {
                    "correlation_id": "cgroup_service_failure",
                    "scope": "node-1",
                    "categories": ["cgroup_access_denied", "runtime_unavailable"],
                    "sources": ["journal"],
                    "window_seconds": 900,
                    "evidence": ["e1", "e2"],
                }
            ],
        }
        collection = {
            "nodes": [{"host": "node-1", "status": "collected"}],
            "options": {"collect_cgroup": False},
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, {}, normalized)}
        self.assertFalse(
            {
                "cgroup.controllers_missing",
                "cgroup.driver_mismatch",
                "cgroup.service_failure",
                "security_agent.cgroup_denial",
            }
            & rule_ids
        )

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

    def test_cilium_replacement_rule_requires_pods_source(self):
        kubernetes = {
            "sources": {
                "cilium_config": {"status": "collected", "data": {"data": {"kube-proxy-replacement": "false"}}},
            }
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, kubernetes)}
        self.assertNotIn("cilium.kube_proxy_replacement_disabled", rule_ids)

    def test_empty_collected_cilium_service_map_is_evaluated(self):
        snapshot = node_snapshot("6.1")
        snapshot["commands"] = [{"id": "cilium_debug_services", "status": "collected", "stdout": '{"services":[]}'}]
        kubernetes = {
            "sources": {
                "services": {
                    "status": "collected",
                    "data": {"items": [{"metadata": {"namespace": "demo", "name": "api"}, "spec": {"type": "ClusterIP", "clusterIP": "10.0.0.1", "ports": [{"port": 443}]}}]},
                }
            }
        }
        findings = evaluate_rules({"nodes": []}, {"node-1": snapshot}, kubernetes)
        self.assertIn("cilium.service_frontend_missing", {item["rule_id"] for item in findings})

    def test_invalid_legacy_cilium_projection_does_not_report_every_service_missing(self):
        snapshot = node_snapshot("6.1")
        snapshot["commands"] = [
            {
                "id": "cilium_debug_services",
                "status": "collected",
                "stdout": '{"services":[{"id":1,"frontend":{}},{"id":2,"frontend":{}}]}',
            }
        ]
        kubernetes = {
            "sources": {
                "services": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {"namespace": "demo", "name": "api"},
                                "spec": {"type": "ClusterIP", "clusterIP": "10.0.0.1", "ports": [{"port": 443}]},
                            }
                        ]
                    },
                }
            }
        }
        findings = evaluate_rules({"nodes": []}, {"node-1": snapshot}, kubernetes)
        self.assertNotIn("cilium.service_frontend_missing", {item["rule_id"] for item in findings})

    def test_cilium_missing_frontend_summary_is_bounded(self):
        snapshot = node_snapshot("6.1")
        snapshot["commands"] = [{"id": "cilium_debug_services", "status": "collected", "stdout": '{"services":[]}'}]
        services = [
            {
                "metadata": {"namespace": "demo", "name": "service-{0:03d}".format(index)},
                "spec": {"type": "ClusterIP", "clusterIP": "10.0.0.{0}".format(index + 1), "ports": [{"port": 443}]},
            }
            for index in range(50)
        ]
        kubernetes = {"sources": {"services": {"status": "collected", "data": {"items": services}}}}
        findings = evaluate_rules({"nodes": []}, {"node-1": snapshot}, kubernetes)
        finding = next(item for item in findings if item["rule_id"] == "cilium.service_frontend_missing")
        self.assertIn("отсутствует 50", finding["summary"])
        self.assertIn("и ещё 45", finding["summary"])
        self.assertLess(len(finding["summary"]), 500)

    def test_statefulset_revision_drift_and_active_job_retry_are_not_failures(self):
        kubernetes = {
            "sources": {
                "workloads": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {"kind": "StatefulSet", "metadata": {"namespace": "demo", "name": "db"}, "spec": {"replicas": 3}, "status": {"currentRevision": "old", "updateRevision": "new", "updatedReplicas": 1, "readyReplicas": 2}},
                            {"kind": "Job", "metadata": {"namespace": "demo", "name": "retry"}, "status": {"failed": 2, "active": 1, "conditions": []}},
                        ]
                    },
                }
            }
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, kubernetes)}
        self.assertNotIn("kubernetes.statefulset_rollout_stalled", rule_ids)
        self.assertNotIn("kubernetes.job_failed", rule_ids)
        self.assertNotIn("kubernetes.workload_degraded", rule_ids)

    def test_deckhouse_dns_requires_nonempty_ready_container_statuses(self):
        kubernetes = {
            "sources": {
                "services": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "d8-kube-dns", "name": "kube-dns"}, "spec": {"clusterIP": "10.0.0.10", "selectorPresent": True, "ports": []}}]}},
                "endpoint_slices": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "d8-kube-dns", "labels": {"kubernetes.io/service-name": "kube-dns"}}, "endpoints": [{"conditions": {"ready": True}}], "ports": []}]}},
                "pods": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "d8-kube-dns", "name": "coredns-a", "labels": {"app.kubernetes.io/name": "coredns"}}, "status": {"phase": "Running", "containerStatuses": []}}]}},
            }
        }
        finding = next(item for item in evaluate_rules({"nodes": []}, {}, kubernetes) if item["rule_id"] == "dns.kube_dns_unavailable")
        self.assertIn("нет Ready CoreDNS Pod", finding["summary"])

    def test_deckhouse_dns_backend_and_external_alias_are_healthy(self):
        kubernetes = {
            "sources": {
                "services": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {"namespace": "d8-kube-dns", "name": "d8-kube-dns"},
                                "spec": {
                                    "type": "ClusterIP",
                                    "clusterIP": "10.0.0.10",
                                    "clusterIPs": ["10.0.0.10"],
                                    "selectorPresent": True,
                                    "ports": [{"name": "dns", "port": 53}],
                                },
                            },
                            {
                                "metadata": {"namespace": "d8-kube-dns", "name": "kube-dns"},
                                "spec": {
                                    "type": "ExternalName",
                                    "externalName": "d8-kube-dns.d8-kube-dns.svc.cluster.local",
                                    "selectorPresent": False,
                                    "ports": [],
                                },
                            },
                        ]
                    },
                },
                "endpoint_slices": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {
                                    "namespace": "d8-kube-dns",
                                    "labels": {"kubernetes.io/service-name": "d8-kube-dns"},
                                },
                                "endpoints": [{"conditions": {"ready": True}}],
                                "ports": [{"name": "dns", "port": 53}],
                            }
                        ]
                    },
                },
                "pods": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {
                                    "namespace": "d8-kube-dns",
                                    "name": "d8-kube-dns-a",
                                    "labels": {"app": "d8-kube-dns"},
                                },
                                "status": {
                                    "phase": "Running",
                                    "containerStatuses": [{"name": "coredns", "ready": True}],
                                },
                            },
                            {
                                "metadata": {
                                    "namespace": "d8-kube-dns",
                                    "name": "node-local-dns-a",
                                    "labels": {"app": "node-local-dns"},
                                },
                                "status": {
                                    "phase": "Running",
                                    "containerStatuses": [{"name": "coredns", "ready": True}],
                                },
                            },
                        ]
                    },
                },
            }
        }
        nodes = {
            "node-1": {
                "facts": {"kubelet_config": {"values": {"clusterDNS": ["10.0.0.10"]}}},
                "commands": [],
            }
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, nodes, kubernetes)}
        self.assertNotIn("dns.kube_dns_unavailable", rule_ids)
        self.assertNotIn("dns.cluster_dns_mismatch", rule_ids)

    def test_selector_present_survives_allowlist_projection(self):
        kubernetes = {
            "sources": {
                "services": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "demo", "name": "api"}, "spec": {"type": "ClusterIP", "selector": {}, "selectorPresent": True, "ports": []}}]}},
                "endpoint_slices": {"status": "collected", "data": {"items": []}},
            }
        }
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {}, kubernetes)}
        self.assertIn("kubernetes.service_no_endpoints", rule_ids)

    def test_old_rotated_kubelet_client_certificate_is_ignored(self):
        snapshot = node_snapshot("6.1")
        snapshot["facts"]["kubelet_certificate_rotation"] = {"status": "collected", "target": "kubelet-client-current-target.pem"}
        snapshot["facts"]["certificates"] = [
            {"path": "/var/lib/kubelet/pki/kubelet-client-old.pem", "metadata": "notAfter=Dec 31 00:00:00 2025 GMT\n"},
            {"path": "/var/lib/kubelet/pki/kubelet-client-current-target.pem", "metadata": "notAfter=Dec 31 00:00:00 2027 GMT\n"},
        ]
        collection = {"ended_at": "2026-01-01T00:00:00Z", "nodes": []}
        rule_ids = {item["rule_id"] for item in evaluate_rules(collection, {"node-1": snapshot}, {})}
        self.assertNotIn("certificate.expiring", rule_ids)

    def test_ipv6_single_interface_disable_without_ipv6_evidence_is_ignored(self):
        snapshot = node_snapshot("6.1")
        snapshot["facts"]["ipv6_disable"] = {"eth0": "1", "all": "0", "default": "0"}
        rule_ids = {item["rule_id"] for item in evaluate_rules({"nodes": []}, {"node-1": snapshot}, {})}
        self.assertNotIn("network.ipv6_disabled", rule_ids)

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
                "containerd.service": {
                    "status": "collected",
                    "properties": {"LoadState": "loaded", "ActiveState": "failed"},
                },
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
