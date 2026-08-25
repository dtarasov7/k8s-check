from kdiag.normalize import classify_message, normalize_evidence
from kdiag.npd_rules import NPD_UPSTREAM_LICENSE, NPD_UPSTREAM_SOURCE, NPD_UPSTREAM_VERSION
from kdiag.rule_catalog import RULE_CATALOG, RULE_PACK_VERSION
from kdiag.rules import evaluate_rules


def run_self_test():
    checks = []

    def check(name, condition, detail):
        checks.append({"name": name, "status": "passed" if condition else "failed", "detail": detail})

    check(
        "message-classification",
        "cgroup_access_denied" in classify_message("write /sys/fs/cgroup/x/io.max: operation not permitted"),
        "cgroup errno/path classification",
    )
    check(
        "rule-catalog",
        bool(RULE_CATALOG) and all(item.get("sources") and item.get("classification") for item in RULE_CATALOG.values()),
        "all catalog entries have sources and classification",
    )
    check(
        "npd-provenance",
        NPD_UPSTREAM_VERSION == "v0.8.25" and NPD_UPSTREAM_LICENSE == "Apache-2.0" and NPD_UPSTREAM_SOURCE.startswith("https://"),
        "pinned Node Problem Detector adaptation has source/version/license",
    )

    collection = {
        "collection_id": "self-test",
        "ended_at": "2026-01-01T00:10:00Z",
        "nodes": [{"host": "node-1", "status": "collected"}],
    }
    node = {
        "host": {"kernel_release": "6.1"},
        "ended_at": "2026-01-01T00:10:00Z",
        "commands": [
            {
                "id": "journal_services_current",
                "status": "collected",
                "stdout": (
                    '{"__REALTIME_TIMESTAMP":"1767225600000000","_SYSTEMD_UNIT":"kubelet.service","MESSAGE":"write /sys/fs/cgroup/x/io.max: operation not permitted"}\n'
                    '{"__REALTIME_TIMESTAMP":"1767225660000000","_SYSTEMD_UNIT":"kubelet.service","MESSAGE":"container runtime is down"}\n'
                ),
            },
            {
                "id": "journal_kernel_current",
                "status": "collected",
                "stdout": '{"__REALTIME_TIMESTAMP":"1767225601000000","MESSAGE":"Buffer I/O error on dev sda, logical block 42"}\n',
            },
        ],
        "pod_logs": {"status": "collected", "entries": []},
        "facts": {
            "boot_changed_during_collection": False,
            "root_disk": {"total_bytes": 100, "free_bytes": 50},
            "ipv6_disable": {},
            "cgroup": {"mode": "v2", "controllers": ["cpu", "io", "memory", "pids"]},
            "certificates": [],
            "service_states": {
                "kubelet.service": {"status": "collected", "properties": {"LoadState": "loaded", "ActiveState": "failed"}}
            },
        },
    }
    kubernetes = {
        "collected_at": "2026-01-01T00:10:00Z",
        "sources": {
            "nodes": {
                "status": "collected",
                "data": {
                    "items": [
                        {
                            "metadata": {"name": "node-1"},
                            "status": {
                                "conditions": [
                                    {
                                        "type": "Ready",
                                        "status": "False",
                                        "reason": "KubeletNotReady",
                                        "message": "kubelet stopped",
                                        "lastTransitionTime": "2026-01-01T00:02:00Z",
                                    }
                                ]
                            },
                        }
                    ]
                },
            },
            "pods": {"status": "collected", "data": {"items": []}},
            "events": {"status": "collected", "data": {"items": []}},
            "services": {
                "status": "collected",
                "data": {"items": [{"metadata": {"namespace": "demo", "name": "no-endpoints"}, "spec": {"type": "ClusterIP", "selector": {"app": "demo"}, "ports": [{"port": 80}]}}]},
            },
            "endpoint_slices": {"status": "collected", "data": {"items": []}},
            "api_readyz": {"status": "collected", "data": {"checks": [{"name": "etcd", "status": "failed", "message": "synthetic"}]}},
            "pvc": {"status": "collected", "data": {"items": [{"metadata": {"namespace": "demo", "name": "data"}, "spec": {}, "status": {"phase": "Pending"}}]}},
        },
        "logs": {"status": "collected", "entries": []},
    }
    normalized = normalize_evidence(collection, {"node-1": node}, kubernetes)
    correlation_ids = {item["correlation_id"] for item in normalized["correlations"]}
    check(
        "event-correlation",
        "node_runtime_failure" in correlation_ids and "cgroup_service_failure" in correlation_ids,
        "Node Ready, kubelet and cgroup events correlate inside the window",
    )
    findings = evaluate_rules(collection, {"node-1": node}, kubernetes, normalized)
    rule_ids = {item["rule_id"] for item in findings}
    check(
        "rule-evaluation",
        {"node.kubelet_inactive", "kubernetes.node_not_ready", "cgroup.service_failure"}.issubset(rule_ids),
        "synthetic incident produces expected findings",
    )
    check(
        "extended-rule-evaluation",
        {"node.io_error", "kubernetes.service_no_endpoints", "controlplane.api_readyz_failed", "storage.pvc_pending"}.issubset(rule_ids),
        "NPD and structured Kubernetes evidence produce expected findings",
    )
    return {
        "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "rule_pack_version": RULE_PACK_VERSION,
        "checks": checks,
    }
