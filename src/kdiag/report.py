import os
from pathlib import Path

from kdiag.normalize import normalize_evidence
from kdiag.rule_catalog import RULE_CATALOG, RULE_PACK_VERSION
from kdiag.rules import evaluate_rules
from kdiag.util import atomic_write_gzip_json, atomic_write_json, atomic_write_bytes, load_gzip_json, markdown_code, markdown_escape


def _safe_member(root, relative):
    if not isinstance(relative, str) or not relative or os.path.isabs(relative):
        raise ValueError("invalid collection member")
    root_path = Path(root).resolve()
    candidate = (root_path / relative).resolve()
    if os.path.commonpath((str(root_path), str(candidate))) != str(root_path):
        raise ValueError("collection member escapes root: {0}".format(relative))
    return candidate


def load_collection(collection_dir):
    root = Path(collection_dir)
    import json
    with (root / "collection.json").open("r", encoding="utf-8") as source:
        collection = json.load(source)
    nodes = {}
    for item in collection.get("nodes", []):
        if item.get("status") != "collected" or not item.get("file"):
            continue
        nodes[item["host"]] = load_gzip_json(_safe_member(root, item["file"]))
    kubernetes = {}
    kubernetes_item = collection.get("kubernetes", {})
    if kubernetes_item.get("status") in ("collected", "partial") and kubernetes_item.get("file"):
        kubernetes = load_gzip_json(_safe_member(root, kubernetes_item["file"]))
    prometheus = {}
    prometheus_item = collection.get("prometheus", {})
    if prometheus_item.get("file"):
        prometheus = load_gzip_json(_safe_member(root, prometheus_item["file"]))
    return collection, nodes, kubernetes, prometheus


def _node_row(name, snapshot):
    host = snapshot.get("host", {})
    os_release = host.get("os_release", {})
    cgroup = snapshot.get("facts", {}).get("cgroup", {})
    kubelet = snapshot.get("facts", {}).get("service_states", {}).get("kubelet.service", {}).get("properties", {})
    return {
        "inventory_host": name,
        "hostname": host.get("hostname"),
        "os": os_release.get("PRETTY_NAME") or os_release.get("NAME"),
        "kernel": host.get("kernel_release"),
        "cgroup_mode": "disabled" if cgroup.get("status") == "disabled" else cgroup.get("mode"),
        "kubelet_state": kubelet.get("ActiveState"),
        "boot_id": snapshot.get("facts", {}).get("boot_id_end"),
        "ipv6_disabled": sorted(key for key, value in snapshot.get("facts", {}).get("ipv6_disable", {}).items() if str(value) == "1"),
    }


def _coverage(collection, nodes, kubernetes):
    coverage = []
    required_commands = {"journal_services_current", "journal_kernel_current"}
    for item in collection.get("nodes", []):
        host = item.get("host")
        coverage.append(
            {
                "source": "node/{0}".format(host),
                "status": item.get("status"),
                "error": item.get("error") or item.get("cleanup_error"),
                "required": True,
            }
        )
        snapshot = nodes.get(host)
        if not snapshot:
            continue
        for command in snapshot.get("commands", []):
            status = "truncated" if command.get("truncated") else command.get("status") or "unknown"
            coverage.append(
                {
                    "source": "node/{0}/command/{1}".format(host, command.get("id") or "unknown"),
                    "status": status,
                    "error": command.get("error"),
                    "required": command.get("id") in required_commands,
                    "bytes": len(str(command.get("stdout") or "").encode("utf-8")),
                }
            )
        pod_logs = snapshot.get("pod_logs", {}) or {}
        coverage.append(
            {
                "source": "node/{0}/pod_logs".format(host),
                "status": pod_logs.get("status") or "missing",
                "error": pod_logs.get("error"),
                "required": True,
                "entry_count": len(pod_logs.get("entries", []) or []),
            }
        )
    coverage.append({"source": "kubernetes", "status": collection.get("kubernetes", {}).get("status"), "error": collection.get("kubernetes", {}).get("error"), "required": True})
    for source_id, source in sorted(kubernetes.get("sources", {}).items()):
        coverage.append(
            {
                "source": "kubernetes/{0}".format(source_id),
                "status": source.get("status"),
                "error": source.get("error"),
                "required": source.get("required", True),
            }
        )
    logs = kubernetes.get("logs")
    if logs:
        coverage.append(
            {
                "source": "kubernetes/logs",
                "status": logs.get("status"),
                "error": logs.get("error"),
                "required": True,
                "entry_count": len(logs.get("entries", []) or []),
            }
        )
        for index, entry in enumerate(logs.get("entries", []) or []):
            coverage.append(
                {
                    "source": "kubernetes/logs/{0}".format(index),
                    "status": "truncated" if entry.get("truncated") else entry.get("status") or "unknown",
                    "error": entry.get("error"),
                    "required": True,
                }
            )
    coverage.append({"source": "prometheus", "status": collection.get("prometheus", {}).get("status"), "error": collection.get("prometheus", {}).get("error"), "required": False})
    return coverage


RULE_COVERAGE_REQUIREMENTS = {}


def _register_rule_requirements(requirements, rule_ids):
    for rule_id in rule_ids:
        RULE_COVERAGE_REQUIREMENTS[rule_id] = requirements


_register_rule_requirements(
    ("node",),
    (
        "certificate.expiring",
        "certificate.kubelet_rotation_broken",
        "cgroup.controllers_missing",
        "dns.nameserver_limit_exceeded",
        "inventory.mixed_kernel",
        "node.kubelet_inactive",
        "node.low_root_disk",
        "node.runtime_inactive",
        "node.swap_active",
        "time.not_synchronized",
    ),
)
_register_rule_requirements(("node", "node/command/df_inodes"), ("node.low_inodes",))
_register_rule_requirements(("node", "node/command/df_blocks"), ("node.low_runtime_disk",))
_register_rule_requirements(
    ("node", "node/command/runtime_crictl_info"),
    ("cgroup.driver_mismatch", "runtime.cri_network_not_ready", "runtime.cri_not_ready"),
)
_register_rule_requirements(
    ("node", "node/command/journal_kernel_current"),
    (
        "node.conntrack_full",
        "node.filesystem_error",
        "node.filesystem_warning",
        "node.hardware_error",
        "node.io_error",
        "node.kernel_oops",
        "node.task_hung",
        "node.unregister_netdevice",
    ),
)
_register_rule_requirements(
    ("node", "node/command/journal_kernel_current", "node/pod_logs", "kubernetes/pods", "kubernetes/logs"),
    ("node.oom_detected",),
)
_register_rule_requirements(
    ("node", "node/command/installed_packages", "node/command/journal_services_current"),
    ("security_agent.cgroup_denial",),
)
_register_rule_requirements(
    ("node", "node/command/journal_kernel_current"),
    ("security_agent.ptrace_alert",),
)
_register_rule_requirements(
    ("node", "node/command/journal_services_current"),
    ("cgroup.service_failure",),
)
_register_rule_requirements(("node", "kubernetes/nodes"), ("inventory.node_set_mismatch",))
_register_rule_requirements(("kubernetes/pods",), ("inventory.mixed_apiserver_versions",))
_register_rule_requirements(
    ("kubernetes/nodes", "kubernetes/pods"),
    ("inventory.unsupported_version_skew",),
)
_register_rule_requirements(
    ("kubernetes/nodes",),
    ("kubernetes.network_unavailable", "kubernetes.node_not_ready", "kubernetes.node_pressure"),
)
_register_rule_requirements(
    ("kubernetes/pods",),
    (
        "kubernetes.container_exit_nonzero",
        "kubernetes.init_container_failed",
        "kubernetes.pod_evicted",
        "kubernetes.pod_oom_killed",
        "kubernetes.pod_restart_storm",
        "kubernetes.pod_waiting",
    ),
)
_register_rule_requirements(
    ("kubernetes/pods", "kubernetes/events"),
    ("kubernetes.image_pull_failure", "kubernetes.pod_crash_loop"),
)
_register_rule_requirements(("kubernetes/events",), ("kubernetes.failed_scheduling", "storage.volume_operation_failure"))
_register_rule_requirements(
    ("kubernetes/events", "kubernetes/logs"),
    ("kubernetes.probe_failures",),
)
_register_rule_requirements(
    ("kubernetes/workloads",),
    (
        "kubernetes.daemonset_misscheduled",
        "kubernetes.deployment_rollout_failed",
        "kubernetes.job_failed",
        "kubernetes.statefulset_rollout_stalled",
        "kubernetes.workload_degraded",
    ),
)
_register_rule_requirements(
    ("kubernetes/services", "kubernetes/endpoint_slices"),
    (
        "kubernetes.service_no_endpoints",
        "kubernetes.service_no_ready_endpoints",
        "kubernetes.service_port_unresolved",
    ),
)
_register_rule_requirements(
    ("kubernetes/services", "kubernetes/endpoint_slices", "kubernetes/pods"),
    ("dns.kube_dns_unavailable",),
)
_register_rule_requirements(("node", "kubernetes/services"), ("dns.cluster_dns_mismatch",))
_register_rule_requirements(("kubernetes/coredns_config",), ("dns.coredns_config_empty",))
_register_rule_requirements(("kubernetes/logs",), ("dns.coredns_errors",))
_register_rule_requirements(("kubernetes/pdb",), ("pdb.disruption_blocked", "pdb.insufficient_healthy"))
_register_rule_requirements(("kubernetes/api_readyz",), ("controlplane.api_readyz_failed",))
_register_rule_requirements(
    ("node", "node/command/journal_services_current", "node/pod_logs", "kubernetes/logs"),
    ("controlplane.authentication_config_read_error",),
)
_register_rule_requirements(("kubernetes/api_services",), ("controlplane.apiservice_unavailable",))
_register_rule_requirements(
    ("kubernetes/nodes", "kubernetes/leases"),
    ("controlplane.node_lease_stale",),
)
_register_rule_requirements(("kubernetes/pods",), ("controlplane.static_pod_unhealthy",))
_register_rule_requirements(("kubernetes/pvc",), ("storage.pvc_pending",))
_register_rule_requirements(("kubernetes/pv",), ("storage.pv_failed",))
_register_rule_requirements(
    ("kubernetes/pvc", "kubernetes/storage_classes"),
    ("storage.storage_class_missing",),
)
_register_rule_requirements(("kubernetes/volume_attachments",), ("storage.volume_attachment_failed",))
_register_rule_requirements(
    ("kubernetes/pv", "kubernetes/csi_drivers", "kubernetes/csi_nodes"),
    ("storage.csi_driver_registration_gap",),
)
_register_rule_requirements(("kubernetes/cilium_endpoints",), ("cilium.endpoint_unhealthy",))
_register_rule_requirements(("kubernetes/cilium_nodes",), ("cilium.node_ipam_error",))
_register_rule_requirements(
    ("kubernetes/cilium_network_policies", "kubernetes/cilium_clusterwide_network_policies"),
    ("cilium.policy_import_failed",),
)
_register_rule_requirements(
    ("kubernetes/cilium_config", "kubernetes/pods"),
    ("cilium.kube_proxy_replacement_disabled",),
)
_register_rule_requirements(("node", "kubernetes/services"), ("cilium.service_frontend_missing",))
_register_rule_requirements(
    ("node", "node/pod_logs", "kubernetes/pods", "kubernetes/logs"),
    ("cilium.unhealthy",),
)
_register_rule_requirements(
    ("node", "kubernetes/pods"),
    ("network.ipv6_disabled",),
)
_register_rule_requirements(
    ("node", "node/command/journal_services_current", "node/pod_logs", "kubernetes/events", "kubernetes/logs"),
    ("network.cni_unavailable",),
)
_register_rule_requirements(
    ("node", "node/command/journal_services_current", "kubernetes/nodes"),
    ("correlation.node_runtime_failure",),
)
_register_rule_requirements(
    ("node", "node/command/journal_services_current", "node/pod_logs", "kubernetes/nodes", "kubernetes/events", "kubernetes/logs"),
    ("correlation.node_cni_failure",),
)
_register_rule_requirements(
    ("node", "node/command/journal_kernel_current", "node/pod_logs", "kubernetes/nodes", "kubernetes/pods", "kubernetes/logs"),
    ("correlation.memory_oom_failure",),
)
_register_rule_requirements(
    ("node", "node/command/journal_services_current", "kubernetes/events", "kubernetes/logs"),
    ("correlation.certificate_api_failure",),
)
_register_rule_requirements(
    ("node", "node/command/journal_kernel_current", "kubernetes/events", "kubernetes/logs"),
    ("correlation.conntrack_network_failure",),
)
_register_rule_requirements(
    ("kubernetes/events", "kubernetes/logs"),
    ("correlation.probe_network_failure",),
)
_register_rule_requirements(
    ("node", "node/command/journal_kernel_current", "node/pod_logs", "kubernetes/nodes", "kubernetes/events", "kubernetes/logs"),
    ("correlation.storage_failure",),
)
_register_rule_requirements(("node",), tuple(rule_id for rule_id in RULE_CATALOG if rule_id.startswith("etcd.")))
_register_rule_requirements(("prometheus",), tuple(rule_id for rule_id in RULE_CATALOG if rule_id.startswith("prometheus.")))


def _requirement_gaps(coverage, requirement):
    if requirement == "node":
        matches = [item for item in coverage if item.get("source", "").startswith("node/") and item["source"].count("/") == 1]
    elif requirement == "node/pod_logs":
        matches = [item for item in coverage if item.get("source", "").startswith("node/") and item["source"].endswith("/pod_logs")]
    elif requirement.startswith("node/command/"):
        command_id = requirement.rsplit("/", 1)[-1]
        matches = [item for item in coverage if item.get("source", "").startswith("node/") and item["source"].endswith("/command/{0}".format(command_id))]
    else:
        matches = [item for item in coverage if item.get("source") == requirement]
    if not matches:
        return ["{0}:missing".format(requirement)]
    return [item["source"] for item in matches if item.get("status") != "collected"]


def _rule_ledger(findings, coverage, options):
    if isinstance(options, bool):
        options = {"collect_cgroup": options}
    options = options or {}
    collect_cgroup = options.get("collect_cgroup", True)
    collect_etcd = options.get("collect_etcd", False)
    matched = {item.get("rule_id") for item in findings}
    prometheus_status = next((item.get("status") for item in coverage if item.get("source") == "prometheus"), None)
    ledger = []
    for rule_id in sorted(RULE_CATALOG):
        missing = []
        if rule_id in matched:
            status = "matched"
        elif rule_id.startswith("cgroup.") or rule_id == "security_agent.cgroup_denial":
            if not collect_cgroup:
                status = "not_applicable"
            else:
                for requirement in RULE_COVERAGE_REQUIREMENTS.get(rule_id, ()):
                    missing.extend(_requirement_gaps(coverage, requirement))
                status = "unknown" if missing else "not_matched"
        elif rule_id.startswith("etcd.") and not collect_etcd:
            status = "not_applicable"
        elif rule_id.startswith("prometheus."):
            if prometheus_status in (None, "not_configured", "disabled"):
                status = "not_applicable"
            else:
                missing = _requirement_gaps(coverage, "prometheus")
                status = "unknown" if missing else "not_matched"
        elif rule_id.startswith("collector."):
            status = "not_matched"
        else:
            for requirement in RULE_COVERAGE_REQUIREMENTS.get(rule_id, ()):
                missing.extend(_requirement_gaps(coverage, requirement))
            missing = sorted(set(missing))
            status = "unknown" if missing else "not_matched"
        ledger.append(
            {
                "rule_id": rule_id,
                "status": status,
                "missing_evidence": missing[:50],
                "missing_evidence_total": len(missing),
            }
        )
    return ledger


def _select_unknown_fingerprints(values, limit=20, per_component=5):
    grouped = {}
    for item in values:
        grouped.setdefault(str(item.get("component") or "unknown"), []).append(item)
    ranked = []
    for component, items in grouped.items():
        ordered = sorted(items, key=lambda item: (-int(item.get("count") or 0), str(item.get("fingerprint") or "")))
        for rank, item in enumerate(ordered[:per_component]):
            ranked.append((rank, -int(item.get("count") or 0), component, item))
    selected = [item for _rank, _count, _component, item in sorted(ranked)[:limit]]
    return selected, max(0, len(values) - len(selected))


def _bounded_report_text(value, limit=220):
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def build_report(collection_dir):
    collection, nodes, kubernetes, prometheus = load_collection(collection_dir)
    normalized = normalize_evidence(collection, nodes, kubernetes)
    findings = evaluate_rules(collection, nodes, kubernetes, normalized, prometheus)
    node_inventory = [_node_row(name, snapshot) for name, snapshot in sorted(nodes.items())]
    coverage = _coverage(collection, nodes, kubernetes)
    ledger = _rule_ledger(findings, coverage, collection.get("options", {}))
    facts = {
        "schema_version": 1,
        "collection_id": collection.get("collection_id"),
        "nodes": node_inventory,
        "options": {
            "collect_cgroup": collection.get("options", {}).get("collect_cgroup", True),
            "collect_etcd": collection.get("options", {}).get("collect_etcd", False),
        },
        "kubernetes": {
            "status": collection.get("kubernetes", {}).get("status"),
            "sources": {
                source_id: {
                    "status": source.get("status"),
                    "required": source.get("required", True),
                    "item_count": len(source.get("data", {}).get("items", []))
                    if isinstance(source.get("data", {}).get("items", []), list)
                    else None,
                }
                for source_id, source in sorted(kubernetes.get("sources", {}).items())
            },
            "logs": {
                "status": kubernetes.get("logs", {}).get("status"),
                "entry_count": len(kubernetes.get("logs", {}).get("entries", [])),
                "bytes": kubernetes.get("logs", {}).get("bytes"),
            },
        },
        "normalization": {
            "stats": normalized.get("stats", {}),
            "correlation_count": len(normalized.get("correlations", [])),
            "unknown_fingerprint_count": len(normalized.get("unknown_fingerprints", [])),
        },
        "coverage": coverage,
        "rule_evaluation_ledger": ledger,
    }
    findings_document = {
        "schema_version": 1,
        "rule_pack_version": RULE_PACK_VERSION,
        "collection_id": collection.get("collection_id"),
        "items": findings,
        "evaluation_ledger": ledger,
    }
    report = {
        "schema_version": 1,
        "rule_pack_version": RULE_PACK_VERSION,
        "collection_id": collection.get("collection_id"),
        "status": collection.get("status"),
        "started_at": collection.get("started_at"),
        "ended_at": collection.get("ended_at"),
        "coverage": coverage,
        "node_inventory": node_inventory,
        "findings": findings,
        "rule_evaluation_ledger": ledger,
        "prometheus_status": prometheus.get("status") if prometheus else collection.get("prometheus", {}).get("status"),
        "normalization": facts["normalization"],
        "options": facts["options"],
    }
    root = Path(collection_dir)
    atomic_write_gzip_json(root / "normalized-events.json.gz", normalized)
    atomic_write_json(root / "facts.json", facts)
    atomic_write_json(root / "findings.json", findings_document)
    atomic_write_json(root / "report.json", report)
    lines = [
        "# Аварийный снимок Kubernetes",
        "",
        "Collection ID: `{0}`".format(markdown_escape(report["collection_id"])),
        "",
        "Статус: **{0}**".format(markdown_escape(report["status"])),
        "",
        "Cgroup checks: **{0}**".format("enabled" if report["options"]["collect_cgroup"] else "disabled"),
        "",
        "Etcd checks: **{0}**".format("enabled" if report["options"]["collect_etcd"] else "disabled"),
        "",
        "## Полнота сбора",
        "",
        "| Источник | Статус | Обязательный | Ошибка |",
        "|---|---|---|---|",
    ]
    for item in coverage:
        lines.append("| {0} | {1} | {2} | {3} |".format(markdown_escape(item.get("source")), markdown_escape(item.get("status")), "yes" if item.get("required", True) else "no", markdown_escape(item.get("error") or "")))
    ledger_counts = {}
    for item in ledger:
        ledger_counts[item["status"]] = ledger_counts.get(item["status"], 0) + 1
    lines.extend(
        [
            "",
            "## Реестр выполнения правил",
            "",
            "matched={0}; not_matched={1}; unknown={2}; not_applicable={3}.".format(
                ledger_counts.get("matched", 0),
                ledger_counts.get("not_matched", 0),
                ledger_counts.get("unknown", 0),
                ledger_counts.get("not_applicable", 0),
            ),
            "",
        ]
    )
    unknown_rules = [item for item in ledger if item["status"] == "unknown"]
    if unknown_rules:
        lines.append("Отсутствие finding по правилам со статусом `unknown` не означает отсутствие проблемы.")
        lines.append("")
        lines.extend(["| Rule ID | Статус | Отсутствующие evidence |", "|---|---|---|"])
        for item in unknown_rules[:100]:
            missing = item.get("missing_evidence", [])
            omitted = item.get("missing_evidence_total", len(missing)) - len(missing)
            text = ", ".join(missing) + ("; omitted={0}".format(omitted) if omitted else "")
            lines.append("| `{0}` | unknown | {1} |".format(markdown_escape(item["rule_id"]), markdown_escape(text)))
        lines.append("")
    lines.extend(["", "## Инвентаризация узлов", "", "| Inventory host | Hostname | ОС | Ядро | Cgroup | kubelet | IPv6 disabled |", "|---|---|---|---|---|---|---|"])
    for item in node_inventory:
        lines.append(
            "| {0} | {1} | {2} | {3} | {4} | {5} | {6} |".format(
                markdown_escape(item.get("inventory_host")),
                markdown_escape(item.get("hostname") or ""),
                markdown_escape(item.get("os") or ""),
                markdown_escape(item.get("kernel") or ""),
                markdown_escape(item.get("cgroup_mode") or ""),
                markdown_escape(item.get("kubelet_state") or ""),
                markdown_escape(", ".join(item.get("ipv6_disabled") or [])),
            )
        )
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("Зарегистрированных deterministic findings нет. Это не доказывает отсутствие проблемы.")
    for finding in findings:
        lines.extend(
            [
                "### [{0}] {1}".format(markdown_escape(finding["severity"]), markdown_escape(finding["title"])),
                "",
                "Rule ID: `{0}`.".format(markdown_escape(finding["rule_id"])),
                "",
                markdown_escape(finding["summary"]),
                "",
                "Тип вывода: `{0}`; detection confidence: `{1}`; causal confidence: `{2}`.".format(
                    markdown_escape(finding.get("classification")),
                    markdown_escape(finding.get("detection_confidence")),
                    markdown_escape(finding.get("causal_confidence")),
                ),
                "",
                "Rule pack: `{0}`; version scope: {1}.".format(
                    markdown_escape(finding.get("rule_pack_version")), markdown_escape(finding.get("version_scope"))
                ),
                "",
                "Время/окно: {0} — {1}; duration={2}s; correlation window={3}s.".format(
                    markdown_escape(finding.get("started_at") or report.get("started_at") or "unknown"),
                    markdown_escape(finding.get("ended_at") or report.get("ended_at") or "unknown"),
                    markdown_escape(finding.get("duration_seconds") if finding.get("duration_seconds") is not None else "unknown"),
                    markdown_escape(finding.get("window_seconds") if finding.get("window_seconds") is not None else "n/a"),
                ),
                "",
                "Затронуто: {0}; total={1}; omitted={2}.".format(
                    markdown_escape(", ".join(finding["affected"][:50]) or "cluster"),
                    finding.get("affected_total", len(finding["affected"])),
                    max(0, finding.get("affected_total", len(finding["affected"])) - min(50, len(finding["affected"]))),
                ),
                "",
                "Источники правил: {0}.".format(", ".join("`{0}`".format(markdown_escape(value)) for value in finding.get("source_refs", []))),
                "",
                "Evidence: {0}; total={1}; omitted={2}.".format(
                    ", ".join("`{0}`".format(markdown_escape(value)) for value in finding["evidence"]),
                    finding.get("evidence_total", len(finding["evidence"])),
                    max(0, finding.get("evidence_total", len(finding["evidence"])) - len(finding["evidence"])),
                ),
                "",
                "Альтернативы: {0}.".format(markdown_escape("; ".join(finding.get("alternatives", [])) or "нет явно перечисленных")),
                "",
                "Counter-evidence: {0}.".format(markdown_escape("; ".join(finding.get("counter_evidence", [])) or "не обнаружено в собранном evidence")),
                "",
                "Missing checks: {0}.".format(markdown_escape("; ".join(finding.get("missing_checks", [])) or "нет явно указанных")),
                "",
                "Рекомендация: {0}".format(markdown_escape(finding["recommendation"])),
                "",
            ]
        )
        fragments = finding.get("evidence_fragments", [])
        if fragments:
            lines.extend(["Bounded evidence excerpts:", ""])
            for fragment in fragments[:20]:
                lines.append(
                    "- `{0}` [{1}] {2}: {3}".format(
                        markdown_escape(fragment.get("reference")),
                        markdown_escape(fragment.get("status")),
                        markdown_escape(fragment.get("timestamp") or "unknown"),
                        markdown_escape(fragment.get("excerpt") or ""),
                    )
                )
            lines.append("")
    stats = normalized.get("stats", {})
    lines.extend(
        [
            "## Нормализация и корреляция",
            "",
            "Обработано записей: {0}; категоризировано: {1}; неизвестно: {2}; malformed: {3}; correlations: {4}; truncated: {5}; unknown replacements: {6}.".format(
                stats.get("input_records", 0),
                stats.get("categorized_records", 0),
                stats.get("uncategorized_records", 0),
                stats.get("malformed_records", 0),
                len(normalized.get("correlations", [])),
                stats.get("truncated", False),
                stats.get("unknown_fingerprint_replacements", 0),
            ),
            "",
        ]
    )
    unknown, unknown_omitted = _select_unknown_fingerprints(normalized.get("unknown_fingerprints", []))
    if unknown:
        lines.extend(
            [
                "### Приблизительные heavy hitters неизвестных fingerprints",
                "",
                "Это не findings, а частые ещё не классифицированные шаблоны для локального triage. Список сбалансирован по компонентам; полный набор остаётся в `normalized-events.json.gz`.",
                "",
            ]
        )
        for item in unknown:
            lines.extend(
                [
                    "- {0} — estimated count: {1}; max error: {2}.".format(
                        markdown_code(item.get("component") or "unknown"),
                        markdown_escape(item.get("count")),
                        markdown_escape(item.get("estimate_error", 0)),
                    ),
                    "  Template: {0}".format(markdown_code(_bounded_report_text(item.get("template")))),
                ]
            )
        if unknown_omitted:
            lines.append("- В Markdown опущено шаблонов: {0}.".format(unknown_omitted))
        lines.append("")
    correlations = normalized.get("correlations", [])
    if correlations:
        lines.extend(["## Correlation timeline", "", "| Episode | Type | Scope | Started | Ended | Duration, s |", "|---|---|---|---|---|---:|"])
        for item in correlations[:100]:
            lines.append(
                "| `{0}` | `{1}` | {2} | {3} | {4} | {5} |".format(
                    markdown_escape(item.get("episode_id") or "unknown"),
                    markdown_escape(item.get("correlation_id")),
                    markdown_escape(item.get("scope")),
                    markdown_escape(item.get("started_at") or "unknown"),
                    markdown_escape(item.get("ended_at") or "unknown"),
                    markdown_escape(item.get("duration_seconds") if item.get("duration_seconds") is not None else "unknown"),
                )
            )
        if len(correlations) > 100:
            lines.extend(["", "Timeline total={0}; omitted={1}.".format(len(correlations), len(correlations) - 100)])
        lines.append("")
    atomic_write_bytes(root / "report.md", ("\n".join(lines).rstrip() + "\n").encode("utf-8"))
    return report
