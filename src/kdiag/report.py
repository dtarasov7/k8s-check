import os
import re
from pathlib import Path

from kdiag.causal import annotate_findings, build_causal_analysis
from kdiag.message_insights import enrich_message_insights
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
    # Even an unreachable snapshot contains the per-source kubectl failures
    # needed to explain coverage. The collector writes that bundle before it
    # derives the aggregate status.
    if kubernetes_item.get("file"):
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


def _coverage(collection, nodes, kubernetes, prometheus=None):
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
    kubernetes_status = collection.get("kubernetes", {}).get("status")
    coverage.append(
        {
            "source": "kubernetes",
            "status": kubernetes_status,
            "error": collection.get("kubernetes", {}).get("error"),
            "required": kubernetes_status != "disabled",
        }
    )
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
    for source_id, source in sorted(((prometheus or {}).get("sources", {}) or {}).items()):
        coverage.append(
            {
                "source": "prometheus/{0}".format(source_id),
                "status": source.get("status"),
                "error": source.get("error"),
                "required": source.get("required", False),
            }
        )
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
        if requirement.startswith("kubernetes/"):
            parent = next((item for item in coverage if item.get("source") == "kubernetes"), None)
            if parent and parent.get("status") not in (None, "collected", "partial"):
                return ["kubernetes:{0}".format(parent.get("status"))]
        return ["{0}:missing".format(requirement)]
    return [
        "{0}:{1}".format(item["source"], item.get("status") or "missing")
        for item in matches
        if item.get("status") != "collected"
    ]


def _rule_ledger(findings, coverage, options):
    if isinstance(options, bool):
        options = {"collect_cgroup": options}
    options = options or {}
    collect_cgroup = options.get("collect_cgroup", True)
    collect_etcd = options.get("collect_etcd", False)
    matched = {item.get("rule_id") for item in findings}
    prometheus_status = next((item.get("status") for item in coverage if item.get("source") == "prometheus"), None)
    kubernetes_status = next((item.get("status") for item in coverage if item.get("source") == "kubernetes"), None)
    ledger = []
    for rule_id in sorted(RULE_CATALOG):
        missing = []
        status = None
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
            requirements = RULE_COVERAGE_REQUIREMENTS.get(rule_id, ())
            if kubernetes_status == "disabled" and any(value.startswith("kubernetes/") for value in requirements):
                status = "not_applicable"
                requirements = ()
            for requirement in requirements:
                missing.extend(_requirement_gaps(coverage, requirement))
            missing = sorted(set(missing))
            if status is None:
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


STATUS_LABELS = {
    "collected": "собрано",
    "partial": "собрано частично",
    "failed": "ошибка",
    "error": "ошибка",
    "timeout": "превышено время ожидания",
    "truncated": "усечено лимитом",
    "unsupported": "недоступно на узле",
    "unreachable": "источник недоступен",
    "source_unavailable": "источник недоступен",
    "permission_denied": "нет прав",
    "missing": "не собрано",
    "disabled": "отключено",
    "not_configured": "не настроено",
    "complete": "сбор завершён",
    "query_error": "ошибка запроса",
    "malformed": "некорректный ответ",
    "invalid_auth": "ошибка настройки доступа",
    "invalid_url": "некорректный адрес",
    "invalid_range": "некорректное окно",
    "unavailable": "недоступно",
    "matched": "проблема обнаружена",
    "not_matched": "проблема не обнаружена",
    "unknown": "не удалось проверить",
    "not_applicable": "не применяется",
    "problem": "обнаружена проблема",
    "healthy": "признаков проблемы нет",
    "observe": "нужно наблюдение",
}

SEVERITY_LABELS = {
    "critical": "КРИТИЧНО",
    "warning": "ПРЕДУПРЕЖДЕНИЕ",
    "info": "СВЕДЕНИЕ",
}

CLASSIFICATION_LABELS = {
    "fact": "зафиксированный факт",
    "correlation": "совпадение признаков по времени и объекту",
    "hypothesis": "предположение, требующее проверки",
}

FINDING_STATUS_LABELS = {
    "active": "активно",
    "resolved": "завершилось",
    "unknown": "неизвестно",
}

FINDING_ROLE_LABELS = {
    "possible_cause": "возможная причина",
    "consequence": "следствие",
    "configuration_risk": "конфигурационный риск",
}

METRIC_TREND_LABELS = {
    "rising": "растёт",
    "falling": "снижается",
    "stable": "без заметного изменения",
}

INSIGHT_CATEGORY_LABELS = {
    "actionable": "ТРЕБУЕТ ВНИМАНИЯ",
    "security": "БЕЗОПАСНОСТЬ",
    "routine": "СОПУТСТВУЮЩЕЕ СООБЩЕНИЕ",
    "observe": "СОПУТСТВУЮЩЕЕ СООБЩЕНИЕ",
}

REPORT_INSIGHT_CATEGORIES = frozenset(("actionable", "security"))

DECISION_STATE_LABELS = {
    "investigate": "проверить сейчас",
    "security_review": "передать на проверку безопасности",
    "monitor": "наблюдать",
}

SOURCE_LABELS = {
    "journal_services_current": "служебный журнал текущей загрузки",
    "journal_services_previous": "служебный журнал предыдущей загрузки",
    "journal_kernel_current": "журнал ядра текущей загрузки",
    "journal_kernel_previous": "журнал ядра предыдущей загрузки",
    "pod_logs": "локальные журналы контейнеров",
    "nodes": "объекты Node",
    "pods": "объекты Pod",
    "events": "события Kubernetes",
    "workloads": "состояние рабочих нагрузок",
    "services": "объекты Service",
    "endpoint_slices": "объекты EndpointSlice",
    "api_readyz": "готовность API server",
    "logs": "журналы системных Pod",
}

PROMETHEUS_SOURCE_LABELS = {
    "alerts": "активные оповещения",
    "runtimeinfo": "состояние процесса",
    "range_api_server_5xx": "ошибки Kubernetes API 5xx",
    "range_api_server_p99_latency": "P99 задержки Kubernetes API",
    "range_etcd_wal_fsync_p99": "P99 fsync WAL etcd",
    "range_pod_restarts_total": "перезапуски контейнеров",
    "range_container_network_errors": "ошибки контейнерной сети",
    "range_node_cpu_iowait_steal": "CPU iowait и steal",
}

FINDING_BACKED_INSIGHTS = frozenset(("authentication_config_read_error", "ptrace_attack_attempt"))


def _status_label(value):
    return STATUS_LABELS.get(str(value or "missing"), str(value or "неизвестно"))


def _confidence_label(value):
    return {
        "high": "высокая",
        "medium": "средняя",
        "low": "низкая",
        "none": "причина не установлена",
    }.get(str(value or "none"), str(value or "не указана"))


def _source_label(value):
    text = str(value or "неизвестный источник")
    match = re.match(r"^node/([^/]+)/command/([^/]+)$", text)
    if match:
        return "Узел {0}: {1}".format(match.group(1), SOURCE_LABELS.get(match.group(2), "команда {0}".format(match.group(2))))
    match = re.match(r"^node/([^/]+)/pod_logs$", text)
    if match:
        return "Узел {0}: {1}".format(match.group(1), SOURCE_LABELS["pod_logs"])
    match = re.match(r"^node/([^/]+)$", text)
    if match:
        return "Узел {0}".format(match.group(1))
    match = re.match(r"^kubernetes/(.+)$", text)
    if match:
        return "Kubernetes: {0}".format(SOURCE_LABELS.get(match.group(1), match.group(1)))
    if text == "kubernetes":
        return "Kubernetes API"
    if text == "prometheus":
        return "Prometheus"
    match = re.match(r"^prometheus/(.+)$", text)
    if match:
        return "Prometheus: {0}".format(PROMETHEUS_SOURCE_LABELS.get(match.group(1), match.group(1)))
    return text


def _coverage_display_rows(values):
    grouped = {}
    rows = []
    for item in values or []:
        if item.get("status") == "collected":
            continue
        source = str(item.get("source") or "")
        node_match = re.match(r"^node/([^/]+)/(command/[^/]+|pod_logs)$", source)
        log_match = re.match(r"^kubernetes/logs/\d+$", source)
        if node_match:
            key = (node_match.group(2), item.get("status"), item.get("error"), item.get("required", True))
            grouped.setdefault(key, []).append(node_match.group(1))
        elif log_match:
            key = ("kubernetes_log_entry", item.get("status"), item.get("error"), item.get("required", True))
            grouped.setdefault(key, []).append(source.rsplit("/", 1)[-1])
        else:
            rows.append(dict(item, display_source=_source_label(source)))
    for source_id, status, error, required in sorted(grouped, key=lambda key: tuple(str(value) for value in key)):
        members = grouped[(source_id, status, error, required)]
        if source_id.startswith("command/"):
            label = SOURCE_LABELS.get(source_id.split("/", 1)[1], "команда {0}".format(source_id.split("/", 1)[1]))
            display_source = "{0}: {1} узл. ({2})".format(label, len(members), ", ".join(sorted(members)[:10]))
        elif source_id == "pod_logs":
            display_source = "{0}: {1} узл. ({2})".format(SOURCE_LABELS["pod_logs"], len(members), ", ".join(sorted(members)[:10]))
        else:
            display_source = "Записи журналов Kubernetes: {0}".format(len(members))
        if len(members) > 10:
            display_source += "; ещё {0}".format(len(members) - 10)
        rows.append(
            {
                "source": source_id,
                "display_source": display_source,
                "status": status,
                "error": error,
                "required": required,
            }
        )
    return sorted(rows, key=lambda item: (str(item.get("status")), str(item.get("display_source"))))


def _human_gap(value):
    text = str(value)
    match = re.match(r"^node/\*/command/([^:]+):([^ ]+) \((\d+) nodes?\)$", text)
    if match:
        return "{0}: {1} на {2} узл.".format(
            SOURCE_LABELS.get(match.group(1), "команда {0}".format(match.group(1))),
            _status_label(match.group(2)),
            match.group(3),
        )
    match = re.match(r"^node/\*/pod_logs:([^ ]+) \((\d+) nodes?\)$", text)
    if match:
        return "{0}: {1} на {2} узл.".format(SOURCE_LABELS["pod_logs"], _status_label(match.group(1)), match.group(2))
    if ":" in text:
        source, status = text.rsplit(":", 1)
        return "{0}: {1}".format(_source_label(source), _status_label(status))
    return _source_label(text)


def _report_message_insights(values):
    return [
        value for value in (values or [])
        if (
            value.get("category") in REPORT_INSIGHT_CATEGORIES
            or value.get("decision_state") == "investigate"
        )
        and value.get("insight_id") not in FINDING_BACKED_INSIGHTS
    ]


def _render_message_insights(lines, values, limit=30):
    insights = _report_message_insights(values)
    if not insights:
        return
    lines.extend(
        [
            "## Сообщения, требующие внимания",
            "",
            "Здесь показаны только сообщения, для которых может требоваться действие. Штатные информационные сообщения скрыты; полный машинный список остаётся в `normalized-events.json.gz`.",
            "",
        ]
    )
    for insight in insights[:limit]:
        occurrence = insight.get("occurrence_range") or {}
        minimum = int(occurrence.get("minimum") or 0)
        maximum = int(occurrence.get("maximum") or 0)
        if insight.get("count_is_exact") or minimum == maximum:
            occurrence_text = "точно {0}".format(maximum)
        else:
            occurrence_text = (
                "гарантированно не менее {0}, оценочная верхняя граница {1}; "
                "алгоритмическая погрешность оценки не более {2}"
            ).format(minimum, maximum, int(insight.get("estimate_error") or 0))
        rate = insight.get("rate_per_hour_range")
        if rate and rate.get("minimum") is not None and rate.get("maximum") is not None:
            if rate.get("minimum") == rate.get("maximum"):
                rate_text = "{0}/ч".format(rate["maximum"])
            else:
                rate_text = "{0}..{1}/ч".format(rate["minimum"], rate["maximum"])
        else:
            rate_text = "недостаточно точных отметок времени"
        nodes = insight.get("affected_nodes") or []
        pods = insight.get("affected_pods") or []
        scope_suffix = "; список ограничен" if insight.get("scope_truncated") else ""
        lines.extend(
            [
                "### [{0}] {1}".format(
                    INSIGHT_CATEGORY_LABELS.get(insight.get("category"), "НАБЛЮДЕНИЕ"),
                    markdown_escape(insight.get("title") or insight.get("insight_id") or "message"),
                ),
                "",
                "Решение: **{0}**. Компонент: {1}.".format(
                    markdown_escape(DECISION_STATE_LABELS.get(insight.get("decision_state"), "наблюдать")),
                    markdown_code(insight.get("component") or "неизвестно"),
                ),
                "",
                "Шаблон: {0}".format(markdown_code(_bounded_report_text(insight.get("template")))),
                "",
                "Частота: {0}; первая запись: {1}; последняя запись: {2}; наблюдаемое окно: {3} с; средняя частота: {4}; записей без точного времени: {5}.".format(
                    occurrence_text,
                    markdown_escape(insight.get("first_seen") or "неизвестно"),
                    markdown_escape(insight.get("last_seen") or "неизвестно"),
                    markdown_escape(
                        insight.get("observed_span_seconds")
                        if insight.get("observed_span_seconds") is not None
                        else "неизвестно"
                    ),
                    markdown_escape(rate_text),
                    markdown_escape(insight.get("inferred_time_samples", 0)),
                ),
                "",
                "Затронутые узлы: {0} ({1}); Pod: {2} ({3}){4}.".format(
                    markdown_escape(", ".join(nodes) or "не определены"),
                    insight.get("affected_nodes_count", len(nodes)),
                    markdown_escape(", ".join(pods) or "не определены"),
                    insight.get("affected_pods_count", len(pods)),
                    scope_suffix,
                ),
                "",
                "Что означает: {0}".format(markdown_escape(insight.get("explanation") or "нет описания")),
                "",
            ]
        )
        checks = insight.get("checks") or []
        if checks:
            lines.extend(["Что проверено автоматически:", ""])
            for check in checks[:20]:
                evidence = check.get("evidence") or []
                evidence_text = "; исходные данные: {0}".format(
                    ", ".join(markdown_code(value) for value in evidence)
                ) if evidence else ""
                lines.append(
                    "- [{0}] {1}: {2}{3}".format(
                        markdown_escape(_status_label(check.get("status") or "observe")),
                        markdown_code(check.get("name") or "check"),
                        markdown_escape(check.get("summary") or ""),
                        evidence_text,
                    )
                )
            lines.append("")
        lines.extend(
            [
                "Что говорит против текущей проблемы: {0}.".format(
                    markdown_escape("; ".join(insight.get("counter_evidence") or []) or "в собранных данных ничего не найдено")
                ),
                "",
                "Что не удалось проверить: {0}.".format(
                    markdown_escape("; ".join(insight.get("missing_checks") or []) or "нет явно указанных")
                ),
                "",
                "Когда требуется действие: {0}".format(markdown_escape(insight.get("decision_condition") or "не указано")),
                "",
                "Что делать: {0}".format(markdown_escape(insight.get("recommendation") or "действие не указано")),
                "",
            ]
        )
        sources = insight.get("sources") or []
        if sources:
            lines.extend(
                [
                    "Справочные материалы (URL сохранены в программе, сеть при анализе не используется): {0}.".format(
                        ", ".join("[источник {0}]({1})".format(index + 1, value) for index, value in enumerate(sources))
                    ),
                    "",
                ]
            )
    if len(insights) > limit:
        lines.extend(["В Markdown опущено карточек: {0}; полный набор находится в `normalized-events.json.gz`.".format(len(insights) - limit), ""])


def _bounded_report_text(value, limit=220):
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


NODE_GAP_RE = re.compile(r"^node/[^/]+/(command/[^:]+|pod_logs):([^:]+)$")


def _compact_missing_evidence(values):
    grouped = {}
    other = []
    for value in values:
        match = NODE_GAP_RE.match(str(value))
        if not match:
            other.append(str(value))
            continue
        key = (match.group(1), match.group(2))
        grouped[key] = grouped.get(key, 0) + 1
    compact = sorted(set(other))
    compact.extend(
        "node/*/{0}:{1} ({2} {3})".format(path, status, count, "node" if count == 1 else "nodes")
        for (path, status), count in sorted(grouped.items())
    )
    return compact


def _render_hypotheses(lines, hypotheses, limit=10):
    lines.extend(
        [
            "## Наиболее вероятные объяснения",
            "",
            "Это детерминированное ранжирование по важности, актуальности, типу правила и связям в топологии. Балл помогает выбрать порядок проверки, но не является вероятностью.",
            "",
        ]
    )
    if not hypotheses:
        lines.extend(["Подтверждённых исходных признаков для ранжирования причин нет.", ""])
        return
    lines.extend(["| Место | Балл | Состояние | Роль | Гипотеза | Может объяснять |", "|---:|---:|---|---|---|---:|"])
    for item in hypotheses[:limit]:
        lines.append(
            "| {0} | {1} | {2} | {3} | {4} | {5} |".format(
                item.get("rank"),
                item.get("score"),
                markdown_escape(FINDING_STATUS_LABELS.get(item.get("status"), item.get("status") or "неизвестно")),
                markdown_escape(FINDING_ROLE_LABELS.get(item.get("role"), item.get("role") or "не указана")),
                markdown_escape(item.get("title") or item.get("rule_id") or "неизвестно"),
                len(item.get("downstream_findings") or []),
            )
        )
    lines.append("")
    for item in hypotheses[: min(limit, 5)]:
        lines.extend(
            [
                "{0}. **{1}** — {2}.".format(
                    item.get("rank"),
                    markdown_escape(item.get("title") or item.get("rule_id") or "неизвестно"),
                    markdown_escape("; ".join(item.get("reasons") or [])),
                ),
                "",
            ]
        )
    if len(hypotheses) > limit:
        lines.extend(["Остальные гипотезы: {0}; полный список находится в `report.json`.".format(len(hypotheses) - limit), ""])


def _render_metric_signals(lines, signals):
    if not signals:
        return
    lines.extend(
        [
            "## Изменения диагностических метрик",
            "",
            "Значения рассчитаны по фиксированным запросам Prometheus в окне инцидента. Универсальные пороги не применяются: таблица показывает форму сигнала, а не самостоятельно поставленный диагноз.",
            "",
            "| Метрика | Начало | Конец | Минимум | Максимум | Тенденция | Точек |",
            "|---|---:|---:|---:|---:|---|---:|",
        ]
    )
    for item in signals:
        lines.append(
            "| {0} | {1:.6g} | {2:.6g} | {3:.6g} | {4:.6g} | {5} | {6} |".format(
                markdown_escape(item.get("title") or item.get("query_id")),
                item.get("first", 0),
                item.get("last", 0),
                item.get("minimum", 0),
                item.get("maximum", 0),
                markdown_escape(METRIC_TREND_LABELS.get(item.get("trend"), item.get("trend") or "неизвестно")),
                item.get("sample_count", 0),
            )
        )
    lines.append("")


def build_report(collection_dir):
    collection, nodes, kubernetes, prometheus = load_collection(collection_dir)
    normalized = normalize_evidence(collection, nodes, kubernetes)
    normalized["message_insights"] = enrich_message_insights(
        normalized.get("message_insights", []), nodes, kubernetes, normalized
    )
    report_message_insights = _report_message_insights(normalized.get("message_insights", []))
    findings = annotate_findings(
        evaluate_rules(collection, nodes, kubernetes, normalized, prometheus),
        collection,
    )
    causal_analysis = build_causal_analysis(kubernetes, findings, normalized, prometheus, collection)
    node_inventory = [_node_row(name, snapshot) for name, snapshot in sorted(nodes.items())]
    coverage = _coverage(collection, nodes, kubernetes, prometheus)
    ledger = _rule_ledger(findings, coverage, collection.get("options", {}))
    facts = {
        "schema_version": 1,
        "collection_id": collection.get("collection_id"),
        "nodes": node_inventory,
        "options": {
            "collect_cgroup": collection.get("options", {}).get("collect_cgroup", True),
            "collect_etcd": collection.get("options", {}).get("collect_etcd", False),
            "purpose": collection.get("options", {}).get("purpose", "check"),
            "incident_start": collection.get("options", {}).get("incident_start"),
            "incident_end": collection.get("options", {}).get("incident_end"),
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
            "message_insight_count": len(normalized.get("message_insights", [])),
            "message_insights_requiring_attention": len(report_message_insights),
            "unknown_fingerprint_count": len(normalized.get("unknown_fingerprints", [])),
        },
        "coverage": coverage,
        "rule_evaluation_ledger": ledger,
        "causal_analysis": {
            "graph_nodes": len(causal_analysis["graph"]["nodes"]),
            "graph_edges": len(causal_analysis["graph"]["edges"]),
            "graph_truncated": causal_analysis["graph"]["truncated"],
            "hypothesis_count": len(causal_analysis["hypotheses"]),
            "metric_signal_count": len(causal_analysis["metric_signals"]),
        },
    }
    findings_document = {
        "schema_version": 1,
        "rule_pack_version": RULE_PACK_VERSION,
        "collection_id": collection.get("collection_id"),
        "items": findings,
        "evaluation_ledger": ledger,
        "hypotheses": causal_analysis["hypotheses"],
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
        "message_insights": report_message_insights,
        "rule_evaluation_ledger": ledger,
        "prometheus_status": prometheus.get("status") if prometheus else collection.get("prometheus", {}).get("status"),
        "normalization": facts["normalization"],
        "options": facts["options"],
        "analysis": causal_analysis["analysis"],
        "hypotheses": causal_analysis["hypotheses"],
        "metric_signals": causal_analysis["metric_signals"],
        "causal_graph": {
            "file": "causal-graph.json",
            "node_count": len(causal_analysis["graph"]["nodes"]),
            "edge_count": len(causal_analysis["graph"]["edges"]),
            "truncated": causal_analysis["graph"]["truncated"],
        },
    }
    root = Path(collection_dir)
    atomic_write_gzip_json(root / "normalized-events.json.gz", normalized)
    atomic_write_json(root / "facts.json", facts)
    atomic_write_json(root / "findings.json", findings_document)
    atomic_write_json(root / "causal-graph.json", causal_analysis)
    atomic_write_json(root / "report.json", report)
    purpose = report["analysis"]["purpose"]
    lines = [
        "# {0}".format("Разбор инцидента Kubernetes" if purpose == "incident" else "Проверка состояния Kubernetes"),
        "",
        "Идентификатор сбора: `{0}`".format(markdown_escape(report["collection_id"])),
        "",
        "Статус сбора: **{0}**".format(markdown_escape(_status_label(report["status"]))),
        "",
        "Проверки cgroup: **{0}**".format("включены" if report["options"]["collect_cgroup"] else "отключены"),
        "",
        "Проверки etcd: **{0}**".format("включены" if report["options"]["collect_etcd"] else "отключены"),
        "",
        "Назначение запуска: **{0}**".format("разбор инцидента" if purpose == "incident" else "обычная проверка"),
        "",
    ]
    if purpose == "incident":
        lines.extend(
            [
                "Окно инцидента: **{0} — {1}**".format(
                    markdown_escape(report["analysis"].get("incident_start") or "не задано"),
                    markdown_escape(report["analysis"].get("incident_end") or "не задано"),
                ),
                "",
            ]
        )
    lines.extend(
        [
        "## Полнота исходных данных",
        "",
        ]
    )
    coverage_rows = _coverage_display_rows(coverage)
    lines.append(
        "Успешно собранных источников: {0}; источников с ограничениями или ошибками: {1}. Полный технический список находится в `report.json`.".format(
            sum(1 for item in coverage if item.get("status") == "collected"),
            len(coverage) - sum(1 for item in coverage if item.get("status") == "collected"),
        )
    )
    if coverage_rows:
        lines.extend(["", "| Источник с ограничением | Статус | Обязательный | Ошибка |", "|---|---|---|---|"])
        for item in coverage_rows:
            lines.append("| {0} | {1} | {2} | {3} |".format(markdown_escape(item.get("display_source")), markdown_escape(_status_label(item.get("status"))), "да" if item.get("required", True) else "нет", markdown_escape(item.get("error") or "")))
    else:
        lines.extend(["", "Все заявленные источники собраны без ошибок и усечения."])
    ledger_counts = {}
    for item in ledger:
        ledger_counts[item["status"]] = ledger_counts.get(item["status"], 0) + 1
    lines.extend(
        [
            "",
            "## Результаты автоматических проверок",
            "",
            "Обнаружена проблема: {0}; проблема не обнаружена: {1}; не удалось проверить: {2}; не применяется: {3}.".format(
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
        lines.append("«Не удалось проверить» означает, что для проверки не хватает исходных данных. Это не признак исправности или неисправности.")
        lines.append("")
        cause_counts = {}
        for item in unknown_rules:
            for cause in _compact_missing_evidence(item.get("missing_evidence", [])):
                cause_counts[cause] = cause_counts.get(cause, 0) + 1
        if cause_counts:
            lines.append("Почему проверки не выполнены (в скобках — сколько проверок зависит от источника):")
            lines.append("")
            for cause, count in sorted(cause_counts.items(), key=lambda item: (-item[1], item[0]))[:10]:
                lines.append("- {0} — {1}.".format(markdown_escape(_human_gap(cause)), count))
            lines.append("")
        lines.extend(["Подробный список по каждой проверке сохранён в `report.json`.", ""])
    _render_hypotheses(lines, causal_analysis["hypotheses"])
    _render_metric_signals(lines, causal_analysis["metric_signals"])
    causal_edges = [item for item in causal_analysis["graph"]["edges"] if item.get("relation") == "may_explain"]
    lines.extend(
        [
            "## Причинный граф",
            "",
            "Граф содержит объектов: {0}; связей: {1}; связей «может объяснять»: {2}. Полный машиночитаемый граф находится в `causal-graph.json`{3}.".format(
                len(causal_analysis["graph"]["nodes"]),
                len(causal_analysis["graph"]["edges"]),
                len(causal_edges),
                "; достигнут лимит размера" if causal_analysis["graph"]["truncated"] else "",
            ),
            "",
        ]
    )
    lines.extend(["", "## Инвентаризация узлов", "", "| Имя в inventory | Имя узла | ОС | Ядро | cgroup | kubelet | Где отключён IPv6 |", "|---|---|---|---|---|---|---|"])
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
    visible_findings = [
        finding for finding in findings
        if purpose == "incident" or finding.get("finding_status") != "resolved"
    ]
    hidden_resolved = len(findings) - len(visible_findings)
    lines.extend(["", "## Обнаруженные проблемы", ""])
    if hidden_resolved:
        lines.extend(
            [
                "Завершившихся исторических проблем скрыто в обычном режиме: {0}. Они сохранены в `findings.json`.".format(hidden_resolved),
                "",
            ]
        )
    if not visible_findings:
        lines.append("Автоматические проверки не обнаружили проблем. Это не доказывает, что кластер полностью исправен: часть источников могла быть недоступна.")
    for finding in visible_findings:
        affected = finding.get("affected") or []
        affected_visible = affected[:10]
        affected_omitted = max(0, finding.get("affected_total", len(affected)) - len(affected_visible))
        evidence = finding.get("evidence") or []
        evidence_visible = evidence[:10]
        evidence_omitted = max(0, finding.get("evidence_total", len(evidence)) - len(evidence_visible))
        lines.extend(
            [
                "### [{0}] {1}".format(
                    markdown_escape(SEVERITY_LABELS.get(finding.get("severity"), str(finding.get("severity") or "СВЕДЕНИЕ").upper())),
                    markdown_escape(finding["title"]),
                ),
                "",
                "Что обнаружено: {0}".format(markdown_escape(finding["summary"])),
                "",
                "Что это означает: {0}".format(markdown_escape(finding.get("explanation") or "Описание отсутствует.")),
                "",
                "Состояние: **{0}**. Роль: **{1}**.".format(
                    markdown_escape(FINDING_STATUS_LABELS.get(finding.get("finding_status"), finding.get("finding_status") or "неизвестно")),
                    markdown_escape(FINDING_ROLE_LABELS.get(finding.get("finding_role"), finding.get("finding_role") or "не указана")),
                ),
                "",
                "Надёжность вывода: {0}; уверенность в обнаружении: {1}; уверенность в установленной причине: {2}.".format(
                    markdown_escape(CLASSIFICATION_LABELS.get(finding.get("classification"), finding.get("classification") or "не указана")),
                    markdown_escape(_confidence_label(finding.get("detection_confidence"))),
                    markdown_escape(_confidence_label(finding.get("causal_confidence"))),
                ),
                "",
                "Время: {0} — {1}; длительность: {2} с; окно сопоставления: {3} с.".format(
                    markdown_escape(finding.get("started_at") or report.get("started_at") or "неизвестно"),
                    markdown_escape(finding.get("ended_at") or report.get("ended_at") or "неизвестно"),
                    markdown_escape(finding.get("duration_seconds") if finding.get("duration_seconds") is not None else "неизвестно"),
                    markdown_escape(finding.get("window_seconds") if finding.get("window_seconds") is not None else "не применяется"),
                ),
                "",
                "Затронутые объекты: {0}; всего: {1}; не показано: {2}.".format(
                    markdown_escape(", ".join(affected_visible) or "кластер"),
                    finding.get("affected_total", len(finding["affected"])),
                    affected_omitted,
                ),
                "",
                "Другие возможные объяснения: {0}.".format(markdown_escape("; ".join(finding.get("alternatives", [])) or "не указаны")),
                "",
                "Что говорит против текущей проблемы: {0}.".format(markdown_escape("; ".join(finding.get("counter_evidence", [])) or "в собранных данных ничего не найдено")),
                "",
                "Что не удалось проверить: {0}.".format(markdown_escape("; ".join(finding.get("missing_checks", [])) or "дополнительные пробелы не указаны")),
                "",
                "Что делать: {0}".format(markdown_escape(finding["recommendation"])),
                "",
                "Идентификатор проверки: `{0}`. Где посмотреть исходные данные: {1}; всего ссылок: {2}; не показано: {3}.".format(
                    markdown_escape(finding["rule_id"]),
                    ", ".join(markdown_code(value) for value in evidence_visible) or "ссылки отсутствуют",
                    finding.get("evidence_total", len(evidence)),
                    evidence_omitted,
                ),
                "",
            ]
        )
        fragments = finding.get("evidence_fragments", [])
        if fragments:
            lines.extend(["Фрагменты исходных сообщений:", ""])
            for fragment in fragments[:10]:
                lines.append(
                    "- `{0}` [{1}] {2}: {3}".format(
                        markdown_escape(fragment.get("reference")),
                        markdown_escape(_status_label(fragment.get("status"))),
                        markdown_escape(fragment.get("timestamp") or "время неизвестно"),
                        markdown_escape(fragment.get("excerpt") or ""),
                    )
                )
            lines.append("")
    stats = normalized.get("stats", {})
    _render_message_insights(lines, report_message_insights)
    lines.extend(
        [
            "## Обработка и сопоставление журналов",
            "",
            "Обработано записей: {0}; с диагностической категорией: {1}; без диагностической категории: {2}; распознано шаблонов каталога: {3}; сохранено неизвестных шаблонов: {4}; повреждено: {5}; исключено вне окна инцидента: {6}; совпадений по времени: {7}; данные усечены: {8}; заменено редких шаблонов: {9}.".format(
                stats.get("input_records", 0),
                stats.get("categorized_records", 0),
                stats.get("uncategorized_records", 0),
                stats.get("message_insight_fingerprints", 0),
                stats.get("unknown_retained_fingerprints", 0),
                stats.get("malformed_records", 0),
                stats.get("incident_window_filtered_records", 0),
                len(normalized.get("correlations", [])),
                stats.get("truncated", False),
                stats.get("unknown_fingerprint_replacements", 0),
            ),
            "",
        ]
    )
    unknown_count = len(normalized.get("unknown_fingerprints", []))
    if unknown_count:
        lines.extend(
            [
                "Сохранено неизвестных шаблонов: {0}. Их тексты не выводятся в основной отчёт без проверенной интерпретации и рекомендации. Полный ограниченный набор сохранён в `normalized-events.json.gz`; автоматически классифицированные сообщения, для которых требуется действие, показаны выше отдельными карточками.".format(unknown_count),
                "",
            ]
        )
    correlations = normalized.get("correlations", [])
    if correlations:
        lines.extend(["## Совпадения признаков по времени", "", "| Эпизод | Тип | Объект | Начало | Конец | Длительность, с |", "|---|---|---|---|---|---:|"])
        for item in correlations[:100]:
            lines.append(
                "| `{0}` | `{1}` | {2} | {3} | {4} | {5} |".format(
                    markdown_escape(item.get("episode_id") or "unknown"),
                    markdown_escape(item.get("correlation_id")),
                    markdown_escape(item.get("scope")),
                    markdown_escape(item.get("started_at") or "неизвестно"),
                    markdown_escape(item.get("ended_at") or "неизвестно"),
                    markdown_escape(item.get("duration_seconds") if item.get("duration_seconds") is not None else "неизвестно"),
                )
            )
        if len(correlations) > 100:
            lines.extend(["", "Всего эпизодов: {0}; не показано: {1}.".format(len(correlations), len(correlations) - 100)])
        lines.append("")
    atomic_write_bytes(root / "report.md", ("\n".join(lines).rstrip() + "\n").encode("utf-8"))
    return report
