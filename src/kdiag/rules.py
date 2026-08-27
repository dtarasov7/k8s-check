import hashlib
import json
import re
from datetime import datetime, timezone

from kdiag.node_identity import match_node_identities
from kdiag.rule_catalog import RULE_PACK_VERSION, rule_metadata
from kdiag.runtime import ACTIVE_SERVICE_STATES, loaded_runtime_service_states, runtime_service_is_active


PROBE_PATTERNS = (
    ("address_family", re.compile(r"address family not supported|eafnosupport", re.I)),
    ("no_route", re.compile(r"no route to host|network is unreachable", re.I)),
    ("connection_refused", re.compile(r"connection refused", re.I)),
    ("timeout", re.compile(r"timed? out|timeout|deadline exceeded|context deadline exceeded", re.I)),
    ("dns", re.compile(r"no such host|temporary failure in name resolution|server misbehaving", re.I)),
    ("tls", re.compile(r"tls|x509|certificate", re.I)),
    ("http_error", re.compile(r"statuscode:\s*[45][0-9][0-9]|http probe failed with statuscode", re.I)),
)

CGROUP_DENIAL_RE = re.compile(
    r"cgroup.*(permission denied|operation not permitted|read-only file system|eacces|eperm|erofs)|"
    r"(permission denied|operation not permitted|read-only file system).*(cgroup|subtree_control|cpu\.|io\.)",
    re.I,
)

CGROUP_RULE_IDS = frozenset(
    (
        "cgroup.controllers_missing",
        "cgroup.driver_mismatch",
        "cgroup.service_failure",
        "security_agent.cgroup_denial",
    )
)

COREDNS_ERROR_QUERY_RE = re.compile(
    r"\bplugin/errors:\s+\d+\s+([^\s:]{1,254})\s+([A-Z][A-Z0-9-]{0,15}):",
    re.I,
)
COREDNS_LOG_QUERY_RE = re.compile(
    r'"\s*([A-Z][A-Z0-9-]{0,15})\s+IN\s+([^\s"]{1,254})(?:\s|\")',
    re.I,
)
COREDNS_QUERY_NAME_RE = re.compile(r"(?:\\[0-9]{3}|[A-Z0-9_*?-])(?:\\[0-9]{3}|[A-Z0-9_.*?-]){0,252}\.?", re.I)
MAX_COREDNS_QUERY_DETAILS = 20
AUTH_CONFIG_PATH_RE = re.compile(r'(/[A-Za-z0-9_./-]*authentication-config\.ya?ml)', re.I)

GAP_SOURCE_LABELS = {
    "journal_services_current": "служебный журнал текущей загрузки",
    "journal_kernel_current": "журнал ядра текущей загрузки",
    "pod_logs": "локальные журналы контейнеров",
    "logs": "журналы системных Pod",
}
GAP_STATUS_LABELS = {
    "truncated": "усечён лимитом размера",
    "timeout": "не собран за отведённое время",
    "failed": "завершился ошибкой",
    "unsupported": "недоступен на узле",
    "permission_denied": "нет прав на чтение",
    "missing": "не собран",
    "source_unavailable": "источник недоступен",
}


def _finding(
    rule_id,
    severity,
    title,
    summary,
    affected,
    evidence,
    recommendation,
    causal_confidence="low",
    alternatives=None,
    classification=None,
    counter_evidence=None,
    missing_checks=None,
    detection_confidence=None,
):
    metadata = rule_metadata(rule_id)
    affected_values = sorted(set(value for value in affected if value is not None))
    scope = ",".join(affected_values) if affected_values else "cluster"
    if len(scope) > 200:
        scope = "sha256-" + hashlib.sha256(scope.encode("utf-8")).hexdigest()[:24]
    resolved_classification = classification or metadata["classification"]
    return {
        "id": "{0}:{1}".format(rule_id, scope),
        "rule_id": rule_id,
        "finding_status": "matched",
        "classification": resolved_classification,
        "rule_pack_version": RULE_PACK_VERSION,
        "version_scope": metadata["version_scope"],
        "source_refs": metadata["sources"],
        "severity": severity,
        "causal_confidence": causal_confidence,
        "detection_confidence": detection_confidence or ("high" if resolved_classification == "fact" else "medium"),
        "title": title,
        "summary": summary,
        "affected": affected_values,
        "affected_total": len(affected_values),
        "evidence": sorted(evidence)[:100],
        "evidence_total": len(set(evidence)),
        "alternatives": (alternatives or [])[:20],
        "counter_evidence": (counter_evidence or [])[:20],
        "missing_checks": (missing_checks or [])[:20],
        "recommendation": recommendation,
        "explanation": metadata["description"],
    }


def _command(snapshot, command_id):
    for item in snapshot.get("commands", []):
        if item.get("id") == command_id:
            return item
    return {}


def _kube_items(kubernetes, source_id):
    return kubernetes.get("sources", {}).get(source_id, {}).get("data", {}).get("items", []) or []


def _classify_probe_message(message):
    for name, pattern in PROBE_PATTERNS:
        if pattern.search(message):
            return name
    return "other"


def _events(normalized, category, sources=None):
    result = []
    for event in (normalized or {}).get("events", []):
        if category not in event.get("categories", []):
            continue
        if sources and event.get("source") not in sources:
            continue
        result.append(event)
    return result


def _collection_gap_summary(values):
    grouped = {}
    for value in values:
        source, status = str(value).rsplit(":", 1) if ":" in str(value) else (str(value), "missing")
        source_id = source.rsplit("/", 1)[-1]
        key = (source_id, status)
        grouped[key] = grouped.get(key, 0) + 1
    details = []
    for (source_id, status), count in sorted(grouped.items(), key=lambda item: (-item[1], item[0])):
        source_label = GAP_SOURCE_LABELS.get(source_id, "источник {0}".format(source_id))
        status_label = GAP_STATUS_LABELS.get(status, status)
        details.append("{0}: {1} ({2})".format(source_label, status_label, count))
    return "; ".join(details)


def _authentication_config_path_key(value):
    return str(value or "").replace("/extra0files/", "/extra-files/")


def _authentication_config_context(node_snapshots, kubernetes, events):
    paths = set()
    for event in events:
        paths.update(
            _authentication_config_path_key(path)
            for path in AUTH_CONFIG_PATH_RE.findall(str(event.get("message_excerpt") or ""))
        )
    counter_evidence = []
    missing_checks = [
        "Видимость файла внутри mount namespace контейнера kube-apiserver напрямую не проверяется."
    ]
    present = []
    metadata_collected = False
    for node_name, snapshot in (node_snapshots or {}).items():
        file_items = snapshot.get("facts", {}).get("authentication_config_files")
        if file_items is None:
            continue
        metadata_collected = True
        for item in file_items or []:
            if paths and _authentication_config_path_key(item.get("path")) not in paths:
                continue
            if item.get("status") == "present":
                present.append((node_name, item))
    if present:
        for node_name, item in present[:20]:
            counter_evidence.append(
                "На узле {0} файл {1} существует сейчас; regular_file={2}, readable={3}.".format(
                    node_name,
                    item.get("path"),
                    item.get("regular_file"),
                    item.get("readable"),
                )
            )
    elif not metadata_collected:
        missing_checks.append("Текущее наличие authentication config на узлах не собиралось этой версией снимка.")

    readyz_source = (kubernetes or {}).get("sources", {}).get("api_readyz", {}) or {}
    readyz_healthy = False
    if readyz_source.get("status") == "collected":
        checks = (readyz_source.get("data") or {}).get("checks") or []
        if checks and not any(item.get("status") == "failed" for item in checks):
            readyz_healthy = True
            counter_evidence.append("Текущая проверка готовности API server (readyz) успешна.")
        elif not checks:
            missing_checks.append("Ответ readyz собран, но отдельные проверки из него не распознаны.")
    else:
        missing_checks.append("Текущее состояние API server через readyz не собрано.")

    pods_source = (kubernetes or {}).get("sources", {}).get("pods", {}) or {}
    apiserver_pods = []
    if pods_source.get("status") == "collected":
        for pod in (pods_source.get("data") or {}).get("items", []) or []:
            metadata = pod.get("metadata", {}) or {}
            containers = pod.get("spec", {}).get("containers", []) or []
            if "kube-apiserver" not in str(metadata.get("name") or "") and not any(
                item.get("name") == "kube-apiserver" for item in containers
            ):
                continue
            statuses = [
                item for item in (pod.get("status", {}).get("containerStatuses") or [])
                if item.get("name") == "kube-apiserver"
            ]
            healthy = pod.get("status", {}).get("phase") == "Running" and bool(statuses) and all(
                item.get("ready") is True for item in statuses
            )
            apiserver_pods.append((metadata.get("namespace"), metadata.get("name"), healthy))
        if apiserver_pods and all(item[2] for item in apiserver_pods):
            counter_evidence.append("Все собранные Pod kube-apiserver сейчас Running/Ready.")
    else:
        missing_checks.append("Текущее состояние Pod kube-apiserver не собрано.")
    pods_healthy = bool(apiserver_pods) and all(item[2] for item in apiserver_pods)
    return {
        "counter_evidence": counter_evidence,
        "missing_checks": missing_checks,
        "current_healthy": bool(present) and readyz_healthy and pods_healthy,
    }


def _event_target(event):
    if event.get("namespace") and event.get("pod"):
        return "{0}/{1}".format(event["namespace"], event["pod"])
    return event.get("node") or event.get("component") or "cluster"


def _event_finding(rule_id, severity, title, summary, events, recommendation, confidence="high", alternatives=None, classification=None):
    finding = _finding(
        rule_id,
        severity,
        title,
        summary,
        sorted(set(_event_target(event) for event in events)),
        sorted(set(event.get("evidence") for event in events if event.get("evidence"))),
        recommendation,
        causal_confidence=confidence,
        alternatives=alternatives,
        classification=classification,
    )
    timestamps = sorted(event.get("timestamp") for event in events if event.get("timestamp") and not event.get("timestamp_inferred"))
    if timestamps:
        finding["started_at"] = timestamps[0]
        finding["ended_at"] = timestamps[-1]
    finding["event_count"] = sum(int(event.get("occurrence_count") or 1) for event in events)
    finding["evidence_fragments"] = [
        {
            "reference": event.get("evidence"),
            "status": "collected",
            "timestamp": event.get("timestamp"),
            "excerpt": event.get("message_excerpt"),
        }
        for event in events[:20]
        if event.get("evidence")
    ]
    return finding


def _coredns_error_query(message):
    text = str(message or "")
    match = COREDNS_ERROR_QUERY_RE.search(text)
    if match:
        name, query_type = match.group(1), match.group(2)
    else:
        match = COREDNS_LOG_QUERY_RE.search(text)
        if not match:
            return None
        query_type, name = match.group(1), match.group(2)
    if not COREDNS_QUERY_NAME_RE.fullmatch(name):
        return None
    return (name.rstrip(".").lower() or ".", query_type.upper())


def _coredns_error_summary(events):
    counts = {}
    identified = 0
    for event in events:
        query = _coredns_error_query(event.get("message_excerpt"))
        if not query:
            continue
        identified += 1
        counts[query] = counts.get(query, 0) + 1
    summary = "Найдено событий: {0}.".format(len(events))
    if not counts:
        return summary + " Имена DNS-запросов не удалось извлечь из этого формата CoreDNS log."
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    details = ["{0} [{1}] ×{2}".format(query[0], query[1], count) for query, count in ordered[:MAX_COREDNS_QUERY_DETAILS]]
    omitted = len(ordered) - len(details)
    suffix = "; ещё {0} уникальных".format(omitted) if omitted else ""
    return "{0} Запросы с ошибками: {1}{2}. Имена извлечены из {3}/{4} событий.".format(
        summary,
        "; ".join(details),
        suffix,
        identified,
        len(events),
    )


def _parse_snapshot_time(value):
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _parse_certificate_date(metadata):
    for line in str(metadata or "").splitlines():
        if not line.startswith("notAfter="):
            continue
        try:
            return datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _low_inode_mounts(snapshot):
    result = []
    output = _command(snapshot, "df_inodes").get("stdout", "")
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6 or not fields[4].endswith("%"):
            continue
        try:
            used_percent = int(fields[4][:-1])
        except ValueError:
            continue
        if used_percent >= 95:
            result.append(fields[-1])
    return result


def _kubelet_cgroup_driver(snapshot):
    values = snapshot.get("facts", {}).get("kubelet_config", {}).get("values", {})
    configured = str(values.get("cgroupDriver") or "").lower()
    if configured in ("systemd", "cgroupfs"):
        return configured
    exec_start = snapshot.get("facts", {}).get("service_states", {}).get("kubelet.service", {}).get("properties", {}).get("ExecStart", "")
    match = re.search(r"--cgroup-driver(?:=|\s+)(systemd|cgroupfs)\b", str(exec_start), re.I)
    return match.group(1).lower() if match else None


def _runtime_cgroup_driver(snapshot):
    command = _command(snapshot, "runtime_crictl_info")
    try:
        document = json.loads(command.get("stdout", ""))
    except (TypeError, json.JSONDecodeError):
        return None
    found = set()

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                lower_key = str(key).lower()
                if lower_key == "systemdcgroup" and isinstance(item, bool):
                    found.add("systemd" if item else "cgroupfs")
                elif lower_key in ("cgroupmanager", "cgroupdriver") and str(item).lower() in ("systemd", "cgroupfs"):
                    found.add(str(item).lower())
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    return next(iter(found)) if len(found) == 1 else None


def _source_collected(kubernetes, source_id):
    return kubernetes.get("sources", {}).get(source_id, {}).get("status") == "collected"


def _object_target(item):
    metadata = item.get("metadata", {}) or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name") or "unknown"
    return "{0}/{1}".format(namespace, name) if namespace else name


def _ready_endpoint(endpoint):
    conditions = endpoint.get("conditions", {}) or {}
    return conditions.get("ready") is not False and conditions.get("terminating") is not True


def _cluster_dns_values(value):
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip().strip("[]")
    return [item.strip().strip("'\"") for item in text.split(",") if item.strip()]


def _npd_findings(normalized):
    findings = []
    definitions = (
        ("node.kernel_oops", ("npd_kernel_oops",), "critical", "Kernel journal содержит KernelOops", "Проверить полный kernel trace, affected module и соответствие ядра/драйверов; не перезагружать узел автоматически."),
        ("node.task_hung", ("npd_task_hung",), "critical", "Kernel сообщает о зависшей task", "Определить task и wait channel, сопоставить с I/O latency, filesystem и blocked PSI."),
        ("node.filesystem_error", ("npd_ext4_error", "npd_xfs_shutdown"), "critical", "Kernel сообщает об ошибке файловой системы", "Сохранить kernel evidence, проверить устройство и состояние ФС; repair выполнять только offline по отдельной процедуре."),
        ("node.filesystem_warning", ("npd_ext4_warning",), "warning", "Kernel сообщает предупреждение EXT4", "Проверить повторяемость, устройство и последующие I/O/filesystem errors."),
        ("node.io_error", ("npd_io_error",), "critical", "Kernel сообщает Buffer I/O error", "Проверить block device, multipath/controller и filesystem evidence; не считать ошибку Kubernetes первопричиной."),
        ("node.unregister_netdevice", ("npd_unregister_netdevice",), "warning", "Kernel ожидает освобождения netdevice", "Сопоставить устройство с Cilium/veth namespace и сетевыми сбоями на этом узле."),
    )
    for rule_id, categories, severity, title, recommendation in definitions:
        events = [event for category in categories for event in _events(normalized, category)]
        if events:
            findings.append(
                _event_finding(
                    rule_id,
                    severity,
                    title,
                    "Совпадений с адаптированными NPD signatures: {0}.".format(len(events)),
                    events,
                    recommendation,
                    confidence="high",
                    classification="fact",
                )
            )
    hardware_categories = ("npd_memory_read_error", "npd_hardware_corrected", "npd_hardware_recoverable", "npd_hardware_fatal")
    hardware = [event for category in hardware_categories for event in _events(normalized, category)]
    if hardware:
        critical = any(set(event.get("categories", [])) & {"npd_hardware_recoverable", "npd_hardware_fatal"} for event in hardware)
        findings.append(
            _event_finding(
                "node.hardware_error",
                "critical" if critical else "warning",
                "Kernel сообщает аппаратную ошибку",
                "Hardware/memory events: {0}.".format(len(hardware)),
                hardware,
                "Проверить EDAC/MCE/firmware и аппаратную диагностику; corrected event не считать отказом без повторяемости.",
                confidence="high",
                classification="fact",
            )
        )
    return findings


def _service_dns_findings(node_snapshots, kubernetes):
    findings = []
    if not (_source_collected(kubernetes, "services") and _source_collected(kubernetes, "endpoint_slices")):
        return findings
    services = _kube_items(kubernetes, "services")
    slices = _kube_items(kubernetes, "endpoint_slices")
    slices_by_service = {}
    for index, endpoint_slice in enumerate(slices):
        metadata = endpoint_slice.get("metadata", {}) or {}
        key = (metadata.get("namespace"), (metadata.get("labels") or {}).get("kubernetes.io/service-name"))
        slices_by_service.setdefault(key, []).append((index, endpoint_slice))

    no_slices = []
    no_ready = []
    unresolved_ports = []
    service_evidence = {}
    for index, service in enumerate(services):
        metadata = service.get("metadata", {}) or {}
        spec = service.get("spec", {}) or {}
        selector_present = spec.get("selectorPresent")
        if selector_present is None:
            selector_present = bool(spec.get("selector"))
        if spec.get("type") == "ExternalName" or not selector_present:
            continue
        target = _object_target(service)
        key = (metadata.get("namespace"), metadata.get("name"))
        service_slices = slices_by_service.get(key, [])
        service_evidence[target] = ["kubernetes.json.gz#sources.services.items[{0}]".format(index)] + [
            "kubernetes.json.gz#sources.endpoint_slices.items[{0}]".format(slice_index)
            for slice_index, _item in service_slices
        ]
        if not service_slices:
            no_slices.append(target)
            continue
        endpoints = [endpoint for _slice_index, item in service_slices for endpoint in item.get("endpoints", []) or []]
        if not any(_ready_endpoint(endpoint) for endpoint in endpoints):
            no_ready.append(target)
            continue
        slice_ports = [port for _slice_index, item in service_slices for port in item.get("ports", []) or []]
        for port in spec.get("ports", []) or []:
            name = port.get("name")
            matching = [candidate for candidate in slice_ports if candidate.get("name") == name]
            target_port = port.get("targetPort") if port.get("targetPort") is not None else port.get("port")
            if not matching or all(candidate.get("port") is None for candidate in matching):
                unresolved_ports.append("{0}:{1}".format(target, name or port.get("port")))
            elif isinstance(target_port, int) and all(candidate.get("port") != target_port for candidate in matching):
                unresolved_ports.append("{0}:{1}".format(target, name or port.get("port")))
    if no_slices:
        findings.append(
            _finding(
                "kubernetes.service_no_endpoints",
                "warning",
                "Selector-based Service не имеет EndpointSlice",
                "Затронуто Service: {0}.".format(len(no_slices)),
                no_slices,
                [evidence for target in no_slices for evidence in service_evidence[target]],
                "Проверить selector, labels Pod и EndpointSlice controller; отсутствие endpoints не доказывает ошибку CNI.",
                causal_confidence="high",
                classification="fact",
            )
        )
    if no_ready:
        findings.append(
            _finding(
                "kubernetes.service_no_ready_endpoints",
                "warning",
                "Service не имеет ready endpoints",
                "EndpointSlice существуют, но ready endpoint отсутствует у {0} Service.".format(len(no_ready)),
                no_ready,
                [evidence for target in no_ready for evidence in service_evidence[target]],
                "Проверить Pod readiness, terminating state и публикацию EndpointSlice.",
                causal_confidence="high",
                classification="fact",
            )
        )
    if unresolved_ports:
        findings.append(
            _finding(
                "kubernetes.service_port_unresolved",
                "warning",
                "Service port не разрешён в EndpointSlice",
                "; ".join(unresolved_ports[:50]),
                unresolved_ports,
                ["kubernetes.json.gz#sources.services", "kubernetes.json.gz#sources.endpoint_slices"],
                "Сверить Service port/targetPort с containerPort и EndpointSlice ports; ручные EndpointSlice проверять отдельно.",
                causal_confidence="medium",
                classification="hypothesis",
            )
        )

    dns_namespaces = ("d8-kube-dns", "kube-system")
    dns_service_names = ("d8-kube-dns", "d8-kube-dns-redirect", "d8-kube-dns-redisrect", "kube-dns")
    dns_services = [
        service
        for service in services
        if (service.get("metadata") or {}).get("namespace") in dns_namespaces
        and (service.get("metadata") or {}).get("name") in dns_service_names
    ]
    backend_services = [
        service
        for service in dns_services
        if (service.get("spec") or {}).get("type") != "ExternalName"
        and (service.get("spec") or {}).get("clusterIP") not in (None, "", "None")
    ]
    backend_services.sort(
        key=lambda service: (
            dns_service_names.index((service.get("metadata") or {}).get("name")),
            str((service.get("metadata") or {}).get("namespace") or ""),
        )
    )
    dns_problems = []
    dns_evidence = ["kubernetes.json.gz#sources.services", "kubernetes.json.gz#sources.endpoint_slices"]
    if not backend_services:
        dns_problems.append("DNS backend Service (d8-kube-dns или kube-dns) отсутствует в d8-kube-dns и kube-system")
    else:
        dns_service = backend_services[0]
        dns_namespace = (dns_service.get("metadata") or {}).get("namespace")
        dns_service_name = (dns_service.get("metadata") or {}).get("name")
        dns_key = (dns_namespace, dns_service_name)
        dns_endpoints = [endpoint for _index, item in slices_by_service.get(dns_key, []) for endpoint in item.get("endpoints", []) or []]
        if not any(_ready_endpoint(endpoint) for endpoint in dns_endpoints):
            dns_problems.append("{0}/{1} не имеет ready endpoints".format(dns_namespace, dns_service_name))
        service_ips = set(dns_service.get("spec", {}).get("clusterIPs") or [dns_service.get("spec", {}).get("clusterIP")])
        service_ips.discard(None)
        mismatches = []
        for node_name, snapshot in node_snapshots.items():
            configured = set(_cluster_dns_values(snapshot.get("facts", {}).get("kubelet_config", {}).get("values", {}).get("clusterDNS")))
            if configured and service_ips and not configured & service_ips:
                mismatches.append("{0}: {1}".format(node_name, ",".join(sorted(configured))))
        if mismatches:
            findings.append(
                _finding(
                    "dns.cluster_dns_mismatch",
                    "critical",
                    "kubelet clusterDNS не совпадает с kube-dns Service",
                    "Service IP: {0}; {1}".format(",".join(sorted(service_ips)), "; ".join(mismatches)),
                    [value.split(":", 1)[0] for value in mismatches],
                    ["kubernetes.json.gz#sources.services"] + ["node-{0}.json.gz#facts.kubelet_config".format(value.split(":", 1)[0]) for value in mismatches],
                    "Сверить effective kubelet clusterDNS с ClusterIP DNS Service; изменение выполнять по процедуре конфигурации узлов.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    if _source_collected(kubernetes, "pods"):
        dns_pods = []
        node_local_dns_pods = []
        for pod in _kube_items(kubernetes, "pods"):
            metadata = pod.get("metadata", {}) or {}
            labels = metadata.get("labels", {}) or {}
            if metadata.get("namespace") not in dns_namespaces:
                continue
            identity = " ".join(
                str(value or "").lower()
                for value in (
                    metadata.get("name"),
                    labels.get("app"),
                    labels.get("k8s-app"),
                    labels.get("app.kubernetes.io/name"),
                )
            )
            if "node-local-dns" in identity:
                node_local_dns_pods.append(pod)
            elif "coredns" in identity or "kube-dns" in identity or "d8-kube-dns" in identity:
                dns_pods.append(pod)
        if not dns_pods:
            dns_problems.append("CoreDNS Pods отсутствуют")
        elif not any(
            pod.get("status", {}).get("phase") == "Running"
            and bool(pod.get("status", {}).get("containerStatuses"))
            and all(status.get("ready") is True for status in pod.get("status", {}).get("containerStatuses", []) or [])
            for pod in dns_pods
        ):
            dns_problems.append("нет Ready CoreDNS Pod")
        if node_local_dns_pods and not any(
            pod.get("status", {}).get("phase") == "Running"
            and bool(pod.get("status", {}).get("containerStatuses"))
            and all(status.get("ready") is True for status in pod.get("status", {}).get("containerStatuses", []) or [])
            for pod in node_local_dns_pods
        ):
            dns_problems.append("node-local-dns присутствует, но не имеет Ready Pod")
        dns_evidence.append("kubernetes.json.gz#sources.pods")
    if dns_problems:
        findings.append(
            _finding(
                "dns.kube_dns_unavailable",
                "critical",
                "Cluster DNS structural health нарушен",
                "; ".join(dns_problems),
                [_object_target(backend_services[0]) if backend_services else "cluster-dns"],
                dns_evidence,
                "Проверить CoreDNS Pods/logs, kube-dns Service/EndpointSlice и затем resolv.conf Pod; active test Pod не создаётся автоматически.",
                causal_confidence="high",
                classification="fact",
            )
        )
    return findings


def _json_command(snapshot, command_id):
    command = _command(snapshot, command_id)
    if command.get("status") != "collected":
        return None
    try:
        return json.loads(command.get("stdout", ""))
    except (TypeError, json.JSONDecodeError):
        return None


def _document_records(document):
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        return []
    if any(key in document for key in ("Status", "status", "health", "Health", "endpoint", "Endpoint")):
        return [document]
    return [value for value in document.values() if isinstance(value, dict)]


def _version_minor(value):
    match = re.search(r"(?:^|[^0-9])v?(\d+)\.(\d+)(?:\.(\d+))?", str(value or ""))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _prometheus_findings(prometheus):
    findings = []
    sources = (prometheus or {}).get("sources", {})
    alerts_source = sources.get("alerts", {})
    if alerts_source.get("status") == "collected":
        alerts = [item for item in alerts_source.get("data", {}).get("alerts", []) if str(item.get("state")).lower() == "firing"]
        if alerts:
            affected = []
            details = []
            for item in alerts[:100]:
                labels = item.get("labels", {}) or {}
                target = labels.get("node") or labels.get("pod") or labels.get("namespace") or labels.get("alertname") or "cluster"
                affected.append(target)
                annotations = item.get("annotations", {}) or {}
                details.append(
                    "{0}: state={1},activeAt={2},severity={3},message={4}".format(
                        labels.get("alertname") or target,
                        item.get("state"),
                        item.get("activeAt") or "unknown",
                        labels.get("severity") or "unknown",
                        annotations.get("summary") or annotations.get("message") or "",
                    )
                )
            findings.append(
                _finding(
                    "prometheus.alert_firing",
                    "warning",
                    "Prometheus содержит firing alerts",
                    "; ".join(details) + "; total={0}; alert rules и annotations считаются внешним evidence.".format(len(alerts)),
                    affected,
                    ["prometheus.json.gz#sources.alerts"],
                    "Сопоставить alert labels и activeAt с исходными bundles; проверить определение alert до вывода о причине.",
                    causal_confidence="none",
                    classification="fact",
                )
            )
    runtime = sources.get("runtimeinfo", {})
    if runtime.get("status") == "collected":
        data = runtime.get("data", {}) or {}
        if data.get("reloadConfigSuccess") is False:
            findings.append(
                _finding(
                    "prometheus.config_reload_failed",
                    "warning",
                    "Последняя перезагрузка конфигурации Prometheus неуспешна",
                    "Prometheus runtimeinfo сообщает reloadConfigSuccess=false.",
                    ["prometheus"],
                    ["prometheus.json.gz#sources.runtimeinfo"],
                    "Проверить Prometheus logs и конфигурацию; kdiag не выполняет reload.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
        try:
            corruption_count = int(data.get("corruptionCount") or 0)
        except (TypeError, ValueError):
            corruption_count = 0
        if corruption_count > 0:
            findings.append(
                _finding(
                    "prometheus.corruption_detected",
                    "critical",
                    "Prometheus сообщает о повреждении storage",
                    "runtimeinfo corruptionCount={0}.".format(corruption_count),
                    ["prometheus"],
                    ["prometheus.json.gz#sources.runtimeinfo"],
                    "Сохранить evidence и следовать процедуре восстановления Prometheus storage; автоматически файлы не удалять.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    return findings


def _pod_workload_findings(collection, kubernetes):
    findings = []
    waiting = []
    init_failed = []
    nonzero = []
    evicted = []
    restart_storm = []
    evidence = {}
    reference_time = _parse_snapshot_time(collection.get("ended_at"))
    ignored_waiting = {"podinitializing", "containercreating", "crashloopbackoff", "errimagepull", "imagepullbackoff"}
    for pod_index, pod in enumerate(_kube_items(kubernetes, "pods")):
        target = _object_target(pod)
        status = pod.get("status", {}) or {}
        if status.get("phase") == "Failed" and str(status.get("reason") or "").lower() == "evicted":
            evicted.append(target)
            evidence.setdefault(target, []).append("kubernetes.json.gz#sources.pods.items[{0}].status".format(pod_index))
        for field, is_init in (("initContainerStatuses", True), ("containerStatuses", False)):
            for status_index, container in enumerate(status.get(field, []) or []):
                container_target = "{0}/{1}".format(target, container.get("name") or "container")
                state = container.get("state", {}) or {}
                state_waiting = state.get("waiting") or {}
                waiting_reason = str(state_waiting.get("reason") or "")
                if waiting_reason and waiting_reason.lower() not in ignored_waiting:
                    (init_failed if is_init else waiting).append("{0}:{1}".format(container_target, waiting_reason))
                    evidence.setdefault(container_target, []).append(
                        "kubernetes.json.gz#sources.pods.items[{0}].status.{1}[{2}].state".format(pod_index, field, status_index)
                    )
                terminated = state.get("terminated") or {}
                exit_code = terminated.get("exitCode")
                reason = str(terminated.get("reason") or "")
                if exit_code not in (None, 0) and reason.lower() not in ("oomkilled", "completed"):
                    if is_init:
                        init_failed.append("{0}:exit={1}".format(container_target, exit_code))
                    elif status.get("phase") == "Failed":
                        nonzero.append("{0}:exit={1}".format(container_target, exit_code))
                    evidence.setdefault(container_target, []).append(
                        "kubernetes.json.gz#sources.pods.items[{0}].status.{1}[{2}].state".format(pod_index, field, status_index)
                    )
                restart_count = int(container.get("restartCount") or 0)
                last_finished_text = ((container.get("lastState") or {}).get("terminated") or {}).get("finishedAt")
                last_finished = _parse_snapshot_time(last_finished_text)
                if restart_count >= 5 and reference_time and last_finished and 0 <= (reference_time - last_finished).total_seconds() <= 3600:
                    restart_storm.append("{0}:restartCount={1},lastFinishedAt={2}".format(container_target, restart_count, last_finished_text))
                    evidence.setdefault(container_target, []).append(
                        "kubernetes.json.gz#sources.pods.items[{0}].status.{1}[{2}]".format(pod_index, field, status_index)
                    )
    definitions = (
        (waiting, "kubernetes.pod_waiting", "Pod containers не могут запуститься", "Проверить reason/message, runtime, volume и projected configuration; Secret contents не собирать."),
        (init_failed, "kubernetes.init_container_failed", "Init containers не завершились успешно", "Проверить init-container current/previous logs, exit code и зависимости до запуска application containers."),
        (nonzero, "kubernetes.container_exit_nonzero", "Containers завершились с ненулевым кодом", "Сопоставить exit code с termination reason и application logs; ненулевой код сам по себе не определяет инфраструктурную причину."),
        (evicted, "kubernetes.pod_evicted", "Pods были evicted", "Сопоставить Pod reason/message с Node pressure, requests и локальным ephemeral storage."),
        (restart_storm, "kubernetes.pod_restart_storm", "Containers имеют высокий cumulative restartCount и недавнее завершение", "Проверить lastState, previous logs, probes, OOM и runtime events; частота рестартов из одного snapshot неизвестна."),
    )
    for values, rule_id, title, recommendation in definitions:
        if not values:
            continue
        targets = sorted(set(value.split(":", 1)[0] for value in values))
        findings.append(
            _finding(
                rule_id,
                "warning",
                title,
                "; ".join(sorted(set(values))[:100]),
                targets,
                [ref for target in targets for ref in evidence.get(target, [])],
                recommendation,
                causal_confidence="high",
                classification="fact",
            )
        )

    workload_problems = {"deployment": [], "daemonset": [], "statefulset": [], "job": []}
    workload_evidence = {}
    for index, workload in enumerate(_kube_items(kubernetes, "workloads")):
        kind = str(workload.get("kind") or "").lower()
        target = _object_target(workload)
        spec = workload.get("spec", {}) or {}
        status = workload.get("status", {}) or {}
        conditions = status.get("conditions", []) or []
        if kind == "deployment" and any(
            (condition.get("reason") == "ProgressDeadlineExceeded" and str(condition.get("status")) == "False")
            or (condition.get("type") == "ReplicaFailure" and str(condition.get("status")) == "True")
            for condition in conditions
        ):
            workload_problems[kind].append(target)
        elif kind == "daemonset" and (status.get("numberMisscheduled") or 0) > 0:
            workload_problems[kind].append(target)
        elif kind == "statefulset" and any(
            str(condition.get("status")) == "True"
            and (
                condition.get("type") in ("ReplicaFailure", "Failed")
                or "fail" in str(condition.get("reason") or "").lower()
            )
            for condition in conditions
        ):
            workload_problems[kind].append(target)
        elif kind == "job" and any(condition.get("type") == "Failed" and str(condition.get("status")) == "True" for condition in conditions):
            workload_problems[kind].append(target)
        if target in workload_problems.get(kind, []):
            workload_evidence[target] = "kubernetes.json.gz#sources.workloads.items[{0}].status".format(index)
    workload_rules = {
        "deployment": ("kubernetes.deployment_rollout_failed", "Deployment rollout завершился ошибкой"),
        "daemonset": ("kubernetes.daemonset_misscheduled", "DaemonSet имеет misscheduled Pods"),
        "statefulset": ("kubernetes.statefulset_rollout_stalled", "StatefulSet rollout имеет явную failed condition"),
        "job": ("kubernetes.job_failed", "Job имеет condition Failed=True"),
    }
    for kind, values in workload_problems.items():
        if values:
            rule_id, title = workload_rules[kind]
            findings.append(
                _finding(rule_id, "warning", title, "Затронуто: {0}.".format(", ".join(values[:100])), values, [workload_evidence[value] for value in values], "Сопоставить workload conditions с Pods и Events; автоматический rollout/restart не выполнять.", causal_confidence="high", classification="fact")
            )
    return findings


def _pdb_findings(kubernetes):
    if not _source_collected(kubernetes, "pdb"):
        return []
    unhealthy = []
    blocked = []
    unhealthy_details = []
    blocked_details = []
    unhealthy_evidence = []
    blocked_evidence = []
    for index, pdb in enumerate(_kube_items(kubernetes, "pdb")):
        status = pdb.get("status", {}) or {}
        expected = int(status.get("expectedPods") or 0)
        current = int(status.get("currentHealthy") or 0)
        desired = int(status.get("desiredHealthy") or 0)
        allowed = int(status.get("disruptionsAllowed") or 0)
        target = _object_target(pdb)
        if expected > 0 and current < desired:
            unhealthy.append(target)
            unhealthy_details.append(
                "{0}: expectedPods={1},currentHealthy={2},desiredHealthy={3},disruptionsAllowed={4}".format(
                    target, expected, current, desired, allowed
                )
            )
            unhealthy_evidence.append("kubernetes.json.gz#sources.pdb.items[{0}].status".format(index))
        if expected > 0 and "disruptionsAllowed" in status and allowed == 0:
            blocked.append(target)
            blocked_details.append(
                "{0}: expectedPods={1},currentHealthy={2},desiredHealthy={3},disruptionsAllowed=0".format(
                    target, expected, current, desired
                )
            )
            blocked_evidence.append("kubernetes.json.gz#sources.pdb.items[{0}].status".format(index))
    findings = []
    if unhealthy:
        findings.append(
            _finding("pdb.insufficient_healthy", "warning", "PDB имеет меньше healthy Pods, чем требуется", "; ".join(unhealthy_details[:100]), unhealthy, unhealthy_evidence, "Проверить соответствующие workload и Pods; PDB не изменять автоматически.", causal_confidence="high", classification="fact")
        )
    if blocked:
        findings.append(
            _finding("pdb.disruption_blocked", "info", "PDB сейчас не разрешает voluntary disruptions", "; ".join(blocked_details[:100]) + "; это может быть нормальным состоянием.", blocked, blocked_evidence, "Учитывать состояние перед drain/maintenance; само по себе оно не является отказом.", causal_confidence="none", classification="fact")
        )
    return findings


def _runtime_and_inventory_findings(collection, node_snapshots, kubernetes):
    findings = []
    runtime_not_ready = []
    network_not_ready = []
    swap_nodes = []
    low_runtime_filesystems = {}
    resolver_limits = []
    rotation_broken = []
    for name, snapshot in node_snapshots.items():
        info = _json_command(snapshot, "runtime_crictl_info")
        runtime_status = (info or {}).get("status") if isinstance(info, dict) else {}
        conditions = runtime_status.get("conditions", []) if isinstance(runtime_status, dict) else []
        for condition in conditions or []:
            ready = condition.get("status") is True or str(condition.get("status")).lower() == "true"
            if condition.get("type") == "RuntimeReady" and not ready:
                runtime_not_ready.append(name)
            if condition.get("type") == "NetworkReady" and not ready:
                network_not_ready.append(name)
        swaps = snapshot.get("facts", {}).get("swaps", {})
        swap_lines = [line for line in swaps.get("text", "").splitlines() if line.strip()]
        fail_swap = str(snapshot.get("facts", {}).get("kubelet_config", {}).get("values", {}).get("failSwapOn", "true")).lower()
        if len(swap_lines) > 1 and fail_swap != "false":
            swap_nodes.append(name)
        resolv = snapshot.get("facts", {}).get("resolv_conf", {})
        if resolv.get("status") in ("collected", "truncated") and len(resolv.get("nameservers", [])) > 3:
            resolver_limits.append(name)
        rotation = snapshot.get("facts", {}).get("kubelet_certificate_rotation", {})
        rotate_enabled = str(snapshot.get("facts", {}).get("kubelet_config", {}).get("values", {}).get("rotateCertificates", "")).lower() == "true"
        if rotate_enabled and rotation.get("status") not in ("collected", None):
            rotation_broken.append("{0}:{1}".format(name, rotation.get("status")))
        disk = _command(snapshot, "df_blocks")
        mounts = []
        for line in disk.get("stdout", "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6 or not parts[-2].endswith("%"):
                continue
            mount = parts[-1]
            try:
                used_percent = int(parts[-2][:-1])
            except ValueError:
                continue
            relevant = mount != "/" and any(
                mount == path or path.startswith(mount.rstrip("/") + "/")
                for path in ("/var/lib/kubelet", "/var/lib/containerd", "/var/lib/containers", "/var/log")
            )
            if relevant and used_percent >= 90:
                mounts.append("{0}={1}%".format(mount, used_percent))
        if mounts:
            low_runtime_filesystems[name] = mounts
    definitions = (
        (runtime_not_ready, "runtime.cri_not_ready", "CRI RuntimeReady=False", "Проверить runtime service, socket, cgroup и storage."),
        (network_not_ready, "runtime.cri_network_not_ready", "CRI NetworkReady=False", "Проверить Cilium agent, CNI config и pod sandbox events."),
        (swap_nodes, "node.swap_active", "На узлах активен swap при failSwapOn", "Сверить policy kubelet и фактическое использование swap; изменение выполнять только по процедуре узла."),
        (resolver_limits, "dns.nameserver_limit_exceeded", "Node resolver содержит более трёх nameserver", "Проверить kubelet resolvConf и локальный caching resolver; Pod resolver может потерять часть nameserver."),
    )
    for values, rule_id, title, recommendation in definitions:
        if values:
            findings.append(_finding(rule_id, "warning", title, "Затронуто узлов: {0}.".format(len(values)), values, ["node-{0}.json.gz".format(name) for name in values], recommendation, causal_confidence="high" if rule_id.startswith("runtime.") else "medium", classification="fact"))
    if low_runtime_filesystems:
        findings.append(_finding("node.low_runtime_disk", "warning", "Заполнена отдельная runtime/kubelet/log filesystem", "; ".join("{0}: {1}".format(name, ",".join(mounts)) for name, mounts in sorted(low_runtime_filesystems.items())), list(low_runtime_filesystems), ["node-{0}.json.gz#commands.df_blocks".format(name) for name in low_runtime_filesystems], "Определить потребителя на соответствующем mount; данные автоматически не удалять.", causal_confidence="high", classification="fact"))
    if rotation_broken:
        findings.append(_finding("certificate.kubelet_rotation_broken", "warning", "Kubelet client certificate rotation path повреждён", "; ".join(rotation_broken), [value.split(":", 1)[0] for value in rotation_broken], ["node-{0}.json.gz#facts.kubelet_certificate_rotation".format(value.split(":", 1)[0]) for value in rotation_broken], "Проверить kubelet-client-current.pem, target certificate и kubelet journal; сертификаты автоматически не заменять.", causal_confidence="high", classification="fact"))

    api_versions = []
    for pod in _kube_items(kubernetes, "pods"):
        name = str((pod.get("metadata") or {}).get("name") or "")
        if name.startswith("kube-apiserver-"):
            for container in (pod.get("spec") or {}).get("containers", []) or []:
                if container.get("name") == "kube-apiserver":
                    version = _version_minor(container.get("image"))
                    if version:
                        api_versions.append(version)
    unsupported = []
    mixed_api_versions = []
    if api_versions:
        oldest_api = min(api_versions)
        newest_api = max(api_versions)
        if newest_api != oldest_api:
            mixed_api_versions.append(
                "kube-apiserver versions {0}.{1}..{2}.{3}".format(
                    oldest_api[0], oldest_api[1], newest_api[0], newest_api[1]
                )
            )
        if newest_api[0] != oldest_api[0] or newest_api[1] - oldest_api[1] > 1:
            unsupported.append("kube-apiserver skew {0}.{1}..{2}.{3}".format(oldest_api[0], oldest_api[1], newest_api[0], newest_api[1]))
        for node in _kube_items(kubernetes, "nodes"):
            name = (node.get("metadata") or {}).get("name")
            kubelet = _version_minor((node.get("status") or {}).get("nodeInfo", {}).get("kubeletVersion"))
            if not kubelet:
                continue
            allowed_older = 2 if kubelet[1] < 25 else 3
            if kubelet[0] != oldest_api[0] or kubelet[1] > oldest_api[1] or newest_api[1] - kubelet[1] > allowed_older:
                unsupported.append(
                    "{0}: kubelet {1}.{2}, apiserver range {3}.{4}..{5}.{6}".format(
                        name, kubelet[0], kubelet[1], oldest_api[0], oldest_api[1], newest_api[0], newest_api[1]
                    )
                )
    if mixed_api_versions:
        findings.append(
            _finding(
                "inventory.mixed_apiserver_versions",
                "info",
                "API server instances используют разные minor versions",
                "; ".join(mixed_api_versions),
                ["kube-apiserver"],
                ["kubernetes.json.gz#sources.pods"],
                "Проверить, что различие укладывается в version-skew policy и соответствует текущему этапу control-plane rollout.",
                causal_confidence="none",
                classification="fact",
            )
        )
    if unsupported:
        findings.append(_finding("inventory.unsupported_version_skew", "critical", "Компоненты Kubernetes имеют неподдерживаемый version skew", "; ".join(unsupported), unsupported, ["kubernetes.json.gz#sources.nodes", "kubernetes.json.gz#sources.pods"], "Планировать выравнивание версий по version-skew policy; minor upgrade kubelet выполнять после drain.", causal_confidence="high", classification="fact"))
    return findings


def _cilium_dns_dataplane_findings(node_snapshots, kubernetes, normalized):
    findings = []
    coredns_events = [
        event
        for event in (normalized or {}).get("events", [])
        if set(event.get("categories", ())) & {"dns_servfail", "dns_forward_loop", "dns_upstream_failure"}
        and "coredns" in str(event.get("component") or "").lower()
    ]
    if coredns_events:
        severity = "critical" if any("dns_forward_loop" in event.get("categories", []) for event in coredns_events) else "warning"
        findings.append(_event_finding("dns.coredns_errors", severity, "CoreDNS сообщает об ошибках resolution/forwarding", _coredns_error_summary(coredns_events), coredns_events, "Проверить имена запросов на опечатки и несуществующие zones, затем CoreDNS forward targets, loop plugin, upstream reachability и resolver узлов.", confidence="high", classification="fact"))
    empty_dns_configs = []
    empty_dns_evidence = []
    for source_id in ("coredns_config", "node_local_dns_config"):
        dns_config = kubernetes.get("sources", {}).get(source_id, {})
        if dns_config.get("status") != "collected" or dns_config.get("data", {}).get("corefilePresent"):
            continue
        metadata = dns_config.get("data", {}).get("metadata", {}) or {}
        empty_dns_configs.append(
            "{0}/{1}".format(metadata.get("namespace") or "unknown", metadata.get("name") or source_id)
        )
        empty_dns_evidence.append("kubernetes.json.gz#sources.{0}".format(source_id))
    if empty_dns_configs:
        findings.append(_finding("dns.coredns_config_empty", "critical", "DNS ConfigMap не содержит Corefile", "ConfigMap без непустого Corefile: {0}.".format(", ".join(empty_dns_configs)), empty_dns_configs, empty_dns_evidence, "Восстановить утверждённый Corefile по change procedure; kdiag конфигурацию не изменяет.", causal_confidence="high", classification="fact"))

    pods = _kube_items(kubernetes, "pods")
    kube_proxy_present = any(
        (pod.get("metadata") or {}).get("namespace") == "kube-system"
        and str((pod.get("metadata") or {}).get("name") or "").startswith("kube-proxy-")
        for pod in pods
    )
    cilium_config = kubernetes.get("sources", {}).get("cilium_config", {})
    replacement = str(cilium_config.get("data", {}).get("data", {}).get("kube-proxy-replacement") or "").lower()
    if _source_collected(kubernetes, "pods") and cilium_config.get("status") == "collected" and not kube_proxy_present and replacement in ("false", "disabled"):
        findings.append(_finding("cilium.kube_proxy_replacement_disabled", "critical", "Cilium kube-proxy replacement явно отключён", "kube-proxy Pods отсутствуют, kube-proxy-replacement={0!r}.".format(replacement), ["cluster"], ["kubernetes.json.gz#sources.cilium_config", "kubernetes.json.gz#sources.pods"], "Проверить effective Cilium KubeProxyReplacement на каждом agent; изменение выполнять только по процедуре Cilium rollout.", causal_confidence="high", classification="fact"))

    expected_frontends = []
    for service in _kube_items(kubernetes, "services"):
        spec = service.get("spec", {}) or {}
        if spec.get("type") == "ExternalName" or spec.get("clusterIP") in (None, "", "None"):
            continue
        ips = spec.get("clusterIPs") or [spec.get("clusterIP")]
        for ip in ips:
            for port in spec.get("ports", []) or []:
                if ip and port.get("port") is not None:
                    expected_frontends.append((str(ip), int(port["port"]), _object_target(service)))
    missing_by_node = {}
    service_evidence = []
    for node_name, snapshot in node_snapshots.items():
        document = None
        command_id = None
        for candidate in ("cilium_debug_services", "cilium_services"):
            value = _json_command(snapshot, candidate)
            if isinstance(value, dict) and isinstance(value.get("services"), list):
                document = value
                command_id = candidate
                break
        if not document:
            continue
        actual = set()
        for service in document.get("services", []):
            frontend = service.get("frontend", {}) or {}
            try:
                actual.add((str(frontend.get("ip")), int(frontend.get("port"))))
            except (TypeError, ValueError):
                continue
        missing = [target for ip, port, target in expected_frontends if (ip, port) not in actual]
        if missing:
            missing_by_node[node_name] = sorted(set(missing))[:100]
            service_evidence.append("node-{0}.json.gz#commands.{1}".format(node_name, command_id))
    if missing_by_node:
        findings.append(_finding("cilium.service_frontend_missing", "warning", "Cilium service map не содержит ожидаемые ClusterIP frontends", "; ".join("{0}: {1}".format(name, ",".join(values)) for name, values in sorted(missing_by_node.items())), list(missing_by_node), service_evidence + ["kubernetes.json.gz#sources.services"], "Повторить snapshot для исключения краткого рассогласования и проверить cilium-dbg service list, agent status и Kubernetes watch errors.", causal_confidence="medium", alternatives=["snapshot попал в момент обновления Service", "CLI показал неполный service scope"], classification="hypothesis"))
    return findings


def _controlplane_etcd_findings(collection, node_snapshots, kubernetes):
    findings = []
    readyz = kubernetes.get("sources", {}).get("api_readyz")
    if readyz:
        failed_checks = [check for check in readyz.get("data", {}).get("checks", []) if check.get("status") == "failed"]
        if failed_checks:
            findings.append(
                _finding(
                    "controlplane.api_readyz_failed",
                    "critical",
                    "API server /readyz содержит failed checks",
                    "; ".join("{0}: {1}".format(item.get("name"), item.get("message")) for item in failed_checks),
                    ["kube-apiserver"],
                    ["kubernetes.json.gz#sources.api_readyz"],
                    "Проверить конкретный failed check; readyz failure не является разрешением на автоматический restart.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    if _source_collected(kubernetes, "api_services"):
        unavailable = []
        evidence = []
        for index, api_service in enumerate(_kube_items(kubernetes, "api_services")):
            for condition in api_service.get("status", {}).get("conditions", []) or []:
                if condition.get("type") == "Available" and str(condition.get("status")) in ("False", "Unknown"):
                    unavailable.append(_object_target(api_service))
                    evidence.append("kubernetes.json.gz#sources.api_services.items[{0}]".format(index))
                    break
        if unavailable:
            findings.append(
                _finding(
                    "controlplane.apiservice_unavailable",
                    "warning",
                    "Aggregated APIService недоступен",
                    "Unavailable APIService: {0}.".format(len(unavailable)),
                    unavailable,
                    evidence,
                    "Проверить backing Service/EndpointSlice, CA и API aggregation logs.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    if _source_collected(kubernetes, "nodes") and _source_collected(kubernetes, "leases"):
        node_names = [(item.get("metadata") or {}).get("name") for item in _kube_items(kubernetes, "nodes")]
        leases = {
            (item.get("metadata") or {}).get("name"): item
            for item in _kube_items(kubernetes, "leases")
            if (item.get("metadata") or {}).get("namespace") == "kube-node-lease"
        }
        epochs = [_parse_snapshot_time((lease.get("spec") or {}).get("renewTime")) for lease in leases.values()]
        epochs = [value for value in epochs if value]
        newest = max(epochs) if epochs else None
        stale = []
        for node_name in node_names:
            lease = leases.get(node_name)
            if not lease:
                stale.append("{0}: missing".format(node_name))
                continue
            renew = _parse_snapshot_time((lease.get("spec") or {}).get("renewTime"))
            duration = int((lease.get("spec") or {}).get("leaseDurationSeconds") or 40)
            if newest and renew and (newest - renew).total_seconds() > max(120, duration * 3):
                stale.append("{0}: lag={1}s".format(node_name, int((newest - renew).total_seconds())))
        if stale:
            findings.append(
                _finding(
                    "controlplane.node_lease_stale",
                    "warning",
                    "Node Lease отсутствует или отстаёт от peer leases",
                    "; ".join(stale),
                    [value.split(":", 1)[0] for value in stale],
                    ["kubernetes.json.gz#sources.leases", "kubernetes.json.gz#sources.nodes"],
                    "Сопоставить Lease с Node Ready, kubelet journal и time synchronization; относительное отставание не доказывает network partition.",
                    causal_confidence="medium",
                    classification="correlation",
                )
            )
    if _source_collected(kubernetes, "pods"):
        control_components = {"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"}
        unhealthy = []
        evidence = []
        for index, pod in enumerate(_kube_items(kubernetes, "pods")):
            metadata = pod.get("metadata", {}) or {}
            labels = metadata.get("labels", {}) or {}
            component = labels.get("component") or labels.get("app.kubernetes.io/component")
            name = str(metadata.get("name") or "")
            if metadata.get("namespace") != "kube-system" or not (component in control_components or any(name.startswith(value + "-") for value in control_components)):
                continue
            statuses = pod.get("status", {}).get("containerStatuses", []) or []
            if pod.get("status", {}).get("phase") != "Running" or not statuses or any(status.get("ready") is not True for status in statuses):
                unhealthy.append(_object_target(pod))
                evidence.append("kubernetes.json.gz#sources.pods.items[{0}]".format(index))
        if unhealthy:
            findings.append(
                _finding(
                    "controlplane.static_pod_unhealthy",
                    "critical",
                    "Control-plane Pod нездоров",
                    "Нездоровых control-plane Pods: {0}.".format(len(unhealthy)),
                    unhealthy,
                    evidence,
                    "Проверить static Pod container state/logs, manifest hash, runtime и соответствующий health endpoint.",
                    causal_confidence="high",
                    classification="fact",
                )
            )

    etcd_gaps = []
    etcd_gap_evidence = []
    health_failures = []
    health_evidence = []
    alarms = []
    alarm_evidence = []
    leaders = set()
    cluster_ids = set()
    revisions = []
    versions = set()
    raft_lag = []
    near_quota = []
    fragmented = []
    status_evidence = []
    for node_name, snapshot in node_snapshots.items():
        etcd = snapshot.get("facts", {}).get("etcd", {})
        if etcd.get("status") in ("partial", "unavailable", "unsupported"):
            etcd_gaps.append("{0}:{1}".format(node_name, etcd.get("status")))
            etcd_gap_evidence.append("node-{0}.json.gz#facts.etcd".format(node_name))
        health = _json_command(snapshot, "etcd_endpoint_health")
        if health is not None:
            for record in _document_records(health):
                value = record.get("health", record.get("Health"))
                error = record.get("error", record.get("Error"))
                if value is False or str(value).lower() == "false" or error:
                    health_failures.append("{0}:{1}".format(node_name, record.get("endpoint") or record.get("Endpoint") or "endpoint"))
                    health_evidence.append("node-{0}.json.gz#commands.etcd_endpoint_health".format(node_name))
        alarm_document = _json_command(snapshot, "etcd_alarm_list")
        if isinstance(alarm_document, dict):
            for alarm in alarm_document.get("alarms", []) or []:
                alarms.append("{0}:{1}".format(node_name, alarm.get("alarm") or alarm.get("Alarm") or "unknown"))
                alarm_evidence.append("node-{0}.json.gz#commands.etcd_alarm_list".format(node_name))
        status_document = _json_command(snapshot, "etcd_endpoint_status")
        if status_document is not None:
            status_evidence.append("node-{0}.json.gz#commands.etcd_endpoint_status".format(node_name))
            for record in _document_records(status_document):
                status = record.get("Status") or record.get("status") or record
                header = status.get("header") or status.get("Header") or {}
                leader = status.get("leader", status.get("Leader"))
                cluster_id = header.get("cluster_id", header.get("clusterId", header.get("clusterID")))
                endpoint = record.get("Endpoint") or record.get("endpoint") or node_name
                revision = header.get("revision", header.get("Revision"))
                version = status.get("version", status.get("Version"))
                raft_index = status.get("raftIndex", status.get("raft_index", status.get("RaftIndex")))
                applied_index = status.get("raftAppliedIndex", status.get("raft_applied_index", status.get("RaftAppliedIndex")))
                db_size = status.get("dbSize", status.get("db_size", status.get("DbSize")))
                db_in_use = status.get("dbSizeInUse", status.get("db_size_in_use", status.get("DbSizeInUse")))
                if leader is not None:
                    leaders.add(str(leader))
                if cluster_id is not None:
                    cluster_ids.add(str(cluster_id))
                if version:
                    versions.add(str(version))
                try:
                    revisions.append(int(revision))
                except (TypeError, ValueError):
                    pass
                try:
                    lag = int(raft_index) - int(applied_index)
                    if lag > 1000:
                        raft_lag.append("{0}:lag={1}".format(endpoint, lag))
                except (TypeError, ValueError):
                    pass
                try:
                    size = int(db_size)
                    in_use = int(db_in_use)
                    quota = int(etcd.get("quota_backend_bytes") or 0)
                    if quota and size / float(quota) >= 0.80:
                        near_quota.append("{0}:{1}/{2}".format(endpoint, size, quota))
                    if size >= 100 * 1024 * 1024 and in_use >= 0 and in_use / float(size) < 0.50:
                        fragmented.append("{0}:db={1},in_use={2}".format(endpoint, size, in_use))
                except (TypeError, ValueError, ZeroDivisionError):
                    pass
    if etcd_gaps:
        findings.append(
            _finding(
                "collector.etcd_evidence_gap",
                "warning",
                "Read-only etcd evidence собрано не полностью",
                "; ".join(etcd_gaps),
                [value.split(":", 1)[0] for value in etcd_gaps],
                etcd_gap_evidence,
                "Проверить наличие etcdctl/crictl, static Pod etcd и стандартных kubeadm healthcheck TLS paths; ключи не копировать.",
                causal_confidence="none",
                classification="fact",
            )
        )
    if health_failures:
        findings.append(
            _finding(
                "etcd.unhealthy",
                "critical",
                "etcd endpoint health failed",
                "; ".join(health_failures),
                health_failures,
                health_evidence,
                "Проверить quorum, network/TLS и member logs; не выполнять member remove/add автоматически.",
                causal_confidence="high",
                classification="fact",
            )
        )
    if alarms:
        findings.append(
            _finding(
                "etcd.alarm_active",
                "critical",
                "В etcd активен alarm",
                "; ".join(alarms),
                alarms,
                alarm_evidence,
                "Определить тип alarm и следовать etcd maintenance procedure; disarm/compact/defrag автоматически не выполняются.",
                causal_confidence="high",
                classification="fact",
            )
        )
    nonzero_leaders = {value for value in leaders if value not in ("0", "", "None")}
    if (leaders and ("0" in leaders or not nonzero_leaders)) or len(nonzero_leaders) > 1 or len(cluster_ids) > 1:
        findings.append(
            _finding(
                "etcd.topology_inconsistent",
                "critical",
                "etcd endpoint status сообщает несогласованную topology",
                "leaders={0}; cluster_ids={1}.".format(sorted(leaders), sorted(cluster_ids)),
                ["etcd"],
                status_evidence,
                "Проверить endpoint status непосредственно на каждом member и quorum; topology автоматически не изменять.",
                causal_confidence="high",
                classification="fact",
            )
        )
    if raft_lag or (revisions and max(revisions) - min(revisions) > 1000):
        findings.append(_finding("etcd.raft_apply_lag", "warning", "etcd members существенно отстают по Raft/revision", "raft lag: {0}; revision range: {1}.".format(", ".join(sorted(set(raft_lag))) or "none", (max(revisions) - min(revisions)) if revisions else "unknown"), ["etcd"], status_evidence, "Проверить disk fsync latency, network RTT, CPU pressure и etcd logs; member topology автоматически не менять.", causal_confidence="medium", classification="hypothesis"))
    if near_quota:
        quota_evidence = [
            "node-{0}.json.gz#facts.etcd.quota_backend_bytes".format(node_name)
            for node_name, snapshot in node_snapshots.items()
            if snapshot.get("facts", {}).get("etcd", {}).get("quota_backend_bytes")
        ]
        findings.append(_finding("etcd.database_near_quota", "critical", "etcd backend приближается к configured quota", "; ".join(sorted(set(near_quota))), ["etcd"], status_evidence + quota_evidence, "Проверить compaction/defragmentation policy и рост keyspace по утверждённой maintenance procedure; автоматически операции не выполнять.", causal_confidence="high", classification="fact"))
    if fragmented:
        findings.append(_finding("etcd.fragmentation_high", "warning", "etcd backend содержит значительный reclaimable space", "; ".join(sorted(set(fragmented))), ["etcd"], status_evidence, "Оценить окно и необходимость online defrag по etcd maintenance procedure; kdiag defrag не выполняет.", causal_confidence="medium", classification="hypothesis"))
    if len(versions) > 1:
        findings.append(_finding("etcd.member_version_drift", "warning", "etcd members имеют разные версии", "versions={0}.".format(sorted(versions)), ["etcd"], status_evidence, "Подтвердить допустимость mixed-version state для текущего upgrade этапа и завершить выравнивание по процедуре.", causal_confidence="high", classification="fact"))
    return findings


def _storage_cilium_findings(kubernetes):
    findings = []
    if _source_collected(kubernetes, "pvc"):
        pending = []
        pending_details = []
        evidence = []
        for index, pvc in enumerate(_kube_items(kubernetes, "pvc")):
            if pvc.get("status", {}).get("phase") == "Pending":
                pending.append(_object_target(pvc))
                status = pvc.get("status", {}) or {}
                pending_details.append(
                    "{0}: phase=Pending,reason={1},message={2},storageClass={3}".format(
                        _object_target(pvc),
                        status.get("reason") or "unknown",
                        status.get("message") or "",
                        (pvc.get("spec") or {}).get("storageClassName") or "default",
                    )
                )
                evidence.append("kubernetes.json.gz#sources.pvc.items[{0}]".format(index))
        if pending:
            findings.append(
                _finding(
                    "storage.pvc_pending",
                    "warning",
                    "PersistentVolumeClaim находится в Pending",
                    "; ".join(pending_details[:50]) + "; total={0}.".format(len(pending)),
                    pending,
                    evidence,
                    "Проверить Events, StorageClass, provisioner, WaitForFirstConsumer и topology; Pending сам по себе не определяет причину.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
        if _source_collected(kubernetes, "storage_classes"):
            classes = {(item.get("metadata") or {}).get("name") for item in _kube_items(kubernetes, "storage_classes")}
            missing = []
            for pvc in _kube_items(kubernetes, "pvc"):
                class_name = pvc.get("spec", {}).get("storageClassName")
                if class_name and class_name not in classes:
                    missing.append("{0}->{1}".format(_object_target(pvc), class_name))
            if missing:
                findings.append(
                    _finding(
                        "storage.storage_class_missing",
                        "critical",
                        "PVC ссылается на отсутствующий StorageClass",
                        "; ".join(missing),
                        missing,
                        ["kubernetes.json.gz#sources.pvc", "kubernetes.json.gz#sources.storage_classes"],
                        "Исправить декларацию или восстановить ожидаемый StorageClass по change procedure; автоматически создавать его нельзя.",
                        causal_confidence="high",
                        classification="fact",
                    )
                )
    if _source_collected(kubernetes, "pv"):
        failed = []
        failed_details = []
        for pv in _kube_items(kubernetes, "pv"):
            if pv.get("status", {}).get("phase") == "Failed":
                failed.append(_object_target(pv))
                status = pv.get("status", {}) or {}
                failed_details.append(
                    "{0}: phase=Failed,reason={1},message={2}".format(
                        _object_target(pv), status.get("reason") or "unknown", status.get("message") or ""
                    )
                )
        if failed:
            findings.append(
                _finding(
                    "storage.pv_failed",
                    "critical",
                    "PersistentVolume находится в Failed",
                    "; ".join(failed_details[:50]) + "; total={0}.".format(len(failed)),
                    failed,
                    ["kubernetes.json.gz#sources.pv"],
                    "Проверить PV reason/message, CSI controller и backend storage; reclaim operation не выполнять автоматически.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    failed_attachments = []
    if _source_collected(kubernetes, "volume_attachments"):
        evidence = []
        for index, attachment in enumerate(_kube_items(kubernetes, "volume_attachments")):
            status = attachment.get("status", {}) or {}
            errors = [value for value in (status.get("attachError"), status.get("detachError")) if value and value.get("message")]
            if status.get("attached") is False and errors:
                failed_attachments.append(attachment)
                evidence.append("kubernetes.json.gz#sources.volume_attachments.items[{0}]".format(index))
        if failed_attachments:
            findings.append(
                _finding(
                    "storage.volume_attachment_failed",
                    "critical",
                    "VolumeAttachment содержит attach/detach error",
                    "; ".join("{0}: {1}".format(_object_target(item), ((item.get("status") or {}).get("attachError") or (item.get("status") or {}).get("detachError") or {}).get("message")) for item in failed_attachments[:50]),
                    [_object_target(item) for item in failed_attachments],
                    evidence,
                    "Проверить CSI controller/node logs, VolumeAttachment node и backend; detach/delete автоматически не выполнять.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    if _source_collected(kubernetes, "pv") and _source_collected(kubernetes, "csi_drivers"):
        pv_drivers = {
            (item.get("metadata") or {}).get("name"): (item.get("spec", {}).get("csi") or {}).get("driver")
            for item in _kube_items(kubernetes, "pv")
            if (item.get("spec", {}).get("csi") or {}).get("driver")
        }
        registered = {(item.get("metadata") or {}).get("name") for item in _kube_items(kubernetes, "csi_drivers")}
        gaps = ["driver {0} used by PV {1} absent in CSIDriver".format(driver, pv) for pv, driver in pv_drivers.items() if driver not in registered]
        if _source_collected(kubernetes, "csi_nodes"):
            node_drivers = {
                (item.get("metadata") or {}).get("name"): {driver.get("name") for driver in item.get("spec", {}).get("drivers", []) or []}
                for item in _kube_items(kubernetes, "csi_nodes")
            }
            for attachment in failed_attachments:
                spec = attachment.get("spec", {}) or {}
                pv_name = (spec.get("source") or {}).get("persistentVolumeName")
                driver = pv_drivers.get(pv_name)
                node_name = spec.get("nodeName")
                if driver and node_name in node_drivers and driver not in node_drivers[node_name]:
                    gaps.append("driver {0} absent on CSINode {1} for PV {2}".format(driver, node_name, pv_name))
        if gaps:
            findings.append(
                _finding(
                    "storage.csi_driver_registration_gap",
                    "warning",
                    "CSI registration evidence не согласовано",
                    "; ".join(gaps[:50]),
                    gaps,
                    ["kubernetes.json.gz#sources.pv", "kubernetes.json.gz#sources.csi_drivers", "kubernetes.json.gz#sources.csi_nodes"],
                    "Проверить CSI controller/node registrar и фактическую модель установки драйвера; отсутствие CSIDriver не всегда является отказом.",
                    causal_confidence="low",
                    classification="hypothesis",
                )
            )
    if _source_collected(kubernetes, "cilium_endpoints"):
        unhealthy = []
        evidence = []
        for index, endpoint in enumerate(_kube_items(kubernetes, "cilium_endpoints")):
            status = endpoint.get("status", {}) or {}
            state = str(status.get("state") or "").lower()
            health = str((status.get("health") or {}).get("overallHealth") or "").lower()
            if (state and state != "ready") or (health and health != "ok"):
                unhealthy.append(_object_target(endpoint))
                evidence.append("kubernetes.json.gz#sources.cilium_endpoints.items[{0}]".format(index))
        if unhealthy:
            findings.append(
                _finding(
                    "cilium.endpoint_unhealthy",
                    "warning",
                    "CiliumEndpoint state/health не ready/ok",
                    "Unhealthy CiliumEndpoint: {0}.".format(len(unhealthy)),
                    unhealthy,
                    evidence,
                    "Сопоставить endpoint state с Cilium agent controllers, identity и regeneration logs на соответствующем Node.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    if _source_collected(kubernetes, "cilium_nodes"):
        failed_nodes = []
        evidence = []
        for index, node in enumerate(_kube_items(kubernetes, "cilium_nodes")):
            error = (((node.get("status") or {}).get("ipam") or {}).get("operatorStatus") or {}).get("error")
            if error:
                failed_nodes.append(_object_target(node))
                evidence.append("kubernetes.json.gz#sources.cilium_nodes.items[{0}]".format(index))
        if failed_nodes:
            findings.append(
                _finding(
                    "cilium.node_ipam_error",
                    "critical",
                    "CiliumNode IPAM operator status содержит error",
                    "CiliumNode with IPAM error: {0}.".format(len(failed_nodes)),
                    failed_nodes,
                    evidence,
                    "Проверить Cilium Operator logs, IPAM mode/pool и CiliumNode spec/status; allocation автоматически не изменять.",
                    causal_confidence="high",
                    classification="fact",
                )
            )
    policy_failures = []
    policy_evidence = []
    for source_id in ("cilium_network_policies", "cilium_clusterwide_network_policies"):
        if not _source_collected(kubernetes, source_id):
            continue
        for index, policy in enumerate(_kube_items(kubernetes, source_id)):
            failed = [node for node in policy.get("status", {}).get("nodes", []) or [] if node.get("ok") is False or node.get("error")]
            if failed:
                policy_failures.append(_object_target(policy))
                policy_evidence.append("kubernetes.json.gz#sources.{0}.items[{1}]".format(source_id, index))
    if policy_failures:
        findings.append(
            _finding(
                "cilium.policy_import_failed",
                "critical",
                "Cilium policy status содержит ошибки",
                "Policies with failed node status: {0}.".format(len(policy_failures)),
                policy_failures,
                policy_evidence,
                "Проверить Cilium agent policy import error и CRD compatibility; policy автоматически не изменять.",
                causal_confidence="high",
                classification="fact",
            )
        )
    return findings


def evaluate_rules(collection, node_snapshots, kubernetes, normalized=None, prometheus=None):
    findings = []
    node_results = collection.get("nodes", [])
    unavailable = [item.get("host") for item in node_results if item.get("status") != "collected"]
    if unavailable:
        findings.append(
            _finding(
                "collector.node_gap",
                "warning",
                "Не со всех узлов получен снимок",
                "Недоступные узлы не исключаются из отчёта; выводы по кластеру неполны.",
                unavailable,
                ["collection.json#nodes"],
                "Проверить SSH, host key, `sudo -n`, Python 3.8 и повторить сбор только после устранения доступа.",
                causal_confidence="none",
            )
        )

    evidence_gaps = []
    evidence_gap_refs = []
    required_commands = ("journal_services_current", "journal_kernel_current")
    for name, snapshot in node_snapshots.items():
        for command_id in required_commands:
            command = _command(snapshot, command_id)
            if command.get("status") != "collected" or command.get("truncated"):
                status = "truncated" if command.get("truncated") else command.get("status") or "missing"
                evidence_gaps.append("{0}/{1}:{2}".format(name, command_id, status))
                evidence_gap_refs.append("node-{0}.json.gz#commands.{1}".format(name, command_id))
        pod_logs_status = snapshot.get("pod_logs", {}).get("status")
        if pod_logs_status and pod_logs_status not in ("collected", "unsupported"):
            evidence_gaps.append("{0}/pod_logs:{1}".format(name, pod_logs_status))
            evidence_gap_refs.append("node-{0}.json.gz#pod_logs".format(name))
    for source_id, source in kubernetes.get("sources", {}).items():
        if source.get("required", True) and source.get("status") != "collected":
            evidence_gaps.append("kubernetes/{0}:{1}".format(source_id, source.get("status")))
            evidence_gap_refs.append("kubernetes.json.gz#sources.{0}".format(source_id))
    logs_status = kubernetes.get("logs", {}).get("status")
    if logs_status and logs_status not in ("collected", "disabled"):
        evidence_gaps.append("kubernetes/logs:{0}".format(logs_status))
        evidence_gap_refs.append("kubernetes.json.gz#logs")
    if evidence_gaps:
        has_truncated_journal = any(
            value.endswith(":truncated") and "/journal_" in value for value in evidence_gaps
        )
        gap_recommendation = (
            "Для усечённых журналов повторить сбор с большим `collection.max_command_bytes` либо меньшим "
            "`collection.since_hours`. До повторного сбора проверки, которым нужны эти журналы, считать неполными."
            if has_truncated_journal
            else "Устранить указанную ошибку доступа/совместимости и повторить сбор; зависимые проверки пока считать неполными."
        )
        findings.append(
            _finding(
                "collector.evidence_gap",
                "warning",
                "Часть обязательных данных собрана не полностью",
                _collection_gap_summary(evidence_gaps),
                sorted(set(value.split("/", 1)[0] for value in evidence_gaps)),
                evidence_gap_refs,
                gap_recommendation,
                causal_confidence="none",
                classification="fact",
            )
        )

    if (normalized or {}).get("stats", {}).get("truncated"):
        stats = normalized["stats"]
        findings.append(
            _finding(
                "collector.normalization_truncated",
                "warning",
                "Нормализация evidence была усечена",
                "Отброшено записей: {0}; candidate limit: {1}; output limit: {2}; по источникам: {3}.".format(
                    stats.get("dropped_records", 0),
                    stats.get("candidate_limit_drops", 0),
                    stats.get("output_limit_drops", 0),
                    stats.get("dropped_by_source", {}),
                ),
                ["cluster"],
                ["normalized-events.json.gz#stats"],
                "Увеличить лимиты только после оценки объёма или сузить окно сбора; зависимые выводы считать неполными.",
                causal_confidence="none",
                classification="fact",
                missing_checks=["events omitted by normalization limits"],
            )
        )

    if _source_collected(kubernetes, "nodes"):
        kubernetes_nodes = _kube_items(kubernetes, "nodes")
        node_matches = match_node_identities(node_snapshots, kubernetes_nodes)
        kubernetes_names = {
            (item.get("metadata") or {}).get("name")
            for item in kubernetes_nodes
            if (item.get("metadata") or {}).get("name")
        }
        missing_snapshots = sorted(kubernetes_names - set(node_matches.values()))
        missing_objects = sorted(set(node_snapshots) - set(node_matches))
        if missing_snapshots or missing_objects:
            findings.append(
                _finding(
                    "inventory.node_set_mismatch",
                    "warning",
                    "Inventory и Kubernetes Node objects не совпадают",
                    "Без node snapshot: {0}; без Kubernetes Node object: {1}.".format(
                        ", ".join(missing_snapshots) or "none", ", ".join(missing_objects) or "none"
                    ),
                    missing_snapshots + missing_objects,
                    ["collection.json#nodes", "kubernetes.json.gz#sources.nodes"],
                    "Сверить inventory aliases, состав кластера и доступность SSH; не считать отсутствующий snapshot здоровым узлом.",
                    causal_confidence="none",
                    classification="fact",
                )
            )

    kernels = {}
    for name, snapshot in node_snapshots.items():
        kernel = snapshot.get("host", {}).get("kernel_release") or "unknown"
        kernels.setdefault(kernel, []).append(name)
    if len(kernels) > 1:
        summary = "; ".join("{0}: {1}".format(kernel, ", ".join(sorted(hosts))) for kernel, hosts in sorted(kernels.items()))
        findings.append(
            _finding(
                "inventory.mixed_kernel",
                "info",
                "На узлах используются разные ядра",
                summary,
                list(node_snapshots),
                ["node-{0}.json.gz#host.kernel_release".format(name) for name in node_snapshots],
                "Сравнивать ошибки по однородным peer groups; не считать разницу ядра первопричиной без механистических evidence.",
                causal_confidence="none",
            )
        )

    boot_changed = [name for name, snapshot in node_snapshots.items() if snapshot.get("facts", {}).get("boot_changed_during_collection")]
    if boot_changed:
        findings.append(
            _finding(
                "collector.boot_changed",
                "warning",
                "Узел перезагрузился во время сбора",
                "Начало и конец snapshot относятся к разным boot ID; единым состоянием такой snapshot считать нельзя.",
                boot_changed,
                ["node-{0}.json.gz#facts.boot_id_start".format(name) for name in boot_changed],
                "Повторить snapshot после стабилизации узла, сохранив текущий bundle для timeline.",
                causal_confidence="none",
            )
        )

    low_disk = []
    for name, snapshot in node_snapshots.items():
        disk = snapshot.get("facts", {}).get("root_disk", {})
        total = disk.get("total_bytes") or 0
        free = disk.get("free_bytes") or 0
        if total and free / total < 0.10:
            low_disk.append(name)
    if low_disk:
        findings.append(
            _finding(
                "node.low_root_disk",
                "warning",
                "На узле мало свободного места",
                "Свободно менее 10% корневой файловой системы.",
                low_disk,
                ["node-{0}.json.gz#facts.root_disk".format(name) for name in low_disk],
                "Проверить disk/inode pressure и удалить данные только по утверждённой эксплуатационной процедуре.",
                causal_confidence="medium",
            )
        )

    low_inodes = {}
    for name, snapshot in node_snapshots.items():
        mounts = _low_inode_mounts(snapshot)
        if mounts:
            low_inodes[name] = mounts
    if low_inodes:
        findings.append(
            _finding(
                "node.low_inodes",
                "warning",
                "На файловой системе заканчиваются inode",
                "; ".join("{0}: {1}".format(name, ", ".join(mounts)) for name, mounts in sorted(low_inodes.items())),
                list(low_inodes),
                ["node-{0}.json.gz#commands.df_inodes".format(name) for name in low_inodes],
                "Определить каталоги с большим числом файлов; не удалять данные автоматически и проверить Node DiskPressure.",
                causal_confidence="high",
                classification="fact",
            )
        )

    kubelet_bad = []
    for name, snapshot in node_snapshots.items():
        state = snapshot.get("facts", {}).get("service_states", {}).get("kubelet.service", {})
        properties = state.get("properties", {})
        if (
            state.get("status") == "collected"
            and properties.get("LoadState") in (None, "loaded")
            and properties.get("ActiveState") not in ACTIVE_SERVICE_STATES
        ):
            kubelet_bad.append(name)
    if kubelet_bad:
        findings.append(
            _finding(
                "node.kubelet_inactive",
                "critical",
                "kubelet не активен",
                "systemd сообщает, что kubelet не находится в active/activating state.",
                kubelet_bad,
                ["node-{0}.json.gz#facts.service_states.kubelet.service".format(name) for name in kubelet_bad],
                "Изучить kubelet journal, runtime/cgroup evidence и точный ExecMainStatus; не перезапускать сервис автоматически.",
                causal_confidence="high",
                alternatives=["ошибка runtime", "cgroup/systemd delegation", "сертификаты", "ресурсы узла"],
            )
        )

    runtime_bad = []
    for name, snapshot in node_snapshots.items():
        states = snapshot.get("facts", {}).get("service_states", {})
        loaded_runtimes = loaded_runtime_service_states(states)
        if loaded_runtimes and not any(runtime_service_is_active(state) for state in loaded_runtimes.values()):
            runtime_bad.append(name)
    if runtime_bad:
        findings.append(
            _finding(
                "node.runtime_inactive",
                "critical",
                "Container runtime не активен",
                "Ни один загруженный containerd, Deckhouse containerd или CRI-O service не находится в active/activating state.",
                runtime_bad,
                ["node-{0}.json.gz#facts.service_states".format(name) for name in runtime_bad],
                "Проверить runtime journal, CRI socket, cgroup driver и storage; автоматический restart не выполнять.",
                causal_confidence="high",
                alternatives=["ошибка конфигурации runtime", "cgroup", "storage", "security agent"],
                classification="fact",
            )
        )

    node_not_ready = _events(normalized, "node_not_ready")
    if node_not_ready:
        findings.append(
            _event_finding(
                "kubernetes.node_not_ready",
                "critical",
                "Kubernetes Node не Ready",
                "Ready=False означает нездоровый узел; Ready=Unknown означает отсутствие heartbeat. Это симптом, а не установленная первопричина.",
                node_not_ready,
                "Сопоставить condition reason/time с kubelet, runtime, CNI, pressure и связью до API.",
                confidence="high",
                alternatives=["kubelet", "runtime", "CNI", "ресурсы", "связь Node—API"],
                classification="fact",
            )
        )

    pressure_events = []
    for category in ("memory_pressure", "disk_pressure", "pid_pressure"):
        pressure_events.extend(_events(normalized, category))
    if pressure_events:
        categories = {}
        for event in pressure_events:
            for category in set(event.get("categories", ())) & {"memory_pressure", "disk_pressure", "pid_pressure"}:
                categories[category] = categories.get(category, 0) + 1
        findings.append(
            _event_finding(
                "kubernetes.node_pressure",
                "critical",
                "Kubernetes сообщает о resource pressure",
                "Активные Node conditions: {0}.".format(categories),
                pressure_events,
                "Проверить соответствующие eviction signals и фактический потребитель; PDB не защищает от node-pressure eviction.",
                confidence="high",
                classification="fact",
            )
        )

    network_unavailable = _events(normalized, "network_unavailable")
    if network_unavailable:
        findings.append(
            _event_finding(
                "kubernetes.network_unavailable",
                "critical",
                "Node condition NetworkUnavailable=True",
                "Kubernetes сообщает, что сеть узла настроена некорректно.",
                network_unavailable,
                "Проверить Cilium agent/status, маршруты, link state и связь между узлами.",
                confidence="high",
                classification="fact",
            )
        )

    crash_loops = _events(normalized, "crash_loop", {"kubernetes_container_state", "kubernetes_event"})
    if crash_loops:
        findings.append(
            _event_finding(
                "kubernetes.pod_crash_loop",
                "warning",
                "Контейнеры находятся в CrashLoopBackOff",
                "Обнаружено состояний/событий: {0}.".format(len(crash_loops)),
                crash_loops,
                "Проверить current/previous container logs, exit code, OOM и зависимости приложения.",
                confidence="high",
                classification="fact",
            )
        )

    image_pull = _events(normalized, "image_pull")
    if image_pull:
        findings.append(
            _event_finding(
                "kubernetes.image_pull_failure",
                "warning",
                "Kubernetes не может получить container image",
                "Обнаружено состояний/событий: {0}.".format(len(image_pull)),
                image_pull,
                "Проверить registry/DNS/TLS, наличие image и imagePullSecret вручную; содержимое Secret не собирается.",
                confidence="high",
                classification="fact",
            )
        )

    pod_oom = _events(normalized, "oom_kill", {"kubernetes_container_state"})
    if pod_oom:
        findings.append(
            _event_finding(
                "kubernetes.pod_oom_killed",
                "critical",
                "Контейнер завершён по OOM",
                "Container state/lastState содержит OOMKilled.",
                pod_oom,
                "Сопоставить memory limit/request, Node MemoryPressure, PSI и kernel OOM records.",
                confidence="high",
                classification="fact",
            )
        )

    scheduling = _events(normalized, "failed_scheduling")
    if scheduling:
        findings.append(
            _event_finding(
                "kubernetes.failed_scheduling",
                "warning",
                "Pods не могут быть запланированы",
                "Обнаружено FailedScheduling событий: {0}.".format(len(scheduling)),
                scheduling,
                "Разобрать message по resources, taints/tolerations, affinity, PVC и topology; не считать любой Pending нехваткой CPU.",
                confidence="high",
                classification="fact",
            )
        )

    degraded_workloads = []
    degraded_evidence = []
    for index, workload in enumerate(_kube_items(kubernetes, "workloads")):
        kind = workload.get("kind")
        spec, status = workload.get("spec", {}), workload.get("status", {})
        if kind == "Deployment":
            desired = spec.get("replicas") if spec.get("replicas") is not None else 1
            ready = status.get("readyReplicas") or 0
            degraded = ready < desired
        elif kind == "StatefulSet":
            desired = spec.get("replicas") if spec.get("replicas") is not None else 1
            ready = status.get("readyReplicas") or 0
            degraded = any(
                str(condition.get("status")) == "True"
                and (condition.get("type") in ("ReplicaFailure", "Failed") or "fail" in str(condition.get("reason") or "").lower())
                for condition in status.get("conditions", []) or []
            )
        elif kind == "DaemonSet":
            desired = status.get("desiredNumberScheduled") or 0
            ready = status.get("numberReady") or 0
            degraded = desired > 0 and ready < desired
        elif kind == "Job":
            desired = None
            ready = None
            degraded = any(
                condition.get("type") == "Failed" and str(condition.get("status")) == "True"
                for condition in status.get("conditions", []) or []
            )
        else:
            degraded = False
        if degraded:
            metadata = workload.get("metadata", {})
            degraded_workloads.append("{0}/{1}/{2}".format(metadata.get("namespace"), kind, metadata.get("name")))
            degraded_evidence.append("kubernetes.json.gz#sources.workloads.items[{0}]".format(index))
    if degraded_workloads:
        findings.append(
            _finding(
                "kubernetes.workload_degraded",
                "warning",
                "Workloads не достигли desired state",
                "Затронуто: {0}.".format(", ".join(degraded_workloads[:50])),
                degraded_workloads,
                degraded_evidence,
                "Сопоставить Pods и Events соответствующего workload; snapshot не выполняет rollout/restart.",
                causal_confidence="high",
                classification="fact",
                missing_checks=["Pods and Events are required to determine the rollout failure mechanism"],
            )
        )

    disabled_ipv6 = []
    for name, snapshot in node_snapshots.items():
        values = snapshot.get("facts", {}).get("ipv6_disable", {})
        if str(values.get("all")) == "1" or str(values.get("default")) == "1":
            disabled_ipv6.append(name)
    pod_ipv6 = []
    pod_ipv6_on_disabled = []
    for pod in _kube_items(kubernetes, "pods"):
        for address in pod.get("status", {}).get("podIPs", []) or []:
            ip = address.get("ip") if isinstance(address, dict) else None
            if ip and ":" in ip:
                pod_name = "{0}/{1}".format(pod.get("metadata", {}).get("namespace"), pod.get("metadata", {}).get("name"))
                pod_ipv6.append(pod_name)
                if pod.get("spec", {}).get("nodeName") in disabled_ipv6:
                    pod_ipv6_on_disabled.append(pod_name)
                break
    probe_events = []
    probe_classes = {}
    for event in _kube_items(kubernetes, "events"):
        message = event.get("note", "")
        reason = str(event.get("reason") or "")
        if reason.lower() == "unhealthy" or "readiness probe" in message.lower() or "liveness probe" in message.lower():
            probe_events.append(event)
            category = _classify_probe_message(message)
            probe_classes[category] = probe_classes.get(category, 0) + 1
    normalized_probe_events = _events(normalized, "probe_failure")
    if normalized_probe_events:
        probe_events = normalized_probe_events
        probe_classes = {}
        taxonomy = ("address_family", "no_route", "connection_refused", "timeout", "dns_error", "certificate_error")
        for event in normalized_probe_events:
            matched = [category for category in taxonomy if category in event.get("categories", [])] or ["other"]
            for category in matched:
                probe_classes[category] = probe_classes.get(category, 0) + 1
    if disabled_ipv6:
        address_family_nodes = set(
            event.get("node") for event in _events(normalized, "address_family") if event.get("node")
        )
        mechanistic_error = bool(address_family_nodes & set(disabled_ipv6))
        linked = mechanistic_error or bool(pod_ipv6)
        if not linked:
            disabled_ipv6 = []
    if disabled_ipv6:
        findings.append(
            _finding(
                "network.ipv6_disabled",
                "critical" if mechanistic_error else "warning",
                "На узлах отключён IPv6",
                "disable_ipv6=1 обнаружен на {0}; IPv6 Pod всего: {1}; на этих узлах: {2}; классы probe errors: {3}.".format(
                    ", ".join(sorted(disabled_ipv6)), len(pod_ipv6), len(pod_ipv6_on_disabled), probe_classes
                ),
                disabled_ipv6,
                ["node-{0}.json.gz#facts.ipv6_disable".format(name) for name in disabled_ipv6]
                + (["kubernetes.json.gz#sources.pods"] if pod_ipv6 else [])
                + [event.get("evidence") for event in _events(normalized, "address_family") if event.get("evidence")],
                "Сопоставить effective sysctl с Pod IP family, Cilium routing и точным классом probe error; возвращать baseline только через change procedure.",
                causal_confidence="medium" if linked else "none",
                alternatives=["приложение не слушает порт", "Cilium route/endpoint", "перегрузка", "HTTP error readiness endpoint"],
                counter_evidence=["IPv6 Pod addresses on unaffected nodes: {0}".format(len(pod_ipv6) - len(pod_ipv6_on_disabled))],
                missing_checks=["effective address family and route on the affected workload node"],
                classification="correlation" if mechanistic_error else "fact",
            )
        )
    if probe_events:
        if normalized_probe_events:
            affected_probes = sorted(set(_event_target(event) for event in probe_events))
            probe_evidence = sorted(set(event.get("evidence") for event in probe_events if event.get("evidence")))
        else:
            affected_probes = sorted(set((event.get("regarding") or {}).get("name") or "unknown" for event in probe_events))
            probe_evidence = ["kubernetes.json.gz#sources.events"]
        findings.append(
            _finding(
                "kubernetes.probe_failures",
                "warning",
                "Kubernetes сообщает об ошибках health probes",
                "Найдено событий: {0}; классификация: {1}.".format(len(probe_events), probe_classes),
                affected_probes,
                probe_evidence,
                "Разбирать timeout/refused/no-route/address-family/DNS/TLS/HTTP отдельно; generic timeout не доказывает проблему IPv6.",
                causal_confidence="medium",
            )
        )

    cni_events = _events(normalized, "cni_unavailable")
    if cni_events:
        findings.append(
            _event_finding(
                "network.cni_unavailable",
                "critical",
                "Обнаружены ошибки CNI/network plugin",
                "Найдено нормализованных событий: {0}; одна строка журнала не устанавливает первопричину.".format(len(cni_events)),
                cni_events,
                "Сопоставить Cilium Pod/status, Node NetworkUnavailable, routes, endpoint health и pod sandbox events.",
                confidence="medium",
                alternatives=["ошибка runtime", "API недоступен", "маршрутизация узла", "Cilium agent"],
                classification="hypothesis",
            )
        )

    cilium_events = _events(normalized, "cilium_unhealthy")
    if cilium_events:
        findings.append(
            _event_finding(
                "cilium.unhealthy",
                "critical",
                "Cilium Pod/container находится в нездоровом состоянии",
                "Обнаружено состояний: {0}.".format(len(cilium_events)),
                cilium_events,
                "Проверить current/previous Cilium logs, cilium status/controllers, endpoint health и connectivity matrix.",
                confidence="high",
                classification="fact",
            )
        )

    node_oom = _events(normalized, "oom_kill", {"journal", "cri_log", "kubernetes_pod_log"})
    if node_oom:
        findings.append(
            _event_finding(
                "node.oom_detected",
                "critical",
                "В журналах обнаружен OOM kill",
                "Найдено сообщений: {0}.".format(len(node_oom)),
                node_oom,
                "Сопоставить killed process/container, cgroup memory limit, Node MemoryPressure и memory PSI.",
                confidence="high",
                classification="fact",
            )
        )

    conntrack_full = _events(normalized, "conntrack_full")
    if conntrack_full:
        findings.append(
            _event_finding(
                "node.conntrack_full",
                "critical",
                "Таблица conntrack переполнена",
                "Kernel/network logs содержат table full.",
                conntrack_full,
                "Проверить nf_conntrack_count/max, характер соединений и Cilium datapath; не увеличивать лимит без оценки RAM.",
                confidence="high",
                classification="fact",
            )
        )

    missing_controllers = []
    cgroup_denials = []
    kaspersky_nodes = []
    kaspersky_packages = {}
    cgroup_denial_excerpts = {}
    for name, snapshot in node_snapshots.items():
        cgroup = snapshot.get("facts", {}).get("cgroup", {})
        controllers = set(cgroup.get("controllers", []))
        if cgroup.get("mode") == "v2" and not {"cpu", "io"}.issubset(controllers):
            missing_controllers.append(name)
        packages = _command(snapshot, "installed_packages").get("stdout", "")
        package_lines = [
            " ".join(line.split())[:500]
            for line in packages.splitlines()
            if "kesl" in line.lower() or "kaspersky" in line.lower()
        ][:5]
        if package_lines:
            kaspersky_nodes.append(name)
            kaspersky_packages[name] = package_lines
        journal = _command(snapshot, "journal_services_current").get("stdout", "") + _command(snapshot, "journal_services_previous").get("stdout", "")
        matched_lines = [" ".join(line.split())[:500] for line in journal.splitlines() if CGROUP_DENIAL_RE.search(line)][:5]
        if matched_lines:
            cgroup_denials.append(name)
            cgroup_denial_excerpts[name] = matched_lines
    if missing_controllers:
        findings.append(
            _finding(
                "cgroup.controllers_missing",
                "warning",
                "В cgroup v2 не видны cpu/io controllers",
                "Отсутствие controller является причиной только при прямой fatal-ошибке kubelet/runtime.",
                missing_controllers,
                ["node-{0}.json.gz#facts.cgroup".format(name) for name in missing_controllers],
                "Проверить kernel config, legacy v1 mounts, systemd delegation, runtime/cgroup driver и process mount namespaces.",
                causal_confidence="low",
                counter_evidence=["Отсутствие controller само по себе не является отказом kubelet/runtime"],
                missing_checks=["fatal kubelet/runtime error for the missing controller", "effective cgroup namespace and delegation"],
                classification="hypothesis",
            )
        )
    driver_mismatches = []
    driver_details = []
    for name, snapshot in node_snapshots.items():
        kubelet_driver = _kubelet_cgroup_driver(snapshot)
        runtime_driver = _runtime_cgroup_driver(snapshot)
        if kubelet_driver and runtime_driver and kubelet_driver != runtime_driver:
            driver_mismatches.append(name)
            driver_details.append("{0}: kubelet={1}, runtime={2}".format(name, kubelet_driver, runtime_driver))
    if driver_mismatches:
        findings.append(
            _finding(
                "cgroup.driver_mismatch",
                "critical",
                "cgroup driver kubelet и runtime не совпадает",
                "; ".join(driver_details),
                driver_mismatches,
                ["node-{0}.json.gz#facts.kubelet_config".format(name) for name in driver_mismatches]
                + ["node-{0}.json.gz#commands.runtime_crictl_info".format(name) for name in driver_mismatches],
                "Проверить effective flags/config обеих сторон; миграцию driver выполнять только по отдельной процедуре с выводом узла.",
                causal_confidence="high",
                classification="fact",
            )
        )
    linked_kaspersky = sorted(set(cgroup_denials) & set(kaspersky_nodes))
    if linked_kaspersky:
        findings.append(
            _finding(
                "security_agent.cgroup_denial",
                "warning",
                "На узле с KESL обнаружен отдельный cgroup access error",
                "; ".join(
                    "{0}: package={1}; journal={2}".format(
                        name,
                        " | ".join(kaspersky_packages.get(name, [])),
                        " | ".join(cgroup_denial_excerpts.get(name, [])),
                    )
                    for name in linked_kaspersky
                ),
                linked_kaspersky,
                ["node-{0}.json.gz#commands.journal_services_current".format(name) for name in linked_kaspersky],
                "Сопоставить точные errno/path с DAC/SELinux/systemd sandboxing и vendor/audit event; сверить exact KESL build и compatibility matrix.",
                causal_confidence="medium",
                alternatives=["DAC/ACL", "SELinux/LSM", "systemd hardening", "cgroup driver mismatch", "kernel/runtime incompatibility"],
                counter_evidence=["Совместное присутствие package и denial не устанавливает инициатора блокировки"],
                missing_checks=["matched KESL audit event", "vendor compatibility for the exact package build"],
                classification="correlation",
            )
        )

    time_unsynchronized = []
    time_evidence = []
    for name, snapshot in node_snapshots.items():
        timedatectl = _command(snapshot, "timedatectl")
        chrony = _command(snapshot, "chrony_tracking")
        timedatectl_text = timedatectl.get("stdout", "")
        chrony_text = chrony.get("stdout", "")
        not_synchronized = "NTPSynchronized=no" in timedatectl_text or re.search(
            r"leap status\s*:\s*not synchroni[sz]ed", chrony_text, re.I
        )
        if not_synchronized:
            time_unsynchronized.append(name)
            if "NTPSynchronized=no" in timedatectl_text:
                time_evidence.append("node-{0}.json.gz#commands.timedatectl".format(name))
            if chrony_text:
                time_evidence.append("node-{0}.json.gz#commands.chrony_tracking".format(name))
    if time_unsynchronized:
        findings.append(
            _finding(
                "time.not_synchronized",
                "warning",
                "На узле не синхронизировано время",
                "timedatectl или chrony явно сообщает отсутствие синхронизации.",
                time_unsynchronized,
                time_evidence,
                "Проверить источник времени, reachability и offset; не менять время автоматически во время расследования.",
                causal_confidence="high",
                classification="fact",
            )
        )

    reference_time = _parse_snapshot_time(collection.get("ended_at"))
    expiring = {}
    expired = {}
    certificate_evidence = []
    if reference_time:
        for name, snapshot in node_snapshots.items():
            rotation_target = snapshot.get("facts", {}).get("kubelet_certificate_rotation", {}).get("target")
            for index, certificate in enumerate(snapshot.get("facts", {}).get("certificates", [])):
                path = str(certificate.get("path") or "")
                basename = path.rsplit("/", 1)[-1]
                if (
                    path.startswith("/var/lib/kubelet/pki/")
                    and re.match(r"^kubelet-client-.*\.pem$", basename)
                    and basename != rotation_target
                ):
                    continue
                not_after = _parse_certificate_date(certificate.get("metadata"))
                if not not_after:
                    continue
                days = (not_after - reference_time).total_seconds() / 86400.0
                if days < 0:
                    expired.setdefault(name, []).append(path)
                elif days <= 30:
                    expiring.setdefault(name, []).append((path, int(days)))
                else:
                    continue
                certificate_evidence.append("node-{0}.json.gz#facts.certificates[{1}]".format(name, index))
    if expired or expiring:
        details = []
        for name, paths in sorted(expired.items()):
            details.append("{0}: expired {1}".format(name, ", ".join(str(path) for path in paths)))
        for name, paths in sorted(expiring.items()):
            details.append("{0}: expiring {1}".format(name, ", ".join("{0} ({1}d)".format(path, days) for path, days in paths)))
        findings.append(
            _finding(
                "certificate.expiring",
                "critical" if expired else "warning",
                "Сертификаты истекли или скоро истекут",
                "; ".join(details),
                sorted(set(expired) | set(expiring)),
                certificate_evidence,
                "Определить владельца и процедуру ротации сертификата; не заменять файлы автоматически.",
                causal_confidence="high",
                classification="fact",
            )
        )

    findings.extend(_npd_findings(normalized))
    findings.extend(_service_dns_findings(node_snapshots, kubernetes))
    findings.extend(_controlplane_etcd_findings(collection, node_snapshots, kubernetes))
    findings.extend(_storage_cilium_findings(kubernetes))
    findings.extend(_pdb_findings(kubernetes))
    findings.extend(_pod_workload_findings(collection, kubernetes))
    findings.extend(_runtime_and_inventory_findings(collection, node_snapshots, kubernetes))
    findings.extend(_cilium_dns_dataplane_findings(node_snapshots, kubernetes, normalized))
    findings.extend(_prometheus_findings(prometheus))

    volume_events = _events(normalized, "volume_error")
    if volume_events:
        findings.append(_event_finding("storage.volume_operation_failure", "warning", "Kubernetes сообщает об ошибках mount/attach volume", "Найдено событий: {0}.".format(len(volume_events)), volume_events, "Сопоставить Pod, PVC/PV, VolumeAttachment и CSI node/controller logs.", confidence="high", classification="fact"))

    auth_config_events = _events(normalized, "authentication_config_read_error")
    auth_config_occurrences = sum(int(event.get("occurrence_count") or 1) for event in auth_config_events)
    if auth_config_occurrences > 1:
        context = _authentication_config_context(node_snapshots, kubernetes, auth_config_events)
        if not context["current_healthy"]:
            finding = _event_finding(
                "controlplane.authentication_config_read_error",
                "warning",
                "В журнале kube-apiserver повторяется ошибка чтения authentication config",
                "Обнаружено повторяющихся записей: {0}. Текущее исправное состояние файла, readyz и Pod kube-apiserver одновременно не подтверждено.".format(auth_config_occurrences),
                auth_config_events,
                "Проверить фактический флаг authentication-config, наличие и mount файла внутри kube-apiserver, затем Deckhouse reconciliation вокруг первой/последней записи; не создавать пустой файл.",
                confidence="none",
                alternatives=[
                    "краткое окно атомарной замены файла",
                    "файл существует на host, но временно не виден в mount namespace контейнера",
                    "устаревший flag или mount после reconciliation",
                ],
                classification="fact",
            )
            finding["counter_evidence"] = context["counter_evidence"][:20]
            finding["missing_checks"] = context["missing_checks"][:20]
            findings.append(finding)

    ptrace_events = _events(normalized, "ptrace_security_alert", {"journal"})
    if ptrace_events:
        findings.append(
            _event_finding(
                "security_agent.ptrace_alert",
                "warning",
                "Kernel/security agent зарегистрировал ptrace alert",
                "Обнаружено ptrace attack messages: {0}; запись не устанавливает вредоносность процесса и не доказывает влияние на Kubernetes.".format(len(ptrace_events)),
                ptrace_events,
                "Зафиксировать обе программы, PID, решение security agent и соседние audit/KESL events; проверить policy и совместимость точных builds до изменения исключений.",
                confidence="none",
                alternatives=["легитимное взаимодействие двух security/backup agents", "защитная блокировка без влияния на workload"],
                classification="fact",
            )
        )

    correlation_rules = {
        "node_runtime_failure": (
            "correlation.node_runtime_failure",
            "critical",
            "Node NotReady связан по времени с kubelet/runtime failure",
            "Проверить systemd и runtime journal вокруг указанного окна; корреляция не определяет исходную причину отказа runtime.",
        ),
        "node_cni_failure": (
            "correlation.node_cni_failure",
            "critical",
            "Node/Pod failure связан по времени с CNI failure",
            "Проверить Cilium status, pod sandbox events, routes и endpoint health на этом узле.",
        ),
        "probe_network_failure": (
            "correlation.probe_network_failure",
            "warning",
            "Probe failure связан по времени с сетевой/DNS ошибкой",
            "Разделить refused/no-route/DNS/timeout и проверить Cilium service path; корреляция не доказывает отказ dataplane.",
        ),
        "storage_failure": (
            "correlation.storage_failure",
            "critical",
            "DiskPressure связан по времени с disk/read-only filesystem error",
            "Проверить nodefs/imagefs/runtime mount и источник ENOSPC/EROFS; данные автоматически не удалять.",
        ),
        "memory_oom_failure": (
            "correlation.memory_oom_failure",
            "critical",
            "MemoryPressure связан по времени с OOM",
            "Сопоставить kernel victim, container limits, node allocatable и PSI; не считать любой exit 137 OOM без evidence.",
        ),
        "cgroup_service_failure": (
            "cgroup.service_failure",
            "critical",
            "cgroup access denial связан по времени с отказом kubelet/runtime",
            "Проверить errno/path, mount namespace, systemd delegation, SELinux и security agent; изменение cgroup не выполнять автоматически.",
        ),
        "certificate_api_failure": (
            "correlation.certificate_api_failure",
            "critical",
            "Certificate/TLS error связан по времени с API failure",
            "Проверить notBefore/notAfter, CA chain, hostname и синхронизацию времени.",
        ),
        "conntrack_network_failure": (
            "correlation.conntrack_network_failure",
            "critical",
            "Conntrack overflow связан по времени с network/probe failure",
            "Проверить conntrack count/max, top connection sources и Cilium service paths.",
        ),
    }
    for correlation in (normalized or {}).get("correlations", []):
        definition = correlation_rules.get(correlation.get("correlation_id"))
        if not definition:
            continue
        rule_id, severity, title, recommendation = definition
        finding = _finding(
                rule_id,
                severity,
                title,
                "Категории: {0}; источники: {1}; окно: {2}s.".format(
                    ", ".join(correlation.get("categories", [])),
                    ", ".join(correlation.get("sources", [])),
                    correlation.get("window_seconds"),
                ),
                [correlation.get("scope")],
                correlation.get("evidence", []),
                recommendation,
                causal_confidence="medium",
                classification="correlation",
            )
        finding.update(
            {
                "episode_id": correlation.get("episode_id"),
                "started_at": correlation.get("started_at"),
                "ended_at": correlation.get("ended_at"),
                "duration_seconds": correlation.get("duration_seconds"),
                "window_seconds": correlation.get("window_seconds"),
            }
        )
        findings.append(finding)

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    if collection.get("options", {}).get("collect_cgroup", True) is False:
        findings = [finding for finding in findings if finding.get("rule_id") not in CGROUP_RULE_IDS]
    return sorted(findings, key=lambda item: (severity_order.get(item["severity"], 9), item["rule_id"], item["id"]))
