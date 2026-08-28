import math
from collections import deque
from datetime import timedelta

from kdiag.analysis import parse_utc_timestamp


MAX_GRAPH_NODES = 5000
MAX_GRAPH_EDGES = 10000
RECENT_EVENT_MINUTES = 15
CAUSAL_TIME_TOLERANCE_MINUTES = 15


CONSEQUENCE_RULE_PREFIXES = (
    "kubernetes.pod_",
    "kubernetes.workload_",
    "kubernetes.service_",
    "kubernetes.probe_",
)
CONSEQUENCE_RULES = frozenset(
    (
        "kubernetes.container_exit_nonzero",
        "kubernetes.init_container_failed",
        "kubernetes.job_failed",
        "kubernetes.failed_scheduling",
        "kubernetes.daemonset_misscheduled",
        "kubernetes.deployment_rollout_failed",
        "kubernetes.statefulset_rollout_stalled",
        "controlplane.apiservice_unavailable",
    )
)
CONFIGURATION_RISK_PREFIXES = ("inventory.", "certificate.", "collector.")
CONFIGURATION_RISK_RULES = frozenset(
    (
        "cgroup.controllers_missing",
        "cgroup.driver_mismatch",
        "cilium.kube_proxy_replacement_disabled",
        "dns.coredns_config_empty",
        "network.ipv6_disabled",
        "node.low_inodes",
        "node.low_root_disk",
        "node.low_runtime_disk",
        "node.swap_active",
        "pdb.disruption_blocked",
        "pdb.insufficient_healthy",
        "storage.storage_class_missing",
        "time.not_synchronized",
    )
)


def _analysis_options(collection):
    options = (collection or {}).get("options", {}) or {}
    return {
        "purpose": options.get("purpose") or "check",
        "incident_start": options.get("incident_start"),
        "incident_end": options.get("incident_end"),
    }


def _finding_role(rule_id):
    if rule_id in CONSEQUENCE_RULES or rule_id.startswith(CONSEQUENCE_RULE_PREFIXES):
        return "consequence"
    if rule_id in CONFIGURATION_RISK_RULES or rule_id.startswith(CONFIGURATION_RISK_PREFIXES):
        return "configuration_risk"
    return "possible_cause"


def _is_current_evidence(reference):
    text = str(reference or "")
    if (
        ":line-" in text
        or "#events" in text
        or "#logs" in text
        or "#sources.events" in text
        or "#sources.logs" in text
        or "/logs/" in text
    ):
        return False
    if "journal_" in text or "pod_logs" in text or "normalized-events" in text:
        return False
    return any(
        marker in text
        for marker in (
            "#facts.",
            "#commands.",
            "#sources.",
            "collection.json#",
            "prometheus.json.gz#sources.",
            "kubernetes.json.gz#sources.",
        )
    )


def _safe_time(value, label):
    if not value:
        return None
    try:
        return parse_utc_timestamp(value, label)
    except ValueError:
        return None


def _finding_activity_status(finding, collection):
    evidence = finding.get("evidence") or []
    if any(_is_current_evidence(value) for value in evidence):
        return "active"

    ended = _safe_time(finding.get("ended_at"), "finding end")
    options = _analysis_options(collection)
    if options["purpose"] == "incident":
        start = _safe_time(options.get("incident_start"), "incident start")
        end = _safe_time(options.get("incident_end"), "incident end")
        if ended and start and ended < start:
            return "resolved"
        if ended and end and ended > end:
            return "unknown"
        return "unknown"

    collected = _safe_time((collection or {}).get("ended_at"), "collection end")
    if ended and collected and ended <= collected - timedelta(minutes=RECENT_EVENT_MINUTES):
        return "resolved"
    return "unknown"


def annotate_findings(findings, collection):
    """Add operator-facing lifecycle state and causal role without changing rule matching."""
    result = []
    for source in findings or []:
        finding = dict(source)
        finding["evaluation_status"] = source.get("evaluation_status") or source.get("finding_status") or "matched"
        finding["finding_status"] = _finding_activity_status(finding, collection)
        finding["finding_role"] = _finding_role(str(finding.get("rule_id") or ""))
        result.append(finding)
    return result


class _GraphBuilder:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.truncated = False

    def node(self, node_id, kind, label, **attributes):
        if not node_id:
            return None
        if node_id not in self.nodes:
            if len(self.nodes) >= MAX_GRAPH_NODES:
                self.truncated = True
                return None
            value = {"id": node_id, "kind": kind, "label": label}
            value.update({key: item for key, item in attributes.items() if item is not None})
            self.nodes[node_id] = value
        return node_id

    def edge(self, source, target, relation, **attributes):
        if not source or not target or source == target:
            return
        if source not in self.nodes or target not in self.nodes:
            return
        key = (source, target, relation)
        if key in self.edges:
            return
        if len(self.edges) >= MAX_GRAPH_EDGES:
            self.truncated = True
            return
        value = {"source": source, "target": target, "relation": relation}
        value.update({key: item for key, item in attributes.items() if item is not None})
        self.edges[key] = value

    def document(self):
        return {
            "nodes": sorted(self.nodes.values(), key=lambda item: item["id"]),
            "edges": sorted(self.edges.values(), key=lambda item: (item["source"], item["target"], item["relation"])),
            "truncated": self.truncated,
        }


def _items(kubernetes, source_id):
    return (((kubernetes or {}).get("sources", {}).get(source_id, {}) or {}).get("data", {}) or {}).get("items", []) or []


def _object_name(item):
    metadata = item.get("metadata", {}) or {}
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if not name:
        return None
    return "{0}/{1}".format(namespace, name) if namespace else str(name)


def _add_kubernetes_topology(graph, kubernetes):
    object_targets = {}

    for item in _items(kubernetes, "nodes"):
        name = _object_name(item)
        node_id = graph.node("node:{0}".format(name), "node", name) if name else None
        if node_id:
            object_targets.setdefault(name, set()).add(node_id)

    workloads = {}
    workload_owner_links = []
    for item in _items(kubernetes, "workloads"):
        name = _object_name(item)
        kind = item.get("kind") or "Workload"
        if not name:
            continue
        node_id = graph.node("workload:{0}:{1}".format(kind, name), "workload", "{0} {1}".format(kind, name), resource_kind=kind)
        workloads[(kind.lower(), name)] = node_id
        object_targets.setdefault(name, set()).add(node_id)
        namespace = (item.get("metadata", {}) or {}).get("namespace") or "default"
        for owner in (item.get("metadata", {}) or {}).get("ownerReferences", []) or []:
            if owner.get("kind") and owner.get("name"):
                workload_owner_links.append(
                    (node_id, str(owner["kind"]), "{0}/{1}".format(namespace, owner["name"]))
                )
    for child_id, owner_kind, owner_name in workload_owner_links:
        owner_id = workloads.get((owner_kind.lower(), owner_name))
        if not owner_id:
            owner_id = graph.node(
                "workload:{0}:{1}".format(owner_kind, owner_name),
                "workload",
                "{0} {1}".format(owner_kind, owner_name),
                resource_kind=owner_kind,
            )
        object_targets.setdefault(owner_name, set()).add(owner_id)
        graph.edge(child_id, owner_id, "member_of")

    pods = {}
    pod_claims = []
    for item in _items(kubernetes, "pods"):
        name = _object_name(item)
        if not name:
            continue
        metadata = item.get("metadata", {}) or {}
        namespace = metadata.get("namespace") or "default"
        spec = item.get("spec", {}) or {}
        pod_id = graph.node("pod:{0}".format(name), "pod", name, namespace=namespace)
        pods[name] = pod_id
        object_targets.setdefault(name, set()).add(pod_id)
        node_name = spec.get("nodeName")
        if node_name:
            node_id = graph.node("node:{0}".format(node_name), "node", node_name)
            object_targets.setdefault(str(node_name), set()).add(node_id)
            graph.edge(node_id, pod_id, "hosts")
        for owner in metadata.get("ownerReferences", []) or []:
            owner_kind = str(owner.get("kind") or "Workload")
            owner_name = owner.get("name")
            if not owner_name:
                continue
            namespaced_name = "{0}/{1}".format(namespace, owner_name)
            workload_id = workloads.get((owner_kind.lower(), namespaced_name))
            if not workload_id:
                workload_id = graph.node(
                    "workload:{0}:{1}".format(owner_kind, namespaced_name),
                    "workload",
                    "{0} {1}".format(owner_kind, namespaced_name),
                    resource_kind=owner_kind,
                )
            object_targets.setdefault(namespaced_name, set()).add(workload_id)
            graph.edge(pod_id, workload_id, "member_of")
        for claim_name in spec.get("persistentVolumeClaims", []) or []:
            pod_claims.append((pod_id, "{0}/{1}".format(namespace, claim_name)))

    services = {}
    for item in _items(kubernetes, "services"):
        name = _object_name(item)
        if not name:
            continue
        service_id = graph.node("service:{0}".format(name), "service", name)
        services[name] = service_id
        object_targets.setdefault(name, set()).add(service_id)

    for item in _items(kubernetes, "endpoint_slices"):
        name = _object_name(item)
        if not name:
            continue
        metadata = item.get("metadata", {}) or {}
        namespace = metadata.get("namespace") or "default"
        slice_id = graph.node("endpoint_slice:{0}".format(name), "endpoint_slice", name)
        object_targets.setdefault(name, set()).add(slice_id)
        for endpoint in item.get("endpoints", []) or []:
            target = endpoint.get("targetRef", {}) or {}
            if str(target.get("kind") or "").lower() != "pod" or not target.get("name"):
                continue
            pod_name = "{0}/{1}".format(target.get("namespace") or namespace, target["name"])
            pod_id = pods.get(pod_name) or graph.node("pod:{0}".format(pod_name), "pod", pod_name)
            object_targets.setdefault(pod_name, set()).add(pod_id)
            graph.edge(pod_id, slice_id, "backend_of")
        service_name = (metadata.get("labels", {}) or {}).get("kubernetes.io/service-name")
        if service_name:
            namespaced_name = "{0}/{1}".format(namespace, service_name)
            service_id = services.get(namespaced_name) or graph.node("service:{0}".format(namespaced_name), "service", namespaced_name)
            object_targets.setdefault(namespaced_name, set()).add(service_id)
            graph.edge(slice_id, service_id, "serves")

    pvc_to_pv = {}
    for item in _items(kubernetes, "pvc"):
        name = _object_name(item)
        if not name:
            continue
        pvc_id = graph.node("pvc:{0}".format(name), "pvc", name)
        object_targets.setdefault(name, set()).add(pvc_id)
        volume_name = (item.get("spec", {}) or {}).get("volumeName")
        if volume_name:
            pvc_to_pv[name] = volume_name
    for pod_id, claim_name in pod_claims:
        pvc_id = graph.node("pvc:{0}".format(claim_name), "pvc", claim_name)
        object_targets.setdefault(claim_name, set()).add(pvc_id)
        graph.edge(pvc_id, pod_id, "used_by")

    pv_nodes = {}
    for item in _items(kubernetes, "pv"):
        name = _object_name(item)
        if not name:
            continue
        pv_id = graph.node("pv:{0}".format(name), "pv", name)
        pv_nodes[name] = pv_id
        object_targets.setdefault(name, set()).add(pv_id)
        driver = ((item.get("spec", {}) or {}).get("csi", {}) or {}).get("driver")
        if driver:
            csi_id = graph.node("csi:{0}".format(driver), "csi_driver", driver)
            object_targets.setdefault(str(driver), set()).add(csi_id)
            graph.edge(csi_id, pv_id, "provisions")
    for claim_name, volume_name in pvc_to_pv.items():
        pv_id = pv_nodes.get(volume_name) or graph.node("pv:{0}".format(volume_name), "pv", volume_name)
        pvc_id = graph.node("pvc:{0}".format(claim_name), "pvc", claim_name)
        graph.edge(pv_id, pvc_id, "binds")

    for item in _items(kubernetes, "volume_attachments"):
        name = _object_name(item)
        spec = item.get("spec", {}) or {}
        if not name:
            continue
        attachment_id = graph.node("volume_attachment:{0}".format(name), "volume_attachment", name)
        object_targets.setdefault(name, set()).add(attachment_id)
        pv_name = (spec.get("source", {}) or {}).get("persistentVolumeName")
        if pv_name:
            pv_id = pv_nodes.get(pv_name) or graph.node("pv:{0}".format(pv_name), "pv", pv_name)
            graph.edge(pv_id, attachment_id, "attaches_as")
        node_name = spec.get("nodeName")
        if node_name:
            node_id = graph.node("node:{0}".format(node_name), "node", node_name)
            object_targets.setdefault(str(node_name), set()).add(node_id)
            graph.edge(attachment_id, node_id, "attaches_to")

    component_ids = {
        "etcd": graph.node("component:etcd", "component", "etcd"),
        "kube_apiserver": graph.node("component:kube-apiserver", "component", "kube-apiserver"),
        "container_runtime": graph.node("component:container-runtime", "component", "container runtime"),
        "cilium": graph.node("component:cilium", "component", "Cilium/CNI"),
        "dns": graph.node("component:dns", "component", "cluster DNS"),
    }
    graph.edge(component_ids["etcd"], component_ids["kube_apiserver"], "serves")
    for node_id, node in list(graph.nodes.items()):
        if node.get("kind") != "node":
            continue
        graph.edge(component_ids["kube_apiserver"], node_id, "controls")
        graph.edge(component_ids["container_runtime"], node_id, "provides_runtime_to")
        graph.edge(component_ids["cilium"], node_id, "provides_network_to")
    for namespaced_name, service_id in services.items():
        if "kube-dns" in namespaced_name or "coredns" in namespaced_name:
            graph.edge(component_ids["dns"], service_id, "provides_dns_as")
    for key, node_id in component_ids.items():
        object_targets["@component:{0}".format(key)] = {node_id}

    return object_targets


def _finding_targets(finding, object_targets):
    targets = set()
    for value in finding.get("affected", []) or []:
        text = str(value)
        targets.update(object_targets.get(text, ()))
        if "/" in text:
            targets.update(object_targets.get(text.split("/", 1)[1], ()))
    rule_id = str(finding.get("rule_id") or "")
    component_key = None
    for prefix, key in (
        ("etcd.", "etcd"),
        ("controlplane.", "kube_apiserver"),
        ("runtime.", "container_runtime"),
        ("cilium.", "cilium"),
        ("network.cni_", "cilium"),
        ("dns.", "dns"),
    ):
        if rule_id.startswith(prefix):
            component_key = key
            break
    if component_key and not targets:
        targets.update(object_targets.get("@component:{0}".format(component_key), ()))
    return targets


def _reachable(adjacency, starts, maximum_depth=6):
    found = set(starts)
    queue = deque((item, 0) for item in starts)
    while queue:
        current, depth = queue.popleft()
        if depth >= maximum_depth:
            continue
        for target in adjacency.get(current, ()):
            if target in found:
                continue
            found.add(target)
            queue.append((target, depth + 1))
    return found


def _temporally_compatible(cause, consequence):
    cause_started = _safe_time(cause.get("started_at"), "cause start")
    consequence_ended = _safe_time(consequence.get("ended_at"), "consequence end")
    if cause_started is None or consequence_ended is None:
        return True
    return cause_started <= consequence_ended + timedelta(minutes=CAUSAL_TIME_TOLERANCE_MINUTES)


def _metric_signals(prometheus):
    result = []
    for source_id, source in sorted(((prometheus or {}).get("sources", {}) or {}).items()):
        if not source_id.startswith("range_") or source.get("status") != "collected":
            continue
        data = source.get("data", {}) or {}
        samples = []
        for series in data.get("series", []) or []:
            for sample in series.get("values", []) or []:
                if not isinstance(sample, list) or len(sample) != 2:
                    continue
                try:
                    timestamp = float(sample[0])
                    value = float(sample[1])
                except (TypeError, ValueError):
                    continue
                if math.isfinite(timestamp) and math.isfinite(value):
                    samples.append((timestamp, value))
        samples.sort()
        if not samples:
            continue
        minimum = min(samples, key=lambda item: item[1])
        maximum = max(samples, key=lambda item: item[1])
        first = samples[0]
        last = samples[-1]
        delta = last[1] - first[1]
        if math.isclose(delta, 0.0, abs_tol=max(1e-12, abs(first[1]) * 0.01)):
            trend = "stable"
        else:
            trend = "rising" if delta > 0 else "falling"
        result.append(
            {
                "query_id": data.get("query_id") or source_id[6:],
                "title": data.get("title") or source_id[6:],
                "unit": data.get("unit"),
                "series_count": data.get("series_count", len(data.get("series", []) or [])),
                "sample_count": len(samples),
                "first": first[1],
                "last": last[1],
                "minimum": minimum[1],
                "maximum": maximum[1],
                "peak_timestamp": maximum[0],
                "change": delta,
                "trend": trend,
                "truncated": bool(data.get("truncated")),
            }
        )
    return result


def _rank_hypotheses(findings, downstream):
    result = []
    severity_score = {"critical": 35, "warning": 20, "info": 5}
    confidence_score = {"high": 15, "medium": 10, "low": 5, "none": 0}
    status_score = {"active": 15, "unknown": 5, "resolved": 0}
    severity_labels = {"critical": "критическая", "warning": "предупреждение", "info": "сведение"}
    status_labels = {"active": "активно", "unknown": "неизвестно", "resolved": "завершилось"}
    confidence_labels = {"high": "высокая", "medium": "средняя", "low": "низкая", "none": "причина не установлена"}
    for finding in findings:
        role = finding.get("finding_role")
        if role == "consequence":
            continue
        reasons = []
        score = severity_score.get(finding.get("severity"), 0)
        reasons.append("важность: {0}".format(severity_labels.get(finding.get("severity"), "не указана")))
        if role == "possible_cause":
            score += 20
            reasons.append("правило описывает возможную причину")
        elif role == "configuration_risk":
            score += 5
            reasons.append("обнаружен конфигурационный риск")
        status = finding.get("finding_status") or "unknown"
        score += status_score.get(status, 0)
        reasons.append("состояние: {0}".format(status_labels.get(status, "неизвестно")))
        confidence = finding.get("causal_confidence") or "none"
        score += confidence_score.get(confidence, 0)
        reasons.append("уверенность в причинной связи: {0}".format(confidence_labels.get(confidence, "не указана")))
        explained = sorted(downstream.get(finding.get("id"), ()))
        if explained:
            score += min(15, 5 * len(explained))
            reasons.append("может объяснять следствий: {0}".format(len(explained)))
        counter_count = len(finding.get("counter_evidence") or [])
        missing_count = len(finding.get("missing_checks") or [])
        if counter_count:
            score -= min(15, 5 * counter_count)
            reasons.append("есть данных против гипотезы: {0}".format(counter_count))
        if missing_count:
            score -= min(10, 2 * missing_count)
            reasons.append("не выполнено проверок: {0}".format(missing_count))
        result.append(
            {
                "finding_id": finding.get("id"),
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title") or finding.get("rule_id"),
                "score": max(0, min(100, score)),
                "status": status,
                "role": role,
                "reasons": reasons,
                "downstream_findings": explained,
                "evidence": (finding.get("evidence") or [])[:10],
                "counter_evidence": (finding.get("counter_evidence") or [])[:10],
                "missing_checks": (finding.get("missing_checks") or [])[:10],
            }
        )
    result.sort(key=lambda item: (-item["score"], str(item.get("rule_id") or ""), str(item.get("finding_id") or "")))
    for rank, item in enumerate(result, 1):
        item["rank"] = rank
    return result


def build_causal_analysis(kubernetes, findings, normalized, prometheus, collection):
    """Build a bounded evidence-derived topology and rank deterministic hypotheses."""
    graph = _GraphBuilder()
    object_targets = _add_kubernetes_topology(graph, kubernetes or {})
    finding_targets = {}
    finding_by_id = {}
    for finding in findings or []:
        finding_id = str(finding.get("id") or finding.get("rule_id") or "unknown")
        finding_by_id[finding_id] = finding
        graph_id = graph.node(
            "finding:{0}".format(finding_id),
            "finding",
            finding.get("title") or finding.get("rule_id") or finding_id,
            rule_id=finding.get("rule_id"),
            status=finding.get("finding_status"),
            role=finding.get("finding_role"),
        )
        targets = _finding_targets(finding, object_targets)
        finding_targets[finding_id] = targets
        for target in sorted(targets):
            graph.edge(graph_id, target, "indicates")

    topology_adjacency = {}
    for edge in list(graph.edges.values()):
        if edge["relation"] != "indicates":
            topology_adjacency.setdefault(edge["source"], set()).add(edge["target"])

    downstream = {}
    causes = [
        item for item in findings or []
        if item.get("finding_role") != "consequence"
        and not str(item.get("rule_id") or "").startswith("collector.")
    ]
    consequences = [item for item in findings or [] if item.get("finding_role") == "consequence"]
    for cause in causes:
        cause_id = cause.get("id")
        reachable = _reachable(topology_adjacency, finding_targets.get(cause_id, set()))
        for consequence in consequences:
            consequence_id = consequence.get("id")
            consequence_targets = finding_targets.get(consequence_id, set())
            if (
                not consequence_targets
                or not reachable.intersection(consequence_targets)
                or not _temporally_compatible(cause, consequence)
            ):
                continue
            graph.edge(
                "finding:{0}".format(cause_id),
                "finding:{0}".format(consequence_id),
                "may_explain",
                basis="topology_and_compatible_time",
            )
            downstream.setdefault(cause_id, set()).add(consequence_id)

    signals = _metric_signals(prometheus or {})
    for signal in signals:
        metric_id = "metric:{0}".format(signal["query_id"])
        graph.node(metric_id, "metric_signal", signal["title"], trend=signal["trend"], maximum=signal["maximum"])
        component = None
        if signal["query_id"].startswith("api_server_"):
            component = "component:kube-apiserver"
        elif signal["query_id"].startswith("etcd_"):
            component = "component:etcd"
        elif "network" in signal["query_id"]:
            component = "component:cilium"
        if component:
            graph.edge(metric_id, component, "describes")

    analysis_options = _analysis_options(collection)
    rankable_findings = [
        item for item in (findings or [])
        if not str(item.get("rule_id") or "").startswith("collector.")
        and (analysis_options["purpose"] == "incident" or item.get("finding_status") != "resolved")
    ]
    return {
        "schema_version": 1,
        "analysis": analysis_options,
        "graph": graph.document(),
        "hypotheses": _rank_hypotheses(rankable_findings, downstream),
        "metric_signals": signals,
        "correlation_episode_count": len((normalized or {}).get("correlations", []) or []),
    }
