import hashlib
import json
import re
from datetime import datetime, timezone

from kdiag.npd_rules import NPD_CATEGORY_PATTERNS
from kdiag.runtime import ACTIVE_SERVICE_STATES, RUNTIME_SERVICE_UNITS, loaded_runtime_service_states, runtime_service_is_active


MAX_NORMALIZED_EVENTS = 50000
MAX_UNKNOWN_FINGERPRINTS = 100
CORRELATION_WINDOW_SECONDS = 15 * 60


CATEGORY_PATTERNS = (
    ("cgroup_access_denied", re.compile(r"(?:cgroup|subtree_control|cpu\.|io\.).*(?:permission denied|operation not permitted|read-only file system|eacces|eperm|erofs)|(?:permission denied|operation not permitted|read-only file system).*(?:cgroup|subtree_control|cpu\.|io\.)", re.I)),
    ("oom_kill", re.compile(r"out of memory|oom-kill|oomkilled|killed process\s+\d+", re.I)),
    ("conntrack_full", re.compile(r"nf_conntrack.*table full|conntrack.*table full", re.I)),
    ("disk_full", re.compile(r"no space left on device|\benospc\b", re.I)),
    ("read_only_fs", re.compile(r"read-only file system|\berofs\b", re.I)),
    ("cni_unavailable", re.compile(r"cni.*(?:not initialized|failed|error)|network plugin.*not ready|networkpluginnotready|failed to setup network for sandbox", re.I)),
    ("runtime_unavailable", re.compile(r"container runtime.*not ready|runtime service.*not ready|container runtime is down|failed to connect.*(?:containerd|crio|cri-o)|cri.*(?:unavailable|connection refused)", re.I)),
    ("api_unreachable", re.compile(r"unable to (?:connect|update node status)|failed to (?:list|watch|update).*api|apiserver.*(?:unreachable|connection refused)|error updating node status", re.I)),
    ("address_family", re.compile(r"address family not supported|\beafnosupport\b", re.I)),
    ("no_route", re.compile(r"no route to host|network is unreachable", re.I)),
    ("connection_refused", re.compile(r"connection refused", re.I)),
    ("dns_error", re.compile(r"no such host|temporary failure in name resolution|server misbehaving|dns.*(?:timeout|failed|error)", re.I)),
    ("timeout", re.compile(r"timed? out|timeout|deadline exceeded|context deadline exceeded", re.I)),
    ("certificate_error", re.compile(r"x509|certificate.*(?:expired|not valid|unknown authority)|tls handshake", re.I)),
    ("clock_error", re.compile(r"clock skew|time.*out of sync|not synchroni[sz]ed|certificate is not yet valid", re.I)),
    ("probe_failure", re.compile(r"readiness probe failed|liveness probe failed|startup probe failed|health probe", re.I)),
    ("image_pull", re.compile(r"imagepullbackoff|errimagepull|failed to pull image|pull image.*(?:failed|error)", re.I)),
    ("failed_scheduling", re.compile(r"failedscheduling|failed to fit in any node|0/\d+ nodes are available|insufficient (?:cpu|memory)", re.I)),
    ("crash_loop", re.compile(r"crashloopbackoff|back-off restarting failed container", re.I)),
    ("pod_sandbox_failure", re.compile(r"failedcreatepodsandbox|failed to create pod sandbox", re.I)),
    ("volume_error", re.compile(r"failedmount|failedattachvolume|unable to attach or mount volumes", re.I)),
    ("dns_servfail", re.compile(r"\bservfail\b", re.I)),
    ("dns_forward_loop", re.compile(r"plugin/loop|loop detected|forwarding loop", re.I)),
    ("dns_upstream_failure", re.compile(r"coredns.*(?:upstream|forward).*(?:timeout|unreachable|refused)|plugin/errors.*(?:timeout|refused|unreachable)", re.I)),
    ("selinux_denial", re.compile(r"avc:\s+denied|selinux.*denied", re.I)),
)


REASON_CATEGORIES = {
    "unhealthy": ("probe_failure",),
    "failedscheduling": ("failed_scheduling",),
    "failed": (),
    "failedcreatepodsandbox": ("pod_sandbox_failure", "cni_unavailable"),
    "networknotready": ("cni_unavailable",),
    "failedpull": ("image_pull",),
    "errimagepull": ("image_pull",),
    "imagepullbackoff": ("image_pull",),
    "failedmount": ("volume_error",),
    "failedattachvolume": ("volume_error",),
    "evicted": ("eviction",),
    "oomkilled": ("oom_kill",),
    "crashloopbackoff": ("crash_loop",),
    "createcontainerconfigerror": ("container_config_error",),
    "runcontainererror": ("container_start_error",),
    "containercannotrun": ("container_start_error",),
}


CATEGORY_SEVERITY = {
    "node_not_ready": "critical",
    "kubelet_inactive": "critical",
    "runtime_unavailable": "critical",
    "cni_unavailable": "critical",
    "cgroup_access_denied": "critical",
    "oom_kill": "critical",
    "disk_pressure": "critical",
    "memory_pressure": "critical",
    "pid_pressure": "critical",
    "network_unavailable": "critical",
    "certificate_error": "critical",
    "conntrack_full": "critical",
    "read_only_fs": "critical",
    "disk_full": "critical",
    "crash_loop": "warning",
    "image_pull": "warning",
    "failed_scheduling": "warning",
    "probe_failure": "warning",
    "pod_not_ready": "warning",
    "pod_pending": "warning",
    "pod_failed": "warning",
    "pod_unknown": "warning",
    "eviction": "warning",
    "volume_error": "warning",
    "container_config_error": "warning",
    "container_start_error": "warning",
    "dns_servfail": "warning",
    "dns_forward_loop": "critical",
    "dns_upstream_failure": "warning",
    "npd_task_hung": "critical",
    "npd_unregister_netdevice": "warning",
    "npd_kernel_oops": "critical",
    "npd_ext4_error": "critical",
    "npd_ext4_warning": "warning",
    "npd_io_error": "critical",
    "npd_xfs_shutdown": "critical",
    "npd_memory_read_error": "warning",
    "npd_hardware_corrected": "warning",
    "npd_hardware_recoverable": "critical",
    "npd_hardware_fatal": "critical",
}


CORRELATION_SPECS = (
    ("node_runtime_failure", ({"node_not_ready"}, {"kubelet_inactive", "runtime_unavailable"})),
    ("node_cni_failure", ({"node_not_ready", "pod_sandbox_failure"}, {"cni_unavailable", "network_unavailable"})),
    ("probe_network_failure", ({"probe_failure"}, {"address_family", "no_route", "connection_refused", "dns_error", "timeout"})),
    ("memory_oom_failure", ({"memory_pressure"}, {"oom_kill"})),
    ("storage_failure", ({"disk_pressure"}, {"disk_full", "read_only_fs"})),
    ("cgroup_service_failure", ({"cgroup_access_denied"}, {"kubelet_inactive", "runtime_unavailable"})),
    ("certificate_api_failure", ({"certificate_error"}, {"api_unreachable", "clock_error"})),
    ("conntrack_network_failure", ({"conntrack_full"}, {"no_route", "connection_refused", "timeout", "probe_failure"})),
)


def _clean_text(value, limit=1024):
    if isinstance(value, list) and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
        value = bytes(value).decode("utf-8", errors="replace")
    text = " ".join(str(value or "").replace("\x00", " ").replace("\r", " ").replace("\n", " ").split())
    return text[:limit]


def _template(message):
    value = message.lower()
    value = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "<uuid>", value)
    value = re.sub(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "<ipv4>", value)
    value = re.sub(r"\b[0-9a-f]{0,4}:[0-9a-f:]{2,}\b", "<ipv6>", value)
    value = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", value)
    value = re.sub(r"\b\d+\b", "<n>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:300]


def classify_message(message, reason=None):
    categories = set(REASON_CATEGORIES.get(str(reason or "").lower(), ()))
    for category, pattern in CATEGORY_PATTERNS + NPD_CATEGORY_PATTERNS:
        if pattern.search(message):
            categories.add(category)
    return sorted(categories)


def _severity(categories, default="info"):
    order = {"info": 0, "warning": 1, "critical": 2}
    result = default
    for category in categories:
        candidate = CATEGORY_SEVERITY.get(category, default)
        if order[candidate] > order[result]:
            result = candidate
    return result


def _iso_from_microseconds(value):
    try:
        return datetime.fromtimestamp(int(value) / 1000000.0, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _epoch(value):
    if not value:
        return None
    text = str(value)
    if text.isdigit() and len(text) >= 13:
        divisor = 1000000.0 if len(text) >= 16 else 1000.0
        try:
            return int(text) / divisor
        except ValueError:
            return None
    match = re.match(r"^(.*?\.)(\d{6})\d+(Z|[+-]\d\d:\d\d)$", text)
    if match:
        text = "".join(match.groups())
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except (ValueError, OverflowError):
        return None


def _event(source, message, categories, evidence, timestamp=None, node=None, namespace=None, pod=None, container=None, component=None, reason=None, inferred_time=False):
    clean_message = _clean_text(message)
    identity = "|".join(str(value or "") for value in (source, evidence, timestamp, clean_message))
    return {
        "event_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
        "timestamp": timestamp,
        "timestamp_epoch": _epoch(timestamp),
        "timestamp_inferred": bool(inferred_time),
        "source": source,
        "node": node,
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "component": component,
        "reason": reason,
        "severity": _severity(categories),
        "categories": sorted(set(categories)),
        "message_excerpt": clean_message,
        "fingerprint": hashlib.sha256(_template(clean_message).encode("utf-8")).hexdigest()[:24],
        "evidence": evidence,
    }


def _command(snapshot, command_id):
    for item in snapshot.get("commands", []):
        if item.get("id") == command_id:
            return item
    return {}


def _append(events, unknown, stats, event):
    stats["input_records"] += 1
    if not event["categories"]:
        stats["uncategorized_records"] += 1
        key = (event.get("component") or event["source"], event["fingerprint"])
        entry = unknown.get(key)
        if entry is None:
            estimate_error = 0
            initial_count = 1
            if len(unknown) >= MAX_UNKNOWN_FINGERPRINTS:
                victim_key, victim = min(unknown.items(), key=lambda item: (item[1]["count"], item[0]))
                del unknown[victim_key]
                estimate_error = victim["count"]
                initial_count = estimate_error + 1
                stats["unknown_fingerprint_replacements"] += 1
            unknown[key] = {
                "component": key[0],
                "fingerprint": key[1],
                "template": _template(event["message_excerpt"]),
                "count": initial_count,
                "estimate_error": estimate_error,
            }
        else:
            entry["count"] += 1
        return
    stats["categorized_records"] += 1
    if len(events) >= MAX_NORMALIZED_EVENTS:
        stats["truncated"] = True
        stats["dropped_records"] += 1
        return
    events.append(event)


def _normalize_journals(node_name, snapshot, events, unknown, stats):
    journal_ids = (
        "journal_services_current",
        "journal_services_previous",
        "journal_kernel_current",
        "journal_kernel_previous",
    )
    fallback = snapshot.get("ended_at")
    for command_id in journal_ids:
        command = _command(snapshot, command_id)
        for line_number, line in enumerate(command.get("stdout", "").splitlines(), 1):
            try:
                record = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                stats["malformed_records"] += 1
                continue
            message = _clean_text(record.get("MESSAGE"))
            if not message:
                continue
            timestamp = _iso_from_microseconds(record.get("__REALTIME_TIMESTAMP")) or fallback
            reason = record.get("SYSLOG_IDENTIFIER")
            categories = classify_message(message, reason)
            evidence = "node-{0}.json.gz#commands.{1}:line-{2}".format(node_name, command_id, line_number)
            _append(
                events,
                unknown,
                stats,
                _event(
                    "journal",
                    message,
                    categories,
                    evidence,
                    timestamp=timestamp,
                    node=node_name,
                    component=record.get("_SYSTEMD_UNIT") or record.get("SYSLOG_IDENTIFIER") or command_id,
                    reason=reason,
                    inferred_time=timestamp == fallback,
                ),
            )


def _normalize_node_pod_logs(node_name, snapshot, events, unknown, stats):
    fallback = snapshot.get("ended_at")
    for entry_index, entry in enumerate(snapshot.get("pod_logs", {}).get("entries", [])):
        for line_number, line in enumerate(entry.get("text", "").splitlines(), 1):
            parts = line.split(" ", 3)
            if len(parts) == 4 and _epoch(parts[0]) is not None:
                timestamp, message = parts[0], parts[3]
                inferred = False
            else:
                timestamp, message, inferred = fallback, line, True
            categories = classify_message(message)
            evidence = "node-{0}.json.gz#pod_logs.entries[{1}]:line-{2}".format(node_name, entry_index, line_number)
            _append(
                events,
                unknown,
                stats,
                _event(
                    "cri_log",
                    message,
                    categories,
                    evidence,
                    timestamp=timestamp,
                    node=node_name,
                    namespace=entry.get("namespace"),
                    pod=entry.get("pod"),
                    container=entry.get("container"),
                    component=entry.get("container"),
                    inferred_time=inferred,
                ),
            )


def _pod_node_index(kubernetes):
    result = {}
    items = kubernetes.get("sources", {}).get("pods", {}).get("data", {}).get("items", []) or []
    for pod in items:
        metadata = pod.get("metadata", {})
        result[(metadata.get("namespace"), metadata.get("name"))] = pod.get("spec", {}).get("nodeName")
    return result


def _normalize_kubernetes_events(kubernetes, events, unknown, stats, pod_nodes):
    fallback = kubernetes.get("collected_at")
    items = kubernetes.get("sources", {}).get("events", {}).get("data", {}).get("items", []) or []
    for index, item in enumerate(items):
        regarding = item.get("regarding", {})
        namespace = regarding.get("namespace") or item.get("metadata", {}).get("namespace")
        pod = regarding.get("name") if regarding.get("kind") == "Pod" else None
        message = item.get("note", "")
        reason = item.get("reason")
        categories = classify_message(message, reason)
        timestamp = item.get("eventTime") or item.get("lastTimestamp") or item.get("firstTimestamp") or fallback
        _append(
            events,
            unknown,
            stats,
            _event(
                "kubernetes_event",
                message,
                categories,
                "kubernetes.json.gz#sources.events.items[{0}]".format(index),
                timestamp=timestamp,
                node=pod_nodes.get((namespace, pod)) or (regarding.get("name") if regarding.get("kind") == "Node" else None),
                namespace=namespace,
                pod=pod,
                component=item.get("reportingController") or item.get("reportingInstance"),
                reason=reason,
                inferred_time=timestamp == fallback,
            ),
        )


def _normalize_node_conditions(kubernetes, events, stats):
    fallback = kubernetes.get("collected_at")
    mapping = {
        "Ready": "node_not_ready",
        "DiskPressure": "disk_pressure",
        "MemoryPressure": "memory_pressure",
        "PIDPressure": "pid_pressure",
        "NetworkUnavailable": "network_unavailable",
    }
    items = kubernetes.get("sources", {}).get("nodes", {}).get("data", {}).get("items", []) or []
    for node_index, item in enumerate(items):
        name = item.get("metadata", {}).get("name")
        for condition_index, condition in enumerate(item.get("status", {}).get("conditions", []) or []):
            condition_type = condition.get("type")
            status = str(condition.get("status"))
            abnormal = (condition_type == "Ready" and status in ("False", "Unknown")) or (
                condition_type != "Ready" and condition_type in mapping and status == "True"
            )
            if not abnormal:
                continue
            category = mapping[condition_type]
            message = "{0}={1}: {2} {3}".format(condition_type, status, condition.get("reason") or "", condition.get("message") or "")
            evidence = "kubernetes.json.gz#sources.nodes.items[{0}].status.conditions[{1}]".format(node_index, condition_index)
            event = _event(
                "kubernetes_condition",
                message,
                [category],
                evidence,
                timestamp=condition.get("lastTransitionTime") or fallback,
                node=name,
                component="kubelet",
                reason=condition.get("reason"),
                inferred_time=not condition.get("lastTransitionTime"),
            )
            _append(events, {}, stats, event)


def _normalize_pod_states(kubernetes, events, stats, pod_nodes):
    fallback = kubernetes.get("collected_at")
    items = kubernetes.get("sources", {}).get("pods", {}).get("data", {}).get("items", []) or []
    for pod_index, item in enumerate(items):
        metadata = item.get("metadata", {})
        namespace, pod = metadata.get("namespace"), metadata.get("name")
        label_values = set(str(value).lower() for value in metadata.get("labels", {}).values())
        is_cilium = namespace == "kube-system" and ("cilium" in label_values or any("cilium" in value for value in label_values))
        node = pod_nodes.get((namespace, pod))
        status = item.get("status", {})
        phase = status.get("phase")
        if phase in ("Pending", "Failed", "Unknown"):
            category = {"Pending": "pod_pending", "Failed": "pod_failed", "Unknown": "pod_unknown"}[phase]
            phase_categories = [category, "cilium_unhealthy"] if is_cilium else [category]
            _append(
                events,
                {},
                stats,
                _event(
                    "kubernetes_pod_state",
                    "Pod phase={0}: {1} {2}".format(phase, status.get("reason") or "", status.get("message") or ""),
                    phase_categories,
                    "kubernetes.json.gz#sources.pods.items[{0}].status".format(pod_index),
                    timestamp=status.get("startTime") or fallback,
                    node=node,
                    namespace=namespace,
                    pod=pod,
                    reason=status.get("reason"),
                    inferred_time=not status.get("startTime"),
                ),
            )
        for status_field in ("initContainerStatuses", "containerStatuses"):
            for status_index, container_status in enumerate(status.get(status_field, []) or []):
                container = container_status.get("name")
                for state_name in ("state", "lastState"):
                    state = container_status.get(state_name, {}) or {}
                    reason = None
                    message = ""
                    if state.get("waiting"):
                        reason = state["waiting"].get("reason")
                        message = state["waiting"].get("message", "")
                    elif state.get("terminated"):
                        reason = state["terminated"].get("reason")
                        message = state["terminated"].get("message", "")
                        if state["terminated"].get("exitCode") not in (None, 0):
                            message = "exitCode={0} {1}".format(state["terminated"].get("exitCode"), message)
                    categories = classify_message(message, reason)
                    if categories and is_cilium:
                        categories = sorted(set(categories) | {"cilium_unhealthy"})
                    if not categories:
                        continue
                    evidence = "kubernetes.json.gz#sources.pods.items[{0}].status.{1}[{2}].{3}".format(
                        pod_index, status_field, status_index, state_name
                    )
                    _append(
                        events,
                        {},
                        stats,
                        _event(
                            "kubernetes_container_state",
                            "{0}: {1}".format(reason or state_name, message),
                            categories,
                            evidence,
                            timestamp=fallback,
                            node=node,
                            namespace=namespace,
                            pod=pod,
                            container=container,
                            component=container,
                            reason=reason,
                            inferred_time=True,
                        ),
                    )


def _normalize_kubernetes_logs(kubernetes, events, unknown, stats, pod_nodes):
    fallback = kubernetes.get("collected_at")
    for entry_index, entry in enumerate(kubernetes.get("logs", {}).get("entries", [])):
        namespace, pod = entry.get("namespace"), entry.get("pod")
        for line_number, line in enumerate(entry.get("text", "").splitlines(), 1):
            first, separator, remainder = line.partition(" ")
            if separator and _epoch(first) is not None:
                timestamp, message, inferred = first, remainder, False
            else:
                timestamp, message, inferred = fallback, line, True
            categories = classify_message(message)
            evidence = "kubernetes.json.gz#logs.entries[{0}]:line-{1}".format(entry_index, line_number)
            _append(
                events,
                unknown,
                stats,
                _event(
                    "kubernetes_pod_log",
                    message,
                    categories,
                    evidence,
                    timestamp=timestamp,
                    node=pod_nodes.get((namespace, pod)),
                    namespace=namespace,
                    pod=pod,
                    container=entry.get("container"),
                    component=entry.get("container"),
                    inferred_time=inferred,
                ),
            )


def _normalize_service_states(node_name, snapshot, events, stats):
    timestamp = snapshot.get("ended_at")
    service_states = snapshot.get("facts", {}).get("service_states", {})
    loaded_runtimes = loaded_runtime_service_states(service_states)
    has_active_runtime = any(runtime_service_is_active(state) for state in loaded_runtimes.values())
    for unit, state in service_states.items():
        properties = state.get("properties", {})
        if state.get("status") != "collected" or properties.get("ActiveState") in ACTIVE_SERVICE_STATES:
            continue
        if unit == "kubelet.service":
            if properties.get("LoadState") not in (None, "loaded"):
                continue
            categories = ["kubelet_inactive"]
        elif unit in RUNTIME_SERVICE_UNITS:
            if unit not in loaded_runtimes or has_active_runtime:
                continue
            categories = ["runtime_unavailable"]
        else:
            continue
        message = "{0}: ActiveState={1}, SubState={2}, Result={3}, ExecMainStatus={4}".format(
            unit,
            properties.get("ActiveState"),
            properties.get("SubState"),
            properties.get("Result"),
            properties.get("ExecMainStatus"),
        )
        _append(
            events,
            {},
            stats,
            _event(
                "systemd_state",
                message,
                categories,
                "node-{0}.json.gz#facts.service_states.{1}".format(node_name, unit),
                timestamp=timestamp,
                node=node_name,
                component=unit,
                inferred_time=True,
            ),
        )


def correlate_events(events, window_seconds=CORRELATION_WINDOW_SECONDS):
    scopes = {}
    for event in events:
        if event.get("node"):
            scope = event["node"]
        elif event.get("namespace") and event.get("pod"):
            scope = "pod:{0}/{1}".format(event["namespace"], event["pod"])
        else:
            continue
        scopes.setdefault(scope, []).append(event)
    correlations = []
    for scope, scoped_events in sorted(scopes.items()):
        for correlation_id, groups in CORRELATION_SPECS:
            relevant_categories = set().union(*groups)
            candidates = sorted(
                (
                    event
                    for event in scoped_events
                    if event.get("timestamp_epoch") is not None
                    and not (event.get("source") == "systemd_state" and event.get("timestamp_inferred"))
                    and set(event.get("categories", ())) & relevant_categories
                ),
                key=lambda event: (event["timestamp_epoch"], event["event_id"]),
            )
            match = None
            category_counts = {}
            left = 0
            for right, event in enumerate(candidates):
                for category in set(event.get("categories", ())) & relevant_categories:
                    category_counts[category] = category_counts.get(category, 0) + 1
                while candidates[right]["timestamp_epoch"] - candidates[left]["timestamp_epoch"] > window_seconds:
                    for category in set(candidates[left].get("categories", ())) & relevant_categories:
                        category_counts[category] -= 1
                    left += 1
                if right > left and all(any(category_counts.get(category, 0) for category in group) for group in groups):
                    match = candidates[left : right + 1]
                    break
            if not match:
                continue
            selected = []
            for group in groups:
                selected.extend(event for event in match if set(event.get("categories", ())) & group)
            unique = {event["event_id"]: event for event in selected}
            if len(unique) < 2:
                continue
            ordered = sorted(unique.values(), key=lambda event: (event.get("timestamp_epoch") or 0, event["event_id"]))[:20]
            correlations.append(
                {
                    "correlation_id": correlation_id,
                    "scope": scope,
                    "window_seconds": window_seconds,
                    "categories": sorted(set().union(*(set(event["categories"]) for event in ordered))),
                    "sources": sorted(set(event["source"] for event in ordered)),
                    "event_ids": [event["event_id"] for event in ordered],
                    "evidence": sorted(set(event["evidence"] for event in ordered)),
                }
            )
    return correlations


def normalize_evidence(collection, node_snapshots, kubernetes):
    events = []
    unknown = {}
    stats = {
        "input_records": 0,
        "categorized_records": 0,
        "uncategorized_records": 0,
        "malformed_records": 0,
        "dropped_records": 0,
        "unknown_fingerprint_replacements": 0,
        "cgroup_events_suppressed": 0,
        "truncated": False,
    }
    for node_name, snapshot in sorted(node_snapshots.items()):
        _normalize_journals(node_name, snapshot, events, unknown, stats)
        _normalize_node_pod_logs(node_name, snapshot, events, unknown, stats)
        _normalize_service_states(node_name, snapshot, events, stats)
    pod_nodes = _pod_node_index(kubernetes)
    _normalize_kubernetes_events(kubernetes, events, unknown, stats, pod_nodes)
    _normalize_node_conditions(kubernetes, events, stats)
    _normalize_pod_states(kubernetes, events, stats, pod_nodes)
    _normalize_kubernetes_logs(kubernetes, events, unknown, stats, pod_nodes)
    if collection.get("options", {}).get("collect_cgroup", True) is False:
        filtered_events = []
        for event in events:
            categories = [category for category in event.get("categories", []) if category != "cgroup_access_denied"]
            if len(categories) == len(event.get("categories", [])):
                filtered_events.append(event)
                continue
            stats["cgroup_events_suppressed"] += 1
            if categories:
                filtered_event = dict(event)
                filtered_event["categories"] = categories
                filtered_event["severity"] = _severity(categories)
                filtered_events.append(filtered_event)
        events = filtered_events
    events.sort(key=lambda event: (event.get("timestamp_epoch") or 0, event["event_id"]))
    unknown_values = sorted(unknown.values(), key=lambda item: (-item["count"], item["component"], item["fingerprint"]))
    stats["unknown_retained_fingerprints"] = len(unknown_values)
    return {
        "schema_version": 1,
        "kind": "normalized_events",
        "collection_id": collection.get("collection_id"),
        "sensitivity": "confidential",
        "stats": stats,
        "events": events,
        "correlations": correlate_events(events),
        "unknown_fingerprints": unknown_values[:MAX_UNKNOWN_FINGERPRINTS],
    }
