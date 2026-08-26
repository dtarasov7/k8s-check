import hashlib
import json
import re
from collections import Counter, deque
from datetime import datetime, timezone

from kdiag.npd_rules import NPD_CATEGORY_PATTERNS
from kdiag.node_identity import match_node_identities
from kdiag.runtime import ACTIVE_SERVICE_STATES, RUNTIME_SERVICE_UNITS, loaded_runtime_service_states, runtime_service_is_active


MAX_NORMALIZED_EVENTS = 50000
MAX_NORMALIZATION_CANDIDATES = 200000
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
    ("authentication_config_read_error", re.compile(r"(?:failed|unable) to read authentication config file.*(?:no such file|permission denied|is a directory)", re.I)),
    ("ptrace_security_alert", re.compile(r"ptrace attack of .{1,512} was attempted by", re.I)),
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
    "authentication_config_read_error": "warning",
    "ptrace_security_alert": "warning",
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


NODE_CONTEXT_CATEGORIES = {
    "cgroup_access_denied",
    "conntrack_full",
    "runtime_unavailable",
    "api_unreachable",
    "npd_task_hung",
    "npd_unregister_netdevice",
    "npd_kernel_oops",
    "npd_ext4_error",
    "npd_ext4_warning",
    "npd_io_error",
    "npd_xfs_shutdown",
    "npd_memory_read_error",
    "npd_hardware_corrected",
    "npd_hardware_recoverable",
    "npd_hardware_fatal",
}
NPD_CATEGORIES = {category for category, _pattern in NPD_CATEGORY_PATTERNS}
DNS_COMPONENT_RE = re.compile(r"(?:^|[-_.])(coredns|kube-dns)(?:$|[-_.])", re.I)


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


def classify_message(message, reason=None, source=None, component=None):
    categories = set(REASON_CATEGORIES.get(str(reason or "").lower(), ()))
    for category, pattern in CATEGORY_PATTERNS:
        if pattern.search(message):
            categories.add(category)
    source_name = str(source or "")
    component_name = str(component or "")
    # Calls without a source retain the original permissive public API. Every
    # normalizer supplies a source and therefore gets the stricter context.
    node_context = source is None or source_name in ("journal", "systemd_state", "kubernetes_condition")
    kernel_context = source is None or source_name == "journal" and (
        "kernel" in component_name.lower() or component_name in ("journal_kernel_current", "journal_kernel_previous")
    )
    if kernel_context:
        for category, pattern in NPD_CATEGORY_PATTERNS:
            if pattern.search(message):
                categories.add(category)
    if not node_context:
        categories.difference_update(NODE_CONTEXT_CATEGORIES)
    if not kernel_context:
        categories.difference_update(NPD_CATEGORIES)
    cni_context = node_context or source_name in ("kubernetes_event", "kubernetes_container_state") or "cilium" in component_name.lower()
    if not cni_context:
        categories.discard("cni_unavailable")
    dns_context = source is None or bool(DNS_COMPONENT_RE.search(component_name))
    if not dns_context:
        categories.difference_update(("dns_servfail", "dns_forward_loop", "dns_upstream_failure"))
    api_server_context = source is None or "apiserver" in component_name.lower()
    if not api_server_context:
        categories.discard("authentication_config_read_error")
    if not kernel_context:
        categories.discard("ptrace_security_alert")
    # A cgroup-specific EROFS is not evidence that the backing filesystem is
    # generally read-only. Keeping both labels caused false storage failures.
    if "cgroup_access_denied" in categories:
        categories.discard("read_only_fs")
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


def _event(
    source,
    message,
    categories,
    evidence,
    timestamp=None,
    node=None,
    namespace=None,
    pod=None,
    container=None,
    component=None,
    reason=None,
    inferred_time=False,
    first_timestamp=None,
    last_timestamp=None,
    occurrence_count=1,
):
    clean_message = _clean_text(message)
    identity = "|".join(str(value or "") for value in (source, evidence, timestamp, clean_message))
    return {
        "event_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
        "timestamp": timestamp,
        "timestamp_epoch": _epoch(timestamp),
        "timestamp_inferred": bool(inferred_time),
        "first_timestamp": first_timestamp or timestamp,
        "last_timestamp": last_timestamp or timestamp,
        "occurrence_count": max(1, int(occurrence_count or 1)),
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
    stats["source_records"][event["source"]] += 1
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
    for category in event.get("categories", []):
        stats["category_records"][category] += 1
    if len(events) >= MAX_NORMALIZATION_CANDIDATES:
        stats["truncated"] = True
        stats["dropped_records"] += 1
        stats["candidate_limit_drops"] += 1
        stats["dropped_by_source"][event["source"]] += 1
        return
    events.append(event)


def _normalize_journals(node_name, snapshot, events, unknown, stats, evidence_name=None):
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
            component = record.get("_SYSTEMD_UNIT") or record.get("SYSLOG_IDENTIFIER") or command_id
            categories = classify_message(message, reason, source="journal", component=component)
            evidence = "node-{0}.json.gz#commands.{1}:line-{2}".format(evidence_name or node_name, command_id, line_number)
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
                    component=component,
                    reason=reason,
                    inferred_time=timestamp == fallback,
                ),
            )


def _normalize_node_pod_logs(node_name, snapshot, events, unknown, stats, evidence_name=None):
    fallback = snapshot.get("ended_at")
    for entry_index, entry in enumerate(snapshot.get("pod_logs", {}).get("entries", [])):
        for line_number, line in enumerate(entry.get("text", "").splitlines(), 1):
            parts = line.split(" ", 3)
            if len(parts) == 4 and _epoch(parts[0]) is not None:
                timestamp, message = parts[0], parts[3]
                inferred = False
            else:
                timestamp, message, inferred = fallback, line, True
            categories = classify_message(message, source="cri_log", component=entry.get("container"))
            evidence = "node-{0}.json.gz#pod_logs.entries[{1}]:line-{2}".format(evidence_name or node_name, entry_index, line_number)
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
        component = item.get("reportingController") or item.get("reportingInstance")
        categories = classify_message(message, reason, source="kubernetes_event", component=component)
        first_timestamp = item.get("firstTimestamp") or item.get("eventTime")
        last_timestamp = item.get("seriesLastObservedTime") or item.get("lastTimestamp") or item.get("eventTime")
        timestamp = last_timestamp or first_timestamp or fallback
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
                component=component,
                reason=reason,
                inferred_time=timestamp == fallback,
                first_timestamp=first_timestamp,
                last_timestamp=last_timestamp,
                occurrence_count=item.get("count") or 1,
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
        is_cilium = namespace in ("kube-system", "d8-cni-cilium") and ("cilium" in label_values or any("cilium" in value for value in label_values))
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
                    # Pod startTime is not the phase-transition time. Preserve
                    # it for ordering but exclude it from causal correlation.
                    inferred_time=True,
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
                    categories = classify_message(
                        message,
                        reason,
                        source="kubernetes_container_state",
                        component=container,
                    )
                    if categories and is_cilium:
                        categories = sorted(set(categories) | {"cilium_unhealthy"})
                    if not categories:
                        continue
                    evidence = "kubernetes.json.gz#sources.pods.items[{0}].status.{1}[{2}].{3}".format(
                        pod_index, status_field, status_index, state_name
                    )
                    state_timestamp = fallback
                    inferred = True
                    if state.get("terminated"):
                        state_timestamp = state["terminated"].get("finishedAt") or state["terminated"].get("startedAt") or fallback
                        inferred = state_timestamp == fallback
                    elif state.get("running"):
                        state_timestamp = state["running"].get("startedAt") or fallback
                        inferred = state_timestamp == fallback
                    _append(
                        events,
                        {},
                        stats,
                        _event(
                            "kubernetes_container_state",
                            "{0}: {1}".format(reason or state_name, message),
                            categories,
                            evidence,
                            timestamp=state_timestamp,
                            node=node,
                            namespace=namespace,
                            pod=pod,
                            container=container,
                            component=container,
                            reason=reason,
                            inferred_time=inferred,
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
            categories = classify_message(
                message,
                source="kubernetes_pod_log",
                component=entry.get("container") or entry.get("pod"),
            )
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


def _normalize_service_states(node_name, snapshot, events, stats, evidence_name=None):
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
                "node-{0}.json.gz#facts.service_states.{1}".format(evidence_name or node_name, unit),
                timestamp=timestamp,
                node=node_name,
                component=unit,
                inferred_time=True,
            ),
        )


def _correlation_scope(event, correlation_id):
    if correlation_id == "probe_network_failure":
        if event.get("namespace") and event.get("pod"):
            return "pod:{0}/{1}".format(event["namespace"], event["pod"])
        return None
    if event.get("node"):
        return "node:{0}".format(event["node"])
    return None


def _episode(correlation_id, scope, match, groups, window_seconds):
    selected = []
    for group in groups:
        selected.extend(event for event in match if set(event.get("categories", ())) & group)
    unique = {event["event_id"]: event for event in selected}
    if len(unique) < 2:
        return None
    ordered = sorted(unique.values(), key=lambda event: (event["timestamp_epoch"], event["event_id"]))[:20]
    started_at = ordered[0].get("timestamp")
    ended_at = ordered[-1].get("timestamp")
    duration = max(0.0, ordered[-1]["timestamp_epoch"] - ordered[0]["timestamp_epoch"])
    identity = "|".join((correlation_id, scope, str(ordered[0]["timestamp_epoch"]), str(ordered[-1]["timestamp_epoch"])))
    return {
        "correlation_id": correlation_id,
        "episode_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
        "scope": scope,
        "window_seconds": window_seconds,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": duration,
        "categories": sorted(set().union(*(set(event["categories"]) for event in ordered))),
        "sources": sorted(set(event["source"] for event in ordered)),
        "event_ids": [event["event_id"] for event in ordered],
        "evidence": sorted(set(event["evidence"] for event in ordered)),
    }


def correlate_events(events, window_seconds=CORRELATION_WINDOW_SECONDS):
    correlations = []
    for correlation_id, groups in CORRELATION_SPECS:
        relevant_categories = set().union(*groups)
        scopes = {}
        for event in events:
            if event.get("timestamp_epoch") is None or event.get("timestamp_inferred"):
                continue
            if not set(event.get("categories", ())) & relevant_categories:
                continue
            scope = _correlation_scope(event, correlation_id)
            if scope:
                scopes.setdefault(scope, []).append(event)
        for scope, scoped_events in sorted(scopes.items()):
            candidates = sorted(scoped_events, key=lambda event: (event["timestamp_epoch"], event["event_id"]))
            start = 0
            while start < len(candidates):
                category_counts = Counter()
                match = None
                left = start
                for right in range(start, len(candidates)):
                    event = candidates[right]
                    category_counts.update(set(event.get("categories", ())) & relevant_categories)
                    while event["timestamp_epoch"] - candidates[left]["timestamp_epoch"] > window_seconds:
                        category_counts.subtract(set(candidates[left].get("categories", ())) & relevant_categories)
                        left += 1
                    if right > left and all(any(category_counts[category] > 0 for category in group) for group in groups):
                        match = candidates[left : right + 1]
                        start = right + 1
                        break
                if match is None:
                    break
                episode = _episode(correlation_id, scope, match, groups, window_seconds)
                if episode:
                    correlations.append(episode)
    return sorted(correlations, key=lambda item: (item["started_at"] or "", item["correlation_id"], item["scope"]))


def _deduplicate_events(events, stats):
    deduplicated = {}
    for event in events:
        key = (
            event.get("source"),
            event.get("node"),
            event.get("namespace"),
            event.get("pod"),
            event.get("container"),
            event.get("timestamp"),
            tuple(event.get("categories", ())),
            event.get("fingerprint"),
        )
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = event
            continue
        existing["occurrence_count"] += event.get("occurrence_count", 1)
        evidence = existing.setdefault("duplicate_evidence", [])
        if event.get("evidence") != existing.get("evidence") and event.get("evidence") not in evidence:
            evidence.append(event.get("evidence"))
        stats["deduplicated_records"] += 1
        stats["dropped_by_source"][event["source"]] += 1
    return list(deduplicated.values())


def _event_bucket(event):
    if event.get("namespace") and event.get("pod"):
        scope = "pod:{0}/{1}".format(event["namespace"], event["pod"])
    elif event.get("node"):
        scope = "node:{0}".format(event["node"])
    else:
        scope = "cluster"
    return event.get("source"), scope, tuple(event.get("categories", ()))


def _fair_limit_events(events, limit, stats):
    if len(events) <= limit:
        return events
    buckets = {}
    for event in events:
        buckets.setdefault(_event_bucket(event), deque()).append(event)
    retained = []
    active = deque(sorted(buckets))
    while active and len(retained) < limit:
        key = active.popleft()
        retained.append(buckets[key].popleft())
        if buckets[key]:
            active.append(key)
    retained_ids = {event["event_id"] for event in retained}
    for event in events:
        if event["event_id"] not in retained_ids:
            stats["dropped_records"] += 1
            stats["output_limit_drops"] += 1
            stats["dropped_by_source"][event["source"]] += 1
    stats["truncated"] = True
    return retained


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
        "candidate_limit_drops": 0,
        "output_limit_drops": 0,
        "deduplicated_records": 0,
        "source_records": Counter(),
        "category_records": Counter(),
        "dropped_by_source": Counter(),
        "truncated": False,
    }
    kubernetes_nodes = kubernetes.get("sources", {}).get("nodes", {}).get("data", {}).get("items", []) or []
    node_identity_map = match_node_identities(node_snapshots, kubernetes_nodes)
    for inventory_name, snapshot in sorted(node_snapshots.items()):
        node_name = node_identity_map.get(inventory_name, inventory_name)
        _normalize_journals(node_name, snapshot, events, unknown, stats, evidence_name=inventory_name)
        _normalize_node_pod_logs(node_name, snapshot, events, unknown, stats, evidence_name=inventory_name)
        _normalize_service_states(node_name, snapshot, events, stats, evidence_name=inventory_name)
    pod_nodes = _pod_node_index(kubernetes)
    _normalize_kubernetes_events(kubernetes, events, unknown, stats, pod_nodes)
    _normalize_node_conditions(kubernetes, events, stats)
    _normalize_pod_states(kubernetes, events, stats, pod_nodes)
    _normalize_kubernetes_logs(kubernetes, events, unknown, stats, pod_nodes)
    if collection.get("options", {}).get("collect_cgroup", True) is False:
        filtered_events = []
        for event in events:
            if "cgroup_access_denied" in event.get("categories", []):
                stats["cgroup_events_suppressed"] += 1
                stats["dropped_by_source"][event["source"]] += 1
                continue
            filtered_events.append(event)
        events = filtered_events
    events = _deduplicate_events(events, stats)
    events = _fair_limit_events(events, MAX_NORMALIZED_EVENTS, stats)
    events.sort(key=lambda event: (event.get("timestamp_epoch") or 0, event["event_id"]))
    unknown_values = sorted(unknown.values(), key=lambda item: (-item["count"], item["component"], item["fingerprint"]))
    stats["unknown_retained_fingerprints"] = len(unknown_values)
    stats["retained_source_records"] = dict(Counter(event["source"] for event in events))
    stats["source_records"] = dict(stats["source_records"])
    stats["category_records"] = dict(stats["category_records"])
    stats["dropped_by_source"] = dict(stats["dropped_by_source"])
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
