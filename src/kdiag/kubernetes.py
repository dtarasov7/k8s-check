import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from kdiag.runner import run_process
from kdiag.util import utc_now


ALLOWED_NODE_LABELS = (
    "kubernetes.io/hostname",
    "kubernetes.io/os",
    "kubernetes.io/arch",
    "node-role.kubernetes.io/control-plane",
    "node-role.kubernetes.io/master",
    "node-role.kubernetes.io/worker",
    "topology.kubernetes.io/region",
    "topology.kubernetes.io/zone",
)

ALLOWED_POD_LABELS = (
    "app",
    "app.kubernetes.io/name",
    "app.kubernetes.io/component",
    "k8s-app",
    "component",
    "tier",
)

ALLOWED_CILIUM_CONFIG_KEYS = (
    "kube-proxy-replacement",
    "kube-proxy-replacement-healthz-bind-address",
    "routing-mode",
    "tunnel-protocol",
    "tunnel-port",
    "ipam",
    "enable-ipv4",
    "enable-ipv6",
    "enable-endpoint-routes",
    "auto-direct-node-routes",
    "enable-bpf-masquerade",
    "bpf-lb-mode",
)


def snapshot_status(snapshot, logs_required):
    statuses = [
        item.get("status")
        for item in snapshot.get("sources", {}).values()
        if item.get("required", True)
    ]
    logs_status = snapshot.get("logs", {}).get("status")
    sources_complete = bool(statuses) and all(status == "collected" for status in statuses)
    logs_complete = not logs_required or logs_status == "collected"
    if sources_complete and logs_complete:
        return "collected"
    if any(status == "collected" for status in statuses):
        return "partial"
    return "unreachable"


def _metadata(value, allowed_labels=()):
    metadata = value or {}
    labels = metadata.get("labels", {}) or {}
    return {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "uid": metadata.get("uid"),
        "generation": metadata.get("generation"),
        "creationTimestamp": metadata.get("creationTimestamp"),
        "deletionTimestamp": metadata.get("deletionTimestamp"),
        "deletionGracePeriodSeconds": metadata.get("deletionGracePeriodSeconds"),
        "finalizers": [str(value)[:256] for value in (metadata.get("finalizers") or [])[:20]],
        "labels": {key: labels[key] for key in allowed_labels if key in labels},
        "labelsProjectionComplete": all(key in allowed_labels for key in labels),
    }


def _conditions(values):
    result = []
    for item in values or []:
        result.append(
            {
                "type": item.get("type"),
                "status": item.get("status"),
                "reason": item.get("reason"),
                "message": str(item.get("message", ""))[:4096],
                "lastTransitionTime": item.get("lastTransitionTime"),
            }
        )
    return result


def _probe(value):
    if not value:
        return None
    projected = {
        "initialDelaySeconds": value.get("initialDelaySeconds"),
        "timeoutSeconds": value.get("timeoutSeconds"),
        "periodSeconds": value.get("periodSeconds"),
        "successThreshold": value.get("successThreshold"),
        "failureThreshold": value.get("failureThreshold"),
    }
    if value.get("httpGet"):
        source = value["httpGet"]
        projected["type"] = "httpGet"
        projected["httpGet"] = {
            "path": source.get("path"),
            "port": source.get("port"),
            "host": source.get("host"),
            "scheme": source.get("scheme"),
        }
    elif value.get("tcpSocket"):
        source = value["tcpSocket"]
        projected["type"] = "tcpSocket"
        projected["tcpSocket"] = {"port": source.get("port"), "host": source.get("host")}
    elif value.get("exec"):
        projected["type"] = "exec"
    elif value.get("grpc"):
        source = value["grpc"]
        projected["type"] = "grpc"
        projected["grpc"] = {"port": source.get("port"), "service": source.get("service")}
    else:
        projected["type"] = "unknown"
    return projected


def _containers(values):
    result = []
    for item in values or []:
        result.append(
            {
                "name": item.get("name"),
                "image": item.get("image"),
                "ports": [
                    {
                        key: port.get(key)
                        for key in ("name", "containerPort", "protocol")
                        if key in port
                    }
                    for port in item.get("ports", []) or []
                ],
                "readinessProbe": _probe(item.get("readinessProbe")),
                "livenessProbe": _probe(item.get("livenessProbe")),
                "startupProbe": _probe(item.get("startupProbe")),
                "resources": item.get("resources", {}),
            }
        )
    return result


def _container_statuses(values):
    result = []
    for item in values or []:
        state = _container_state(item.get("state", {}) or {})
        last_state = _container_state(item.get("lastState", {}) or {})
        result.append(
            {
                "name": item.get("name"),
                "ready": item.get("ready"),
                "restartCount": item.get("restartCount"),
                "image": item.get("image"),
                "imageID": item.get("imageID"),
                "containerID": item.get("containerID"),
                "state": state,
                "lastState": last_state,
            }
        )
    return result


def _container_state(value):
    if value.get("waiting"):
        waiting = value["waiting"] or {}
        return {"waiting": {"reason": waiting.get("reason"), "message": str(waiting.get("message", ""))[:4096]}}
    if value.get("terminated"):
        terminated = value["terminated"] or {}
        return {
            "terminated": {
                "exitCode": terminated.get("exitCode"),
                "signal": terminated.get("signal"),
                "reason": terminated.get("reason"),
                "message": str(terminated.get("message", ""))[:4096],
                "startedAt": terminated.get("startedAt"),
                "finishedAt": terminated.get("finishedAt"),
                "containerID": terminated.get("containerID"),
            }
        }
    if value.get("running"):
        running = value["running"] or {}
        return {"running": {"startedAt": running.get("startedAt")}}
    return {}


def _selector(value):
    selector = value or {}
    match_labels = selector.get("matchLabels", {}) or {}
    result = {"matchLabels": {key: match_labels[key] for key in ALLOWED_POD_LABELS if key in match_labels}}
    expressions = []
    for expression in selector.get("matchExpressions", []) or []:
        if expression.get("key") in ALLOWED_POD_LABELS:
            expressions.append(
                {"key": expression.get("key"), "operator": expression.get("operator"), "values": expression.get("values")}
            )
    if expressions:
        result["matchExpressions"] = expressions
    return result


def project_node(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "Node"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_NODE_LABELS),
        "spec": {"podCIDR": spec.get("podCIDR"), "podCIDRs": spec.get("podCIDRs"), "taints": spec.get("taints")},
        "status": {
            "addresses": status.get("addresses"),
            "capacity": status.get("capacity"),
            "allocatable": status.get("allocatable"),
            "conditions": _conditions(status.get("conditions")),
            "nodeInfo": status.get("nodeInfo"),
        },
    }


def project_pod(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "Pod"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "spec": {
            "nodeName": spec.get("nodeName"),
            "hostNetwork": spec.get("hostNetwork"),
            "dnsPolicy": spec.get("dnsPolicy"),
            "restartPolicy": spec.get("restartPolicy"),
            "containers": _containers(spec.get("containers")),
            "initContainers": _containers(spec.get("initContainers")),
        },
        "status": {
            "phase": status.get("phase"),
            "hostIP": status.get("hostIP"),
            "hostIPs": status.get("hostIPs"),
            "podIP": status.get("podIP"),
            "podIPs": status.get("podIPs"),
            "startTime": status.get("startTime"),
            "reason": status.get("reason"),
            "message": str(status.get("message", ""))[:4096],
            "conditions": _conditions(status.get("conditions")),
            "containerStatuses": _container_statuses(status.get("containerStatuses")),
            "initContainerStatuses": _container_statuses(status.get("initContainerStatuses")),
        },
    }


def project_event(item):
    metadata = item.get("metadata", {}) or {}
    regarding = item.get("regarding") or item.get("involvedObject") or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "Event"),
        "metadata": {"name": metadata.get("name"), "namespace": metadata.get("namespace"), "uid": metadata.get("uid")},
        "type": item.get("type"),
        "reason": item.get("reason"),
        "note": str(item.get("note") or item.get("message") or "")[:8192],
        "regarding": {"apiVersion": regarding.get("apiVersion"), "kind": regarding.get("kind"), "namespace": regarding.get("namespace"), "name": regarding.get("name"), "uid": regarding.get("uid")},
        "reportingController": item.get("reportingController") or item.get("source", {}).get("component"),
        "reportingInstance": item.get("reportingInstance") or item.get("source", {}).get("host"),
        "eventTime": item.get("eventTime"),
        "firstTimestamp": item.get("firstTimestamp"),
        "lastTimestamp": item.get("lastTimestamp"),
        "count": item.get("count") or item.get("series", {}).get("count"),
    }


def project_workload(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "spec": {
            "replicas": spec.get("replicas"),
            "selector": _selector(spec.get("selector")),
            "updateStrategy": spec.get("updateStrategy"),
            "strategy": spec.get("strategy"),
        },
        "status": {
            key: status.get(key)
            for key in (
                "observedGeneration",
                "replicas",
                "readyReplicas",
                "availableReplicas",
                "updatedReplicas",
                "currentReplicas",
                "unavailableReplicas",
                "desiredNumberScheduled",
                "numberReady",
                "numberAvailable",
                "numberUnavailable",
                "numberMisscheduled",
                "currentNumberScheduled",
                "updatedNumberScheduled",
                "currentRevision",
                "updateRevision",
                "succeeded",
                "failed",
                "active",
                "conditions",
            )
            if key in status
        },
    }


def project_pdb(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "PodDisruptionBudget"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "spec": {
            "minAvailable": spec.get("minAvailable"),
            "maxUnavailable": spec.get("maxUnavailable"),
            "selector": _selector(spec.get("selector")),
        },
        "status": {
            key: status.get(key)
            for key in ("observedGeneration", "disruptionsAllowed", "currentHealthy", "desiredHealthy", "expectedPods")
            if key in status
        },
    }


def project_coredns_config(item):
    corefile = str((item.get("data") or {}).get("Corefile") or "")[:256 * 1024]
    plugins = set()
    forward_targets = []
    for raw_line in corefile.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line in ("{", "}") or line.endswith("{"):
            continue
        parts = line.split()
        plugin = parts[0]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", plugin):
            plugins.add(plugin)
        if plugin in ("forward", "proxy") and len(parts) >= 3:
            forward_targets.extend(parts[2:10])
    return {
        "metadata": _metadata(item.get("metadata")),
        "plugins": sorted(plugins),
        "forwardTargets": [str(value)[:512] for value in forward_targets[:32]],
        "corefilePresent": bool(corefile.strip()),
    }


def _pod_log_priority(pod):
    metadata = pod.get("metadata", {}) or {}
    status = pod.get("status", {}) or {}
    namespace = metadata.get("namespace") or ""
    name = metadata.get("name") or ""
    labels = metadata.get("labels", {}) or {}
    component_text = " ".join(str(value).lower() for value in list(labels.values()) + [name])
    system_priority = 4
    for index, component in enumerate(("kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler", "coredns", "kube-dns", "cilium", "csi")):
        if component in component_text:
            system_priority = index // 2
            break
    statuses = (status.get("initContainerStatuses", []) or []) + (status.get("containerStatuses", []) or [])
    unhealthy = status.get("phase") not in ("Running", "Succeeded") or any(
        item.get("ready") is False
        or item.get("state", {}).get("waiting")
        or ((item.get("restartCount") or 0) > 0)
        for item in statuses
    )
    return (0 if unhealthy else 1, system_priority, namespace, name)


def project_service(item):
    spec = item.get("spec", {}) or {}
    selector = spec.get("selector") or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "Service"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "spec": {
            "type": spec.get("type"),
            "clusterIP": spec.get("clusterIP"),
            "clusterIPs": spec.get("clusterIPs"),
            "ipFamilies": spec.get("ipFamilies"),
            "ipFamilyPolicy": spec.get("ipFamilyPolicy"),
            "externalTrafficPolicy": spec.get("externalTrafficPolicy"),
            "internalTrafficPolicy": spec.get("internalTrafficPolicy"),
            "selector": _selector({"matchLabels": selector}).get("matchLabels", {}),
            "selectorProjectionComplete": all(key in ALLOWED_POD_LABELS for key in selector),
            "ports": spec.get("ports"),
        },
    }


def project_endpoint_slice(item):
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "EndpointSlice"),
        "metadata": _metadata(item.get("metadata"), ("kubernetes.io/service-name",)),
        "addressType": item.get("addressType"),
        "ports": item.get("ports"),
        "endpoints": [
            {
                "addresses": endpoint.get("addresses"),
                "conditions": endpoint.get("conditions"),
                "hostname": endpoint.get("hostname"),
                "nodeName": endpoint.get("nodeName"),
                "zone": endpoint.get("zone"),
                "targetRef": {
                    key: (endpoint.get("targetRef") or {}).get(key)
                    for key in ("apiVersion", "kind", "namespace", "name", "uid")
                    if key in (endpoint.get("targetRef") or {})
                },
            }
            for endpoint in item.get("endpoints", []) or []
        ],
    }


def project_generic_status(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "spec": {
            key: spec.get(key)
            for key in ("storageClassName", "volumeName", "accessModes", "resources", "nodeName")
            if key in spec
        },
        "status": {
            key: (_conditions(status.get(key)) if key == "conditions" else status.get(key))
            for key in ("phase", "capacity", "accessModes", "conditions", "attached")
            if key in status
        },
    }


def project_api_service(item):
    spec = item.get("spec", {}) or {}
    service = spec.get("service", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "APIService"),
        "metadata": _metadata(item.get("metadata")),
        "spec": {
            "group": spec.get("group"),
            "version": spec.get("version"),
            "groupPriorityMinimum": spec.get("groupPriorityMinimum"),
            "versionPriority": spec.get("versionPriority"),
            "service": {key: service.get(key) for key in ("namespace", "name", "port") if key in service},
        },
        "status": {"conditions": _conditions((item.get("status") or {}).get("conditions"))},
    }


def project_lease(item):
    spec = item.get("spec", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "Lease"),
        "metadata": _metadata(item.get("metadata")),
        "spec": {
            key: spec.get(key)
            for key in ("holderIdentity", "leaseDurationSeconds", "acquireTime", "renewTime", "leaseTransitions")
            if key in spec
        },
    }


def project_volume_attachment(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    source = spec.get("source", {}) or {}

    def error(value):
        value = value or {}
        return {
            "time": value.get("time"),
            "message": str(value.get("message", ""))[:4096],
        } if value else None

    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "VolumeAttachment"),
        "metadata": _metadata(item.get("metadata")),
        "spec": {
            "attacher": spec.get("attacher"),
            "nodeName": spec.get("nodeName"),
            "source": {"persistentVolumeName": source.get("persistentVolumeName")},
        },
        "status": {
            "attached": status.get("attached"),
            "attachError": error(status.get("attachError")),
            "detachError": error(status.get("detachError")),
        },
    }


def project_pv(item):
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    claim = spec.get("claimRef", {}) or {}
    csi = spec.get("csi", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "PersistentVolume"),
        "metadata": _metadata(item.get("metadata")),
        "spec": {
            "storageClassName": spec.get("storageClassName"),
            "capacity": spec.get("capacity"),
            "accessModes": spec.get("accessModes"),
            "persistentVolumeReclaimPolicy": spec.get("persistentVolumeReclaimPolicy"),
            "claimRef": {key: claim.get(key) for key in ("namespace", "name", "uid") if key in claim},
            "csi": {key: csi.get(key) for key in ("driver", "fsType") if key in csi},
        },
        "status": {"phase": status.get("phase"), "reason": status.get("reason"), "message": str(status.get("message", ""))[:4096]},
    }


def project_csi_driver(item):
    spec = item.get("spec", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "CSIDriver"),
        "metadata": _metadata(item.get("metadata")),
        "spec": {
            key: spec.get(key)
            for key in ("attachRequired", "podInfoOnMount", "storageCapacity", "fsGroupPolicy", "volumeLifecycleModes")
            if key in spec
        },
    }


def project_csi_node(item):
    drivers = []
    for driver in (item.get("spec") or {}).get("drivers", []) or []:
        drivers.append(
            {
                "name": driver.get("name"),
                "topologyKeys": driver.get("topologyKeys"),
                "allocatable": {"count": (driver.get("allocatable") or {}).get("count")},
            }
        )
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "CSINode"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_NODE_LABELS),
        "spec": {"drivers": drivers},
    }


def project_storage_class(item):
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "StorageClass"),
        "metadata": _metadata(item.get("metadata")),
        "provisioner": item.get("provisioner"),
        "reclaimPolicy": item.get("reclaimPolicy"),
        "volumeBindingMode": item.get("volumeBindingMode"),
        "allowVolumeExpansion": item.get("allowVolumeExpansion"),
    }


def project_csi_storage_capacity(item):
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "CSIStorageCapacity"),
        "metadata": _metadata(item.get("metadata")),
        "storageClassName": item.get("storageClassName"),
        "capacity": item.get("capacity"),
        "maximumVolumeSize": item.get("maximumVolumeSize"),
    }


def project_network_policy(item):
    spec = item.get("spec", {}) or {}
    selector = spec.get("podSelector", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "NetworkPolicy"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "spec": {
            "podSelector": _selector(selector),
            "selectorProjectionComplete": all(key in ALLOWED_POD_LABELS for key in (selector.get("matchLabels") or {})),
            "policyTypes": spec.get("policyTypes"),
            "ingressRuleCount": len(spec.get("ingress", []) or []),
            "egressRuleCount": len(spec.get("egress", []) or []),
        },
    }


def project_cilium_endpoint(item):
    status = item.get("status", {}) or {}
    health = status.get("health", {}) or {}
    networking = status.get("networking", {}) or {}
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "CiliumEndpoint"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "status": {
            "state": status.get("state"),
            "health": {"overallHealth": health.get("overallHealth")},
            "networking": {"node": networking.get("node")},
            "identity": {"id": (status.get("identity") or {}).get("id")},
        },
    }


def project_cilium_node(item):
    status = item.get("status", {}) or {}
    operator_status = ((status.get("ipam") or {}).get("operator-status") or {})
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind", "CiliumNode"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_NODE_LABELS),
        "status": {
            "conditions": _conditions(status.get("conditions")),
            "health": str(status.get("health", ""))[:4096] if status.get("health") is not None else None,
            "ipam": {
                "operatorStatus": {
                    "error": str(operator_status.get("error", ""))[:4096],
                }
            },
        },
    }


def project_cilium_policy(item):
    status = item.get("status", {}) or {}
    nodes = []
    for node_name, node_status in sorted((status.get("nodes") or {}).items()):
        node_status = node_status or {}
        nodes.append(
            {
                "node": node_name,
                "enforcing": node_status.get("enforcing"),
                "ok": node_status.get("ok"),
                "error": str(node_status.get("error", ""))[:4096],
                "revision": node_status.get("revision"),
                "lastUpdated": node_status.get("lastUpdated"),
            }
        )
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": _metadata(item.get("metadata"), ALLOWED_POD_LABELS),
        "status": {"conditions": _conditions(status.get("conditions")), "nodes": nodes[:100]},
    }


def project_readyz(text):
    checks = []
    for line in text.splitlines()[:256]:
        match = re.search(r"\[([+-])\]([^ ]+)(?:\s+(.*))?$", line.strip())
        if match:
            checks.append(
                {
                    "name": match.group(2)[:256],
                    "status": "passed" if match.group(1) == "+" else "failed",
                    "message": str(match.group(3) or "")[:1024],
                }
            )
    return {"checks": checks, "lineCount": len(text.splitlines())}


def _project_list(payload, projector):
    return {
        "apiVersion": payload.get("apiVersion"),
        "kind": payload.get("kind"),
        "resourceVersion": (payload.get("metadata") or {}).get("resourceVersion"),
        "items": [projector(item) for item in payload.get("items", []) or []],
    }


class KubectlCollector:
    def __init__(self, kubeconfig=None, context=None, timeout_seconds=30, max_wire_bytes=64 * 1024 * 1024, progress=None):
        self.kubeconfig = kubeconfig
        self.context = context
        self.timeout_seconds = timeout_seconds
        self.max_wire_bytes = max_wire_bytes
        self.progress = progress

    def _emit_progress(self, source_id, status):
        if self.progress is not None:
            self.progress("detail", "kubernetes/{0}: {1}".format(source_id, status))

    def _base(self):
        argv = ["kubectl"]
        if self.kubeconfig:
            argv.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            argv.extend(["--context", self.context])
        return argv

    def _json_source(self, source_id, arguments, projector, required=True):
        result = run_process(self._base() + arguments, self.timeout_seconds, self.max_wire_bytes)
        base = {
            "id": source_id,
            "status": "collected" if result.returncode == 0 and not result.truncated and not result.timed_out else "failed",
            "returncode": result.returncode,
            "duration_ms": result.duration_ms,
            "truncated": result.truncated,
            "timed_out": result.timed_out,
            "error": result.error or result.stderr.decode("utf-8", errors="replace")[:4096] or None,
            "required": required,
        }
        if base["status"] != "collected":
            if result.timed_out:
                base["status"] = "timeout"
            elif result.truncated:
                base["status"] = "truncated"
            elif result.returncode is None:
                base["status"] = "unsupported"
            return base
        try:
            payload = json.loads(result.stdout.decode("utf-8"))
            base["data"] = projector(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            base["status"] = "malformed"
            base["error"] = str(error)
        return base

    def _text_source(self, source_id, arguments, projector, required=True):
        result = run_process(self._base() + arguments, self.timeout_seconds, min(self.max_wire_bytes, 1024 * 1024))
        text = result.stdout.decode("utf-8", errors="replace")
        diagnostic_text = text + "\n" + result.stderr.decode("utf-8", errors="replace")
        status = "collected" if result.returncode == 0 and not result.truncated and not result.timed_out else "failed"
        if result.timed_out:
            status = "timeout"
        elif result.truncated:
            status = "truncated"
        elif result.returncode is None:
            status = "unsupported"
        return {
            "id": source_id,
            "status": status,
            "required": required,
            "returncode": result.returncode,
            "duration_ms": result.duration_ms,
            "truncated": result.truncated,
            "timed_out": result.timed_out,
            "error": result.error or result.stderr.decode("utf-8", errors="replace")[:4096] or None,
            "data": projector(diagnostic_text),
        }

    def collect(self, system_namespaces, application_namespaces, collect_logs, log_tail_lines, max_log_pods, max_log_bytes):
        sources = {}
        specifications = (
            ("nodes", ["get", "nodes", "-o", "json"], project_node, True),
            ("pods", ["get", "pods", "--all-namespaces", "-o", "json"], project_pod, True),
            ("events", ["get", "events", "--all-namespaces", "-o", "json"], project_event, True),
            ("workloads", ["get", "deployments,statefulsets,daemonsets,jobs", "--all-namespaces", "-o", "json"], project_workload, True),
            ("services", ["get", "services", "--all-namespaces", "-o", "json"], project_service, True),
            ("endpoint_slices", ["get", "endpointslices.discovery.k8s.io", "--all-namespaces", "-o", "json"], project_endpoint_slice, True),
            ("pdb", ["get", "poddisruptionbudgets.policy", "--all-namespaces", "-o", "json"], project_pdb, True),
            ("pvc", ["get", "persistentvolumeclaims", "--all-namespaces", "-o", "json"], project_generic_status, True),
            ("pv", ["get", "persistentvolumes", "-o", "json"], project_pv, True),
            ("api_services", ["get", "apiservices.apiregistration.k8s.io", "-o", "json"], project_api_service, True),
            ("leases", ["get", "leases.coordination.k8s.io", "--all-namespaces", "-o", "json"], project_lease, True),
            ("volume_attachments", ["get", "volumeattachments.storage.k8s.io", "-o", "json"], project_volume_attachment, True),
            ("csi_drivers", ["get", "csidrivers.storage.k8s.io", "-o", "json"], project_csi_driver, True),
            ("csi_nodes", ["get", "csinodes.storage.k8s.io", "-o", "json"], project_csi_node, True),
            ("storage_classes", ["get", "storageclasses.storage.k8s.io", "-o", "json"], project_storage_class, True),
            ("csi_storage_capacities", ["get", "csistoragecapacities.storage.k8s.io", "--all-namespaces", "-o", "json"], project_csi_storage_capacity, False),
            ("network_policies", ["get", "networkpolicies.networking.k8s.io", "--all-namespaces", "-o", "json"], project_network_policy, True),
            ("cilium_nodes", ["get", "ciliumnodes.cilium.io", "-o", "json"], project_cilium_node, False),
            ("cilium_endpoints", ["get", "ciliumendpoints.cilium.io", "--all-namespaces", "-o", "json"], project_cilium_endpoint, False),
            ("cilium_network_policies", ["get", "ciliumnetworkpolicies.cilium.io", "--all-namespaces", "-o", "json"], project_cilium_policy, False),
            ("cilium_clusterwide_network_policies", ["get", "ciliumclusterwidenetworkpolicies.cilium.io", "-o", "json"], project_cilium_policy, False),
        )
        futures = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            for source_id, arguments, projector, required in specifications:
                future = executor.submit(
                    self._json_source,
                    source_id,
                    arguments,
                    lambda value, item_projector=projector: _project_list(value, item_projector),
                    required,
                )
                futures[future] = (source_id, required)
            readyz_future = executor.submit(self._text_source, "api_readyz", ["get", "--raw=/readyz?verbose"], project_readyz)
            futures[readyz_future] = ("api_readyz", True)
            cilium_config_future = executor.submit(
                self._json_source,
                "cilium_config",
                ["get", "configmap", "cilium-config", "--namespace", "kube-system", "-o", "json"],
                lambda value: {
                    "metadata": _metadata(value.get("metadata")),
                    "data": {key: (value.get("data") or {}).get(key) for key in ALLOWED_CILIUM_CONFIG_KEYS if key in (value.get("data") or {})},
                },
                False,
            )
            futures[cilium_config_future] = ("cilium_config", False)
            coredns_config_future = executor.submit(
                self._json_source,
                "coredns_config",
                ["get", "configmap", "coredns", "--namespace", "kube-system", "-o", "json"],
                project_coredns_config,
                False,
            )
            futures[coredns_config_future] = ("coredns_config", False)
            for future in as_completed(futures):
                source_id, required = futures[future]
                try:
                    sources[source_id] = future.result()
                except Exception as error:
                    sources[source_id] = {"id": source_id, "status": "failed", "required": required, "error": str(error)}
                self._emit_progress(source_id, sources[source_id].get("status"))
        logs = self._collect_logs(
            sources.get("pods", {}),
            sorted(set(system_namespaces) | set(application_namespaces)),
            log_tail_lines,
            max_log_pods,
            max_log_bytes,
        ) if collect_logs else {"status": "disabled", "entries": []}
        self._emit_progress("logs", logs.get("status"))
        return {
            "kind": "kubernetes_snapshot",
            "collected_at": utc_now(),
            "sensitivity": "confidential",
            "sources": sources,
            "logs": logs,
        }

    def _collect_logs(self, pods_source, namespaces, tail_lines, max_pods, max_total_bytes):
        if pods_source.get("status") != "collected":
            return {"status": "source_unavailable", "entries": [], "error": "pods source unavailable"}
        pods = pods_source.get("data", {}).get("items", [])
        selected = [pod for pod in pods if pod.get("metadata", {}).get("namespace") in set(namespaces)]
        selected.sort(key=_pod_log_priority)
        entries = []
        consumed = 0
        limited = len(selected) > max_pods
        for pod in selected[:max_pods]:
            namespace = pod.get("metadata", {}).get("namespace")
            name = pod.get("metadata", {}).get("name")
            regular_statuses = {item.get("name"): item for item in pod.get("status", {}).get("containerStatuses", [])}
            init_statuses = {item.get("name"): item for item in pod.get("status", {}).get("initContainerStatuses", [])}
            containers = [
                (container, regular_statuses.get(container.get("name"), {}), False)
                for container in pod.get("spec", {}).get("containers", [])
            ] + [
                (container, init_statuses.get(container.get("name"), {}), True)
                for container in pod.get("spec", {}).get("initContainers", [])
            ]
            for container, container_status, init_container in containers:
                container_name = container.get("name")
                if not namespace or not name or not container_name or consumed >= max_total_bytes:
                    limited = True
                    break
                for previous in (False, True):
                    if previous and not (container_status.get("restartCount") or 0):
                        continue
                    remaining = max_total_bytes - consumed
                    if remaining <= 0:
                        limited = True
                        break
                    argv = self._base() + [
                        "logs",
                        "--namespace",
                        namespace,
                        name,
                        "--container",
                        container_name,
                        "--tail",
                        str(tail_lines),
                        "--timestamps=true",
                    ]
                    if previous:
                        argv.append("--previous")
                    result = run_process(argv, self.timeout_seconds, min(remaining, 512 * 1024))
                    text = result.stdout.decode("utf-8", errors="replace")
                    consumed += len(result.stdout)
                    entries.append(
                        {
                            "namespace": namespace,
                            "pod": name,
                            "container": container_name,
                            "init_container": init_container,
                            "previous": previous,
                            "status": "collected" if result.returncode == 0 and not result.truncated else "failed",
                            "truncated": result.truncated,
                            "text": text,
                            "error": result.stderr.decode("utf-8", errors="replace")[:2000] if result.returncode else None,
                        }
                    )
        if limited or consumed >= max_total_bytes:
            status = "truncated"
        elif any(entry.get("status") != "collected" for entry in entries):
            status = "partial"
        else:
            status = "collected"
        return {"status": status, "entries": entries, "bytes": consumed, "selected_pods": len(selected)}


def collect_prometheus(url, timeout_seconds, max_response_bytes):
    if not url:
        return {"kind": "prometheus_snapshot", "status": "not_configured", "sources": {}}
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        return {"kind": "prometheus_snapshot", "status": "invalid_url", "sources": {}, "error": "only http/https URL is accepted"}
    base = url.rstrip("/")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    sources = {}
    for source_id, path in (("alerts", "/api/v1/alerts"), ("runtimeinfo", "/api/v1/status/runtimeinfo")):
        request = urllib.request.Request(base + path, method="GET", headers={"Accept": "application/json", "User-Agent": "kdiag/0.1"})
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                payload = response.read(max_response_bytes + 1)
            if len(payload) > max_response_bytes:
                sources[source_id] = {"status": "truncated", "error": "response exceeds limit"}
                continue
            document = json.loads(payload.decode("utf-8"))
            if source_id == "alerts":
                alerts = []
                for alert in document.get("data", {}).get("alerts", []) or []:
                    labels = alert.get("labels", {}) or {}
                    annotations = alert.get("annotations", {}) or {}
                    alerts.append(
                        {
                            "labels": {key: labels.get(key) for key in ("alertname", "severity", "namespace", "pod", "node", "job") if key in labels},
                            "annotations": {key: str(annotations.get(key, ""))[:4096] for key in ("summary", "description") if key in annotations},
                            "state": alert.get("state"),
                            "activeAt": alert.get("activeAt"),
                        }
                    )
                projected = {"alerts": alerts}
            else:
                data = document.get("data", {}) or {}
                projected = {key: data.get(key) for key in ("startTime", "CWD", "reloadConfigSuccess", "lastConfigTime", "corruptionCount") if key in data}
            sources[source_id] = {"status": "collected", "data": projected}
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            sources[source_id] = {"status": "unreachable", "error": str(error)}
    overall = "collected" if any(item.get("status") == "collected" for item in sources.values()) else "unreachable"
    return {"kind": "prometheus_snapshot", "status": overall, "collected_at": utc_now(), "sources": sources}
