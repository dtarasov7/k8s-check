import copy
import json
import os
import re
from pathlib import Path

from kdiag.bundle import verify_manifest, write_manifest
from kdiag.node_identity import match_node_identities
from kdiag.report import load_collection
from kdiag.util import (
    atomic_write_bytes,
    atomic_write_json,
    json_bytes,
    markdown_code,
    markdown_escape,
    sha256_bytes,
    utc_now,
)


BASELINE_SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPLICA_SET_SUFFIX_RE = re.compile(r"-[a-z0-9]{8,10}$")
GENERATED_POD_SUFFIX_RE = re.compile(r"-[a-z0-9]{8,10}-[a-z0-9]{5}$")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/[0-9]{1,3})?(?![0-9A-Fa-f:])")

VOLATILE_KEYS = frozenset(
    (
        "uid",
        "resourceversion",
        "creationtimestamp",
        "deletiontimestamp",
        "deletiongraceperiodseconds",
        "generation",
        "observedgeneration",
        "renewtime",
        "acquiretime",
        "eventtime",
        "firsttimestamp",
        "lasttimestamp",
        "lasttransitiontime",
        "startedat",
        "finishedat",
        "starttime",
        "collected_at",
        "started_at",
        "ended_at",
        "pid",
        "mainpid",
        "podip",
        "podips",
        "hostip",
        "hostips",
        "clusterip",
        "clusterips",
        "addresses",
        "podcidr",
        "podcidrs",
        "containerid",
        "imageid",
        "renewTime",
    )
)

KUBERNETES_PROFILE_SOURCES = (
    "nodes",
    "pods",
    "workloads",
    "services",
    "storage_classes",
    "csi_drivers",
    "csi_nodes",
    "coredns_config",
    "node_local_dns_config",
    "cilium_config",
)

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

CATEGORY_LABELS = {
    "new_problem": "новая проблема",
    "removed": "объект исчез",
    "added": "объект добавлен",
    "changed": "конфигурация изменилась",
    "resolved": "проблема устранена",
    "unverifiable": "не удалось проверить",
}

CATEGORY_ACTIONS = {
    "new_problem": "Открыть текущий report.json, проверить evidence правила и устранить причину.",
    "removed": "Проверить, было ли удаление запланировано; при необходимости восстановить объект.",
    "added": "Подтвердить, что объект добавлен в рамках согласованного изменения.",
    "changed": "Сопоставить изменённые поля с журналом изменений и подтвердить новую конфигурацию.",
    "resolved": "Подтвердить устойчивое устранение проблемы и отсутствие пробелов исходных данных.",
    "unverifiable": "Повторить сбор с доступным указанным источником; отсутствие данных не считать удалением.",
}


def _read_json(path, max_bytes=64 * 1024 * 1024):
    source_path = Path(path)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("JSON document is missing or is not a regular file: {0}".format(source_path))
    if source_path.stat().st_size > max_bytes:
        raise ValueError("JSON document exceeds size limit: {0}".format(source_path))
    try:
        with source_path.open("r", encoding="utf-8") as source:
            value = json.load(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON document {0}: {1}".format(source_path, error)) from error
    if not isinstance(value, dict):
        raise ValueError("JSON document root must be an object: {0}".format(source_path))
    return value


def _output_path(path, forbidden_root=None):
    destination = Path(path).resolve()
    if destination.exists():
        raise ValueError("refusing to overwrite existing file: {0}".format(destination))
    if forbidden_root is not None:
        root = Path(forbidden_root).resolve()
        if os.path.commonpath((str(root), str(destination))) == str(root):
            raise ValueError("baseline document must be stored outside the collection directory")
    return destination


def _clean_text(value):
    text = str(value or "")
    text = IPV4_RE.sub("<ip>", text)
    text = IPV6_RE.sub("<ip>", text)
    return text


def _stable_value(value):
    if isinstance(value, dict):
        return {
            str(key): _stable_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key).lower() not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_stable_value(item) for item in value]
    if isinstance(value, tuple):
        return [_stable_value(item) for item in value]
    if isinstance(value, str):
        return _clean_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _clean_text(value)


def _hash(value):
    return sha256_bytes(json_bytes(_stable_value(value)))


def _profile_object(key, kind, name, value):
    stable = _stable_value(value)
    return {
        "key": str(key),
        "kind": str(kind),
        "name": str(name),
        "sha256": _hash(stable),
        "value": stable,
    }


def _source(status, required, objects=None):
    return {
        "status": str(status or "missing"),
        "required": bool(required),
        "objects": sorted(objects or [], key=lambda item: item["key"]),
    }


def _metadata_name(item):
    metadata = item.get("metadata", {}) or {}
    return metadata.get("namespace"), metadata.get("name")


def _roles(labels):
    result = []
    for key in sorted(labels or {}):
        if key.startswith("node-role.kubernetes.io/"):
            result.append(key.split("/", 1)[1])
    return result


def _project_nodes(items):
    objects = []
    for item in items:
        metadata = item.get("metadata", {}) or {}
        status = item.get("status", {}) or {}
        node_info = status.get("nodeInfo", {}) or {}
        name = metadata.get("name")
        if not name:
            continue
        value = {
            "name": name,
            "roles": _roles(metadata.get("labels", {}) or {}),
            "kubelet_version": node_info.get("kubeletVersion"),
            "runtime_version": node_info.get("containerRuntimeVersion"),
            "operating_system": node_info.get("operatingSystem"),
            "os_image": node_info.get("osImage"),
            "architecture": node_info.get("architecture"),
            "kernel_version": node_info.get("kernelVersion"),
        }
        objects.append(_profile_object("node:{0}".format(name), "node", name, value))
    return objects


def _service_tags(namespace, name, labels):
    text = " ".join([str(namespace or ""), str(name or "")] + [str(value) for value in (labels or {}).values()]).lower()
    return ["dns"] if any(token in text for token in ("coredns", "kube-dns", "node-local-dns", "d8-kube-dns")) else []


def _project_services(items):
    objects = []
    for item in items:
        namespace, name = _metadata_name(item)
        if not name:
            continue
        metadata = item.get("metadata", {}) or {}
        spec = item.get("spec", {}) or {}
        ports = []
        for port in spec.get("ports", []) or []:
            ports.append(
                {
                    key: port.get(key)
                    for key in ("name", "port", "protocol", "targetPort", "appProtocol")
                    if key in port
                }
            )
        value = {
            "namespace": namespace,
            "name": name,
            "type": spec.get("type"),
            "external_name": spec.get("externalName"),
            "selector": spec.get("selector") or {},
            "ports": sorted(ports, key=lambda value: (str(value.get("name")), str(value.get("port")))),
            "tags": _service_tags(namespace, name, metadata.get("labels", {}) or {}),
        }
        display = "{0}/{1}".format(namespace or "default", name)
        objects.append(_profile_object("service:{0}".format(display), "service", display, value))
    return objects


def _project_workloads(items):
    objects = []
    for item in items:
        kind = item.get("kind")
        if kind not in ("Deployment", "StatefulSet", "DaemonSet"):
            continue
        namespace, name = _metadata_name(item)
        if not name:
            continue
        spec = item.get("spec", {}) or {}
        value = {
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "replicas": spec.get("replicas"),
            "selector": spec.get("selector") or {},
            "strategy": spec.get("strategy"),
            "update_strategy": spec.get("updateStrategy"),
        }
        display = "{0}/{1}/{2}".format(kind, namespace or "default", name)
        objects.append(_profile_object("workload:{0}".format(display), "workload", display, value))
    return objects


def _project_storage_classes(items):
    objects = []
    for item in items:
        _namespace, name = _metadata_name(item)
        if not name:
            continue
        value = {
            "name": name,
            "provisioner": item.get("provisioner"),
            "reclaim_policy": item.get("reclaimPolicy"),
            "volume_binding_mode": item.get("volumeBindingMode"),
            "allow_volume_expansion": item.get("allowVolumeExpansion"),
        }
        objects.append(_profile_object("storage_class:{0}".format(name), "storage_class", name, value))
    return objects


def _project_csi_drivers(items):
    objects = []
    for item in items:
        _namespace, name = _metadata_name(item)
        if not name:
            continue
        value = {"name": name, "spec": item.get("spec", {}) or {}}
        objects.append(_profile_object("csi_driver:{0}".format(name), "csi_driver", name, value))
    return objects


def _project_csi_nodes(items):
    objects = []
    for item in items:
        _namespace, name = _metadata_name(item)
        if not name:
            continue
        drivers = []
        for driver in (item.get("spec", {}) or {}).get("drivers", []) or []:
            drivers.append(
                {
                    "name": driver.get("name"),
                    "topology_keys": sorted(driver.get("topologyKeys") or []),
                    "allocatable_count": (driver.get("allocatable") or {}).get("count"),
                }
            )
        value = {"node": name, "drivers": sorted(drivers, key=lambda value: str(value.get("name")))}
        objects.append(_profile_object("csi_node:{0}".format(name), "csi_node", name, value))
    return objects


def _component_name(pod):
    metadata = pod.get("metadata", {}) or {}
    labels = metadata.get("labels", {}) or {}
    for key in ("app.kubernetes.io/name", "k8s-app", "component", "app"):
        if labels.get(key):
            return str(labels[key])
    owners = metadata.get("ownerReferences", []) or []
    controller = next((item for item in owners if item.get("controller") is True), owners[0] if owners else {})
    if controller.get("kind") == "Job":
        return None
    if controller.get("name"):
        if controller.get("kind") == "ReplicaSet":
            return REPLICA_SET_SUFFIX_RE.sub("", str(controller["name"]))
        return str(controller["name"])
    return GENERATED_POD_SUFFIX_RE.sub("", str(metadata.get("name") or ""))


def _component_role(component, namespace=None):
    text = str(component or "").lower()
    namespace_text = str(namespace or "").lower()
    if text == "etcd" or text.startswith("etcd-"):
        return "etcd"
    if any(value in text for value in ("kube-apiserver", "kube-controller-manager", "kube-scheduler", "control-plane-manager")):
        return "control_plane"
    if any(value in text for value in ("coredns", "kube-dns", "node-local-dns", "dns")):
        return "dns"
    if "cilium" in text or (text == "agent" and "cilium" in namespace_text):
        return "cilium"
    if "csi" in text:
        return "csi"
    return "system"


def _project_system_components(items):
    grouped = {}
    for pod in items:
        metadata = pod.get("metadata", {}) or {}
        namespace = str(metadata.get("namespace") or "default")
        if namespace != "kube-system" and not namespace.startswith("d8-"):
            continue
        component = _component_name(pod)
        if not component:
            continue
        spec = pod.get("spec", {}) or {}
        node = spec.get("nodeName") or "unscheduled"
        key = (namespace, component, node)
        grouped.setdefault(key, set())
        for container in (spec.get("containers", []) or []) + (spec.get("initContainers", []) or []):
            name = container.get("name")
            image = container.get("image")
            if name or image:
                grouped[key].add((str(name or ""), str(image or "")))
    objects = []
    for namespace, component, node in sorted(grouped):
        role = _component_role(component, namespace)
        value = {
            "namespace": namespace,
            "component": component,
            "node": node,
            "role": role,
            "containers": [
                {"name": name, "image": image}
                for name, image in sorted(grouped[(namespace, component, node)])
            ],
        }
        display = "{0}/{1}@{2}".format(namespace, component, node)
        objects.append(_profile_object("system_component:{0}".format(display), "system_component", display, value))
    return objects


def _project_config(source_id, source):
    if source.get("status") != "collected":
        return []
    data = source.get("data", {}) or {}
    metadata = data.get("metadata", {}) or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name") or source_id
    stable_data = {
        key: value
        for key, value in data.items()
        if key != "metadata"
    }
    value = {
        "namespace": namespace,
        "name": name,
        "configuration": stable_data,
        "configuration_sha256": _hash(stable_data),
    }
    display = "{0}/{1}".format(namespace or "cluster", name)
    return [_profile_object("config:{0}:{1}".format(source_id, display), "configuration", display, value)]


def _node_profile_sources(collection, nodes, kubernetes):
    result = {}
    kubernetes_nodes = ((kubernetes.get("sources", {}).get("nodes", {}).get("data", {}) or {}).get("items", []) or [])
    identities = match_node_identities(nodes, kubernetes_nodes)
    for item in collection.get("nodes", []) or []:
        alias = item.get("host")
        if not alias:
            continue
        snapshot = nodes.get(alias)
        status = item.get("status") or "missing"
        objects = []
        if status == "collected" and snapshot:
            facts = snapshot.get("facts", {}) or {}
            cgroup = facts.get("cgroup", {}) or {}
            if cgroup.get("status") == "disabled" or not cgroup.get("mode"):
                status = cgroup.get("status") or "missing"
            else:
                host = snapshot.get("host", {}) or {}
                os_release = host.get("os_release", {}) or {}
                file_hashes = [
                    {"path": value.get("path"), "sha256": value.get("sha256")}
                    for value in (facts.get("file_hashes", []) or [])
                    if value.get("path") and SHA256_RE.fullmatch(str(value.get("sha256") or ""))
                ]
                kubelet_values = (facts.get("kubelet_config", {}) or {}).get("values", {}) or {}
                canonical_name = identities.get(alias) or host.get("hostname") or alias
                value = {
                    "inventory_host": alias,
                    "node": canonical_name,
                    "os": {
                        "name": os_release.get("NAME"),
                        "pretty_name": os_release.get("PRETTY_NAME"),
                        "version_id": os_release.get("VERSION_ID"),
                    },
                    "architecture": host.get("machine"),
                    "kernel_release": host.get("kernel_release"),
                    "cgroup": {
                        "mode": cgroup.get("mode"),
                        "controllers": sorted(cgroup.get("controllers") or []),
                        "subtree_control": sorted(cgroup.get("subtree_control") or []),
                        "kubelet_driver": kubelet_values.get("cgroupDriver"),
                    },
                    "kubelet_configuration_sha256": _hash(kubelet_values),
                    "configuration_hashes": sorted(file_hashes, key=lambda value: str(value.get("path"))),
                }
                objects.append(_profile_object("node_configuration:{0}".format(canonical_name), "node_configuration", canonical_name, value))
        result["node/{0}".format(alias)] = _source(status, True, objects)
    return result


def _aggregate_findings(findings):
    grouped = {}
    for finding in findings or []:
        if finding.get("finding_status") != "active" or not finding.get("rule_id"):
            continue
        rule_id = str(finding["rule_id"])
        group = grouped.setdefault(rule_id, {"count": 0, "severities": set(), "roles": set()})
        group["count"] += 1
        group["severities"].add(str(finding.get("severity") or "info"))
        if finding.get("finding_role"):
            group["roles"].add(str(finding["finding_role"]))
    objects = []
    for rule_id, group in sorted(grouped.items()):
        severity = max(group["severities"], key=lambda value: SEVERITY_ORDER.get(value, -1))
        value = {
            "rule_id": rule_id,
            "severity": severity,
            "roles": sorted(group["roles"]),
            "occurrences": group["count"],
        }
        objects.append(_profile_object("finding:{0}".format(rule_id), "finding", rule_id, value))
    return objects


def _material_gaps(report, profile_sources):
    gaps = set()
    for item in report.get("coverage", []) or []:
        if item.get("required") and item.get("status") != "collected":
            gaps.add("{0}:{1}".format(item.get("source") or "unknown", item.get("status") or "missing"))
    for source_id, source in profile_sources.items():
        if source.get("required") and source.get("status") != "collected":
            gaps.add("{0}:{1}".format(source_id, source.get("status") or "missing"))
    return sorted(gaps)


def build_profile(collection_dir):
    root = Path(collection_dir).resolve()
    collection, nodes, kubernetes, _prometheus = load_collection(root)
    report = _read_json(root / "report.json")
    sources = {}

    projectors = {
        "nodes": _project_nodes,
        "pods": _project_system_components,
        "workloads": _project_workloads,
        "services": _project_services,
        "storage_classes": _project_storage_classes,
        "csi_drivers": _project_csi_drivers,
        "csi_nodes": _project_csi_nodes,
    }
    kubernetes_sources = kubernetes.get("sources", {}) or {}
    for source_id in KUBERNETES_PROFILE_SOURCES:
        raw_source = kubernetes_sources.get(source_id, {}) or {}
        status = raw_source.get("status") or "missing"
        required = raw_source.get("required", source_id not in ("coredns_config", "node_local_dns_config", "cilium_config"))
        if source_id in projectors and status == "collected":
            items = ((raw_source.get("data", {}) or {}).get("items", []) or [])
            objects = projectors[source_id](items)
        elif source_id in ("coredns_config", "node_local_dns_config", "cilium_config"):
            objects = _project_config(source_id, raw_source)
        else:
            objects = []
        sources["kubernetes/{0}".format(source_id)] = _source(status, required, objects)

    node_sources = _node_profile_sources(collection, nodes, kubernetes)
    sources.update(node_sources)
    sources["report/findings"] = _source("collected", True, _aggregate_findings(report.get("findings", [])))
    critical = [
        item["name"]
        for item in sources["report/findings"]["objects"]
        if item.get("value", {}).get("severity") == "critical"
    ]
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "sources": {key: sources[key] for key in sorted(sources)},
        "quality": {
            "active_critical_findings": sorted(critical),
            "material_gaps": _material_gaps(report, sources),
        },
    }


def _profile_sha256(profile):
    return sha256_bytes(json_bytes(profile))


def _validate_profile(profile):
    if not isinstance(profile, dict) or profile.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError("baseline profile has an unsupported schema")
    sources = profile.get("sources")
    quality = profile.get("quality")
    if not isinstance(sources, dict) or not isinstance(quality, dict):
        raise ValueError("baseline profile is missing sources or quality metadata")
    critical = []
    required_gaps = set()
    for source_id, source in sources.items():
        if not isinstance(source, dict) or not isinstance(source.get("objects"), list):
            raise ValueError("invalid baseline profile source: {0}".format(source_id))
        if source.get("required") and source.get("status") != "collected":
            required_gaps.add("{0}:{1}".format(source_id, source.get("status") or "missing"))
        seen = set()
        for item in source["objects"]:
            key = item.get("key") if isinstance(item, dict) else None
            digest = item.get("sha256") if isinstance(item, dict) else None
            if not isinstance(key, str) or not key or key in seen:
                raise ValueError("invalid or duplicate baseline object key in {0}".format(source_id))
            seen.add(key)
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest != _hash(item.get("value")):
                raise ValueError("baseline object SHA-256 mismatch: {0}".format(key))
            if item.get("kind") == "finding" and item.get("value", {}).get("severity") == "critical":
                critical.append(item.get("name"))
    if sorted(quality.get("active_critical_findings", []) or []) != sorted(critical):
        raise ValueError("baseline profile critical-finding summary mismatch")
    recorded_gaps = set(quality.get("material_gaps", []) or [])
    if not required_gaps.issubset(recorded_gaps):
        raise ValueError("baseline profile material-gap summary mismatch")


def create_candidate(collection_dir, name, output_path):
    baseline_name = str(name or "").strip()
    if not baseline_name or len(baseline_name) > 256 or any(ord(character) < 32 for character in baseline_name):
        raise ValueError("baseline name must be a non-empty printable string up to 256 characters")
    root = Path(collection_dir).resolve()
    verify_manifest(root)
    destination = _output_path(output_path, forbidden_root=root)
    collection = _read_json(root / "collection.json")
    profile = build_profile(root)
    candidate = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": "kdiag_baseline_candidate",
        "name": baseline_name,
        "created_at": utc_now(),
        "source_collection_id": collection.get("collection_id"),
        "source_collector_version": collection.get("collector_version"),
        "integrity": {
            "hash_algorithm": "sha256",
            "profile_sha256": _profile_sha256(profile),
        },
        "profile": profile,
    }
    atomic_write_json(destination, candidate)
    return candidate


def _validate_candidate(document):
    if document.get("schema_version") != BASELINE_SCHEMA_VERSION or document.get("kind") != "kdiag_baseline_candidate":
        raise ValueError("document is not a supported baseline candidate")
    integrity = document.get("integrity", {}) or {}
    expected = integrity.get("profile_sha256")
    if integrity.get("hash_algorithm") != "sha256" or not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise ValueError("candidate has invalid profile SHA-256")
    actual = _profile_sha256(document.get("profile"))
    if actual != expected:
        raise ValueError("candidate profile SHA-256 mismatch")
    _validate_profile(document.get("profile"))
    return document


def _document_sha256(document):
    payload = copy.deepcopy(document)
    integrity = payload.get("integrity", {}) or {}
    integrity.pop("document_sha256", None)
    payload["integrity"] = integrity
    return sha256_bytes(json_bytes(payload))


def approve_candidate(candidate_path, approved_by, output_path, override_unsafe=False):
    author = str(approved_by or "").strip()
    if not author or len(author) > 256 or any(ord(character) < 32 for character in author):
        raise ValueError("approved-by must be a non-empty printable string up to 256 characters")
    candidate = _validate_candidate(_read_json(candidate_path))
    destination = _output_path(output_path)
    quality = (candidate.get("profile", {}) or {}).get("quality", {}) or {}
    critical = quality.get("active_critical_findings", []) or []
    gaps = quality.get("material_gaps", []) or []
    reasons = []
    if critical:
        reasons.append("active critical findings: {0}".format(", ".join(str(value) for value in critical)))
    if gaps:
        reasons.append("material collection gaps: {0}".format(", ".join(str(value) for value in gaps)))
    if reasons and not override_unsafe:
        raise ValueError("baseline approval is blocked; use --override-unsafe explicitly: {0}".format("; ".join(reasons)))

    approved = copy.deepcopy(candidate)
    approved["kind"] = "kdiag_approved_baseline"
    approved["approval"] = {
        "approved_by": author,
        "approved_at": utc_now(),
        "unsafe_override": bool(override_unsafe),
        "override_reasons": reasons if override_unsafe else [],
    }
    approved["integrity"]["document_sha256"] = _document_sha256(approved)
    atomic_write_json(destination, approved)
    return approved


def verify_approved_baseline(path):
    document = _read_json(path)
    canonical = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if Path(path).read_bytes() != canonical:
        raise ValueError("approved baseline file is not in its canonical hashed representation")
    if document.get("schema_version") != BASELINE_SCHEMA_VERSION or document.get("kind") != "kdiag_approved_baseline":
        raise ValueError("comparison requires an approved baseline")
    integrity = document.get("integrity", {}) or {}
    expected_profile = integrity.get("profile_sha256")
    expected_document = integrity.get("document_sha256")
    if integrity.get("hash_algorithm") != "sha256":
        raise ValueError("approved baseline uses an unsupported hash algorithm")
    if not isinstance(expected_profile, str) or not SHA256_RE.fullmatch(expected_profile):
        raise ValueError("approved baseline has invalid profile SHA-256")
    if not isinstance(expected_document, str) or not SHA256_RE.fullmatch(expected_document):
        raise ValueError("approved baseline has invalid document SHA-256")
    if _profile_sha256(document.get("profile")) != expected_profile:
        raise ValueError("approved baseline profile SHA-256 mismatch")
    _validate_profile(document.get("profile"))
    if _document_sha256(document) != expected_document:
        raise ValueError("approved baseline document SHA-256 mismatch")
    approval = document.get("approval", {}) or {}
    if not approval.get("approved_by") or not approval.get("approved_at"):
        raise ValueError("approved baseline is missing approval metadata")
    quality = (document.get("profile", {}) or {}).get("quality", {}) or {}
    has_blockers = bool(quality.get("active_critical_findings") or quality.get("material_gaps"))
    if has_blockers and not approval.get("unsafe_override"):
        raise ValueError("approved baseline contains blockers without an unsafe override")
    if approval.get("unsafe_override") and not approval.get("override_reasons"):
        raise ValueError("approved baseline unsafe override has no recorded reasons")
    return document


def _changed_paths(before, after, prefix=""):
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        for key in sorted(set(before) | set(after)):
            child = "{0}.{1}".format(prefix, key) if prefix else str(key)
            if key not in before or key not in after:
                result.append(child)
            else:
                result.extend(_changed_paths(before[key], after[key], child))
        return result
    if before != after:
        return [prefix or "value"]
    return []


def _change(category, source_id, item=None, before=None, after=None, **extra):
    selected = item or after or before or {}
    result = {
        "category": category,
        "source": source_id,
        "object_kind": selected.get("kind"),
        "object_key": selected.get("key"),
        "object_name": selected.get("name"),
        "before_sha256": before.get("sha256") if before else None,
        "after_sha256": after.get("sha256") if after else None,
        "meaning_ru": CATEGORY_LABELS[category],
        "recommended_action_ru": CATEGORY_ACTIONS[category],
    }
    result.update(extra)
    return result


def compare_profiles(baseline, current_profile, collection_id=None):
    baseline_profile = baseline.get("profile", {}) or {}
    baseline_sources = baseline_profile.get("sources", {}) or {}
    current_sources = current_profile.get("sources", {}) or {}
    changes = []
    for source_id in sorted(set(baseline_sources) | set(current_sources)):
        before_source = baseline_sources.get(source_id)
        after_source = current_sources.get(source_id)
        before_status = (before_source or {}).get("status") or "missing"
        after_status = (after_source or {}).get("status") or "missing"
        if before_status != "collected" or after_status != "collected":
            if (
                before_status != "collected"
                and after_status != "collected"
                and not (before_source or {}).get("required")
                and not (after_source or {}).get("required")
            ):
                continue
            changes.append(
                _change(
                    "unverifiable",
                    source_id,
                    baseline_status=before_status,
                    current_status=after_status,
                    missing_source=source_id,
                )
            )
            continue
        before_items = {item["key"]: item for item in before_source.get("objects", []) or []}
        after_items = {item["key"]: item for item in after_source.get("objects", []) or []}
        for key in sorted(set(before_items) | set(after_items)):
            before = before_items.get(key)
            after = after_items.get(key)
            if before is None:
                category = "new_problem" if after.get("kind") == "finding" else "added"
                changes.append(_change(category, source_id, item=after, after=after))
            elif after is None:
                category = "resolved" if before.get("kind") == "finding" else "removed"
                changes.append(_change(category, source_id, item=before, before=before))
            elif before.get("sha256") != after.get("sha256"):
                changes.append(
                    _change(
                        "changed",
                        source_id,
                        item=after,
                        before=before,
                        after=after,
                        changed_fields=_changed_paths(before.get("value"), after.get("value"))[:100],
                    )
                )
    counts = {category: 0 for category in CATEGORY_LABELS}
    for change in changes:
        counts[change["category"]] += 1
    if counts["unverifiable"]:
        status = "incomplete"
    elif changes:
        status = "changes_detected"
    else:
        status = "no_changes"
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": "kdiag_baseline_comparison",
        "generated_at": utc_now(),
        "collection_id": collection_id,
        "baseline": {
            "name": baseline.get("name"),
            "source_collection_id": baseline.get("source_collection_id"),
            "approved_by": (baseline.get("approval", {}) or {}).get("approved_by"),
            "approved_at": (baseline.get("approval", {}) or {}).get("approved_at"),
            "unsafe_override": bool((baseline.get("approval", {}) or {}).get("unsafe_override")),
            "override_reasons": (baseline.get("approval", {}) or {}).get("override_reasons", []) or [],
            "profile_sha256": (baseline.get("integrity", {}) or {}).get("profile_sha256"),
            "document_sha256": (baseline.get("integrity", {}) or {}).get("document_sha256"),
        },
        "status": status,
        "summary": counts,
        "missing_sources": sorted(
            {change["missing_source"] for change in changes if change["category"] == "unverifiable"}
        ),
        "changes": changes,
    }


def comparison_markdown(comparison):
    status_text = {
        "no_changes": "изменений не обнаружено",
        "changes_detected": "обнаружены изменения",
        "incomplete": "часть сравнения выполнить невозможно",
    }.get(comparison.get("status"), str(comparison.get("status") or "неизвестно"))
    baseline = comparison.get("baseline", {}) or {}
    lines = [
        "# Сравнение с утверждённым baseline",
        "",
        "Коллекция: {0}.".format(markdown_code(comparison.get("collection_id") or "неизвестно")),
        "",
        "Baseline: **{0}**, утверждён: {1} ({2}).".format(
            markdown_escape(baseline.get("name") or "без имени"),
            markdown_escape(baseline.get("approved_by") or "неизвестно"),
            markdown_escape(baseline.get("approved_at") or "время неизвестно"),
        ),
        "",
        "Результат: **{0}**.".format(markdown_escape(status_text)),
        "",
        "| Категория | Количество |",
        "|---|---:|",
    ]
    summary = comparison.get("summary", {}) or {}
    for category in CATEGORY_LABELS:
        lines.append("| {0} | {1} |".format(CATEGORY_LABELS[category], summary.get(category, 0)))
    if baseline.get("unsafe_override"):
        lines.extend(
            [
                "",
                "Внимание: baseline утверждён с `--override-unsafe`. Причины: {0}.".format(
                    markdown_escape("; ".join(str(value) for value in baseline.get("override_reasons", [])) or "не указаны")
                ),
            ]
        )
    changes = comparison.get("changes", []) or []
    if not changes:
        lines.extend(
            [
                "",
                "Устойчивые признаки совпадают с утверждённым baseline.",
                "",
                "Рекомендуемое действие: сохранить результат как подтверждение проверки; новый baseline автоматически не создавать.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "## Изменения и действия",
                "",
                "| Тип | Объект или источник | Значение | Рекомендуемое действие |",
                "|---|---|---|---|",
            ]
        )
        for change in changes[:500]:
            target = change.get("object_name") or change.get("missing_source") or change.get("source")
            meaning = change.get("meaning_ru") or CATEGORY_LABELS.get(change.get("category"), "изменение")
            if change.get("category") == "unverifiable":
                meaning = "{0}: baseline={1}, новая коллекция={2}".format(
                    meaning,
                    change.get("baseline_status"),
                    change.get("current_status"),
                )
            elif change.get("changed_fields"):
                meaning = "{0}; поля: {1}".format(meaning, ", ".join(change["changed_fields"][:20]))
            lines.append(
                "| {0} | {1} | {2} | {3} |".format(
                    markdown_escape(CATEGORY_LABELS.get(change.get("category"), change.get("category"))),
                    markdown_code(target or "неизвестно"),
                    markdown_escape(meaning),
                    markdown_escape(change.get("recommended_action_ru") or "Проверить изменение."),
                )
            )
        if len(changes) > 500:
            lines.extend(["", "В Markdown не показано изменений: {0}; полный список находится в `baseline-comparison.json`.".format(len(changes) - 500)])
    if comparison.get("missing_sources"):
        lines.extend(
            [
                "",
                "Отсутствующий источник означает только невозможность проверки. Объекты из него не помечаются удалёнными.",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def compare_collection(collection_dir, baseline_path, verify_collection_integrity=True, update_collection_manifest=True):
    root = Path(collection_dir).resolve()
    if verify_collection_integrity:
        verify_manifest(root)
    baseline = verify_approved_baseline(baseline_path)
    collection = _read_json(root / "collection.json")
    current_profile = build_profile(root)
    comparison = compare_profiles(baseline, current_profile, collection_id=collection.get("collection_id"))
    json_path = root / "baseline-comparison.json"
    markdown_path = root / "baseline-comparison.md"
    atomic_write_json(json_path, comparison)
    atomic_write_bytes(markdown_path, comparison_markdown(comparison).encode("utf-8"))
    if update_collection_manifest:
        write_manifest(root)
    return {"comparison": comparison, "json": json_path, "markdown": markdown_path}
