import glob
import json
import os
import platform
import re
import shutil
import socket
import stat
from pathlib import Path

from kdiag import __version__
from kdiag.runner import run_check, run_process
from kdiag.runtime import RUNTIME_SERVICE_UNITS
from kdiag.util import SCHEMA_VERSION, sha256_file, utc_now


PACKAGE_PREFIXES = (
    "kernel",
    "kubelet",
    "kubectl",
    "kubernetes",
    "containerd",
    "cri-o",
    "crio",
    "runc",
    "cilium",
    "kesl",
    "kaspersky",
    "systemd",
    "iproute",
)

SERVICE_UNITS = ("kubelet.service",) + RUNTIME_SERVICE_UNITS + (
    "NetworkManager.service",
    "kesl.service",
    "kesl-supervisor.service",
)

HASH_PATTERNS = (
    "/var/lib/kubelet/config.yaml",
    "/etc/kubernetes/kubelet.conf",
    "/etc/kubernetes/manifests/*.yaml",
    "/etc/kubernetes/manifests/*.yml",
    "/etc/cni/net.d/*",
    "/etc/systemd/system/kubelet.service.d/*",
    "/usr/lib/systemd/system/kubelet.service",
    "/usr/lib/systemd/system/containerd.service",
    "/etc/systemd/system/containerd.service",
    "/etc/systemd/system/containerd.service.d/*",
    "/usr/lib/systemd/system/containerd-deckhouse.service",
    "/etc/systemd/system/containerd-deckhouse.service",
    "/etc/systemd/system/containerd-deckhouse.service.d/*",
    "/usr/lib/systemd/system/crio.service",
    "/etc/systemd/system/crio.service",
    "/etc/systemd/system/crio.service.d/*",
    "/etc/containerd/config.toml",
    "/etc/crio/crio.conf",
)

SYSCTL_PREFIXES = (
    "net.ipv6.",
    "net.ipv4.ip_forward",
    "net.bridge.bridge-nf-call-",
    "kernel.pid_max",
    "vm.overcommit_",
    "fs.inotify.",
)

KUBELET_CONFIG_KEYS = (
    "cgroupDriver",
    "clusterDNS",
    "clusterDomain",
    "containerLogMaxFiles",
    "containerLogMaxSize",
    "failSwapOn",
    "maxPods",
    "podPidsLimit",
    "protectKernelDefaults",
    "resolvConf",
    "rotateCertificates",
    "serializeImagePulls",
    "staticPodPath",
)

ETCD_MANIFEST = "/etc/kubernetes/manifests/etcd.yaml"
ETCD_CA = "/etc/kubernetes/pki/etcd/ca.crt"
ETCD_CERT = "/etc/kubernetes/pki/etcd/healthcheck-client.crt"
ETCD_KEY = "/etc/kubernetes/pki/etcd/healthcheck-client.key"
AUTHENTICATION_CONFIG_PATHS = (
    "/etc/kubernetes/deckhouse/extra-files/authentication-config.yaml",
)


def _read_text(path, max_bytes=1024 * 1024):
    try:
        with open(path, "rb") as source:
            payload = source.read(max_bytes + 1)
    except (FileNotFoundError, PermissionError, OSError) as error:
        return {"status": "unavailable", "error": str(error)}
    truncated = len(payload) > max_bytes
    return {
        "status": "truncated" if truncated else "collected",
        "text": payload[:max_bytes].decode("utf-8", errors="replace"),
        "truncated": truncated,
    }


def _os_release():
    result = _read_text("/etc/os-release", 64 * 1024)
    values = {}
    if result.get("text"):
        for line in result["text"].splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def _boot_id():
    result = _read_text("/proc/sys/kernel/random/boot_id", 256)
    return result.get("text", "").strip() or None


def _authentication_config_files(paths=AUTHENTICATION_CONFIG_PATHS):
    result = []
    for path in paths:
        item = {"path": str(path), "status": "absent"}
        try:
            file_stat = os.stat(path)
        except FileNotFoundError:
            result.append(item)
            continue
        except OSError as error:
            item.update({"status": "unavailable", "error": str(error)[:1024]})
            result.append(item)
            continue
        item.update(
            {
                "status": "present",
                "regular_file": stat.S_ISREG(file_stat.st_mode),
                "readable": os.access(path, os.R_OK),
                "size_bytes": file_stat.st_size,
                "mode": "{0:04o}".format(stat.S_IMODE(file_stat.st_mode)),
                "uid": file_stat.st_uid,
                "gid": file_stat.st_gid,
                "mtime_ns": file_stat.st_mtime_ns,
            }
        )
        result.append(item)
    return result


def _ipv6_disable_values():
    values = {}
    root = Path("/proc/sys/net/ipv6/conf")
    if not root.is_dir():
        return values
    for path in sorted(root.glob("*/disable_ipv6")):
        result = _read_text(str(path), 64)
        if result.get("status") == "collected":
            values[path.parent.name] = result.get("text", "").strip()
    return values


def _cgroup_facts():
    root = Path("/sys/fs/cgroup")
    controllers = _read_text(str(root / "cgroup.controllers"), 64 * 1024)
    subtree = _read_text(str(root / "cgroup.subtree_control"), 64 * 1024)
    if controllers.get("status") == "collected":
        mode = "v2"
    elif Path("/sys/fs/cgroup/unified").exists():
        mode = "hybrid"
    else:
        mode = "v1_or_unknown"
    return {
        "mode": mode,
        "controllers": controllers.get("text", "").split(),
        "subtree_control": subtree.get("text", "").split(),
        "proc_cgroups": _read_text("/proc/cgroups", 256 * 1024),
        "mountinfo": _read_text("/proc/self/mountinfo", 1024 * 1024),
    }


def _allowlisted_top_level_config(path, allowed_keys):
    source = _read_text(path, 1024 * 1024)
    result = {"status": source.get("status"), "values": {}}
    if source.get("status") not in ("collected", "truncated"):
        result["error"] = source.get("error")
        return result
    allowed = set(allowed_keys)
    list_key = None
    for line in source.get("text", "").splitlines():
        stripped = line.strip()
        if list_key and stripped.startswith("- "):
            result["values"][list_key].append(stripped[2:].split(" #", 1)[0].strip().strip("'\""))
            continue
        if not line or line[0].isspace() or stripped.startswith("#") or ":" not in line:
            list_key = None
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        list_key = None
        if key not in allowed:
            continue
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if not value and key == "clusterDNS":
            result["values"][key] = []
            list_key = key
        else:
            result["values"][key] = value
    return result


def _root_disk():
    usage = shutil.disk_usage("/")
    return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}


def _command_specs(since_hours):
    since = "{0} hours ago".format(since_hours)
    journal_units = []
    for unit in SERVICE_UNITS:
        journal_units.extend(["-u", unit])
    return [
        ("uname", ["uname", "-a"], "internal"),
        ("installed_packages", ["rpm", "-qa", "--qf", "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\\n"], "internal"),
        ("dnf_history", ["dnf", "history", "list"], "internal"),
        ("ip_addr", ["ip", "-j", "addr", "show"], "confidential"),
        ("ip_route", ["ip", "-j", "route", "show", "table", "all"], "confidential"),
        ("ip_rule", ["ip", "-j", "rule", "show"], "confidential"),
        ("ip_link", ["ip", "-j", "link", "show"], "confidential"),
        ("listeners", ["ss", "-H", "-lntup"], "confidential"),
        ("findmnt", ["findmnt", "-J"], "internal"),
        ("df_blocks", ["df", "-P"], "internal"),
        ("df_inodes", ["df", "-Pi"], "internal"),
        ("timedatectl", ["timedatectl", "show", "--no-pager"], "internal"),
        ("chrony_tracking", ["chronyc", "tracking"], "internal"),
        ("getenforce", ["getenforce"], "internal"),
        ("audit_avc", ["ausearch", "-m", "AVC,USER_AVC", "-ts", "recent"], "confidential"),
        ("runtime_crictl_info", ["crictl", "info"], "confidential"),
        ("runtime_crictl_pods", ["crictl", "pods", "-o", "json"], "confidential"),
        ("runtime_crictl_containers", ["crictl", "ps", "-a", "-o", "json"], "confidential"),
        ("runtime_crictl_version", ["crictl", "version"], "internal"),
        ("runtime_containerd_version", ["containerd", "--version"], "internal"),
        ("runtime_crio_version", ["crio", "--version"], "internal"),
        ("runtime_runc_version", ["runc", "--version"], "internal"),
        ("cilium_status", ["cilium", "status", "--output", "json"], "internal"),
        ("cilium_debug_status", ["cilium-dbg", "status", "--output", "json"], "internal"),
        ("cilium_services", ["cilium", "service", "list", "--output", "json"], "confidential"),
        ("cilium_debug_services", ["cilium-dbg", "service", "list", "--output", "json"], "confidential"),
        ("conntrack_stats", ["conntrack", "-S"], "internal"),
        ("nft_ruleset", ["nft", "-j", "list", "ruleset"], "confidential"),
        ("iptables_rules", ["iptables-save"], "confidential"),
        ("journal_boots", ["journalctl", "--list-boots", "--no-pager"], "internal"),
        (
            "journal_services_current",
            ["journalctl", "--no-pager", "--utc", "--reverse", "-o", "json", "--since", since] + journal_units,
            "confidential",
        ),
        (
            "journal_services_previous",
            ["journalctl", "--no-pager", "--utc", "-o", "json", "-b", "-1", "-n", "2000"] + journal_units,
            "confidential",
        ),
        ("journal_kernel_current", ["journalctl", "--no-pager", "--utc", "--reverse", "-o", "json", "-k", "--since", since], "confidential"),
        ("journal_kernel_previous", ["journalctl", "--no-pager", "--utc", "-o", "json", "-k", "-b", "-1", "-n", "2000"], "confidential"),
    ]


def _project_cri_records(record, source_key):
    if not record.get("stdout") or record.get("status") != "collected":
        return record
    try:
        document = json.loads(record["stdout"])
    except (TypeError, ValueError):
        projected = dict(record)
        projected["status"] = "malformed"
        projected["error"] = "crictl returned malformed JSON"
        projected["stdout"] = ""
        return projected
    values = document.get(source_key, []) if isinstance(document, dict) else []
    projected_values = []
    for value in values[:2000] if isinstance(values, list) else []:
        metadata = value.get("metadata", {}) or {}
        image = value.get("image", {}) or {}
        projected_values.append(
            {
                "id": value.get("id"),
                "podSandboxId": value.get("podSandboxId"),
                "metadata": {key: metadata.get(key) for key in ("name", "namespace", "uid", "attempt") if key in metadata},
                "image": {"image": image.get("image")},
                "imageRef": value.get("imageRef"),
                "state": value.get("state"),
                "createdAt": value.get("createdAt"),
            }
        )
    projected = dict(record)
    projected["stdout"] = json.dumps({source_key: projected_values}, ensure_ascii=False, separators=(",", ":"))
    projected["truncated"] = len(values) > len(projected_values) if isinstance(values, list) else False
    return projected


def _project_cilium_services(record):
    if not record.get("stdout") or record.get("status") != "collected":
        return record
    try:
        document = json.loads(record["stdout"])
    except (TypeError, ValueError):
        projected = dict(record)
        projected["status"] = "malformed"
        projected["error"] = "Cilium returned malformed service JSON"
        projected["stdout"] = ""
        return projected
    values = document if isinstance(document, list) else (document.get("services", []) if isinstance(document, dict) else [])
    services = []
    for value in values[:10000] if isinstance(values, list) else []:
        frontend = value.get("frontend-address") or value.get("frontendAddress") or value.get("frontend") or {}
        backends = value.get("backend-addresses") or value.get("backendAddresses") or value.get("backends") or []
        services.append(
            {
                "id": value.get("id"),
                "name": str(value.get("name") or "")[:512],
                "type": value.get("type"),
                "frontend": {key: frontend.get(key) for key in ("ip", "port", "protocol", "scope") if key in frontend},
                "backends": [
                    {key: backend.get(key) for key in ("ip", "port", "protocol", "state") if key in backend}
                    for backend in backends[:1000]
                    if isinstance(backend, dict)
                ],
            }
        )
    projected = dict(record)
    projected["stdout"] = json.dumps({"services": services}, ensure_ascii=False, separators=(",", ":"))
    projected["truncated"] = len(values) > len(services) if isinstance(values, list) else False
    return projected


def _cilium_container_fallback(commands, timeout_seconds, max_command_bytes):
    command_by_id = {item.get("id"): item for item in commands or []}
    status_available = any(
        command_by_id.get(command_id, {}).get("status") == "collected"
        for command_id in ("cilium_debug_status", "cilium_status")
    )
    services_available = any(
        command_by_id.get(command_id, {}).get("status") == "collected"
        for command_id in ("cilium_debug_services", "cilium_services")
    )
    if status_available and services_available:
        return []
    crictl = shutil.which("crictl")
    pods_record = command_by_id.get("runtime_crictl_pods", {})
    runtime_record = command_by_id.get("runtime_crictl_containers", {})
    if not crictl or runtime_record.get("status") != "collected":
        return []
    try:
        containers = json.loads(runtime_record.get("stdout", "")).get("containers", [])
    except (AttributeError, TypeError, ValueError):
        return []
    pod_sandboxes = {}
    if pods_record.get("status") == "collected":
        try:
            pods = json.loads(pods_record.get("stdout", "")).get("items", [])
        except (AttributeError, TypeError, ValueError):
            pods = []
        for pod in pods if isinstance(pods, list) else []:
            metadata = pod.get("metadata", {}) or {}
            sandbox_id = str(pod.get("id") or "")
            namespace = str(metadata.get("namespace") or "")
            pod_name = str(metadata.get("name") or "")
            if sandbox_id:
                pod_sandboxes[sandbox_id] = (namespace, pod_name)
    candidates = []
    for container in containers if isinstance(containers, list) else []:
        metadata = container.get("metadata", {}) or {}
        name = str(metadata.get("name") or "").lower()
        container_id = str(container.get("id") or "")
        sandbox_id = str(container.get("podSandboxId") or "")
        namespace, pod_name = pod_sandboxes.get(sandbox_id, ("", ""))
        recognized_pod = (
            namespace == "kube-system" and pod_name.startswith("cilium-")
        ) or (
            namespace == "d8-cni-cilium" and pod_name.startswith("agent-")
        )
        state = str(container.get("state") or "").lower()
        if (
            (recognized_pod or name == "cilium" or "cilium-agent" in name)
            and state in ("container_running", "running")
            and re.fullmatch(r"[A-Za-z0-9_.:-]{8,256}", container_id)
        ):
            candidates.append((0 if recognized_pod else 1, namespace, pod_name, container_id, name))
    if not candidates:
        return []

    _priority, namespace, pod_name, container_id, container_name = sorted(candidates)[0]
    specifications = []
    if not status_available:
        specifications.append(("cilium_debug_status", ["status", "--output", "json"], "internal", False))
    if not services_available:
        specifications.append(("cilium_debug_services", ["service", "list", "--output", "json"], "confidential", True))
    replacements = []
    for command_id, arguments, sensitivity, project_services in specifications:
        for binary in (
            "cilium-dbg",
            "/usr/bin/cilium-dbg",
            "/bin/cilium-dbg",
            "cilium-debug",
            "/usr/bin/cilium-debug",
            "cilium",
            "/usr/bin/cilium",
            "/bin/cilium",
        ):
            result = run_process(
                [crictl, "exec", container_id, binary] + arguments,
                min(timeout_seconds, 15),
                max_command_bytes,
            )
            record = result.record(command_id, sensitivity=sensitivity)
            if record.get("status") != "collected":
                continue
            try:
                json.loads(record.get("stdout", ""))
            except (TypeError, ValueError):
                continue
            record["transport"] = "crictl"
            record["container"] = container_name
            record["binary"] = binary
            record["pod"] = "{0}/{1}".format(namespace, pod_name) if namespace and pod_name else None
            replacements.append(_project_cilium_services(record) if project_services else record)
            break
    return replacements


def _apply_cilium_fallback(commands, replacements):
    result = list(commands)
    equivalent_ids = {
        "cilium_debug_status": {"cilium_debug_status", "cilium_status"},
        "cilium_debug_services": {"cilium_debug_services", "cilium_services"},
    }
    for replacement in replacements:
        superseded = equivalent_ids.get(replacement.get("id"), {replacement.get("id")})
        result = [item for item in result if item.get("id") not in superseded]
        result.append(replacement)
    return result


def _filtered_command(record):
    if record.get("id") != "installed_packages" or not record.get("stdout"):
        if record.get("id") == "runtime_crictl_pods":
            return _project_cri_records(record, "items")
        if record.get("id") == "runtime_crictl_containers":
            return _project_cri_records(record, "containers")
        if record.get("id") in ("cilium_services", "cilium_debug_services"):
            return _project_cilium_services(record)
        return record
    kept = []
    for line in record["stdout"].splitlines():
        name = line.split("|", 1)[0].lower()
        if name.startswith(PACKAGE_PREFIXES):
            kept.append(line)
    record = dict(record)
    record["stdout"] = "\n".join(kept) + ("\n" if kept else "")
    return record


def _resolv_conf_facts(path):
    if not isinstance(path, str) or not path.startswith("/") or ".." in Path(path).parts:
        return {"path": path, "status": "invalid", "nameservers": [], "search": [], "options": []}
    source = _read_text(path, 64 * 1024)
    result = {"path": path, "status": source.get("status"), "nameservers": [], "search": [], "options": []}
    if source.get("status") not in ("collected", "truncated"):
        result["error"] = source.get("error")
        return result
    for raw_line in source.get("text", "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "nameserver" and len(parts) == 2:
            result["nameservers"].append(parts[1][:256])
        elif parts[0] in ("search", "domain"):
            result["search"].extend(value[:256] for value in parts[1:16])
        elif parts[0] == "options":
            result["options"].extend(value[:256] for value in parts[1:16])
    return result


def _kubelet_certificate_rotation(root="/var/lib/kubelet/pki"):
    directory = Path(root)
    link = directory / "kubelet-client-current.pem"
    result = {"path": str(link), "status": "missing", "is_symlink": False, "target": None}
    if not os.path.lexists(str(link)):
        return result
    result["is_symlink"] = link.is_symlink()
    if not result["is_symlink"]:
        result["status"] = "not_symlink"
        return result
    try:
        target_text = os.readlink(str(link))
        target = (directory / target_text).resolve() if not os.path.isabs(target_text) else Path(target_text).resolve()
        result["target"] = target.name
        if os.path.commonpath((str(directory.resolve()), str(target))) != str(directory.resolve()):
            result["status"] = "target_outside_pki"
        elif not target.is_file():
            result["status"] = "broken"
        else:
            result["status"] = "collected"
    except OSError as error:
        result["status"] = "unavailable"
        result["error"] = str(error)
    return result


def _service_states(timeout_seconds, max_bytes):
    states = {}
    properties = (
        "Id,LoadState,ActiveState,SubState,Result,MainPID,ExecMainStatus,UnitFileState,FragmentPath,"
        "DropInPaths,ControlGroup,Delegate,Slice,ExecStart"
    )
    for unit in SERVICE_UNITS:
        result = run_process(
            ["systemctl", "show", unit, "--no-pager", "--property", properties],
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_bytes,
        )
        values = {}
        if result.returncode == 0:
            for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    values[key] = value
        states[unit] = {
            "status": "collected" if result.returncode == 0 else "unavailable",
            "properties": values,
            "error": result.stderr.decode("utf-8", errors="replace")[:2000] if result.returncode else None,
        }
    return states


def _process_cgroups(service_states):
    result = {}
    for unit, state in service_states.items():
        pid = state.get("properties", {}).get("MainPID")
        if not pid or not pid.isdigit() or pid == "0":
            continue
        result[unit] = {
            "pid": int(pid),
            "cgroup": _read_text("/proc/{0}/cgroup".format(pid), 64 * 1024),
            "mountinfo": _read_text("/proc/{0}/mountinfo".format(pid), 1024 * 1024),
            "status": _read_text("/proc/{0}/status".format(pid), 256 * 1024),
        }
    return result


def _file_hashes(max_files=1000, max_file_bytes=32 * 1024 * 1024):
    paths = set()
    for pattern in HASH_PATTERNS:
        for item in glob.glob(pattern):
            paths.add(item)
    records = []
    for value in sorted(paths)[:max_files]:
        path = Path(value)
        try:
            file_stat = path.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                continue
            digest, size = sha256_file(str(path), max_bytes=max_file_bytes)
            records.append(
                {
                    "path": str(path),
                    "size": size,
                    "mtime_ns": file_stat.st_mtime_ns,
                    "mode": stat.S_IMODE(file_stat.st_mode),
                    "uid": file_stat.st_uid,
                    "gid": file_stat.st_gid,
                    "sha256": digest,
                }
            )
        except (OSError, ValueError) as error:
            records.append({"path": str(path), "error": str(error)})
    return records


def _sysctl_assignments(max_files=100, max_total_bytes=2 * 1024 * 1024):
    candidates = ["/usr/lib/sysctl.d/*.conf", "/run/sysctl.d/*.conf", "/etc/sysctl.d/*.conf", "/etc/sysctl.conf"]
    paths = []
    for pattern in candidates:
        paths.extend(glob.glob(pattern))
    records = []
    consumed = 0
    for value in sorted(dict.fromkeys(paths))[:max_files]:
        result = _read_text(value, min(256 * 1024, max_total_bytes - consumed))
        text = result.get("text", "")
        consumed += len(text.encode("utf-8", errors="replace"))
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
                continue
            key, configured_value = stripped.split("=", 1)
            key = key.strip().lstrip("-")
            if key.startswith(SYSCTL_PREFIXES):
                records.append({"path": value, "line": number, "key": key, "value": configured_value.strip()})
        if consumed >= max_total_bytes:
            break
    return records


def _certificate_metadata(timeout_seconds, max_command_bytes, max_certificates=100):
    roots = ("/etc/kubernetes/pki", "/var/lib/kubelet/pki")
    paths = []
    for root in roots:
        if os.path.isdir(root):
            paths.extend(glob.glob(os.path.join(root, "**", "*.crt"), recursive=True))
            paths.extend(glob.glob(os.path.join(root, "**", "*.pem"), recursive=True))
    records = []
    for path in sorted(dict.fromkeys(paths))[:max_certificates]:
        if "key" in Path(path).name.lower():
            continue
        try:
            if not stat.S_ISREG(os.stat(path, follow_symlinks=False).st_mode):
                continue
            digest, size = sha256_file(path, max_bytes=8 * 1024 * 1024)
        except (OSError, ValueError) as error:
            records.append({"path": path, "error": str(error)})
            continue
        command = [
            "openssl",
            "x509",
            "-in",
            path,
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-dates",
            "-fingerprint",
            "-sha256",
        ]
        result = run_process(command, timeout_seconds, max_command_bytes)
        records.append(
            {
                "path": path,
                "size": size,
                "sha256": digest,
                "status": "collected" if result.returncode == 0 else "unavailable",
                "metadata": result.stdout.decode("utf-8", errors="replace"),
                "error": result.stderr.decode("utf-8", errors="replace")[:2000] if result.returncode else None,
            }
        )
    return records


def _all_collected(commands):
    return bool(commands) and all(item.get("status") == "collected" for item in commands)


def _run_etcd_checks(prefix, ca_path, cert_path, key_path, timeout_seconds, max_command_bytes):
    common = list(prefix) + [
        "--endpoints=https://127.0.0.1:2379",
        "--cacert={0}".format(ca_path),
        "--cert={0}".format(cert_path),
        "--key={0}".format(key_path),
        "--dial-timeout=5s",
        "--command-timeout={0}s".format(max(5, timeout_seconds)),
    ]
    specifications = (
        ("etcd_endpoint_status", ["endpoint", "status", "--cluster", "--write-out=json"]),
        ("etcd_endpoint_health", ["endpoint", "health", "--cluster", "--write-out=json"]),
        ("etcd_alarm_list", ["alarm", "list", "--write-out=json"]),
    )
    commands = []
    for check_id, arguments in specifications:
        result = run_process(common + arguments, timeout_seconds, max_command_bytes)
        commands.append(result.record(check_id, sensitivity="confidential"))
    return commands


def _container_root_executable(crictl, container_id, name, timeout_seconds, max_command_bytes):
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,256}", str(container_id or "")):
        return None
    inspected = run_process(
        [crictl, "inspect", container_id],
        timeout_seconds,
        min(max_command_bytes, 1024 * 1024),
    )
    if inspected.returncode != 0 or inspected.truncated:
        return None
    try:
        document = json.loads(inspected.stdout.decode("utf-8"))
        pid = int((document.get("info") or {}).get("pid"))
    except (AttributeError, TypeError, ValueError):
        return None
    if pid <= 1:
        return None
    for path in ("/usr/bin/{0}", "/usr/local/bin/{0}", "/bin/{0}"):
        candidate = Path("/proc/{0}/root{1}".format(pid, path.format(name)))
        try:
            if candidate.is_file() and os.access(str(candidate), os.X_OK):
                return str(candidate)
        except OSError:
            continue
    return None


def _etcd_snapshot(
    enabled,
    timeout_seconds,
    max_command_bytes,
    manifest_path=ETCD_MANIFEST,
    ca_path=ETCD_CA,
    cert_path=ETCD_CERT,
    key_path=ETCD_KEY,
):
    if not enabled:
        return {"status": "disabled", "commands": []}
    if not Path(manifest_path).is_file():
        return {"status": "not_applicable", "commands": []}
    manifest = _read_text(manifest_path, 1024 * 1024)
    quota_backend_bytes = None
    quota_match = re.search(r"--quota-backend-bytes(?:=|\s+)(\d+)", manifest.get("text", ""))
    if quota_match:
        quota_backend_bytes = int(quota_match.group(1))
    missing = [path for path in (ca_path, cert_path, key_path) if not Path(path).is_file()]
    if missing:
        return {
            "status": "unavailable",
            "commands": [],
            "error": "standard kubeadm etcd TLS files unavailable: {0}".format(", ".join(missing)),
        }

    etcd_timeout = min(timeout_seconds, 15)
    commands = []
    container_id = None
    crictl = shutil.which("crictl")
    if crictl:
        discovery_result = run_process(
            [crictl, "ps", "--name", "etcd", "--state", "Running", "--quiet"],
            etcd_timeout,
            min(max_command_bytes, 64 * 1024),
        )
        discovery = discovery_result.record("etcd_container_discovery", sensitivity="internal")
        commands.append(discovery)
        container_ids = [line.strip() for line in discovery.get("stdout", "").splitlines() if line.strip()]
        if discovery.get("status") == "collected" and container_ids:
            container_id = container_ids[0]

    attempts = []
    if crictl and container_id:
        attempts.append(
            (
                "crictl",
                _run_etcd_checks(
                    [crictl, "exec", container_id, "etcdctl"],
                    ca_path,
                    cert_path,
                    key_path,
                    etcd_timeout,
                    max_command_bytes,
                ),
            )
        )

    executable = shutil.which("etcdctl")
    executable_transport = "host"
    if not executable and crictl and container_id and attempts and not _all_collected(attempts[0][1]):
        executable = _container_root_executable(
            crictl,
            container_id,
            "etcdctl",
            etcd_timeout,
            max_command_bytes,
        )
        executable_transport = "host-container-root"
    if executable and (not attempts or not _all_collected(attempts[0][1])):
        attempts.append(
            (
                executable_transport,
                _run_etcd_checks(
                    [executable],
                    ca_path,
                    cert_path,
                    key_path,
                    etcd_timeout,
                    max_command_bytes,
                ),
            )
        )

    if not attempts:
        if crictl:
            return {
                "status": "unavailable",
                "transport": "crictl",
                "commands": commands,
                "error": "running etcd container not found and host etcdctl is unavailable",
            }
        return {"status": "unsupported", "commands": [], "error": "neither crictl nor etcdctl found"}

    transport, selected_commands = max(
        attempts,
        key=lambda attempt: sum(item.get("status") == "collected" for item in attempt[1]),
    )
    commands.extend(selected_commands)
    statuses = [item.get("status") for item in selected_commands]
    if statuses and all(status == "collected" for status in statuses):
        status = "collected"
    elif any(status == "collected" for status in statuses):
        status = "partial"
    else:
        status = "unavailable"
    value = {"status": status, "transport": transport, "quota_backend_bytes": quota_backend_bytes, "commands": commands}
    if attempts[0][0] == "crictl" and transport != "crictl":
        value["fallback_from"] = "crictl"
    return value


def _tail_regular_file(path, count):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("not a regular file")
        start = max(file_stat.st_size - count, 0)
        os.lseek(descriptor, start, os.SEEK_SET)
        payload = os.read(descriptor, count)
        return payload, start > 0, file_stat
    finally:
        os.close(descriptor)


def _pod_log_snapshot(namespaces, tail_bytes, total_bytes, max_files):
    root = Path("/var/log/pods")
    if not root.is_dir():
        return {"status": "unsupported", "entries": [], "error": "/var/log/pods not found"}
    allowed = set(namespaces)
    candidates = []
    try:
        for pod_dir in root.iterdir():
            parts = pod_dir.name.split("_", 2)
            if len(parts) != 3 or parts[0] not in allowed or not pod_dir.is_dir():
                continue
            namespace, pod, pod_uid = parts
            for container_dir in pod_dir.iterdir():
                if not container_dir.is_dir():
                    continue
                for log_path in container_dir.glob("*.log"):
                    try:
                        resolved_parent = log_path.parent.resolve(strict=True)
                        if os.path.commonpath((str(root.resolve()), str(resolved_parent))) != str(root.resolve()):
                            continue
                        file_stat = os.stat(str(log_path), follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISREG(file_stat.st_mode):
                        candidates.append((file_stat.st_mtime_ns, namespace, pod, pod_uid, container_dir.name, log_path))
    except (PermissionError, OSError) as error:
        return {"status": "permission_denied", "entries": [], "error": str(error)}
    candidates.sort(reverse=True, key=lambda item: item[0])
    entries = []
    consumed = 0
    errors = []
    for _mtime, namespace, pod, pod_uid, container, path in candidates[:max_files]:
        remaining = total_bytes - consumed
        if remaining <= 0:
            break
        count = min(tail_bytes, remaining)
        try:
            payload, truncated, file_stat = _tail_regular_file(str(path), count)
        except (OSError, ValueError) as error:
            errors.append({"path": str(path), "error": str(error)})
            continue
        consumed += len(payload)
        entries.append(
            {
                "namespace": namespace,
                "pod": pod,
                "pod_uid": pod_uid,
                "container": container,
                "path": str(path),
                "size": file_stat.st_size,
                "mtime_ns": file_stat.st_mtime_ns,
                "truncated": truncated,
                "text": payload.decode("utf-8", errors="replace"),
            }
        )
    status = "truncated" if consumed >= total_bytes or len(candidates) > max_files else "collected"
    return {"status": status, "entries": entries, "errors": errors, "bytes": consumed, "candidate_files": len(candidates)}


def collect_node_snapshot(since_hours, timeout_seconds, max_command_bytes, system_namespaces, application_namespaces, pod_log_tail_bytes, pod_log_total_bytes, pod_log_max_files, collect_etcd=False, collect_cgroup=True):
    started_at = utc_now()
    boot_start = _boot_id()
    commands = []
    for check_id, argv, sensitivity in _command_specs(since_hours):
        record = run_check(check_id, argv, timeout_seconds, max_command_bytes, sensitivity=sensitivity)
        commands.append(_filtered_command(record))
    commands = _apply_cilium_fallback(
        commands,
        _cilium_container_fallback(commands, timeout_seconds, max_command_bytes),
    )
    service_states = _service_states(timeout_seconds, max_command_bytes)
    etcd = _etcd_snapshot(collect_etcd, timeout_seconds, max_command_bytes)
    commands.extend(etcd.pop("commands"))
    namespaces = sorted(set(system_namespaces) | set(application_namespaces))
    kubelet_config = _allowlisted_top_level_config("/var/lib/kubelet/config.yaml", KUBELET_CONFIG_KEYS)
    resolv_path = kubelet_config.get("values", {}).get("resolvConf") or "/etc/resolv.conf"
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "collector_version": __version__,
        "kind": "node_snapshot",
        "started_at": started_at,
        "ended_at": utc_now(),
        "sensitivity": "confidential",
        "options": {"collect_cgroup": collect_cgroup, "collect_etcd": collect_etcd},
        "host": {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "kernel_release": platform.release(),
            "machine": platform.machine(),
            "os_release": _os_release(),
        },
        "facts": {
            "boot_id_start": boot_start,
            "boot_id_end": _boot_id(),
            "proc_cmdline": _read_text("/proc/cmdline", 64 * 1024),
            "uptime": _read_text("/proc/uptime", 4096),
            "meminfo": _read_text("/proc/meminfo", 256 * 1024),
            "pressure_cpu": _read_text("/proc/pressure/cpu", 64 * 1024),
            "pressure_memory": _read_text("/proc/pressure/memory", 64 * 1024),
            "pressure_io": _read_text("/proc/pressure/io", 64 * 1024),
            "root_disk": _root_disk(),
            "ipv6_disable": _ipv6_disable_values(),
            "cgroup": _cgroup_facts() if collect_cgroup else {"status": "disabled"},
            "kubelet_config": kubelet_config,
            "resolv_conf": _resolv_conf_facts(resolv_path),
            "swaps": _read_text("/proc/swaps", 64 * 1024),
            "service_states": service_states,
            "process_cgroups": _process_cgroups(service_states) if collect_cgroup else {"status": "disabled"},
            "file_hashes": _file_hashes(),
            "sysctl_assignments": _sysctl_assignments(),
            "certificates": _certificate_metadata(timeout_seconds, max_command_bytes),
            "kubelet_certificate_rotation": _kubelet_certificate_rotation(),
            "authentication_config_files": _authentication_config_files(),
            "etcd": etcd,
        },
        "commands": commands,
        "pod_logs": _pod_log_snapshot(namespaces, pod_log_tail_bytes, pod_log_total_bytes, pod_log_max_files),
    }
    snapshot["facts"]["boot_changed_during_collection"] = snapshot["facts"]["boot_id_start"] != snapshot["facts"]["boot_id_end"]
    return snapshot
