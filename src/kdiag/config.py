import copy
import json
import re
from pathlib import Path

from kdiag.analysis import resolve_analysis_window
from kdiag.util import require_k8s_name


MIB = 1024 * 1024
GIB = 1024 * MIB
REMOTE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./+-]+$")


DEFAULT_CONFIG = {
    "schema_version": 1,
    "analysis": {
        "purpose": "check",
        "incident_start": None,
        "incident_end": None,
    },
    "collection": {
        "since_hours": 24,
        "parallelism": 2,
        "command_timeout_seconds": 30,
        "max_command_bytes": 1 * MIB,
        "max_node_bundle_bytes": 32 * MIB,
        "central_reserve_bytes": 1 * GIB,
        "pod_log_tail_bytes": 64 * 1024,
        "pod_log_total_bytes": 8 * MIB,
        "pod_log_max_files": 200,
        "collect_etcd": True,
        "collect_cgroup": True,
    },
    "ssh": {
        "connect_timeout_seconds": 10,
        "remote_python": "/usr/bin/python3.8",
        "user": None,
        "port": 22,
    },
    "kubernetes": {
        "enabled": True,
        "kubeconfig": None,
        "context": None,
        "command_timeout_seconds": 30,
        "max_wire_bytes": 64 * MIB,
        "max_bundle_bytes": 128 * MIB,
        "system_namespaces": ["d8-cni-cilium", "d8-kube-dns", "kube-system"],
        "application_namespaces": [],
        "collect_system_logs": True,
        "log_tail_lines": 200,
        "max_log_pods": 100,
        "max_log_bytes": 32 * MIB,
    },
    "prometheus": {
        "url": None,
        "username": None,
        "password": None,
        "timeout_seconds": 3,
        "max_response_bytes": 1 * MIB,
    },
}


def _merge_known(target, override, path=""):
    for key, value in override.items():
        current_path = "{0}.{1}".format(path, key) if path else key
        if key not in target:
            raise ValueError("unknown configuration key: {0}".format(current_path))
        if isinstance(target[key], dict):
            if not isinstance(value, dict):
                raise ValueError("configuration section must be an object: {0}".format(current_path))
            _merge_known(target[key], value, current_path)
        else:
            target[key] = value


def _positive_int(config, section, key, minimum=1, maximum=None):
    value = config[section][key]
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or (maximum is not None and value > maximum):
        raise ValueError("invalid {0}.{1}: {2!r}".format(section, key, value))


def validate_config(config):
    if config.get("schema_version") != 1:
        raise ValueError("unsupported schema_version")
    if not isinstance(config["kubernetes"].get("enabled"), bool):
        raise ValueError("kubernetes.enabled must be boolean")
    if not isinstance(config["kubernetes"].get("collect_system_logs"), bool):
        raise ValueError("kubernetes.collect_system_logs must be boolean")
    if not isinstance(config["collection"].get("collect_etcd"), bool):
        raise ValueError("collection.collect_etcd must be boolean")
    if not isinstance(config["collection"].get("collect_cgroup"), bool):
        raise ValueError("collection.collect_cgroup must be boolean")
    analysis = config["analysis"]
    resolved_analysis = resolve_analysis_window(
        analysis.get("purpose"),
        incident_start=analysis.get("incident_start"),
        incident_end=analysis.get("incident_end"),
    )
    analysis.update(resolved_analysis)
    for key in (
        "since_hours",
        "parallelism",
        "command_timeout_seconds",
        "max_command_bytes",
        "max_node_bundle_bytes",
        "central_reserve_bytes",
        "pod_log_tail_bytes",
        "pod_log_total_bytes",
        "pod_log_max_files",
    ):
        _positive_int(config, "collection", key)
    for key in ("connect_timeout_seconds", "port"):
        _positive_int(config, "ssh", key, maximum=65535 if key == "port" else None)
    remote_python = config["ssh"]["remote_python"]
    if (
        not isinstance(remote_python, str)
        or not REMOTE_PATH_RE.fullmatch(remote_python)
        or ".." in Path(remote_python).parts
    ):
        raise ValueError("ssh.remote_python must be a safe absolute path")
    for key in (
        "command_timeout_seconds",
        "max_wire_bytes",
        "max_bundle_bytes",
        "log_tail_lines",
        "max_log_pods",
        "max_log_bytes",
    ):
        _positive_int(config, "kubernetes", key)
    for list_key in ("system_namespaces", "application_namespaces"):
        values = config["kubernetes"][list_key]
        if not isinstance(values, list):
            raise ValueError("kubernetes.{0} must be an array".format(list_key))
        config["kubernetes"][list_key] = sorted(set(require_k8s_name(item) for item in values))
    if config["ssh"]["user"] is not None and not isinstance(config["ssh"]["user"], str):
        raise ValueError("ssh.user must be a string or null")
    for key in ("timeout_seconds", "max_response_bytes"):
        _positive_int(config, "prometheus", key)
    prometheus = config["prometheus"]
    if prometheus["url"] is not None and not isinstance(prometheus["url"], str):
        raise ValueError("prometheus.url must be a string or null")
    username = prometheus.get("username")
    password = prometheus.get("password")
    if (username is None) != (password is None):
        raise ValueError("prometheus.username and prometheus.password must be specified together")
    if username is not None:
        if not isinstance(username, str) or not username or len(username) > 1024:
            raise ValueError("prometheus.username must be a non-empty string up to 1024 characters")
        if ":" in username or any(ord(character) < 32 or ord(character) == 127 for character in username):
            raise ValueError("prometheus.username contains characters unsafe for HTTP Basic authentication")
        if not isinstance(password, str) or len(password) > 16384:
            raise ValueError("prometheus.password must be a string up to 16384 characters")
        if any(ord(character) < 32 and character not in ("\t",) for character in password):
            raise ValueError("prometheus.password contains control characters")
        if not prometheus.get("url"):
            raise ValueError("prometheus.url is required when credentials are configured")
    return config


def load_config(path=None):
    config = copy.deepcopy(DEFAULT_CONFIG)
    if path:
        with Path(path).open("r", encoding="utf-8") as source:
            override = json.load(source)
        if not isinstance(override, dict):
            raise ValueError("configuration root must be an object")
        _merge_known(config, override)
    return validate_config(config)
