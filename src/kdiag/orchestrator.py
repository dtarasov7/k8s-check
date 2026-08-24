import os
import shutil
import sys
import tempfile
import uuid
import zipapp
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from kdiag import __version__
from kdiag.bundle import write_manifest
from kdiag.inventory import load_ansible_inventory
from kdiag.kubernetes import KubectlCollector, collect_prometheus, snapshot_status
from kdiag.report import build_report
from kdiag.transport import SSHTransport
from kdiag.util import SCHEMA_VERSION, atomic_write_gzip_json, atomic_write_json, utc_now


def _collection_id():
    return utc_now().replace("-", "").replace(":", "").replace(".", "").replace("Z", "Z-") + uuid.uuid4().hex[:8]


def _zip_member(path):
    return "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo")


def _agent_archive(target):
    argv0 = Path(sys.argv[0])
    if argv0.suffix == ".pyz" and argv0.is_file():
        shutil.copy2(str(argv0), str(target))
        return
    source_root = Path(__file__).resolve().parents[1]
    if not (source_root / "kdiag" / "cli.py").is_file():
        raise RuntimeError("cannot locate src tree; pass a built .pyz executable")
    zipapp.create_archive(str(source_root), str(target), main="kdiag.cli:entrypoint", filter=_zip_member, compressed=True)


def _node_arguments(config):
    collection = config["collection"]
    arguments = [
        "--since-hours",
        str(collection["since_hours"]),
        "--command-timeout-seconds",
        str(collection["command_timeout_seconds"]),
        "--max-command-bytes",
        str(collection["max_command_bytes"]),
        "--pod-log-tail-bytes",
        str(collection["pod_log_tail_bytes"]),
        "--pod-log-total-bytes",
        str(collection["pod_log_total_bytes"]),
        "--pod-log-max-files",
        str(collection["pod_log_max_files"]),
    ]
    if collection["collect_etcd"]:
        arguments.append("--collect-etcd")
    for namespace in config["kubernetes"]["system_namespaces"]:
        arguments.extend(["--system-namespace", namespace])
    for namespace in config["kubernetes"]["application_namespaces"]:
        arguments.extend(["--application-namespace", namespace])
    return arguments


def _preflight_disk(output_root, host_count, config):
    collection = config["collection"]
    kubernetes_budget = config["kubernetes"]["max_bundle_bytes"] if config["kubernetes"]["enabled"] else 0
    required = collection["central_reserve_bytes"] + host_count * collection["max_node_bundle_bytes"] + kubernetes_budget
    free = shutil.disk_usage(str(output_root)).free
    if free < required:
        raise RuntimeError("not enough free disk: required at least {0} bytes, available {1}".format(required, free))


def run_snapshot(inventory_path, group, output_root, config):
    started_at = utc_now()
    collection_id = _collection_id()
    root = Path(output_root).resolve()
    root_existed = root.exists()
    root.mkdir(parents=True, exist_ok=True)
    if not root_existed:
        os.chmod(str(root), 0o700)
    collection_dir = root / collection_id
    collection_dir.mkdir(mode=0o700)

    hosts = load_ansible_inventory(
        inventory_path,
        group=group,
        default_user=config["ssh"]["user"],
        default_port=config["ssh"]["port"],
    )
    _preflight_disk(root, len(hosts), config)
    transport = SSHTransport(
        config["ssh"]["connect_timeout_seconds"],
        config["ssh"]["remote_python"],
        config["collection"]["max_node_bundle_bytes"],
    )
    node_results = []
    with tempfile.TemporaryDirectory(prefix="kdiag-agent-") as temporary_directory:
        agent_path = Path(temporary_directory) / "kdiag.pyz"
        _agent_archive(agent_path)
        with ThreadPoolExecutor(max_workers=min(config["collection"]["parallelism"], len(hosts))) as executor:
            futures = {}
            for host in hosts:
                destination = collection_dir / "node-{0}.json.gz".format(host.name)
                future = executor.submit(
                    transport.collect_node,
                    host,
                    agent_path,
                    destination,
                    collection_id,
                    _node_arguments(config),
                    max(config["collection"]["command_timeout_seconds"] * 10, 300),
                )
                futures[future] = host.name
            for future in as_completed(futures):
                host_name = futures[future]
                try:
                    node_results.append(future.result())
                except Exception as error:
                    node_results.append({"host": host_name, "status": "failed", "error": str(error)})
    node_results.sort(key=lambda item: item.get("host") or "")

    kubernetes_result = {"status": "disabled", "file": None, "error": None}
    if config["kubernetes"]["enabled"]:
        if not config["kubernetes"].get("kubeconfig"):
            kubernetes_result = {"status": "configuration_error", "file": None, "error": "kubernetes.kubeconfig is required"}
        elif not Path(config["kubernetes"]["kubeconfig"]).is_file():
            kubernetes_result = {"status": "configuration_error", "file": None, "error": "kubernetes.kubeconfig is not a regular file"}
        else:
            collector = KubectlCollector(
                kubeconfig=config["kubernetes"].get("kubeconfig"),
                context=config["kubernetes"].get("context"),
                timeout_seconds=config["kubernetes"]["command_timeout_seconds"],
                max_wire_bytes=config["kubernetes"]["max_wire_bytes"],
            )
            snapshot = collector.collect(
                config["kubernetes"]["system_namespaces"],
                config["kubernetes"]["application_namespaces"],
                config["kubernetes"]["collect_system_logs"],
                config["kubernetes"]["log_tail_lines"],
                config["kubernetes"]["max_log_pods"],
                config["kubernetes"]["max_log_bytes"],
            )
            kube_status = snapshot_status(snapshot, config["kubernetes"]["collect_system_logs"])
            path = collection_dir / "kubernetes.json.gz"
            atomic_write_gzip_json(path, snapshot)
            if path.stat().st_size > config["kubernetes"]["max_bundle_bytes"]:
                path.unlink()
                kubernetes_result = {"status": "truncated", "file": None, "error": "projected Kubernetes bundle exceeds limit"}
            else:
                kubernetes_result = {"status": kube_status, "file": path.name, "error": None}

    prometheus_snapshot = collect_prometheus(
        config["prometheus"].get("url"),
        config["prometheus"]["timeout_seconds"],
        config["prometheus"]["max_response_bytes"],
    )
    prometheus_path = collection_dir / "prometheus.json.gz"
    atomic_write_gzip_json(prometheus_path, prometheus_snapshot)
    prometheus_result = {"status": prometheus_snapshot.get("status"), "file": prometheus_path.name, "error": prometheus_snapshot.get("error")}

    all_nodes_collected = all(item.get("status") == "collected" for item in node_results)
    kubernetes_ok = not config["kubernetes"]["enabled"] or kubernetes_result.get("status") == "collected"
    collection_status = "complete" if all_nodes_collected and kubernetes_ok else "partial"
    collection = {
        "schema_version": SCHEMA_VERSION,
        "collector_version": __version__,
        "kind": "incident_collection",
        "collection_id": collection_id,
        "status": collection_status,
        "started_at": started_at,
        "ended_at": utc_now(),
        "inventory": {"path": str(Path(inventory_path).resolve()), "group": group, "host_count": len(hosts)},
        "limits": {
            "max_node_bundle_bytes": config["collection"]["max_node_bundle_bytes"],
            "central_reserve_bytes": config["collection"]["central_reserve_bytes"],
        },
        "nodes": node_results,
        "kubernetes": kubernetes_result,
        "prometheus": prometheus_result,
    }
    atomic_write_json(collection_dir / "collection.json", collection)
    build_report(collection_dir)
    write_manifest(collection_dir)
    return collection_dir, collection_status
