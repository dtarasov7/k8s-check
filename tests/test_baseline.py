import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from kdiag.baseline import (
    approve_candidate,
    compare_collection,
    create_candidate,
    verify_approved_baseline,
)
from kdiag.bundle import verify_manifest, write_manifest
from kdiag.cli import main
from kdiag.util import atomic_write_gzip_json, atomic_write_json


def _finding(rule_id, severity="warning"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "finding_status": "active",
        "finding_role": "configuration_risk",
        "started_at": "2026-08-27T10:00:00Z",
        "affected": ["demo/app-7d9c8f6d4b-abcde"],
    }


def _make_collection(
    root,
    collection_id,
    services=None,
    findings=None,
    service_status="collected",
    volatile_variant=1,
):
    root.mkdir()
    node_suffix = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" if volatile_variant == 1 else "ffffffff-1111-2222-3333-444444444444"
    pod_name = "coredns-7d9c8f6d4b-abcde" if volatile_variant == 1 else "coredns-6f8b7c5d4a-fghij"
    pod_ip = "10.244.0.10" if volatile_variant == 1 else "10.244.9.99"
    pid = "1234" if volatile_variant == 1 else "9876"
    cluster_dns = "10.96.0.10" if volatile_variant == 1 else "10.96.0.11"
    forward_target = "8.8.8.8" if volatile_variant == 1 else "1.1.1.1"
    services = services if services is not None else [
        {
            "metadata": {"namespace": "default", "name": "api", "uid": node_suffix, "creationTimestamp": "2026-08-27T10:00:00Z"},
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.96.1.10" if volatile_variant == 1 else "10.96.2.20",
                "selector": {"app": "api"},
                "ports": [{"name": "http", "port": 80, "targetPort": 8080, "nodePort": 30123}],
            },
        }
    ]
    sources = {
        "nodes": {
            "status": "collected",
            "required": True,
            "data": {
                "items": [
                    {
                        "metadata": {
                            "name": "node-1",
                            "uid": node_suffix,
                            "creationTimestamp": "2026-08-27T10:00:00Z",
                            "labels": {
                                "kubernetes.io/hostname": "node-1",
                                "node-role.kubernetes.io/control-plane": "",
                            },
                        },
                        "status": {
                            "addresses": [{"type": "InternalIP", "address": pod_ip}],
                            "nodeInfo": {
                                "kubeletVersion": "v1.31.4",
                                "containerRuntimeVersion": "containerd://1.7.20",
                                "operatingSystem": "linux",
                                "osImage": "RED OS 8",
                                "architecture": "amd64",
                                "kernelVersion": "6.1.0",
                            },
                        },
                    }
                ]
            },
        },
        "pods": {
            "status": "collected",
            "required": True,
            "data": {
                "items": [
                    {
                        "metadata": {
                            "namespace": "kube-system",
                            "name": pod_name,
                            "uid": node_suffix,
                            "labels": {"k8s-app": "coredns"},
                            "ownerReferences": [
                                {"kind": "ReplicaSet", "name": "coredns-7d9c8f6d4b", "uid": node_suffix, "controller": True}
                            ],
                        },
                        "spec": {
                            "nodeName": "node-1",
                            "containers": [{"name": "coredns", "image": "registry.k8s.io/coredns:v1.11.1"}],
                        },
                        "status": {
                            "podIP": pod_ip,
                            "startTime": "2026-08-27T10:00:00Z",
                            "containerStatuses": [{"name": "coredns", "containerID": "containerd://random"}],
                        },
                    }
                ]
            },
        },
        "workloads": {
            "status": "collected",
            "required": True,
            "data": {
                "items": [
                    {
                        "kind": "Deployment",
                        "metadata": {"namespace": "default", "name": "api", "uid": node_suffix},
                        "spec": {"replicas": 2, "selector": {"matchLabels": {"app": "api"}}, "strategy": {"type": "RollingUpdate"}},
                        "status": {"readyReplicas": volatile_variant},
                    },
                    {
                        "kind": "Job",
                        "metadata": {"namespace": "default", "name": "backup-{0}".format(pod_name), "uid": node_suffix},
                        "spec": {"replicas": 1},
                    },
                    {
                        "kind": "ReplicaSet",
                        "metadata": {"namespace": "default", "name": "api-{0}".format(pod_name), "uid": node_suffix},
                        "spec": {"replicas": volatile_variant},
                    },
                ]
            },
        },
        "services": {
            "status": service_status,
            "required": True,
            "data": {"items": services if service_status == "collected" else []},
        },
        "storage_classes": {
            "status": "collected",
            "required": True,
            "data": {"items": [{"metadata": {"name": "fast", "uid": node_suffix}, "provisioner": "csi.example", "volumeBindingMode": "WaitForFirstConsumer"}]},
        },
        "csi_drivers": {
            "status": "collected",
            "required": True,
            "data": {"items": [{"metadata": {"name": "csi.example", "uid": node_suffix}, "spec": {"attachRequired": True}}]},
        },
        "csi_nodes": {
            "status": "collected",
            "required": True,
            "data": {"items": [{"metadata": {"name": "node-1", "uid": node_suffix}, "spec": {"drivers": [{"name": "csi.example", "topologyKeys": ["topology.kubernetes.io/zone"]}]}}]},
        },
        "coredns_config": {
            "status": "collected",
            "required": False,
            "data": {
                "metadata": {"namespace": "kube-system", "name": "coredns", "uid": node_suffix},
                "plugins": ["errors", "forward", "kubernetes"],
                "forwardTargets": [forward_target],
                "corefilePresent": True,
            },
        },
        "node_local_dns_config": {"status": "unsupported", "required": False},
        "cilium_config": {
            "status": "collected",
            "required": False,
            "data": {
                "metadata": {"namespace": "d8-cni-cilium", "name": "cilium-configmap", "uid": node_suffix},
                "data": {"routing-mode": "tunnel", "kube-proxy-replacement": "true"},
            },
        },
    }
    atomic_write_gzip_json(
        root / "node-n1.json.gz",
        {
            "host": {
                "hostname": "node-1",
                "fqdn": "node-1.example.test",
                "kernel_release": "6.1.0",
                "machine": "x86_64",
                "os_release": {"NAME": "RED OS", "PRETTY_NAME": "RED OS 8", "VERSION_ID": "8"},
            },
            "facts": {
                "cgroup": {"mode": "v2", "controllers": ["cpu", "memory"], "subtree_control": ["cpu"]},
                "kubelet_config": {"status": "collected", "values": {"cgroupDriver": "systemd", "clusterDNS": [cluster_dns]}},
                "file_hashes": [{"path": "/var/lib/kubelet/config.yaml", "sha256": "a" * 64, "mtime_ns": volatile_variant}],
                "service_states": {"kubelet.service": {"properties": {"MainPID": pid}}},
                "process_cgroups": {"kubelet.service": {"pid": int(pid)}},
            },
            "pod_logs": {"status": "collected", "entries": [{"pod_uid": node_suffix, "text": "volatile log line"}]},
        },
    )
    atomic_write_gzip_json(
        root / "kubernetes.json.gz",
        {
            "collected_at": "2026-08-27T1{0}:00:00Z".format(volatile_variant),
            "sources": sources,
            "logs": {"status": "collected", "entries": [{"pod": pod_name, "text": "volatile log line"}]},
        },
    )
    atomic_write_json(
        root / "collection.json",
        {
            "schema_version": 1,
            "collector_version": "0.10.0",
            "kind": "diagnostic_collection",
            "collection_id": collection_id,
            "status": "complete" if service_status == "collected" else "partial",
            "started_at": "2026-08-27T1{0}:00:00Z".format(volatile_variant),
            "ended_at": "2026-08-27T1{0}:10:00Z".format(volatile_variant),
            "nodes": [{"host": "n1", "status": "collected", "file": "node-n1.json.gz"}],
            "kubernetes": {"status": "collected" if service_status == "collected" else "partial", "file": "kubernetes.json.gz"},
            "prometheus": {"status": "not_configured"},
        },
    )
    coverage = [
        {"source": "node/n1", "status": "collected", "required": True},
        {"source": "kubernetes", "status": "collected" if service_status == "collected" else "partial", "required": True},
    ]
    for source_id, source in sources.items():
        coverage.append(
            {
                "source": "kubernetes/{0}".format(source_id),
                "status": source["status"],
                "required": source.get("required", True),
            }
        )
    atomic_write_json(
        root / "report.json",
        {
            "schema_version": 1,
            "collection_id": collection_id,
            "coverage": coverage,
            "findings": findings or [],
        },
    )
    write_manifest(root)
    return root


class BaselineTest(unittest.TestCase):
    def _approved(self, directory, collection, name="prod"):
        candidate_path = Path(directory) / "candidate.json"
        baseline_path = Path(directory) / "baseline.json"
        create_candidate(collection, name, candidate_path)
        approve_candidate(candidate_path, "operator", baseline_path)
        return candidate_path, baseline_path

    def test_create_candidate_contains_stable_profile_and_no_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = _make_collection(root / "collection", "base")
            candidate_path = root / "candidate.json"
            candidate = create_candidate(collection, "production", candidate_path)

            self.assertEqual("kdiag_baseline_candidate", candidate["kind"])
            self.assertNotIn("approval", candidate)
            self.assertEqual(64, len(candidate["integrity"]["profile_sha256"]))
            self.assertIn("kubernetes/services", candidate["profile"]["sources"])
            self.assertIn("kubernetes/cilium_config", candidate["profile"]["sources"])
            serialized = candidate_path.read_text(encoding="utf-8")
            for volatile in (
                "10.96.0.10",
                "10.244.0.10",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "coredns-7d9c8f6d4b-abcde",
                "backup-coredns",
                '"MainPID"',
                "volatile log line",
            ):
                self.assertNotIn(volatile, serialized)
            self.assertIn("registry.k8s.io/coredns:v1.11.1", serialized)
            self.assertIn("configuration_sha256", serialized)

    def test_comparison_rejects_unapproved_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = _make_collection(root / "collection", "base")
            candidate_path = root / "candidate.json"
            create_candidate(collection, "production", candidate_path)
            with self.assertRaisesRegex(ValueError, "approved baseline"):
                compare_collection(collection, candidate_path)

    def test_approval_and_hash_verification_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = _make_collection(root / "collection", "base")
            candidate_path, baseline_path = self._approved(root, collection)
            baseline = verify_approved_baseline(baseline_path)
            self.assertEqual("operator", baseline["approval"]["approved_by"])
            self.assertFalse(baseline["approval"]["unsafe_override"])
            self.assertEqual(64, len(baseline["integrity"]["profile_sha256"]))
            self.assertEqual(64, len(baseline["integrity"]["document_sha256"]))
            with self.assertRaisesRegex(ValueError, "overwrite"):
                approve_candidate(candidate_path, "other", baseline_path)

    def test_approval_blocks_active_critical_and_records_explicit_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = _make_collection(root / "collection", "critical", findings=[_finding("node.down", "critical")])
            candidate_path = root / "candidate.json"
            create_candidate(collection, "unsafe", candidate_path)
            with self.assertRaisesRegex(ValueError, "active critical findings"):
                approve_candidate(candidate_path, "operator", root / "rejected.json")
            approved = approve_candidate(
                candidate_path,
                "operator",
                root / "overridden.json",
                override_unsafe=True,
            )
            self.assertTrue(approved["approval"]["unsafe_override"])
            self.assertIn("active critical findings", approved["approval"]["override_reasons"][0])

            incomplete = _make_collection(root / "incomplete", "incomplete", service_status="failed")
            incomplete_candidate = root / "incomplete-candidate.json"
            create_candidate(incomplete, "incomplete", incomplete_candidate)
            with self.assertRaisesRegex(ValueError, "material collection gaps"):
                approve_candidate(incomplete_candidate, "operator", root / "incomplete-baseline.json")

    def test_tampered_approved_baseline_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = _make_collection(root / "collection", "base")
            _candidate_path, baseline_path = self._approved(root, collection)
            document = json.loads(baseline_path.read_text(encoding="utf-8"))
            document["approval"]["approved_by"] = "attacker"
            atomic_write_json(baseline_path, document)
            with self.assertRaisesRegex(ValueError, "document SHA-256 mismatch"):
                verify_approved_baseline(baseline_path)
            with self.assertRaisesRegex(ValueError, "document SHA-256 mismatch"):
                compare_collection(collection, baseline_path)

            profile_path = root / "baseline-profile.json"
            approve_candidate(root / "candidate.json", "operator", profile_path)
            profile_document = json.loads(profile_path.read_text(encoding="utf-8"))
            profile_document["profile"]["sources"]["kubernetes/services"]["objects"][0]["value"]["type"] = "ExternalName"
            atomic_write_json(profile_path, profile_document)
            with self.assertRaisesRegex(ValueError, "profile SHA-256 mismatch"):
                verify_approved_baseline(profile_path)

            whitespace_path = root / "baseline-whitespace.json"
            approve_candidate(root / "candidate.json", "operator", whitespace_path)
            whitespace_path.write_bytes(whitespace_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "canonical hashed representation"):
                verify_approved_baseline(whitespace_path)

    def test_compare_classifies_added_removed_changed_new_and_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before_services = [
                {"metadata": {"namespace": "default", "name": "old"}, "spec": {"type": "ClusterIP", "ports": [{"port": 80}]}},
                {"metadata": {"namespace": "default", "name": "api"}, "spec": {"type": "ClusterIP", "ports": [{"port": 80}]}},
            ]
            baseline_collection = _make_collection(
                root / "baseline-collection",
                "base",
                services=before_services,
                findings=[_finding("problem.old")],
            )
            _candidate_path, baseline_path = self._approved(root, baseline_collection)
            after_services = [
                {"metadata": {"namespace": "default", "name": "api"}, "spec": {"type": "ClusterIP", "ports": [{"port": 81}]}},
                {"metadata": {"namespace": "default", "name": "new"}, "spec": {"type": "ClusterIP", "ports": [{"port": 80}]}},
            ]
            current = _make_collection(
                root / "current",
                "current",
                services=after_services,
                findings=[_finding("problem.new")],
            )
            result = compare_collection(current, baseline_path)["comparison"]
            categories = {item["category"] for item in result["changes"]}
            self.assertTrue({"added", "removed", "changed", "new_problem", "resolved"}.issubset(categories))
            self.assertEqual("changes_detected", result["status"])

    def test_missing_source_is_unverifiable_without_false_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_collection = _make_collection(root / "baseline-collection", "base")
            _candidate_path, baseline_path = self._approved(root, baseline_collection)
            current = _make_collection(root / "current", "current", service_status="failed")
            comparison = compare_collection(current, baseline_path)["comparison"]
            service_changes = [item for item in comparison["changes"] if item["source"] == "kubernetes/services"]
            self.assertEqual(["unverifiable"], [item["category"] for item in service_changes])
            self.assertNotIn("removed", [item["category"] for item in service_changes])
            self.assertIn("kubernetes/services", comparison["missing_sources"])

    def test_volatile_fields_do_not_create_differences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_collection = _make_collection(root / "baseline-collection", "base", volatile_variant=1)
            _candidate_path, baseline_path = self._approved(root, baseline_collection)
            current = _make_collection(root / "current", "current", volatile_variant=2)
            comparison = compare_collection(current, baseline_path)["comparison"]
            self.assertEqual("no_changes", comparison["status"])
            self.assertEqual([], comparison["changes"])

    def test_cli_writes_json_and_russian_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = _make_collection(root / "collection", "base")
            candidate_path = root / "candidate.json"
            baseline_path = root / "baseline.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    0,
                    main(["baseline", "create", str(collection), "--name", "production", "--output", str(candidate_path)]),
                )
                self.assertEqual(
                    0,
                    main(["baseline", "approve", str(candidate_path), "--approved-by", "operator", "--output", str(baseline_path)]),
                )
                self.assertEqual(0, main(["compare", str(collection), "--baseline", str(baseline_path)]))
            comparison = json.loads((collection / "baseline-comparison.json").read_text(encoding="utf-8"))
            markdown = (collection / "baseline-comparison.md").read_text(encoding="utf-8")
            self.assertEqual("no_changes", comparison["status"])
            self.assertIn("Сравнение с утверждённым baseline", markdown)
            self.assertIn("Рекомендуемое действие", markdown)
            self.assertEqual("verified", verify_manifest(collection)["status"])


if __name__ == "__main__":
    unittest.main()
