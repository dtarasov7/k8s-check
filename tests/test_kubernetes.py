import json
import unittest
from unittest.mock import patch

from kdiag.kubernetes import (
    KubectlCollector,
    _pod_log_priority,
    project_api_service,
    project_cilium_endpoint,
    project_coredns_config,
    project_event,
    project_pdb,
    project_pod,
    project_pv,
    project_readyz,
    project_service,
    project_storage_class,
    project_volume_attachment,
    project_workload,
    snapshot_status,
)
from kdiag.runner import ProcessResult


class KubernetesProjectionTest(unittest.TestCase):
    def test_pod_projection_drops_secret_bearing_fields(self):
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "n", "annotations": {"token": "SECRET"}, "labels": {"app": "demo", "secret": "SECRET"}},
            "spec": {
                "nodeName": "node-1",
                "imagePullSecrets": [{"name": "registry-credentials"}],
                "containers": [
                    {
                        "name": "app",
                        "image": "demo:v1",
                        "command": ["SECRET"],
                        "args": ["SECRET"],
                        "env": [{"name": "TOKEN", "value": "SECRET"}],
                        "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080, "httpHeaders": [{"name": "Authorization", "value": "SECRET"}]}},
                    }
                ],
            },
            "status": {"phase": "Running", "containerStatuses": []},
        }
        projected = project_pod(pod)
        encoded = json.dumps(projected)
        self.assertNotIn("SECRET", encoded)
        self.assertEqual("demo", projected["metadata"]["labels"]["app"])
        self.assertEqual(["registry-credentials"], projected["spec"]["imagePullSecrets"])
        self.assertEqual("/ready", projected["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"])

    def test_selectors_are_allowlisted(self):
        workload = {"kind": "Deployment", "metadata": {}, "spec": {"selector": {"matchLabels": {"app": "demo", "secret": "SECRET"}}}, "status": {}}
        service = {"kind": "Service", "metadata": {}, "spec": {"selector": {"app": "demo", "secret": "SECRET"}}}
        self.assertNotIn("SECRET", json.dumps(project_workload(workload)))
        self.assertNotIn("SECRET", json.dumps(project_service(service)))
        projected = project_service({"kind": "Service", "metadata": {}, "spec": {"selector": {"secret": "SECRET"}}})
        self.assertEqual({}, projected["spec"]["selector"])
        self.assertTrue(projected["spec"]["selectorPresent"])

    def test_event_series_timestamp_and_count_are_preserved(self):
        projected = project_event(
            {
                "metadata": {"name": "event", "namespace": "demo"},
                "reason": "Failed",
                "message": "failure",
                "count": None,
                "series": {"lastObservedTime": "2026-01-01T00:10:00Z", "count": 17},
            }
        )
        self.assertEqual("2026-01-01T00:10:00Z", projected["seriesLastObservedTime"])
        self.assertEqual(17, projected["count"])

    def test_snapshot_status_requires_all_requested_sources_and_logs(self):
        complete = {
            "sources": {"nodes": {"status": "collected"}, "pods": {"status": "collected"}},
            "logs": {"status": "collected"},
        }
        self.assertEqual("collected", snapshot_status(complete, True))
        complete["sources"]["pods"]["status"] = "failed"
        self.assertEqual("partial", snapshot_status(complete, True))
        complete["sources"]["nodes"]["status"] = "failed"
        self.assertEqual("unreachable", snapshot_status(complete, True))

    def test_optional_source_does_not_degrade_snapshot(self):
        snapshot = {
            "sources": {
                "nodes": {"status": "collected"},
                "cilium_optional": {"status": "failed", "required": False},
            },
            "logs": {"status": "collected"},
        }
        self.assertEqual("collected", snapshot_status(snapshot, True))

    def test_new_projections_drop_secret_bearing_fields(self):
        documents = [
            project_api_service({"metadata": {"name": "v1.demo"}, "spec": {"caBundle": "SECRET", "service": {"namespace": "n", "name": "s"}}}),
            project_pv({"metadata": {"name": "pv"}, "spec": {"csi": {"driver": "demo.csi", "volumeHandle": "SECRET"}}}),
            project_storage_class({"metadata": {"name": "sc"}, "provisioner": "demo.csi", "parameters": {"password": "SECRET"}}),
            project_volume_attachment({"metadata": {"name": "va"}, "spec": {"source": {"inlineVolumeSpec": {"secret": "SECRET"}}}}),
            project_cilium_endpoint({"metadata": {"name": "cep", "labels": {"security-label": "SECRET"}}, "status": {"identity": {"labels": ["SECRET"], "id": 42}}}),
        ]
        self.assertNotIn("SECRET", json.dumps(documents))

    def test_readyz_projection_extracts_bounded_checks(self):
        projected = project_readyz("[+]ping ok\n[-]etcd failed: timeout\nreadyz check failed\n")
        self.assertEqual("passed", projected["checks"][0]["status"])
        self.assertEqual({"name": "etcd", "status": "failed", "message": "failed: timeout"}, projected["checks"][1])

    def test_pdb_and_coredns_projections_keep_only_diagnostic_fields(self):
        pdb = project_pdb({
            "metadata": {"name": "api", "namespace": "demo", "annotations": {"secret": "SECRET"}},
            "spec": {"minAvailable": 2, "selector": {"matchLabels": {"app": "api", "secret": "SECRET"}}},
            "status": {"currentHealthy": 1, "desiredHealthy": 2, "disruptionsAllowed": 0, "expectedPods": 2},
        })
        coredns = project_coredns_config({"metadata": {"name": "coredns"}, "data": {"Corefile": ".:53 {\n errors\n forward . 10.0.0.2\n cache 30\n}\n", "password": "SECRET"}})
        self.assertEqual(1, pdb["status"]["currentHealthy"])
        self.assertEqual(["cache", "errors", "forward"], coredns["plugins"])
        self.assertEqual(["10.0.0.2"], coredns["forwardTargets"])
        self.assertNotIn("SECRET", json.dumps([pdb, coredns]))

    def test_unhealthy_pod_has_log_priority(self):
        healthy = {"metadata": {"namespace": "kube-system", "name": "a"}, "status": {"phase": "Running", "containerStatuses": [{"name": "app", "ready": True, "restartCount": 0}]}}
        unhealthy = {"metadata": {"namespace": "kube-system", "name": "z"}, "status": {"phase": "Pending", "initContainerStatuses": [{"name": "init", "ready": False, "state": {"waiting": {"reason": "RunContainerError"}}}]}}
        self.assertLess(_pod_log_priority(unhealthy), _pod_log_priority(healthy))

    def test_log_collection_includes_init_containers(self):
        pod_source = {"status": "collected", "data": {"items": [{
            "metadata": {"namespace": "kube-system", "name": "demo"},
            "spec": {"containers": [{"name": "app"}], "initContainers": [{"name": "init"}]},
            "status": {"containerStatuses": [{"name": "app", "restartCount": 0}], "initContainerStatuses": [{"name": "init", "restartCount": 1}]},
        }]}}
        def fake_run(argv, timeout_seconds, max_stdout_bytes):
            return ProcessResult(list(argv), 0, b"2026-01-01T00:00:00Z ok\n", b"", "start", "end", 1)
        collector = KubectlCollector(kubeconfig="/tmp/readonly", timeout_seconds=1, max_wire_bytes=1024)
        with patch("kdiag.kubernetes.run_process", side_effect=fake_run):
            result = collector._collect_logs(pod_source, ["kube-system"], 10, 10, 4096)
        init_entries = [item for item in result["entries"] if item["container"] == "init"]
        self.assertEqual(2, len(init_entries))
        self.assertTrue(all(item["init_container"] for item in init_entries))

    def test_extended_collector_uses_read_only_gets_and_marks_optional_sources(self):
        calls = []

        def fake_run(argv, timeout_seconds, max_stdout_bytes):
            calls.append(list(argv))
            if any("--raw=/readyz" in item for item in argv):
                stdout = b"[+]ping ok\n[+]etcd ok\n"
            elif "configmap" in argv:
                stdout = b'{"metadata":{"name":"cilium-config"},"data":{}}'
            else:
                stdout = b'{"apiVersion":"v1","kind":"List","metadata":{},"items":[]}'
            return ProcessResult(list(argv), 0, stdout, b"", "start", "end", 1)

        with patch("kdiag.kubernetes.run_process", side_effect=fake_run):
            snapshot = KubectlCollector(kubeconfig="/tmp/readonly", timeout_seconds=1, max_wire_bytes=1024 * 1024).collect(
                ["kube-system"], [], False, 10, 10, 1024
            )
        self.assertEqual("collected", snapshot["sources"]["api_readyz"]["status"])
        self.assertFalse(snapshot["sources"]["cilium_nodes"]["required"])
        self.assertTrue(snapshot["sources"]["volume_attachments"]["required"])
        self.assertTrue(all("get" in argv for argv in calls))
        self.assertFalse(any("exec" in argv or "apply" in argv or "delete" in argv for argv in calls))

    def test_configmap_discovery_falls_back_from_deckhouse_to_vanilla(self):
        calls = []

        def fake_run(argv, timeout_seconds, max_stdout_bytes):
            calls.append(list(argv))
            namespace = argv[argv.index("--namespace") + 1]
            if namespace == "d8-kube-dns":
                return ProcessResult(list(argv), 1, b"", b"not found", "start", "end", 1)
            return ProcessResult(
                list(argv),
                0,
                b'{"metadata":{"namespace":"kube-system","name":"coredns"},"data":{"Corefile":".:53 { errors }"}}',
                b"",
                "start",
                "end",
                1,
            )

        collector = KubectlCollector(kubeconfig="/tmp/readonly", timeout_seconds=1, max_wire_bytes=1024 * 1024)
        with patch("kdiag.kubernetes.run_process", side_effect=fake_run):
            result = collector._first_json_source(
                "coredns_config",
                (("d8-kube-dns", "coredns"), ("kube-system", "coredns")),
                project_coredns_config,
            )
        self.assertEqual("collected", result["status"])
        self.assertEqual("kube-system/coredns", result["discovered_at"])
        self.assertEqual(["failed", "collected"], [item["status"] for item in result["attempts"]])
        self.assertEqual(["d8-kube-dns", "kube-system"], [argv[argv.index("--namespace") + 1] for argv in calls])


if __name__ == "__main__":
    unittest.main()
