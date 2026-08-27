import json
import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

from kdiag.node import KUBELET_CONFIG_KEYS, SERVICE_UNITS, _allowlisted_top_level_config, _authentication_config_files, _apply_cilium_fallback, _cilium_container_fallback, _command_specs, _kubelet_certificate_rotation, _project_cri_records, _resolv_conf_facts
from kdiag.runner import ProcessResult


class NodeConfigTest(unittest.TestCase):
    def test_current_journals_keep_newest_records_when_size_limited(self):
        commands = {check_id: argv for check_id, argv, _sensitivity in _command_specs(24)}
        self.assertIn("--reverse", commands["journal_services_current"])
        self.assertIn("--reverse", commands["journal_kernel_current"])

    def test_authentication_config_probe_collects_metadata_not_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authentication-config.yaml"
            path.write_text("secret-value", encoding="utf-8")
            result = _authentication_config_files((str(path), str(path.parent / "missing.yaml")))
        self.assertEqual("present", result[0]["status"])
        self.assertTrue(result[0]["regular_file"])
        self.assertEqual("absent", result[1]["status"])
        self.assertNotIn("secret-value", __import__("json").dumps(result))

    def test_deckhouse_containerd_is_collected_like_other_runtimes(self):
        self.assertIn("containerd-deckhouse.service", SERVICE_UNITS)
        journal = {check_id: argv for check_id, argv, _sensitivity in _command_specs(24)}["journal_services_current"]
        self.assertIn("containerd-deckhouse.service", journal)

    def test_kubelet_cluster_dns_block_list_is_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "clusterDNS:\n  - 10.96.0.10\n  - fd00::a\ncgroupDriver: systemd\nauthentication:\n  anonymous:\n    enabled: true\n",
                encoding="utf-8",
            )
            result = _allowlisted_top_level_config(str(path), KUBELET_CONFIG_KEYS)
        self.assertEqual(["10.96.0.10", "fd00::a"], result["values"]["clusterDNS"])
        self.assertEqual("systemd", result["values"]["cgroupDriver"])
        self.assertNotIn("authentication", result["values"])

    def test_cri_projection_drops_labels_and_annotations(self):
        record = {"id": "runtime_crictl_containers", "status": "collected", "stdout": '{"containers":[{"id":"c1","metadata":{"name":"app","attempt":1},"labels":{"token":"SECRET"},"annotations":{"token":"SECRET"},"image":{"image":"demo:v1"},"state":"CONTAINER_RUNNING"}]}' }
        projected = _project_cri_records(record, "containers")
        self.assertNotIn("SECRET", projected["stdout"])
        self.assertEqual("app", __import__("json").loads(projected["stdout"])["containers"][0]["metadata"]["name"])

    def test_resolver_and_kubelet_certificate_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resolv = root / "resolv.conf"
            resolv.write_text("nameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch svc.cluster.local\noptions ndots:5\n", encoding="utf-8")
            target = root / "kubelet-client-2026.pem"
            target.write_text("certificate", encoding="utf-8")
            (root / "kubelet-client-current.pem").symlink_to(target.name)
            facts = _resolv_conf_facts(str(resolv))
            rotation = _kubelet_certificate_rotation(str(root))
        self.assertEqual(["10.0.0.1", "10.0.0.2"], facts["nameservers"])
        self.assertEqual("collected", rotation["status"])
        self.assertEqual(target.name, rotation["target"])

    def test_cilium_cli_falls_back_to_the_running_agent_container(self):
        commands = [
            {
                "id": "runtime_crictl_pods",
                "status": "collected",
                "stdout": json.dumps(
                    {
                        "items": [
                            {
                                "id": "sandbox12345678",
                                "metadata": {"name": "agent-node-a", "namespace": "d8-cni-cilium"},
                                "state": "SANDBOX_READY",
                            }
                        ]
                    }
                ),
            },
            {
                "id": "runtime_crictl_containers",
                "status": "collected",
                "stdout": json.dumps(
                    {
                        "containers": [
                            {
                                "id": "abcdef1234567890",
                                "podSandboxId": "sandbox12345678",
                                "metadata": {"name": "cilium-agent"},
                                "state": "CONTAINER_RUNNING",
                            }
                        ]
                    }
                ),
            },
            {"id": "cilium_status", "status": "unsupported"},
            {"id": "cilium_debug_status", "status": "unsupported"},
            {"id": "cilium_services", "status": "unsupported"},
            {"id": "cilium_debug_services", "status": "unsupported"},
        ]
        calls = []

        def fake_run(argv, timeout_seconds, max_stdout_bytes):
            calls.append(list(argv))
            if argv[3] == "cilium-dbg":
                return ProcessResult(list(argv), 127, b"", b"not found", "start", "end", 1)
            stdout = b'{"services":[]}' if "service" in argv else b'{"cilium-health":{"overallHealth":"OK"}}'
            return ProcessResult(list(argv), 0, stdout, b"", "start", "end", 1)

        with patch("kdiag.node.shutil.which", return_value="/opt/deckhouse/bin/crictl"), patch(
            "kdiag.node.run_process", side_effect=fake_run
        ):
            fallback = _cilium_container_fallback(commands, 5, 4096)
        self.assertEqual(["cilium_debug_status", "cilium_debug_services"], [item["id"] for item in fallback])
        self.assertTrue(all(call[:3] == ["/opt/deckhouse/bin/crictl", "exec", "abcdef1234567890"] for call in calls))
        self.assertTrue(any("/usr/bin/cilium-dbg" in call for call in calls))
        self.assertTrue(all(item["pod"] == "d8-cni-cilium/agent-node-a" for item in fallback))

    def test_cilium_v114_vanilla_pod_uses_cilium_binary(self):
        commands = [
            {
                "id": "runtime_crictl_pods",
                "status": "collected",
                "stdout": '{"items":[{"id":"sandbox12345678","metadata":{"name":"cilium-worker-a","namespace":"kube-system"},"state":"SANDBOX_READY"}]}',
            },
            {
                "id": "runtime_crictl_containers",
                "status": "collected",
                "stdout": '{"containers":[{"id":"abcdef1234567890","podSandboxId":"sandbox12345678","metadata":{"name":"cilium-agent"},"state":"CONTAINER_RUNNING"}]}',
            },
        ]

        def fake_run(argv, timeout_seconds, max_stdout_bytes):
            if argv[3] != "/usr/bin/cilium":
                return ProcessResult(list(argv), 127, b"", b"not found", "start", "end", 1)
            stdout = b'{"services":[]}' if "service" in argv else b'{"cilium-health":{"overallHealth":"OK"}}'
            return ProcessResult(list(argv), 0, stdout, b"", "start", "end", 1)

        with patch("kdiag.node.shutil.which", return_value="/usr/bin/crictl"), patch(
            "kdiag.node.run_process", side_effect=fake_run
        ):
            fallback = _cilium_container_fallback(commands, 5, 4096)
        self.assertEqual(2, len(fallback))
        self.assertTrue(all(item["binary"] == "/usr/bin/cilium" for item in fallback))
        self.assertTrue(all(item["pod"] == "kube-system/cilium-worker-a" for item in fallback))

    def test_successful_cilium_fallback_removes_equivalent_host_failures(self):
        commands = [
            {"id": "cilium_status", "status": "unsupported"},
            {"id": "cilium_debug_status", "status": "unsupported"},
            {"id": "cilium_services", "status": "unsupported"},
            {"id": "cilium_debug_services", "status": "unsupported"},
        ]
        replacements = [
            {"id": "cilium_debug_status", "status": "collected"},
            {"id": "cilium_debug_services", "status": "collected"},
        ]
        result = _apply_cilium_fallback(commands, replacements)
        self.assertEqual(["cilium_debug_status", "cilium_debug_services"], [item["id"] for item in result])


if __name__ == "__main__":
    unittest.main()
