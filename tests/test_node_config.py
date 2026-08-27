import tempfile
import unittest
from pathlib import Path

from kdiag.node import KUBELET_CONFIG_KEYS, SERVICE_UNITS, _allowlisted_top_level_config, _authentication_config_files, _command_specs, _kubelet_certificate_rotation, _project_cri_records, _resolv_conf_facts


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


if __name__ == "__main__":
    unittest.main()
