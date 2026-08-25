import unittest
from unittest.mock import patch

from kdiag.node import collect_node_snapshot


class NodeSmokeTest(unittest.TestCase):
    def test_local_snapshot_is_partial_but_structured(self):
        snapshot = collect_node_snapshot(
            since_hours=1,
            timeout_seconds=1,
            max_command_bytes=64 * 1024,
            system_namespaces=[],
            application_namespaces=[],
            pod_log_tail_bytes=1024,
            pod_log_total_bytes=4096,
            pod_log_max_files=1,
        )
        self.assertEqual("node_snapshot", snapshot["kind"])
        self.assertEqual(1, snapshot["schema_version"])
        self.assertIn("kernel_release", snapshot["host"])
        self.assertIn("cgroup", snapshot["facts"])
        self.assertGreater(len(snapshot["commands"]), 10)

    def test_cgroup_collection_can_be_disabled(self):
        with patch("kdiag.node._cgroup_facts", side_effect=AssertionError("cgroup facts must not be read")), patch(
            "kdiag.node._process_cgroups", side_effect=AssertionError("process cgroups must not be read")
        ):
            snapshot = collect_node_snapshot(
                since_hours=1,
                timeout_seconds=1,
                max_command_bytes=64 * 1024,
                system_namespaces=[],
                application_namespaces=[],
                pod_log_tail_bytes=1024,
                pod_log_total_bytes=4096,
                pod_log_max_files=1,
                collect_cgroup=False,
            )
        self.assertEqual({"status": "disabled"}, snapshot["facts"]["cgroup"])
        self.assertEqual({"status": "disabled"}, snapshot["facts"]["process_cgroups"])
        self.assertFalse(snapshot["options"]["collect_cgroup"])


if __name__ == "__main__":
    unittest.main()
