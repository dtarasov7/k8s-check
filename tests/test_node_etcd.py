import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kdiag.node import _container_root_executable, _etcd_snapshot
from kdiag.runner import ProcessResult


def result(argv, stdout=b"", returncode=0):
    return ProcessResult(
        list(argv),
        returncode,
        stdout,
        b"" if returncode == 0 else b"failure",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1,
    )


class EtcdCollectionTest(unittest.TestCase):
    def test_container_root_executable_uses_inspected_container_pid(self):
        inspected = result(
            ["/usr/bin/crictl", "inspect", "container-id"],
            b'{"info":{"pid":4321}}',
        )
        with patch("kdiag.node.run_process", return_value=inspected), patch(
            "kdiag.node.Path.is_file", return_value=True
        ), patch("kdiag.node.os.access", return_value=True):
            executable = _container_root_executable(
                "/usr/bin/crictl", "container-id", "etcdctl", 5, 4096
            )
        self.assertEqual("/proc/4321/root/usr/bin/etcdctl", executable)

    def test_non_control_plane_node_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            value = _etcd_snapshot(True, 5, 1024, manifest_path=str(Path(directory) / "missing.yaml"))
        self.assertEqual("not_applicable", value["status"])
        self.assertEqual([], value["commands"])

    def test_crictl_transport_runs_only_allowlisted_read_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("etcd.yaml", "ca.crt", "health.crt", "health.key")]
            for path in paths:
                path.write_text("synthetic", encoding="utf-8")
            paths[0].write_text("    - --quota-backend-bytes=2147483648\n", encoding="utf-8")

            calls = []

            def fake_run(argv, timeout_seconds, max_stdout_bytes):
                calls.append(list(argv))
                if "ps" in argv:
                    return result(argv, b"container-id\n")
                if "health" in argv:
                    return result(argv, b'[{"endpoint":"a","health":true}]')
                if "status" in argv:
                    return result(argv, b'[{"Endpoint":"a","Status":{"leader":1}}]')
                return result(argv, b'{"alarms":[]}')

            with patch(
                "kdiag.node.shutil.which",
                side_effect=lambda name: "/usr/bin/crictl" if name == "crictl" else "/usr/bin/etcdctl" if name == "etcdctl" else None,
            ), patch(
                "kdiag.node.run_process", side_effect=fake_run
            ):
                value = _etcd_snapshot(
                    True,
                    5,
                    4096,
                    manifest_path=str(paths[0]),
                    ca_path=str(paths[1]),
                    cert_path=str(paths[2]),
                    key_path=str(paths[3]),
                )
        self.assertEqual("collected", value["status"])
        self.assertEqual("crictl", value["transport"])
        self.assertEqual(2147483648, value["quota_backend_bytes"])
        joined = [" ".join(argv) for argv in calls]
        self.assertTrue(any("endpoint status" in item for item in joined))
        self.assertTrue(any("endpoint health" in item for item in joined))
        self.assertTrue(any("alarm list" in item for item in joined))
        self.assertFalse(any(any(word in item for word in ("defrag", "compact", "disarm", "snapshot", "member remove", "member add")) for item in joined))

    def test_failed_container_exec_falls_back_to_binary_from_running_container_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("etcd.yaml", "ca.crt", "health.crt", "health.key")]
            for path in paths:
                path.write_text("synthetic", encoding="utf-8")

            calls = []

            def fake_run(argv, timeout_seconds, max_stdout_bytes):
                calls.append(list(argv))
                if "ps" in argv:
                    return result(argv, b"container-id\n")
                if argv[:3] == ["/usr/bin/crictl", "exec", "container-id"]:
                    return result(argv, returncode=1)
                if argv[0] == "/proc/4321/root/usr/bin/etcdctl":
                    if "health" in argv:
                        return result(argv, b'[{"endpoint":"a","health":true}]')
                    if "status" in argv:
                        return result(argv, b'[{"Endpoint":"a","Status":{"leader":1}}]')
                    return result(argv, b'{"alarms":[]}')
                return result(argv, returncode=1)

            with patch(
                "kdiag.node.shutil.which",
                side_effect=lambda name: "/usr/bin/crictl" if name == "crictl" else None,
            ), patch(
                "kdiag.node._container_root_executable",
                return_value="/proc/4321/root/usr/bin/etcdctl",
            ), patch(
                "kdiag.node.run_process", side_effect=fake_run
            ):
                value = _etcd_snapshot(
                    True,
                    5,
                    4096,
                    manifest_path=str(paths[0]),
                    ca_path=str(paths[1]),
                    cert_path=str(paths[2]),
                    key_path=str(paths[3]),
                )
        self.assertEqual("collected", value["status"])
        self.assertEqual("host-container-root", value["transport"])
        self.assertEqual("crictl", value["fallback_from"])
        self.assertTrue(any(call[0] == "/proc/4321/root/usr/bin/etcdctl" for call in calls))


if __name__ == "__main__":
    unittest.main()
