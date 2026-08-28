import io
import tempfile
import unittest
from pathlib import Path

from kdiag.cli import _parser, _progress_callback, _snapshot_config
from kdiag.orchestrator import _node_arguments


class CLIProgressTest(unittest.TestCase):
    def test_snapshot_progress_levels_and_cgroup_flag(self):
        arguments = _parser().parse_args(
            ["snapshot", "--inventory", "inventory.ini", "--skip-cgroup", "--progress", "detail"]
        )
        self.assertTrue(arguments.skip_cgroup)
        self.assertEqual("detail", arguments.progress)
        config = _snapshot_config(arguments)
        self.assertFalse(config["collection"]["collect_cgroup"])
        self.assertIn("--skip-cgroup", _node_arguments(config))

    def test_summary_hides_detail_and_off_has_no_writer(self):
        output = io.StringIO()
        progress = _progress_callback("summary", stream=output)
        progress("detail", "hidden")
        progress("summary", "visible")
        self.assertEqual("[kdiag] visible\n", output.getvalue())
        self.assertIsNone(_progress_callback("off", stream=output))

        detail_output = io.StringIO()
        detail = _progress_callback("detail", stream=detail_output)
        detail("detail", "source status")
        self.assertEqual("[kdiag] source status\n", detail_output.getvalue())

    def test_prometheus_password_is_read_from_file_not_command_line(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "prometheus-password"
            password_file.write_text("secret-from-file\n", encoding="utf-8")
            arguments = _parser().parse_args(
                [
                    "snapshot",
                    "--inventory",
                    "inventory.ini",
                    "--prometheus-url",
                    "https://prometheus.example.test",
                    "--prometheus-username",
                    "operator",
                    "--prometheus-password-file",
                    str(password_file),
                ]
            )
            config = _snapshot_config(arguments)
        self.assertEqual("operator", config["prometheus"]["username"])
        self.assertEqual("secret-from-file", config["prometheus"]["password"])

    def test_incident_purpose_resolves_window_and_passes_it_to_nodes(self):
        arguments = _parser().parse_args(
            [
                "snapshot",
                "--inventory",
                "inventory.ini",
                "--purpose",
                "incident",
                "--incident-start",
                "2026-08-27T10:00:00Z",
                "--incident-end",
                "2026-08-27T11:00:00Z",
            ]
        )
        config = _snapshot_config(arguments)
        self.assertEqual("incident", config["analysis"]["purpose"])
        node_arguments = _node_arguments(config)
        self.assertEqual("2026-08-27T10:00:00Z", node_arguments[node_arguments.index("--journal-since") + 1])
        self.assertEqual("2026-08-27T11:00:00Z", node_arguments[node_arguments.index("--journal-until") + 1])

    def test_incident_requires_an_explicit_window(self):
        arguments = _parser().parse_args(
            ["snapshot", "--inventory", "inventory.ini", "--purpose", "incident"]
        )
        with self.assertRaisesRegex(ValueError, "incident window"):
            _snapshot_config(arguments)


if __name__ == "__main__":
    unittest.main()
