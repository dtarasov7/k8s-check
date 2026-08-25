import io
import unittest

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


if __name__ == "__main__":
    unittest.main()
