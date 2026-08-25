import json
import tempfile
import unittest
from pathlib import Path

from kdiag.config import load_config


class ConfigTest(unittest.TestCase):
    def test_known_override_is_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"collection": {"parallelism": 1}}), encoding="utf-8")
            config = load_config(path)
        self.assertEqual(1, config["collection"]["parallelism"])
        self.assertEqual(24, config["collection"]["since_hours"])

    def test_unknown_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"collection": {"typo": 1}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_remote_python_rejects_shell_syntax_and_parent_segments(self):
        for value in ("/usr/bin/python3.8;id", "/usr/bin/python 3.8", "/usr/../tmp/python3.8"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                path.write_text(json.dumps({"ssh": {"remote_python": value}}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "safe absolute path"):
                    load_config(path)

    def test_collect_etcd_requires_boolean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"collection": {"collect_etcd": "yes"}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "collect_etcd must be boolean"):
                load_config(path)

    def test_collect_cgroup_can_be_disabled_and_requires_boolean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"collection": {"collect_cgroup": False}}), encoding="utf-8")
            config = load_config(path)
        self.assertFalse(config["collection"]["collect_cgroup"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"collection": {"collect_cgroup": "no"}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "collect_cgroup must be boolean"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
