import tempfile
import unittest
from pathlib import Path

from kdiag.bundle import verify_manifest, write_manifest


class BundleTest(unittest.TestCase):
    def test_manifest_verifies_unchanged_files_and_detects_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "collection.json").write_bytes(b"{}\n")
            (root / "report.md").write_bytes(b"report\n")
            write_manifest(root)

            result = verify_manifest(root)
            self.assertEqual("verified", result["status"])
            self.assertEqual(2, result["members"])

            (root / "report.md").write_bytes(b"tamper\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_manifest(root)

    def test_manifest_detects_unexpected_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "collection.json").write_bytes(b"{}\n")
            write_manifest(root)
            (root / "extra.txt").write_bytes(b"extra\n")
            with self.assertRaisesRegex(ValueError, "absent from manifest"):
                verify_manifest(root)

    def test_manifest_rejects_non_file_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            with self.assertRaisesRegex(ValueError, "non-file"):
                write_manifest(root)


if __name__ == "__main__":
    unittest.main()
