import unittest

from kdiag.rule_catalog import RULE_CATALOG
from kdiag.selftest import run_self_test


class SelfTestTest(unittest.TestCase):
    def test_embedded_self_test_passes(self):
        result = run_self_test()
        self.assertEqual("passed", result["status"])
        self.assertTrue(all(item["status"] == "passed" for item in result["checks"]))

    def test_catalog_has_only_documented_classifications(self):
        for rule_id, metadata in RULE_CATALOG.items():
            with self.subTest(rule_id=rule_id):
                self.assertIn(metadata["classification"], ("fact", "correlation", "hypothesis"))
                self.assertTrue(metadata["sources"])


if __name__ == "__main__":
    unittest.main()
