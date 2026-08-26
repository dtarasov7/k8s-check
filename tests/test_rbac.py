import unittest
from pathlib import Path


class RBACTest(unittest.TestCase):
    def test_extended_collector_permissions_remain_read_only(self):
        text = (Path(__file__).parents[1] / "deploy" / "kubernetes" / "kdiag-rbac.yaml").read_text(encoding="utf-8")
        for resource in (
            "apiservices",
            "leases",
            "volumeattachments",
            "csidrivers",
            "csinodes",
            "networkpolicies",
            "ciliumnodes",
            "ciliumendpoints",
        ):
            self.assertIn(resource, text)
        self.assertIn('nonResourceURLs: ["/readyz"]', text)
        self.assertNotIn("pods/exec", text)
        self.assertNotIn('resources: ["secrets"]', text)
        self.assertNotIn('verbs: ["create"]', text)
        self.assertNotIn('verbs: ["update"]', text)
        self.assertNotIn('verbs: ["patch"]', text)
        self.assertNotIn('verbs: ["delete"]', text)
        for namespace in ("d8-kube-dns", "d8-cni-cilium", "kube-system"):
            self.assertIn("namespace: {0}".format(namespace), text)
        self.assertEqual(3, text.count('resources: ["pods/log"]'))


if __name__ == "__main__":
    unittest.main()
