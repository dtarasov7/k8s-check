import json
import unittest
from pathlib import Path

from kdiag.normalize import classify_message, correlate_events, normalize_evidence


FIXTURES = Path(__file__).parent / "fixtures"


class NormalizeTest(unittest.TestCase):
    def test_classification_uses_semantics_not_exact_line(self):
        categories = classify_message("write /sys/fs/cgroup/x/io.max: operation not permitted")
        self.assertIn("cgroup_access_denied", categories)
        self.assertIn("timeout", classify_message("context deadline exceeded"))

    def test_pinned_npd_signatures_are_classified(self):
        cases = {
            "task x:1 blocked for more than 120 seconds.": "npd_task_hung",
            "unregister_netdevice: waiting for veth0 to become free. Usage count = 1": "npd_unregister_netdevice",
            "BUG: unable to handle kernel NULL pointer dereference at 0": "npd_kernel_oops",
            "EXT4-fs error (device sda): bad inode": "npd_ext4_error",
            "EXT4-fs warning (device sda): test": "npd_ext4_warning",
            "Buffer I/O error on dev sda": "npd_io_error",
            "XFS (dm-0): Shutting down filesystem": "npd_xfs_shutdown",
            "CE memory read error page 1": "npd_memory_read_error",
            "mce: [Hardware Error]: event severity: fatal": "npd_hardware_fatal",
        }
        for message, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, classify_message(message))

    def test_synthetic_sources_are_normalized_and_correlated(self):
        journal = (FIXTURES / "journal-synthetic.jsonl").read_text(encoding="utf-8")
        kubernetes = json.loads((FIXTURES / "kubernetes-synthetic.json").read_text(encoding="utf-8"))
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [{"id": "journal_services_current", "stdout": journal}],
                "pod_logs": {"entries": []},
                "facts": {
                    "service_states": {
                        "kubelet.service": {
                            "status": "collected",
                            "properties": {"ActiveState": "failed", "SubState": "failed", "Result": "exit-code", "ExecMainStatus": "1"},
                        }
                    }
                },
            }
        }
        normalized = normalize_evidence({"collection_id": "synthetic"}, nodes, kubernetes)
        categories = {category for event in normalized["events"] for category in event["categories"]}
        for expected in (
            "cgroup_access_denied",
            "conntrack_full",
            "oom_kill",
            "cni_unavailable",
            "node_not_ready",
            "memory_pressure",
            "kubelet_inactive",
            "crash_loop",
            "probe_failure",
            "timeout",
        ):
            self.assertIn(expected, categories)
        correlation_ids = {item["correlation_id"] for item in normalized["correlations"]}
        self.assertIn("node_runtime_failure", correlation_ids)
        self.assertIn("node_cni_failure", correlation_ids)
        self.assertIn("cgroup_service_failure", correlation_ids)
        self.assertIn("memory_oom_failure", correlation_ids)
        self.assertEqual(1, normalized["stats"]["malformed_records"])
        self.assertEqual(1, normalized["stats"]["unknown_retained_fingerprints"])
        self.assertEqual(1, normalized["unknown_fingerprints"][0]["count"])

    def test_unknown_fingerprint_memory_is_bounded(self):
        def token(index):
            first, second = divmod(index, 26)
            return chr(97 + first) + chr(97 + second)

        journal = "\n".join(
            json.dumps({"MESSAGE": "ordinary synthetic token-" + token(index), "_SYSTEMD_UNIT": "demo.service"})
            for index in range(110)
        )
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [{"id": "journal_services_current", "stdout": journal}],
                "pod_logs": {"entries": []},
                "facts": {"service_states": {}},
            }
        }
        normalized = normalize_evidence({"collection_id": "unknowns"}, nodes, {})
        self.assertEqual(100, len(normalized["unknown_fingerprints"]))
        self.assertEqual(100, normalized["stats"]["unknown_retained_fingerprints"])
        self.assertEqual(10, normalized["stats"]["unknown_fingerprint_replacements"])

    def test_one_record_cannot_correlate_with_itself(self):
        event = {
            "event_id": "one",
            "timestamp_epoch": 1.0,
            "node": "node-1",
            "namespace": None,
            "pod": None,
            "categories": ["probe_failure", "timeout"],
            "source": "synthetic",
            "evidence": "synthetic#one",
        }
        self.assertEqual([], correlate_events([event]))

    def test_correlation_handles_large_single_category_stream(self):
        events = [
            {
                "event_id": "event-{0}".format(index),
                "timestamp_epoch": float(index),
                "node": "node-1",
                "namespace": None,
                "pod": None,
                "categories": ["probe_failure"],
                "source": "synthetic",
                "evidence": "synthetic#{0}".format(index),
            }
            for index in range(5000)
        ]
        self.assertEqual([], correlate_events(events))


if __name__ == "__main__":
    unittest.main()
