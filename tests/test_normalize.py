import json
import unittest
from pathlib import Path
from unittest import mock

import kdiag.normalize as normalize_module
from kdiag.normalize import classify_message, correlate_events, normalize_evidence


FIXTURES = Path(__file__).parent / "fixtures"


class NormalizeTest(unittest.TestCase):
    def test_classification_uses_semantics_not_exact_line(self):
        categories = classify_message("write /sys/fs/cgroup/x/io.max: operation not permitted")
        self.assertIn("cgroup_access_denied", categories)
        self.assertIn("timeout", classify_message("context deadline exceeded"))

    def test_classification_rejects_node_and_dns_signatures_in_unrelated_logs(self):
        self.assertNotIn(
            "cgroup_access_denied",
            classify_message("cgroup write: operation not permitted", source="cri_log", component="application"),
        )
        self.assertNotIn(
            "npd_ext4_error",
            classify_message("EXT4-fs error (device demo)", source="kubernetes_pod_log", component="application"),
        )
        self.assertNotIn(
            "dns_servfail",
            classify_message("request returned SERVFAIL", source="kubernetes_pod_log", component="application"),
        )
        self.assertIn(
            "dns_servfail",
            classify_message("request returned SERVFAIL", source="kubernetes_pod_log", component="coredns"),
        )

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

    def test_disabled_cgroup_checks_suppress_cgroup_events_and_correlations(self):
        journal = (FIXTURES / "journal-synthetic.jsonl").read_text(encoding="utf-8")
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [{"id": "journal_services_current", "stdout": journal}],
                "pod_logs": {"entries": []},
                "facts": {
                    "service_states": {
                        "kubelet.service": {
                            "status": "collected",
                            "properties": {"ActiveState": "failed"},
                        }
                    }
                },
            }
        }
        normalized = normalize_evidence(
            {"collection_id": "no-cgroup", "options": {"collect_cgroup": False}},
            nodes,
            {},
        )
        categories = {category for event in normalized["events"] for category in event["categories"]}
        correlation_ids = {item["correlation_id"] for item in normalized["correlations"]}
        self.assertNotIn("cgroup_access_denied", categories)
        self.assertNotIn("cgroup_service_failure", correlation_ids)
        self.assertGreater(normalized["stats"]["cgroup_events_suppressed"], 0)
        for event in normalized["events"]:
            self.assertNotIn("read_only_fs", event["categories"])

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

    def test_all_inferred_timestamps_are_excluded_from_correlations(self):
        events = [
            self._correlation_event("one", 1, ["probe_failure"], pod="pod-a", inferred=True),
            self._correlation_event("two", 2, ["timeout"], pod="pod-a"),
        ]
        self.assertEqual([], correlate_events(events))

    def test_probe_correlation_is_scoped_to_pod(self):
        events = [
            self._correlation_event("one", 1, ["probe_failure"], pod="pod-a"),
            self._correlation_event("two", 2, ["timeout"], pod="pod-b"),
        ]
        self.assertEqual([], correlate_events(events))

    def test_node_correlation_is_scoped_to_node(self):
        events = [
            self._correlation_event("one", 1, ["node_not_ready"], node="node-a"),
            self._correlation_event("two", 2, ["runtime_unavailable"], node="node-b"),
        ]
        self.assertEqual([], correlate_events(events))

    def test_correlation_emits_independent_episodes_with_timing(self):
        events = []
        for prefix, start in (("first", 10), ("second", 2000)):
            events.extend(
                (
                    self._correlation_event(prefix + "-probe", start, ["probe_failure"], pod="pod-a"),
                    self._correlation_event(prefix + "-timeout", start + 5, ["timeout"], pod="pod-a"),
                )
            )
        episodes = [item for item in correlate_events(events) if item["correlation_id"] == "probe_network_failure"]
        self.assertEqual(2, len(episodes))
        self.assertEqual([5.0, 5.0], [item["duration_seconds"] for item in episodes])
        self.assertTrue(all(item["episode_id"] for item in episodes))
        self.assertEqual(2, len({item["episode_id"] for item in episodes}))

    @staticmethod
    def _correlation_event(event_id, timestamp, categories, node="node-1", pod=None, inferred=False):
        return {
            "event_id": event_id,
            "timestamp": "2026-01-01T00:{0:02d}:00Z".format(timestamp % 60),
            "timestamp_epoch": float(timestamp),
            "timestamp_inferred": inferred,
            "node": node,
            "namespace": "demo" if pod else None,
            "pod": pod,
            "categories": categories,
            "source": "synthetic",
            "evidence": "synthetic#" + event_id,
        }

    def test_normalization_deduplicates_and_serializes_stats(self):
        duplicate = json.dumps(
            {
                "MESSAGE": "context deadline exceeded",
                "_SYSTEMD_UNIT": "kubelet.service",
                "__REALTIME_TIMESTAMP": "1767225600000000",
            }
        )
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [{"id": "journal_services_current", "stdout": duplicate + "\n" + duplicate}],
                "pod_logs": {"entries": []},
                "facts": {"service_states": {}},
            }
        }
        normalized = normalize_evidence({"collection_id": "duplicates"}, nodes, {})
        self.assertEqual(1, len(normalized["events"]))
        self.assertEqual(2, normalized["events"][0]["occurrence_count"])
        self.assertEqual(1, normalized["stats"]["deduplicated_records"])
        json.dumps(normalized)

    def test_output_limit_round_robins_between_sources(self):
        journal = "\n".join(
            json.dumps(
                {
                    "MESSAGE": "context deadline exceeded token-{0}".format(index),
                    "_SYSTEMD_UNIT": "kubelet.service",
                    "__REALTIME_TIMESTAMP": str(1767225600000000 + index * 1000000),
                }
            )
            for index in range(3)
        )
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [{"id": "journal_services_current", "stdout": journal}],
                "pod_logs": {"entries": []},
                "facts": {"service_states": {}},
            }
        }
        kubernetes = {
            "collected_at": "2026-01-01T00:10:00Z",
            "logs": {
                "entries": [
                    {
                        "namespace": "demo",
                        "pod": "pod-a",
                        "container": "app",
                        "text": "2026-01-01T00:00:00Z context deadline exceeded from pod",
                    }
                ]
            },
        }
        with mock.patch.object(normalize_module, "MAX_NORMALIZED_EVENTS", 2):
            normalized = normalize_evidence({"collection_id": "limited"}, nodes, kubernetes)
        self.assertEqual({"journal", "kubernetes_pod_log"}, {event["source"] for event in normalized["events"]})
        self.assertEqual(2, normalized["stats"]["output_limit_drops"])
        self.assertTrue(normalized["stats"]["truncated"])

    def test_runtime_state_ignores_missing_and_inactive_alternative_units(self):
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [],
                "pod_logs": {"entries": []},
                "facts": {
                    "service_states": {
                        "containerd.service": {
                            "status": "collected",
                            "properties": {"LoadState": "loaded", "ActiveState": "inactive"},
                        },
                        "containerd-deckhouse.service": {
                            "status": "collected",
                            "properties": {"LoadState": "loaded", "ActiveState": "active"},
                        },
                        "crio.service": {
                            "status": "collected",
                            "properties": {"LoadState": "not-found", "ActiveState": "inactive"},
                        },
                    }
                },
            }
        }
        normalized = normalize_evidence({"collection_id": "deckhouse"}, nodes, {})
        categories = {category for event in normalized["events"] for category in event["categories"]}
        self.assertNotIn("runtime_unavailable", categories)

    def test_failed_loaded_deckhouse_runtime_is_reported_as_state_not_timed_event(self):
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [],
                "pod_logs": {"entries": []},
                "facts": {
                    "service_states": {
                        "containerd.service": {
                            "status": "collected",
                            "properties": {"LoadState": "not-found", "ActiveState": "inactive"},
                        },
                        "containerd-deckhouse.service": {
                            "status": "collected",
                            "properties": {"LoadState": "loaded", "ActiveState": "failed"},
                        },
                        "crio.service": {
                            "status": "collected",
                            "properties": {"LoadState": "not-found", "ActiveState": "inactive"},
                        },
                    }
                },
            }
        }
        normalized = normalize_evidence({"collection_id": "deckhouse-failed"}, nodes, {})
        runtime_events = [event for event in normalized["events"] if "runtime_unavailable" in event["categories"]]
        self.assertEqual(1, len(runtime_events))
        self.assertEqual("containerd-deckhouse.service", runtime_events[0]["component"])
        cgroup_event = {
            "event_id": "cgroup",
            "timestamp_epoch": runtime_events[0]["timestamp_epoch"] - 1,
            "node": "node-1",
            "categories": ["cgroup_access_denied"],
            "source": "journal",
            "evidence": "journal#1",
        }
        self.assertNotIn(
            "cgroup_service_failure",
            {item["correlation_id"] for item in correlate_events([cgroup_event] + runtime_events)},
        )

    def test_runtime_state_requires_explicit_loaded_state(self):
        nodes = {
            "node-1": {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [],
                "pod_logs": {"entries": []},
                "facts": {
                    "service_states": {
                        "containerd.service": {
                            "status": "collected",
                            "properties": {"ActiveState": "failed"},
                        }
                    }
                },
            }
        }
        normalized = normalize_evidence({"collection_id": "runtime-load-unknown"}, nodes, {})
        categories = {category for event in normalized["events"] for category in event["categories"]}
        self.assertNotIn("runtime_unavailable", categories)

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
