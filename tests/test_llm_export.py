import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from kdiag.cli import main
from kdiag.llm_client import analyze_local
from kdiag.llm_export import import_llm_response, prepare_llm_export, validate_external_export
from kdiag.util import atomic_write_gzip_json, atomic_write_json, load_gzip_json


class _FakeHTTPResponse:
    def __init__(self, document):
        self.payload = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        return False

    def read(self, limit):
        return self.payload[:limit]


class LLMExportTest(unittest.TestCase):
    def _collection(self, root):
        collection = root / "collection"
        collection.mkdir()
        atomic_write_json(
            collection / "collection.json",
            {
                "schema_version": 1,
                "collector_version": "0.4.0",
                "collection_id": "incident-internal",
                "status": "partial",
                "started_at": "2026-01-01T00:00:00Z",
                "ended_at": "2026-01-01T00:10:00Z",
                "nodes": [
                    {"host": "node-a.internal.example", "status": "collected", "file": "node-a.json.gz"},
                    {"host": "node-b.internal.example", "status": "unreachable", "error": "ssh 10.10.0.12 failed"},
                ],
                "kubernetes": {"status": "partial", "file": "kubernetes.json.gz"},
                "prometheus": {"status": "not_configured", "file": "prometheus.json.gz"},
            },
        )
        atomic_write_json(
            collection / "facts.json",
            {
                "schema_version": 1,
                "nodes": [
                    {
                        "inventory_host": "node-a.internal.example",
                        "hostname": "node-a.internal.example",
                        "os": "RED OS 7.3",
                        "kernel": "6.1.0-1",
                        "cgroup_mode": "v2",
                        "kubelet_state": "active",
                    }
                ],
                "kubernetes": {"status": "partial", "sources": {"pods": {"status": "collected", "item_count": 2}}},
                "normalization": {"stats": {"input_records": 3}, "correlation_count": 1, "unknown_fingerprint_count": 1},
            },
        )
        atomic_write_json(
            collection / "report.json",
            {
                "schema_version": 1,
                "rule_pack_version": "2026.08.3",
                "collection_id": "incident-internal",
                "status": "partial",
                "coverage": [
                    {"source": "node/node-a.internal.example", "status": "collected", "required": True},
                    {"source": "node/node-b.internal.example", "status": "unreachable", "required": True, "error": "ssh 10.10.0.12 failed"},
                    {"source": "kubernetes/pods", "status": "collected", "required": True},
                ],
                "findings": [
                    {
                        "id": "kubernetes.pod_waiting:private-ns/api-pod-7d9",
                        "rule_id": "kubernetes.pod_waiting",
                        "classification": "fact",
                        "rule_pack_version": "2026.08.3",
                        "severity": "warning",
                        "causal_confidence": "high",
                        "title": "Pod cannot start",
                        "summary": "api-pod-7d9 on node-a.internal.example cannot connect to 10.10.0.12:8443 via /var/lib/private/socket",
                        "affected": ["private-ns/api-pod-7d9"],
                        "evidence": ["node-node-a.internal.example.json.gz#commands.journal_services_current:line-3"],
                        "alternatives": ["Service payments-internal may be unavailable"],
                        "counter_evidence": [],
                        "missing_checks": ["check service account build-bot"],
                        "recommendation": "Inspect Cilium v1.14.6 and containerd 1.6.28 without changing the cluster.",
                    }
                ],
            },
        )
        atomic_write_gzip_json(
            collection / "normalized-events.json.gz",
            {
                "stats": {"input_records": 3, "categorized_records": 2},
                "events": [
                    {
                        "event_id": "raw-event-id",
                        "timestamp_epoch": 100.0,
                        "source": "journal",
                        "node": "node-a.internal.example",
                        "namespace": "private-ns",
                        "pod": "api-pod-7d9",
                        "container": "private-api",
                        "component": "private-api.service",
                        "reason": "Failed",
                        "severity": "warning",
                        "categories": ["connection_refused"],
                        "message_excerpt": "connect 10.10.0.12:8443 for user deploy-user failed",
                        "evidence": "node-node-a.internal.example.json.gz#commands.journal_services_current:line-3",
                    }
                ],
                "correlations": [
                    {
                        "correlation_id": "node_runtime_failure",
                        "scope": "node-a.internal.example",
                        "categories": ["node_not_ready", "runtime_unavailable"],
                        "sources": ["journal", "kubernetes_event"],
                        "window_seconds": 900,
                        "evidence": ["node-node-a.internal.example.json.gz#commands.journal_services_current:line-3"],
                    }
                ],
                "unknown_fingerprints": [
                    {"component": "private-api.service", "fingerprint": "abcdef", "template": "request to 10.10.0.12 failed for deploy-user", "count": 4, "estimate_error": 0}
                ],
            },
        )
        return collection

    def test_external_export_removes_internal_topology_and_restores_known_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            destination = root / "llm"
            result = prepare_llm_export(
                collection,
                destination,
                profile="external",
                mode="fast-triage",
                question="Why does api-pod-7d9 fail on node-a.internal.example?",
            )
            export_text = "\n".join(path.read_text(encoding="utf-8") for path in sorted((destination / "export").glob("*.json")))
            export_text += (destination / "export" / "prompt.external.txt").read_text(encoding="utf-8")
            for forbidden in (
                "node-a.internal.example",
                "node-b.internal.example",
                "private-ns",
                "api-pod-7d9",
                "payments-internal",
                "build-bot",
                "deploy-user",
                "10.10.0.12",
                "/var/lib/private/socket",
                "8443",
            ):
                self.assertNotIn(forbidden, export_text)
            self.assertIn("Cilium", export_text)
            self.assertIn("v1.14.6", export_text)
            self.assertEqual("passed", validate_external_export(destination / "export")["status"])
            self.assertTrue(result["token_map"].is_file())
            self.assertEqual(0o600, result["token_map"].stat().st_mode & 0o777)

            token_map = json.loads(result["token_map"].read_text(encoding="utf-8"))
            node_token = next(token for token, item in token_map["tokens"].items() if item["value"] == "node-a.internal.example")
            response = root / "response.txt"
            response.write_text("Investigate {0}; evidence EVIDENCE_001.".format(node_token), encoding="utf-8")
            imported = import_llm_response(response, result["token_map"], root / "imported")
            restored = imported["restored"].read_text(encoding="utf-8")
            self.assertIn("node-a.internal.example", restored)
            self.assertIn("EVIDENCE_001", restored)

    def test_local_prepared_package_is_minimized_but_keeps_local_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            destination = root / "local"
            prepare_llm_export(collection, destination, profile="local", mode="deep-analysis", question="Analyze incident")
            incident = (destination / "prepared" / "incident.local.json").read_text(encoding="utf-8")
            self.assertFalse((destination / "export").exists())
            self.assertIn("node-a.internal.example", incident)
            self.assertIn("api-pod-7d9", incident)
            self.assertNotIn("ssh 10.10.0.12 failed", incident)

    def test_canary_secret_blocks_external_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            with self.assertRaisesRegex(ValueError, "canary"):
                prepare_llm_export(
                    collection,
                    root / "blocked",
                    profile="external",
                    mode="fast-triage",
                    question="KDIAG_CANARY_DO_NOT_EXPORT",
                )

    def test_cli_manual_external_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            destination = root / "cli-export"
            self.assertEqual(
                0,
                main(
                    [
                        "llm", "prepare", str(collection), "--output-dir", str(destination),
                        "--profile", "external", "--question", "Analyze the affected workload",
                    ]
                ),
            )
            self.assertEqual(0, main(["llm", "validate-export", str(destination / "export")]))

    def test_response_contract_rejects_unknown_evidence_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            prepared = prepare_llm_export(
                collection,
                root / "external",
                profile="external",
                mode="fast-triage",
                question="Analyze the incident",
            )
            response = root / "response.json"
            response.write_text(
                json.dumps(
                    {
                        "claims": [
                            {
                                "text": "Run kubectl delete pod before checking evidence",
                                "supporting_evidence_ids": ["EVIDENCE_999"],
                                "contradicting_evidence_ids": [],
                                "confidence_label": "high",
                            }
                        ],
                        "missing_check_ids": [],
                        "alternatives": [],
                        "operator_questions": [],
                        "version_scope": "unknown",
                        "abstain_reason": None,
                    }
                ),
                encoding="utf-8",
            )
            imported = import_llm_response(response, prepared["token_map"], root / "rejected-response")
            report = json.loads(imported["report"].read_text(encoding="utf-8"))
            self.assertEqual("rejected", report["validation_status"])
            self.assertEqual(["EVIDENCE_999"], report["unknown_evidence_ids"])
            self.assertTrue(report["mutating_commands_detected"])

    def test_response_contract_accepts_known_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            prepared = prepare_llm_export(
                collection,
                root / "external",
                profile="external",
                mode="deep-analysis",
                question="Analyze the incident",
            )
            response = root / "response.json"
            response.write_text(
                json.dumps(
                    {
                        "claims": [
                            {
                                "text": "Runtime or network initialization failed",
                                "supporting_evidence_ids": ["EVIDENCE_001"],
                                "contradicting_evidence_ids": [],
                                "confidence_label": "medium",
                            }
                        ],
                        "missing_check_ids": ["runtime-status"],
                        "alternatives": [],
                        "operator_questions": [],
                        "version_scope": "Cilium v1.14.6",
                        "abstain_reason": None,
                    }
                ),
                encoding="utf-8",
            )
            imported = import_llm_response(response, prepared["token_map"], root / "valid-response")
            report = json.loads(imported["report"].read_text(encoding="utf-8"))
            self.assertEqual("validated", report["validation_status"])

    def test_package_budget_truncates_events_but_keeps_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            normalized_path = collection / "normalized-events.json.gz"
            normalized = load_gzip_json(normalized_path)
            prototype = dict(normalized["events"][0])
            normalized["events"] = []
            for index in range(120):
                event = dict(prototype)
                event["event_id"] = "event-{0}".format(index)
                event["timestamp_epoch"] = 100.0 + index
                event["message_excerpt"] = "diagnostic marker {0} ".format(index) + ("x" * 900)
                normalized["events"].append(event)
            atomic_write_gzip_json(normalized_path, normalized)
            prepared = prepare_llm_export(
                collection,
                root / "bounded",
                profile="local",
                mode="deep-analysis",
                question="Разбери инцидент и сохрани подтверждённую причину",
                max_package_bytes=16 * 1024,
            )
            self.assertLessEqual(prepared["package"].stat().st_size, 16 * 1024)
            package = json.loads(prepared["package"].read_text(encoding="utf-8"))
            self.assertEqual("Pod cannot start", package["findings"][0]["title"])
            self.assertGreater(package["truncation"]["removed"]["events"], 0)

    def test_analyze_local_sends_prepared_package_and_validates_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            prepared = prepare_llm_export(
                collection,
                root / "prepared",
                profile="local",
                mode="fast-triage",
                question="Analyze the incident",
            )
            model_response = {
                "claims": [
                    {
                        "text": "The runtime or network path failed",
                        "supporting_evidence_ids": ["EVIDENCE_001"],
                        "contradicting_evidence_ids": [],
                        "confidence_label": "medium",
                    }
                ],
                "missing_check_ids": [],
                "alternatives": [],
                "operator_questions": [],
                "version_scope": "Cilium v1.14.6",
                "abstain_reason": None,
            }
            envelope = {"choices": [{"message": {"content": json.dumps(model_response)}}]}
            with patch("kdiag.llm_client._open_local_request", return_value=_FakeHTTPResponse(envelope)) as request_call:
                return_code = main(
                    [
                        "llm", "analyze-local", str(prepared["prepared"]),
                        "--output-dir", str(root / "analysis"),
                        "--endpoint", "http://127.0.0.1:8080/v1/chat/completions",
                        "--model", "local-test-model",
                    ]
                )
            self.assertEqual(0, return_code)
            self.assertTrue((root / "analysis" / "response.validated.json").is_file())
            self.assertTrue((root / "analysis" / "manifest.json").is_file())
            request = request_call.call_args.args[0]
            payload = json.loads(request.data.decode("utf-8"))
            self.assertEqual("local-test-model", payload["model"])
            self.assertEqual({"type": "json_object"}, payload["response_format"])
            self.assertIn("Pod cannot start", payload["messages"][1]["content"])
            self.assertNotIn(str(collection), request.data.decode("utf-8"))

    def test_analyze_local_rejects_non_loopback_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            prepared = prepare_llm_export(
                collection,
                root / "prepared",
                profile="local",
                mode="fast-triage",
                question="Analyze the incident",
            )
            with self.assertRaisesRegex(ValueError, "literal loopback"):
                analyze_local(
                    prepared["prepared"],
                    root / "analysis",
                    "http://llm.internal.example/v1/chat/completions",
                    "local-test-model",
                )

    def test_analyze_local_reports_unavailable_service_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            prepared = prepare_llm_export(
                collection,
                root / "prepared",
                profile="local",
                mode="fast-triage",
                question="Analyze the incident",
            )
            with patch("kdiag.llm_client._open_local_request", side_effect=URLError("connection refused")):
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    analyze_local(
                        prepared["prepared"],
                        root / "analysis",
                        "http://127.0.0.1:8080/v1/chat/completions",
                        "local-test-model",
                        timeout_seconds=1,
                    )
            self.assertFalse((root / "analysis").exists())

    def test_analyze_local_accepts_legacy_export_and_rejects_malformed_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = self._collection(root)
            prepared = prepare_llm_export(
                collection,
                root / "prepared",
                profile="local",
                mode="fast-triage",
                question="Analyze the incident",
            )
            legacy_export = prepared["root"] / "export"
            prepared["prepared"].rename(legacy_export)
            envelope = {"choices": [{"message": {"content": "not a JSON response"}}]}
            with patch("kdiag.llm_client._open_local_request", return_value=_FakeHTTPResponse(envelope)):
                result = analyze_local(
                    legacy_export,
                    root / "analysis",
                    "http://127.0.0.1:8080/v1/chat/completions",
                    "local-test-model",
                )
            self.assertEqual("rejected", result["validation_status"])
            self.assertEqual("not a JSON response", result["raw"].read_text(encoding="utf-8"))
            self.assertFalse((root / "analysis" / "response.validated.json").exists())


if __name__ == "__main__":
    unittest.main()
