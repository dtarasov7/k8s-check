import os
from pathlib import Path

from kdiag.normalize import normalize_evidence
from kdiag.rule_catalog import RULE_CATALOG, RULE_PACK_VERSION
from kdiag.rules import evaluate_rules
from kdiag.util import atomic_write_gzip_json, atomic_write_json, atomic_write_bytes, load_gzip_json, markdown_escape


def _safe_member(root, relative):
    if not isinstance(relative, str) or not relative or os.path.isabs(relative):
        raise ValueError("invalid collection member")
    root_path = Path(root).resolve()
    candidate = (root_path / relative).resolve()
    if os.path.commonpath((str(root_path), str(candidate))) != str(root_path):
        raise ValueError("collection member escapes root: {0}".format(relative))
    return candidate


def load_collection(collection_dir):
    root = Path(collection_dir)
    import json
    with (root / "collection.json").open("r", encoding="utf-8") as source:
        collection = json.load(source)
    nodes = {}
    for item in collection.get("nodes", []):
        if item.get("status") != "collected" or not item.get("file"):
            continue
        nodes[item["host"]] = load_gzip_json(_safe_member(root, item["file"]))
    kubernetes = {}
    kubernetes_item = collection.get("kubernetes", {})
    if kubernetes_item.get("status") in ("collected", "partial") and kubernetes_item.get("file"):
        kubernetes = load_gzip_json(_safe_member(root, kubernetes_item["file"]))
    prometheus = {}
    prometheus_item = collection.get("prometheus", {})
    if prometheus_item.get("file"):
        prometheus = load_gzip_json(_safe_member(root, prometheus_item["file"]))
    return collection, nodes, kubernetes, prometheus


def _node_row(name, snapshot):
    host = snapshot.get("host", {})
    os_release = host.get("os_release", {})
    cgroup = snapshot.get("facts", {}).get("cgroup", {})
    kubelet = snapshot.get("facts", {}).get("service_states", {}).get("kubelet.service", {}).get("properties", {})
    return {
        "inventory_host": name,
        "hostname": host.get("hostname"),
        "os": os_release.get("PRETTY_NAME") or os_release.get("NAME"),
        "kernel": host.get("kernel_release"),
        "cgroup_mode": "disabled" if cgroup.get("status") == "disabled" else cgroup.get("mode"),
        "kubelet_state": kubelet.get("ActiveState"),
        "boot_id": snapshot.get("facts", {}).get("boot_id_end"),
        "ipv6_disabled": sorted(key for key, value in snapshot.get("facts", {}).get("ipv6_disable", {}).items() if str(value) == "1"),
    }


def _coverage(collection, nodes, kubernetes):
    coverage = []
    required_commands = {"journal_services_current", "journal_kernel_current"}
    for item in collection.get("nodes", []):
        host = item.get("host")
        coverage.append(
            {
                "source": "node/{0}".format(host),
                "status": item.get("status"),
                "error": item.get("error") or item.get("cleanup_error"),
                "required": True,
            }
        )
        snapshot = nodes.get(host)
        if not snapshot:
            continue
        for command in snapshot.get("commands", []):
            status = "truncated" if command.get("truncated") else command.get("status") or "unknown"
            coverage.append(
                {
                    "source": "node/{0}/command/{1}".format(host, command.get("id") or "unknown"),
                    "status": status,
                    "error": command.get("error"),
                    "required": command.get("id") in required_commands,
                    "bytes": len(str(command.get("stdout") or "").encode("utf-8")),
                }
            )
        pod_logs = snapshot.get("pod_logs", {}) or {}
        coverage.append(
            {
                "source": "node/{0}/pod_logs".format(host),
                "status": pod_logs.get("status") or "missing",
                "error": pod_logs.get("error"),
                "required": True,
                "entry_count": len(pod_logs.get("entries", []) or []),
            }
        )
    coverage.append({"source": "kubernetes", "status": collection.get("kubernetes", {}).get("status"), "error": collection.get("kubernetes", {}).get("error"), "required": True})
    for source_id, source in sorted(kubernetes.get("sources", {}).items()):
        coverage.append(
            {
                "source": "kubernetes/{0}".format(source_id),
                "status": source.get("status"),
                "error": source.get("error"),
                "required": source.get("required", True),
            }
        )
    logs = kubernetes.get("logs")
    if logs:
        coverage.append(
            {
                "source": "kubernetes/logs",
                "status": logs.get("status"),
                "error": logs.get("error"),
                "required": True,
                "entry_count": len(logs.get("entries", []) or []),
            }
        )
        for index, entry in enumerate(logs.get("entries", []) or []):
            coverage.append(
                {
                    "source": "kubernetes/logs/{0}".format(index),
                    "status": "truncated" if entry.get("truncated") else entry.get("status") or "unknown",
                    "error": entry.get("error"),
                    "required": True,
                }
            )
    coverage.append({"source": "prometheus", "status": collection.get("prometheus", {}).get("status"), "error": collection.get("prometheus", {}).get("error"), "required": False})
    return coverage


def _rule_ledger(findings, coverage, collect_cgroup):
    matched = {item.get("rule_id") for item in findings}
    node_gaps = [item["source"] for item in coverage if item.get("required") and item["source"].startswith("node/") and item.get("status") != "collected"]
    kube_gaps = [item["source"] for item in coverage if item.get("required") and item["source"].startswith("kubernetes") and item.get("status") != "collected"]
    prometheus_status = next((item.get("status") for item in coverage if item.get("source") == "prometheus"), None)
    ledger = []
    for rule_id in sorted(RULE_CATALOG):
        missing = []
        if rule_id in matched:
            status = "matched"
        elif rule_id.startswith("cgroup.") or rule_id == "security_agent.cgroup_denial":
            status = "not_applicable" if not collect_cgroup else ("unknown" if node_gaps else "not_matched")
            missing = node_gaps
        elif rule_id.startswith("prometheus."):
            if prometheus_status in (None, "not_configured", "disabled"):
                status = "not_applicable"
            elif prometheus_status != "collected":
                status = "unknown"
                missing = ["prometheus"]
            else:
                status = "not_matched"
        elif rule_id.startswith(("kubernetes.", "dns.", "storage.", "pdb.", "controlplane.", "cilium.")):
            status = "unknown" if kube_gaps else "not_matched"
            missing = kube_gaps
        elif rule_id.startswith("correlation."):
            missing = node_gaps + kube_gaps
            status = "unknown" if missing else "not_matched"
        elif rule_id.startswith("collector."):
            status = "not_matched"
        else:
            status = "unknown" if node_gaps else "not_matched"
            missing = node_gaps
        ledger.append(
            {
                "rule_id": rule_id,
                "status": status,
                "missing_evidence": missing[:50],
                "missing_evidence_total": len(missing),
            }
        )
    return ledger


def build_report(collection_dir):
    collection, nodes, kubernetes, prometheus = load_collection(collection_dir)
    normalized = normalize_evidence(collection, nodes, kubernetes)
    findings = evaluate_rules(collection, nodes, kubernetes, normalized, prometheus)
    node_inventory = [_node_row(name, snapshot) for name, snapshot in sorted(nodes.items())]
    coverage = _coverage(collection, nodes, kubernetes)
    ledger = _rule_ledger(findings, coverage, collection.get("options", {}).get("collect_cgroup", True))
    facts = {
        "schema_version": 1,
        "collection_id": collection.get("collection_id"),
        "nodes": node_inventory,
        "options": {"collect_cgroup": collection.get("options", {}).get("collect_cgroup", True)},
        "kubernetes": {
            "status": collection.get("kubernetes", {}).get("status"),
            "sources": {
                source_id: {
                    "status": source.get("status"),
                    "required": source.get("required", True),
                    "item_count": len(source.get("data", {}).get("items", []))
                    if isinstance(source.get("data", {}).get("items", []), list)
                    else None,
                }
                for source_id, source in sorted(kubernetes.get("sources", {}).items())
            },
            "logs": {
                "status": kubernetes.get("logs", {}).get("status"),
                "entry_count": len(kubernetes.get("logs", {}).get("entries", [])),
                "bytes": kubernetes.get("logs", {}).get("bytes"),
            },
        },
        "normalization": {
            "stats": normalized.get("stats", {}),
            "correlation_count": len(normalized.get("correlations", [])),
            "unknown_fingerprint_count": len(normalized.get("unknown_fingerprints", [])),
        },
        "coverage": coverage,
        "rule_evaluation_ledger": ledger,
    }
    findings_document = {
        "schema_version": 1,
        "rule_pack_version": RULE_PACK_VERSION,
        "collection_id": collection.get("collection_id"),
        "items": findings,
        "evaluation_ledger": ledger,
    }
    report = {
        "schema_version": 1,
        "rule_pack_version": RULE_PACK_VERSION,
        "collection_id": collection.get("collection_id"),
        "status": collection.get("status"),
        "started_at": collection.get("started_at"),
        "ended_at": collection.get("ended_at"),
        "coverage": coverage,
        "node_inventory": node_inventory,
        "findings": findings,
        "rule_evaluation_ledger": ledger,
        "prometheus_status": prometheus.get("status") if prometheus else collection.get("prometheus", {}).get("status"),
        "normalization": facts["normalization"],
        "options": facts["options"],
    }
    root = Path(collection_dir)
    atomic_write_gzip_json(root / "normalized-events.json.gz", normalized)
    atomic_write_json(root / "facts.json", facts)
    atomic_write_json(root / "findings.json", findings_document)
    atomic_write_json(root / "report.json", report)
    lines = [
        "# Аварийный снимок Kubernetes",
        "",
        "Collection ID: `{0}`".format(markdown_escape(report["collection_id"])),
        "",
        "Статус: **{0}**".format(markdown_escape(report["status"])),
        "",
        "Cgroup checks: **{0}**".format("enabled" if report["options"]["collect_cgroup"] else "disabled"),
        "",
        "## Полнота сбора",
        "",
        "| Источник | Статус | Обязательный | Ошибка |",
        "|---|---|---|---|",
    ]
    for item in coverage:
        lines.append("| {0} | {1} | {2} | {3} |".format(markdown_escape(item.get("source")), markdown_escape(item.get("status")), "yes" if item.get("required", True) else "no", markdown_escape(item.get("error") or "")))
    ledger_counts = {}
    for item in ledger:
        ledger_counts[item["status"]] = ledger_counts.get(item["status"], 0) + 1
    lines.extend(
        [
            "",
            "## Реестр выполнения правил",
            "",
            "matched={0}; not_matched={1}; unknown={2}; not_applicable={3}.".format(
                ledger_counts.get("matched", 0),
                ledger_counts.get("not_matched", 0),
                ledger_counts.get("unknown", 0),
                ledger_counts.get("not_applicable", 0),
            ),
            "",
        ]
    )
    unknown_rules = [item for item in ledger if item["status"] == "unknown"]
    if unknown_rules:
        lines.append("Отсутствие finding по правилам со статусом `unknown` не означает отсутствие проблемы.")
        lines.append("")
        lines.extend(["| Rule ID | Статус | Отсутствующие evidence |", "|---|---|---|"])
        for item in unknown_rules[:100]:
            missing = item.get("missing_evidence", [])
            omitted = item.get("missing_evidence_total", len(missing)) - len(missing)
            text = ", ".join(missing) + ("; omitted={0}".format(omitted) if omitted else "")
            lines.append("| `{0}` | unknown | {1} |".format(markdown_escape(item["rule_id"]), markdown_escape(text)))
        lines.append("")
    lines.extend(["", "## Инвентаризация узлов", "", "| Inventory host | Hostname | ОС | Ядро | Cgroup | kubelet | IPv6 disabled |", "|---|---|---|---|---|---|---|"])
    for item in node_inventory:
        lines.append(
            "| {0} | {1} | {2} | {3} | {4} | {5} | {6} |".format(
                markdown_escape(item.get("inventory_host")),
                markdown_escape(item.get("hostname") or ""),
                markdown_escape(item.get("os") or ""),
                markdown_escape(item.get("kernel") or ""),
                markdown_escape(item.get("cgroup_mode") or ""),
                markdown_escape(item.get("kubelet_state") or ""),
                markdown_escape(", ".join(item.get("ipv6_disabled") or [])),
            )
        )
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("Зарегистрированных deterministic findings нет. Это не доказывает отсутствие проблемы.")
    for finding in findings:
        lines.extend(
            [
                "### [{0}] {1}".format(markdown_escape(finding["severity"]), markdown_escape(finding["title"])),
                "",
                "Rule ID: `{0}`.".format(markdown_escape(finding["rule_id"])),
                "",
                markdown_escape(finding["summary"]),
                "",
                "Тип вывода: `{0}`; detection confidence: `{1}`; causal confidence: `{2}`.".format(
                    markdown_escape(finding.get("classification")),
                    markdown_escape(finding.get("detection_confidence")),
                    markdown_escape(finding.get("causal_confidence")),
                ),
                "",
                "Rule pack: `{0}`; version scope: {1}.".format(
                    markdown_escape(finding.get("rule_pack_version")), markdown_escape(finding.get("version_scope"))
                ),
                "",
                "Время/окно: {0} — {1}; duration={2}s; correlation window={3}s.".format(
                    markdown_escape(finding.get("started_at") or report.get("started_at") or "unknown"),
                    markdown_escape(finding.get("ended_at") or report.get("ended_at") or "unknown"),
                    markdown_escape(finding.get("duration_seconds") if finding.get("duration_seconds") is not None else "unknown"),
                    markdown_escape(finding.get("window_seconds") if finding.get("window_seconds") is not None else "n/a"),
                ),
                "",
                "Затронуто: {0}; total={1}; omitted={2}.".format(
                    markdown_escape(", ".join(finding["affected"][:50]) or "cluster"),
                    finding.get("affected_total", len(finding["affected"])),
                    max(0, finding.get("affected_total", len(finding["affected"])) - min(50, len(finding["affected"]))),
                ),
                "",
                "Источники правил: {0}.".format(", ".join("`{0}`".format(markdown_escape(value)) for value in finding.get("source_refs", []))),
                "",
                "Evidence: {0}; total={1}; omitted={2}.".format(
                    ", ".join("`{0}`".format(markdown_escape(value)) for value in finding["evidence"]),
                    finding.get("evidence_total", len(finding["evidence"])),
                    max(0, finding.get("evidence_total", len(finding["evidence"])) - len(finding["evidence"])),
                ),
                "",
                "Альтернативы: {0}.".format(markdown_escape("; ".join(finding.get("alternatives", [])) or "нет явно перечисленных")),
                "",
                "Counter-evidence: {0}.".format(markdown_escape("; ".join(finding.get("counter_evidence", [])) or "не обнаружено в собранном evidence")),
                "",
                "Missing checks: {0}.".format(markdown_escape("; ".join(finding.get("missing_checks", [])) or "нет явно указанных")),
                "",
                "Рекомендация: {0}".format(markdown_escape(finding["recommendation"])),
                "",
            ]
        )
        fragments = finding.get("evidence_fragments", [])
        if fragments:
            lines.extend(["Bounded evidence excerpts:", ""])
            for fragment in fragments[:20]:
                lines.append(
                    "- `{0}` [{1}] {2}: {3}".format(
                        markdown_escape(fragment.get("reference")),
                        markdown_escape(fragment.get("status")),
                        markdown_escape(fragment.get("timestamp") or "unknown"),
                        markdown_escape(fragment.get("excerpt") or ""),
                    )
                )
            lines.append("")
    stats = normalized.get("stats", {})
    lines.extend(
        [
            "## Нормализация и корреляция",
            "",
            "Обработано записей: {0}; категоризировано: {1}; неизвестно: {2}; malformed: {3}; correlations: {4}; truncated: {5}; unknown replacements: {6}.".format(
                stats.get("input_records", 0),
                stats.get("categorized_records", 0),
                stats.get("uncategorized_records", 0),
                stats.get("malformed_records", 0),
                len(normalized.get("correlations", [])),
                stats.get("truncated", False),
                stats.get("unknown_fingerprint_replacements", 0),
            ),
            "",
        ]
    )
    unknown = normalized.get("unknown_fingerprints", [])[:20]
    if unknown:
        lines.extend(["### Приблизительные heavy hitters неизвестных fingerprints", "", "| Компонент | Estimated count | Max error | Template |", "|---|---:|---:|---|"])
        for item in unknown:
            lines.append(
                "| {0} | {1} | {2} | {3} |".format(
                    markdown_escape(item.get("component")),
                    markdown_escape(item.get("count")),
                    markdown_escape(item.get("estimate_error", 0)),
                    markdown_escape(item.get("template")),
                )
            )
        lines.append("")
    correlations = normalized.get("correlations", [])
    if correlations:
        lines.extend(["## Correlation timeline", "", "| Episode | Type | Scope | Started | Ended | Duration, s |", "|---|---|---|---|---|---:|"])
        for item in correlations[:100]:
            lines.append(
                "| `{0}` | `{1}` | {2} | {3} | {4} | {5} |".format(
                    markdown_escape(item.get("episode_id") or "unknown"),
                    markdown_escape(item.get("correlation_id")),
                    markdown_escape(item.get("scope")),
                    markdown_escape(item.get("started_at") or "unknown"),
                    markdown_escape(item.get("ended_at") or "unknown"),
                    markdown_escape(item.get("duration_seconds") if item.get("duration_seconds") is not None else "unknown"),
                )
            )
        if len(correlations) > 100:
            lines.extend(["", "Timeline total={0}; omitted={1}.".format(len(correlations), len(correlations) - 100)])
        lines.append("")
    atomic_write_bytes(root / "report.md", ("\n".join(lines).rstrip() + "\n").encode("utf-8"))
    return report
