import os
from pathlib import Path

from kdiag.normalize import normalize_evidence
from kdiag.rule_catalog import RULE_PACK_VERSION
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
        "cgroup_mode": cgroup.get("mode"),
        "kubelet_state": kubelet.get("ActiveState"),
        "boot_id": snapshot.get("facts", {}).get("boot_id_end"),
        "ipv6_disabled": sorted(key for key, value in snapshot.get("facts", {}).get("ipv6_disable", {}).items() if str(value) == "1"),
    }


def build_report(collection_dir):
    collection, nodes, kubernetes, prometheus = load_collection(collection_dir)
    normalized = normalize_evidence(collection, nodes, kubernetes)
    findings = evaluate_rules(collection, nodes, kubernetes, normalized, prometheus)
    node_inventory = [_node_row(name, snapshot) for name, snapshot in sorted(nodes.items())]
    coverage = []
    for item in collection.get("nodes", []):
        coverage.append(
            {
                "source": "node/{0}".format(item.get("host")),
                "status": item.get("status"),
                "error": item.get("error") or item.get("cleanup_error"),
                "required": True,
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
    if kubernetes.get("logs"):
        coverage.append(
            {
                "source": "kubernetes/logs",
                "status": kubernetes["logs"].get("status"),
                "error": kubernetes["logs"].get("error"),
                "required": True,
            }
        )
    coverage.append({"source": "prometheus", "status": collection.get("prometheus", {}).get("status"), "error": collection.get("prometheus", {}).get("error"), "required": False})
    facts = {
        "schema_version": 1,
        "collection_id": collection.get("collection_id"),
        "nodes": node_inventory,
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
    }
    findings_document = {
        "schema_version": 1,
        "rule_pack_version": RULE_PACK_VERSION,
        "collection_id": collection.get("collection_id"),
        "items": findings,
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
        "prometheus_status": prometheus.get("status") if prometheus else collection.get("prometheus", {}).get("status"),
        "normalization": facts["normalization"],
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
        "## Полнота сбора",
        "",
        "| Источник | Статус | Обязательный | Ошибка |",
        "|---|---|---|---|",
    ]
    for item in coverage:
        lines.append("| {0} | {1} | {2} | {3} |".format(markdown_escape(item.get("source")), markdown_escape(item.get("status")), "yes" if item.get("required", True) else "no", markdown_escape(item.get("error") or "")))
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
                markdown_escape(finding["summary"]),
                "",
                "Тип вывода: `{0}`; rule pack: `{1}`.".format(
                    markdown_escape(finding.get("classification")), markdown_escape(finding.get("rule_pack_version"))
                ),
                "",
                "Причинная уверенность: `{0}`.".format(markdown_escape(finding["causal_confidence"])),
                "",
                "Затронуто: {0}.".format(markdown_escape(", ".join(finding["affected"]) or "cluster")),
                "",
                "Evidence: {0}.".format(", ".join("`{0}`".format(markdown_escape(value)) for value in finding["evidence"])),
                "",
                "Рекомендация: {0}".format(markdown_escape(finding["recommendation"])),
                "",
            ]
        )
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
    atomic_write_bytes(root / "report.md", ("\n".join(lines).rstrip() + "\n").encode("utf-8"))
    return report
