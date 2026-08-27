import argparse
import json
import sys
from pathlib import Path

from kdiag import __version__
from kdiag.bundle import verify_manifest, write_manifest
from kdiag.config import load_config, validate_config
from kdiag.llm_client import DEFAULT_LOCAL_ENDPOINT, DEFAULT_LOCAL_TIMEOUT_SECONDS, DEFAULT_MAX_OUTPUT_TOKENS, analyze_local
from kdiag.llm_export import DEFAULT_MAX_PACKAGE_BYTES, import_llm_response, prepare_llm_export, validate_external_export
from kdiag.node import collect_node_snapshot
from kdiag.orchestrator import run_snapshot
from kdiag.report import build_report
from kdiag.rule_catalog import RULE_CATALOG, RULE_PACK_VERSION, rule_metadata
from kdiag.selftest import run_self_test
from kdiag.util import gzip_json_bytes, require_k8s_name


def _parser():
    parser = argparse.ArgumentParser(prog="kdiag", description="Разовый deterministic snapshot Kubernetes/RED OS с необязательным LLM-контуром")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot", help="собрать аварийный snapshot")
    snapshot.add_argument("--inventory", "-i", required=True, help="путь к Ansible inventory")
    snapshot.add_argument("--group", "-g", help="ограничить inventory группой")
    snapshot.add_argument("--output-dir", "-o", default="./kdiag-data", help="корневой каталог результатов")
    snapshot.add_argument("--config", help="JSON-конфигурация")
    snapshot.add_argument("--kubeconfig", help="отдельный read-only kubeconfig")
    snapshot.add_argument("--context", help="kubectl context")
    snapshot.add_argument("--skip-kubernetes", action="store_true", help="не опрашивать Kubernetes API")
    snapshot.add_argument("--prometheus-url", help="необязательный URL Prometheus")
    snapshot.add_argument("--prometheus-username", help="имя для HTTP Basic authentication Prometheus")
    snapshot.add_argument(
        "--prometheus-password-file",
        help="файл с паролем Prometheus; пароль не передаётся в аргументах процесса",
    )
    snapshot.add_argument("--ssh-user", help="SSH user по умолчанию")
    snapshot.add_argument("--ssh-port", type=int, help="SSH port по умолчанию")
    snapshot.add_argument("--remote-python", help="абсолютный путь Python 3.8 на узлах")
    snapshot.add_argument("--parallelism", type=int, help="число одновременно собираемых узлов")
    snapshot.add_argument("--since-hours", type=int, help="глубина журналов")
    snapshot.add_argument("--application-namespace", action="append", default=None, help="разрешить прикладной namespace; можно повторять")
    snapshot.add_argument("--skip-cgroup", action="store_true", help="не собирать cgroup facts и не выполнять cgroup checks")
    snapshot.add_argument(
        "--progress",
        choices=("off", "summary", "detail"),
        default="summary",
        help="уровень отображения хода сбора; вывод идёт в stderr",
    )

    node = subparsers.add_parser("node-snapshot", help=argparse.SUPPRESS)
    node.add_argument("--since-hours", type=int, required=True)
    node.add_argument("--command-timeout-seconds", type=int, required=True)
    node.add_argument("--max-command-bytes", type=int, required=True)
    node.add_argument("--pod-log-tail-bytes", type=int, required=True)
    node.add_argument("--pod-log-total-bytes", type=int, required=True)
    node.add_argument("--pod-log-max-files", type=int, required=True)
    node.add_argument("--collect-etcd", action="store_true")
    node.add_argument("--skip-cgroup", action="store_true")
    node.add_argument("--system-namespace", action="append", default=[])
    node.add_argument("--application-namespace", action="append", default=[])

    report = subparsers.add_parser("report", help="повторно построить отчёт из collection")
    report.add_argument("collection_dir")

    verify = subparsers.add_parser("verify", help="проверить полноту и SHA-256 файлов collection")
    verify.add_argument("collection_dir")

    rules = subparsers.add_parser("rules", help="просмотреть автономный каталог правил")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    rule_list = rule_commands.add_parser("list", help="перечислить правила")
    rule_list.add_argument("--json", action="store_true", help="вывести JSON")
    rule_explain = rule_commands.add_parser("explain", help="объяснить правило")
    rule_explain.add_argument("rule_id")
    rule_explain.add_argument("--json", action="store_true", help="вывести JSON")

    self_test = subparsers.add_parser("self-test", help="запустить встроенные synthetic проверки")
    self_test.add_argument("--json", action="store_true", help="вывести JSON")

    llm = subparsers.add_parser("llm", help="подготовить минимизированные данные для LLM")
    llm_commands = llm.add_subparsers(dest="llm_command", required=True)
    llm_prepare = llm_commands.add_parser("prepare", help="создать локальный или внешний incident package")
    llm_prepare.add_argument("collection_dir")
    llm_prepare.add_argument("--output-dir", "-o", required=True, help="новый или пустой каталог результата")
    llm_prepare.add_argument("--profile", choices=("local", "external"), required=True)
    llm_prepare.add_argument("--mode", choices=("fast-triage", "deep-analysis"), default="fast-triage")
    llm_prepare.add_argument("--question", required=True, help="вопрос оператора к модели")
    llm_prepare.add_argument("--max-package-bytes", type=int, default=DEFAULT_MAX_PACKAGE_BYTES)
    llm_validate = llm_commands.add_parser("validate-export", help="повторно проверить внешний каталог перед передачей")
    llm_validate.add_argument("export_dir")
    llm_analyze = llm_commands.add_parser("analyze-local", help="передать готовый local package локальному LLM service")
    llm_analyze.add_argument("prepared_dir", help="каталог prepared; legacy export от local profile также поддерживается")
    llm_analyze.add_argument("--output-dir", "-o", required=True, help="новый или пустой каталог результата")
    llm_analyze.add_argument("--endpoint", default=DEFAULT_LOCAL_ENDPOINT, help="loopback OpenAI-compatible chat-completions URL")
    llm_analyze.add_argument("--model", required=True, help="имя модели в локальном inference service")
    llm_analyze.add_argument("--timeout-seconds", type=int, default=DEFAULT_LOCAL_TIMEOUT_SECONDS)
    llm_analyze.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    llm_import = llm_commands.add_parser("import-response", help="сохранить и разанонимизировать ручной ответ")
    llm_import.add_argument("response_path")
    llm_import.add_argument("--token-map", required=True, help="локальный private/token-map.json")
    llm_import.add_argument("--output-dir", "-o", required=True, help="новый или пустой каталог результата")
    return parser


def _snapshot_config(arguments):
    config = load_config(arguments.config)
    if arguments.kubeconfig:
        config["kubernetes"]["kubeconfig"] = str(Path(arguments.kubeconfig).resolve())
    if arguments.context:
        config["kubernetes"]["context"] = arguments.context
    if arguments.skip_kubernetes:
        config["kubernetes"]["enabled"] = False
    if arguments.prometheus_url:
        config["prometheus"]["url"] = arguments.prometheus_url
    if arguments.prometheus_username:
        config["prometheus"]["username"] = arguments.prometheus_username
    if arguments.prometheus_password_file:
        password_path = Path(arguments.prometheus_password_file)
        if not password_path.is_file():
            raise ValueError("prometheus password file is not a regular file")
        payload = password_path.read_bytes()
        if len(payload) > 16 * 1024:
            raise ValueError("prometheus password file exceeds 16384 bytes")
        try:
            config["prometheus"]["password"] = payload.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as error:
            raise ValueError("prometheus password file must be UTF-8") from error
    if arguments.ssh_user:
        config["ssh"]["user"] = arguments.ssh_user
    if arguments.ssh_port is not None:
        config["ssh"]["port"] = arguments.ssh_port
    if arguments.remote_python:
        config["ssh"]["remote_python"] = arguments.remote_python
    if arguments.parallelism is not None:
        config["collection"]["parallelism"] = arguments.parallelism
    if arguments.since_hours is not None:
        config["collection"]["since_hours"] = arguments.since_hours
    if arguments.skip_cgroup:
        config["collection"]["collect_cgroup"] = False
    if arguments.application_namespace is not None:
        config["kubernetes"]["application_namespaces"] = [require_k8s_name(value) for value in arguments.application_namespace]
    return validate_config(config)


def _progress_callback(mode, stream=None):
    if mode == "off":
        return None
    output = stream if stream is not None else sys.stderr

    def emit(level, message):
        if level == "detail" and mode != "detail":
            return
        print("[kdiag] {0}".format(message), file=output, flush=True)

    return emit


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "snapshot":
            config = _snapshot_config(arguments)
            collection_dir, status = run_snapshot(
                arguments.inventory,
                arguments.group,
                arguments.output_dir,
                config,
                progress=_progress_callback(arguments.progress),
            )
            print(str(collection_dir))
            return 0 if status == "complete" else 1
        if arguments.command == "node-snapshot":
            system_namespaces = [require_k8s_name(value) for value in arguments.system_namespace]
            application_namespaces = [require_k8s_name(value) for value in arguments.application_namespace]
            snapshot = collect_node_snapshot(
                arguments.since_hours,
                arguments.command_timeout_seconds,
                arguments.max_command_bytes,
                system_namespaces,
                application_namespaces,
                arguments.pod_log_tail_bytes,
                arguments.pod_log_total_bytes,
                arguments.pod_log_max_files,
                arguments.collect_etcd,
                not arguments.skip_cgroup,
            )
            sys.stdout.buffer.write(gzip_json_bytes(snapshot))
            sys.stdout.buffer.flush()
            return 0
        if arguments.command == "report":
            build_report(arguments.collection_dir)
            write_manifest(arguments.collection_dir)
            print(str(Path(arguments.collection_dir).resolve() / "report.md"))
            return 0
        if arguments.command == "verify":
            result = verify_manifest(arguments.collection_dir)
            print("verified {0} members".format(result["members"]))
            return 0
        if arguments.command == "rules":
            if arguments.rules_command == "list":
                if arguments.json:
                    print(json.dumps({"rule_pack_version": RULE_PACK_VERSION, "rules": RULE_CATALOG}, ensure_ascii=False, indent=2, sort_keys=True))
                else:
                    print("rule pack {0}: {1} rules".format(RULE_PACK_VERSION, len(RULE_CATALOG)))
                    for rule_id, metadata in sorted(RULE_CATALOG.items()):
                        print("{0}\t{1}\t{2}".format(rule_id, metadata["classification"], metadata["title"]))
                return 0
            metadata = rule_metadata(arguments.rule_id)
            if arguments.rule_id not in RULE_CATALOG:
                raise ValueError("unknown rule_id: {0}".format(arguments.rule_id))
            document = dict(metadata)
            document["rule_id"] = arguments.rule_id
            document["rule_pack_version"] = RULE_PACK_VERSION
            if arguments.json:
                print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                print("{0}: {1}".format(arguments.rule_id, metadata["title"]))
                print("classification: {0}".format(metadata["classification"]))
                print("version scope: {0}".format(metadata["version_scope"]))
                print(metadata["description"])
                for source in metadata["sources"]:
                    print("source: {0}".format(source))
            return 0
        if arguments.command == "self-test":
            result = run_self_test()
            if arguments.json:
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                print("self-test: {0}; rule pack: {1}".format(result["status"], result["rule_pack_version"]))
                for check in result["checks"]:
                    print("{0}\t{1}\t{2}".format(check["status"], check["name"], check["detail"]))
            return 0 if result["status"] == "passed" else 1
        if arguments.command == "llm":
            if arguments.llm_command == "prepare":
                result = prepare_llm_export(
                    arguments.collection_dir,
                    arguments.output_dir,
                    profile=arguments.profile,
                    mode=arguments.mode,
                    question=arguments.question,
                    max_package_bytes=arguments.max_package_bytes,
                )
                print(str(result["package_dir"]))
                return 0
            if arguments.llm_command == "validate-export":
                result = validate_external_export(arguments.export_dir)
                print("LLM external export: {0}; verified {1} members".format(result["status"], result["manifest_members"]))
                return 0
            if arguments.llm_command == "analyze-local":
                result = analyze_local(
                    arguments.prepared_dir,
                    arguments.output_dir,
                    arguments.endpoint,
                    arguments.model,
                    timeout_seconds=arguments.timeout_seconds,
                    max_output_tokens=arguments.max_output_tokens,
                )
                print(str(result["markdown"]))
                return 0 if result["validation_status"] == "validated" else 1
            if arguments.llm_command == "import-response":
                result = import_llm_response(arguments.response_path, arguments.token_map, arguments.output_dir)
                print(str(result["restored"]))
                return 0
    except (ValueError, RuntimeError, OSError) as error:
        print("kdiag: {0}".format(error), file=sys.stderr)
        return 2
    return 2


def entrypoint():
    raise SystemExit(main())
