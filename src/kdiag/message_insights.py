import copy
import re


def _entry(insight_id, category, component, message, title, explanation, decision_condition, recommendation, sources=()):
    return {
        "insight_id": insight_id,
        "category": category,
        "component_pattern": re.compile(component, re.I),
        "message_pattern": re.compile(message, re.I),
        "title": title,
        "explanation": explanation,
        "decision_condition": decision_condition,
        "recommendation": recommendation,
        "sources": list(sources),
    }


MESSAGE_INSIGHT_CATALOG = (
    _entry(
        "image_pull_secret_unavailable",
        "actionable",
        r"kubelet",
        r"unable to retrieve (?:some )?(?:image )?pull secret",
        "kubelet не получил image pull Secret",
        "Образ ещё может запуститься из локального кэша, с другими учётными данными или без авторизации. Сообщение указывает на риск следующего скачивания образа, но само по себе не означает отказ Pod.",
        "Проверять немедленно при ImagePullBackOff/ErrImagePull, FailedToRetrieveImagePullSecret, неготовом Pod или остановившемся обновлении; при Running/Ready считать скрытым риском.",
        "Сопоставить состояние Pod, события Kubernetes и imagePullSecrets; содержимое Secret не читать и не включать в набор kdiag.",
        (
            "https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/",
            "https://github.com/kubernetes/kubernetes/issues/128544",
        ),
    ),
    _entry(
        "nginx_upstream_temporarily_disabled",
        "actionable",
        r"(?:proxy|nginx)",
        r"upstream server temporarily disabled while",
        "Nginx временно исключил upstream",
        "Предыдущая попытка соединения с целевым сервером завершилась ошибкой. Одиночная запись может быть кратковременной; повторение вместе с неуспешным readyz, неготовым EndpointSlice или сетевыми ошибками указывает на возможное влияние.",
        "Проверять при неуспешном API readyz, неготовом совпавшем EndpointSlice, отказе соединения, превышении времени ожидания, отсутствии маршрута либо пользовательских ответах 5xx.",
        "Проверить соседнюю исходную строку ошибки Nginx, целевой адрес, readyz и сетевые события в том же временном окне.",
    ),
    _entry(
        "ipv6_link_ready",
        "observe",
        r"kernel|journal_kernel",
        r"ipv6:\s*addrconf\(netdev_change\).*link becomes ready",
        "IPv6 сообщил о готовности интерфейса",
        "Это информационный переход link state. Большая подтверждённая частота может отражать Pod/interface churn, но не является сетевой ошибкой сама по себе.",
        "Расследовать только вместе с NetworkUnavailable, CNI errors, probe failures либо неожиданной частой сменой физического интерфейса.",
        "Сравнить Node/time distribution с CNI, Pod churn и Node conditions.",
    ),
    _entry(
        "containerd_port_forward",
        "observe",
        r"containerd",
        r"executing port forwarding in network namespace",
        "containerd выполняет port-forward",
        "Обычная операция CRI port-forward/exec в network namespace; это activity/audit signal, а не failure.",
        "Проверять только если port-forward неожиданен, слишком част или совпадает с runtime/network failure.",
        "Сопоставить окно с административными действиями и runtime events; автоматически не считать инцидентом.",
    ),
    _entry(
        "nginx_config_equal_skip_reload",
        "routine",
        r"reloader|nginx|proxy",
        r"nginx(?:_new)?\.conf.*(?:are|is) equal.*skipping reload",
        "Конфигурация Nginx не изменилась",
        "Reloader сравнил конфигурации и корректно пропустил ненужный reload.",
        "Действие не требуется; наблюдать только аномальную частоту reconciliation или соседний failed reload.",
        "Скрывать как routine activity, сохраняя диапазон частоты.",
    ),
    _entry(
        "systemd_sysv_compat_unit",
        "observe",
        r"sysv-generator|systemd",
        r"lacks a native systemd unit file.*automatically generating",
        "systemd создал compatibility unit для SysV script",
        "Legacy init script автоматически обёрнут systemd. Это предупреждение о совместимости/техническом долге, не доказательство отказа сервиса.",
        "Действовать при failed generated unit, нарушенном ordering или требовании vendor package использовать native unit.",
        "Проверить ActiveState/Result соответствующего сервиса и package version; не заменять vendor unit вручную без процедуры.",
        ("https://www.freedesktop.org/software/systemd/man/latest/systemd-sysv-generator.html",),
    ),
    _entry(
        "kernel_requirements_met",
        "routine",
        r"check-linux-kernel",
        r"meets the requirements",
        "Проверка требований ядра успешна",
        "Компонент подтвердил совместимость обнаруженного ядра/архитектуры.",
        "Действие не требуется, если рядом нет отдельного failed/unsupported результата.",
        "Скрывать как успешную routine-проверку.",
    ),
    _entry(
        "coredns_kubeforward_update",
        "routine",
        r"coredns|kube-dns",
        r"kubeforward.*updated servers",
        "CoreDNS обновил upstream servers",
        "Плагин kubeforward применил новое состояние Service/Endpoint; сообщение само по себе успешно.",
        "Наблюдать только при непрерывном churn вместе с SERVFAIL/timeout или неготовыми DNS endpoints.",
        "Сопоставить с DNS errors и EndpointSlice; иначе скрывать как routine activity.",
    ),
    _entry(
        "stale_dns_connections_removed",
        "observe",
        r"stale-dns-connections-cleaner",
        r"removed.*stale connections",
        "Удалены stale DNS connections",
        "Deckhouse helper успешно удалил устаревшие DNS conntrack entries; сама строка описывает восстановительное действие.",
        "Расследовать устойчивую подтверждённую частоту только вместе с DNS/CNI failures.",
        "Сравнить окно с CoreDNS errors, kube-dns endpoints и Cilium/network events.",
        ("https://github.com/deckhouse/deckhouse/blob/main/CHANGELOG/CHANGELOG-v1.74.md",),
    ),
    _entry(
        "kube_rbac_proxy_configured",
        "routine",
        r"kube-rbac-proxy",
        r"(?:parsed upstream|parsing configuration from environment|using config|added upstream)",
        "kube-rbac-proxy загрузил конфигурацию",
        "Startup/configuration message без признака ошибки.",
        "Действовать только при частых рестартах Pod или соседнем bind/upstream failure.",
        "Сопоставить с Pod readiness/restarts; иначе скрывать как routine activity.",
    ),
    _entry(
        "kubelet_image_unpack_success",
        "routine",
        r"kubelet",
        r"container image .*unpacked successfully on machine",
        "Образ контейнера успешно распакован",
        "kubelet завершил штатную подготовку образа. Это не ImagePull failure и не причина инцидента.",
        "Показывать только при одновременном нездоровом состоянии или частых рестартах связанного Pod.",
        "Скрывать как успешную операцию kubelet; при деградации проверять состояние Pod и соседние image events.",
    ),
    _entry(
        "statefulset_pod_created_successfully",
        "routine",
        r"statefulset-controller",
        r"create(?:d)? pod .* in statefulset .* successful",
        "StatefulSet успешно создал Pod",
        "Контроллер подтвердил успешный шаг reconciliation. Для штатного smoke-mini-* это ожидаемая запись.",
        "Показывать только если созданный Pod не готов, перезапускается или rollout остановился.",
        "Скрывать успешную запись; состояние StatefulSet и Pod анализировать по структурным данным.",
    ),
    _entry(
        "cert_manager_waiting_for_approval",
        "observe",
        r"cert-manager",
        r"not signing certificaterequest until it is approved",
        "cert-manager ожидает одобрения CertificateRequest",
        "Ожидание approval является штатной частью выдачи сертификата. Проблемой оно становится только при длительно зависшем запросе.",
        "Проверять при повторении без последующей выдачи сертификата либо при неготовом потребителе TLS.",
        "Сопоставить с состоянием CertificateRequest/Certificate и событиями issuer; одиночную запись скрывать.",
    ),
    _entry(
        "cert_manager_certificate_fetched",
        "routine",
        r"cert-manager",
        r"certificate fetched from issuer successfully",
        "cert-manager успешно получил сертификат",
        "Issuer вернул сертификат; строка подтверждает успешный этап reconciliation.",
        "Показывать только при одновременной неготовности cert-manager Pod или последующей ошибке сохранения Secret.",
        "Скрывать как успешную операцию cert-manager.",
    ),
    _entry(
        "cert_manager_secret_initial_issue",
        "observe",
        r"cert-manager",
        r"issuing certificate as secret does not exist",
        "cert-manager начал первичную выдачу сертификата",
        "Отсутствие целевого Secret до первой успешной выдачи ожидаемо. Повторяющийся цикл без создания Secret уже требует проверки.",
        "Проверять при повторении вместе с issuer error, неготовностью Pod или отсутствием последующего success-сообщения.",
        "Сопоставить с Certificate conditions и событиями issuer; одиночную запись скрывать.",
    ),
    _entry(
        "stale_dns_cleaner_schedule",
        "routine",
        r"stale-dns-connections-cleaner",
        r"then every .* seconds",
        "DNS cleaner сообщил расписание запуска",
        "Компонент вывел интервал своей штатной периодической работы.",
        "Действие не требуется без DNS/CNI failures или нездорового Pod.",
        "Скрывать как startup-конфигурацию.",
    ),
    _entry(
        "control_plane_pod_checksum_mismatch",
        "actionable",
        r"control-plane-manager",
        r"kubernetes pod checksum does not match expected",
        "Control-plane manager обнаружил несовпадение checksum Pod",
        "Фактический static Pod ещё не соответствует рассчитанной Deckhouse конфигурации. Это может быть кратким состоянием rollout, но устойчивое повторение указывает на незавершённый reconciliation.",
        "Проверять при повторении, рестартах или неготовности kube-apiserver/etcd/controller-manager/scheduler.",
        "Сопоставить expected/current checksum, готовность control-plane Pod и события Deckhouse вокруг того же окна; вручную manifest не перезаписывать.",
    ),
    _entry(
        "kubelet_image_gc_insufficient",
        "actionable",
        r"kubelet",
        r"failed to garbage collect required amount of images",
        "kubelet не смог освободить требуемый объём образов",
        "Image GC нашёл меньше удаляемых данных, чем требовалось. Это может предшествовать DiskPressure или отказам скачивания образов.",
        "Проверять при повторении, высоком заполнении image filesystem, DiskPressure или ImagePull failures.",
        "Проверить df/inodes, Node DiskPressure, runtime image usage и действующие пороги kubelet; изображения автоматически не удалять.",
    ),
    _entry(
        "kernel_crypto_implementation",
        "routine",
        r"kernel|journal_kernel",
        r"(?:device-mapper verity|sha256).*using implementation",
        "Ядро выбрало crypto implementation",
        "Информационное сообщение об аппаратно/программно оптимизированной реализации hash algorithm.",
        "Действие не требуется без отдельного integrity/verity failure.",
        "Скрывать как routine kernel initialization.",
    ),
    _entry(
        "nginx_worker_started",
        "routine",
        r"proxy|nginx",
        r"start worker process",
        "Nginx запустил worker process",
        "Обычное startup/reload сообщение.",
        "Наблюдать только если Pod/process часто перезапускается или reload завершается ошибкой.",
        "Сопоставить с Pod restartCount и readiness; иначе скрывать.",
    ),
    _entry(
        "coredns_config_reloaded",
        "routine",
        r"coredns|kube-dns",
        r"plugin/reload.*running configuration",
        "CoreDNS загрузил конфигурацию",
        "Успешное сообщение reload plugin с hash конфигурации.",
        "Действовать только при restart churn, failed reload или DNS errors.",
        "Сопоставить с CoreDNS readiness/restarts; иначе скрывать.",
    ),
    _entry(
        "config_reloader_reload",
        "routine",
        r"reloader",
        r"reloading config",
        "Reloader применяет конфигурацию",
        "Обычное сообщение reconciliation/reload без самостоятельного признака ошибки.",
        "Действовать только при failed reload, частых рестартах или деградации зависимого proxy.",
        "Сопоставить с readiness/restarts и соседними errors.",
    ),
    _entry(
        "authentication_config_read_error",
        "actionable",
        r"kube-apiserver|apiserver",
        r"(?:failed|unable) to read authentication config file",
        "API server не прочитал authentication config",
        "Dynamic authentication configuration не была прочитана. В зависимости от запуска API server это может оставить прежнюю конфигурацию либо нарушить authentication flow.",
        "Расследовать при повторении, failed API readyz, authentication errors или если указанный файл должен управляться текущей конфигурацией Deckhouse.",
        "Проверить существование/mount файла, права, аргументы API server и соседние readyz/authentication errors; не считать отсутствие файла безопасным без проверки intended configuration.",
    ),
    _entry(
        "ptrace_attack_attempt",
        "security",
        r"kernel|journal_kernel",
        r"ptrace attack of .{1,512} was attempted by",
        "Зафиксирована попытка ptrace",
        "Сообщение security-модуля фиксирует попытку одного процесса получить ptrace-доступ к другому. Это требует проверки инициатора и назначения, но само по себе не доказывает успешную компрометацию.",
        "Передать на security review, если инициатор не относится к разрешённому monitoring/security tooling, попытки повторяются либо target содержит чувствительные данные.",
        "Сопоставить executable, PID/cgroup, Node, время и штатные политики KESL; проверить, была ли операция заблокирована.",
    ),
    _entry(
        "kesl_sessionstat_telemetry",
        "routine",
        r"kernel|journal_kernel",
        r"sessionstat(?:ctl)?:ipv6g6?\s*:?\s*\(serviceprocess",
        "KESL записал session telemetry",
        "Строка sessionstat описывает внутренние счётчики service process и не является ошибкой без отдельного failure/denial marker.",
        "Действие не требуется; анализировать только при аномальном log volume или вместе с ошибкой KESL.",
        "Скрывать как routine telemetry, сохраняя агрегированную частоту и Node scope.",
    ),
)


def match_message_insight(component, message):
    component_text = str(component or "")
    message_text = str(message or "")
    for entry in MESSAGE_INSIGHT_CATALOG:
        if entry["component_pattern"].search(component_text) and entry["message_pattern"].search(message_text):
            return {
                key: copy.deepcopy(value)
                for key, value in entry.items()
                if key not in ("component_pattern", "message_pattern")
            }
    return None


POD_REF_RE = re.compile(r'\bpod\s*=\s*"([^"\s]+/[^"\s]+)"', re.I)
UPSTREAM_IP_RE = re.compile(
    r'\bupstream\s*(?:=|:)\s*"?(?:https?://)?(\[[0-9a-f:]+\]|(?:\d{1,3}\.){3}\d{1,3})',
    re.I,
)
NETWORK_ERROR_CATEGORIES = frozenset(("api_unreachable", "connection_refused", "no_route", "timeout", "probe_failure", "cni_unavailable"))
DNS_ERROR_CATEGORIES = frozenset(("dns_servfail", "dns_forward_loop", "dns_upstream_failure", "dns_error"))


def _items(kubernetes, source_id):
    return (kubernetes or {}).get("sources", {}).get(source_id, {}).get("data", {}).get("items", []) or []


def _source_status(kubernetes, source_id):
    return (kubernetes or {}).get("sources", {}).get(source_id, {}).get("status") or "missing"


def _add_check(insight, name, status, summary, evidence=()):
    insight["checks"].append(
        {
            "name": name,
            "status": status,
            "summary": summary,
            "evidence": list(evidence)[:20],
        }
    )
    if status == "problem":
        insight["decision_state"] = "investigate"


def _pod_status(pod):
    status = pod.get("status", {}) or {}
    regular_containers = status.get("containerStatuses") or []
    containers = (status.get("initContainerStatuses") or []) + regular_containers
    waiting = []
    restarts = 0
    for container in containers:
        restarts += int(container.get("restartCount") or 0)
        waiting_state = (container.get("state") or {}).get("waiting") or {}
        if waiting_state.get("reason"):
            waiting.append(str(waiting_state["reason"]))
    ready = bool(regular_containers) and all(container.get("ready") is True for container in regular_containers)
    return status.get("phase"), ready, restarts, sorted(set(waiting))


def _component_pod_check(insight, kubernetes):
    if _source_status(kubernetes, "pods") != "collected":
        insight["missing_checks"].append("kubernetes/pods:{0}".format(_source_status(kubernetes, "pods")))
        return
    component = str(insight.get("component") or "").lower().replace(".service", "")
    if not component or component in ("kernel", "systemd", "systemd-sysv-generator"):
        return
    matches = []
    for index, pod in enumerate(_items(kubernetes, "pods")):
        metadata = pod.get("metadata", {}) or {}
        names = [str(metadata.get("name") or "").lower()]
        names.extend(str(item.get("name") or "").lower() for item in (pod.get("spec", {}).get("containers") or []))
        if any(component in value or value in component for value in names if len(value) >= 4):
            matches.append((index, pod))
    if not matches:
        return
    problems = []
    healthy = []
    evidence = []
    for index, pod in matches[:20]:
        metadata = pod.get("metadata", {}) or {}
        target = "{0}/{1}".format(metadata.get("namespace") or "unknown", metadata.get("name") or "unknown")
        phase, ready, restarts, waiting = _pod_status(pod)
        detail = "{0}: состояние={1}, готов={2}, перезапусков={3}, ожидание={4}".format(target, phase, ready, restarts, ",".join(waiting) or "нет")
        if phase not in (None, "Running") or not ready or waiting:
            problems.append(detail)
        else:
            healthy.append(detail)
        evidence.append("kubernetes.json.gz#sources.pods.items[{0}]".format(index))
    if problems:
        _add_check(insight, "component_pod_state", "problem", "; ".join(problems[:10]), evidence)
    elif healthy:
        _add_check(insight, "component_pod_state", "healthy", "; ".join(healthy[:10]), evidence)
        insight["counter_evidence"].append("Связанные Pod компонентов в снимке имеют состояние Running/Ready.")


def _pull_secret_checks(insight, kubernetes):
    references = set()
    for example in insight.get("examples", []):
        match = POD_REF_RE.search(str(example.get("message") or ""))
        if match:
            references.add(match.group(1))
    pod_status = _source_status(kubernetes, "pods")
    if pod_status != "collected":
        insight["missing_checks"].append("kubernetes/pods:{0}".format(pod_status))
    else:
        matches = []
        for index, pod in enumerate(_items(kubernetes, "pods")):
            metadata = pod.get("metadata", {}) or {}
            target = "{0}/{1}".format(metadata.get("namespace") or "unknown", metadata.get("name") or "unknown")
            if not references or target in references:
                matches.append((index, target, pod))
        details = []
        evidence = []
        problem = False
        healthy = False
        for index, target, pod in matches[:20]:
            phase, ready, restarts, waiting = _pod_status(pod)
            pull_secrets = pod.get("spec", {}).get("imagePullSecrets") or []
            details.append(
                "{0}: состояние={1}, готов={2}, перезапусков={3}, ожидание={4}, imagePullSecrets={5}".format(
                    target, phase, ready, restarts, ",".join(waiting) or "нет", ",".join(str(value) for value in pull_secrets) or "нет"
                )
            )
            evidence.append("kubernetes.json.gz#sources.pods.items[{0}]".format(index))
            if set(waiting) & {"ImagePullBackOff", "ErrImagePull"} or phase in ("Failed", "Unknown"):
                problem = True
            elif phase == "Running" and ready:
                healthy = True
        if details:
            _add_check(insight, "pod_state", "problem" if problem else "healthy" if healthy else "observe", "; ".join(details), evidence)
        else:
            insight["missing_checks"].append("Pod из сообщения kubelet отсутствует в собранном снимке Pod")

    event_status = _source_status(kubernetes, "events")
    if event_status != "collected":
        insight["missing_checks"].append("kubernetes/events:{0}".format(event_status))
    else:
        matches = []
        evidence = []
        for index, event in enumerate(_items(kubernetes, "events")):
            regarding = event.get("regarding", {}) or {}
            target = "{0}/{1}".format(regarding.get("namespace") or "unknown", regarding.get("name") or "unknown")
            reason = str(event.get("reason") or "")
            if (not references or target in references) and reason in ("FailedToRetrieveImagePullSecret", "Failed", "FailedPull", "ErrImagePull"):
                matches.append("{0}: {1}".format(target, reason))
                evidence.append("kubernetes.json.gz#sources.events.items[{0}]".format(index))
        if matches:
            _add_check(insight, "kubernetes_events", "problem", "; ".join(matches[:20]), evidence)
        else:
            _add_check(insight, "kubernetes_events", "healthy", "В собранных событиях Kubernetes нет совпавшей ошибки скачивания образа.")
            insight["counter_evidence"].append("Нет совпавшего FailedToRetrieveImagePullSecret/ImagePull event в собранном окне.")
    insight["missing_checks"].append("Существование и содержимое Secret не проверяются: kdiag не запрашивает Secrets.")


def _related_event_check(insight, normalized, categories, name):
    nodes = set(insight.get("affected_nodes") or [])
    first_epoch = insight.get("first_seen_epoch")
    last_epoch = insight.get("last_seen_epoch")
    matches = []
    evidence = []
    found_categories = set()
    for event in (normalized or {}).get("events", []):
        event_categories = set(event.get("categories", ())) & set(categories)
        if not event_categories:
            continue
        if nodes and event.get("node") and event.get("node") not in nodes:
            continue
        epoch = event.get("timestamp_epoch")
        if epoch is not None and first_epoch is not None and epoch < first_epoch - 900:
            continue
        if epoch is not None and last_epoch is not None and epoch > last_epoch + 900:
            continue
        found_categories.update(event_categories)
        matches.append(str(event.get("message_excerpt") or ",".join(sorted(event_categories))))
        if event.get("evidence"):
            evidence.append(event["evidence"])
    if matches:
        _add_check(
            insight,
            name,
            "problem",
            "Связанные категории: {0}; событий: {1}.".format(", ".join(sorted(found_categories)), len(matches)),
            evidence,
        )
    elif (normalized or {}).get("stats", {}).get("truncated"):
        _add_check(insight, name, "observe", "Связанных ошибок среди сохранённых событий не найдено, но результат обработки журналов усечён.")
        insight["missing_checks"].append("Обработанные события усечены; отсутствие связанной записи не опровергает проблему")
    else:
        _add_check(insight, name, "healthy", "Связанных распознанных ошибок на том же узле и в том же временном окне не найдено.")
        insight["counter_evidence"].append("Нет связанных ошибок типа {0} на том же узле и в том же временном окне.".format(name))


def _readyz_check(insight, kubernetes):
    status = _source_status(kubernetes, "api_readyz")
    if status != "collected":
        insight["missing_checks"].append("kubernetes/api_readyz:{0}".format(status))
        return
    checks = (kubernetes.get("sources", {}).get("api_readyz", {}).get("data", {}) or {}).get("checks", []) or []
    failed = [item for item in checks if item.get("status") == "failed"]
    if failed:
        _add_check(
            insight,
            "api_readyz",
            "problem",
            "Неуспешные проверки: {0}.".format(", ".join(str(item.get("name")) for item in failed[:20])),
            ("kubernetes.json.gz#sources.api_readyz",),
        )
    else:
        _add_check(insight, "api_readyz", "healthy", "Проверка готовности API server не содержит ошибок.", ("kubernetes.json.gz#sources.api_readyz",))
        insight["counter_evidence"].append("Проверка готовности API server не содержит ошибок.")


def _endpoint_check(insight, kubernetes):
    status = _source_status(kubernetes, "endpoint_slices")
    if status != "collected":
        insight["missing_checks"].append("kubernetes/endpoint_slices:{0}".format(status))
        return
    upstream_ips = set()
    for example in insight.get("examples", []):
        upstream_ips.update(value.strip("[]") for value in UPSTREAM_IP_RE.findall(str(example.get("message") or "")))
    if not upstream_ips:
        insight["missing_checks"].append("Адрес целевого сервера не сохранился в ограниченном наборе примеров")
        return
    matched = []
    evidence = []
    problem = False
    for index, endpoint_slice in enumerate(_items(kubernetes, "endpoint_slices")):
        metadata = endpoint_slice.get("metadata", {}) or {}
        service_name = (metadata.get("labels") or {}).get("kubernetes.io/service-name") or metadata.get("name")
        for endpoint in endpoint_slice.get("endpoints", []) or []:
            addresses = set(str(value) for value in (endpoint.get("addresses") or []))
            overlap = sorted(addresses & upstream_ips)
            if not overlap:
                continue
            ready = (endpoint.get("conditions") or {}).get("ready")
            matched.append("{0}: адреса={1}, готов={2}".format(service_name, ",".join(overlap), ready))
            evidence.append("kubernetes.json.gz#sources.endpoint_slices.items[{0}]".format(index))
            if ready is False:
                problem = True
    if matched:
        _add_check(insight, "endpoint_state", "problem" if problem else "healthy", "; ".join(matched[:20]), evidence)
        if not problem:
            insight["counter_evidence"].append("Целевой адрес присутствует в готовом EndpointSlice.")
    else:
        _add_check(insight, "endpoint_state", "observe", "Целевой адрес не найден среди собранных EndpointSlice.")


def _kesl_service_check(insight, node_snapshots):
    values = []
    evidence = []
    problem = False
    for node, snapshot in (node_snapshots or {}).items():
        states = snapshot.get("facts", {}).get("service_states", {}) or {}
        for unit in ("kesl.service", "kesl-supervisor.service"):
            state = states.get(unit, {})
            if state.get("status") != "collected":
                continue
            active = (state.get("properties") or {}).get("ActiveState")
            values.append("{0}/{1}: {2}".format(node, unit, active))
            evidence.append("node-{0}.json.gz#facts.service_states.{1}".format(node, unit))
            if active not in ("active", "activating"):
                problem = True
    if values:
        _add_check(insight, "service_state", "problem" if problem else "healthy", "; ".join(values), evidence)
        if not problem:
            insight["counter_evidence"].append("Собранные KESL systemd services активны.")
    else:
        insight["missing_checks"].append("Связанный generated service state не входит в собранный allowlist")


def enrich_message_insights(insights, node_snapshots, kubernetes, normalized):
    result = []
    default_state = {"routine": "routine", "observe": "monitor", "actionable": "monitor", "security": "security_review"}
    for source in insights or []:
        insight = copy.deepcopy(source)
        insight["checks"] = []
        insight["counter_evidence"] = []
        insight["missing_checks"] = []
        insight["decision_state"] = default_state.get(insight.get("category"), "monitor")
        insight_id = insight.get("insight_id")
        if insight_id == "image_pull_secret_unavailable":
            _pull_secret_checks(insight, kubernetes)
        elif insight_id == "nginx_upstream_temporarily_disabled":
            _readyz_check(insight, kubernetes)
            _endpoint_check(insight, kubernetes)
            _related_event_check(insight, normalized, NETWORK_ERROR_CATEGORIES, "related_journal_events")
        elif insight_id == "authentication_config_read_error":
            _readyz_check(insight, kubernetes)
        elif insight_id in ("ipv6_link_ready", "containerd_port_forward"):
            _related_event_check(insight, normalized, NETWORK_ERROR_CATEGORIES, "related_journal_events")
        elif insight_id in ("stale_dns_connections_removed", "coredns_kubeforward_update", "coredns_config_reloaded"):
            _related_event_check(insight, normalized, DNS_ERROR_CATEGORIES | NETWORK_ERROR_CATEGORIES, "related_dns_network_events")
        elif insight_id == "systemd_sysv_compat_unit":
            _kesl_service_check(insight, node_snapshots)
        _component_pod_check(insight, kubernetes)
        insight["counter_evidence"] = sorted(set(insight["counter_evidence"]))[:20]
        insight["missing_checks"] = sorted(set(insight["missing_checks"]))[:20]
        result.append(insight)
    priority = {"security": 0, "actionable": 1, "observe": 2, "routine": 3}
    return sorted(result, key=lambda item: (priority.get(item.get("category"), 9), -int((item.get("occurrence_range") or {}).get("minimum") or 0), str(item.get("insight_id"))))
