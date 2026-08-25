# Журнал изменений

В этом файле документируются все существенные изменения `kdiag`.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), проект использует [семантическое версионирование](https://semver.org/lang/ru/spec/v2.0.0.html).

## [Не выпущено]

### Добавлено

- Добавлены `collection.collect_cgroup=false` и `--skip-cgroup`: прямые cgroup facts не собираются, cgroup events/correlations и связанные findings подавляются, а выбранный режим фиксируется в collection и отчётах.
- Добавлена отключаемая визуализация выполнения `--progress off|summary|detail` в `stderr`: этапы, состояние сбора по узлам, категории node evidence и статусы Kubernetes API sources.
- Добавлена поддержка Deckhouse `containerd-deckhouse.service` наряду с vanilla `containerd.service` и `crio.service`; scope rule pack расширен до Kubernetes 1.24–1.31.

### Исправлено

- Runtime units с `LoadState=not-found` больше не создают `runtime_unavailable`/`node.runtime_inactive`; неактивный альтернативный runtime игнорируется, если другой загруженный runtime работает.
- Снимок статического systemd state больше не получает искусственную временную причинность в 15-минутных correlations; для временной корреляции требуется реальное timestamped event.

### Документация

- Добавлена пошаговая инструкция по созданию отдельного kubeconfig для ServiceAccount `kdiag-reader` с краткоживущим TokenRequest, встроенным CA, режимом файла `0600`, обновлением токена и проверкой RBAC.
- Добавлена отдельная инструкция с точными read-only командами ручной проверки cgroup на узле и шаблоном обезличенного результата.

## [0.6.0] - 2026-08-24

### Добавлено

- Добавлена команда `kdiag llm analyze-local` для проверенных подготовленных local packages и OpenAI-compatible chat-completions service на literal loopback.
- Добавлены ограничение ответа, проверка evidence IDs/контракта, отклонение изменяющих команд, Markdown-rendering и SHA-256 manifest результатов локального анализа.
- Добавлен hardened systemd deployment llama.cpp с loopback/offline defaults, непривилегированной service identity, отключёнными logging/UI/agent mode и двуязычной инструкцией установки на РЕД ОС.

### Безопасность

- Локальный клиент отключает proxy и redirects, не передаёт пути к collection, запрещает non-loopback endpoints и не исполняет предложения модели.
- Новые local packages используют `prepared/` вместо вводящего в заблуждение `export/`; `analyze-local` сохраняет совместимость с legacy local `export/` packages версии 0.5.0.

## [0.5.0] - 2026-08-24

### Добавлено

- Добавлен первый этап необязательной LLM-интеграции: минимизированные incident packages с ограничением размера и версионированные prompts для `fast-triage` и `deep-analysis`.
- Добавлен fail-closed внешний профиль: incident-local псевдонимы, outbound DLP, отдельный token map с режимом `0600`, проверка manifest экспорта и точное восстановление известных токенов в сохранённом вручную ответе.
- Добавлены команды `kdiag llm prepare`, `llm validate-export` и `llm import-response`; runtime модели, автоматизация браузера и внешний сетевой клиент не включены.
- Добавлена проверка контракта ответа, evidence IDs и изменяющих команд; исходный внешний ответ сохраняется как недоверенный материал аудита.

### Безопасность

- Из внешнего пакета удаляются известные внутренние имена узлов, Kubernetes-объектов и учётных записей, IP/MAC/CIDR, DNS, URL, UID, host paths и ports endpoints; диагностические названия и версии компонентов сохраняются.

## [0.4.0] - 2026-08-24

### Добавлено

- Английский README проекта, соответствующий русскому README.
- Английские и русские архитектурные диаграммы PlantUML: контекст системы, компоненты, выполнение snapshot и конвейер обработки evidence.
- Английский и русский журналы изменений.
- Автономный набор расширен до 93 проверок: lifecycle Pod/init containers, ошибки rollout, состояние PDB, CRI readiness/inventory, resolver/CoreDNS, Prometheus, version skew, ротация сертификата kubelet, lag/capacity/fragmentation/version drift etcd.
- Добавлено read-only сравнение Cilium service maps для кластеров без kube-proxy. Отсутствие kube-proxy допустимо при включённом Cilium replacement; finding уровня fact создаётся только при явно отключённом replacement.
- Добавлены приоритетный сбор current/previous logs нездоровых системных и init containers, ограниченная проекция CoreDNS ConfigMap и точные evidence references новых findings.

## [0.3.0] - 2026-08-24

### Добавлено

- Разовый ограниченный по объёму аварийный snapshot Kubernetes и РЕД ОС.
- Параллельный сбор с узлов через `scp`, `ssh` и неинтерактивный `sudo` с помощью Python zip application, использующего только стандартную библиотеку.
- Read-only сбор из Kubernetes основных ресурсов, workloads, discovery, control-plane, storage, networking и выбранных ресурсов Cilium.
- Ограниченные журналы системных Pod и прикладных Pod только из явно разрешённых namespace.
- Необязательный Prometheus source, недоступность которого не прерывает сбор.
- Read-only сбор status, health и alarms stacked-etcd со стандартной структурой kubeadm.
- Автономная нормализация событий, корреляция в пределах 15 минут, fingerprints неизвестных сообщений и версионируемый детерминированный набор правил.
- Findings с классификацией `fact`, `correlation` или `hypothesis`, evidence и рекомендациями.
- Результаты в JSON, gzip/JSON и Markdown с coverage matrix.
- Создание и проверка SHA-256 manifest набора файлов.
- Команды повторной сборки отчёта, просмотра правил и встроенного synthetic self-test.
- Пример отдельного read-only Kubernetes RBAC и руководства пользователя на двух языках.

### Безопасность

- Из сбора исключены Kubernetes Secrets, `pods/exec`, изменяющие операции, автоматическое исправление и содержимое закрытых ключей.
- Журналы прикладных namespace требуют явного allowlist.
- Команды запускаются фиксированными списками аргументов, с ограничением объёма, таймаутами и строгой проверкой SSH host key.
