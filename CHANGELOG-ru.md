# Журнал изменений

В этом файле документируются все существенные изменения `kdiag`.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), проект использует [семантическое версионирование](https://semver.org/lang/ru/spec/v2.0.0.html).

## [Не выпущено]

## [0.8.1] - 2026-08-27

### Изменено

- `report.md` переработан как понятный русскоязычный отчёт администратора: технические английские заголовки заменены, а каждая проблема теперь последовательно отвечает «что обнаружено», «что это означает», «что говорит против», «что не удалось проверить» и «что делать».
- Штатные карточки категорий `routine` и `observe` больше не выводятся в `report.md` и `report.json`; они остаются в конфиденциальном `normalized-events.json.gz`. Карточки authentication-config и ptrace, для которых уже существуют отдельные проверки, также скрыты во избежание дублирования.
- Успешные проверки сбора и одинаковые ошибки на разных узлах сворачиваются в Markdown. Полный технический перечень источников и результаты каждой проверки без изменений остаются в JSON.

### Исправлено

- Текущие журналы теперь запрашиваются от новых записей к старым. При достижении лимита kdiag сохраняет ближайшую к инциденту часть окна, а не самые старые записи.
- Сборщик сохраняет только метаданные Deckhouse authentication config, но не содержимое. Проверка различает старую/кратковременную ошибку чтения и текущее отсутствие файла по наличию файла на host, API readyz и готовности Pod kube-apiserver; отдельно указано, что видимость внутри mount namespace контейнера напрямую не проверяется.
- Предупреждения об усечённых журналах группируются по источнику и числу узлов и указывают точные параметры `collection.max_command_bytes` / `collection.since_hours` вместо длинного списка путей.

## [0.8.0] - 2026-08-26

### Добавлено

- Добавлен детерминированный офлайн-каталог распространённых шаблонов Kubernetes/Deckhouse. Triage-карточки относят сообщения к `routine`, `observe`, `actionable` или `security` и показывают объяснение, условие решения, рекомендацию, bounded-примеры, диапазон частоты, timestamps/rate, затронутые Node/Pod, локальные корреляции, counter-evidence и missing checks.
- Карточки локально сопоставляются с readiness/restarts Pod, Events, API readyz, готовностью EndpointSlice и категоризированными ошибками journal. Allowlist-проекция Pod сохраняет имена `imagePullSecrets`, но объекты и содержимое Secrets по-прежнему не собираются.

### Исправлено

- Фильтр штатных DNS smoke-запросов Deckhouse исправлен на реальное имя `smoke-mini-*`. Подавляются только производные normalized events/findings; confidential raw evidence не изменяется.
- Приблизительная частота fingerprints теперь выводится как гарантированный минимум и оценочная верхняя граница с явным описанием алгоритмической погрешности вместо неоднозначного `max error`.

### Документация

- Описан контракт offline triage-карточек и ограничения: это не findings, LLM и сеть не требуются, а отсутствующий source evidence или не встроенные сведения о версии продукта автоматически не восполняются.

## [0.7.2] - 2026-08-26

### Исправлено

- Kubernetes bundle с агрегатным статусом `unreachable` теперь читается при построении отчёта. Реальные per-source статусы `failed`, `forbidden`, `timeout` и другие больше не превращаются в ложное `missing` для всех зависимых правил.
- Gaps в rule ledger теперь содержат статус, одинаковая недоступная node command группируется по узлам, а перед таблицей выводятся основные причины `unknown`. Зависящие от намеренно отключённого Kubernetes collector правила получают `not_applicable`.
- CoreDNS error events для штатного DNS probe `smoke-mini-*` исключаются из normalized derived output и findings. Исходный log evidence не изменяется и остаётся в confidential collection bundle.

## [0.7.1] - 2026-08-26

### Добавлено

- Добавлены осторожные fact-findings для повторяющихся ошибок чтения authentication config у kube-apiserver и kernel/security-agent ptrace alerts. Оба сохраняют bounded excerpts и явно не утверждают недоступность API, вредоносность или причинность без дополнительных evidence.

### Исправлено

- В детерминированный безопасный `PATH` сборщика добавлен Deckhouse-каталог `/opt/deckhouse/bin`, поэтому поставляемые с Deckhouse `crictl`, `containerd` и `runc` находятся без наследования неконтролируемого login environment.
- Отсутствующие исполняемые файлы, включая необязательные клиенты `nft` и `conntrack`, теперь отображаются как недоступные команды вместо вводящего в заблуждение сообщения Python «No such file or directory».
- Статус `unknown` в ledger теперь вычисляется по объявленным зависимостям evidence каждого правила. Усечение Pod logs или отказ одного Kubernetes source больше не переводит несвязанные Node, Kubernetes, DNS, storage и Cilium правила в `unknown`.
- Inventory aliases, собранные hostname/FQDN, имена Kubernetes Node и label `kubernetes.io/hostname` сопоставляются по однозначному exact или short name. Это устраняет ложные inventory mismatch и восстанавливает Node-scoped correlations, когда inventory использует короткие имена, а Kubernetes — FQDN.
- Выбранный режим сбора etcd теперь сохраняется в метаданных node/collection/report, поэтому отключённые etcd-правила получают `not_applicable`, а не `unknown` или `not_matched`.
- Heavy hitters неизвестных fingerprints теперь выводятся компактным сбалансированным по компонентам списком с bounded templates в code formatting. Angle-bracket placeholders отображаются как читаемые `<n>`, `<ipv6>` и подобные токены вместо буквальных HTML entities.

### Документация

- Зафиксировано, что Kubernetes API audit logs, включая Deckhouse-specific backends, намеренно не собираются до появления отдельного bounded и redacted режима с явным opt-in.

## [0.7.0] - 2026-08-26

### Добавлено

- Добавлены coverage по node commands, node/Kubernetes Pod logs и Kubernetes sources, а также ledger из 96 правил со статусами matched, not-matched, unknown и not-applicable.
- Добавлены bounded evidence cards, независимые scoped correlation episodes с временем, справедливое ограничение events, дедупликация, counters отбрасывания по sources, поиск расхождения inventory/Node и finding об усечении нормализации.
- Добавлен discovery Deckhouse CSE Pro 1.74 для ConfigMap/log namespaces Cilium/CoreDNS с fallback к vanilla; kube-proxy остаётся необязательным.
- Local/external LLM packages теперь содержат bounded evidence fragments status/value/excerpt/timestamp; внешние fragments псевдонимизируются и проходят DLP, token/evidence maps остаются приватными.
- Findings об ошибках CoreDNS resolution теперь показывают до 20 уникальных имён неуспешных запросов, query type и частоту; ссылки на строки остаются evidence.
- Добавлены `collection.collect_cgroup=false` и `--skip-cgroup`: прямые cgroup facts не собираются, cgroup events/correlations и связанные findings подавляются, а выбранный режим фиксируется в collection и отчётах.
- Добавлена отключаемая визуализация выполнения `--progress off|summary|detail` в `stderr`: этапы, состояние сбора по узлам, категории node evidence и статусы Kubernetes API sources.
- Добавлена поддержка Deckhouse `containerd-deckhouse.service` наряду с vanilla `containerd.service` и `crio.service`; scope rule pack расширен до Kubernetes 1.24–1.31.

### Исправлено

- Устранены ложные findings для старых ротированных kubelet client certificates, нормального StatefulSet revision drift, активных retry Job, пустого массива CoreDNS container statuses, отфильтрованных Service selectors, отсутствующего Cilium coverage, пустой успешно собранной Cilium service map, per-interface IPv6 disable и неверной границы version skew.
- Все inferred timestamps исключены из причинных correlations; `collect_cgroup=false` подавляет событие целиком, включая EROFS/read-only labels.
- Read-only EROFS/container snapshot mounts внутри каталога containerd больше не считаются заполненными runtime filesystems; проверка анализирует только отдельные backing mount points runtime, kubelet и logs.
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
