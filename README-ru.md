# kdiag: разовый аварийный снимок Kubernetes / РЕД ОС

`kdiag` собирает с узлов и Kubernetes API ограниченный диагностический snapshot, нормализует и коррелирует события, формирует локальные gzip/JSON bundles, deterministic findings и Markdown-отчёт. Необязательная offline-команда подготавливает минимизированные данные для LLM, но LLM не требуется для сбора и детерминированного анализа. Автоматическое исправление и постоянные агенты не используются.

## Что реализовано

- discovery узлов через существующий Ansible inventory;
- доставка одного stdlib-only `.pyz` через системный `scp`;
- запуск node collector через `ssh` и `sudo -n`;
- продолжение сбора при недоступном узле, API или Prometheus;
- node evidence: OS/kernel/boot/packages, systemd/kubelet, CRI inventory/readiness, journals, сеть/sysctl, cgroup, PSI/resources, config hashes, certificate rotation metadata, read-only stacked-etcd status/capacity и bounded CRI logs;
- определение активного runtime для vanilla `containerd.service`, `crio.service` и Deckhouse `containerd-deckhouse.service`; отсутствующие и неиспользуемые альтернативные units не считаются отказом;
- allowlist-проекция Nodes, Pods, Events, workloads, Services, EndpointSlices, APIService, Lease, PDB/PV/PVC/CSI, NetworkPolicy и диагностических Cilium CRD;
- API server `/readyz?verbose` и параллельный bounded Kubernetes collection тремя read-only запросами;
- bounded current/previous logs только системных и явно разрешённых namespace;
- manifest SHA-256, JSON-отчёт и Markdown-отчёт;
- автономный rule pack для Node Problem Detector signatures, Pod lifecycle/rollouts/PDB, Service/CoreDNS/EndpointSlice, Prometheus, control-plane/etcd capacity, storage/CSI, runtime/Cilium, version skew, ресурсов, времени и сертификатов;
- диагностика Cilium в режиме без kube-proxy по effective replacement setting и read-only service maps на узлах; само отсутствие kube-proxy не считается ошибкой;
- разделение выводов на `fact`, `correlation` и `hypothesis`, нормализованные events и fingerprints неизвестных сообщений.
- необязательные минимизированные пакеты для локальной LLM и fail-closed псевдонимизированные пакеты для ручной работы с внешней LLM.

Подробные инструкции: [User Guide (English)](docs/UserGuide.md) и [Руководство пользователя (русский)](docs/UserGuide-ru.md).

Архитектура, покрытие и первичные источники описаны в [документе rule pack](docs/autonomous-rule-pack.md).

Архитектурные диаграммы PlantUML находятся в [каталоге diagramms](diagramms/).

Система ничего не меняет в Kubernetes и не перезапускает сервисы. На Node временно копируется `/tmp/kdiag-<collection>.pyz`, который удаляется после запуска.

## Требования

На управляющем сервере:

- Python 3.8;
- `ansible-inventory`, `ssh`, `scp`, `kubectl`;
- Ansible inventory, из которого `ansible-inventory --list --export` получает JSON;
- настроенные SSH key и `known_hosts`;
- отдельный read-only kubeconfig для collector.
- каталог `--output-dir`, доступный на запись запускающей учётной записи; рекомендуется заранее создать его с режимом `0700` на локальной файловой системе управляющего сервера.

Пример прав для отдельной Kubernetes identity находится в [RBAC-манифесте](deploy/kubernetes/kdiag-rbac.yaml). Он не применяется автоматически. `pods/log` разрешён только в `kube-system`; для каждого прикладного namespace следует создать отдельные namespace-scoped Role/RoleBinding по этому образцу.

Пошаговое создание отдельного kubeconfig для ServiceAccount `kdiag-system/kdiag-reader`, включая выпуск и обновление краткоживущего токена, описано в разделе [Kubernetes identity и RBAC](docs/UserGuide-ru.md#6-kubernetes-identity-и-rbac) руководства пользователя.

После выдачи kubeconfig проверьте права именно этой identity:

```bash
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i list nodes
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i list pods --all-namespaces
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i get pods/log --namespace kube-system
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i get /readyz
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i list apiservices.apiregistration.k8s.io
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i create pods/exec --all-namespaces
kubectl --kubeconfig /path/to/kdiag-readonly.kubeconfig auth can-i get secrets --all-namespaces
```

Первые пять команд должны вернуть `yes`, две последние — `no`. `kdiag` не использует `pods/exec`.

На узлах:

- Python 3.8 по известному абсолютному пути, по умолчанию `/usr/bin/python3.8`;
- неинтерактивный `sudo -n` до root для текущей SSH-учётки;
- штатные системные утилиты. Отсутствующая утилита отмечается как `unsupported`, а не ломает snapshot.

На control-plane узлах `collect_etcd=true` использует host `etcdctl` либо `crictl exec` в уже работающий static Pod etcd. Выполняются только `endpoint status`, `endpoint health` и `alarm list` со стандартными kubeadm healthcheck TLS paths. Содержимое private key не читается и не попадает в bundle. Для external/non-kubeadm etcd источник будет `not_applicable` или `unavailable`.

Текущая широкая возможность `sudo` делает SSH-учётку высокопривилегированной независимо от `kdiag`. Для постоянной эксплуатации рекомендуется root-owned wrapper/узкий `sudoers`; первый аварийный вариант использует уже разрешённую модель доступа.

## Сборка без сети

```bash
python3.8 scripts/build.py
python3.8 dist/kdiag.pyz --version
```

Артефакт `dist/kdiag.pyz` содержит только исходный код проекта и стандартную библиотеку Python не включает. `pip install` не требуется.

## Конфигурация

Скопируйте [пример конфигурации](config/snapshot.example.json) и укажите отдельный kubeconfig. Не добавляйте в JSON пароли, SSH private key или Kubernetes tokens; конфигурация хранит только пути.

Безопасный default для прикладных namespace — пустой список. Namespace можно разрешить в JSON или повторяемым параметром `--application-namespace`.

Сбор stacked-etcd включён параметром `collection.collect_etcd=true`; его можно отключить в JSON. Прямой cgroup-сбор и связанные проверки можно отключить через `collection.collect_cgroup=false` или `--skip-cgroup`. Optional Cilium CRD и `CSIStorageCapacity` не переводят snapshot в `partial`, если API конкретной версии отсутствует, но отображаются в coverage matrix.

## Запуск

```bash
python3.8 dist/kdiag.pyz snapshot \
  --inventory /path/to/inventory \
  --group k8s \
  --config /path/to/snapshot.json \
  --kubeconfig /path/to/kdiag-readonly.kubeconfig \
  --output-dir /var/lib/kdiag
```

Полезные параметры:

- `--ssh-user USER` — user по умолчанию, если его нет в inventory;
- `--remote-python /path/python3.8` — Python на узлах;
- `--since-hours 24` — окно журналов;
- `--parallelism 2` — число одновременно опрашиваемых узлов;
- `--progress off|summary|detail` — отключить progress, показать этапы/узлы или также статусы отдельных источников; по умолчанию `summary`, вывод направляется в `stderr`;
- `--skip-cgroup` — не собирать прямые cgroup facts и не создавать cgroup events/findings;
- `--skip-kubernetes` — собрать только node evidence;
- `--prometheus-url URL` — best-effort Prometheus evidence;
- `--application-namespace NAME` — явно разрешить логи namespace.

`ansible_ssh_common_args` и `ansible_ssh_extra_args` намеренно не исполняются. Для ProxyJump или сложного inventory сначала создайте проверенный OpenSSH alias и используйте его как `ansible_host`.

Из inventory используются только имя узла, `ansible_host`, `ansible_user` и `ansible_port`. Ключ текущей учётной записи должен быть доступен обычному `ssh` через стандартный путь, `ssh-agent` или проверенный OpenSSH config; `ansible_ssh_private_key_file` не переносится в команду.

## Результат

Каждый запуск создаёт отдельный каталог:

```text
<output>/<collection-id>/
  collection.json
  node-<inventory-host>.json.gz
  kubernetes.json.gz
  prometheus.json.gz
  normalized-events.json.gz
  facts.json
  findings.json
  report.json
  report.md
  manifest.json
```

`report.md` начинается с coverage matrix. Отсутствие источника отображается явно. Повторно построить derived-отчёт можно командой:

```bash
python3.8 dist/kdiag.pyz report /var/lib/kdiag/<collection-id>
```

Проверить полноту набора и SHA-256 каждого файла:

```bash
python3.8 dist/kdiag.pyz verify /var/lib/kdiag/<collection-id>
```

Manifest выявляет случайную порчу, удаление и добавление файлов. Он не является цифровой подписью и не защищает от намеренной согласованной подмены файлов вместе с `manifest.json`.

## Автономные правила

Команды не используют сеть и не обращаются к кластеру:

```bash
python3.8 dist/kdiag.pyz self-test
python3.8 dist/kdiag.pyz rules list
python3.8 dist/kdiag.pyz rules explain kubernetes.node_not_ready
```

`normalized-events.json.gz` содержит категоризированные события, корреляции и bounded approximate heavy hitters неизвестных fingerprints. Исходные сообщения остаются confidential evidence; передавать этот файл за пределы контура без отдельного обезличивания нельзя.

Коды завершения snapshot:

- `0` — все Node и обязательный Kubernetes source собраны;
- `1` — частичный snapshot сохранён, но один или несколько обязательных источников недоступны;
- `2` — configuration/preflight error, запуск не выполнен.

Prometheus необязателен и на код завершения не влияет.

## Необязательный incident package для LLM

`prepare` создаёт данные, но не устанавливает и не вызывает модель. Локальный пакет сохраняет эксплуатационные идентификаторы, но не включает исходные bundles и полные журналы:

```bash
python3.8 dist/kdiag.pyz llm prepare /var/lib/kdiag/<collection-id> \
  --output-dir /secure/kdiag-llm-local \
  --profile local \
  --mode deep-analysis \
  --question "Каковы наиболее вероятные причины?"
```

Передайте подготовленный package отдельно развёрнутому OpenAI-compatible service, слушающему literal loopback:

```bash
python3.8 dist/kdiag.pyz llm analyze-local /secure/kdiag-llm-local/prepared \
  --model local-model-name \
  --output-dir /secure/kdiag-llm-local-response
```

`analyze-local` передаёт содержимое подготовленного JSON, а не путь к collection, и никогда не исполняет предложения модели. Модель/runtime не входят в `kdiag.pyz` и не настраиваются им.

Пример hardened systemd deployment llama.cpp находится в [deploy/systemd](deploy/systemd/README-ru.md). Новые local preparations используют `prepared/`; `analyze-local` также принимает legacy-каталоги local `export/`, созданные kdiag 0.5.0.

Для ручной работы с внешней LLM используйте `--profile external`. Команда псевдонимизирует известные имена узлов, Kubernetes-ресурсов и учётных записей, адреса, DNS, пути, UID и ports endpoints; сохраняет диагностически значимые названия и версии компонентов; выполняет outbound DLP; создаёт раздельные каталоги `export/` и `private/`. Просмотрите экспорт, повторно проверьте его и передавайте только содержимое `export/`:

```bash
python3.8 dist/kdiag.pyz llm validate-export /secure/kdiag-llm-external/export
python3.8 dist/kdiag.pyz llm import-response /secure/google-response.txt \
  --token-map /secure/kdiag-llm-external/private/token-map.json \
  --output-dir /secure/kdiag-llm-response
```

`private/token-map.json` содержит таблицу разанонимизации и не должен покидать доверенный контур. Внешний ответ считается недоверенным; `kdiag` сохраняет исходную и восстановленную копии. Автоматизация браузера и прямой доступ к Google API намеренно отсутствуют.

## Лимиты и хранение

По умолчанию один compressed Node bundle ограничен 32 MiB, Kubernetes bundle — 128 MiB, а перед запуском сохраняется резерв 1 GiB. При первоначальном лимите 5 ГБ на управляющем сервере не запускайте несколько snapshot без контролируемой retention.

Backup не нужен для самого сбора. Без backup отказ диска управляющего сервера уничтожит ранее полученные bundles и baseline; это риск сохранности истории, а не работоспособности разового snapshot.

## Проверка

```bash
PYTHONPATH=src python3.8 -m compileall -q src tests
PYTHONPATH=src python3.8 -m unittest discover -s tests -v
python3.8 scripts/build.py
python3.8 dist/kdiag.pyz --version
python3.8 dist/kdiag.pyz verify /var/lib/kdiag/<collection-id>
```
