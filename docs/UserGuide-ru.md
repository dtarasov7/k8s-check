# Руководство пользователя kdiag

## 1. Назначение и границы решения

<code>kdiag 0.8.1</code> создаёт разовый аварийный снимок Kubernetes-кластера и выполняет полностью автономный детерминированный анализ. Текущая диагностическая совместимость — vanilla Kubernetes и Deckhouse CSE Pro 1.74 с Kubernetes 1.24–1.31, до 20 узлов и около 1000 Pod. Это совместимость форматов исходных данных и проверок, а не заявление о lifecycle support.

Программа запускается на отдельном управляющем сервере. Она подключается к каждому узлу по SSH, выполняет диагностические команды через неинтерактивный sudo и опрашивает Kubernetes API с отдельным kubeconfig. Prometheus необязателен: снимок можно получить при недоступности Prometheus или всего Kubernetes API.

Текущая версия реализует только этап **«Разовый аварийный снимок и инвентаризация»**. Периодический baseline и непрерывный watch Kubernetes/журналов относятся к следующим этапам и пока отсутствуют.

Для работы не требуются LLM, Интернет, внешние Python-пакеты, агенты на узлах, DaemonSet или база данных. Анализ выполняет версионируемый набор правил. Необязательная команда после сбора готовит минимизированные данные для LLM и не влияет на детерминированный отчёт. Программа не обновляет Kubernetes, не исправляет кластер, не перезапускает службы, не меняет sysctl и не модифицирует etcd.

## 2. Схема работы

Управляющий сервер одновременно является сборщиком и центральным хранилищем:

~~~text
Управляющий сервер
  kdiag.pyz + JSON-конфигурация + Ansible inventory + отдельный kubeconfig
       |                              |
       | SSH + sudo -n                | read-only запросы Kubernetes API
       v                              v
  Узлы Kubernetes                Kubernetes API VIP
       |
       +-- параметры ОС, конфигурация, systemd и journald
       +-- evidence kubelet/runtime/Cilium/KESL/ядра
       +-- опциональная read-only проверка локального etcd

  Результат: отдельный каталог снимка на управляющем сервере
~~~

Последовательность работы:

1. Проверить конфигурацию, резерв диска, inventory, SSH, sudo и доступ к API.
2. Собрать ограниченный по объёму evidence с узлов и из Kubernetes.
3. Нормализовать журналы и структурированные состояния Kubernetes.
4. Сопоставить связанные записи в окне 15 минут.
5. Выполнить детерминированные правила и сформировать JSON- и Markdown-отчёты.
6. Создать манифест с размерами файлов и SHA-256.

Недоступность одного узла или API обычно приводит к сохранению **частичного снимка**, а не к потере уже собранного evidence.

## 3. Безопасность и классификация данных

Сборщик использует read-only команды и глаголы Kubernetes. Поставляемый RBAC не разрешает чтение Secrets, <code>pods/exec</code> и операции изменения. Для etcd выполняются только <code>endpoint status</code>, <code>endpoint health</code> и <code>alarm list</code>; запись в etcd отсутствует.

Стандартные пути клиентских сертификатов etcd могут использоваться локально, но содержимое закрытых ключей в снимок не копируется. Журналы прикладных Pod не собираются, пока namespace явно не добавлен в allowlist.

Снимок **не обезличен**. Он может содержать имена узлов и Kubernetes-объектов, namespace, образы, IP-адреса, идентификаторы хранилищ, Events, выбранные журналы Pod, journald, конфигурационные значения, subject и сроки сертификатов. Весь каталог результата следует считать конфиденциальными эксплуатационными данными. Перед передачей за пределы контура его необходимо проверить и обезличить.

<code>manifest.json</code> позволяет обнаружить изменение файлов по SHA-256. Это не цифровая подпись и не подтверждение авторства снимка.

## 4. Требования

### 4.1 Управляющий сервер

- Python 3.8.
- <code>ssh</code>, <code>scp</code>, <code>kubectl</code> и <code>ansible-inventory</code> в PATH.
- Ansible inventory со всеми узлами.
- Доступ по SSH-ключу и корректные записи known_hosts.
- Отдельная Kubernetes identity и kubeconfig.
- На старте — 5 ГиБ свободного места; по умолчанию 1 ГиБ сохраняется как неприкосновенный резерв.

Ansible применяется только для разбора inventory и переменных <code>ansible_host</code>, <code>ansible_user</code>, <code>ansible_port</code>. Playbook не запускается. Нельзя рассчитывать, что произвольные connection plugins, <code>ansible_ssh_common_args</code> или <code>ansible_ssh_private_key_file</code> будут использованы kdiag; необходимые маршруты и ключи следует настроить в обычном OpenSSH.

### 4.2 Узлы кластера

- Python 3.8 по настроенному абсолютному пути; по умолчанию <code>/usr/bin/python3.8</code>.
- Доступ по SSH-ключу для учётной записи управляющего сервера.
- Беспарольный неинтерактивный <code>sudo -n</code> до root.
- Persistent journald и стандартные средства диагностики: systemctl, journalctl, sysctl, df, ss, ip.
- В целевом контуре доступно до 5 ГиБ на узел; стандартный лимит временного сжатого bundle равен только 32 МиБ.

Node commands выполняются с фиксированным безопасным PATH: сначала <code>/opt/deckhouse/bin</code>, затем стандартные системные каталоги. Это позволяет находить поставляемые Deckhouse <code>crictl</code>, <code>containerd</code> и <code>runc</code> без наследования произвольного login PATH. Если необязательный CLI, например <code>nft</code> или <code>conntrack</code>, отсутствует, запись команды получает <code>unsupported</code>; это само по себе ничего не говорит о поддержке nftables или conntrack ядром.

Временные данные на узле удаляются после нормально завершившейся передачи. После прерванного запуска следует проверить наличие остатков.

### 4.3 Допущения для etcd

Read-only проверка stacked etcd в стиле kubeadm выполняется только при стандартных путях:

~~~text
/etc/kubernetes/manifests/etcd.yaml
/etc/kubernetes/pki/etcd/ca.crt
/etc/kubernetes/pki/etcd/healthcheck-client.crt
/etc/kubernetes/pki/etcd/healthcheck-client.key
~~~

Используется установленный на узле etcdctl либо crictl для вызова etcdctl внутри уже работающего локального контейнера etcd. Для внешнего etcd и нестандартной раскладки будет сформирован evidence gap, а не недостоверный диагноз.

## 5. Сборка, тестирование и перенос в изолированный контур

Поставляемый файл — <code>dist/kdiag.pyz</code>, Python zip application только с кодом проекта и стандартной библиотекой.

~~~bash
python3.8 scripts/build.py
PYTHONPATH=src python3.8 -m unittest discover -s tests -v
python3.8 dist/kdiag.pyz self-test
sha256sum dist/kdiag.pyz
~~~

Через утверждённый процесс переноса передаются pyz, сохранённая контрольная сумма, проверенная JSON-конфигурация, RBAC-манифесты и руководства. После переноса:

~~~bash
sha256sum kdiag.pyz
python3.8 kdiag.pyz --version
python3.8 kdiag.pyz self-test
~~~

Не следует брать контрольную сумму из документации: легитимная пересборка меняет её.

## 6. Kubernetes identity и RBAC

Следует создать отдельную identity, даже если для первого контролируемого теста доступен super-admin. Минимальные полномочия уменьшают последствия компрометации долгоживущего kubeconfig.

Поставляемый манифест <code>deploy/kubernetes/kdiag-rbac.yaml</code> создаёт:

- namespace <code>kdiag-system</code> и ServiceAccount <code>kdiag-reader</code>;
- read-only ClusterRole и ClusterRoleBinding для структурных ресурсов;
- Role и RoleBinding для <code>pods/log</code> в <code>kube-system</code>.

Перед применением манифеста нужно проверить subjects во всех binding. Нельзя добавлять Secrets, pods/exec или write-глаголы. Roles для прикладных namespace автоматически не создаются: необходимо создать аналогичные namespaced Role и RoleBinding, привязать их к <code>kdiag-system/kdiag-reader</code> и добавить в конфигурацию только согласованный namespace.

Сборщик читает Nodes, Pods, Events, workload-объекты, Services, EndpointSlices, PDB, PVC, PV, APIService, Leases, VolumeAttachments, CSI-объекты, StorageClasses, NetworkPolicies, выбранные Cilium CRD, разрешённые поля ConfigMap <code>cilium-config</code> и <code>coredns</code>, non-resource URL <code>/readyz</code> и журналы Pod только в разрешённых namespace. Discovery ConfigMap сначала проверяет Deckhouse locations (`d8-cni-cilium`, `d8-kube-dns`), затем vanilla `kube-system`, сохраняя все attempts и выбранный object.

### Создание kubeconfig для kdiag-reader

Команды выполняются на защищённом управляющем сервере с использованием bootstrap kubeconfig, которому разрешены применение RBAC-манифеста и создание ServiceAccount TokenRequest. Его текущий context должен указывать на целевой кластер. Для разового snapshot рекомендуется краткоживущий токен, а не бессрочный Secret типа <code>kubernetes.io/service-account-token</code>.

~~~bash
umask 077
install -d -m 0700 /secure/kdiag
ADMIN_KUBECONFIG=/secure/admin.kubeconfig
KDIAG_KUBECONFIG=/secure/kdiag/kdiag-reader.kubeconfig
KDIAG_CA=/secure/kdiag/kdiag-ca.crt

kubectl --kubeconfig "$ADMIN_KUBECONFIG" apply -f deploy/kubernetes/kdiag-rbac.yaml
kubectl --kubeconfig "$ADMIN_KUBECONFIG" -n kdiag-system get serviceaccount kdiag-reader

KDIAG_SERVER="$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl --kubeconfig "$ADMIN_KUBECONFIG" config view --raw --minify --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 --decode > "$KDIAG_CA"
KDIAG_TOKEN="$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" -n kdiag-system create token kdiag-reader --duration=8h)"

test -n "$KDIAG_SERVER"
test -s "$KDIAG_CA"
test -n "$KDIAG_TOKEN"

kubectl config set-cluster kdiag-cluster \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --server "$KDIAG_SERVER" \
  --certificate-authority "$KDIAG_CA" \
  --embed-certs=true
kubectl config set-credentials kdiag-reader \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --token "$KDIAG_TOKEN"
kubectl config set-context kdiag-reader@kdiag-cluster \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --cluster kdiag-cluster \
  --user kdiag-reader \
  --namespace kdiag-system
kubectl config use-context kdiag-reader@kdiag-cluster \
  --kubeconfig "$KDIAG_KUBECONFIG"
chmod 0600 "$KDIAG_KUBECONFIG"
unset KDIAG_TOKEN
~~~

Проверка <code>test -s "$KDIAG_CA"</code> намеренно останавливает процедуру, если из bootstrap kubeconfig нельзя получить CA. Не заменяйте её параметром <code>--insecure-skip-tls-verify</code>. API server может выдать токен на меньший срок, чем запрошенные 8 часов. После истечения токена <code>kubectl</code> вернёт Unauthorized; перед следующим snapshot обновите только credentials в существующем kubeconfig:

~~~bash
KDIAG_TOKEN="$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" -n kdiag-system create token kdiag-reader --duration=8h)"
test -n "$KDIAG_TOKEN"
kubectl config set-credentials kdiag-reader \
  --kubeconfig "$KDIAG_KUBECONFIG" \
  --token "$KDIAG_TOKEN"
chmod 0600 "$KDIAG_KUBECONFIG"
unset KDIAG_TOKEN
~~~

Не копируйте bootstrap kubeconfig на сервер постоянного запуска и не добавляйте токен в JSON-конфигурацию. Для запуска по расписанию нужен утверждённый процесс обновления краткоживущих credentials до старта snapshot.

~~~bash
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get nodes
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get /readyz
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get pods/log -n kube-system
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i get secrets -A
kubectl --kubeconfig /secure/kdiag/kdiag-reader.kubeconfig auth can-i create pods -A
~~~

Первые три команды должны вернуть yes, последние две — no. Role/RoleBinding для приложения создаётся только в явно согласованных namespace.

## 7. Inventory

Можно использовать любой формат, понимаемый установленным ansible-inventory. Минимальный INI:

~~~ini
[k8s_nodes]
cp01 ansible_host=10.10.0.11 ansible_user=kdiag
cp02 ansible_host=10.10.0.12 ansible_user=kdiag
worker01 ansible_host=10.10.0.21 ansible_user=kdiag
~~~

~~~bash
ansible-inventory -i inventory.ini --list
ssh cp01 true
ssh cp01 sudo -n true
~~~

Следует проверить каждый профиль подключения. Пароли и закрытые ключи нельзя помещать в конфигурацию снимка.

Inventory alias не обязан совпадать с <code>metadata.name</code> Kubernetes Node. kdiag сравнивает alias, собранные hostname/FQDN, имя Node и <code>kubernetes.io/hostname</code>. Exact match имеет приоритет; short name и FQDN сопоставляются только однозначно. Неоднозначные identity остаются несопоставленными и создают <code>inventory.node_set_mismatch</code>, а не предполагаемую связь.

## 8. Справочник конфигурации

Нужно скопировать <code>config/snapshot.example.json</code> в отдельный файл среды. Формат имеет <code>schema_version: 1</code>. Ошибочные значения останавливают preflight с кодом 2.

### 8.1 Collection

| Ключ | По умолчанию | Назначение |
|---|---:|---|
| <code>collection.since_hours</code> | 24 | Глубина журналов и Events. |
| <code>collection.parallelism</code> | 2 | Одновременные сборы с узлов; малое значение ограничивает нагрузку. |
| <code>collection.command_timeout_seconds</code> | 30 | Таймаут команды на узле. |
| <code>collection.max_command_bytes</code> | 1048576 | Максимум данных одной команды; усечение фиксируется. |
| <code>collection.max_node_bundle_bytes</code> | 33554432 | Максимальный сжатый bundle одного узла. |
| <code>collection.central_reserve_bytes</code> | 1073741824 | Место, которое обязано остаться свободным на управляющем сервере. |
| <code>collection.pod_log_tail_bytes</code> | 65536 | Tail одного CRI-файла при сборе с узла. |
| <code>collection.pod_log_total_bytes</code> | 8388608 | Суммарные прямые CRI-журналы одного узла. |
| <code>collection.pod_log_max_files</code> | 200 | Число прямых CRI-файлов на узел. |
| <code>collection.collect_etcd</code> | true | Read-only status, health и alarms локального etcd. |
| <code>collection.collect_cgroup</code> | true | Прямые cgroup facts/process mappings и связанные cgroup events/findings. |

### 8.2 SSH

| Ключ | По умолчанию | Назначение |
|---|---:|---|
| <code>ssh.connect_timeout_seconds</code> | 10 | Таймаут подключения. |
| <code>ssh.remote_python</code> | /usr/bin/python3.8 | Абсолютный путь Python на узле. |
| <code>ssh.user</code> | null | Необязательное глобальное переопределение пользователя. |
| <code>ssh.port</code> | 22 | Необязательное глобальное переопределение порта. |

### 8.3 Kubernetes

| Ключ | По умолчанию | Назначение |
|---|---:|---|
| <code>kubernetes.enabled</code> | true | Включить сбор через API. |
| <code>kubernetes.kubeconfig</code> | null | Отдельный kubeconfig; CLI может переопределить. |
| <code>kubernetes.context</code> | null | Необязательный context. |
| <code>kubernetes.command_timeout_seconds</code> | 30 | Таймаут каждого запроса. |
| <code>kubernetes.max_wire_bytes</code> | 67108864 | Максимум исходного ответа API. |
| <code>kubernetes.max_bundle_bytes</code> | 134217728 | Максимум сжатого Kubernetes bundle. |
| <code>kubernetes.system_namespaces</code> | [d8-cni-cilium, d8-kube-dns, kube-system] | Allowlist системных Pod logs vanilla и Deckhouse. |
| <code>kubernetes.application_namespaces</code> | [] | Явный allowlist прикладных журналов; пустой означает запрет. |
| <code>kubernetes.collect_system_logs</code> | true | Собирать ограниченные системные Pod logs. |
| <code>kubernetes.log_tail_lines</code> | 200 | Tail строк каждого контейнера. |
| <code>kubernetes.max_log_pods</code> | 100 | Максимум Pod для сбора журналов через API. |
| <code>kubernetes.max_log_bytes</code> | 33554432 | Суммарный лимит Pod logs через API. |

### 8.4 Prometheus

| Ключ | По умолчанию | Назначение |
|---|---:|---|
| <code>prometheus.url</code> | null | Необязательный URL; null отключает источник. |
| <code>prometheus.timeout_seconds</code> | 3 | Короткий таймаут, чтобы Prometheus не блокировал аварийный сбор. |
| <code>prometheus.max_response_bytes</code> | 1048576 | Максимальный размер ответа. |

Недоступность Prometheus не является фатальной.

### 8.5 Начальные 5 ГиБ

Стандартные верхние границы сжатых bundle для 20 узлов и Kubernetes суммарно дают около 768 МиБ без отчётов и рабочих данных. Это защитные лимиты, а не ожидаемый объём. Начинать следует со стандартных значений и изучать <code>manifest.json</code>. При регулярном усечении важного evidence увеличивается только соответствующий лимит и обсуждается расширение диска. Нельзя обнулять резерв 1 ГиБ ради запуска на заполненной файловой системе.

## 9. Preflight и запуск

~~~bash
python3.8 dist/kdiag.pyz --version
python3.8 dist/kdiag.pyz self-test
python3.8 dist/kdiag.pyz rules list
ansible-inventory -i inventory.ini --list
df -h /var/lib/kdiag
kubectl --kubeconfig /secure/kdiag.kubeconfig get --raw='/readyz?verbose'
~~~

Дополнительно проверяются SSH, sudo -n, путь remote Python и корректность времени.

Полный снимок:

~~~bash
python3.8 dist/kdiag.pyz snapshot \
  --inventory inventory.ini \
  --group k8s_nodes \
  --config config/snapshot.json \
  --kubeconfig /secure/kdiag.kubeconfig \
  --output-dir /var/lib/kdiag
~~~

По умолчанию в <code>stderr</code> выводится progress уровня <code>summary</code>: этапы, начало и завершение сбора каждого inventory-узла, Kubernetes API, Prometheus и построение отчёта. Уровень <code>detail</code> дополнительно перечисляет категории node evidence и результат каждого Kubernetes API source. <code>stdout</code> по-прежнему содержит только путь к collection, поэтому автоматический разбор не меняется:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --progress detail -o /var/lib/kdiag

python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --progress off -o /var/lib/kdiag
~~~

Если cgroup-проверки неприменимы к платформе или создают недостоверный шум, их можно отключить для конкретного запуска:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --skip-cgroup -o /var/lib/kdiag
~~~

При этом не читаются прямые <code>/sys/fs/cgroup</code> и <code>/proc/&lt;pid&gt;/cgroup</code> facts, подавляются cgroup events/correlations и правила <code>cgroup.*</code> и <code>security_agent.cgroup_denial</code>. Общие journals kubelet/runtime продолжают собираться, поэтому исходная строка журнала может содержать слово <code>cgroup</code>, но не создаёт cgroup finding и не попадает в подготовленные LLM events как cgroup-событие. Состояние переключателя сохраняется в <code>collection.json</code>, <code>facts.json</code>, <code>report.json</code> и <code>report.md</code>.

Разрешённые прикладные namespace задаются повторяющимся параметром:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json \
  --application-namespace app-a \
  --application-namespace app-b \
  -o /var/lib/kdiag
~~~

Сначала нужно выдать pods/log в этих namespace. Параметр не обходит RBAC.

Сбор только с узлов при недоступном API:

~~~bash
python3.8 dist/kdiag.pyz snapshot -i inventory.ini -g k8s_nodes \
  --config config/snapshot.json --skip-kubernetes -o /var/lib/kdiag
~~~

Host evidence сохранится, но структурные Kubernetes-проверки не выполнятся. Prometheus можно задать через <code>--prometheus-url http://host:9090</code>.

| Код | Значение | Действие |
|---:|---|---|
| 0 | Сбор завершён. | Прочитать отчёт и раздел evidence gaps. |
| 1 | Сохранён частичный снимок. | Сохранить его, изучить статусы источников и решить, нужен ли повтор. |
| 2 | Ошибка конфигурации/preflight. | Исправить локальную проблему; полноценный снимок не предполагается. |

Нельзя удалять частичный снимок, пока новый не охватывает то же окно инцидента.

## 10. Каталог результата

Каждый запуск создаёт <code>&lt;output&gt;/&lt;collection-id&gt;/</code>:

| Файл | Назначение |
|---|---|
| <code>collection.json</code> | ID, время, версия, статус и метаданные источников. |
| <code>node-&lt;inventory-host&gt;.json.gz</code> | Evidence и статусы команд одного узла. |
| <code>kubernetes.json.gz</code> | Ресурсы API, readyz и ограниченные Pod logs. |
| <code>prometheus.json.gz</code> | Необязательный ограниченный evidence Prometheus. |
| <code>normalized-events.json.gz</code> | Нормализованные записи, offline message insights, fingerprints и корреляции; конфиденциально. |
| <code>facts.json</code> | Выведенные структурированные факты. |
| <code>findings.json</code> | Машиночитаемые срабатывания правил. |
| <code>report.json</code> | Общий машиночитаемый отчёт. |
| <code>report.md</code> | Основной отчёт администратора. |
| <code>manifest.json</code> | Размеры и SHA-256 файлов. |

Inventory alias и имя Kubernetes Node могут отличаться. Однозначные hostname/FQDN и уникальные short-name совпадения канонизируются к имени Kubernetes Node для Node-scoped correlation; неоднозначные identity остаются видимым mismatch.

Полнота фиксируется для каждой команды узла, группы журналов Pod, источника Kubernetes и отдельной записи журналов Kubernetes. Успешный родительский набор не скрывает внутреннюю ошибку, превышение времени или усечение. В `facts.json`, `findings.json` и `report.json` сохраняются стабильные машинные статусы. В Markdown они переводятся на русский, одинаковые проблемы группируются по узлам, а полный список по каждой проверке не печатается. Отказ Events влияет только на проверки, которым нужны события, но не на проверку состояния Node при успешно собранных объектах Node.

Сводка Markdown объясняет, почему проверки не выполнены и сколько проверок зависит от каждого отсутствующего источника; полный технический список остаётся в `report.json`. При намеренно отключённом сборе Kubernetes зависимые проверки помечаются как неприменимые. Даже недоступный Kubernetes bundle читается для сохранения точных причин отказа отдельных источников.

Встроенный каталог по-прежнему классифицирует известные сообщения как штатные, требующие наблюдения, требующие внимания или относящиеся к безопасности. Штатные сообщения и сообщения для наблюдения остаются в конфиденциальном `normalized-events.json.gz`; в `report.md` и `report.json` выводятся только требующие внимания сообщения, для которых ещё нет отдельной детерминированной проверки. LLM, сеть и внешние API не используются.

Для Deckhouse authentication config на узле собираются только метаданные файла `/etc/kubernetes/deckhouse/extra-files/authentication-config.yaml`, но не содержимое. Запись журнала доказывает ошибку чтения только в момент своего timestamp. Отчёт отдельно проверяет текущее наличие файла на host, API readyz и готовность Pod kube-apiserver и явно предупреждает, что видимость внутри mount namespace контейнера напрямую не проверяется.

Журналы текущей загрузки запрашиваются от новых записей к старым. Если `collection.max_command_bytes` приводит к усечению, сохраняются ближайшие к инциденту новые записи. При таком предупреждении следует увеличить лимит либо уменьшить `collection.since_hours`.

Оставшийся раздел unknown fingerprints также является справочным. Он показывает сбалансированное по компонентам подмножество — не более пяти templates на компонент, ограничивает длинные строки и выводит placeholders вида `<n>` и `<ipv6>` в читаемом code formatting. Приблизительная частота показывается как гарантированный минимум и оценочная верхняя граница с алгоритмической погрешностью, а не как severity. Полный bounded-набор сохраняется в `normalized-events.json.gz`.

~~~bash
python3.8 dist/kdiag.pyz report /var/lib/kdiag/COLLECTION_ID
python3.8 dist/kdiag.pyz verify /var/lib/kdiag/COLLECTION_ID
~~~

## 11. Интерпретация, нормализация и корреляция

Сначала читаются статус сбора и evidence gaps, затем факты, корреляции и гипотезы:

- **fact** — прямое структурированное состояние или сильная детерминированная сигнатура;
- **correlation** — не менее двух различных симптомов в одном Node/Pod scope за 15 минут; причинность не доказана;
- **hypothesis** — evidence косвенный или платформа допускает корректное исключение; перед действием нужна проверка.

Отсутствие finding не доказывает отсутствие проблемы. Evidence мог оказаться за временным окном, быть усечён, запрещён RBAC, находиться на недоступном узле, иметь неизвестную сигнатуру или нестандартное расположение.

Нормализуются journald JSON, прямые CRI logs, Kubernetes Events, Node conditions, состояния Pod/контейнеров, выбранные Pod logs и systemd. Записи дедуплицируются, output справедливо ограничивается по source/scope/category, inferred timestamps исключаются из причинных correlations. Результат корреляции состоит из независимых Pod- или Node-scoped episodes с началом, концом, duration и episode ID. Усечение создаёт явные per-source counters и finding.

CoreDNS error records с query name, начинающимся с `smoke-mini-`, считаются шумом штатной Deckhouse smoke-проверки и исключаются из normalized events и findings. Confidential raw log bundle не перезаписывается.

## 12. Подробное описание проверок

В артефакт встроено 98 отчётных правил. Точный каталог конкретной сборки:

~~~bash
python3.8 dist/kdiag.pyz rules list
python3.8 dist/kdiag.pyz rules explain kubernetes.node_not_ready
python3.8 dist/kdiag.pyz rules list --json
~~~

### 12.1 Полнота сбора и инвентаризация

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>collector.node_gap</code> | fact | Запрошенный node bundle отсутствует, завершился ошибкой/таймаутом или неприемлем. | Восстановить SSH/sudo/Python/диск, предварительно сохранить частичный снимок. |
| <code>collector.evidence_gap</code> | fact | Обязательные журналы, Pod logs или Kubernetes-источники запрещены, не собраны, не поддержаны или усечены. Отсутствие опциональных Cilium CRD, CSIStorageCapacity или Prometheus само по себе исключено. | Изучить статусы и исправить только недостающее право, таймаут или лимит. |
| <code>collector.normalization_truncated</code> | fact | Лимиты нормализации исключили часть категоризированных записей. | Считать зависимые отрицательные результаты неполными и менять только нужный лимит/окно. |
| <code>collector.boot_changed</code> | fact | Boot ID узла изменился во время сбора. | Разделить timeline по перезагрузке; состояния до/после не были одновременными. |
| <code>inventory.node_set_mismatch</code> | fact | Inventory snapshots и Kubernetes Node objects расходятся. | Проверить aliases inventory, состав кластера и SSH-доступ. |
| <code>collector.etcd_evidence_gap</code> | fact | Включённый сбор etcd недоступен, частичен, не поддержан или ошибочен. | Проверить топологию, пути, инструменты и права; отсутствие данных не означает здоровье. |
| <code>inventory.mixed_kernel</code> | fact | На узлах обнаружено более одной версии ядра. | Сравнить модули и совместимость Cilium/runtime/KESL, историю rollout; неоднородность — риск, не автоматическая неисправность. |
| <code>inventory.unsupported_version_skew</code> | fact | Minor-версии kube-apiserver или kubelet выходят за поддерживаемый skew. | Планировать выравнивание по version-skew policy; не менять порядок upgrade импровизированно. |

### 12.2 ОС и службы узлов

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>node.kubelet_inactive</code> | fact | systemd-состояние kubelet не active/activating. | Проверить status/journal и предпосылки: cgroup, runtime, сертификаты, mounts. |
| <code>node.runtime_inactive</code> | fact | Ни один загруженный vanilla containerd, Deckhouse containerd или CRI-O unit не активен. Units с LoadState=not-found и неактивные альтернативы при работающем runtime игнорируются. | Проверить journal, socket и storage до перезапуска. |
| <code>node.low_root_disk</code> | fact | На корневой ФС менее 10% свободного места. | Найти рост images, CRI logs, journal и файлов; не удалять runtime data вслепую. |
| <code>node.low_inodes</code> | fact | На собранной ФС занято не менее 95% inode. | Найти каталоги с большим числом файлов и ошибки retention. |
| <code>time.not_synchronized</code> | fact | NTPSynchronized=no либо chrony сообщает отсутствие синхронизации. | Восстановить источник времени и оценить достоверность timestamps/сертификатов. |
| <code>certificate.expiring</code> | fact | Обнаруженный сертификат истёк или истекает в течение 30 дней. | Проверить часы, владельца сертификата и утверждённую ротацию. |
| <code>node.conntrack_full</code> | fact | В журнале есть точная сигнатура переполнения/отбрасывания conntrack. | Проверить текущее/максимальное число записей и источник трафика до tuning. |
| <code>node.oom_detected</code> | fact | В kernel, CRI или Pod log есть сигнатура OOM kill. | Установить процесс/cgroup и сопоставить limits и pressure. |
| <code>runtime.cri_not_ready</code> | fact | CRI сообщает RuntimeReady=False. | Проверить runtime service/socket, cgroups и runtime storage. |
| <code>runtime.cri_network_not_ready</code> | fact | CRI сообщает NetworkReady=False. | Проверить Cilium, CNI config и sandbox Events на узле. |
| <code>node.swap_active</code> | fact | Swap активен, а kubelet failSwapOn не отключён. | Сопоставить policy kubelet и фактический swap до изменения узла. |
| <code>node.low_runtime_disk</code> | fact | Отдельная backing filesystem для kubelet/runtime/log data заполнена не менее чем на 90%. Read-only container snapshot submounts, включая EROFS layers, игнорируются. | Найти потребителя на mount; не удалять runtime data вслепую. |
| <code>certificate.kubelet_rotation_broken</code> | fact | Rotation включена, но kubelet-client-current.pem или target некорректны. | Проверить symlink, target certificate и kubelet journal; не заменять сертификаты автоматически. |

### 12.3 Kernel-проверки на основе Node Problem Detector

Сигнатуры адаптированы из зафиксированной upstream-конфигурации Node Problem Detector. Они распознают сообщения, но не проверяют и не восстанавливают оборудование или ФС.

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>node.task_hung</code> | fact | Ядро сообщает о долго заблокированной/hung task. | Сохранить stack задачи и storage evidence до перезагрузки. |
| <code>node.unregister_netdevice</code> | fact | Ядро долго ждёт unregister сетевого устройства. | Сопоставить Cilium/veth lifecycle, интерфейсы, удаление Pod и версию ядра. |
| <code>node.kernel_oops</code> | fact | Сигнатура kernel oops/panic-класса. | Сохранить полный journal, сравнить ядра и модули узлов. |
| <code>node.filesystem_error</code> | fact | EXT4 error либо XFS forced-shutdown/error. | Снизить запись, проверить устройство/ФС, следовать процедуре конкретной ФС. |
| <code>node.filesystem_warning</code> | fact | Сигнатура EXT4 warning. | Изучить соседние сообщения и состояние storage. |
| <code>node.io_error</code> | fact | Сигнатура Buffer I/O error. | Определить device/path, сопоставить multipath/storage/filesystem evidence. |
| <code>node.hardware_error</code> | fact | Machine check, memory error, corrected/recoverable/fatal hardware message. | Сопоставить с оборудованием и выполнить утверждённую vendor-диагностику. |

### 12.4 Kubernetes Nodes, Pods, probes и workloads

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>kubernetes.node_not_ready</code> | fact | Node Ready=False или Unknown. | Прочитать reason/message, Lease, kubelet/runtime/CNI evidence и Events. |
| <code>kubernetes.node_pressure</code> | fact | MemoryPressure, DiskPressure или PIDPressure=True. | Исследовать именно указанный ресурс и eviction signals. |
| <code>kubernetes.network_unavailable</code> | fact | NetworkUnavailable=True. | Проверить Cilium, routes, devices, IPAM и журналы узла. |
| <code>kubernetes.pod_crash_loop</code> | fact | Состояние контейнера CrashLoopBackOff. | Проверить previous/current logs, exit status, probes и зависимости. |
| <code>kubernetes.image_pull_failure</code> | fact | Container state/Event сообщает image pull/back-off. | Проверить имя image, registry, механизм credentials, trust и диск. |
| <code>kubernetes.pod_oom_killed</code> | fact | Причина завершения контейнера OOMKilled. | Сравнить limit, потребление workload и pressure узла. |
| <code>kubernetes.failed_scheduling</code> | fact | Event сообщает FailedScheduling. | Следовать reason: ресурсы, taints, affinity, volumes и topology требуют разных действий. |
| <code>kubernetes.probe_failures</code> | fact | Readiness/liveness/startup probe неуспешна в Event/log; по возможности классифицируется timeout, refused, no route, address family, DNS, TLS или HTTP. | Проверить точный endpoint из правильного network context и конфигурацию probe. |
| <code>kubernetes.workload_degraded</code> | fact | Deployment/StatefulSet ready меньше desired; DaemonSet ready меньше desired scheduled; либо Job failed без success. | Изучить дочерние Pods/Events и kind-specific поля desired/ready. |
| <code>kubernetes.pod_waiting</code> | fact | Container имеет диагностический waiting reason вне image-pull/crash-loop правил. | Проверить точный reason, current/previous logs, mounts, config и runtime Events. |
| <code>kubernetes.init_container_failed</code> | fact | Init container ожидает с ошибкой или завершился ненулевым кодом. | Проверить current/previous logs init container и подготавливаемую зависимость. |
| <code>kubernetes.container_exit_nonzero</code> | fact | Container в Failed Pod завершился ненулевым кодом без OOMKilled/Completed. | Начать с exit reason/code и previous logs. |
| <code>kubernetes.pod_evicted</code> | fact | Phase/reason Pod сообщает eviction. | Сопоставить сообщение eviction с node pressure и QoS. |
| <code>kubernetes.pod_restart_storm</code> | fact | restartCount не менее пяти, последнее завершение — не старше часа. | Проверить последний previous log и первый отказ в окне инцидента. |
| <code>kubernetes.deployment_rollout_failed</code> | fact | Deployment сообщает ProgressDeadlineExceeded или ReplicaFailure. | Проверить ReplicaSets, недоступные Pods, admission, quota и scheduling. |
| <code>kubernetes.daemonset_misscheduled</code> | fact | DaemonSet numberMisscheduled больше нуля. | Сравнить selectors, taints/tolerations, affinity и node labels. |
| <code>kubernetes.statefulset_rollout_stalled</code> | fact | Ревизии StatefulSet различаются при неполном числе updated replicas. | Проверить первый не обновлённый ordinal и его storage/readiness constraints. |
| <code>kubernetes.job_failed</code> | fact | Job condition Failed=True. | Проверить failed Pods, backoffLimit, deadline и exit codes. |
| <code>pdb.insufficient_healthy</code> | fact | currentHealthy меньше desiredHealthy. | Восстановить workload до maintenance; PDB автоматически не ослаблять. |
| <code>pdb.disruption_blocked</code> | fact | disruptionsAllowed равно нулю. | Учитывать при maintenance; само по себе это не outage. |

### 12.5 IPv6, CNI и Cilium

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>network.ipv6_disabled</code> | fact с корреляционным контекстом | Эффективное net.ipv6.conf.*.disable_ipv6=1. Приоритет повышается при IPv6 Pod или address-family errors на том же узле. | Сопоставить задуманные address families Cilium и sysctl всех узлов; отменять через контролируемую процедуру ОС. |
| <code>network.cni_unavailable</code> | hypothesis | Сигнатуры CNI initialization, Pod sandbox networking, plugin или network unavailable. | Проверить Cilium/runtime на том же узле; сообщение может быть следствием. |
| <code>cilium.unhealthy</code> | fact | Cilium Pod/container отсутствует, не Running/Ready, находится в ожидании или повторно падает. | Разделить agent/operator scope; проверить logs, mounts/cgroups, Node и API. |
| <code>cilium.endpoint_unhealthy</code> | fact | CiliumEndpoint не ready или health не OK. | Сопоставить endpoint с Pod/узлом, проверить policy, identity, IP и agent. |
| <code>cilium.node_ipam_error</code> | fact | В status CiliumNode IPAM/operator есть явная ошибка. | Проверить pools, allocations, operator logs и конфликты адресов. |
| <code>cilium.policy_import_failed</code> | fact | В node status Cilium policy указано ok=false или error. | Найти policy revision/узел и проверить policy и agent state. |
| <code>cilium.kube_proxy_replacement_disabled</code> | fact | Pods kube-proxy отсутствуют, а Cilium config явно отключает replacement. | Проверить effective replacement на каждом agent и использовать утверждённый Cilium rollout. |
| <code>cilium.service_frontend_missing</code> | hypothesis | Read-only Cilium service map узла не содержит ожидаемый Service ClusterIP/port. | Повторить снимок, затем проверить service list, agent status и watch errors. |

Кластер может штатно работать без kube-proxy. Само его отсутствие никогда не создаёт finding; при включённом Cilium replacement это ожидаемое поддерживаемое состояние.

### 12.6 cgroup и security agents

Правила <code>cgroup.*</code> и <code>security_agent.cgroup_denial</code> отключаются параметром <code>collection.collect_cgroup=false</code> или CLI-флагом <code>--skip-cgroup</code>. Независимый ptrace alert остаётся включённым, поскольку не выводится из cgroup evidence. Для старых collection без сохранённого параметра сохраняется прежнее cgroup-поведение.

Точные read-only команды для ручной проверки одного узла и шаблон обезличенного результата приведены в [отдельной инструкции](cgroup-manual-checks-ru.md).

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>cgroup.controllers_missing</code> | hypothesis | В cgroup v2 контроллер cpu или io отсутствует в собранных данных hierarchy/delegation. | Проверить иерархию, kernel arguments, systemd delegation и security software. |
| <code>cgroup.driver_mismatch</code> | fact | Явные значения cgroup driver у kubelet и runtime различаются. | Выравнивать через утверждённую процедуру изменения платформы. |
| <code>cgroup.service_failure</code> | correlation | cgroup denial/failure и отказ kubelet/runtime на одном узле за 15 минут. | Упорядочить timeline, проверить kernel/security audit evidence. |
| <code>security_agent.cgroup_denial</code> | correlation | Обнаружен KESL и cgroup denial/failure в одном scope узла. | Зафиксировать точный build KESL, ядро и denied operation, проверить vendor policy/compatibility. Это не доказательство причины. |
| <code>security_agent.ptrace_alert</code> | fact | В kernel/security-agent journal есть ptrace attack message с двумя участвующими процессами. | Зафиксировать обе программы/PID и соседние audit/KESL events; не выводить вредоносность или влияние на Kubernetes только из этой строки. |

### 12.7 Service, EndpointSlice и DNS

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>kubernetes.service_no_endpoints</code> | fact | Selector-based не-ExternalName Service не имеет EndpointSlice. | Сравнить selector и Pod labels, проверить controller, admission и readiness. |
| <code>kubernetes.service_no_ready_endpoints</code> | fact | Slices существуют, но нет ready и non-terminating endpoint. | Проверить Pod readiness и endpoint conditions, включая намеренный publish-not-ready. |
| <code>kubernetes.service_port_unresolved</code> | hypothesis | Service port/target не сопоставляется с портами EndpointSlice либо данные отсутствуют/противоречивы. | Сравнить port, targetPort, именованные container ports и slice ports. |
| <code>dns.kube_dns_unavailable</code> | fact | kube-dns отсутствует/не имеет ready endpoints либо CoreDNS Pods отсутствуют, не Running или не полностью Ready. | Проверить CoreDNS, Service/Slices, Cilium и upstream resolvers. |
| <code>dns.cluster_dns_mismatch</code> | fact | Явный kubelet clusterDNS не пересекается с ClusterIP kube-dns. | Проверить все address families и источники kubelet config, затем контролируемый rollout. |
| <code>dns.nameserver_limit_exceeded</code> | fact | Resolver kubelet содержит более трёх nameserver. | Проверить kubelet resolvConf и при необходимости утверждённый local caching resolver. |
| <code>dns.coredns_errors</code> | fact | В CoreDNS logs есть SERVFAIL, forwarding loop или upstream failure. Отчёт группирует до 20 извлечённых query names по типу и частоте, сохраняя ссылки на исходные строки. | Проверить имена на опечатки и несуществующие zones, затем forward targets, loop plugin, upstream reachability и resolver узлов. |
| <code>dns.coredns_config_empty</code> | fact | ConfigMap coredns не содержит непустой Corefile. | Восстановить утверждённый Corefile через change control. |

### 12.8 Control plane и API

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>controlplane.api_readyz_failed</code> | fact | Полученный readyz verbose содержит failed subcheck либо ошибку endpoint. | Использовать имя subcheck для выбора evidence apiserver/зависимости. |
| <code>controlplane.authentication_config_read_error</code> | fact | kube-apiserver сообщает, что настроенный authentication file нельзя прочитать. | Проверить effective flag, mount/path, права и окно Deckhouse reconciliation; не создавать пустой файл вместо отсутствующего. |
| <code>controlplane.apiservice_unavailable</code> | fact | Aggregated APIService имеет Available=False или Unknown. | Изучить reason, backing Service/endpoints, TLS и extension server. |
| <code>controlplane.node_lease_stale</code> | correlation | Lease отсутствует либо старше нового peer Lease более чем на max(120 с, 3 x leaseDurationSeconds). | Сравнить kubelet, доступ к API и часы; учесть глобальную остановку API. |
| <code>controlplane.static_pod_unhealthy</code> | fact | Собранный mirror Pod etcd/apiserver/scheduler/controller-manager отсутствует или нездоров. | Сопоставить с control-plane node, проверить manifest, kubelet, container и зависимости. |

### 12.9 etcd

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>etcd.unhealthy</code> | fact | Endpoint health возвращает false, unhealthy, timeout или error. | Сохранить member output, проверить quorum, сеть, disk latency и сертификаты. |
| <code>etcd.alarm_active</code> | fact | alarm list возвращает хотя бы один active alarm. | Следовать процедуре alarm; до defrag/disarm проверить storage и backup. |
| <code>etcd.topology_inconsistent</code> | fact | Нет leader, несколько leader IDs или cluster IDs среди ожидаемых peers. | Проверить endpoints/timestamps и рассматривать как quorum/topology incident. |
| <code>etcd.raft_apply_lag</code> | hypothesis | Applied Raft index или revision endpoint существенно различаются. | Проверить disk fsync latency, network RTT, CPU pressure и member logs. |
| <code>etcd.database_near_quota</code> | fact | dbSize достиг не менее 80% configured backend quota. | Исследовать рост keyspace и следовать утверждённой compaction/defrag процедуре. |
| <code>etcd.fragmentation_high</code> | hypothesis | Достаточно крупный dbSize более чем вдвое превышает dbSizeInUse. | Оценить окно online defrag; kdiag не выполняет defrag. |
| <code>etcd.member_version_drift</code> | fact | Endpoint status сообщает разные версии members. | Проверить допустимость upgrade stage и завершить выравнивание. |

### 12.10 Storage и CSI

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>storage.pvc_pending</code> | fact | PVC находится в phase Pending. | Проверить Events, StorageClass, binding mode, capacity/topology и provisioner. |
| <code>storage.storage_class_missing</code> | fact | Явный PVC storageClassName отсутствует среди собранных StorageClass. | Проверить написание/lifecycle и provisioner до создания объектов. |
| <code>storage.pv_failed</code> | fact | PV находится в phase Failed. | Проверить status, claim relation и CSI/backend; сначала защитить данные. |
| <code>storage.volume_attachment_failed</code> | fact | VolumeAttachment имеет attached=false и attach/detach error. | Проверить driver, node, volume ID, topology, другие attachments и controller logs. |
| <code>storage.csi_driver_registration_gap</code> | hypothesis | Driver из PV/attachment отсутствует в CSIDriver либо driver ошибочного attachment не зарегистрирован на целевом CSINode. | Проверить CSI controller/node registration; отсутствие CSIDriver не всегда ошибка. |
| <code>storage.volume_operation_failure</code> | fact | Event сообщает FailedMount, FailedAttachVolume или связанную volume operation error. | Следовать reason события к evidence CSI/controller/node/storage. |

### 12.11 Межисточниковые корреляции

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>correlation.node_runtime_failure</code> | correlation | Node NotReady и отказ kubelet/runtime за 15 минут. | Упорядочить события и найти первый отказавший компонент. |
| <code>correlation.node_cni_failure</code> | correlation | Отказ Node/Pod sandbox и CNI/network за 15 минут. | Проверить локальное состояние Cilium/runtime около первого события. |
| <code>correlation.memory_oom_failure</code> | correlation | MemoryPressure и OOM evidence за 15 минут. | Разделить глобальное исчерпание узла и workload cgroup. |
| <code>correlation.certificate_api_failure</code> | correlation | TLS/certificate error совпадает с API или time error за 15 минут. | Проверить часы и certificate chain/expiry до ротации. |
| <code>correlation.conntrack_network_failure</code> | correlation | Переполнение conntrack совпадает с network/probe failure за 15 минут. | Проверить occupancy/drops и источник трафика до tuning. |
| <code>correlation.probe_network_failure</code> | correlation | Probe failure и network/DNS error совпадают в одном scope за 15 минут. | Повторить из правильного network context и определить первое событие. |
| <code>correlation.storage_failure</code> | correlation | DiskPressure совпадает с filesystem/full/read-only evidence на одном узле. | Защитить данные, определить mount/device и упорядочить timeline. |

### 12.12 Prometheus

| Правило | Тип | Что проверяется | Безопасное первое действие |
|---|---|---|---|
| <code>prometheus.alert_firing</code> | fact | Необязательный Prometheus API вернул firing alerts. | Следовать конкретному alert и сохранить labels/annotations вместе с cluster evidence. |
| <code>prometheus.config_reload_failed</code> | fact | Runtime information сообщает reloadConfigSuccess=false. | Проверить validation конфигурации Prometheus и reload logs. |
| <code>prometheus.corruption_detected</code> | fact | Runtime information сообщает ненулевой corruption counter. | Сохранить storage/log evidence и следовать процедуре восстановления Prometheus. |

## 13. Устранение проблем самого сборщика

- **Не работает SSH:** проверить имя после разбора inventory, OpenSSH config, host key, user/port, sudo -n и remote Python. Успешный Ansible playbook недостаточен: после разбора inventory kdiag вызывает OpenSSH.
- **Node utility имеет статус unsupported:** проверить имя команды в coverage. Deckhouse tools ищутся в <code>/opt/deckhouse/bin</code>; отсутствие executable <code>nft</code> или <code>conntrack</code> означает отсутствие userspace client, а не доказанное отсутствие подсистемы ядра.
- **Kubernetes отвечает Forbidden:** выполнить auth can-i с тем же kubeconfig/context и добавить только недостающее read-право. Отсутствующий Cilium CRD или CSIStorageCapacity может быть нормой; RBAC denial — другая ситуация.
- **Нет readyz:** отличить недоступность API/TLS/auth от отсутствия права на non-resource URL. Отсутствие ответа не равно failed внутреннего subcheck.
- **Нет etcd evidence:** проверить опцию, stacked topology, стандартные пути, etcdctl/crictl, container state и sudo. Нельзя копировать закрытый ключ только ради устранения finding.
- **Данные усечены:** сначала изучить counters/status; увеличить наиболее узкий лимит. Уменьшать look-back или scope namespace можно только при сохранении окна инцидента.
- **Нужно пересоздать отчёт:** применить команду report к каталогу и затем verify. Если важна доказательная целостность, сохранить оригинал.

## 14. Рекомендуемый порядок при инциденте

1. Зафиксировать начало инцидента и по возможности не менять узлы до первого снимка.
2. Выполнить preflight из-под рабочей учётной записи.
3. Запустить полный снимок; при мёртвом API получить node-only evidence, не ожидая бесконечно.
4. Сохранить каталог и exit code.
5. Выполнить verify и приложить report, collection metadata и manifest к инциденту.
6. Изучить evidence gaps до интерпретации отсутствующих findings.
7. Сначала разбирать facts, затем correlations, затем hypotheses.
8. Проверить исходный evidence и актуальное состояние.
9. Исправлять через действующие процедуры ОС/Kubernetes/vendor по одному контролируемому изменению.
10. Получить второй снимок и сравнить полноту и findings.

Backup не нужен для самого сбора. Он важен перед рискованным вмешательством в etcd, storage, сертификаты или узлы: необходимо подтвердить восстанавливаемый backup и понятную процедуру restore.

## 15. Необязательный LLM package и ручная работа с внешней LLM

LLM-конвейер разделён на явные стадии. «Минимизация» означает выбор ограниченного диагностического evidence без raw bundles и полных журналов. «Псевдонимизация» дополнительно заменяет внутренние идентификаторы. Команды имеют непересекающуюся ответственность:

| Команда | Создаёт incident package | Псевдонимизирует | Вызывает LLM |
|---|---:|---:|---:|
| `llm prepare --profile local` | да | нет | нет |
| `llm prepare --profile external` | да | да | нет |
| `llm validate-export` | нет | нет | нет |
| `llm analyze-local` | нет | нет | только локальный service |
| `llm import-response` | нет | восстанавливает известные внешние токены | нет |

Исходный collection остаётся конфиденциальным и не передаётся inference service. Оба профиля исключают raw bundles и полные logs, но включают выбранные bounded evidence fragments с `status`, `value`, `excerpt`, `timestamp` для своих `EVIDENCE_NNN`. Усечение fragments/events/fingerprints отражается явно.

### 15.1 Подготовка локального package

Создайте минимизированные данные с сохранением реальных эксплуатационных идентификаторов внутри доверенного контура:

~~~bash
python3.8 dist/kdiag.pyz llm prepare /var/lib/kdiag/<collection-id> \
  --output-dir /secure/llm-local \
  --profile local \
  --mode deep-analysis \
  --question "Объясни вероятные причины и пробелы в evidence"
~~~

Результат:

~~~text
/secure/llm-local/
  prepared/
    incident.local.json
    prompt.local.txt
    preview.md
    redaction-report.json
    manifest.json
  private/
    token-map.json
~~~

Локальный каталог `prepared/` не разрешён для внешней передачи. `incident.local.json` — минимизированный incident package, а `prompt.local.txt` — отдельный набор инструкций модели. `analyze-local` продолжает принимать legacy-каталог local `export/`, созданный kdiag 0.5.0, проверяя содержимое и manifest, а не имя каталога.

### 15.2 Анализ уже подготовленного локального package

`analyze-local` не читает collection и не создаёт второй incident package. Команда проверяет manifest от `prepare --profile local`, читает `incident.local.json` и `prompt.local.txt` в клиентский процесс и передаёт локальному OpenAI-compatible endpoint `/v1/chat/completions` их содержимое, а не пути к файлам:

~~~bash
python3.8 dist/kdiag.pyz llm analyze-local /secure/llm-local/prepared \
  --model local-model-name \
  --endpoint http://127.0.0.1:8080/v1/chat/completions \
  --timeout-seconds 180 \
  --max-output-tokens 2048 \
  --output-dir /secure/llm-local-response
~~~

Разрешены только literal loopback HTTP-адреса `127.0.0.1` и `::1`. Credentials, query string, произвольный endpoint path, удалённый host и HTTPS запрещены. Inference service должен работать под непривилегированной identity без kubeconfig, SSH keys, доступа к collection directory, shell/tools и Internet. Имя модели обязательно, поскольку конкретная модель/runtime зависят от deployment и не входят в `kdiag.pyz`.

Hardened offline-пример llama.cpp с systemd unit и environment template описан в [`deploy/systemd/README-ru.md`](../deploy/systemd/README-ru.md). Его pilot defaults необходимо настроить и измерить на точной сборке РЕД ОС/GPU.

Каталог анализа содержит:

~~~text
/secure/llm-local-response/
  response.raw.txt
  response.validated.json      # только при успешной проверке контракта
  response.md
  analysis-report.json
  manifest.json
~~~

Ответ всегда считается недоверенным. `kdiag` проверяет JSON-контракт, указанные `EVIDENCE_NNN` и отклоняет ответы с изменяющими командами. Код `0` означает проверенный ответ, `1` — service ответил, но контракт отклонён, `2` — ошибка package, endpoint, service или I/O. Предложенные команды никогда не исполняются.

### 15.3 Подготовка ручного внешнего package

Для ручной работы с Google «Поиск ИИ» подготовьте внешний профиль:

~~~bash
python3.8 dist/kdiag.pyz llm prepare /var/lib/kdiag/<collection-id> \
  --output-dir /secure/llm-external \
  --profile external \
  --mode fast-triage \
  --question "Каковы наиболее вероятные причины?"
python3.8 dist/kdiag.pyz llm validate-export /secure/llm-external/export
~~~

Внешний профиль заменяет node/host, namespace, Pod, Service, user/account/ServiceAccount, network topology, path, UID и endpoint values во findings и evidence fragments. Экспорт запрещается, если outbound DLP обнаруживает остаточный IP/CIDR, MAC, DNS, URL, e-mail, UID, абсолютный host path, credential pattern, private key, JWT или canary. Названия и версии Kubernetes, Cilium, container runtime, etcd, CoreDNS, kernel и RED OS сохраняются. Просмотрите `preview.md`, `incident.external.json`, `prompt.external.txt` и `redaction-report.json`, после чего вручную передайте только содержимое `export/`. Соседний `private/token-map.json` передавать нельзя.

### 15.4 Импорт сохранённого вручную внешнего ответа

Сохраните внешний ответ в файл и восстановите только известные placeholders:

~~~bash
python3.8 dist/kdiag.pyz llm import-response /secure/google-response.txt \
  --token-map /secure/llm-external/private/token-map.json \
  --output-dir /secure/llm-response
~~~

Ответ считается недоверенным. Команда сохраняет его без изменений, создаёт `response.restored.txt` и отмечает неизвестные placeholders. Перед любыми действиями проверяйте claims по указанным `EVIDENCE_NNN` и исходному collection.

## 16. Ограничения

- Rule pack распознаёт известные структуры и сигнатуры, но не является универсальным root-cause engine.
- `kdiag` содержит loopback-клиент, но не поставляет, не устанавливает, не настраивает и не контролирует локальную модель/runtime.
- Рекомендации не исполняются автоматически.
- Прикладные logs требуют явного allowlist namespace и RBAC.
- Сбор на узле предполагает стандартные journald/CRI layouts.
- Для etcd поддержан стандартный локальный stacked kubeadm-вариант.
- Approximate heavy hitters могут не сохранить редкое неизвестное сообщение.
- Окно 15 минут может пропустить медленный инцидент или связать совпавшие симптомы.
- Автоматические и синтетические тесты не заменяют canary на точных сборках RED OS 7.x, ядра, runtime, Cilium, KESL и Kubernetes.
- Baseline и continuous watch в эту версию не входят.

## 17. Происхождение и сопровождение правил

Интернет во время работы не нужен. В metadata правил сохранены ссылки для инженерной трассировки. Kernel-сигнатуры адаптированы из зафиксированной upstream-конфигурации Node Problem Detector; атрибуция находится в <code>THIRD_PARTY_NOTICES.md</code>.

При обновлении необходимо зафиксировать upstream-версию и лицензию, определить детерминированный required evidence, добавить позитивные/негативные/missing-source/truncation/correlation тесты, классифицировать fact/correlation/hypothesis, выполнить все тесты и self-test, записать новую SHA-256 и перенести в контур именно проверенный артефакт.
