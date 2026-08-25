# Автономный rule pack kdiag

Rule pack `2026.08.4` содержит 93 проверки и работает без сети, LLM и внешней базы знаний. После сборки все классификаторы, карточки правил, ссылки на первичные источники и synthetic self-test входят в `kdiag.pyz`.

## Модель достоверности

- `fact` — прямое структурированное состояние или однозначное измерение: `Ready=False`, `OOMKilled`, inactive service, срок сертификата.
- `correlation` — независимые события совпали на одном Node в 15-минутном окне. Это усиливает гипотезу, но не доказывает исходную первопричину.
- `hypothesis` — сигнатура журнала или неполная комбинация evidence. Требуются указанные в рекомендации локальные проверки.

Отсутствие finding не означает отсутствие проблемы. Недоступный источник отмечается отдельно; правило не должно превращать missing evidence в `not_matched`.

## Pipeline

1. JSON-строки journald, node CRI logs, Kubernetes Events, Node conditions, Pod/container states и разрешённые Pod logs приводятся к единому event envelope.
2. Текст классифицируется по устойчивым семантическим признакам: component/reason, errno, cgroup path, Kubernetes reason и network error class. Точные динамические значения не входят в fingerprint.
3. На диск попадают категоризированные события и до 100 приблизительных heavy hitters неизвестных fingerprints. Для каждого сохранены оценка частоты и её максимальная ошибка; полные исходные журналы остаются в исходных gzip bundles.
4. Корреляции строятся только внутри одного Node либо одного Pod scope и в окне 900 секунд.
5. Rule evaluator формирует findings с `classification`, `causal_confidence`, evidence, alternatives, безопасной рекомендацией и первичными источниками.

Фиксированные защитные пределы нормализатора: не более 50 000 категоризированных событий и 100 неизвестных fingerprints в памяти и на диске на один snapshot. Превышение лимита events отображается как `stats.truncated=true` и `dropped_records`; замещения unknown heavy hitters — как `unknown_fingerprint_replacements`.

## Покрытие

- collector gaps, reboot boundary и mixed kernel inventory;
- root disk и inode exhaustion;
- kubelet/container runtime state для vanilla containerd, CRI-O и Deckhouse containerd с исключением отсутствующих/неиспользуемых альтернативных units;
- Node Ready/Unknown, Memory/Disk/PID pressure и NetworkUnavailable;
- CrashLoopBackOff, image pull, OOMKilled, FailedScheduling, eviction, init/container failures, restart storms и kind-specific rollout failures;
- PDB health и возможность voluntary disruption;
- readiness/liveness/startup probe taxonomy;
- IPv6, CNI и Cilium Pod health;
- cgroup v2 controllers, kubelet/runtime driver mismatch и cgroup access denial;
- осторожная корреляция KESL с cgroup denial без утверждения причинности;
- kernel OOM и conntrack table full;
- адаптированные Node Problem Detector `v0.8.25` signatures: KernelOops, TaskHung, netdevice, EXT4/XFS, Buffer I/O и hardware errors;
- Service → EndpointSlice → ready endpoint/port, kube-dns Service/CoreDNS, Corefile plugins/forward targets и kubelet resolver/clusterDNS;
- Cilium kube-proxy replacement и сравнение Service ClusterIP с read-only service maps; отсутствие kube-proxy само по себе штатно;
- API server readyz, aggregated APIService, Node Lease и control-plane Pod health;
- stacked-etcd endpoint health/status, active alarms, Raft/revision lag, backend quota, fragmentation и member version drift через allowlisted read-only commands;
- PVC/PV/StorageClass, VolumeAttachment, CSIDriver/CSINode и CiliumEndpoint/CiliumNode/policy status;
- CRI RuntimeReady/NetworkReady, активный swap, отдельные runtime filesystems и Kubernetes version skew;
- time synchronization, X.509 `notAfter` и целостность symlink ротации kubelet client certificate;
- firing alerts, failed config reload и corruption counter из необязательного Prometheus API;
- runtime, CNI, memory/OOM, certificate/API и conntrack/network correlations.

Пороговые значения, не являющиеся протокольными состояниями: root filesystem — менее 10% свободных блоков, inode — менее 5%, certificate warning — 30 суток. PSI собирается как evidence, но отдельный универсальный PSI threshold намеренно не задан: Linux определяет смысл метрик, а допустимый уровень зависит от нагрузки и должен калиброваться внутри контура.

## Первичные интернет-источники

Источники использовались при подготовке, но runtime-доступ к ним не требуется:

- Kubernetes 1.24 release/tag: <https://kubernetes.io/releases/1.24/>;
- Kubernetes 1.31 release/tag: <https://kubernetes.io/releases/1.31/>;
- Deckhouse rename of its containerd systemd unit: <https://github.com/deckhouse/deckhouse/blob/main/CHANGELOG/CHANGELOG-v1.52.md>;
- Node conditions: <https://kubernetes.io/docs/reference/node/node-status/>;
- Pod diagnostics и FailedScheduling: <https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/>;
- probes: <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/>;
- node pressure/eviction: <https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/>;
- container runtime/cgroup drivers: <https://kubernetes.io/docs/setup/production-environment/container-runtimes/>;
- Kubernetes logging/CRI rotation: <https://kubernetes.io/docs/concepts/cluster-administration/logging/>;
- Linux cgroup v2: <https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html>;
- Linux PSI: <https://www.kernel.org/doc/html/latest/accounting/psi.html>;
- systemd journal: <https://www.freedesktop.org/software/systemd/man/journalctl.html>;
- Cilium troubleshooting: <https://docs.cilium.io/en/stable/operations/troubleshooting/>;
- Cilium kube-proxy-free mode: <https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/>;
- Cilium service list: <https://docs.cilium.io/en/latest/cmdref/cilium-dbg_service_list/>;
- kubeadm certificate inspection: <https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-certs/>;
- KESL compatibility reference: <https://support.kaspersky.com/KES4Linux/12.1.0/en-US/KES4Linux-12.1.0-en-US.pdf>.
- pinned Node Problem Detector kernel rules: <https://raw.githubusercontent.com/kubernetes/node-problem-detector/v0.8.25/config/kernel-monitor.json>;
- Service troubleshooting: <https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/>;
- DNS troubleshooting: <https://kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/>;
- PodDisruptionBudget: <https://kubernetes.io/docs/tasks/run-application/configure-pdb/>;
- Kubernetes version skew: <https://kubernetes.io/releases/version-skew-policy/>;
- CRI troubleshooting: <https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/>;
- Prometheus HTTP API: <https://prometheus.io/docs/prometheus/latest/querying/api/>;
- API health endpoints: <https://kubernetes.io/docs/reference/using-api/health-checks/>;
- Kubernetes Lease: <https://kubernetes.io/docs/concepts/architecture/leases/>;
- etcd cluster status и maintenance: <https://etcd.io/docs/v3.5/tutorials/how-to-check-cluster-status/>, <https://etcd.io/docs/v3.5/op-guide/maintenance/>.

Текущая Cilium documentation используется для общей семантики status/health. Имена CLI и сообщения должны проверяться по фактически обнаруженной версии Cilium; поэтому одиночная строка Cilium имеет уровень hypothesis, а структурированное состояние Pod — fact.

Provenance и условия использования адаптированных upstream signatures зафиксированы в [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). Runtime не скачивает и не исполняет Node Problem Detector.

## Synthetic data и автономная проверка

Исходные fixtures разработки:

- `tests/fixtures/journal-synthetic.jsonl`;
- `tests/fixtures/kubernetes-synthetic.json`.
- `tests/fixtures/journal-npd-synthetic.jsonl`;
- `tests/fixtures/kubernetes-extended-synthetic.json`.

Внутри изолированного контура исходные tests не нужны:

```bash
python3.8 kdiag.pyz self-test
python3.8 kdiag.pyz rules list
python3.8 kdiag.pyz rules explain cgroup.service_failure
```

`self-test` использует встроенный synthetic incident и проверяет классификацию, каталог, временную корреляцию и ожидаемые findings. Команда не подключается к Node, Kubernetes API или интернету.

## Ограничения

- Rule pack не определяет любую неизвестную первопричину.
- Он не выполняет remediation и не формирует команды, изменяющие cluster state.
- Public issue trackers и форумы не используются как доказательство причины.
- Локальные патчи РЕД ОС, точный KESL build и версия Cilium могут менять тексты сообщений.
- Unknown fingerprints остаются внутри incident bundle и предназначены для локального анализа администратора.
- Rule sources объясняют семантику проверки, но не являются доказательством, что конкретный vendor component вызвал конкретный инцидент.
- Проверки Service/DNS являются пассивными: программа не создаёт test Pod и не выполняет `pods/exec`.
- Полный etcd check поддерживает stacked kubeadm layout со стандартными healthcheck certificate paths; external/custom etcd требует отдельной конфигурации в будущей версии.
- Cilium CRD имеют `required=false`, потому что их набор и status schema зависят от версии; отсутствие CRD отображается в coverage, но не считается неисправностью кластера.
