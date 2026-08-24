# Журнал изменений

В этом файле документируются все существенные изменения `kdiag`.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), проект использует [семантическое версионирование](https://semver.org/lang/ru/spec/v2.0.0.html).

## [Не выпущено]

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
