# Handoff

## Goal

Проверить `kdiag 0.9.2` на реальном Deckhouse-кластере и затем продолжить развитие корреляции первопричин и режимов обычной проверки/инцидента.

## Changed files

- `src/kdiag/node.py` -> убран прямой `crio --version`; PID из `crictl inspect` читается из объекта или JSON-строки; `etcdctl`, `cilium-dbg` и `cilium` имеют ограниченный fallback через стандартные пути rootfs точного процесса `etcd`/`cilium-agent`; поддержаны оба известных пути Deckhouse authentication config.
- `src/kdiag/kubernetes.py` -> ConfigMap `kube-system/d8-kube-dns` стал первым Deckhouse DNS-кандидатом; старые Deckhouse и vanilla варианты сохранены.
- `src/kdiag/message_insights.py` -> распознаны штатные success/info-шаблоны со скриншота; они скрыты без связанной проблемы и повышаются до проверки только при гарантированном минимуме 1000 записей либо минимуме 100 записей и 100 записей/ч.
- `src/kdiag/rules.py`, `src/kdiag/rule_catalog.py` -> разрешившаяся authentication-config race скрывается при существующем читаемом файле, успешном readyz и готовых kube-apiserver Pod; rule pack `2026.08.13`.
- `src/kdiag/__init__.py`, `dist/kdiag.pyz` -> версия `0.9.2`.
- `tests/test_node_config.py`, `tests/test_node_etcd.py`, `tests/test_kubernetes.py`, `tests/test_message_insights.py`, `tests/test_rules.py` -> regression-тесты новых fallback, DKP DNS, CRI-O probe, штатных сообщений и authentication config.
- `README-ru.md`, `README.md`, `docs/UserGuide-ru.md`, `docs/UserGuide.md`, `docs/a.md`, `docs/autonomous-rule-pack.md`, `docs/k8s-diagnostic-system-implementation-plan-no-llm.md`, `docs/todo.md`, `CHANGELOG-ru.md`, `CHANGELOG.md` -> контракт и выпуск `0.9.2`.

## Current failure

Локальных ошибок нет. Реальный Deckhouse canary `0.9.2` ещё не выполнен; `0.9.1` на целевом кластере не находил `etcdctl`/`cilium-dbg` и создавал шум по DNS/authentication/success-сообщениям.

## Current hypothesis

Причиной пропуска бинарников были запрещённый container exec, единственная ожидаемая форма PID в CRI inspect и отсутствие process-root fallback для Cilium. Шум отчёта возникал из-за неверного первого namespace ConfigMap, unconditional finding для уже разрешившейся authentication race и неполного каталога штатных шаблонов.

## Test results

- `env PYTHONPATH=src python3 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3 -m unittest discover -s tests -q` -> 129 tests passed.
- `python3 scripts/build.py` -> passed.
- `python3 dist/kdiag.pyz --version` -> `0.9.2`.
- `python3 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.13`; 98 rules.
- `sha256sum dist/kdiag.pyz` -> `69cbafd68d818c96215d6d21cdd9fb216e3275956fd8c1d64dc74d6b843b539c`.
- `git status --short` -> unavailable: рабочий `.git` не содержит метаданных репозитория (`fatal: not a git repository`).

## Next step

Запустить `python3 dist/kdiag.pyz snapshot -i inventory.ini --config config/snapshot.json -o kdiag-data-0.9.2`, затем проверить transport Cilium/etcd и отсутствие указанных ложных сообщений в `report.md`.
