# Handoff

## Goal

Проверить `kdiag 0.11.2` на реальном Deckhouse/Cilium 1.17 snapshot и затем выполнить baseline create/approve/compare на целевых vanilla и Deckhouse-кластерах.

## Changed files

- `src/kdiag/node.py` -> разбор Cilium API Service через `status.realized`, проверка схемы и fail-closed для partial/truncated данных.
- `src/kdiag/rules.py` -> защита старых некорректных проекций и компактное описание Cilium service-map mismatch.
- `src/kdiag/normalize.py`, `src/kdiag/message_insights.py`, `src/kdiag/report.py` -> классификация штатных Deckhouse-сообщений, actionable Go stack trace, таблица проанализированных routine/observe сообщений и до пяти unknown fingerprints для ручной классификации.
- `tests/test_node_config.py`, `tests/test_rules.py`, `tests/test_message_insights.py`, `tests/test_report.py` -> regression-тесты проекции, fail-closed, ограниченного вывода и классификации сообщений.
- `src/kdiag/__init__.py`, `dist/kdiag.pyz` -> версия `0.11.2`.
- `README-ru.md`, `README.md`, `docs/UserGuide-ru.md`, `docs/UserGuide.md`, `docs/k8s-diagnostic-system-implementation-plan-no-llm.md`, `docs/todo.md`, `CHANGELOG-ru.md`, `CHANGELOG.md` -> поведение и выпуск 0.11.2.

## Current failure

Локальных ошибок нет. Реальный canary с Cilium 1.17 не выполнен; git metadata недоступна (`fatal: not a git repository`).

## Current hypothesis

Предыдущее ложное срабатывание возникало потому, что реальный Cilium 1.17 frontend находится в `status.realized.frontend-address`, а старая проекция искала его на верхнем уровне и создавала пустой frontend для каждой записи.

## Test results

- `env PYTHONPATH=src python3 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3 -m unittest discover -s tests -q` -> 159 passed.
- `python3 scripts/build.py` -> passed.
- `python3 dist/kdiag.pyz --help` -> passed.
- `python3 dist/kdiag.pyz --version` -> `0.11.2`.
- `python3 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.14`.
- `python3 -m zipfile -t dist/kdiag.pyz` -> passed.
- `sha256sum dist/kdiag.pyz` -> `7b640785f77aab5db7e7206c4a3515768b26490de9629f482790942eb2aba89f`.

## Next step

Запустить `python3 dist/kdiag.pyz snapshot -i inventory.ini --config config/snapshot.json -o /var/lib/kdiag` на целевом Deckhouse/Cilium 1.17-кластере и проверить отсутствие ложного `cilium.service_frontend_missing`.
