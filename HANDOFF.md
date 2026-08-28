# Handoff

## Goal

Проверить `kdiag 0.11.0` baseline create/approve/compare на реальных vanilla и Deckhouse-кластерах.

## Changed files

- `src/kdiag/baseline.py` -> стабильный source-aware профиль, candidate/approval, два SHA-256, blockers/override, diff JSON и русский Markdown.
- `src/kdiag/cli.py`, `src/kdiag/orchestrator.py` -> команды `baseline create|approve`, `compare` и `snapshot --baseline` с включением результатов в manifest.
- `src/kdiag/__init__.py`, `dist/kdiag.pyz` -> версия `0.11.0`.
- `tests/test_baseline.py` -> candidate, approval/hashes/tamper, critical/gaps, diff classes, missing source, volatile fields и CLI.
- `README-ru.md`, `README.md`, `docs/UserGuide-ru.md`, `docs/UserGuide.md`, `docs/k8s-diagnostic-system-implementation-plan-no-llm.md`, `docs/todo.md`, `CHANGELOG-ru.md`, `CHANGELOG.md` -> контракт и выпуск 0.11.0.

## Current failure

Локальных ошибок нет. Реальный canary baseline на целевых vanilla/Deckhouse-кластерах не выполнен; git metadata недоступна (`fatal: not a git repository`).

## Current hypothesis

Source-aware diff исключает ложные удаления при missing source, а стабильная проекция подавляет UID/IP/PID/timestamps/Job/generated suffix; реальные коллекции нужны для проверки component identity во время rollout.

## Test results

- `env PYTHONPATH=src python3 -m compileall -q src tests scripts` -> passed.
- `env PYTHONPATH=src python3 -m unittest discover -s tests -q` -> 153 passed.
- `python3 scripts/build.py` -> passed.
- `python3 dist/kdiag.pyz --help` и help новых команд -> passed.
- `python3 dist/kdiag.pyz --version` -> `0.11.0`.
- `python3 dist/kdiag.pyz self-test` -> passed; rule pack `2026.08.14`.
- `python3 -m zipfile -t dist/kdiag.pyz` -> passed.
- `sha256sum dist/kdiag.pyz` -> `11af7d554a05d8815be28e98b0ecbf16a0a1f169149ad2cdf377a18573c42cd7`.

## Next step

Запустить `python3 dist/kdiag.pyz baseline create /var/lib/kdiag/COLLECTION_ID --name production --output /secure/baseline-candidate.json` на проверенной реальной collection.
