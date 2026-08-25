# Plan

Добавить к `kdiag` необязательный LLM-контур, который строит из уже собранного snapshot минимизированный incident package и версионированный prompt, передаёт их локальной модели либо готовит безопасный ручной экспорт для Google «Поиск ИИ». Детерминированные rules и исходные bundles остаются источником evidence; LLM формирует только проверяемые гипотезы и не получает средств воздействия на кластер.

## Scope

- In: построение incident package тем же `kdiag`, локальный HTTP inference без tools, два режима срочности, ручной внешний workflow, минимизация, защита сетевой топологии, псевдонимизация, восстановление известных псевдонимов в ответе, аудит и regression tests.

- Out: передача raw snapshot наружу, автоматизация браузера или прямое соединение с `google.com`, fine-tuning на первом этапе, выполнение команд от LLM, cluster/SSH credentials у inference service и зависимость основного отчёта от доступности модели.

## Action items

[ ] Зафиксировать архитектурную границу: `kdiag` читает collection, формирует package/prompt, валидирует и отображает ответ; отдельный `kdiag-llm.service` принимает только подготовленный JSON по loopback или Unix socket. Inference service запускается непривилегированным пользователем, не имеет kubeconfig, SSH keys, доступа к collection directory, shell/tools или Internet.

[ ] Добавить в CLI команды `llm prepare COLLECTION --profile local|external`, `llm validate-export`, `llm analyze-local`, `llm import-response` и `llm render-response`. Реализацию разделить на `src/kdiag/llm_package.py`, `llm_prompt.py`, `llm_redact.py`, `llm_client.py` и `llm_response.py`; GPU/runtime dependencies не включать в stdlib-only `kdiag.pyz`.

[x] Определить версионированную JSON-схему `llm-incident.json`: вопрос оператора, collection/rule-pack versions, coverage и evidence gaps, findings, факты, корреляции, неизвестные fingerprints, контрдоказательства и небольшие excerpts. Каждый элемент должен иметь нейтральный evidence ID, который не кодирует hostname, namespace, UID или иные исходные значения.

[ ] Реализовать relevance-based минимизацию по allowlist и byte/token budget. Сохранять evidence, поддерживающее и опровергающее findings, сообщения неизвестного класса и контекст вокруг начала сбоя; не считать данные несущественными только потому, что они не совпали с существующим правилом. Raw journals, полные Pod logs, command stdout и Kubernetes bundles в package не включать.

[x] Подготовить версионированные prompt templates для `fast-triage` и `deep-analysis`. Быстрый режим должен вернуть до пяти ранжированных гипотез, evidence IDs, противоречия, недостающие read-only checks и `abstain` при недостатке данных; углублённый режим дополнительно анализирует неизвестные fingerprints. Evidence явно размечать как недоверенные данные, инструкции из логов запрещать выполнять.

[x] Задать контракт ответа модели: `claims`, `supporting_evidence_ids`, `contradicting_evidence_ids`, `missing_check_ids`, `alternatives`, `operator_questions`, `version_scope` и `abstain_reason`. Проверять существование всех IDs и отклонять свободные команды изменения кластера; confidence модели не интерпретировать как измеренную вероятность.

[ ] Реализовать локальный профиль без псевдонимизации прямых идентификаторов, но с теми же ограничениями объёма и sensitivity. Package передаётся сервису из памяти или по HTTP, а не через выдачу сервису пути к raw collection; prompt/response content не записывать в service logs. (Подготовка package и loopback HTTP client готовы; deployment/hardening inference service и запрет content logging ожидают выбора модели/runtime.)

[ ] Реализовать внешний профиль с политикой fail closed. Разрешить передавать названия используемых Kubernetes-компонентов и диагностически важные версии, например Kubernetes, Cilium, container runtime, etcd, CoreDNS, kernel и RED OS; разрешить семантическую роль затронутого узла (`control-plane`/`worker`) и тип ресурса без реального имени. (Fail-closed export и allowlist компонентов готовы; семантические роли узлов ещё не добавлены.)

[ ] Запретить во внешнем package IP/MAC/CIDR/subnet, routes, DNS/hostname, username/account/ServiceAccount, namespace, Pod/Service/Node names, UID, registry/repository URL, storage ID, certificate subject/SAN, proxy/no_proxy, host paths, connection strings и полные списки endpoints. Точные нестандартные ports, полную связь Node→Pod→Service и точные размеры топологии удалять либо обобщать, если они не обязательны для конкретного вопроса.

[ ] Учитывать, что стабильные псевдонимы сами раскрывают граф. Передавать только минимальный причинный фрагмент через incident-local токены `NODE_A`, `RESOURCE_B`, `ADDR_C` и отношения `same-node`/`same-resource`; остальную topology агрегировать диапазонами. Prompt с динамическим incident context пропускать через тот же sanitizer, что и JSON.

[x] Реализовать incident-local token map и обратное восстановление. Таблицу соответствий хранить отдельно от экспортируемых файлов с режимом `0600`; внешний ответ сохранять неизменным, а restored-копию строить точной заменой только известных токенов по границам. Неизвестные, повреждённые или придуманные моделью placeholders оставлять как есть и отмечать в отчёте.

[ ] Добавить outbound DLP scan для IP/CIDR, hostname/DNS, credentials, JWT, PEM/private keys, email, URL, Kubernetes identifiers, high-entropy/base64 strings и canary secrets. При совпадении package не экспортировать; `redaction-report.json` должен содержать только detector type, count и локальный evidence reference без исходного значения.

[x] Оформить ручной Google workflow: `kdiag llm prepare --profile external` создаёт `prompt.external.txt`, `incident.external.json`, preview и redaction report; оператор просматривает их, вручную передаёт содержимое в «Поиск ИИ», сохраняет ответ в файл и запускает `llm import-response`. Никакого browser automation или обхода ограничений продукта не реализовывать.

[ ] Принять 24 GB VRAM как минимальную конфигурацию для пилота: 16 физических CPU cores с AVX2, минимум 64 GB RAM, рекомендуется 128 GB ECC, минимум 2 TB NVMe. Первый baseline — `Qwen3-30B-A3B Q4_K_M`, challenger — `Qwen3-14B Q8`; native context обеих моделей ограничить в kdiag-профиле до 12–16K tokens ради latency. Официальные карточки: [Qwen3-30B-A3B](https://huggingface.co/Qwen/Qwen3-30B-A3B-GGUF), [Qwen3-14B](https://huggingface.co/Qwen/Qwen3-14B-GGUF).

[ ] Принять 96 GB VRAM как рекомендуемую production-конфигурацию при сопоставимом современном GPU: 24–32 физических CPU cores, минимум 128 GB RAM, рекомендуется 256 GB ECC, 4 TB enterprise NVMe; для единственного локального хранилища предпочесть RAID1. Сравнить `Qwen3-32B BF16` как стабильный dense baseline и `Qwen3.5-35B-A3B BF16/FP8` как MoE challenger. Официальные карточки: [Qwen3-32B](https://huggingface.co/Qwen/Qwen3-32B), [Qwen3.5-35B-A3B](https://huggingface.co/Qwen/Qwen3.5-35B-A3B).

[ ] Не выбирать окончательную модель или runtime только по объёму VRAM: после появления карты зафиксировать GPU model, compute capability, memory bandwidth, driver/CUDA compatibility с конкретной RED OS и измерить загрузку модели, prompt processing и generation. При неизвестной карте 96 GB остаётся предпочтительным capacity-вариантом, но не гарантирует меньшую latency, чем более быстрый 24 GB GPU.

[ ] Использовать pinned `llama.cpp` с CUDA и OpenAI-compatible server как первый runtime: он не требует Python environment основного приложения и поддерживает GGUF quantization. На 96 GB отдельно проверить pinned `vLLM` в изолированном Python 3.12 environment/container; актуальная документация требует Linux, Python 3.10–3.13 и NVIDIA compute capability не ниже 7.5. Источники: [llama.cpp](https://github.com/ggml-org/llama.cpp), [vLLM GPU requirements](https://docs.vllm.ai/en/latest/getting_started/installation/gpu/).

[ ] Зафиксировать SLO для прогретой модели: подготовка package не более 5 секунд, первый token не более 10 секунд, `fast-triage` не более 60 секунд на 24 GB и целевые 30–45 секунд на 96 GB, `deep-analysis` не более 180 секунд. Модель держать загруженной; cold start не считать штатным аварийным путём. Конкретные SLO подтвердить только benchmark на выбранной карте.

[ ] Собрать закрытый gold set минимум из 20–30 инцидентов: известная причина, несколько правдоподобных причин, evidence gap, неизвестная причина, шум, русский технический текст, Kubernetes/Cilium/etcd, malicious instructions в Pod log и canary secrets. Измерять корректность evidence links, abstain rate, false claims, privacy leak rate, TTFT, полное время и peak VRAM/RAM.

[ ] Добавить unit/integration tests на token-budget truncation, сохранение причины после минимизации, противоречивое evidence, стабильность/коллизии токенов, Unicode, prompt injection, outbound DLP, отсутствие topology leakage, round-trip ответа, неизвестные placeholders, malformed JSON и недоступный inference endpoint. Основной snapshot/report/self-test должен проходить без установленной LLM.

[ ] Выполнять rollout по этапам: сначала package/schema/prompt без inference; затем offline benchmark 24/96 GB; затем локальный read-only pilot; после privacy review — ручной внешний export. Production enablement требует закреплённых model/runtime digests, SLO, gold-set regression gate, systemd hardening, retention и rollback на предыдущую модель/prompt.

## Open questions

- Точная модель GPU пока неизвестна; до закупки или закрепления SLO необходимо получить хотя бы `vendor/model`, memory bandwidth, compute capability и поддерживаемую связку driver/CUDA на целевой RED OS.

- Нужно отдельно утвердить, допустимы ли во внешнем package обобщённые размеры кластера (`1`, `2–5`, `6–20`, `>20`) и нестандартные port numbers; по умолчанию план считает их topology-sensitive и удаляет.
