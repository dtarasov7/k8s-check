# Hardened deployment llama.cpp для kdiag

Каталог содержит пример deployment отдельно собранного и закреплённого `llama-server`. Он не устанавливается автоматически и не содержит модель, CUDA, NVIDIA driver или binaries llama.cpp.

## Граница безопасности

Unit работает от статической непривилегированной учётной записи `kdiag-llm`, слушает только `127.0.0.1:8080`, запрещает сетевую загрузку llama.cpp, Web UI, agent/tools mode, slots endpoint, внешнюю сеть через systemd address filter и logging llama.cpp. У service нет kubeconfig, SSH keys, пути к collection, shell integration или writable-каталога модели. `kdiag analyze-local` передаёт только содержимое проверенных prepared JSON и prompt.

Service file одновременно использует bind на loopback и systemd `IPAddressDeny`/`IPAddressAllow`. Проверьте, что сборка systemd целевой РЕД ОС поддерживает и применяет IP address filter; проигнорированная директива не заменяет firewall.

## Сборка и перенос

Соберите runtime в контролируемой среде для точной комбинации GPU/CUDA и закрепите release или commit llama.cpp. Текущие upstream-команды CUDA build:

```bash
cmake -B build -DGGML_CUDA=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target llama-server
```

Зафиксируйте source revision, compiler, CUDA version, checksums binary/shared libraries, URL/revision/license модели, checksum GGUF и compute capability целевой GPU. Перенесите проверенные артефакты через утверждённый offline-процесс. Не настраивайте `LLAMA_ARG_MODEL_URL`, `LLAMA_ARG_HF_REPO`, `HF_TOKEN`, tools, MCP servers или agent mode.

## Установка на РЕД ОС

Создайте system account без login shell. Добавьте её только в группы, которым принадлежат нужные NVIDIA device nodes; проверьте группы, а не предполагайте, что они всегда называются `video` и `render`.

```bash
getent group video
getent group render
stat -c '%n %U %G %a' /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm
groupadd --system kdiag-llm
useradd --system --gid kdiag-llm --home-dir /var/cache/kdiag-llm --shell /sbin/nologin kdiag-llm
usermod --append --groups video,render kdiag-llm
install -d -o root -g kdiag-llm -m 0750 /opt/kdiag-llm/bin /opt/kdiag-llm/models /etc/kdiag-llm
install -o root -g kdiag-llm -m 0750 llama-server /opt/kdiag-llm/bin/llama-server
install -o root -g kdiag-llm -m 0640 model.gguf /opt/kdiag-llm/models/model.gguf
install -o root -g kdiag-llm -m 0640 llama-server.env /etc/kdiag-llm/llama-server.env
install -o root -g root -m 0644 kdiag-llm.service /etc/systemd/system/kdiag-llm.service
```

Если одна из GPU groups отсутствует или device ownership отличается, замените список групп `usermod` группами из вывода `stat`. Не делайте NVIDIA devices world-writable.

Скопируйте `llama-server.env.example` в `llama-server.env` и меняйте параметры только после фиксации точного hardware. `LLAMA_ARG_THREADS=16` и context 16K — pilot defaults, а не production sizing. Значение `LLAMA_ARG_ALIAS=kdiag-local` должно совпадать с `analyze-local --model kdiag-local`.

## Проверка и запуск

```bash
/opt/kdiag-llm/bin/llama-server --version
ldd /opt/kdiag-llm/bin/llama-server
systemd-analyze verify /etc/systemd/system/kdiag-llm.service
systemctl daemon-reload
systemctl enable --now kdiag-llm.service
systemctl status kdiag-llm.service
curl --fail --silent http://127.0.0.1:8080/health
ss -lntp | grep ':8080'
systemd-analyze security kdiag-llm.service
```

Listener должен быть только `127.0.0.1:8080`. Проверьте из отдельного network namespace или другого host, что port 8080 недоступен. До обработки incident data изучите journal и подтвердите отсутствие prompt/response. Unit передаёт `--log-disable` и отбрасывает stdout; stderr остаётся для ошибок запуска.

Запуск клиента:

```bash
python3.8 kdiag.pyz llm analyze-local /secure/llm-local/prepared \
  --model kdiag-local \
  --endpoint http://127.0.0.1:8080/v1/chat/completions \
  --output-dir /secure/llm-analysis
```

Не включайте production до проверки на точной сборке РЕД ОС/GPU synthetic prompt, canary secret, prompt injection, timeout, VRAM/RAM, TTFT, полной latency и отсутствия content logging.

## Upstream-источники

- [Официальная инструкция сборки llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md)
- [Официальная документация llama-server и актуальные environment variables](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)

Command-line flags и environment variables проверены 2026-08-24. Закрепите и повторно проверьте их для точной revision llama.cpp, выбранной для deployment.
