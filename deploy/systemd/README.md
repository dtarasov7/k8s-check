# Hardened llama.cpp deployment for kdiag

This directory contains an example deployment for a separately built and pinned `llama-server`. It is not installed automatically and does not include a model, CUDA, the NVIDIA driver, or llama.cpp binaries.

## Security boundary

The unit runs as the static unprivileged `kdiag-llm` account, binds only to `127.0.0.1:8080`, disables llama.cpp network downloads, Web UI, agent/tools mode, slots endpoint, proxies through the systemd address filter, and llama.cpp logging. It has no kubeconfig, SSH keys, collection path, shell integration, or writable model directory. `kdiag analyze-local` sends only the verified prepared JSON and prompt content.

The service file uses both a loopback bind and systemd `IPAddressDeny`/`IPAddressAllow`. Verify that the target RED OS systemd build supports and enforces the IP address filter; do not treat an ignored directive as a firewall.

## Build and transfer

Build on a controlled system against the exact target GPU/CUDA combination and pin a llama.cpp release or commit. The current upstream CUDA build commands are:

```bash
cmake -B build -DGGML_CUDA=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target llama-server
```

Record the source revision, compiler, CUDA version, binary/shared-library checksums, model URL/revision/license, GGUF checksum, and target GPU compute capability. Transfer the reviewed artifacts through the approved offline process. Do not configure `LLAMA_ARG_MODEL_URL`, `LLAMA_ARG_HF_REPO`, `HF_TOKEN`, tools, MCP servers, or an agent mode.

## Install on RED OS

Create a system account without a login shell. Add it only to the groups that own the required NVIDIA device nodes; inspect those groups instead of assuming they are always named `video` and `render`.

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

If either GPU group does not exist or device ownership differs, replace the `usermod` group list with the groups reported by `stat`. Do not make NVIDIA devices world-writable.

Copy `llama-server.env.example` to `llama-server.env` and tune only after recording the exact hardware. `LLAMA_ARG_THREADS=16` and the 16K context are pilot defaults, not production sizing. Keep `LLAMA_ARG_ALIAS=kdiag-local` synchronized with `analyze-local --model kdiag-local`.

## Validate and start

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

The listener must be only `127.0.0.1:8080`. Test from a separate network namespace or host that port 8080 is unreachable. Inspect the journal before incident data is used and confirm that prompts and responses are not logged. The supplied unit passes `--log-disable` and discards stdout; stderr remains available for startup failures.

Run the client with:

```bash
python3.8 kdiag.pyz llm analyze-local /secure/llm-local/prepared \
  --model kdiag-local \
  --endpoint http://127.0.0.1:8080/v1/chat/completions \
  --output-dir /secure/llm-analysis
```

Do not enable production use until a synthetic prompt, a canary secret, a prompt-injection sample, timeout behavior, VRAM/RAM use, TTFT, total latency, and absence of content logging have been verified on the exact RED OS/GPU build.

## Upstream references

- [Official llama.cpp build guide](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md)
- [Official llama-server documentation and current environment variables](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)

The command-line flags and environment variables were checked on 2026-08-24. Pin and re-check them against the exact llama.cpp revision selected for deployment.
