# Ручная проверка cgroup на узле

Этот документ воспроизводит read-only источники, которые `kdiag` использует для cgroup facts и связанных правил. Команды ничего не изменяют и не перезапускают. Для соответствия удалённому node collector они выполняются через `sudo -n`.

## 1. Режим cgroup и контроллеры

```bash
sudo -n sh -c '
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
    printf "mode=v2\n"
elif [ -e /sys/fs/cgroup/unified ]; then
    printf "mode=hybrid\n"
else
    printf "mode=v1_or_unknown\n"
fi
'
```

```bash
sudo -n cat /sys/fs/cgroup/cgroup.controllers
sudo -n cat /sys/fs/cgroup/cgroup.subtree_control
sudo -n cat /proc/cgroups
sudo -n grep -E '(^|[[:space:]])cgroup2?([[:space:]]|$)' /proc/self/mountinfo
```

Пустой `cgroup.subtree_control` сам по себе не является ошибкой. Finding `cgroup.controllers_missing` создаётся только для cgroup v2, если в `cgroup.controllers` отсутствует `cpu` или `io`.

## 2. Настройки systemd для сервисов

```bash
for unit in \
    kubelet.service \
    containerd.service \
    containerd-deckhouse.service \
    crio.service \
    NetworkManager.service \
    kesl.service \
    kesl-supervisor.service
do
    sudo -n systemctl show "$unit" \
        --no-pager \
        --property=Id,LoadState,ActiveState,SubState,Result,MainPID,ExecMainStatus,UnitFileState,FragmentPath,DropInPaths,ControlGroup,Delegate,Slice,ExecStart
done
```

Отсутствие неиспользуемых альтернативных runtime units и KESL units допустимо. Отказ runtime фиксируется только для явно загруженных units, если ни один из них не находится в `active` или `activating`. В анализе также используются `SubState`, `ControlGroup`, `Delegate`, `Slice`, `MainPID` и cgroup driver в `ExecStart`, если он там задан.

## 3. Cgroup процессов kubelet и runtime

```bash
for unit in kubelet.service containerd.service containerd-deckhouse.service crio.service
do
    pid="$(sudo -n systemctl show "$unit" --property=MainPID --value)"
    if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        printf '\n[%s pid=%s]\n' "$unit" "$pid"
        sudo -n cat "/proc/$pid/cgroup"
        sudo -n grep -E '(^|[[:space:]])cgroup2?([[:space:]]|$)' "/proc/$pid/mountinfo"
    fi
done
```

`kdiag` также сохраняет `/proc/<pid>/status`, но текущие cgroup rules непосредственно его не анализируют.

## 4. Cgroup driver kubelet

```bash
sudo -n grep -nE '^[[:space:]]*cgroupDriver[[:space:]]*:' \
    /var/lib/kubelet/config.yaml
```

```bash
sudo -n systemctl show kubelet.service \
    --no-pager \
    --property=ExecStart
```

Ожидаемое определяемое значение — `systemd` или `cgroupfs`.

## 5. Cgroup driver container runtime

Точная команда node collector:

```bash
sudo -n crictl info
```

Сокращённый просмотр значимых полей:

```bash
sudo -n crictl info |
    grep -iE 'systemd.?cgroup|cgroup.?driver|cgroup.?manager'
```

`kdiag` рекурсивно ищет JSON-поля `SystemdCgroup`, `cgroupDriver` и `cgroupManager`. `SystemdCgroup=true` означает `systemd`, `false` — `cgroupfs`. Finding `cgroup.driver_mismatch` появляется, если оба driver определены однозначно и различаются.

## 6. Cgroup errors в журналах

Текущая загрузка, стандартное окно 24 часа:

```bash
sudo -n journalctl \
    --no-pager --utc -o json \
    --since '24 hours ago' \
    -u kubelet.service \
    -u containerd.service \
    -u containerd-deckhouse.service \
    -u crio.service \
    -u NetworkManager.service \
    -u kesl.service \
    -u kesl-supervisor.service |
grep -iE 'cgroup|subtree_control|cpu\.|io\.' |
grep -iE 'permission denied|operation not permitted|read-only file system|eacces|eperm|erofs'
```

Предыдущая загрузка:

```bash
sudo -n journalctl \
    --no-pager --utc -o json \
    -b -1 -n 2000 \
    -u kubelet.service \
    -u containerd.service \
    -u containerd-deckhouse.service \
    -u crio.service \
    -u NetworkManager.service \
    -u kesl.service \
    -u kesl-supervisor.service |
grep -iE 'cgroup|subtree_control|cpu\.|io\.' |
grep -iE 'permission denied|operation not permitted|read-only file system|eacces|eperm|erofs'
```

Kernel journal текущей загрузки:

```bash
sudo -n journalctl --no-pager --utc -o json -k \
    --since '24 hours ago' |
grep -iE 'cgroup|subtree_control|cpu\.|io\.' |
grep -iE 'permission denied|operation not permitted|read-only file system|eacces|eperm|erofs'
```

Kernel journal предыдущей загрузки:

```bash
sudo -n journalctl --no-pager --utc -o json -k \
    -b -1 -n 2000 |
grep -iE 'cgroup|subtree_control|cpu\.|io\.' |
grep -iE 'permission denied|operation not permitted|read-only file system|eacces|eperm|erofs'
```

## 7. Версии компонентов и наличие KESL

```bash
sudo -n rpm -qa \
    --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\n' |
grep -Ei '^(kernel|kubelet|containerd|cri-o|crio|runc|cilium|kesl|kaspersky|systemd)\|'
```

Наличие KESL вместе с cgroup denial создаёт `security_agent.cgroup_denial`. Это корреляция, а не доказательство блокировки со стороны Kaspersky.

## Обезличенное описание результата

Для разбора достаточно заполнить шаблон без IP, hostname, PID, полных cgroup paths и имён Pod:

```text
mode:
controllers:
subtree_control:
kubelet driver:
runtime driver:

kubelet:
  ActiveState:
  Delegate:
  ControlGroup:

runtime:
  unit:
  ActiveState:
  Delegate:
  ControlGroup:

cgroup denial:
  найден/не найден:
  текущая или предыдущая загрузка:
  сервис или kernel:
  операция: read/write/create
  объект: controllers/subtree_control/cpu/io/другое
  errno: EPERM/EACCES/EROFS/другое

KESL установлен: да/нет
```
