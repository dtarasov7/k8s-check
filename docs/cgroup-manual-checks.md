# Manual cgroup checks on a node

This document reproduces the read-only sources used by `kdiag` for cgroup facts and related rules. The commands do not modify anything or restart services. They use `sudo -n` to match the remote node collector.

## 1. Cgroup mode and controllers

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

An empty `cgroup.subtree_control` is not an error by itself. `cgroup.controllers_missing` is emitted only for cgroup v2 when `cpu` or `io` is absent from `cgroup.controllers`.

## 2. Service systemd settings

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

Missing unused runtime alternatives and missing KESL units are valid. A runtime failure is reported only for explicitly loaded runtime units when none of them is active or activating. The analysis also uses `SubState`, `ControlGroup`, `Delegate`, `Slice`, `MainPID`, and any cgroup driver in `ExecStart`.

## 3. Kubelet and runtime process cgroups

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

`kdiag` also records `/proc/<pid>/status`, but current cgroup rules do not directly evaluate it.

## 4. Kubelet cgroup driver

```bash
sudo -n grep -nE '^[[:space:]]*cgroupDriver[[:space:]]*:' \
    /var/lib/kubelet/config.yaml
```

```bash
sudo -n systemctl show kubelet.service \
    --no-pager \
    --property=ExecStart
```

The expected detectable value is `systemd` or `cgroupfs`.

## 5. Container runtime cgroup driver

The exact node collector command is:

```bash
sudo -n crictl info
```

To display only relevant fields:

```bash
sudo -n crictl info |
    grep -iE 'systemd.?cgroup|cgroup.?driver|cgroup.?manager'
```

`kdiag` recursively searches the JSON fields `SystemdCgroup`, `cgroupDriver`, and `cgroupManager`. `SystemdCgroup=true` means `systemd`; `false` means `cgroupfs`. `cgroup.driver_mismatch` is emitted only when both drivers are unambiguous and differ.

## 6. Cgroup errors in journals

Current boot, using the default 24-hour window:

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

Previous boot:

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

Current-boot kernel journal:

```bash
sudo -n journalctl --no-pager --utc -o json -k \
    --since '24 hours ago' |
grep -iE 'cgroup|subtree_control|cpu\.|io\.' |
grep -iE 'permission denied|operation not permitted|read-only file system|eacces|eperm|erofs'
```

Previous-boot kernel journal:

```bash
sudo -n journalctl --no-pager --utc -o json -k \
    -b -1 -n 2000 |
grep -iE 'cgroup|subtree_control|cpu\.|io\.' |
grep -iE 'permission denied|operation not permitted|read-only file system|eacces|eperm|erofs'
```

## 7. Component versions and KESL presence

```bash
sudo -n rpm -qa \
    --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\n' |
grep -Ei '^(kernel|kubelet|containerd|cri-o|crio|runc|cilium|kesl|kaspersky|systemd)\|'
```

KESL presence together with a cgroup denial produces `security_agent.cgroup_denial`. This is a correlation, not proof that Kaspersky blocked the operation.

## Sanitized result template

The following is sufficient for analysis; omit IPs, hostnames, PIDs, full cgroup paths, and Pod names:

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
  found/not found:
  current or previous boot:
  service or kernel:
  operation: read/write/create
  object: controllers/subtree_control/cpu/io/other
  errno: EPERM/EACCES/EROFS/other

KESL installed: yes/no
```
