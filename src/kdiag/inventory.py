import json
import os
import re
import tempfile
from dataclasses import dataclass

from kdiag.runner import run_process
from kdiag.util import require_safe_id


USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


@dataclass(frozen=True)
class HostSpec:
    name: str
    target: str
    user: object
    port: int

    @property
    def ssh_destination(self):
        target = self.target
        if ":" in target and not target.startswith("["):
            target = "[{0}]".format(target)
        return "{0}@{1}".format(self.user, target) if self.user else target


def _group_hosts(document, group, seen=None):
    if seen is None:
        seen = set()
    if group in seen:
        return set()
    seen.add(group)
    data = document.get(group, {})
    hosts = set(data.get("hosts", []) or [])
    for child in data.get("children", []) or []:
        hosts.update(_group_hosts(document, child, seen))
    return hosts


def parse_ansible_inventory(document, group=None, default_user=None, default_port=22):
    if not isinstance(document, dict):
        raise ValueError("ansible inventory output must be an object")
    hostvars = document.get("_meta", {}).get("hostvars", {})
    if not isinstance(hostvars, dict):
        raise ValueError("ansible inventory _meta.hostvars must be an object")
    if group:
        if group not in document:
            raise ValueError("inventory group not found: {0}".format(group))
        names = _group_hosts(document, group)
    elif hostvars:
        names = set(hostvars)
    else:
        names = set()
        for name in document:
            if name not in ("_meta", "all", "ungrouped"):
                names.update(_group_hosts(document, name))
    if not names:
        raise ValueError("inventory selection contains no hosts")

    hosts = []
    for name in sorted(names):
        require_safe_id(name, "inventory hostname")
        variables = hostvars.get(name, {}) or {}
        if not isinstance(variables, dict):
            raise ValueError("hostvars must be an object for {0}".format(name))
        connection = variables.get("ansible_connection", "ssh")
        if connection not in ("ssh", "smart"):
            raise ValueError("unsupported connection {0!r} for {1}".format(connection, name))
        if variables.get("ansible_ssh_common_args") or variables.get("ansible_ssh_extra_args"):
            raise ValueError("SSH common/extra args are not accepted; configure a reviewed OpenSSH alias for {0}".format(name))
        target = str(variables.get("ansible_host", name))
        require_safe_id(target, "SSH target")
        user = variables.get("ansible_user", default_user)
        if user is not None and (not isinstance(user, str) or not USER_RE.fullmatch(user)):
            raise ValueError("unsafe SSH user for {0}: {1!r}".format(name, user))
        port = variables.get("ansible_port", default_port)
        if not isinstance(port, int):
            try:
                port = int(port)
            except (TypeError, ValueError):
                raise ValueError("invalid SSH port for {0}: {1!r}".format(name, port))
        if port < 1 or port > 65535:
            raise ValueError("invalid SSH port for {0}: {1}".format(name, port))
        hosts.append(HostSpec(name=name, target=target, user=user, port=port))
    return hosts


def load_ansible_inventory(path, group=None, default_user=None, default_port=22, timeout_seconds=30):
    inherited = {}
    for name in ("HOME", "USER", "LOGNAME", "ANSIBLE_CONFIG"):
        if os.environ.get(name):
            inherited[name] = os.environ[name]
    with tempfile.TemporaryDirectory(prefix="kdiag-ansible-") as temporary_directory:
        inherited["ANSIBLE_LOCAL_TEMP"] = temporary_directory
        result = run_process(
            ["ansible-inventory", "--inventory", path, "--list", "--export"],
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=16 * 1024 * 1024,
            env=inherited,
        )
    if result.error:
        raise RuntimeError("cannot execute ansible-inventory: {0}".format(result.error))
    if result.returncode != 0 or result.truncated or result.timed_out:
        raise RuntimeError("ansible-inventory failed: {0}".format(result.stderr.decode("utf-8", errors="replace")[:2000]))
    try:
        document = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid ansible-inventory JSON: {0}".format(error))
    return parse_ansible_inventory(document, group=group, default_user=default_user, default_port=default_port)
