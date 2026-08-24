import os
import time
from pathlib import Path

from kdiag.runner import run_process
from kdiag.util import atomic_write_bytes, decode_gzip_json_bytes, sha256_bytes


class SSHTransport:
    def __init__(self, connect_timeout_seconds, remote_python, max_bundle_bytes):
        self.connect_timeout_seconds = connect_timeout_seconds
        self.remote_python = remote_python
        self.max_bundle_bytes = max_bundle_bytes

    def _environment(self):
        inherited = {}
        for name in ("HOME", "USER", "LOGNAME", "SSH_AUTH_SOCK"):
            if os.environ.get(name):
                inherited[name] = os.environ[name]
        return inherited

    def _ssh_prefix(self, host):
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout={0}".format(self.connect_timeout_seconds),
            "-p",
            str(host.port),
            host.ssh_destination,
        ]

    def _scp_prefix(self, host):
        return [
            "scp",
            "-q",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout={0}".format(self.connect_timeout_seconds),
            "-P",
            str(host.port),
        ]

    def _cleanup_remote(self, host, remote_path):
        result = run_process(
            self._ssh_prefix(host) + ["rm", "-f", remote_path],
            timeout_seconds=max(self.connect_timeout_seconds * 2, 30),
            max_stdout_bytes=64 * 1024,
            max_stderr_bytes=64 * 1024,
            env=self._environment(),
        )
        if result.returncode != 0 or result.error:
            return result.error or result.stderr.decode("utf-8", errors="replace")[:2000] or "remote cleanup failed"
        return None

    def collect_node(self, host, agent_path, destination, collection_id, node_arguments, timeout_seconds):
        started = time.monotonic()
        remote_path = "/tmp/kdiag-{0}.pyz".format(collection_id)
        upload = run_process(
            self._scp_prefix(host) + [str(agent_path), "{0}:{1}".format(host.ssh_destination, remote_path)],
            timeout_seconds=max(self.connect_timeout_seconds * 2, 30),
            max_stdout_bytes=64 * 1024,
            max_stderr_bytes=256 * 1024,
            env=self._environment(),
        )
        if upload.returncode != 0 or upload.error or upload.timed_out:
            cleanup_error = self._cleanup_remote(host, remote_path)
            return {
                "host": host.name,
                "status": "unreachable" if upload.returncode in (None, 255) else "failed",
                "duration_ms": int((time.monotonic() - started) * 1000),
                "error": upload.error or upload.stderr.decode("utf-8", errors="replace")[:4096] or "scp failed",
                "cleanup_error": cleanup_error,
            }
        command = self._ssh_prefix(host) + [
            "sudo",
            "-n",
            self.remote_python,
            remote_path,
            "node-snapshot",
        ] + list(node_arguments)
        result = run_process(
            command,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=self.max_bundle_bytes,
            max_stderr_bytes=512 * 1024,
            env=self._environment(),
        )
        cleanup_error = self._cleanup_remote(host, remote_path)
        if result.returncode != 0 or result.error or result.timed_out or result.truncated:
            if result.timed_out:
                status = "timeout"
            elif result.truncated:
                status = "truncated"
            elif result.returncode in (None, 255):
                status = "unreachable"
            elif b"sudo" in result.stderr.lower() and (b"password" in result.stderr.lower() or b"not allowed" in result.stderr.lower()):
                status = "permission_denied"
            else:
                status = "failed"
            return {
                "host": host.name,
                "status": status,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "error": result.error or result.stderr.decode("utf-8", errors="replace")[:4096] or "remote collector failed",
                "truncated": result.truncated,
                "cleanup_error": cleanup_error,
            }
        try:
            document = decode_gzip_json_bytes(result.stdout)
            if document.get("kind") != "node_snapshot" or document.get("schema_version") != 1:
                raise ValueError("unexpected node snapshot schema")
        except (ValueError, OSError, EOFError, UnicodeDecodeError) as error:
            return {
                "host": host.name,
                "status": "malformed",
                "duration_ms": int((time.monotonic() - started) * 1000),
                "error": str(error),
                "cleanup_error": cleanup_error,
            }
        atomic_write_bytes(destination, result.stdout)
        return {
            "host": host.name,
            "target": host.target,
            "status": "collected",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "file": str(Path(destination).name),
            "compressed_bytes": len(result.stdout),
            "sha256": sha256_bytes(result.stdout),
            "cleanup_error": cleanup_error,
        }
