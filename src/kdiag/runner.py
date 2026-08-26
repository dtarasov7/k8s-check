import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

from kdiag.util import utc_now


DEFAULT_PATH = "/opt/deckhouse/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class ProcessResult:
    argv: list
    returncode: object
    stdout: bytes
    stderr: bytes
    started_at: str
    ended_at: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False
    error: object = None

    def record(self, check_id, sensitivity="internal"):
        if self.returncode is None:
            status = "unsupported"
        elif self.error:
            status = "error"
        elif self.timed_out:
            status = "timeout"
        elif self.truncated:
            status = "truncated"
        elif self.returncode == 0:
            status = "collected"
        else:
            status = "failed"
        return {
            "id": check_id,
            "argv": list(self.argv),
            "status": status,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "sensitivity": sensitivity,
            "stdout": self.stdout.decode("utf-8", errors="replace"),
            "stderr": self.stderr.decode("utf-8", errors="replace"),
            "error": self.error,
        }


def safe_environment(extra=None):
    environment = {
        "PATH": DEFAULT_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "PAGER": "cat",
        "SYSTEMD_PAGER": "cat",
    }
    if extra:
        environment.update(extra)
    return environment


def _terminate_process_group(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 0.5
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_process(argv, timeout_seconds, max_stdout_bytes, max_stderr_bytes=128 * 1024, env=None):
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty sequence of strings")
    started_at = utc_now()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=safe_environment(env),
        )
    except (FileNotFoundError, PermissionError, OSError) as error:
        ended = time.monotonic()
        if isinstance(error, FileNotFoundError):
            message = "command unavailable: {0} (executable not found)".format(argv[0])
        elif isinstance(error, PermissionError):
            message = "command unavailable: {0} (permission denied)".format(argv[0])
        else:
            message = str(error)
        return ProcessResult(
            list(argv), None, b"", b"", started_at, utc_now(), int((ended - started) * 1000), error=message
        )

    selector = selectors.DefaultSelector()
    streams = {process.stdout.fileno(): ("stdout", bytearray(), max_stdout_bytes), process.stderr.fileno(): ("stderr", bytearray(), max_stderr_bytes)}
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)

    timed_out = False
    truncated = False
    deadline = started + timeout_seconds
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _terminate_process_group(process)
            remaining = 0
        events = selector.select(timeout=min(max(remaining, 0), 0.2))
        if not events and process.poll() is not None:
            events = [(key, selectors.EVENT_READ) for key in list(selector.get_map().values())]
        for key, _mask in events:
            name, buffer, limit = streams[key.fd]
            try:
                chunk = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(key.fd)
                continue
            available = max(limit - len(buffer), 0)
            if available:
                buffer.extend(chunk[:available])
            if len(chunk) > available:
                truncated = True
                _terminate_process_group(process)
        if (timed_out or truncated) and process.poll() is not None and not selector.get_map():
            break

    selector.close()
    try:
        returncode = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        returncode = process.wait()
    ended = time.monotonic()
    stdout_value = bytes(streams[process.stdout.fileno()][1])
    stderr_value = bytes(streams[process.stderr.fileno()][1])
    process.stdout.close()
    process.stderr.close()
    return ProcessResult(
        list(argv),
        returncode,
        stdout_value,
        stderr_value,
        started_at,
        utc_now(),
        int((ended - started) * 1000),
        timed_out=timed_out,
        truncated=truncated,
        error=None,
    )


def run_check(check_id, argv, timeout_seconds, max_stdout_bytes, sensitivity="internal"):
    return run_process(argv, timeout_seconds, max_stdout_bytes).record(check_id, sensitivity=sensitivity)
