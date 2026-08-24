import gzip
import hashlib
import io
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 1
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def require_safe_id(value, field):
    if not isinstance(value, str) or not value or value.startswith("-") or not SAFE_ID_RE.fullmatch(value):
        raise ValueError("unsafe {0}: {1!r}".format(field, value))
    return value


def require_k8s_name(value, field="namespace"):
    if not isinstance(value, str) or not value or not K8S_NAME_RE.fullmatch(value):
        raise ValueError("invalid {0}: {1!r}".format(field, value))
    return value


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def gzip_json_bytes(value):
    return gzip.compress(json_bytes(value), compresslevel=6, mtime=0)


def decode_gzip_json_bytes(payload, max_uncompressed_bytes=128 * 1024 * 1024):
    with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as source:
        decoded = source.read(max_uncompressed_bytes + 1)
    if len(decoded) > max_uncompressed_bytes:
        raise ValueError("uncompressed payload exceeds limit")
    return json.loads(decoded.decode("utf-8"))


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path, max_bytes=None):
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError("file exceeds hash limit: {0}".format(path))
            digest.update(chunk)
    return digest.hexdigest(), total


def atomic_write_bytes(path, payload, mode=0o600):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".{0}.".format(destination.name), suffix=".part", dir=str(destination.parent)
    )
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, str(destination))
        directory_fd = os.open(str(destination.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def atomic_write_json(path, value):
    atomic_write_bytes(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")


def atomic_write_gzip_json(path, value):
    atomic_write_bytes(path, gzip_json_bytes(value))


def load_gzip_json(path, max_bytes=128 * 1024 * 1024):
    compressed_size = os.path.getsize(path)
    if compressed_size > max_bytes:
        raise ValueError("compressed file exceeds limit: {0}".format(path))
    with gzip.open(path, "rb") as source:
        payload = source.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("uncompressed file exceeds limit: {0}".format(path))
    return json.loads(payload.decode("utf-8"))


def markdown_escape(value):
    text = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("<", "&lt;").replace(">", "&gt;")
