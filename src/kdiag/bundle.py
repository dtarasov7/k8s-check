import json
import os
import re
from pathlib import Path

from kdiag.util import atomic_write_json, sha256_file, utc_now


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MEMBER_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _member_path(root, relative):
    if not isinstance(relative, str) or not relative or os.path.isabs(relative) or not MEMBER_RE.fullmatch(relative):
        raise ValueError("invalid manifest member path")
    if Path(relative).name != relative or relative in (".", ".."):
        raise ValueError("manifest member must be a top-level file: {0!r}".format(relative))
    root_path = Path(root).resolve()
    candidate = root_path / relative
    if candidate.is_symlink():
        raise ValueError("manifest member must not be a symlink: {0}".format(relative))
    resolved = candidate.resolve()
    if os.path.commonpath((str(root_path), str(resolved))) != str(root_path):
        raise ValueError("manifest member escapes collection: {0}".format(relative))
    return resolved


def _data_files(root):
    result = []
    for path in sorted(Path(root).iterdir(), key=lambda item: item.name):
        if path.name == "manifest.json":
            continue
        if path.is_symlink():
            raise ValueError("collection contains a symlink: {0}".format(path.name))
        if not path.is_file():
            raise ValueError("collection contains a non-file member: {0}".format(path.name))
        if not MEMBER_RE.fullmatch(path.name):
            raise ValueError("collection contains an unsafe file name: {0!r}".format(path.name))
        result.append(path)
    return result


def build_manifest(collection_dir):
    root = Path(collection_dir).resolve()
    members = []
    for path in _data_files(root):
        digest, size = sha256_file(str(path))
        members.append({"path": path.name, "size": size, "sha256": digest})
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "hash_algorithm": "sha256",
        "members": members,
    }


def write_manifest(collection_dir):
    manifest = build_manifest(collection_dir)
    atomic_write_json(Path(collection_dir) / "manifest.json", manifest)
    return manifest


def verify_manifest(collection_dir):
    root = Path(collection_dir).resolve()
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("manifest.json is missing or is not a regular file")
    if manifest_path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("manifest.json exceeds size limit")
    with manifest_path.open("r", encoding="utf-8") as source:
        manifest = json.load(source)
    if not isinstance(manifest, dict):
        raise ValueError("manifest root must be an object")
    if manifest.get("schema_version") != 1 or manifest.get("hash_algorithm") != "sha256":
        raise ValueError("unsupported manifest format")
    members = manifest.get("members")
    if not isinstance(members, list):
        raise ValueError("invalid manifest members")

    seen = set()
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("invalid manifest member")
        relative = member.get("path")
        if not isinstance(relative, str):
            raise ValueError("invalid manifest member path")
        if relative in seen:
            raise ValueError("duplicate manifest member: {0}".format(relative))
        seen.add(relative)
        expected_size = member.get("size")
        expected_digest = member.get("sha256")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
            raise ValueError("invalid size for manifest member: {0}".format(relative))
        if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
            raise ValueError("invalid SHA-256 for manifest member: {0}".format(relative))
        path = _member_path(root, relative)
        if not path.is_file():
            raise ValueError("manifest member is missing: {0}".format(relative))
        actual_digest, actual_size = sha256_file(str(path))
        if actual_size != expected_size:
            raise ValueError("size mismatch for manifest member: {0}".format(relative))
        if actual_digest != expected_digest:
            raise ValueError("SHA-256 mismatch for manifest member: {0}".format(relative))

    actual = {path.name for path in _data_files(root)}
    unexpected = sorted(actual - seen)
    if unexpected:
        raise ValueError("files are absent from manifest: {0}".format(", ".join(unexpected)))
    return {"status": "verified", "members": len(members)}
