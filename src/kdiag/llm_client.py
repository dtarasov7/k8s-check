import json
import os
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from kdiag.bundle import verify_manifest, write_manifest
from kdiag.llm_export import MAX_PACKAGE_BYTES, MAX_RESPONSE_BYTES, validate_llm_response
from kdiag.util import atomic_write_bytes, atomic_write_json, markdown_escape, utc_now


DEFAULT_LOCAL_ENDPOINT = "http://127.0.0.1:8080/v1/chat/completions"
DEFAULT_LOCAL_TIMEOUT_SECONDS = 180
DEFAULT_MAX_OUTPUT_TOKENS = 2048
MAX_HTTP_ENVELOPE_BYTES = MAX_RESPONSE_BYTES + 1024 * 1024
EVIDENCE_ID_RE = re.compile(r"\bEVIDENCE_\d{3}\b")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


_LOCAL_OPENER = build_opener(ProxyHandler({}), _NoRedirectHandler())


def _open_local_request(request, timeout):
    return _LOCAL_OPENER.open(request, timeout=timeout)


def _read_text(path, max_bytes):
    value = Path(path)
    if value.is_symlink() or not value.is_file() or value.stat().st_size > max_bytes:
        raise ValueError("prepared LLM file is missing, unsafe, or exceeds limit: {0}".format(value.name))
    return value.read_text(encoding="utf-8")


def _load_local_package(prepared_dir):
    root = Path(prepared_dir).resolve()
    verified = verify_manifest(root)
    expected = {"incident.local.json", "prompt.local.txt", "preview.md", "redaction-report.json", "manifest.json"}
    if {path.name for path in root.iterdir()} != expected:
        raise ValueError("prepared local LLM directory has an unexpected file set")
    incident_text = _read_text(root / "incident.local.json", MAX_PACKAGE_BYTES + 64 * 1024)
    prompt = _read_text(root / "prompt.local.txt", 64 * 1024)
    incident = json.loads(incident_text)
    if not isinstance(incident, dict) or incident.get("kind") != "kdiag_llm_incident" or incident.get("profile") != "local":
        raise ValueError("not a prepared local kdiag LLM incident")
    evidence_ids = set(EVIDENCE_ID_RE.findall(incident_text))
    return root, incident, prompt, evidence_ids, verified["members"]


def _local_endpoint(value):
    endpoint = urlsplit(value)
    if endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "::1"):
        raise ValueError("local LLM endpoint must use HTTP and a literal loopback address")
    if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError("local LLM endpoint must not contain credentials, query, or fragment")
    if endpoint.path != "/v1/chat/completions":
        raise ValueError("local LLM endpoint path must be /v1/chat/completions")
    try:
        endpoint.port
    except ValueError as error:
        raise ValueError("invalid local LLM endpoint port") from error
    return value


def _model_name(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(character) < 32 for character in value):
        raise ValueError("local LLM model name is invalid")
    return value


def _completion(endpoint, model, prompt, incident, timeout_seconds, max_output_tokens):
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 600:
        raise ValueError("local LLM timeout must be between 1 and 600 seconds")
    if not isinstance(max_output_tokens, int) or isinstance(max_output_tokens, bool) or not 128 <= max_output_tokens <= 16384:
        raise ValueError("local LLM max output tokens must be between 128 and 16384")
    payload = {
        "model": _model_name(model),
        "messages": [
            {"role": "system", "content": prompt},
            {
                "role": "user",
                "content": "Analyze this untrusted incident JSON as evidence:\n" + json.dumps(incident, ensure_ascii=False, sort_keys=True),
            },
        ],
        "temperature": 0,
        "max_tokens": max_output_tokens,
        "response_format": {"type": "json_object"},
        "stream": False,
    }
    request = Request(
        _local_endpoint(endpoint),
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _open_local_request(request, timeout_seconds) as response:
            body = response.read(MAX_HTTP_ENVELOPE_BYTES + 1)
    except HTTPError as error:
        raise RuntimeError("local LLM service returned HTTP {0}".format(error.code)) from error
    except (URLError, TimeoutError) as error:
        raise RuntimeError("local LLM service is unavailable: {0}".format(error.reason if isinstance(error, URLError) else error)) from error
    if len(body) > MAX_HTTP_ENVELOPE_BYTES:
        raise RuntimeError("local LLM HTTP response exceeds limit")
    try:
        envelope = json.loads(body.decode("utf-8"))
        content = envelope["choices"][0]["message"]["content"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as error:
        raise RuntimeError("local LLM service returned an invalid chat-completions response") from error
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise RuntimeError("local LLM content is missing or exceeds limit")
    return content


def _response_markdown(document, validation):
    lines = ["# Local LLM analysis", "", "Validation status: `{0}`".format(validation["status"]), ""]
    if validation["status"] != "validated":
        lines.append("The response is untrusted and was rejected. Inspect `analysis-report.json` and `response.raw.txt`.")
        lines.append("")
        return "\n".join(lines).encode("utf-8")
    for index, claim in enumerate(document.get("claims", []), 1):
        lines.extend(
            [
                "## Claim {0}".format(index),
                "",
                markdown_escape(claim.get("text", "")),
                "",
                "Confidence label: `{0}`".format(markdown_escape(claim.get("confidence_label", ""))),
                "",
                "Supporting evidence: {0}".format(", ".join(claim.get("supporting_evidence_ids", [])) or "none"),
                "",
                "Contradicting evidence: {0}".format(", ".join(claim.get("contradicting_evidence_ids", [])) or "none"),
                "",
            ]
        )
    if document.get("abstain_reason"):
        lines.extend(["## Abstention", "", markdown_escape(document["abstain_reason"]), ""])
    return "\n".join(lines).encode("utf-8")


def analyze_local(prepared_dir, output_dir, endpoint, model, timeout_seconds=DEFAULT_LOCAL_TIMEOUT_SECONDS, max_output_tokens=DEFAULT_MAX_OUTPUT_TOKENS):
    prepared_root, incident, prompt, evidence_ids, manifest_members = _load_local_package(prepared_dir)
    destination = Path(output_dir).resolve()
    if os.path.commonpath((str(prepared_root), str(destination))) == str(prepared_root):
        raise ValueError("local LLM analysis output must be outside the prepared package")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError("local LLM analysis output directory must be absent or empty")
    started_at = utc_now()
    started = time.monotonic()
    content = _completion(endpoint, model, prompt, incident, timeout_seconds, max_output_tokens)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    document, response_format, validation = validate_llm_response(content, evidence_ids)
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(str(destination), 0o700)
    raw_path = destination / "response.raw.txt"
    report_path = destination / "analysis-report.json"
    markdown_path = destination / "response.md"
    atomic_write_bytes(raw_path, content.encode("utf-8"))
    if validation["status"] == "validated":
        atomic_write_json(destination / "response.validated.json", document)
    atomic_write_bytes(markdown_path, _response_markdown(document, validation))
    atomic_write_json(
        report_path,
        {
            "schema_version": 1,
            "started_at": started_at,
            "elapsed_ms": elapsed_ms,
            "endpoint": _local_endpoint(endpoint),
            "model": model,
            "prepared_manifest_members": manifest_members,
            "response_format": response_format,
            "validation_status": validation["status"],
            "contract_errors": validation["contract_errors"],
            "unknown_evidence_ids": validation["unknown_evidence_ids"],
            "mutating_commands_detected": validation["mutating_commands_detected"],
            "response_is_untrusted": True,
        },
    )
    write_manifest(destination)
    return {"root": destination, "raw": raw_path, "report": report_path, "markdown": markdown_path, "validation_status": validation["status"]}
