#!/usr/bin/env python3
"""A00-only finite dual native leaf harness. Default validates a plan, never runs it.

No automatic database/server creation. --execute requires an explicit isolated
run manifest. --selftest uses local NO_MODEL_FIXTURE transport only. The only
real provider endpoint permitted is http://127.0.0.1:17891/v1/messages.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import tempfile
import traceback
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "forgeflow.next.dual-leaf.run.v1"
UPSTREAM = "http://127.0.0.1:17891"
MODEL = "glm-5.3"
MAX_REQUESTS = 12
PER_EXECUTOR = 6
MAX_OUTPUT = 8192
MAX_INPUT = 256 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
WALL_SECONDS = 300
RESERVE_USD = 10
EXPECTED_PRICING = {"group_default": 1, "model_ratio": 0.5927067435209744,
                    "completion_ratio": 3.5, "model_price": 0, "quota_type": 0,
                    "enable_groups": ["default"], "quota_per_unit": 500000,
                    "quota_display_type": "USD"}


class Blocked(RuntimeError):
    pass


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value, private=False):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 16384:
            raise Blocked("credential must be a private current-user regular file, at most 16 KiB")
        value = stream.read(16385).decode().strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise Blocked("credential must be one nonempty single-line value")
    return value


def file_ref(value):
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise Blocked("file reference requires exactly path and sha256")
    path = Path(value["path"])
    if not path.is_absolute() or not path.is_file() or sha(path) != value["sha256"]:
        raise Blocked("pinned input file is absent or changed: " + str(path))
    return path


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname or ""
    if host == "localhost":
        host = "127.0.0.1"
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise Blocked("API must be an explicit plain HTTP loopback origin")
    try:
        okay = ipaddress.ip_address(host).is_loopback
    except ValueError:
        okay = False
    if not okay or parsed.port is None or parsed.port in (8787, 17891):
        raise Blocked("production/provider origins are not isolated control APIs")
    return "http://" + (f"[{host}]:{parsed.port}" if ":" in host else f"{host}:{parsed.port}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def price_domain():
    values = []
    for suffix in ("/api/pricing", "/api/status"):
        with opener().open(UPSTREAM + suffix, timeout=5) as reply:
            raw = reply.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise Blocked("pricing response exceeds read bound")
        values.append(json.loads(raw))
    pricing, status = values
    rows = [row for row in pricing.get("data", []) if row.get("model_name") == MODEL]
    if pricing.get("success") is not True or len(rows) != 1:
        raise Blocked("pricing domain lacks one exact GLM-5.3 row")
    row = rows[0]
    observed = {"group_default": pricing.get("group_ratio", {}).get("default"),
                **{key: row.get(key) for key in ("model_ratio", "completion_ratio", "model_price", "quota_type", "enable_groups")},
                **{key: status.get("data", {}).get(key) for key in ("quota_per_unit", "quota_display_type")}}
    if status.get("success") is not True or observed != EXPECTED_PRICING or any(type(observed[key]) is bool for key in ("group_default", "model_ratio", "completion_ratio", "model_price", "quota_type", "quota_per_unit")):
        raise Blocked("live pricing domain changed; stop before provider dispatch")
    return observed


def redact(value, credentials=()):
    if isinstance(value, dict):
        return {key: "<REDACTED>" if key.lower() in {"token", "scope_token", "api_key", "auth_token", "authorization", "password", "secret"} else redact(item, credentials) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, credentials) for item in value]
    if isinstance(value, str):
        for secret in credentials:
            value = value.replace(secret, "<REDACTED>")
    return value


def validate_payload(raw):
    if not 0 < len(raw) <= MAX_INPUT:
        raise Blocked("INPUT_BYTE_LIMIT")
    def distinct(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Blocked("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    try:
        body = json.loads(raw, object_pairs_hook=distinct)
    except ValueError:
        raise Blocked("INVALID_JSON")
    if not isinstance(body, dict) or body.get("model") != MODEL:
        raise Blocked("MODEL_NOT_ALLOWED")
    cap = body.get("max_tokens")
    if type(cap) is not int or not 1 <= cap <= MAX_OUTPUT:
        raise Blocked("OUTPUT_TOKEN_LIMIT")
    if body.get("stream") is not True:
        raise Blocked("STREAM_REQUIRED_FOR_FINITE_USAGE_CAPTURE")
    for tool in body.get("tools", []):
        if not isinstance(tool, dict) or tool.get("type", "custom") != "custom" or str(tool.get("name", "")).lower() in {"websearch", "web_search", "webfetch", "web_fetch"}:
            raise Blocked("SERVER_TOOLS_OR_PAID_WEB_SEARCH_NOT_ALLOWED")
    def content(value):
        if isinstance(value, dict):
            if value.get("type") in {"image", "document", "audio", "video", "search_result"}:
                raise Blocked("NON_TEXT_TOOL_INPUT_NOT_ALLOWED")
            for child in value.values():
                content(child)
        elif isinstance(value, list):
            for child in value:
                content(child)
    content(body.get("messages", []))
    content(body.get("system", []))
    return body


def request_limits(manifest):
    if "request_limits" not in manifest:
        return {"total_requests": MAX_REQUESTS, "per_executor_requests": PER_EXECUTOR}
    limits = manifest["request_limits"]
    if not isinstance(limits, dict) or set(limits) != {"total_requests", "per_executor_requests"}:
        raise Blocked("request_limits requires exactly total_requests and per_executor_requests")
    if (type(limits["total_requests"]) is not int or not 1 <= limits["total_requests"] <= MAX_REQUESTS
            or type(limits["per_executor_requests"]) is not int or not 1 <= limits["per_executor_requests"] <= PER_EXECUTOR):
        raise Blocked("request_limits may only reduce strict integer total 1..12 and per-executor 1..6")
    return dict(limits)


class ForwardPolicy:
    def __init__(self, journal, check_price=price_domain, limits=None):
        self.journal = journal
        self.check_price = check_price
        self.limits = request_limits({} if limits is None else {"request_limits": limits})
        self.lock = threading.Lock()
        self.total = 0
        self.per_executor = {"dsh": 0, "claude": 0}
        self.inflight = 0
        self.uncertain = False
        self.deadlines = {}
        self.records = []

    def record(self, value):
        value = {"at_unix": time.time(), **value}
        self.records.append(value)
        if self.journal:
            fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as stream:
                stream.write(json.dumps(value, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())

    def activate(self, executor):
        with self.lock:
            if executor in self.deadlines:
                raise Blocked("executor task already activated; no automatic retry")
            self.deadlines[executor] = time.monotonic() + WALL_SECONDS

    def reserve(self, executor, raw):
        body = validate_payload(raw)
        with self.lock:
            if executor not in self.deadlines or time.monotonic() >= self.deadlines[executor]:
                raise Blocked("TASK_NOT_ACTIVE_OR_WALL_LIMIT")
            if self.uncertain or self.inflight:
                raise Blocked("INFLIGHT_OR_UNKNOWN_REQUEST_RETAINS_RESERVATION")
            if self.total >= self.limits["total_requests"] or self.per_executor[executor] >= self.limits["per_executor_requests"]:
                raise Blocked("REQUEST_COUNT_LIMIT")
            try:
                domain = self.check_price()  # before opening upstream socket
            except Exception:
                raise Blocked("PRICING_DOMAIN_UNAVAILABLE_OR_CHANGED") from None
            if (self.total + 1) * RESERVE_USD > 300:
                raise Blocked("USD_RESERVATION_LIMIT")
            self.total += 1
            self.per_executor[executor] += 1
            self.inflight += 1
            request_id = f"{executor}-{self.per_executor[executor]:02d}"
            self.record({"kind": "UPSTREAM_RESERVATION", "request_id": request_id, "executor": executor,
                         "model": body["model"], "body_sha256": hashlib.sha256(raw).hexdigest(),
                         "input_bytes": len(raw), "max_tokens": body["max_tokens"], "reserved_usd": RESERVE_USD,
                         "total_reserved_usd": self.total * RESERVE_USD, "pricing_domain": domain,
                         "request_limits": self.limits,
                         "financial_hard_guarantee": False, "provider_charge_status": "UNKNOWN"})
            return request_id, self.deadlines[executor]

    def settle(self, request_id, complete, usage, facts):
        with self.lock:
            bad_response = facts.get("upstream_status") != 200 or not facts.get("provider_response_model_matches", False)
            if isinstance(usage, dict) and type(usage.get("output_tokens")) is int and usage["output_tokens"] > MAX_OUTPUT:
                bad_response = True
            if complete and not bad_response:
                self.inflight -= 1
            else:
                self.uncertain = True
            # Keep the entire USD10 reservation even when usage is present: usage
            # is not a trusted money-debit receipt and no reservation is recycled.
            estimate = None
            if isinstance(usage, dict) and type(usage.get("input_tokens")) is int and type(usage.get("output_tokens")) is int:
                estimate = (usage["input_tokens"] + usage["output_tokens"] * EXPECTED_PRICING["completion_ratio"]) * EXPECTED_PRICING["model_ratio"] / EXPECTED_PRICING["quota_per_unit"]
            self.record({"kind": "UPSTREAM_OBSERVATION", "request_id": request_id, "transport_complete": complete,
                         "usage": usage, "observed_usage_status": "OBSERVED" if usage else "UNKNOWN",
                         "local_ratio_reference_estimate_usd": estimate, "actual_billed_usd": None,
                         "actual_billing_status": "UNKNOWN", "reservation_released_usd": 0, **facts})


class Usage:
    def __init__(self):
        self.buffer = b""
        self.usage = {}
        self.message_stop = False
        self.response_models = set()

    def feed(self, chunk):
        self.buffer += chunk
        if len(self.buffer) > MAX_RESPONSE:
            raise Blocked("SSE_LINE_BOUND")
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if not line.startswith(b"data:"):
                continue
            try:
                value = json.loads(line[5:].strip())
            except ValueError:
                continue
            if not isinstance(value, dict):
                continue
            message = value.get("message", {})
            if isinstance(message, dict):
                if isinstance(message.get("model"), str):
                    self.response_models.add(message["model"])
                self.take(message.get("usage"))
            self.take(value.get("usage"))
            self.message_stop |= value.get("type") == "message_stop"

    def take(self, usage):
        if isinstance(usage, dict):
            for key in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "reasoning_tokens", "total_tokens"):
                if type(usage.get(key)) is int and usage[key] >= 0:
                    self.usage[key] = usage[key]


def delivery_projection(real_attempt_ids, records):
    """Separate entered real HTTP opens from reservations, receipts and billing."""
    observations = {row["request_id"]: row for row in records
                    if row.get("kind") == "UPSTREAM_OBSERVATION" and row.get("real_upstream_http_open_attempted") is True}
    observed = [observations.get(request_id) for request_id in real_attempt_ids]
    matched = sum(bool(row and row.get("upstream_status") == 200 and row.get("message_stop_observed")
                       and row.get("provider_response_model_matches") and isinstance(row.get("usage"), dict)
                       and type(row["usage"].get("input_tokens")) is int
                       and type(row["usage"].get("output_tokens")) is int) for row in observed)
    return {"real_provider_calls": len(real_attempt_ids), "real_upstream_http_attempts": len(real_attempt_ids),
            "real_provider_calls_semantics": "entered fixed real upstream HTTP open attempts; not a provider-accepted/model-invocation/billed count",
            "responses_with_matching_model_usage": {"count": matched, "denominator": len(real_attempt_ids),
                "criteria": "HTTP200, matching GLM-5.3 response model, numeric input/output usage and message_stop"},
            "unknown_delivery": sum(row is None or row.get("upstream_status") is None for row in observed),
            "unknown_transport": sum(row is None or not row.get("transport_complete") for row in observed),
            "actual_supplier_debit_status": "UNKNOWN", "actual_supplier_debit_usd": None}


def target_facts(target, method):
    # Never persist arbitrary path/query strings or a credential-bearing URL.
    known = target if target in ("/v1/messages", "/v1/messages?beta=true") else None
    return {"target_pattern": known or "UNRECOGNIZED_SHA256_ONLY",
            "target_sha256": hashlib.sha256(target.encode("utf-8", "replace")).hexdigest(),
            "http_method": method if method in {"POST", "GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "CONNECT", "TRACE"} else "OTHER_SHA256_ONLY",
            "method_sha256": hashlib.sha256(method.encode("utf-8", "replace")).hexdigest()}


class Forwarder:
    def __init__(self, port, tokens, upstream_secret, runtime, policy, test_transport=None):
        self.tokens, self.policy = tokens, policy
        self.root, self.secret = runtime, upstream_secret
        self.records = []
        self.real_attempt_ids = []
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def fail(self, code, message):
                outer.records.append({"kind": "REJECTED_BEFORE_UPSTREAM", "http_status": code,
                    "code": message, **target_facts(getattr(self, "path", ""), getattr(self, "command", ""))})
                data = json.dumps({"error": {"type": "forgeflow_next_boundary", "code": message}}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if getattr(self, "command", None) != "HEAD":
                    self.wfile.write(data)
            def reject_method(self):
                self.fail(405, "HTTP_METHOD_NOT_ALLOWED")
            do_GET = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_CONNECT = do_TRACE = reject_method
            def send_error(self, code, message=None, explain=None):
                self.fail(code, "HTTP_PARSE_OR_UNKNOWN_METHOD_REJECTED")
            def do_POST(self):
                if self.path not in ("/v1/messages", "/v1/messages?beta=true"):
                    self.fail(404, "ONLY_MESSAGES_ALLOWED")
                    return
                supplied = self.headers.get("Authorization", "")
                token = supplied.removeprefix("Bearer ") if supplied.startswith("Bearer ") else self.headers.get("x-api-key", "")
                executor = next((key for key, value in outer.tokens.items() if hmac.compare_digest(value, token)), None)
                if executor is None:
                    self.fail(403, "RUN_TOKEN_REQUIRED")
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= MAX_INPUT or self.headers.get("Content-Encoding") or self.headers.get("Transfer-Encoding"):
                        raise Blocked("INPUT_LENGTH_OR_ENCODING_REJECTED")
                    raw = self.rfile.read(size)
                    request_id, deadline = outer.policy.reserve(executor, raw)
                except (ValueError, Blocked) as error:
                    message = str(error) if isinstance(error, Blocked) else "INVALID_CONTENT_LENGTH"
                    self.fail(429 if "LIMIT" in message or "INFLIGHT" in message else 403, message)
                    return
                response = None
                started = time.monotonic()
                total = 0
                digest = hashlib.sha256()
                meter = Usage()
                completed = False
                upstream_status = None
                upstream_ids = {}
                error_type = None
                real_open_attempted = False
                try:
                    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + outer.secret}
                    for key in ("anthropic-version", "anthropic-beta", "accept"):
                        value = self.headers.get(key)
                        if value and len(value) <= 1024:
                            headers[key] = value
                    timeout = max(0.1, min(120, deadline - time.monotonic()))
                    request = urllib.request.Request(UPSTREAM + self.path, data=raw, method="POST", headers=headers)
                    try:
                        if test_transport:
                            response = test_transport(request, timeout)
                        else:
                            # Persist intent at the real open boundary, separately
                            # from the earlier quota/budget reservation. A timeout
                            # still says nothing about upstream acceptance/debit.
                            with outer.policy.lock:
                                outer.policy.record({"kind": "REAL_UPSTREAM_HTTP_OPEN_ATTEMPT", "request_id": request_id})
                                outer.real_attempt_ids.append(request_id)
                            real_open_attempted = True
                            response = opener().open(request, timeout=timeout)
                    except urllib.error.HTTPError as error:
                        response = error
                    upstream_status = response.status
                    upstream_ids = {key: response.headers[key] for key in ("x-request-id", "request-id") if response.headers.get(key)}
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.headers.get("Content-Type", "application/octet-stream"))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    raw_path = outer.root / (request_id + ".upstream.sse")
                    fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as capture:
                        disconnected = False
                        while True:
                            if time.monotonic() >= deadline:
                                raise Blocked("TASK_WALL_LIMIT_DURING_RESPONSE")
                            chunk = response.read1(8192)
                            if not chunk:
                                completed = True
                                break
                            total += len(chunk)
                            if total > MAX_RESPONSE:
                                raise Blocked("RESPONSE_BYTE_LIMIT")
                            digest.update(chunk)
                            meter.feed(chunk)
                            capture.write(chunk)
                            if not disconnected:
                                try:
                                    self.wfile.write(chunk)
                                    self.wfile.flush()
                                except (BrokenPipeError, ConnectionResetError):
                                    disconnected = True  # drain for real EOF/usage, do not retry
                        capture.flush()
                        os.fsync(capture.fileno())
                except BaseException as error:
                    error_type = type(error).__name__
                finally:
                    if response is not None:
                        response.close()
                    facts = {"upstream_status": upstream_status, "received_bytes": total,
                             "received_sha256": digest.hexdigest(), "message_stop_observed": meter.message_stop,
                             "response_models": sorted(meter.response_models), "upstream_request_ids": upstream_ids,
                             "elapsed_seconds": round(time.monotonic() - started, 6), "error_type": error_type,
                             "real_upstream_http_open_attempted": real_open_attempted,
                             "transport_kind": "REAL_UPSTREAM_HTTP" if real_open_attempted else "NO_MODEL_FIXTURE_OR_NOT_OPENED",
                             "provider_response_model_matches": meter.response_models == {MODEL}}
                    outer.policy.settle(request_id, completed, meter.usage or None, facts)
        class Server(ThreadingHTTPServer):
            daemon_threads = True
        self.server = Server(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        return {"listener_closed": not self.thread.is_alive(), "rejected_requests": self.records,
                "total_provider_reservations": self.policy.total, "per_executor": self.policy.per_executor,
                "inflight_or_uncertain": self.policy.inflight, "unknown_transport": self.policy.uncertain,
                "reserved_usd_not_released": self.policy.total * RESERVE_USD,
                "request_limits": self.policy.limits,
                "delivery": delivery_projection(self.real_attempt_ids, self.policy.records),
                "not_proven": ["full-host network egress prevention", "actual supplier monetary debit", "unlimited source token has no upstream monetary cap"]}


class API:
    def __init__(self, base, token, output):
        self.base, self.token, self.output, self.sequence = origin(base), token, output, 0
        self.last_get = {}
    def audit(self, method, path, status, raw, value, elapsed):
        self.sequence += 1
        raw_hash = hashlib.sha256(raw).hexdigest()
        data = value.get("data", value) if isinstance(value, dict) else value
        payload_hash = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        endpoint = (method, path)
        previous = self.last_get.get(endpoint)
        if method == "GET" and status < 400 and previous and previous["status"] == status and previous["payload_sha256"] == payload_hash:
            previous["repeat_count"] += 1
            sample = {"request_sequence": self.sequence, "method": method, "path": path,
                      "status": status, "received_at_unix": time.time(), "elapsed_seconds": elapsed,
                      "response_sha256": raw_hash, "payload_sha256": payload_hash,
                      "first_full_record": previous["first_full_record"], "repeat_count": previous["repeat_count"]}
            fd = os.open(self.output / "http-polls.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as stream:
                stream.write(json.dumps(sample, ensure_ascii=False) + "\n")
            return
        audited_value = redact(value, [self.token])
        if len(raw) > 256 * 1024 and status < 400:
            # Large successful profiles already have immutable input references.
            # Errors are never suppressed or reduced to a successful-body hash.
            audited_value = {"large_body_reference_only": True, "bytes": len(raw),
                             "sha256": raw_hash, "top_level_keys": sorted(value) if isinstance(value, dict) else None}
        filename = f"http-{self.sequence:04d}.json"
        save(self.output / filename, {"method": method, "path": path, "status": status,
             "elapsed_seconds": elapsed, "received_at_unix": time.time(),
             "response_sha256": raw_hash, "payload_sha256": payload_hash, "response": audited_value})
        if method == "GET":
            self.last_get[endpoint] = {"status": status, "payload_sha256": payload_hash,
                                      "first_full_record": filename, "repeat_count": 0}
    def request(self, method, path, body=None, key=None, allowed_error=False, timeout=35):
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = key or secrets.token_hex(16)
        request = urllib.request.Request(self.base + "/api/v1" + path, data=data, method=method, headers=headers)
        start = time.monotonic()
        try:
            response = opener().open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(32 * 1024 * 1024 + 1)
            status = response.status
        if len(raw) > 32 * 1024 * 1024:
            raise Blocked("scoped API response exceeds evidence bound")
        try:
            value = json.loads(raw)
        except ValueError:
            self.audit(method, path, status, raw,
                {"non_json_response_utf8": raw.decode("utf-8", "replace").replace(self.token, "<REDACTED>")},
                round(time.monotonic() - start, 6))
            raise Blocked("actual API returned non-JSON; original response preserved after credential redaction") from None
        self.audit(method, path, status, raw, value, round(time.monotonic() - start, 6))
        if status >= 400 and not allowed_error:
            raise Blocked("actual API rejection; preserve HTTP evidence: " + path)
        return status, value
    def data(self, method, path, body=None, key=None):
        status, value = self.request(method, path, body, key)
        if not isinstance(value, dict) or "data" not in value:
            raise Blocked("actual API response does not match data envelope: " + path)
        return value["data"]


def fingerprint(pid):
    path = Path("/proc") / str(pid)
    text = (path / "stat").read_text()
    return {"pid": pid, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "start_ticks": text[text.rindex(")") + 2:].split()[19], "executable_sha256": sha(path / "exe")}


def server_identity(manifest):
    observed = fingerprint(manifest["server_pid"])
    if observed["executable_sha256"] != manifest["server_executable_sha256"]:
        raise Blocked("isolated server executable identity differs")
    expected = shared_state_root(manifest)
    # Read only the pinned isolated server's configured data-root variable;
    # never export its remaining environment or credentials.
    raw = (Path("/proc") / str(manifest["server_pid"]) / "environ").read_bytes()
    values = [entry.split(b"=", 1)[1] for entry in raw.split(b"\0") if entry.startswith(b"FORGEFLOW_DATA_ROOT=")]
    if len(values) != 1 or Path(values[0].decode()).resolve() != expected:
        raise Blocked("isolated server actual FORGEFLOW_DATA_ROOT differs from shared-state manifest")
    observed.update(local_state_mode="SHARED_SERVER_WORKER_ROOT", data_root=str(expected),
                    data_root_verified_from_pinned_server_environment=True)
    return observed


def git(root, *args, binary=False):
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "0", "LC_ALL": "C"}
    result = subprocess.run(["/usr/bin/git", "-C", str(root), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args], env=env, capture_output=True, timeout=30)
    if result.returncode:
        raise Blocked("owned fixture Git command failed; no production repository touched")
    return result.stdout if binary else result.stdout.decode().strip()


ORACLE = r'''import importlib.util,json,os,pathlib,sys
sys.dont_write_bytecode=True
subject=os.environ.get('NEXT_ORACLE_SUBJECT','calculator.py')
if subject not in ('calculator.py','owned/calculator.py'):raise SystemExit('undeclared oracle subject')
s=importlib.util.spec_from_file_location('candidate',pathlib.Path.cwd()/subject);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
role=os.environ['NEXT_ORACLE_ROLE'];cases=[]
def check(name,kind,ok):cases.append({'name':name,'kind':kind,'outcome':'passed' if ok else 'failed'})
def rejects(a,b):
 try:m.add(a,b)
 except TypeError:return True
 return False
if role=='author':
 check('author_integer_add','positive',m.add(2,3)==5)
 check('author_string_rejected','negative',rejects('2',3))
elif role=='consumer':
 check('consumer_negative_and_zero','positive',m.add(-9,4)==-5 and m.add(0,0)==0)
 check('consumer_bool_rejected','negative',rejects(True,1))
else:
 check('independent_reference_matrix','positive',all(m.add(a,b)==a+b for a,b in [(-100,21),(1234567,7654321),(0,-7),(7,0),(999,-999)]))
 check('independent_invalid_matrix','negative',all(rejects(a,b) for a,b in [(1,None),(1,1.0),([],3),({},4),(False,False)]))
pathlib.Path(os.environ['FORGEFLOW_REPORT_PATH']).write_text(json.dumps({'binding':json.loads(os.environ['FORGEFLOW_EVIDENCE_BINDING']),'oracle_id':'next-dual-leaf-add.v1','cases':cases}))
print(json.dumps({'role':role,'executed':len(cases),'failed':sum(x['outcome']!='passed' for x in cases)}))
if any(x['outcome']!='passed' for x in cases):sys.exit(1)
'''
CASE_NAMES = {"author": [("author_integer_add", "positive"), ("author_string_rejected", "negative")],
              "consumer": [("consumer_negative_and_zero", "positive"), ("consumer_bool_rejected", "negative")],
              "independent": [("independent_reference_matrix", "positive"), ("independent_invalid_matrix", "negative")]}


def helpers():
    path = ROOT / "verification/algorithm_check.py"
    if str(ROOT / "verification") not in sys.path:
        sys.path.insert(0, str(ROOT / "verification"))
    spec = importlib.util.spec_from_file_location("next_dual_algorithm", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def registration_value(reference):
    value = json.loads(file_ref(reference).read_text())
    if "profile_ref" in value and "native_mode_ref" in value:
        profile = json.loads(file_ref(value["profile_ref"]).read_text())
        managed = json.loads(file_ref(value["native_mode_ref"]).read_text())
        return {**profile, "kind": "DSH_MANAGED", "native_mode": managed}
    return value


def wait_for(callback, deadline, purpose):
    while time.monotonic() < deadline:
        value = callback()
        if value is not None:
            return value
        time.sleep(0.5)
    raise Blocked("bounded actual wait expired: " + purpose)


def terminal_ack(journal, attempt):
    identities = ("project_id", "task_id", "task_revision", "attempt_id", "lease_id", "worker_id", "generation", "operation_id", "base_sha")
    for path in sorted(set(journal.glob("result-*-ack.json")) | {journal / "result-ack.json"}):
        if not path.is_file():
            continue
        value = json.loads(path.read_text())
        response = value.get("controller_response", {})
        authority = response.get("data", response)
        terminal = authority.get("terminal", authority)
        if value.get("terminal_confirmed") is True and terminal.get("state") == attempt.get("state") and all(
                key in attempt and key in terminal and attempt[key] == terminal[key] for key in identities):
            return {"path": str(path), "sha256": sha(path), "event_id": value.get("event_id"),
                    "terminal_confirmed": True, "state": terminal["state"]}
    return None


def await_cancel_terminal(read_attempt, read_evidence, clock=time.monotonic, pause=time.sleep):
    """Let the same owned Worker complete its real stop handshake, at most 30s."""
    started = clock()
    deadline = started + 30
    last = None
    last_error = None
    evidence = {}
    polls = 0
    while clock() < deadline:
        try:
            last = read_attempt(min(3, max(0.05, deadline - clock())))
            polls += 1
            if isinstance(last, dict) and last.get("state") in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                evidence = read_evidence(last, min(3, remaining))
                if evidence.get("resource_release_observed") and evidence.get("lease_revoked_observed") and evidence.get("terminal_ack"):
                    return {"status": "TERMINAL_RELEASE_ACK_OBSERVED", "terminal_observed": True,
                            "state": last["state"], "actual_attempt": last, "polls": polls,
                            "elapsed_seconds": round(clock() - started, 6), **evidence}
        except Exception as error:
            last_error = type(error).__name__
        remaining = deadline - clock()
        if remaining > 0:
            pause(min(0.5, remaining))
    return {"status": "UNKNOWN", "terminal_observed": isinstance(last, dict) and last.get("state") in {"SUCCEEDED", "FAILED", "CANCELLED"},
            "state": last.get("state", "UNKNOWN") if isinstance(last, dict) else "UNKNOWN",
            "actual_attempt": last, "polls": polls, "last_read_error_type": last_error,
            "elapsed_seconds": round(clock() - started, 6), "resource_release_observed": False, **evidence,
            "next_action": "preserve canonical state and journal; stop only fingerprint-matched owned Worker; no restart"}


def executor_order(manifest):
    order = manifest.get("executor_order", ["dsh", "claude"])
    if not isinstance(order, list) or len(order) != 2 or any(not isinstance(item, str) for item in order) or set(order) != {"dsh", "claude"}:
        raise Blocked("executor_order must be an exact permutation of dsh and claude")
    return order


def code_scope(manifest, executor=None):
    if "code_scope_modes" in manifest:
        modes = manifest["code_scope_modes"]
        if (not isinstance(modes, dict) or set(modes) != {"dsh", "claude"}
                or any(not isinstance(value, str) or value not in {"EXACT_FILE", "OWNED_DIRECTORY"} for value in modes.values())):
            raise Blocked("code_scope_modes requires exactly dsh and claude with EXACT_FILE or OWNED_DIRECTORY literals")
        if executor not in {"dsh", "claude"}:
            raise Blocked("per-driver code scope requires an explicit dsh or claude selector")
        mode = modes[executor]
    else:
        mode = manifest.get("code_scope_mode", "EXACT_FILE")
    if mode == "EXACT_FILE":
        return {"mode": mode, "subject": "calculator.py", "owner_include": ["calculator.py"], "write_set": ["calculator.py"]}
    if mode == "OWNED_DIRECTORY":
        return {"mode": mode, "subject": "owned/calculator.py", "owner_include": ["owned/"], "write_set": ["owned/"]}
    raise Blocked("code_scope_mode must be EXACT_FILE or OWNED_DIRECTORY")


def require_read_edit_tools(profile):
    tools = profile.get("tools_allowlist")
    if not isinstance(tools, list) or len(tools) != 2 or sorted(tools) != ["Edit", "Read"]:
        raise Blocked("OWNED_DIRECTORY Claude qualification requires exactly Read and Edit tools")


def native_edit_pair(raw_path, workspace, subject, session_id):
    """Inspect complete native messages, not partial deltas or model assertions."""
    target = (Path(workspace).resolve() / subject).resolve()
    uses, results, forbidden, errors = {}, {}, set(), []
    for line_number, raw in enumerate(Path(raw_path).read_bytes().splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except ValueError:
            errors.append("malformed_raw_line")
            continue
        if not isinstance(value, dict):
            errors.append("non_object_raw_line")
            continue
        if value.get("type") not in {"assistant", "user"} or value.get("parent_tool_use_id") is not None:
            continue
        if value.get("session_id") != session_id:
            errors.append("native_root_session_mismatch")
            continue
        blocks = value.get("message", {}).get("content", [])
        for block in blocks if isinstance(blocks, list) else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and value["type"] == "assistant":
                name, identity = block.get("name"), block.get("id")
                if name not in {"Read", "Edit"}:
                    forbidden.add(str(name))
                if name != "Edit":
                    continue
                path = block.get("input", {}).get("file_path")
                try:
                    resolved = (Path(workspace) / path).resolve() if isinstance(path, str) else None
                except (ValueError, OSError):
                    resolved = None
                if not isinstance(identity, str) or not identity or identity in uses or resolved != target:
                    errors.append("Edit_identity_duplicate_or_target_mismatch")
                else:
                    uses[identity] = line_number
            elif block.get("type") == "tool_result" and value["type"] == "user":
                identity = block.get("tool_use_id")
                if isinstance(identity, str):
                    if identity in results:
                        errors.append("duplicate_tool_result_identity")
                    results[identity] = {"line": line_number, "non_error": block.get("is_error", False) is False}
    pairs = [{"tool_use_id": identity, "tool_use_line": line, "tool_result_line": results[identity]["line"], "subject": subject}
             for identity, line in uses.items() if identity in results and results[identity]["non_error"] and results[identity]["line"] > line]
    return {"status": "VERIFIED" if pairs and not forbidden and not errors else "FAILED",
            "successful_Edit_pairs": pairs, "Edit_calls": len(uses), "forbidden_tool_names": sorted(forbidden),
            "protocol_errors": errors, "raw_path": str(raw_path), "raw_sha256": sha(raw_path),
            "qualification_scope": "complete native root Edit tool_use and same-id non-error tool_result for the declared subject; final Git scope checked separately"}


def verify_final_wrapper(integration):
    """Git persists this full pre-decision wrapper, not a naked role receipt."""
    receipt = integration["receipt"]
    artifact = Path(receipt["artifact_root"])
    path = artifact / "forgeflow-verification.json"
    durable = json.loads(path.read_text())  # no fallback to verifier scratch files
    expected = {key: value for key, value in receipt.items() if key not in {"commit_decided", "ref_updated"}}
    if durable != expected:
        raise Blocked("durable full integration wrapper differs from API receipt without finalization flags")
    verification = durable["verification"]
    binding = verification["binding"]
    if (durable["new_sha"] != integration["integrated_sha"]
            or binding["integrated_sha"] != integration["integrated_sha"]
            or binding["candidate_sha"] != integration["candidate_sha"]
            or binding["attempt_id"] != integration["attempt_id"]
            or binding["generation"] != integration["generation"]
            or durable["source_tree_oid"] != binding["source_hash"]):
        raise Blocked("durable wrapper SHA/tree/attempt binding differs from finalized integration")
    if sha(artifact / verification["log_path"]) != verification["log_hash"]:
        raise Blocked("durable wrapper raw verification log hash differs")
    return {"path": str(path), "sha256": sha(path), "full_wrapper_match": True,
            "excluded_API_fields": ["commit_decided", "ref_updated"],
            "verification_receipt_hash": durable["verification_receipt_hash"]}


def shared_state_root(manifest):
    if manifest.get("local_state_mode") != "SHARED_SERVER_WORKER_ROOT":
        raise Blocked("explicit local_state_mode=SHARED_SERVER_WORKER_ROOT required; remote artifact handoff is not implemented here")
    value = manifest.get("server_data_root")
    if not isinstance(value, str):
        raise Blocked("explicit existing shared server data_root required")
    root = Path(value)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise Blocked("shared server data_root must be an existing absolute real directory without aliases")
    return root


def validate_manifest(manifest):
    if manifest.get("schema_version") != SCHEMA or manifest.get("owned_workers_authorized") is not True:
        raise Blocked("A00 run manifest with explicit owned Workers is required")
    shared_root = shared_state_root(manifest)
    limits = request_limits(manifest)
    run = manifest.get("run_id", "")
    if not run or not run.isascii() or len(run) > 64 or any(not (char.isalnum() or char in "-_") for char in run):
        raise Blocked("finite run_id required")
    origin(manifest["api_origin"])
    if type(manifest["forwarder_port"]) is not int or not 1024 <= manifest["forwarder_port"] <= 65535 or manifest["forwarder_port"] in (8787, 17891, urllib.parse.urlsplit(manifest["api_origin"]).port):
        raise Blocked("distinct explicit test-only forwarder port required")
    file_ref(manifest["build_receipt"])
    file_ref(manifest["worker_binary"])
    if set(manifest["executors"]) != {"dsh", "claude"}:
        raise Blocked("exactly two native executor specifications required")
    for kind, config in manifest["executors"].items():
        for field in ("worker_config_template", "executor_profile", "resource_profile", "model_route"):
            file_ref(config[field])
        if not config.get("worker_id"):
            raise Blocked("explicit unique Worker identity required")
    if manifest["executors"]["dsh"]["worker_id"] == manifest["executors"]["claude"]["worker_id"]:
        raise Blocked("Workers must be independent")
    for field in ("output_root", "private_runtime_root", "server_data_root"):
        if not Path(manifest[field]).is_absolute():
            raise Blocked("absolute isolated output/runtime/server paths required")
    if Path(manifest["output_root"]).resolve() == Path(manifest["private_runtime_root"]).resolve():
        raise Blocked("public evidence and private runtime roots must differ")
    if manifest.get("budget_usd", 300) != 300:
        raise Blocked("this finite admission fixes the total authorized budget at USD300")
    return {"status": "PLAN_VALIDATED_NOT_EXECUTED", "schema_version": SCHEMA, "run_id": run,
            "executor_order": executor_order(manifest),
            "request_limits": limits,
            "code_scope": code_scope(manifest) if "code_scope_modes" not in manifest else None,
            "code_scopes": {kind: code_scope(manifest, kind) for kind in ("dsh", "claude")},
            "state_deployment_contract": {"local_state_mode": "SHARED_SERVER_WORKER_ROOT", "data_root": str(shared_root),
                "remote_worker_artifact_handoff": "NOT_IMPLEMENTED",
                "recovery_boundary": "Worker filters execution recovery by worker_id/project_id; preparation compatibility views are checked/restored before that filter"},
            "real_provider_calls": 0, "api_mutations": 0, "limits": {**limits,
            "max_output_tokens": MAX_OUTPUT, "max_input_bytes": MAX_INPUT, "max_response_bytes": MAX_RESPONSE,
            "inflight": 1, "task_wall_seconds": WALL_SECONDS, "per_request_reserve_usd": RESERVE_USD,
            "maximum_reserved_usd": limits["total_requests"] * RESERVE_USD}, "pricing_expected": EXPECTED_PRICING}


def execute(manifest):
    plan = validate_manifest(manifest)
    output, runtime = Path(manifest["output_root"]), Path(manifest["private_runtime_root"])
    # Fail before any network/actor if a prior run directory exists. Do not reuse
    # its request counters or clean an incomplete attempt to make a retry pass.
    if output.exists() or runtime.exists():
        raise Blocked("new independent evidence/runtime directories required; previous runs preserved")
    output.mkdir(parents=True, mode=0o700)
    runtime.mkdir(parents=True, mode=0o700)
    report = {**plan, "status": "INCONCLUSIVE", "source_harness_sha256": sha(__file__), "tasks": {}, "errors": [], "shutdown": {},
              "pinned_admission_inputs": {key: manifest[key] for key in ("build_receipt", "worker_binary")},
              "not_proven": ["native Teams/Workflow", "host-wide financial/network enforcement", "actual supplier monetary debit", "100+ sessions", "production qualification", "hostile candidate cannot forge its own in-process oracle report"]}
    processes = {}
    created_projects = set()
    active = []
    forwarder = None
    api = None
    try:
        report["server_identity"] = server_identity(manifest)
        report["initial_live_pricing"] = price_domain()
        provider_secret = private_read(manifest["upstream_secret_file"])
        tokens = {kind: private_read(config["forwarder_token_file"]) for kind, config in manifest["executors"].items()}
        if len(set(tokens.values())) != 2 or provider_secret in tokens.values():
            raise Blocked("per-executor alias tokens must be distinct from each other and the upstream credential")
        policy = ForwardPolicy(runtime / "upstream-journal.jsonl", limits=plan["request_limits"])
        forwarder = Forwarder(manifest["forwarder_port"], tokens, provider_secret, runtime, policy)
        forwarder.start()
        api = API(manifest["api_origin"], private_read(manifest["api_owner_token_file"]), output)
        projects = api.data("GET", "/projects")
        if projects != []:
            raise Blocked("this initial finite run requires an empty isolated project catalog")
        report["round_live_pricing"] = price_domain()
        alg = helpers()
        report["algorithm_helper_sha256"] = sha(ROOT / "verification/algorithm_check.py")
        oracle = runtime / "oracle.py"
        oracle.write_text(ORACLE)
        oracle.chmod(0o444)
        shared_global = None
        for kind in executor_order(manifest):
            scope = code_scope(manifest, kind)
            subject = scope["subject"]
            config = manifest["executors"][kind]
            project = "next-dual-" + manifest["run_id"] + "-" + kind
            worker_id = config["worker_id"]
            task_id = "t00000"
            record = {"project_id": project, "worker_id": worker_id, "status": "INCONCLUSIVE", "code_scope": scope}
            report["tasks"][kind] = record
            seed = runtime / (kind + "-seed")
            seed.mkdir()
            (seed / subject).parent.mkdir(parents=True, exist_ok=True)
            (seed / subject).write_text("def add(a, b):\n    raise NotImplementedError('native model must implement this task')\n")
            git(seed, "init", "--initial-branch=main")
            git(seed, "add", subject)
            git(seed, "-c", "user.name=Next independent fixture", "-c", "user.email=next@example.test", "commit", "-m", "Known unimplemented isolated leaf")
            base = git(seed, "rev-parse", "HEAD")
            created = api.data("POST", "/projects", {"project_id": project, "name": "Independent " + kind + " native leaf", "root_path": str(seed),
                "authority_mode": "MANAGED", "data_origin": "NATIVE", "goal": "Implement typed integer addition with independent verification and fenced Git integration",
                "technology_stack": ["Python standard library"], "timezone": "Asia/Shanghai", "paused": False, "archived": False, "revision": 0})
            created_projects.add(project)
            canonical = Path(created["root_path"])
            api.data("POST", f"/projects/{project}/teams", {"project_id": project, "team_id": "root", "parent_team_id": None, "name": "Finite leaf", "paused": False, "revision": 0})
            api.data("POST", f"/projects/{project}/owners", {"id": "root", "value": {"owner_id": "root", "root_team_id": "root", "include": scope["owner_include"], "exclude": []}})
            requirement = api.data("POST", f"/projects/{project}/requirements", {"project_id": project, "requirement_id": "R01", "title": "Typed addition",
                "source_anchor": "next-leaf#R01", "outcome": "add accepts exact integers, excludes bool, returns sum; other operand types raise TypeError",
                "scope": "calculator.py only" if scope["mode"] == "EXACT_FILE" else subject + " accepted source only", "acceptance": ["three independent-role positive/negative checks and real fenced Git integration"],
                "priority": 1, "weight": 1, "deferred_reason": None, "revision": 0})
            registration = registration_value(config["executor_profile"])
            if kind == "claude" and scope["mode"] == "OWNED_DIRECTORY":
                require_read_edit_tools(registration)
            resource = json.loads(file_ref(config["resource_profile"]).read_text())
            route = json.loads(file_ref(config["model_route"]).read_text())
            expected_kind = "DSH_MANAGED" if kind == "dsh" else "CLAUDE_CODE_LEAF"
            if registration.get("kind") != expected_kind or route.get("model") != MODEL or route.get("max_output_tokens") != MAX_OUTPUT:
                raise Blocked("native registration kind or frozen GLM route differs")
            if not resource.get("sandbox"):
                raise Blocked("strong sandbox resource profile required")
            readonly = resource["sandbox"].get("readonly_paths", [])
            if str(oracle) not in readonly:
                readonly.append(str(oracle))
                resource["sandbox"]["readonly_paths"] = readonly
            worker_config = json.loads(file_ref(config["worker_config_template"]).read_text())
            data_root = shared_state_root(manifest)
            worker_config.update(control_url=api.base, worker_id=worker_id, project_id=project, data_root=str(data_root), model_route_id=route["id"], max_active_attempts=1, max_log_bytes=8 * 1024 * 1024)
            worker_config["sandbox"] = resource["sandbox"]
            alias_file = Path(config["forwarder_token_file"]).resolve()
            secret_refs = list(worker_config.get("secret_files", {}))
            if kind == "claude":
                if registration.get("provider_base_url") != f"http://127.0.0.1:{manifest['forwarder_port']}" or len(secret_refs) != 1:
                    raise Blocked("Claude profile must freeze this forwarder origin and one alias secret reference")
                binding = worker_config["secret_files"][secret_refs[0]]
                if Path(binding["path"]).resolve() != alias_file or binding["env_name"] != "ANTHROPIC_AUTH_TOKEN":
                    raise Blocked("Claude Worker must receive only its per-run AUTH_TOKEN alias")
            worker_config_path = runtime / (kind + "-worker.json")
            save(worker_config_path, worker_config, private=True)
            save(output / (kind + "-registered-run-inputs.json"), {"worker_config_sha256": sha(worker_config_path), "worker_config_private_path": str(worker_config_path),
                 "executor_profile_sha256": hashlib.sha256(json.dumps(registration, sort_keys=True).encode()).hexdigest(),
                 "resource_profile_sha256": hashlib.sha256(json.dumps(resource, sort_keys=True).encode()).hexdigest(), "model_route": route,
                 "known_dynamic_changes": ["new project/Worker", "Worker data_root explicitly matches pinned server's existing isolated state root", "one pinned independent oracle readonly path", "one activity slot", "bounded log bytes"]})
            log = (runtime / (kind + "-worker.log")).open("xb")
            process = subprocess.Popen([str(file_ref(manifest["worker_binary"])), "--config", str(worker_config_path)],
                env={"PATH": "/usr/bin:/bin", "RUST_LOG": "info", "FORGEFLOW_WORKER_TOKEN": private_read(config["worker_token_file"])},
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            identity = fingerprint(process.pid)
            processes[kind] = (process, log, identity)
            save(runtime / (kind + "-owned-worker.json"), identity, private=True)
            deadline = time.monotonic() + WALL_SECONDS
            limits = {**alg.vector(1), "coding_slot": 1, "cpu_units": 4, "memory_bytes": 2 * 1024 * 1024 * 1024, "provider_inflight": 1}
            scopes = [("global", None, None, None)] if shared_global is None else []
            scopes += [("project-" + kind, project, None, None), ("team-" + kind, project, "root", None), ("worker-" + kind, None, None, worker_id)]
            for resource_scope, proj, team, worker in scopes:
                policy_body = {"policy": {"scope_id": resource_scope, "parent_scope_id": None, "project_id": proj, "team_id": team, "worker_id": worker,
                    "limits": limits, "revision": 0, "paused": False}}
                if worker:
                    # There is no GET /workers route. The genuine Worker alone
                    # registers itself. A successful typed policy FK proves its
                    # identity now exists; Store admission later independently
                    # rechecks the actual profile capability and liveness.
                    def registered_policy():
                        if process.poll() is not None:
                            raise Blocked("owned Worker exited; preserve private log")
                        status, value = api.request("POST", "/resource-policies", policy_body,
                            key="worker-policy-" + worker_id, allowed_error=True)
                        if status < 400:
                            return value
                        if value.get("code") == "REFERENCE_NOT_FOUND":
                            return None
                        raise Blocked("real Worker policy rejected; preserve actual API response")
                    record["worker_identity_fk_receipt"] = wait_for(registered_policy,
                        min(deadline, time.monotonic() + 45), "genuine Worker registration and policy FK")
                else:
                    api.data("POST", "/resource-policies", policy_body)
            shared_global = True
            for collection, value in (("executor_profiles", registration), ("resource_profiles", resource), ("model_routes", route)):
                api.data("POST", f"/projects/{project}/documents/{collection}", {"id": value["id"], "value": value})
            compiled = alg.make_compile(1)
            compiled["flow"]["project_id"] = project
            task = compiled["flow"]["tasks"][0]
            task.update(project_id=project, owner_id="root", team_id="root", read_set=[subject], write_set=list(scope["write_set"]), dependencies=[])
            task["resource_request"].update(coding_slot=1, cpu_units=1, memory_bytes=512 * 1024 * 1024, provider_inflight=1)
            input_hash = hashlib.sha256(git(canonical, "cat-file", "blob", base + ":" + subject, binary=True)).hexdigest()
            api.data("POST", f"/projects/{project}/documents/input_snapshots", {"id": subject, "value": {"path": subject, "relative_path": subject, "sha256": input_hash, "source_kind": "GIT_BLOB", "base_sha": base}})
            meaning = alg.requirement_digest(requirement)
            compiled["context"].update(owners=[{"owner_id": "root", "root_team_id": "root", "include": scope["owner_include"], "exclude": []}],
                current_inputs={subject: input_hash}, requirement_semantic_digests={"R01": meaning}, requirements=[{"requirement_id": "R01", "source_document": "next-leaf", "anchor": "R01", "acceptance": "\n".join(requirement["acceptance"]), "priority": 1, "deferred_reason": None}])
            spec = compiled["context"]["task_specs"][task_id]
            plan_id = "next-add-" + kind
            spec.update(outcome=requirement["outcome"], inputs=[{"path": subject, "sha256": input_hash, "producer_task_id": None}], mandatory_paths=[subject], dependency_refs=[],
                contract_produces=[], contract_consumes=[], design_anchors=["next-leaf#R01"], requirement_digest_refs={"R01": meaning}, execution_profile=registration["id"], verification_plan=plan_id, verification_case_count=6,
                not_proven=["native Teams and Workflow", "full-host egress and financial enforcement"])
            alg.refresh_digest(task, spec)
            prompt_text = "Read calculator.py, then implement add(a,b). Accept only exact Python int operands (reject bool), return integer sum; reject every other type with TypeError. Change only existing calculator.py. Use Read/Edit/Write as available; do not create other files, spawn agents or call web search. This is a real admitted code task. Report what changed.\n"
            if scope["mode"] == "OWNED_DIRECTORY":
                prompt_text = "Read owned/calculator.py, then use the native Edit tool to implement add(a,b) in that existing file. Accept only exact Python int operands (reject bool), return integer sum; reject every other type with TypeError. Only Read and Edit are permitted for this task. Do not run tests, self-tests, commands, diagnostics or Bash; do not use Write, add tools, create other files, spawn agents or use web search. After the native Edit succeeds, report the change without further tools. The owned/ directory is the admitted write boundary; only owned/calculator.py may remain changed.\n"
            prompt = api.data("POST", f"/projects/{project}/artifacts", {"content_utf8": prompt_text, "kind": "PROMPT"})
            context_text = json.dumps({"files": [{"path": subject, "sha256": input_hash}], "mandatory_paths": [subject]}, separators=(",", ":"))
            context = api.data("POST", f"/projects/{project}/artifacts", {"content_utf8": context_text, "kind": "CONTEXT_MANIFEST"})
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            task["envelope"] = {"schema_version": "forgeflow.execution.v1", "operation_id": "pending-" + kind, "project_id": project, "task_id": task_id, "task_revision": task["task_revision"],
                "attempt_id": "pending-" + kind, "lease_id": "pending-" + kind, "generation": 1, "worker_id": worker_id, "workspace_root": str(canonical), "base_sha": base,
                "context_manifest": {"artifact_id": context["artifact_id"], "sha256": context["sha256"], "mandatory_paths": [subject], "rendered_utf8_bytes": len(prompt_text.encode()), "token_estimate": None, "tokenizer_id": None},
                "write_set": list(scope["write_set"]), "prompt_artifact": {"artifact_id": prompt["artifact_id"], "sha256": prompt["sha256"]}, "model_route_id": route["id"], "executor_profile_id": registration["id"], "resource_profile_id": resource["id"], "verification_plan_id": plan_id,
                "allowed_effects": ["READ_WORKSPACE", "WRITE_DECLARED_PATHS", "RUN_APPROVED_COMMANDS", "REQUEST_APPROVED_MODEL"], "issued_at": now.isoformat(), "expires_at": (now + datetime.timedelta(seconds=120)).isoformat(), "deadline_at": (now + datetime.timedelta(seconds=WALL_SECONDS)).isoformat(),
                "artifact_prefix": str(Path(manifest["server_data_root"]) / "artifacts"), "secret_refs": secret_refs, "idempotency_key": "pending-" + kind, "trace_id": "next-" + kind,
                "enforcement": {"model_budget_mode": "direct_observed", "stage_resource_mode": "ATTEMPT_RESERVATION", "build_capable": False, "gateway_coverage_receipt_id": None, "tool_guard_receipt_id": None, "attempt_reserved_build_permits": 0, "all_model_routes_covered": False, "disabled_tool_entry_ids": []},
                "session_purpose": "EXECUTION", "max_model_requests": plan["request_limits"]["per_executor_requests"], "resume_session_id": None, "command": None}
            commands = [{"role": role, "program": "/usr/bin/python3", "args": ["-I", "-B", str(oracle)], "env": {"NEXT_ORACLE_ROLE": role, "NEXT_ORACLE_SUBJECT": subject, "PYTHONDONTWRITEBYTECODE": "1"}, "executable_hash": sha("/usr/bin/python3"), "bound_inputs": [{"path": str(oracle), "sha256": sha(oracle)}], "report_path": role + ".json", "expected_cases": [{"name": name, "kind": case_kind} for name, case_kind in CASE_NAMES[role]], "timeout_seconds": 20} for role in CASE_NAMES]
            api.data("POST", f"/projects/{project}/documents/verification_plans", {"id": plan_id, "value": {"plan_id": plan_id, "task_revision": task["task_revision"], "contract_version": "next-dual-leaf.v1", "input_hash": task["input_digest"], "environment_profile": resource["id"], "oracle_id": "next-dual-leaf-add.v1", "verifier_id": "independent-next-oracle", "author_id": worker_id, "commands": commands}})
            saved = api.data("POST", f"/projects/{project}/flow-revisions", {"flow": compiled["flow"], "context": compiled["context"]})
            committed = api.data("POST", f"/flows/{project}:1/commit", {"expected_revision": saved["revision"]})
            if committed["state"] != "COMMITTED" or committed["tasks"][0]["input_digest"] != task["input_digest"]:
                raise Blocked("Flow not committed by actual server")
            admission_body = {"actor_id": "overwritten", "idempotency_key": "overwritten", "project_id": project, "task_id": task_id, "task_revision": task["task_revision"], "flow_revision": 1, "policy_revision": 1, "input_digest": task["input_digest"], "worker_id": worker_id, "lease_seconds": 120, "envelope": task["envelope"]}
            policy.activate(kind)
            key = "next-admit-" + kind + "-" + manifest["run_id"]
            admitted = api.data("POST", f"/projects/{project}/admissions", admission_body, key)
            attempt = admitted["attempt"]["attempt_id"]
            record["attempt_id"] = attempt
            record["generation"] = admitted["attempt"]["generation"]
            active.append((project, attempt))
            replay = api.data("POST", f"/projects/{project}/admissions", admission_body, key)
            if replay["attempt"]["attempt_id"] != attempt:
                raise Blocked("idempotency replay created a different Attempt")
            def verifying():
                value = api.data("GET", f"/attempts/{attempt}?project_id={project}")
                if value["state"] in {"FAILED", "CANCELLED", "RECOVERY_REQUIRED"}:
                    raise Blocked("native author did not reach verifier: " + value["state"])
                return value if value["state"] == "VERIFYING" else None
            wait_for(verifying, deadline, "native model write and confirmed author stop")
            journal = data_root / "attempts" / attempt
            result = json.loads((journal / "result.json").read_text())
            stop = json.loads((journal / "stop.json").read_text())
            native_kind = expected_kind if kind == "dsh" else "CLAUDE_CODE_LEAF"
            if result["evidence"].get("executor_kind") != native_kind or not stop["process_exit_confirmed"] or stop["exit_code"] != 0 or not result["outcome"].get("upstream_session_id"):
                raise Blocked("native identity or physical stop evidence incomplete")
            if sha(journal / "stdout.ndjson") != result["outcome"]["raw_event_digest"] or result["outcome"]["completion_reason"] != "EXECUTOR_COMPLETED":
                raise Blocked("independent raw stream hash or executor completion differs")
            record["native_result_sha256"] = sha(journal / "result.json")
            if kind == "claude" and scope["mode"] == "OWNED_DIRECTORY":
                metadata = json.loads((journal / "worktree.json").read_text())
                paired = native_edit_pair(journal / "stdout.ndjson", metadata["worktree"]["absolute_path"],
                                          subject, result["outcome"]["upstream_session_id"])
                record["native_edit"] = {**paired, "native_pair_status": paired["status"],
                                         "status": "PARTIAL" if paired["status"] == "VERIFIED" else "FAILED",
                                         "final_git_scope": "NOT_RUN"}
                if paired["status"] != "VERIFIED":
                    raise Blocked("owned-directory Claude lacks an actual same-id successful native Edit pair in complete raw evidence")
            # Bindings require a CURRENT lease, so this positive control must
            # precede integration/revocation. The immediately following foreign
            # negative uses this exact credential/client; a 401 never qualifies.
            guard_output = output / (kind + "-scope-negative")
            guard_output.mkdir()
            worker_api = API(api.base, private_read(config["worker_token_file"]), guard_output)
            own_http, own_value = worker_api.request("GET",
                f"/attempts/{attempt}/bindings?project_id={project}&worker_id={worker_id}&generation={record['generation']}",
                allowed_error=True)
            if own_http != 200 or not isinstance(own_value.get("data"), dict) or own_value["data"].get("executor_profile", {}).get("id") != registration["id"]:
                raise Blocked("own live bindings positive control failed; do not claim cross-project isolation")
            record["scope_positive_control"] = {"http_status": own_http, "project_id": project,
                "worker_id": worker_id, "generation": record["generation"], "profile_id": registration["id"],
                "phase": "VERIFYING_BEFORE_LEASE_REVOCATION", "response_retained_or_hash_bound": True}
            other = "claude" if kind == "dsh" else "dsh"
            foreign = "next-dual-" + manifest["run_id"] + "-" + other
            foreign_http, foreign_value = worker_api.request("GET",
                f"/attempts/{attempt}/bindings?project_id={foreign}&worker_id={worker_id}&generation={record['generation']}",
                allowed_error=True)
            if foreign_http != 403 or foreign_value.get("code") != "WORKER_SCOPE_DENIED":
                raise Blocked("foreign negative lacks explicit scope denial; bad token/stale lease/not-found do not qualify")
            record["cross_project_negative"] = {"http_status": foreign_http, "code": foreign_value.get("code"),
                "own_bindings_positive_http": own_http, "same_authenticated_client": True,
                "generation": record["generation"], "phase": "VERIFYING_BEFORE_INTEGRATION",
                "foreign_project_id": foreign, "foreign_project_exists": foreign in created_projects,
                "qualification_scope": "scope denial against existing independent managed project" if foreign in created_projects else "scope authentication rejects before project lookup; foreign project not yet created",
                "response_retained": True}
            accepted = api.request("POST", f"/attempts/{attempt}/verify-and-integrate", {"project_id": project})[1]
            operation_id = accepted.get("operation_id")
            if not operation_id:
                raise Blocked("actual verifier command lacks operation identity")
            def integrated():
                value = api.data("GET", "/operations/" + operation_id)
                if value["status"] in {"FAILED", "RECOVERY_REQUIRED"}:
                    raise Blocked("real verification/integration operation failed")
                return value if value["status"] == "SUCCEEDED" else None
            operation = wait_for(integrated, deadline, "independent verifier and Git lane")
            integration = operation["result"]["integration"]
            verification = integration["receipt"]["verification"]
            if integration["state"] != "FINALIZED" or not integration["receipt"].get("commit_decided") or not integration["receipt"].get("ref_updated"):
                raise Blocked("Git intent not durably finalized")
            if verification["total"] != 6 or verification["failed"] or verification["skipped"] or verification["positive_cases"] != 3 or verification["negative_cases"] != 3:
                raise Blocked("independent real positive/negative denominator does not match frozen plan")
            binding = verification["binding"]
            if binding["input_hash"] != task["input_digest"] or binding["task_revision"] != task["task_revision"] or binding["generation"] != admitted["attempt"]["generation"] or binding["verification_plan_id"] != plan_id:
                raise Blocked("verification receipt differs from admitted task/profile identity")
            git(canonical, "merge-base", "--is-ancestor", integration["integrated_sha"], "refs/heads/main")
            if git(canonical, "rev-parse", integration["integrated_sha"] + "^{tree}") != binding["source_hash"]:
                raise Blocked("verification source tree differs from integrated main tree")
            if git(canonical, "diff", "--name-only", integration["expected_sha"], integration["integrated_sha"]).splitlines() != [subject]:
                raise Blocked("integrated write scope differs")
            if "native_edit" in record:
                record["native_edit"].update(status="VERIFIED", final_git_scope="VERIFIED", integrated_sha=integration["integrated_sha"])
            artifact = Path(integration["receipt"]["artifact_root"])
            if sha(artifact / verification["log_path"]) != verification["log_hash"]:
                raise Blocked("verification raw log digest differs")
            record["durable_integration_wrapper"] = verify_final_wrapper(integration)
            snapshot = api.data("GET", f"/projects/{project}/snapshot")
            actual = [row for row in snapshot["attempts"] if row["attempt_id"] == attempt]
            allocations = [row for row in snapshot["allocations"] if row["attempt_id"] == attempt]
            leases = [row for row in snapshot["leases"] if row["attempt_id"] == attempt]
            if len(actual) != 1 or actual[0]["state"] != "SUCCEEDED" or not allocations or any(row["state"] != "RELEASED" for row in allocations) or not leases or any(not row["revoked_at"] for row in leases):
                raise Blocked("canonical terminal state or allocations do not agree")
            record.update(status="VERIFIED", candidate_sha=integration["candidate_sha"], integrated_sha=integration["integrated_sha"], verification=verification,
                          raw_artifacts=[{"path": str(journal / name), "sha256": sha(journal / name)} for name in ("stdout.ndjson", "stderr.log", "launch-receipt.json", "stop.json", "result.json", "envelope.json", "execution-bindings.json")])
        observations = [row for row in policy.records if row["kind"] == "UPSTREAM_OBSERVATION"]
        if not observations or not all(policy.per_executor[key] >= 1 for key in ("dsh", "claude")) or policy.uncertain or any(not row["provider_response_model_matches"] or row["upstream_status"] != 200 or not row["message_stop_observed"] or not row["usage"] for row in observations):
            raise Blocked("provider transport/model/usage closure is not fully established")
        report["status"] = "VERIFIED"
        report["qualified_scope"] = "two actual isolated native code leaf tasks, independent six-case verifiers each, fenced FINALIZED Git integration; not monetary or full-host egress qualification"
    except BaseException as error:
        report["status"] = "BLOCKED" if isinstance(error, Blocked) else "FAILED"
        report["errors"].append({"type": type(error).__name__, "message": str(error) if isinstance(error, Blocked) else "actual runner error; preserve private logs and scoped HTTP evidence",
            "traceback_frames": [{"file": frame.f_code.co_filename, "line": line, "function": frame.f_code.co_name}
                                 for frame, line in traceback.walk_tb(error.__traceback__)]})
    finally:
        if api and report["status"] != "VERIFIED":
            for project, attempt in active:
                try:
                    actual = api.data("GET", f"/attempts/{attempt}?project_id={project}")
                    if actual["state"] not in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                        status, value = api.request("POST", f"/attempts/{attempt}/cancel", {
                            "project_id": project, "expected_revision": actual["revision"],
                            "reason": "A00 finite dual-leaf experiment stopped after preserved failure"},
                            allowed_error=True)
                        cancellation = {"attempt_id": attempt,
                            "http_status": status, "result": value,
                            "stop_or_merge_completion_not_inferred": True}
                        if status < 400:
                            release_cache = {}
                            def read_cancelled_attempt(timeout):
                                _, reply = api.request("GET", f"/attempts/{attempt}?project_id={project}", timeout=timeout)
                                if not isinstance(reply.get("data"), dict):
                                    raise Blocked("cleanup attempt response lacks actual data")
                                return reply["data"]
                            def read_release_and_ack(last, timeout):
                                if not release_cache.get("resource_release_observed") or not release_cache.get("lease_revoked_observed"):
                                    _, reply = api.request("GET", f"/projects/{project}/snapshot", timeout=timeout)
                                    snapshot = reply["data"]
                                    allocations = [row for row in snapshot["allocations"] if row["attempt_id"] == attempt]
                                    leases = [row for row in snapshot["leases"] if row["attempt_id"] == attempt]
                                    release_cache.update(resource_release_observed=bool(allocations) and all(row["state"] == "RELEASED" for row in allocations),
                                        lease_revoked_observed=bool(leases) and all(row["revoked_at"] for row in leases),
                                        allocation_rows=len(allocations), lease_rows=len(leases), snapshot_revision=snapshot["revision"], snapshot_as_of=snapshot["as_of"])
                                journal = shared_state_root(manifest) / "attempts" / attempt
                                return {**release_cache, "terminal_ack": terminal_ack(journal, last)}
                            cancellation["terminal_wait"] = await_cancel_terminal(read_cancelled_attempt, read_release_and_ack)
                        report.setdefault("failure_cancellation", []).append(cancellation)
                except BaseException as error:
                    report.setdefault("failure_cancellation", []).append({"attempt_id": attempt,
                        "error_type": type(error).__name__, "state": "UNKNOWN_PRESERVED"})
        for kind, (process, log, identity) in processes.items():
            try:
                if process.poll() is None:
                    if fingerprint(process.pid) != identity:
                        raise Blocked("owned Worker fingerprint changed; refuse signalling")
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        if fingerprint(process.pid) != identity:
                            raise Blocked("owned Worker fingerprint changed before bounded kill")
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                report["shutdown"][kind] = {"exited": True, "returncode": process.returncode, "identity": identity}
            except BaseException as error:
                report["shutdown"][kind] = {"exited": False, "error_type": type(error).__name__}
                report["status"] = "INCONCLUSIVE"
            log.close()
        if forwarder:
            report["forwarder"] = forwarder.close()
            report.update(report["forwarder"]["delivery"])
        else:
            report.update(delivery_projection([], []))
        report["real_provider_reservations"] = forwarder.policy.total if forwarder else 0
        save(output / "receipt.json", report)
    print(json.dumps({"receipt": str(output / "receipt.json"), "status": report["status"], "real_provider_reservations": report["real_provider_reservations"]}))
    return 0 if report["status"] == "VERIFIED" else 1


def selftest():
    # No provider, pricing HTTP, real credential, API, DB or native process.
    cases = []
    raw = json.dumps({"model": MODEL, "stream": True, "max_tokens": MAX_OUTPUT, "messages": [{"role": "user", "content": "NO_MODEL_FIXTURE"}]}).encode()
    def check(name, callback):
        try:
            callback()
        except Blocked:
            cases.append({"name": name, "status": "VERIFIED", "upstream_calls": 0})
        else:
            raise AssertionError("negative boundary unexpectedly accepted: " + name)
    policy = ForwardPolicy(None, lambda: dict(EXPECTED_PRICING))
    assert request_limits({}) == policy.limits == {"total_requests": 12, "per_executor_requests": 6}
    low_limits = request_limits({"request_limits": {"total_requests": 10, "per_executor_requests": 5}})
    lower = ForwardPolicy(None, lambda: dict(EXPECTED_PRICING), limits=low_limits)
    lower.activate("dsh");lower.activate("claude")
    for _ in range(5):
        identity, _ = lower.reserve("claude", raw)
        lower.settle(identity, True, {"input_tokens": 1, "output_tokens": 1}, {"upstream_status": 200, "provider_response_model_matches": True, "real_upstream_http_open_attempted": False})
    check("reduced_per_executor_5_actual_reserve_6_refused", lambda: lower.reserve("claude", raw))
    for _ in range(5):
        identity, _ = lower.reserve("dsh", raw)
        lower.settle(identity, True, {"input_tokens": 1, "output_tokens": 1}, {"upstream_status": 200, "provider_response_model_matches": True, "real_upstream_http_open_attempted": False})
    assert lower.total == 10 and lower.total * RESERVE_USD == 100 and lower.limits == low_limits
    check("reduced_total_10_actual_reserve_11_refused", lambda: lower.reserve("dsh", raw))
    independent_total = ForwardPolicy(None, lambda: dict(EXPECTED_PRICING), limits={"total_requests": 1, "per_executor_requests": 5})
    independent_total.activate("dsh");independent_total.activate("claude")
    identity, _ = independent_total.reserve("claude", raw)
    independent_total.settle(identity, True, {"input_tokens": 1, "output_tokens": 1}, {"upstream_status": 200, "provider_response_model_matches": True})
    check("lower_global_cap_blocks_other_executor_before_its_own_cap", lambda: independent_total.reserve("dsh", raw))
    for index, value in enumerate((None, {"total_requests": 13, "per_executor_requests": 5},
            {"total_requests": 10, "per_executor_requests": 7}, {"total_requests": True, "per_executor_requests": 5},
            {"total_requests": 10, "per_executor_requests": False}, {"total_requests": 10.0, "per_executor_requests": 5},
            {"total_requests": "10", "per_executor_requests": 5}, {"total_requests": 0, "per_executor_requests": 5},
            {"total_requests": 10, "per_executor_requests": 5, "unknown": 1}, {"total_requests": 10})):
        check("invalid_request_limits_" + str(index), lambda value=value: request_limits({"request_limits": value}))
    cases.append({"name": "default_12_6_compatible_lower_10_5_reserves_100USD_fixture_only", "status": "VERIFIED",
                  "fixture_reservations": lower.total, "real_provider_calls": 0})
    policy.activate("claude")
    wrong = json.loads(raw); wrong["model"] = "unapproved-small-or-fallback"
    check("wrong_model_zero_upstream", lambda: policy.reserve("claude", json.dumps(wrong).encode()))
    excessive = json.loads(raw); excessive["max_tokens"] = MAX_OUTPUT + 1
    check("excess_output_zero_upstream", lambda: policy.reserve("claude", json.dumps(excessive).encode()))
    check("oversized_input_zero_upstream", lambda: policy.reserve("claude", b"x" * (MAX_INPUT + 1)))
    server_tool = json.loads(raw); server_tool["tools"] = [{"type": "web_search_20250305", "name": "web_search"}]
    check("paid_server_search_zero_upstream", lambda: policy.reserve("claude", json.dumps(server_tool).encode()))
    policy.per_executor["claude"] = PER_EXECUTOR
    check("per_executor_count_zero_upstream", lambda: policy.reserve("claude", raw))
    policy.per_executor["claude"] = 0; policy.total = MAX_REQUESTS
    check("global_count_zero_upstream", lambda: policy.reserve("claude", raw))
    policy.total = 0; policy.inflight = 1
    check("inflight_zero_upstream", lambda: policy.reserve("claude", raw))
    policy.inflight = 0; policy.deadlines["claude"] = time.monotonic() - 1
    check("wall_zero_upstream", lambda: policy.reserve("claude", raw))
    for url in ("http://127.0.0.1:8787", "http://192.0.2.1:18877", "http://127.0.0.1:17891"):
        check("production_origin_refused_" + url, lambda url=url: origin(url))
    assert executor_order({}) == ["dsh", "claude"]
    assert executor_order({"executor_order": ["claude", "dsh"]}) == ["claude", "dsh"]
    cases.append({"name": "executor_order_default_and_reverse", "status": "VERIFIED", "actual_provider_calls": 0})
    check("duplicate_executor_order_refused", lambda: executor_order({"executor_order": ["claude", "claude"]}))
    with tempfile.TemporaryDirectory(prefix="forgeflow-next-wrapper-selftest-") as folder:
        root = Path(folder)
        log = root / "verification-raw.log"
        log.write_text("NO_MODEL_FIXTURE actual immutable verification log bytes\n")
        binding = {"attempt_id": "fixture-attempt", "generation": 1, "candidate_sha": "b" * 40,
                   "integrated_sha": "a" * 40, "source_hash": "c" * 40}
        wrapper = {"artifact_root": str(root), "new_sha": "a" * 40, "source_tree_oid": "c" * 40,
                   "verification_receipt_hash": "d" * 64,
                   "verification": {"binding": binding, "total": 6, "log_path": log.name, "log_hash": sha(log)},
                   "diff_manifest_hash": "e" * 64, "source_content_algorithm": "forgeflow.source-content.v1",
                   "source_content_sha256": "f" * 64, "integration_workspace": "fixture-integration", "verifier_scratch_root": "fixture-scratch"}
        durable_path = root / "forgeflow-verification.json"
        save(durable_path, wrapper)
        intent = {"attempt_id": "fixture-attempt", "generation": 1, "candidate_sha": "b" * 40,
                  "integrated_sha": "a" * 40, "receipt": {**copy.deepcopy(wrapper), "commit_decided": True, "ref_updated": True}}
        assert verify_final_wrapper(intent)["full_wrapper_match"]
        cases.append({"name": "actual_full_durable_wrapper_matches_API_minus_two_finalization_flags", "status": "VERIFIED", "actual_provider_calls": 0})
        bad_nested = copy.deepcopy(intent);bad_nested["receipt"]["verification"]["total"] = 7
        bad_new_sha = copy.deepcopy(intent);bad_new_sha["receipt"]["new_sha"] = "0" * 40
        bad_hash = copy.deepcopy(intent);bad_hash["receipt"]["verification_receipt_hash"] = "0" * 64
        bad_candidate = copy.deepcopy(intent);bad_candidate["candidate_sha"] = "0" * 40
        for name, bad in (("wrapper_wrong_nested", bad_nested), ("wrapper_wrong_new_sha", bad_new_sha),
                          ("wrapper_wrong_hash", bad_hash), ("wrapper_wrong_candidate_binding", bad_candidate)):
            check(name, lambda bad=bad: verify_final_wrapper(bad))
        log.write_text("NO_MODEL_FIXTURE altered log bytes\n")
        check("wrapper_actual_log_bytes_changed", lambda: verify_final_wrapper(intent))
        save(root / "verification-receipt.json", wrapper["verification"])
        durable_path.unlink()
        try:
            verify_final_wrapper(intent)
        except FileNotFoundError:
            cases.append({"name": "missing_final_wrapper_never_uses_scratch_receipt_name", "status": "VERIFIED", "actual_provider_calls": 0})
        else:
            raise AssertionError("missing immutable final wrapper accepted")
    assert code_scope({}) == {"mode": "EXACT_FILE", "subject": "calculator.py", "owner_include": ["calculator.py"], "write_set": ["calculator.py"]}
    assert code_scope({"code_scope_mode": "OWNED_DIRECTORY"}) == {"mode": "OWNED_DIRECTORY", "subject": "owned/calculator.py", "owner_include": ["owned/"], "write_set": ["owned/"]}
    mixed = {"code_scope_modes": {"dsh": "EXACT_FILE", "claude": "OWNED_DIRECTORY"}}
    assert code_scope(mixed, "dsh")["subject"] == "calculator.py" and code_scope(mixed, "dsh")["write_set"] == ["calculator.py"]
    assert code_scope(mixed, "claude")["subject"] == "owned/calculator.py" and code_scope(mixed, "claude")["write_set"] == ["owned/"]
    assert all(code_scope({}, kind)["mode"] == "EXACT_FILE" for kind in ("dsh", "claude"))
    assert all(code_scope({"code_scope_mode": "OWNED_DIRECTORY"}, kind)["mode"] == "OWNED_DIRECTORY" for kind in ("dsh", "claude"))
    for index, modes in enumerate((None, {}, {"dsh": "EXACT_FILE"}, {"dsh": "EXACT_FILE", "claude": "OWNED_DIRECTORY", "other": "EXACT_FILE"},
            {"dsh": "UNKNOWN", "claude": "OWNED_DIRECTORY"}, {"dsh": True, "claude": "OWNED_DIRECTORY"})):
        check("invalid_per_driver_scope_map_" + str(index), lambda modes=modes: code_scope({"code_scope_modes": modes}, "dsh"))
    check("per_driver_scope_missing_selector_refused", lambda: code_scope(mixed))
    check("unknown_code_scope_refused", lambda: code_scope({"code_scope_mode": "UNBOUNDED"}))
    require_read_edit_tools({"tools_allowlist": ["Read", "Edit"]})
    check("owned_profile_Bash_refused", lambda: require_read_edit_tools({"tools_allowlist": ["Read", "Edit", "Bash"]}))
    check("owned_profile_Write_refused", lambda: require_read_edit_tools({"tools_allowlist": ["Read", "Write"]}))
    with tempfile.TemporaryDirectory(prefix="forgeflow-next-owned-scope-selftest-") as folder:
        fixture = Path(folder)
        good = "def add(a,b):\n    if type(a) is not int or type(b) is not int: raise TypeError('integers required')\n    return a+b\n"
        for executor in ("dsh", "claude"):
            scope = code_scope(mixed, executor)
            mode = scope["mode"]
            root = fixture / mode
            root.mkdir()
            (root / "owned").mkdir()
            (root / scope["subject"]).write_text(good)
            other = "owned/calculator.py" if scope["subject"] == "calculator.py" else "calculator.py"
            (root / other).write_text("raise RuntimeError('wrong subject must never be imported')\n")
            total = 0
            for role in CASE_NAMES:
                report = root / (role + ".json")
                done = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c", ORACLE], cwd=root,
                    env={"PATH": "/usr/bin:/bin", "NEXT_ORACLE_SUBJECT": scope["subject"], "NEXT_ORACLE_ROLE": role,
                         "FORGEFLOW_REPORT_PATH": str(report), "FORGEFLOW_EVIDENCE_BINDING": "{}"}, capture_output=True, timeout=5)
                assert done.returncode == 0
                parsed = json.loads(report.read_text())
                assert len(parsed["cases"]) == 2 and all(row["outcome"] == "passed" for row in parsed["cases"])
                total += len(parsed["cases"])
            assert total == 6
            bad_subject = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c", ORACLE], cwd=root,
                env={"PATH": "/usr/bin:/bin", "NEXT_ORACLE_SUBJECT": "../outside.py"}, capture_output=True, timeout=5)
            assert bad_subject.returncode != 0 and b"undeclared oracle subject" in bad_subject.stderr
            cases.append({"name": "scope_" + mode + "_actual_oracle_subject_3roles_6cases_and_undeclared_path_denied", "status": "VERIFIED",
                          "executor": executor, "subject": scope["subject"], "owner_include": scope["owner_include"], "write_set": scope["write_set"], "actual_provider_calls": 0})
        native_raw = fixture / "native.ndjson"
        workspace = fixture / "OWNED_DIRECTORY"
        use = {"type": "assistant", "session_id": "fixture-session", "message": {"content": [{"type": "tool_use", "name": "Edit", "id": "edit-1", "input": {"file_path": "owned/calculator.py"}}]}}
        result = {"type": "user", "session_id": "fixture-session", "message": {"content": [{"type": "tool_result", "tool_use_id": "edit-1", "is_error": False, "content": "NO_MODEL_FIXTURE"}]}}
        def pair(events):
            native_raw.write_text("\n".join(json.dumps(value) for value in events) + "\n")
            return native_edit_pair(native_raw, workspace, "owned/calculator.py", "fixture-session")
        assert pair([use, result])["status"] == "VERIFIED"
        failed = copy.deepcopy(result);failed["message"]["content"][0]["is_error"] = True
        wrong_id = copy.deepcopy(result);wrong_id["message"]["content"][0]["tool_use_id"] = "different-id"
        wrong_file = copy.deepcopy(use);wrong_file["message"]["content"][0]["input"]["file_path"] = "calculator.py"
        forbidden = copy.deepcopy(use);forbidden["message"]["content"][0].update(name="Bash", id="bash-1")
        assert all(pair(events)["status"] == "FAILED" for events in ([use, failed], [use, wrong_id], [result, use], [wrong_file, result], [use, result, forbidden]))
        cases.append({"name": "complete_native_Edit_same_id_success_and_5_error_order_path_tool_negatives", "status": "VERIFIED", "actual_provider_calls": 0})
    fake_time = [0.0]
    sequence = iter([{"attempt_id": "fixture", "state": "STOPPING", "revision": 2},
                     {"attempt_id": "fixture", "state": "CANCELLED", "revision": 3, "result": {"completion_reason": "CANCELLED"}}])
    terminal = await_cancel_terminal(lambda timeout: next(sequence), lambda attempt, timeout: {
        "resource_release_observed": True, "lease_revoked_observed": True, "terminal_ack": {"terminal_confirmed": True}}, clock=lambda: fake_time[0],
                                    pause=lambda seconds: fake_time.__setitem__(0, fake_time[0] + seconds))
    assert terminal["terminal_observed"] and terminal["state"] == "CANCELLED" and terminal["actual_attempt"]["revision"] == 3 and terminal["polls"] == 2
    cases.append({"name": "cancel_STOPPING_then_CANCELLED_waits_for_real_attempt_fixture", "status": "VERIFIED", "actual_provider_calls": 0})
    fake_time[0] = 0.0
    uncertain = await_cancel_terminal(lambda timeout: {"attempt_id": "fixture", "state": "STOPPING", "revision": 2}, lambda attempt, timeout: {},
        clock=lambda: fake_time[0], pause=lambda seconds: fake_time.__setitem__(0, fake_time[0] + seconds))
    assert uncertain["status"] == "UNKNOWN" and not uncertain["terminal_observed"] and uncertain["state"] == "STOPPING"
    assert uncertain["elapsed_seconds"] == 30 and uncertain["resource_release_observed"] is False
    cases.append({"name": "cancel_30s_STILL_STOPPING_preserves_UNKNOWN_no_release_claim", "status": "VERIFIED",
                  "clock": "injected_NO_MODEL_FIXTURE", "actual_provider_calls": 0})
    fake_time[0] = 0.0
    incomplete = await_cancel_terminal(lambda timeout: {"attempt_id": "fixture", "state": "CANCELLED", "revision": 3},
        lambda attempt, timeout: {"resource_release_observed": False, "lease_revoked_observed": True, "terminal_ack": None},
        clock=lambda: fake_time[0], pause=lambda seconds: fake_time.__setitem__(0, fake_time[0] + seconds))
    assert incomplete["status"] == "UNKNOWN" and incomplete["terminal_observed"] and not incomplete["resource_release_observed"] and incomplete["terminal_ack"] is None
    with tempfile.TemporaryDirectory(prefix="forgeflow-next-ack-selftest-") as folder:
        journal = Path(folder)
        identity = {key: "fixture" for key in ("project_id", "task_id", "attempt_id", "lease_id", "worker_id", "operation_id", "base_sha")}
        identity.update(task_revision=1, generation=1, state="CANCELLED")
        original = {"event_id": "old-author-result", "terminal_confirmed": False, "controller_response": {"data": {**identity, "state": "VERIFYING"}}}
        save(journal / "result-ack.json", original)
        old_hash = sha(journal / "result-ack.json")
        assert terminal_ack(journal, identity) is None
        save(journal / "result-post-stop-ack.json", {"event_id": "new-stop-confirmation", "terminal_confirmed": True, "controller_response": {"data": {"terminal": identity}}})
        ack = terminal_ack(journal, identity)
        assert ack["path"].endswith("result-post-stop-ack.json") and sha(journal / "result-ack.json") == old_hash
    cases.append({"name": "terminal_without_release_ACK_unknown_new_ACK_preserves_original", "status": "VERIFIED", "actual_provider_calls": 0})
    check("missing_shared_state_mode_refused", lambda: shared_state_root({}))
    with tempfile.TemporaryDirectory(prefix="forgeflow-next-shared-state-selftest-") as folder:
        root = Path(folder).resolve()
        check("shared_root_without_explicit_mode_refused", lambda: shared_state_root({"server_data_root": str(root)}))
        configured = {"local_state_mode": "SHARED_SERVER_WORKER_ROOT", "server_data_root": str(root)}
        check("missing_shared_root_refused", lambda: shared_state_root({**configured, "server_data_root": str(root / "missing")}))
        fixture = subprocess.Popen(["/usr/bin/python3", "-B", "-c", "import time;print('READY',flush=True);time.sleep(10)"],
            env={"PATH": "/usr/bin:/bin", "FORGEFLOW_DATA_ROOT": str(root), "UNRELATED_SECRET": "DO_NOT_EXPORT_PROCESS_ENV"},
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            assert fixture.stdout.readline() == b"READY\n"
            identity_input = {**configured, "server_pid": fixture.pid, "server_executable_sha256": sha("/usr/bin/python3")}
            observed = server_identity(identity_input)
            assert observed["data_root"] == str(root) and "DO_NOT_EXPORT_PROCESS_ENV" not in json.dumps(observed)
            mismatched = root / "wrong-state"
            mismatched.mkdir()
            check("pinned_process_actual_data_root_mismatch_refused", lambda: server_identity({**identity_input, "server_data_root": str(mismatched)}))
            cases.append({"name": "pinned_process_shared_state_env_alignment_no_unrelated_env_export", "status": "VERIFIED",
                          "execution_kind": "NO_MODEL_FIXTURE", "actual_provider_calls": 0})
        finally:
            fixture.terminate()
            fixture.wait(timeout=3)
            fixture.stdout.close()
    with tempfile.TemporaryDirectory(prefix="forgeflow-next-poll-selftest-") as folder:
        audit = API("http://127.0.0.1:39999", "NO_MODEL_FIXTURE_TOKEN", Path(folder))
        def log(method, status, data):
            value = {"data": data}
            audit.audit(method, "/attempts/fixture", status, json.dumps(value).encode(), value, 0.001)
        log("GET", 200, {"attempt_id": "fixture", "state": "RUNNING", "revision": 1})
        log("GET", 200, {"attempt_id": "fixture", "state": "RUNNING", "revision": 1})
        log("GET", 200, {"attempt_id": "fixture", "state": "VERIFYING", "revision": 2})
        log("GET", 409, {"code": "LEASE_STALE", "reason": "actual negative fixture"})
        log("GET", 409, {"code": "LEASE_STALE", "reason": "actual negative fixture"})
        log("POST", 200, {"operation_id": "command-a"})
        log("POST", 200, {"operation_id": "command-a"})
        records = list(Path(folder).glob("http-*.json"))
        polls = [json.loads(line) for line in (Path(folder) / "http-polls.jsonl").read_text().splitlines()]
        assert len(records) == 6 and len(polls) == 1 and polls[0]["first_full_record"] == "http-0001.json"
        assert (Path(folder) / "http-0003.json").exists()
        assert (Path(folder) / "http-0004.json").exists() and (Path(folder) / "http-0005.json").exists()
        assert (Path(folder) / "http-0006.json").exists() and (Path(folder) / "http-0007.json").exists()
        cases.append({"name": "stable_GET_JSONL_state_change_errors_commands_preserved", "status": "VERIFIED",
                      "requests": 7, "full_records": 6, "compact_poll_samples": 1, "actual_provider_calls": 0})
    # Exercise the real HTTP handler against one private localhost SSE fixture.
    # test_transport is injected here only; no manifest/execute option exposes it.
    hit_count = [0]
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            hit_count[0] += 1
            self.rfile.read(int(self.headers["Content-Length"]))
            frames = [{"type": "message_start", "message": {"model": MODEL, "usage": {"input_tokens": 3, "output_tokens": 0}}},
                      {"type": "message_delta", "usage": {"output_tokens": 2}}, {"type": "message_stop"}]
            data = b"".join(b"data: " + json.dumps(frame).encode() + b"\n\n" for frame in frames)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    fake = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    fake_thread = threading.Thread(target=fake.serve_forever, daemon=True)
    fake_thread.start()
    with tempfile.TemporaryDirectory(prefix="forgeflow-next-no-model-selftest-") as folder:
        local_policy = ForwardPolicy(None, lambda: dict(EXPECTED_PRICING))
        local_policy.activate("claude")
        def local_transport(request, timeout):
            local = urllib.request.Request(f"http://127.0.0.1:{fake.server_port}/v1/messages", data=request.data,
                                           method="POST", headers={"Content-Type": "application/json"})
            return opener().open(local, timeout=timeout)
        forward = Forwarder(0, {"claude": "NO_MODEL_FIXTURE_ALIAS", "dsh": "NO_MODEL_DSH_ALIAS"},
                            "NO_MODEL_FIXTURE_UPSTREAM", Path(folder), local_policy, test_transport=local_transport)
        forward.start()
        def call(payload, target="/v1/messages", method="POST", token="NO_MODEL_FIXTURE_ALIAS"):
            request = urllib.request.Request(f"http://127.0.0.1:{forward.server.server_port}" + target, data=payload,
                method=method, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            try:
                response = opener().open(request, timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, response.read()
        try:
            for name, payload in (("http_wrong_model", json.dumps(wrong).encode()), ("http_excess_output", json.dumps(excessive).encode())):
                before = hit_count[0]
                http, _ = call(payload)
                assert http >= 400 and hit_count[0] == before == 0
                cases.append({"name": name, "status": "VERIFIED", "fixture_upstream_delta": 0, "actual_provider_calls": 0})
            for target in ("/v1/messages?beta=true&beta=true", "/v1/messages?beta=false", "/v1/messages?credential=DO_NOT_LOG_QUERY_SECRET"):
                http, _ = call(raw, target=target)
                assert http == 404 and hit_count[0] == 0
            http, _ = call(raw, method="GET")
            assert http == 405 and hit_count[0] == 0
            http, _ = call(raw, token="NO_MODEL_BAD_ALIAS")
            assert http == 403 and hit_count[0] == 0
            assert "DO_NOT_LOG_QUERY_SECRET" not in json.dumps(forward.records)
            assert any(row["http_method"] == "GET" for row in forward.records)
            cases.append({"name": "HTTP_unknown_duplicate_query_method_auth_zero_upstream_and_query_redacted", "status": "VERIFIED", "negative_denominator": 5, "actual_provider_calls": 0})
            http, _ = call(raw)
            assert http == 200
            stop_at = time.monotonic() + 3
            while not any(row["kind"] == "UPSTREAM_OBSERVATION" for row in local_policy.records) and time.monotonic() < stop_at:
                time.sleep(0.01)
            observed = next(row for row in local_policy.records if row["kind"] == "UPSTREAM_OBSERVATION")
            assert hit_count[0] == 1 and observed["usage"] == {"input_tokens": 3, "output_tokens": 2} and observed["transport_complete"]
            cases.append({"name": "http_fixture_SSE_usage_readback", "status": "VERIFIED", "fixture_upstream_calls": 1, "actual_provider_calls": 0})
            projection = delivery_projection(forward.real_attempt_ids, local_policy.records)
            assert local_policy.total == 1 and projection["real_provider_calls"] == projection["real_upstream_http_attempts"] == 0
            assert projection["responses_with_matching_model_usage"] == {"count": 0, "denominator": 0,
                "criteria": "HTTP200, matching GLM-5.3 response model, numeric input/output usage and message_stop"}
            assert projection["actual_supplier_debit_status"] == "UNKNOWN" and projection["actual_supplier_debit_usd"] is None
            assert delivery_projection([], [])["real_upstream_http_attempts"] == 0
            cases.append({"name": "fixture_reservation_usage_never_become_real_calls_or_billing", "status": "VERIFIED",
                          "fixture_reservations": 1, "real_provider_calls": 0, "real_upstream_http_attempts": 0,
                          "real_response_denominator": 0, "supplier_final_debit": "UNKNOWN"})
            http, _ = call(raw, target="/v1/messages?beta=true")
            assert http == 200 and hit_count[0] == 2
            cases.append({"name": "exact_beta_true_query_accepts_same_model_budget_auth", "status": "VERIFIED",
                          "fixture_upstream_calls": 1, "actual_provider_calls": 0})
            local_policy.per_executor["claude"] = PER_EXECUTOR
            before = hit_count[0]
            http, _ = call(raw)
            assert http >= 400 and hit_count[0] == before
            cases.append({"name": "http_count_exhaustion_zero_additional_upstream", "status": "VERIFIED", "fixture_upstream_delta": 0, "actual_provider_calls": 0})
        finally:
            forward.close()
            fake.shutdown()
            fake.server_close()
            fake_thread.join(3)
    print(json.dumps({"schema_version": "forgeflow.next.dual-leaf.selftest.v1", "execution_kind": "NO_MODEL_FIXTURE", "status": "VERIFIED", "cases": cases,
                      "denominator": len(cases), "actual_provider_calls": 0, "external_network_requests": 0,
                      "local_fixture_upstream_requests": hit_count[0],
                      "not_proven": ["real pricing endpoint", "real DSH/Claude model/API/Worker/Verify/Git chain", "financial enforcement"]}))
    return 0


def capture_claude(args):
    """Real pinned CLI, synthetic SSE only, in a route-less private netns."""
    program = Path(args.capture_claude_elf).resolve()
    if not program.is_file() or sha(program) != args.capture_claude_sha256 or program.open("rb").read(4) != b"\x7fELF":
        raise Blocked("capture requires the exact pinned real Linux Claude ELF")
    folder = Path(args.capture_output).resolve()
    if not args.offline_netns_child:
        if folder.exists():
            raise Blocked("capture evidence directory must be new; previous evidence preserved")
        folder.mkdir(parents=True, mode=0o700)
        parent_netns = os.readlink("/proc/self/ns/net")
        command = ["/usr/bin/bwrap", "--unshare-user", "--unshare-net",
                   "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
                   "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                   "--ro-bind", str(program), str(program),
                   "--ro-bind", str(Path(__file__).resolve()), str(Path(__file__).resolve()),
                   "--bind", str(folder), str(folder), "--chdir", str(folder),
                   "--", "/usr/bin/python3", "-B", str(Path(__file__).resolve()),
                   "--capture-claude-elf", str(program), "--capture-claude-sha256", args.capture_claude_sha256,
                   "--capture-output", str(folder), "--offline-netns-child", "--parent-netns", parent_netns]
        result = subprocess.run(command, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, capture_output=True, timeout=65)
        save(folder / "namespace-launch.json", {"argv": command, "exit_code": result.returncode,
             "stdout": result.stdout.decode("utf-8", "replace"), "stderr": result.stderr.decode("utf-8", "replace"),
             "execution_kind": "NO_MODEL_FIXTURE", "real_provider_calls": 0}, private=True)
        print(json.dumps({"execution_kind": "NO_MODEL_FIXTURE", "capture_receipt": str(folder / "capture-receipt.json"),
                          "namespace_exit_code": result.returncode, "actual_provider_calls": 0}))
        return result.returncode
    namespace = os.readlink("/proc/self/ns/net")
    interfaces = [line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    if not args.parent_netns or namespace == args.parent_netns or any(name != "lo" for name in interfaces):
        raise Blocked("capture must execute in an isolated loopback-only network namespace")
    if len(Path("/proc/net/route").read_text().splitlines()) > 1:
        raise Blocked("capture namespace unexpectedly has an upstream route")
    import io
    frames = [
        {"type": "message_start", "message": {"id": "msg_no_model_fixture", "type": "message", "role": "assistant", "model": MODEL, "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 0}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "NO_MODEL_FIXTURE"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 2}},
        {"type": "message_stop"},
    ]
    wire = b"".join(("event: " + value["type"] + "\ndata: " + json.dumps(value) + "\n\n").encode() for value in frames)
    fixture_calls = []
    class FixtureResponse:
        status = 200
        headers = {"Content-Type": "text/event-stream"}
        def __init__(self):
            self.stream = io.BytesIO(wire)
        def read1(self, count):
            return self.stream.read(count)
        def close(self):
            self.stream.close()
    def transport(request, timeout):
        parsed = urllib.parse.urlsplit(request.full_url)
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        fixture_calls.append({"execution_kind": "NO_MODEL_FIXTURE", "request_sha256": hashlib.sha256(request.data).hexdigest(),
                              **target_facts(target, "POST")})
        return FixtureResponse()
    policy = ForwardPolicy(folder / "fixture-policy.jsonl", lambda: dict(EXPECTED_PRICING))
    policy.activate("claude")
    forward = Forwarder(0, {"claude": "NO_MODEL_CAPTURE_ALIAS", "dsh": "NO_MODEL_UNUSED_DSH_ALIAS"},
                        "NO_MODEL_FIXTURE_NO_REAL_CREDENTIAL", folder, policy, test_transport=transport)
    home = folder / "empty-home"
    home.mkdir(mode=0o700)
    command = [str(program), "--bare", "--print", "--output-format", "stream-json", "--verbose",
               "--include-partial-messages", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
               "--model", MODEL, "--max-budget-usd", "1.00", "--tools", "", "--allowedTools", "",
               "--permission-mode", "dontAsk", "--permission-prompts", "none", "--no-session-persistence"]
    forward.start()
    try:
        try:
            result = subprocess.run(command, input=b"Return NO_MODEL_FIXTURE without tools.\n", cwd=folder,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home),
                     "ANTHROPIC_AUTH_TOKEN": "NO_MODEL_CAPTURE_ALIAS", "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{forward.server.server_port}",
                     "CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(MAX_OUTPUT),
                     "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}, capture_output=True, timeout=45)
            cli_exit, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            cli_exit, stdout, stderr = None, error.stdout or b"", error.stderr or b""
        (folder / "claude.stdout.ndjson").write_bytes(stdout.replace(b"NO_MODEL_CAPTURE_ALIAS", b"<FIXTURE_ALIAS>"))
        (folder / "claude.stderr.log").write_bytes(stderr.replace(b"NO_MODEL_CAPTURE_ALIAS", b"<FIXTURE_ALIAS>"))
    finally:
        closure = forward.close()
    receipt = {"execution_kind": "NO_MODEL_FIXTURE", "harness_sha256": sha(__file__), "program": str(program),
               "program_sha256": sha(program), "argv": command, "cli_exit_code": cli_exit,
               "parent_netns": args.parent_netns, "capture_netns": namespace, "interfaces": interfaces,
               "default_routes": [], "personal_home_or_settings_read": False, "real_credentials_supplied": False,
               "real_provider_calls": 0, "fixture_transport_calls": len(fixture_calls),
               "fixture_transport_requests": fixture_calls,
               "rejected_targets": closure["rejected_requests"], "delivery": closure["delivery"],
               "stdout_sha256": sha(folder / "claude.stdout.ndjson"), "stderr_sha256": sha(folder / "claude.stderr.log"),
               "not_proven": ["real model response", "live provider authentication", "native business chain"]}
    save(folder / "capture-receipt.json", receipt, private=True)
    print(json.dumps({"capture_receipt": str(folder / "capture-receipt.json"), "cli_exit_code": cli_exit,
                      "rejected_targets": receipt["rejected_targets"], "actual_provider_calls": 0}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--run-manifest", type=Path)
    parser.add_argument("--execute", action="store_true", help="A00 only: run admitted real workloads against explicitly isolated actors")
    parser.add_argument("--capture-claude-elf", type=Path, help="capture only against synthetic SSE in an isolated loopback-only netns")
    parser.add_argument("--capture-claude-sha256")
    parser.add_argument("--capture-output", type=Path)
    parser.add_argument("--offline-netns-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.capture_claude_elf:
        if args.selftest or args.execute or args.run_manifest or not args.capture_claude_sha256 or not args.capture_output:
            parser.error("capture requires pinned ELF/hash/new output only; cannot combine with real execution")
        return capture_claude(args)
    if args.selftest:
        if args.execute or args.run_manifest:
            parser.error("--selftest cannot be combined with real run options")
        return selftest()
    if not args.run_manifest:
        if args.execute:
            parser.error("--execute requires --run-manifest")
        print(json.dumps({"status": "NOT_RUN", "reason": "explicit A00 run manifest required; default never calls models/services", "schema_version": SCHEMA}))
        return 0
    manifest = json.loads(args.run_manifest.read_text())
    if not args.execute:
        print(json.dumps(validate_manifest(manifest), ensure_ascii=False))
        return 0
    return execute(manifest)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Blocked, OSError, ValueError, KeyError) as error:
        print(json.dumps({"status": "BLOCKED", "type": type(error).__name__, "message": str(error) if isinstance(error, Blocked) else "run manifest/environment error; no automatic fallback"}), file=sys.stderr)
        raise SystemExit(2)
