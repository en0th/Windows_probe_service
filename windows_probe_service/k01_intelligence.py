"""K01's documented read-only API, behind the local service's pairing token.

Only the saved HTTPS origin and the two documented API paths are used. Browser
session fallback is a separate userscript operation; no browser cookie or token
is accepted, persisted or returned by this module.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
import contextvars
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import http.client
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from probe_models import normalize_host


LOGIN_PATH = "/api/cms/user/login"
CHANGE_PASSWORD_PATH = "/api/v1/account/changepwd"
TRACE_PATH = "/api/v1/threatintelligence/api/traceability"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CACHE_BYTES = 32 * 1024 * 1024
MAX_CACHE_ENTRIES = 128
MAX_INFLIGHT = 16
MAX_QUERY_SECONDS = 65
COUNTS = (10, 20, 50, 100)
_SECRET_KEY = re.compile(r"password|(?:access_|refresh_)?token|cookie|authorization|secret", re.I)

# Correlation id shared by the browser, this service and the K01 transport, so one
# failed query can be followed across probe.jsonl and the userscript trace ring.
_TRACE_ID = contextvars.ContextVar("soar_k01_trace_id", default="")
_TRACE_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,64}")

# Which HTTP stack served the current request; surfaces in transport diagnostics so a
# fallback retry is visible in probe.jsonl instead of silently masquerading as urllib.
_TRANSPORT = contextvars.ContextVar("soar_k01_transport", default="urllib")

# Some K01 gateways ask for a TLS renegotiation after the request body is written.
# OpenSSL 3.x clients (Python 3.11 ssl) refuse it and the server drops the socket, while
# the OS stack (Windows schannel via curl.exe) completes it. When the plain socket dies
# mid-request we retry once over the OS stack instead of failing the whole query.
CURL_FALLBACK_ENV = "SOAR_K01_CURL_FALLBACK"
CURL_TIMEOUT_PAD_SECONDS = 5.0
_RENEGOTIATION_ERRORS = (
    http.client.RemoteDisconnected,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    ssl.SSLEOFError,
)

# Actionable hints keyed by transport diagnostic code; appended to the caller-facing
# message so the userscript log alone is enough to tell the failure classes apart.
# K01 business rejections that have a specific operator action. Mapping these to
# ``K01_FRONTEND_REQUIRED`` also lets a configured, already-logged-in K01 page
# serve the query through the session fallback instead of leaving the operator
# with the generic "query rejected" message.
_QUERY_RECOVERY = {
    10140: ("api_initial_password_required", "initial_password_not_changed"),
}

_TRANSPORT_HINTS = {
    "certificate_verification_failed":
        "（证书校验失败：请为该 K01 目标配置可信 CA 文件，或关闭 TLS 校验以信任内网自签证书。）",
    "tls_handshake_failed":
        "（TLS 握手失败：目标端口可能不是 HTTPS 服务，或 TLS 版本/加密套件不匹配。）",
    "connection_timeout":
        "（连接超时：目标主机无响应，常见于防火墙丢弃或路由不通。）",
    "dns_resolution_failed":
        "（域名解析失败：请改用 IP 地址，或确认本机 DNS 能解析该域名。）",
    "connection_refused":
        "（连接被拒绝：目标端口未监听，或 K01 服务未启动。）",
    "network_unreachable":
        "（网络不可达：本机与 K01 网段之间没有路由。）",
    "connection_reset":
        "（连接被重置：对端在收到请求后断开，可能是中间安全设备阻断，或服务端要求 TLS 重协商而 OpenSSL 客户端无法完成；已尝试系统 TLS 栈重试。）",
    "ca_file_error":
        "（CA 文件不可用：请检查 CA 路径、读取权限与证书格式。）",
    "tls_context_error":
        "（TLS 上下文创建失败：请检查系统 OpenSSL 与 CA 配置。）",
    "unexpected_redirect":
        "（目标返回重定向：本地服务拒绝跟随，请在浏览器确认最终可用地址。）",
    "non_json_response":
        "（目标返回非 JSON 内容：常见于登录页/网关拦截页，请检查地址与权限。）",
}


def new_trace_id():
    """Bounded, log-safe correlation id (no PII, no credentials).

    Shaped like the userscript ids (32 hex characters) so both sides of a failing
    request grep to the same token.
    """
    return secrets.token_hex(16)


def normalize_trace_id(value):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value if _TRACE_PATTERN.fullmatch(value) else ""


def set_trace_id(value):
    """Bind a correlation id to the current task/thread context; returns the reset token."""
    return _TRACE_ID.set(normalize_trace_id(value))


def reset_trace_id(token):
    try:
        _TRACE_ID.reset(token)
    except (ValueError, RuntimeError):
        _TRACE_ID.set("")


def current_trace_id():
    return _TRACE_ID.get()


# Build stamp injected by service.py. Every K01 payload carries it so an operator can
# tell from the userscript log alone which exe actually answered a query.
_SERVICE_VERSION = ""


def set_service_version(version):
    global _SERVICE_VERSION
    _SERVICE_VERSION = str(version or "")


class K01Error(Exception):
    def __init__(self, code, message, status=502, *, reason=None, fallback=False,
                 stage=None, diagnostic_code=None, diagnostic=None, upstream_status=None):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
        self.reason, self.fallback = reason, fallback
        self.stage = stage
        self.diagnostic_code = diagnostic_code
        self.diagnostic = diagnostic if isinstance(diagnostic, dict) else {}
        self.upstream_status = upstream_status
        self.trace_id = ""

    def payload(self):
        value = {"success": False, "code": self.code, "message": self.message,
                 "fallbackAllowed": self.fallback, "authSource": "api-account"}
        if _SERVICE_VERSION:
            value["serviceVersion"] = _SERVICE_VERSION
        if self.reason:
            value["reason"] = self.reason
        # Transport forensics must reach the userscript: the local log alone cannot be
        # read by the operator, and the userscript log is the only place a mixed
        # exe/browser failure can be told apart.
        if self.stage:
            value["stage"] = self.stage
        if self.upstream_status is not None:
            value["upstreamStatus"] = self.upstream_status
        if self.diagnostic_code:
            value["diagnosticCode"] = self.diagnostic_code
        if self.diagnostic:
            value["diagnostic"] = self.diagnostic
        trace_id = self.trace_id or current_trace_id()
        if trace_id:
            value["traceId"] = trace_id
        return value


def frontend_required(reason):
    messages = {
        "api_not_configured": "API 账号尚未配置，请使用已登录的 K01 页面查询。",
        "api_login_failed": "API 账号登录未成功，请使用已登录的 K01 页面查询。",
        "api_login_unavailable": "当前 K01 未提供此 API 登录接口，请使用已登录的 K01 页面查询。",
        "api_access_denied": "API 账号无权查询此情报，请使用已登录的 K01 页面查询。",
        "api_endpoint_unavailable": "当前 K01 未提供此正式溯源接口，请使用已登录的 K01 页面查询。",
        "api_initial_password_required": "K01 API 账号仍使用初始密码，请先在 K01 网页端使用该账号登录并修改初始密码，再在本地服务配置中更新 API 密码后重试。",
    }
    return K01Error("K01_FRONTEND_REQUIRED", messages[reason], 409,
                    reason=reason, fallback=True)


def normalized_origin(value):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("invalid K01 baseUrl")
    value = value.strip()
    if not value:
        return ""
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("invalid K01 baseUrl")
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.path not in {"", "/"}
                or parts.query or parts.fragment):
            raise ValueError("invalid K01 baseUrl")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid K01 port")
        hostname = parts.hostname.encode("idna").decode("ascii").lower()
        if ":" in hostname:
            raise ValueError("K01 origin must use IPv4 or a hostname")
        if not re.fullmatch(r"[a-z0-9.-]+", hostname) or hostname.startswith("."):
            raise ValueError("invalid K01 hostname")
        # Numeric-looking malformed addresses must not be silently treated as DNS.
        if re.fullmatch(r"[0-9.]+", hostname):
            if str(ipaddress.IPv4Address(hostname)) != hostname:
                raise ValueError("invalid K01 IPv4")
        else:
            hostname = normalize_host(hostname)
        authority = hostname + (":" + str(port) if port is not None and port != 443 else "")
        return urlunsplit(("https", authority, "", "", ""))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid K01 baseUrl") from exc


@dataclass(frozen=True)
class K01Config:
    base_url: str = ""
    username: str = ""
    password: str = field(default="", repr=False)
    ca_file: str = ""
    timeout_ms: int = 15000
    cache_seconds: int = 600
    verify_tls: bool = True

    @property
    def configured(self):
        return bool(self.base_url and self.username and self.password)

    def public(self):
        return {"baseUrl": self.base_url, "username": self.username,
                "passwordConfigured": bool(self.password), "caFile": self.ca_file,
                "verifyTLS": self.verify_tls, "timeoutMs": self.timeout_ms,
                "cacheSeconds": self.cache_seconds}

    def stored(self):
        value = self.public()
        value.pop("passwordConfigured")
        value["password"] = self.password
        return value


def config_from_payload(payload, previous=None):
    if not isinstance(payload, dict) or set(payload) - {
            "baseUrl", "username", "password", "clearPassword", "caFile",
            "verifyTLS", "timeoutMs", "cacheSeconds"}:
        raise ValueError("invalid K01 configuration")
    previous = previous or K01Config()
    clear = payload.get("clearPassword", False)
    verify_tls = payload.get("verifyTLS", previous.verify_tls)
    if type(clear) is not bool or type(verify_tls) is not bool:
        raise ValueError("invalid K01 configuration")
    values = {}
    for key, old, maximum in (("username", previous.username, 128),
                              ("password", previous.password, 1024),
                              ("caFile", previous.ca_file, 4096)):
        value = payload.get(key, old)
        if not isinstance(value, str) or len(value) > maximum or "\0" in value:
            raise ValueError("invalid K01 configuration")
        values[key] = value.strip() if key != "password" else value
    password = "" if clear else values["password"] or previous.password
    numbers = {}
    for key, old, low, high in (("timeoutMs", previous.timeout_ms, 1000, 30000),
                               ("cacheSeconds", previous.cache_seconds, 0, 3600)):
        value = payload.get(key, old)
        if type(value) is not int or not low <= value <= high:
            raise ValueError("invalid K01 configuration")
        numbers[key] = value
    return K01Config(normalized_origin(payload.get("baseUrl", previous.base_url)),
                     values["username"], password, values["caFile"],
                     numbers["timeoutMs"], numbers["cacheSeconds"], verify_tls)


def validate_trace_payload(payload):
    if not isinstance(payload, dict) or set(payload) - {"host", "count", "force"}:
        raise ValueError("invalid K01 query")
    host = normalize_host(payload.get("host"))
    if ":" in host:
        raise ValueError("only IPv4 and domain names are supported")
    count, force = payload.get("count", 10), payload.get("force", False)
    if type(count) is not int or count not in COUNTS or type(force) is not bool:
        raise ValueError("invalid K01 query")
    return host, count, force


def validate_change_password_payload(payload):
    """Validate the one-time K01 API-account password change request.

    The old password is deliberately not accepted from the browser; it is read
    from the local service's protected configuration and never echoed back.
    """
    if not isinstance(payload, dict) or set(payload) != {"newPassword", "confirmPassword"}:
        raise ValueError("invalid K01 password change")
    new_password, confirm_password = payload.get("newPassword"), payload.get("confirmPassword")
    if not isinstance(new_password, str) or not isinstance(confirm_password, str):
        raise ValueError("invalid K01 password change")
    if not 8 <= len(new_password) <= 16 or new_password != confirm_password:
        raise ValueError("invalid K01 password change")
    return new_password


def scrub(value, secrets=(), depth=0):
    if depth > 32:
        return "[depth-limit]"
    if isinstance(value, dict):
        return {key: scrub(item, secrets, depth + 1) for key, item in value.items()
                if not _SECRET_KEY.search(str(key))}
    if isinstance(value, list):
        return [scrub(item, secrets, depth + 1) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return re.sub(r"Bearer\s+[^\s\"',;]+", "Bearer [REDACTED]", value, flags=re.I)
    return value


@dataclass
class Reply:
    status: int
    data: object
    # Forensics travel with the reply so the client can attach them to whatever
    # K01Error it raises for a non-200 status (redirect, gateway page, 5xx...).
    diagnostic_code: str = ""
    diagnostic: dict = field(default_factory=dict)
    stage: str = ""
    elapsed_ms: int = 0


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _diagnostic_text(value, config, bearer):
    if not isinstance(value, str):
        return ""
    text = value
    for secret in (config.username, config.password, bearer):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return re.sub(r"Bearer\s+[^\s\"',;]+", "Bearer [REDACTED]", text, flags=re.I)[:240]


def _transport_diagnostic(error, config, bearer, timeout_ms, request_started):
    """Return bounded, credential-scrubbed transport diagnostics for local logs."""
    cause = error.reason if isinstance(error, URLError) else error
    if isinstance(cause, ssl.SSLCertVerificationError):
        detail = {"exceptionType": type(cause).__name__}
        verify_code = getattr(cause, "verify_code", None)
        verify_message = _diagnostic_text(getattr(cause, "verify_message", ""), config, bearer)
        if type(verify_code) is int:
            detail["verifyCode"] = verify_code
        if verify_message:
            detail["verifyMessage"] = verify_message
        else:
            # Some platforms leave verify_code/verify_message unset; keep the OpenSSL
            # reason and a bounded message so the cause is still identifiable.
            reason = getattr(cause, "reason", "")
            if isinstance(reason, str) and reason:
                detail["sslReason"] = reason[:96]
            message = _diagnostic_text(str(cause)[:200], config, bearer)
            if message:
                detail["message"] = message
        return "certificate_verification_failed", detail
    if isinstance(cause, ssl.SSLError):
        detail = {"exceptionType": type(cause).__name__}
        for attr, key in (("library", "sslLibrary"), ("reason", "sslReason")):
            value = getattr(cause, attr, None)
            if isinstance(value, str) and value:
                detail[key] = value[:96]
        return "tls_handshake_failed", detail
    if isinstance(cause, (TimeoutError, asyncio.TimeoutError)):
        return "connection_timeout", {"exceptionType": type(cause).__name__,
                                       "timeoutMs": timeout_ms}
    if isinstance(cause, socket.gaierror):
        detail = {"exceptionType": type(cause).__name__}
        if type(cause.errno) is int:
            detail["errno"] = cause.errno
        message = _diagnostic_text(cause.strerror or "", config, bearer)
        if message:
            detail["osError"] = message
        return "dns_resolution_failed", detail
    if isinstance(cause, OSError):
        number = cause.errno
        if not request_started:
            diagnostic_code = "ca_file_error" if config.ca_file else "tls_context_error"
        else:
            diagnostic_code = {
                errno.ECONNREFUSED: "connection_refused",
                errno.ETIMEDOUT: "connection_timeout",
                errno.ENETUNREACH: "network_unreachable",
                errno.EHOSTUNREACH: "network_unreachable",
                errno.ECONNRESET: "connection_reset",
            }.get(number, "socket_error")
        detail = {"exceptionType": type(cause).__name__}
        if type(number) is int:
            detail["errno"] = number
        message = _diagnostic_text(cause.strerror or "", config, bearer)
        if message:
            detail["osError"] = message
        if not request_started and config.ca_file:
            detail["caFileConfigured"] = True
        return diagnostic_code, detail
    if isinstance(error, URLError):
        return "url_error", {"exceptionType": type(cause).__name__}
    return "transport_error", {"exceptionType": type(cause).__name__}


def _protocol_diagnostic(error):
    detail = {"exceptionType": type(error).__name__}
    for attr in ("pos", "lineno", "colno", "start", "end"):
        value = getattr(error, attr, None)
        if type(value) is int:
            detail[attr] = value
    return detail


def _upstream_failure(error, stage, status, diagnostic_code, diagnostic=None):
    error.stage = stage
    error.upstream_status = status
    error.diagnostic_code = diagnostic_code
    error.diagnostic = diagnostic or {"httpStatus": status}
    return error


def _reject_constant(value):
    raise ValueError("non-standard JSON")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _tls_context(config):
    if config.verify_tls:
        return ssl.create_default_context(cafile=config.ca_file or None)
    # Explicit user opt-out: retain TLS encryption, but skip peer certificate and hostname validation.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _body_prefix(response, config, bearer):
    """Read (and scrub) a bounded prefix of an unexpected response body."""
    try:
        raw = response.read(240)
    except Exception:
        return ""
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    try:
        text = bytes(raw).decode("utf-8", "replace")
    except Exception:
        return ""
    return _diagnostic_text(re.sub(r"\s+", " ", text).strip(), config, bearer)


def _reply_response_detail(response, config, bearer, elapsed_ms):
    """Header forensics for a non-200 reply; never includes credentials or full body."""
    headers = getattr(response, "headers", None) or {}
    content_type = ""
    location = ""
    try:
        content_type = str(headers.get("Content-Type", "")).split(";", 1)[0].strip().lower()[:96]
        location = str(headers.get("Location", "") or "")
    except Exception:
        pass
    detail = {"httpStatus": getattr(response, "code", None), "elapsedMs": elapsed_ms,
              "transport": _TRANSPORT.get()}
    if content_type:
        detail["contentType"] = content_type
    if location:
        try:
            location_parts = urlsplit(location)
        except ValueError:
            location_parts = None
        if location_parts is not None and location_parts.hostname:
            detail["locationHost"] = _diagnostic_text(location_parts.hostname, config, bearer)
            detail["locationPath"] = _diagnostic_text(location_parts.path[:120], config, bearer)
        else:
            detail["locationPath"] = _diagnostic_text(location[:120], config, bearer)
    prefix = _body_prefix(response, config, bearer)
    if prefix:
        detail["bodyPrefix"] = prefix
    return detail


def _transport_error(code, message, status, cause, config, bearer, request_started,
                     stage, path, elapsed_ms):
    """Attach bounded, credential-scrubbed transport forensics to a caller-facing error."""
    try:
        diagnostic_code, diagnostic = _transport_diagnostic(
            cause, config, bearer, config.timeout_ms, request_started)
    except Exception:  # a diagnostic must never mask the original failure
        diagnostic_code = "diagnostic_unavailable"
        diagnostic = {"exceptionType": type(cause).__name__}
    hint = _TRANSPORT_HINTS.get(diagnostic_code)
    if hint and hint not in message:
        message = message + hint
    error = K01Error(code, message, status, fallback=True)
    error.stage = stage
    error.diagnostic_code = diagnostic_code
    error.diagnostic = {"requestPath": path, "elapsedMs": elapsed_ms,
                        "timeoutMs": config.timeout_ms,
                        "verifyTLS": config.verify_tls,
                        "transport": _TRANSPORT.get(),
                        "caFileConfigured": bool(config.ca_file), **diagnostic}
    return error


def _with_reply(error, reply):
    """Copy reply forensics onto the error the client is about to raise."""
    if reply is None:
        return error
    if getattr(reply, "stage", ""):
        error.stage = reply.stage
    if getattr(reply, "status", None) is not None:
        error.upstream_status = reply.status
    if getattr(reply, "diagnostic_code", ""):
        error.diagnostic_code = reply.diagnostic_code
    if getattr(reply, "diagnostic", None):
        error.diagnostic = dict(reply.diagnostic)
    hint = _TRANSPORT_HINTS.get(error.diagnostic_code or "")
    if hint and hint not in error.message:
        error.message = error.message + hint
    return error


def _curl_fallback_enabled():
    return os.environ.get(CURL_FALLBACK_ENV, "1").strip().lower() not in {"0", "false", "no", "off"}


def _curl_binary():
    for name in ("curl.exe", "curl"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def _is_renegotiation_drop(error):
    """True when the socket died after the request was written (renegotiation refusal)."""
    pending = [error]
    for _ in range(4):
        if not pending:
            break
        current = pending.pop(0)
        if isinstance(current, _RENEGOTIATION_ERRORS):
            return True
        text = str(current).lower()
        if "renegotiat" in text:
            return True
        if isinstance(current, ssl.SSLError) and "eof" in text:
            return True
        for attr in ("reason", "__cause__", "__context__"):
            nested = getattr(current, attr, None)
            if isinstance(nested, BaseException):
                pending.append(nested)
    return False


class _CurlReply:
    """Response stand-in so the curl path reuses the urllib body handling."""

    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self._body = body
        self._offset = 0

    def read(self, amount=None):
        if amount is None or amount < 0:
            chunk = self._body[self._offset:]
        else:
            chunk = self._body[self._offset:self._offset + amount]
        self._offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _curl_command(binary, config, path, header_file, payload_file, header_out, body_out):
    limit = "{:.3f}".format(config.timeout_ms / 1000)
    command = [binary, "-sS", "--http1.1", "--no-progress-meter",
               "--max-time", limit, "--connect-timeout", limit,
               "-X", "POST", config.base_url + path,
               "-H", "@" + header_file,
               "--data-binary", "@" + payload_file,
               "-D", header_out, "-o", body_out,
               "-w", "%{http_code}"]
    if not config.verify_tls:
        command.append("-k")
    elif config.ca_file:
        command.extend(["--cacert", config.ca_file])
    return command


def _curl_headers(raw):
    headers = {}
    for line in raw.replace("\r\n", "\n").split("\n"):
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or name.upper().startswith("HTTP/"):
            continue
        headers[name] = value.strip()
        headers.setdefault(name.lower(), value.strip())
    return headers


def _post_with_os_tls(config, path, payload_bytes, bearer):
    """Retry the request through curl so the OS TLS stack can renegotiate.

    Credentials never reach the process command line: headers and body are handed over
    through owner-only temp files that are deleted before returning.
    """
    binary = _curl_binary()
    if not binary:
        raise OSError(errno.ECONNRESET, "curl fallback unavailable")
    workdir = tempfile.mkdtemp(prefix="k01-os-tls-")
    try:
        header_file = os.path.join(workdir, "request.headers")
        payload_file = os.path.join(workdir, "request.body")
        header_out = os.path.join(workdir, "response.headers")
        body_out = os.path.join(workdir, "response.body")
        lines = ["Accept: application/json",
                 "Content-Type: application/json; charset=utf-8"]
        if bearer:
            lines.append("Authorization: Bearer " + bearer)
            # The K01 web frontend sends the same token in this legacy header for
            # account operations; send it in addition to the documented bearer
            # header so /account/changepwd works on both API and frontend builds.
            if path == CHANGE_PASSWORD_PATH:
                lines.append("access_token: " + bearer)
        for name, content in ((header_file, ("\n".join(lines) + "\n").encode("utf-8")),
                              (payload_file, payload_bytes),
                              (header_out, b""),
                              (body_out, b"")):
            with open(name, "wb") as handle:
                handle.write(content)
            os.chmod(name, 0o600)
        completed = subprocess.run(
            _curl_command(binary, config, path, header_file, payload_file, header_out, body_out),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=config.timeout_ms / 1000 + CURL_TIMEOUT_PAD_SECONDS, check=False)
        status = 0
        produced = completed.stdout.decode("ascii", "replace").strip().splitlines()
        if produced and produced[-1].strip().isdigit():
            status = int(produced[-1].strip())
        if status <= 0:
            stderr = completed.stderr.decode("utf-8", "replace").strip()
            raise OSError(errno.ECONNRESET,
                          "os tls retry failed (curl exit {0}): {1}".format(
                              completed.returncode, stderr[:160]))
        with open(header_out, "rb") as handle:
            headers = _curl_headers(handle.read(65536).decode("latin-1", "replace"))
        with open(body_out, "rb") as handle:
            body = handle.read(MAX_RESPONSE_BYTES + 1)
        return _CurlReply(status, headers, body)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _blocking_post(config, path, payload, bearer, *, stage=None):
    if path not in {LOGIN_PATH, CHANGE_PASSWORD_PATH, TRACE_PATH}:
        raise ValueError("undocumented K01 endpoint")
    stage = stage or ("login" if path == LOGIN_PATH else
                      "change-password" if path == CHANGE_PASSWORD_PATH else "trace")
    started = time.monotonic()
    request_started = False
    _TRANSPORT.set("urllib")
    try:
        context = _tls_context(config)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
        headers = {"Accept": "application/json", "Content-Type": "application/json; charset=utf-8"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
            if path == CHANGE_PASSWORD_PATH:
                headers["access_token"] = bearer
        request = Request(config.base_url + path,
                          data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                          headers=headers, method="POST")
        request_started = True
        try:
            response = opener.open(request, timeout=config.timeout_ms / 1000)
        except HTTPError as exc:
            response = exc
        except (URLError, OSError) as exc:
            # The gateway asked to renegotiate and OpenSSL refused, so the socket died
            # after the body was written. Replay once over the OS TLS stack.
            if not (_is_renegotiation_drop(exc) and _curl_fallback_enabled()
                    and _curl_binary()):
                raise
            _TRANSPORT.set("os-tls")
            response = _post_with_os_tls(config, path, request.data, bearer)
        with response:
            status = response.code
            elapsed_ms = round((time.monotonic() - started) * 1000)
            # Error pages are not parsed or exposed to the caller; only bounded,
            # scrubbed header/body forensics are kept for the local log.
            if status != 200:
                code = "unexpected_redirect" if 300 <= status < 400 else "upstream_http_error"
                return Reply(status, None, diagnostic_code=code, stage=stage,
                             elapsed_ms=elapsed_ms,
                             diagnostic=_reply_response_detail(response, config, bearer, elapsed_ms))
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
                raise _upstream_failure(
                    K01Error("K01_RESPONSE_TOO_LARGE", "K01 返回内容超过允许大小。"), stage, status,
                    "response_too_large",
                    {"httpStatus": status, "declaredLength": str(length)[:24], "elapsedMs": elapsed_ms})
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
            if content_type not in {"application/json", "text/json"} and not content_type.endswith("+json"):
                raise _upstream_failure(
                    K01Error("K01_PROTOCOL_ERROR", "K01 返回的内容不是有效情报 JSON。"), stage, status,
                    "non_json_response",
                    {"httpStatus": status, "contentType": content_type[:96], "elapsedMs": elapsed_ms,
                     "bodyPrefix": _body_prefix(response, config, bearer)})
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise _upstream_failure(
                    K01Error("K01_RESPONSE_TOO_LARGE", "K01 返回内容超过允许大小。"), stage, status,
                    "response_too_large", {"httpStatus": status, "elapsedMs": elapsed_ms})
            try:
                data = json.loads(content, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
            except (UnicodeError, ValueError, RecursionError) as exc:
                detail = _protocol_diagnostic(exc)
                detail.update({"httpStatus": status, "contentType": content_type[:96],
                               "bytes": len(content), "elapsedMs": elapsed_ms})
                raise _upstream_failure(
                    K01Error("K01_PROTOCOL_ERROR", "K01 返回的内容不是有效情报 JSON。"), stage, status,
                    "invalid_json", detail) from None
            if not isinstance(data, dict):
                raise _upstream_failure(
                    K01Error("K01_PROTOCOL_ERROR", "K01 返回的内容不是有效情报 JSON。"), stage, status,
                    "non_object_json", {"httpStatus": status, "jsonType": type(data).__name__,
                                        "elapsedMs": elapsed_ms})
            return Reply(status, data, stage=stage, elapsed_ms=elapsed_ms)
    except K01Error:
        raise
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise _transport_error("K01_TIMEOUT", "K01 查询超时，请重试。", 504, exc, config, bearer,
                               request_started, stage, path,
                               round((time.monotonic() - started) * 1000)) from None
    except (ssl.SSLError, ssl.CertificateError) as exc:
        raise _transport_error("K01_TLS_ERROR", "K01 证书验证失败，请检查可信 CA 配置。", 502, exc,
                               config, bearer, request_started, stage, path,
                               round((time.monotonic() - started) * 1000)) from None
    except URLError as exc:
        reason = exc.reason
        elapsed_ms = round((time.monotonic() - started) * 1000)
        if isinstance(reason, (TimeoutError, asyncio.TimeoutError)):
            raise _transport_error("K01_TIMEOUT", "K01 查询超时，请重试。", 504, exc, config, bearer,
                                   request_started, stage, path, elapsed_ms) from None
        if isinstance(reason, (ssl.SSLError, ssl.CertificateError)):
            raise _transport_error("K01_TLS_ERROR", "K01 证书验证失败，请检查可信 CA 配置。", 502, exc,
                                   config, bearer, request_started, stage, path, elapsed_ms) from None
        raise _transport_error("K01_CONNECTION_ERROR", "本地服务连接 K01 失败，请检查地址和网络。", 502,
                               exc, config, bearer, request_started, stage, path, elapsed_ms) from None
    except (UnicodeError, ValueError, RecursionError):
        raise K01Error("K01_PROTOCOL_ERROR", "K01 返回的内容不是有效情报 JSON。") from None
    except OSError as exc:
        raise _transport_error("K01_CONNECTION_ERROR", "本地服务连接 K01 失败，请检查地址、网络和 CA 文件。",
                               502, exc, config, bearer, request_started, stage, path,
                               round((time.monotonic() - started) * 1000)) from None


async def post_json(config, path, payload, bearer):
    return await asyncio.to_thread(_blocking_post, config, path, payload, bearer)


class K01IntelligenceClient:
    def __init__(self, data_dir, pairing_token, logger=None, transport=None, clock=time.monotonic):
        self.path = Path(data_dir) / "config.json"
        self.pairing_token = pairing_token
        self.logger = logger or logging.getLogger("soar-k01")
        self.transport = transport or post_json
        self.clock = clock
        self.config = self._load()
        self.revision = 0
        self.token = None
        self.login_notice = None
        self.login_lock = None
        self.semaphore = None
        self.inflight = {}
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.closed = False

    def _load(self):
        if not self.path.exists():
            return K01Config()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return config_from_payload(data.get("k01", {}))

    def public_config(self):
        return {"success": True, "config": self.config.public()}

    def status(self):
        return {"success": True, "configured": self.config.configured,
                "authSource": "api-account", "config": self.config.public(),
                "tokenAvailable": bool(self.token and self.token[0] == self.revision
                                       and self.token[2] > self.clock())}

    def update_config(self, payload):
        candidate = config_from_payload(payload, self.config)
        original = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {"token": self.pairing_token}
        if not isinstance(original, dict):
            raise ValueError("invalid service configuration")
        original["k01"] = candidate.stored()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self.path.parent, prefix=".k01-config-", suffix=".tmp",
                                         mode="w", encoding="utf-8", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(original, stream, ensure_ascii=False, indent=2)
        try:
            if os.name != "nt":
                temporary.chmod(0o600)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        self.config = candidate
        self.revision += 1
        self.token = None
        self.login_notice = None
        self.cache.clear()
        self.cache_bytes = 0
        self._log("k01-config-saved", configured=candidate.configured)
        return self.public_config()

    def _log(self, event, **fields):
        trace_id = current_trace_id()
        if trace_id:
            fields.setdefault("traceId", trace_id)
        self.logger.info(json.dumps({"time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                                     "event": event, **fields}, ensure_ascii=False, default=str))

    def _config_forensics(self):
        """Non-secret view of the active configuration for failure logs."""
        return {"baseUrl": self.config.base_url, "usernameConfigured": bool(self.config.username),
                "verifyTLS": self.config.verify_tls, "caFileConfigured": bool(self.config.ca_file),
                "timeoutMs": self.config.timeout_ms, "cacheSeconds": self.config.cache_seconds,
                "revision": self.revision, "tokenAvailable": bool(self.token)}

    def _login_rejected(self, reply, config, diagnostic_code):
        """Explain a rejected login with the gateway's own error_code/msg.

        Without this an HTTP 200 + ``success:false`` login only reports
        ``api_login_failed`` and the wrong password is indistinguishable from a
        locked account or a gateway page, so the operator retries blindly.
        """
        body = reply.data if isinstance(reply.data, dict) else {}
        error_code = body.get("error_code")
        message = _diagnostic_text(str(body.get("msg", ""))[:160], config, None)
        error = frontend_required("api_login_failed")
        if message:
            error.message = f"{error.message}（上游返回：{message}）"
        return _with_reply(error, Reply(
            reply.status, None, diagnostic_code=diagnostic_code, stage="login",
            elapsed_ms=getattr(reply, "elapsed_ms", 0),
            diagnostic={"httpStatus": reply.status,
                        "successFlag": repr(body.get("success"))[:16],
                        "errorCode": error_code if type(error_code) is int else repr(error_code)[:24],
                        "message": message}))

    async def _get_token(self, config, revision):
        if self.login_lock is None:
            self.login_lock = asyncio.Lock()
        async with self.login_lock:
            if self.token and self.token[0] == revision and self.token[2] > self.clock():
                return self.token[1]
            reply = await self.transport(config, LOGIN_PATH,
                                         {"username": config.username, "password": config.password}, None)
            if reply.status in {404, 405}:
                raise _with_reply(frontend_required("api_login_unavailable"), reply)
            if reply.status in {400, 401, 403}:
                raise self._login_rejected(reply, config, "login_http_rejected")
            if reply.status != 200:
                raise _with_reply(K01Error("K01_UPSTREAM_ERROR", "K01 登录服务返回异常，请稍后重试。"), reply)
            body = reply.data
            if not isinstance(body, dict) or type(body.get("success")) is not bool:
                raise _with_reply(K01Error("K01_PROTOCOL_ERROR", "K01 登录响应格式异常。"), reply)
            token_block = body.get("token") if isinstance(body.get("token"), dict) else {}
            token = token_block.get("access_token")
            usable = isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9._~+/-]{1,32768}=*", token)
            # K01 flags "首次登录建议修改密码" as success:false + error_code:999 while still
            # returning a usable access_token. The issued token is the real signal: dropping
            # it turns a password-change advisory into a hard login failure.
            if body["success"] is not True and not usable:
                raise self._login_rejected(reply, config, "login_rejected")
            if not usable:
                raise _with_reply(K01Error("K01_PROTOCOL_ERROR", "K01 登录响应缺少有效访问令牌。"), reply)
            if body["success"] is not True:
                error_code = body.get("error_code")
                self.login_notice = {
                    "status": _diagnostic_text(str(body.get("status", ""))[:32], config, None),
                    "errorCode": error_code if type(error_code) is int else None,
                    "message": _diagnostic_text(str(body.get("msg", ""))[:160], config, None)}
                self._log("k01-api-login", result="ok-with-notice",
                          elapsedMs=getattr(reply, "elapsed_ms", 0), tokenLength=len(token),
                          upstreamStatus=reply.status, errorCode=self.login_notice["errorCode"],
                          notice=self.login_notice["message"])
            else:
                self._log("k01-api-login", result="ok", elapsedMs=getattr(reply, "elapsed_ms", 0),
                          tokenLength=len(token))
            if revision == self.revision:
                self.token = (revision, token, self.clock() + 900)
            return token

    async def change_password(self, payload):
        """Change the configured K01 API password, then persist the new value.

        K01 rejects all intelligence queries with error_code 10140 while an API
        account still uses its initial password. The browser only supplies the
        new password; the saved API password is used as ``oldpwd`` and is never
        returned to the caller. Changing the password is an explicit user action
        and is never triggered automatically by a failed query.
        """
        new_password = validate_change_password_payload(payload)
        config, revision = self.config, self.revision
        if not config.configured:
            raise frontend_required("api_not_configured")
        bearer = await self._get_token(config, revision)
        reply = await self.transport(config, CHANGE_PASSWORD_PATH, {
            "username": config.username,
            "oldpwd": config.password,
            "newpwd": new_password,
            "confirmpwd": new_password,
        }, bearer)
        if reply.status in {404, 405}:
            raise _with_reply(K01Error("K01_PASSWORD_CHANGE_UNAVAILABLE",
                                       "当前 K01 未提供修改密码接口，请使用 K01 网页端修改。", 409),
                              reply)
        body = reply.data if isinstance(reply.data, dict) else {}
        upstream_message = _diagnostic_text(str(body.get("msg", ""))[:160], config, bearer)
        if new_password:
            upstream_message = upstream_message.replace(new_password, "[REDACTED]")
        error_code = body.get("error_code", 0)
        success = reply.status == 200 and body.get("success") is True and error_code == 0
        if not success:
            error = K01Error("K01_PASSWORD_CHANGE_FAILED",
                             "K01 修改密码失败，请检查旧密码和新密码要求。", 502)
            if upstream_message:
                error.message = f"{error.message}（上游返回：{upstream_message}）"
            raise _with_reply(error, Reply(
                reply.status, None, diagnostic_code="password_change_rejected",
                stage="change-password", elapsed_ms=getattr(reply, "elapsed_ms", 0),
                diagnostic={"httpStatus": reply.status,
                            "successFlag": repr(body.get("success"))[:16],
                            "errorCode": error_code if type(error_code) is int else repr(error_code)[:24],
                            "message": upstream_message}))
        if revision != self.revision:
            raise K01Error("K01_PASSWORD_CHANGED_CONFIG_SAVE_FAILED",
                           "K01 密码已修改，但本地配置在此期间被更新；请立即在 K01 配置中手动更新新密码。",
                           500, stage="change-password")
        try:
            self.update_config({"password": new_password})
        except (OSError, ValueError) as exc:
            raise K01Error("K01_PASSWORD_CHANGED_CONFIG_SAVE_FAILED",
                           "K01 密码已修改，但本地保存新密码失败；请立即在 K01 配置中手动更新新密码。",
                           500, stage="change-password") from exc
        self._log("k01-password-changed", usernameConfigured=True,
                  passwordChanged=True, upstreamStatus=reply.status)
        return {"success": True, "message": "K01 API 密码已修改并保存，将重新查询。",
                "passwordChanged": True, "config": self.public_config()["config"]}

    async def _query(self, config, revision, host, count):
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(2)
        async with self.semaphore:
            started = self.clock()
            bearer = await self._get_token(config, revision)
            for attempt in range(2):
                reply = await self.transport(config, TRACE_PATH, {"host": host, "count": count}, bearer)
                if reply.status in {404, 405}:
                    raise _with_reply(frontend_required("api_endpoint_unavailable"), reply)
                body = reply.data if isinstance(reply.data, dict) else {}
                denied = reply.status in {401, 403} or (reply.status == 200 and body.get("success") is False
                                                       and body.get("error_code") in (401, 403))
                if not denied:
                    break
                if self.token and self.token[0] == revision and self.token[1] == bearer:
                    self.token = None
                if attempt:
                    raise _with_reply(frontend_required("api_access_denied"), reply)
                bearer = await self._get_token(config, revision)
            if reply.status != 200:
                raise _with_reply(K01Error("K01_UPSTREAM_ERROR", "K01 情报服务返回异常，请稍后重试。"), reply)
            error_code = body.get("error_code", 0)
            if (body.get("success") is not True or type(error_code) is not int or error_code != 0
                    or not isinstance(body.get("data"), dict)):
                upstream_message = _diagnostic_text(str(body.get("msg", ""))[:160], config, bearer)
                recovery = _QUERY_RECOVERY.get(error_code) if type(error_code) is int else None
                if recovery:
                    reason, diagnostic_code = recovery
                    error = frontend_required(reason)
                else:
                    diagnostic_code = "k01_query_rejected"
                    error = K01Error("K01_QUERY_ERROR", "K01 未返回成功的情报结果。")
                if upstream_message:
                    error.message = f"{error.message}（上游返回：{upstream_message}）"
                raise _with_reply(error, Reply(
                    reply.status, None, diagnostic_code=diagnostic_code,
                    stage="trace", elapsed_ms=getattr(reply, "elapsed_ms", 0),
                    diagnostic={"httpStatus": reply.status, "successFlag": repr(body.get("success"))[:16],
                                "errorCode": error_code if type(error_code) is int else repr(error_code)[:24],
                                "dataType": type(body.get("data")).__name__,
                                "message": upstream_message}))
            result = {"success": True, "host": host, "authSource": "api-account",
                      "serviceVersion": _SERVICE_VERSION,
                      "queriedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                      "elapsedMs": round((self.clock() - started) * 1000), "cacheHit": False,
                      "data": scrub(body["data"], (config.password, bearer, self.pairing_token))}
            encoded = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
            if config.cache_seconds and revision == self.revision and encoded <= MAX_CACHE_BYTES:
                key = (revision, host, count)
                old = self.cache.pop(key, None)
                if old:
                    self.cache_bytes -= old[2]
                self.cache[key] = (self.clock() + config.cache_seconds, copy.deepcopy(result), encoded)
                self.cache_bytes += encoded
                while len(self.cache) > MAX_CACHE_ENTRIES or self.cache_bytes > MAX_CACHE_BYTES:
                    _, entry = self.cache.popitem(last=False)
                    self.cache_bytes -= entry[2]
            if self.login_notice:
                result["loginNotice"] = dict(self.login_notice)
            self._log("k01-query-result", host=host, authSource="api-account", elapsedMs=result["elapsedMs"], cacheHit=False)
            return result

    async def trace(self, payload):
        host, count, force = validate_trace_payload(payload)
        if self.closed:
            raise K01Error("K01_CLOSED", "本地服务正在关闭。", 503)
        config, revision = self.config, self.revision
        if not config.configured:
            raise frontend_required("api_not_configured")
        key = (revision, host, count)
        cached = self.cache.get(key)
        if cached and cached[0] <= self.clock():
            self.cache.pop(key)
            self.cache_bytes -= cached[2]
            cached = None
        if cached and not force:
            self.cache.move_to_end(key)
            result = copy.deepcopy(cached[1])
            result["cacheHit"] = True
            self._log("k01-query-result", host=host, authSource="api-account", elapsedMs=0, cacheHit=True)
            return result
        task = self.inflight.get(key)
        if task is None:
            if len(self.inflight) >= MAX_INFLIGHT:
                raise K01Error("K01_BUSY", "K01 查询队列已满，请稍后重试。", 429)
            task = asyncio.create_task(self._query_with_deadline(config, revision, host, count))
            self.inflight[key] = task
            def finished(completed):
                if self.inflight.get(key) is completed:
                    self.inflight.pop(key, None)
                if not completed.cancelled():
                    completed.exception()  # Retrieve errors even when all HTTP callers disconnected.
            task.add_done_callback(finished)
        try:
            return copy.deepcopy(await asyncio.shield(task))
        except K01Error as error:
            error.trace_id = error.trace_id or current_trace_id()
            self._log("k01-query-error", host=host, count=count, code=error.code, reason=error.reason,
                      fallbackAllowed=error.fallback, status=error.status, stage=error.stage,
                      upstreamStatus=error.upstream_status, diagnosticCode=error.diagnostic_code,
                      diagnostic=error.diagnostic, config=self._config_forensics())
            raise

    async def _query_with_deadline(self, config, revision, host, count):
        try:
            # Include semaphore admission, login-lock waiting and any one-time
            # authentication retry in one budget below the browser timeout.
            return await asyncio.wait_for(self._query(config, revision, host, count),
                                          timeout=MAX_QUERY_SECONDS)
        except asyncio.TimeoutError:
            raise K01Error("K01_TIMEOUT", "K01 查询超时，请重试。", 504) from None

    async def close(self):
        self.closed = True
        tasks = list(self.inflight.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.inflight.clear()
        self.cache.clear()
        self.cache_bytes = 0
        self.token = None
        self.login_notice = None
