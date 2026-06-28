#!/usr/bin/python3
"""
Copyright (c) 2026 Penterep Security s.r.o.

pt403bypass - testing tool for 401/403 authorization bypass techniques.
"""

from __future__ import annotations

import argparse
import base64
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(__file__.rsplit("/", 1)[0])
from urllib.parse import quote, unquote, urljoin, urlparse, urlunparse

import requests
from requests.structures import CaseInsensitiveDict

try:
    from ptlibs.http.raw_http_client import RawHttpClient
except ImportError:
    RawHttpClient = None

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper
from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint


WHITE = "\033[97m"
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

BLOCKED_STATUS_CODES: frozenset[int] = frozenset({401, 403})
DEFAULT_HIDE_STATUSES: frozenset[int] = frozenset({401, 403, 404})

LONG_DOT_PREFIX = "./" * 64
LONG_ENCODED_DOT_PREFIX = "%2F%2E" * 13


def _display_http_status(code: int, *, colorize: bool = True) -> str:
    text = f"[{code}]"
    if not colorize:
        return text
    if code == 200:
        return f"{GREEN}{text}{RESET}"
    if code == 500:
        return f"{RED}{text}{RESET}"
    return text


def _extract_page_title(content: bytes) -> str | None:
    if not content:
        return None
    text = content.decode("utf-8", errors="replace")
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = html.unescape(match.group(1))
    title = " ".join(title.split())
    return title or None


def _infer_http_status_from_body(raw: bytes) -> int | None:
    if not raw or _is_proxy_artifact_response(raw):
        return None
    line_match = re.match(rb"HTTP/\d\.\d (\d{3})", raw)
    if line_match:
        return int(line_match.group(1))
    title = _extract_page_title(raw)
    if title:
        title_match = re.match(r"^(\d{3})\b", title)
        if title_match:
            return int(title_match.group(1))
    return None


def _is_proxy_artifact_response(raw: bytes) -> bool:
    if not raw:
        return False
    title = _extract_page_title(raw)
    if title and "burp suite" in title.lower():
        return True
    sample = raw[:8192].decode("utf-8", errors="replace").lower()
    return "portswigger" in sample and "burp" in sample


def _redirect_href_from_html(content: bytes, base_url: str) -> str | None:
    text = content.decode("utf-8", errors="replace")
    match = re.search(r"""<a[^>]+href=["']([^"']+)["']""", text, re.IGNORECASE)
    if not match:
        return None
    href = html.unescape(match.group(1).strip())
    if not href:
        return None
    return urljoin(base_url, href)


def _is_redirect_status(code: int) -> bool:
    return 300 <= code <= 399 and code != 304


def _redirect_target(response: requests.Response) -> str | None:
    location = response.headers.get("Location")
    if location:
        return urljoin(response.url or "", location.strip())
    if response.content:
        return _redirect_href_from_html(response.content, response.url or "")
    return None


def _format_status_suffix(response: requests.Response, *, colorize: bool = True) -> str:
    status_code = response.status_code
    suffix = _display_http_status(status_code, colorize=colorize)
    if status_code == 200:
        title = _extract_page_title(response.content or b"") or "-"
        length = len(response.content or b"")
        suffix = f"{suffix} Title: {title} Length: {length}"
    elif _is_redirect_status(status_code):
        target = _redirect_target(response)
        if target:
            target_text = (
                _osc8_hyperlink(target, target, link_id=_link_id_for_url(target))
                if _is_web_url(target)
                else target
            )
            suffix = f"{suffix} -> {target_text}"
    return suffix


def _split_label_for_output(label: str, width: int) -> tuple[list[str], str]:
    if len(label) <= width:
        return [], label
    prefix_lines: list[str] = []
    rest = label
    while len(rest) > width:
        break_at = rest.rfind("/", 0, width + 1)
        if break_at <= 0:
            break_at = width
        prefix_lines.append(rest[:break_at])
        rest = rest[break_at:]
    return prefix_lines, rest


def _is_web_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def _link_id_for_url(url: str) -> str:
    return format(abs(hash(url)) & 0xFFFFFFFF, "x")


def _osc8_hyperlink(url: str, text: str, *, link_id: str | None = None) -> str:
    safe_url = url.replace("\033", "").replace("\x07", "")
    if link_id:
        header = f"\033]8;id={link_id};{safe_url}\033\\"
    else:
        header = f"\033]8;;{safe_url}\033\\"
    return f"{header}{text}\033]8;;\033\\"


def _format_label_text(
    text: str,
    width: int,
    *,
    link_url: str | None = None,
    link_id: str | None = None,
) -> str:
    visible = _osc8_hyperlink(link_url, text, link_id=link_id) if link_url else text
    return f"{visible}{' ' * max(0, width - len(text))}"


def _remap_requests_exception_ptlibs(exc: requests.RequestException) -> requests.RequestException:
    try:
        HttpClient._remap_requests_exception(None, exc)  # type: ignore[arg-type]
    except requests.RequestException as remapped:
        return remapped
    return exc


def _templates_dir(explicit: str | None) -> str:
    if explicit:
        return explicit
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def _read_lines(path: str, *, skip_comment_lines: bool) -> list[str]:
    if not os.path.isfile(path):
        return []
    out: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\r\n")
            if not raw.strip():
                continue
            if skip_comment_lines and raw.lstrip().startswith("#"):
                continue
            out.append(raw)
    return out


def _read_header_names_from_file(path: str) -> list[str]:
    names: list[str] = []
    for raw in _read_lines(path, skip_comment_lines=True):
        if ":" in raw:
            name = raw.split(":", 1)[0].strip()
        else:
            name = raw.strip()
        if name:
            names.append(name)
    return names


def _read_ip_values_from_file(path: str) -> list[str]:
    return [x.strip() for x in _read_lines(path, skip_comment_lines=True)]


def _header_ip_pairs_from_files(templates_dir: str, hname: str, iname: str) -> list[tuple[str, str]] | None:
    hpath = os.path.join(templates_dir, hname)
    ipath = os.path.join(templates_dir, iname)
    if not (os.path.isfile(hpath) and os.path.isfile(ipath)):
        return None
    names = _read_header_names_from_file(hpath)
    ips = _read_ip_values_from_file(ipath)
    if not names or not ips:
        return None
    return [(n, ip) for n in names for ip in ips]


def load_header_ip_pairs(templates_dir: str) -> list[tuple[str, str]]:
    pairs = _header_ip_pairs_from_files(templates_dir, "source_ip_headers.txt", "ip.txt")
    return pairs if pairs is not None else []


_HOST_LIKE_HEADERS = frozenset({
    "host",
    "x-forwarded-host",
    "forwarded-host",
    "proxy-host",
    "x-host",
    "x-http-host-override",
})


def _format_ip_for_header(header: str, value: str) -> str:
    """RFC 7230: IPv6 literals in Host-style headers must use bracket form."""
    if header.lower() not in _HOST_LIKE_HEADERS:
        return value
    if value.startswith("["):
        return value
    try:
        if isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address):
            return f"[{value}]"
    except ValueError:
        pass
    return value


def load_path_payloads(templates_dir: str) -> list[str]:
    return _read_lines(os.path.join(templates_dir, "path_patterns.txt"), skip_comment_lines=True)


def load_static_header_payloads(templates_dir: str) -> list[dict[str, str]]:
    path = os.path.join(templates_dir, "static_headers.txt")
    out: list[dict[str, str]] = []
    for line in _read_lines(path, skip_comment_lines=True):
        if "|" not in line:
            continue
        name, value = line.split("|", 1)
        name, value = name.strip(), value.strip()
        if name:
            out.append({name: value})
    return out


def load_header_combo_sets(templates_dir: str) -> list[dict[str, str]]:
    path = os.path.join(templates_dir, "header_combos.txt")
    out: list[dict[str, str]] = []
    for line in _read_lines(path, skip_comment_lines=True):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            out.append({str(k): str(v) for k, v in row.items()})
    return out


def load_methods(templates_dir: str) -> list[str]:
    path = os.path.join(templates_dir, "methods.txt")
    methods: list[str] = []
    seen: set[str] = set()
    for line in _read_lines(path, skip_comment_lines=True):
        m = line.strip().upper()
        if m and m not in seen:
            seen.add(m)
            methods.append(m)
    return methods


def default_methods_for_argparse() -> list[str]:
    return load_methods(_templates_dir(None))


def load_user_agents(templates_dir: str) -> list[str]:
    path = os.path.join(templates_dir, "user_agents.txt")
    return [x.strip() for x in _read_lines(path, skip_comment_lines=True) if x.strip()]


def load_connection_strip_header_names(templates_dir: str) -> list[str]:
    path = os.path.join(templates_dir, "connection_strip_headers.txt")
    names: list[str] = []
    seen: set[str] = set()
    for raw in _read_lines(path, skip_comment_lines=True):
        name = raw.split(":", 1)[0].strip() if ":" in raw else raw.strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _headers_without_keys(headers: dict[str, str], drop_keys: frozenset[str]) -> dict[str, str]:
    dk = {k.lower() for k in drop_keys}
    return {k: v for k, v in headers.items() if k.lower() not in dk}


def _normalize_proxy_url(url: str) -> str:
    if "://" not in url:
        return f"http://{url}"
    return url


def _proxy_endpoint(proxy_url: str) -> tuple[str, int]:
    parsed = urlparse(_normalize_proxy_url(proxy_url))
    host = parsed.hostname
    if not host:
        raise ValueError(f"invalid proxy URL: {proxy_url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    return host, port


def _read_http_response_head(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            raise OSError("HTTP response headers too large")
    return buf


def _proxy_connect(
    target_host: str,
    target_port: int,
    proxy_url: str,
    timeout: float,
) -> socket.socket:
    proxy_host, proxy_port = _proxy_endpoint(proxy_url)
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    connect_target = f"{target_host}:{target_port}"
    req = (
        f"CONNECT {connect_target} HTTP/1.1\r\n"
        f"Host: {connect_target}\r\n"
        f"Proxy-Connection: keep-alive\r\n"
        f"\r\n"
    )
    try:
        sock.sendall(req.encode("ascii", errors="strict"))
        head = _read_http_response_head(sock, timeout)
    except OSError:
        sock.close()
        raise
    first_line = head.split(b"\r\n", 1)[0]
    match = re.match(rb"HTTP/\d\.\d (\d{3})", first_line)
    if not match:
        sock.close()
        raise OSError(f"proxy CONNECT failed: {first_line.decode('utf-8', 'replace')}")
    status = int(match.group(1))
    if status != 200:
        sock.close()
        raise OSError(f"proxy CONNECT failed: HTTP {status}")
    return sock


def _open_plain_target_socket(
    host: str,
    port: int,
    *,
    proxy_url: str | None,
    timeout: float,
) -> socket.socket:
    if proxy_url:
        return _proxy_connect(host, port, proxy_url, timeout)
    return socket.create_connection((host, port), timeout=timeout)


def _http_client_connection_from_socket(
    sock: socket.socket,
    host: str,
    port: int,
    major: int,
    minor: int,
    timeout: float,
    *,
    scheme: str,
    ssl_context: ssl.SSLContext | None = None,
) -> http.client.HTTPConnection:
    conn_http, conn_https = _cached_http_connection_pair(major, minor)
    base_cls = conn_https if scheme == "https" else conn_http
    plain_sock = sock

    class _SocketConn(base_cls):
        def connect(self) -> None:
            if scheme == "https":
                if ssl_context is not None:
                    self.sock = ssl_context.wrap_socket(plain_sock, server_hostname=host)
                else:
                    self.sock = plain_sock
            else:
                self.sock = plain_sock

    conn_kw: dict = {"host": host, "port": port, "timeout": timeout}
    if scheme == "https" and ssl_context is not None:
        conn_kw["context"] = ssl_context
    return _SocketConn(**conn_kw)


def _open_target_socket(
    host: str,
    port: int,
    scheme: str,
    *,
    proxy_url: str | None,
    timeout: float,
    ssl_context: ssl.SSLContext | None = None,
) -> socket.socket:
    sock = _open_plain_target_socket(host, port, proxy_url=proxy_url, timeout=timeout)
    if scheme == "https":
        ctx = ssl_context or ssl.create_default_context()
        if ssl_context is None:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _http09_wire_payload(path: str) -> bytes:
    return f"GET {path}\r\n".encode("ascii", errors="strict")


def _proxy_forward_request(
    method: str,
    absolute_url: str,
    version: str,
    headers: dict[str, str] | None,
    proxy_url: str,
    timeout: float,
) -> bytes:
    proxy_host, proxy_port = _proxy_endpoint(proxy_url)
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    lines = [f"{method.upper()} {absolute_url} {version}"]
    if headers:
        for key, value in headers.items():
            if key.lower() == "connection":
                continue
            lines.append(f"{key}: {value}")
    lines.extend(["", ""])
    try:
        sock.sendall("\r\n".join(lines).encode("ascii", errors="strict"))
        return _recv_http_bytes(sock, timeout)
    finally:
        sock.close()


def _response_from_http09_raw(raw: bytes, url: str) -> requests.Response:
    if _is_proxy_artifact_response(raw):
        r = requests.Response()
        r.url = url
        r.status_code = 0
        r._content = b"HTTP/0.9: proxy returned its own page (try direct connection or Burp tunnel settings)"
        return r

    if raw.startswith(b"HTTP/"):
        return _parse_http_response(raw, url)

    inferred = _infer_http_status_from_body(raw)
    r = requests.Response()
    r.url = url
    r.status_code = inferred if inferred is not None else 200
    r._content = raw
    r.headers = CaseInsensitiveDict({"X-Assumed-Protocol": "HTTP/0.9"})
    return r


def _recv_http_bytes(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            block = sock.recv(65536)
        except socket.timeout:
            break
        if not block:
            break
        chunks.append(block)
    return b"".join(chunks)


def _parse_http_response(raw: bytes, url: str) -> requests.Response:
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        inferred = _infer_http_status_from_body(raw)
        r = requests.Response()
        r.url = url
        r.status_code = inferred if inferred is not None else 200
        r._content = raw
        r.headers = CaseInsensitiveDict({"X-Assumed-Protocol": "HTTP/0.9"})
        return r

    head = raw[:header_end]
    body = raw[header_end + 4:]
    first_line = head.split(b"\r\n", 1)[0]
    match = re.match(rb"HTTP/\d\.\d (\d{3})", first_line)
    status = int(match.group(1)) if match else 0
    hdrs = CaseInsensitiveDict()
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        hdrs[name.decode("latin-1", "replace").strip()] = value.decode("latin-1", "replace").strip()
    cl = hdrs.get("Content-Length")
    if cl and cl.isdigit():
        want = int(cl)
        body = body[:want]
    r = requests.Response()
    r.url = url
    r.status_code = status
    r._content = body
    r.headers = hdrs
    return r


def _http_client_connection_pair(major: int, minor: int) -> tuple[type[http.client.HTTPConnection], type[http.client.HTTPSConnection]]:
    vsn = major * 10 + minor
    ver_str = f"HTTP/{major}.{minor}"

    class _H(http.client.HTTPConnection):
        _http_vsn = vsn
        _http_vsn_str = ver_str

    class _HS(http.client.HTTPSConnection):
        _http_vsn = vsn
        _http_vsn_str = ver_str

    return _H, _HS


_HttpConnPairCache: dict[tuple[int, int], tuple[type, type]] = {}


def _cached_http_connection_pair(major: int, minor: int) -> tuple[type, type]:
    key = (major, minor)
    if key not in _HttpConnPairCache:
        _HttpConnPairCache[key] = _http_client_connection_pair(major, minor)
    return _HttpConnPairCache[key]


def _parse_http_protocol_version_line(raw: str) -> str | None:
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    sl = s.strip().lower().replace(" ", "")
    if sl in ("2", "http/2", "h2", "https/2"):
        return "2"
    if sl in ("2-real", "http/2-real", "h2-real"):
        return "2-real"
    if sl in ("1.1", "http/1.1"):
        return "1.1"
    if sl in ("1.0", "http/1.0"):
        return "1.0"
    if sl in ("1.0-no-host", "http/1.0-no-host", "1.0nohost", "1.0+nohost"):
        return "1.0-no-host"
    if sl in ("0.9", "http/0.9"):
        return "0.9"
    if sl in ("0.9-real", "http/0.9-real"):
        return "0.9-real"
    return None


def load_http_protocol_versions(templates_dir: str) -> list[str]:
    path = os.path.join(templates_dir, "http_protocol_versions.txt")
    out: list[str] = []
    seen: set[str] = set()
    for line in _read_lines(path, skip_comment_lines=True):
        tok = _parse_http_protocol_version_line(line)
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


_PROTOCOL_VERSION_LABELS: dict[str, str] = {
    "2":           "GET HTTP/2",
    "1.1":         "GET HTTP/1.1",
    "1.0":         "GET HTTP/1.0",
    "1.0-no-host": "GET HTTP/1.0 (no Host)",
    "0.9":         "GET HTTP/0.9",
}


def load_midpaths(templates_dir: str) -> list[str]:
    return _read_lines(os.path.join(templates_dir, "path_mid.txt"), skip_comment_lines=False)


def load_endpaths(templates_dir: str) -> list[str]:
    return _read_lines(os.path.join(templates_dir, "path_end.txt"), skip_comment_lines=False)


def _strip_unicode_format_chars(s: str) -> str:
    return "".join(ch for ch in s if unicodedata.category(ch) != "Cf")


def load_extensions(templates_dir: str) -> list[str]:
    path = os.path.join(templates_dir, "extensions.txt")
    out: list[str] = []
    seen: set[str] = set()
    for line in _read_lines(path, skip_comment_lines=False):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        s = _strip_unicode_format_chars(raw).strip()
        if not s or s.startswith("#"):
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def path_directory_and_last(parsed: urlparse) -> tuple[str, str]:
    path = parsed.path or "/"
    if path == "/":
        return "/", ""
    if path.endswith("/"):
        body = path.rstrip("/")
        parent, _, seg = body.rpartition("/")
        last = seg + "/"
        directory = parent if parent.startswith("/") else ("/" + parent if parent else "/")
        if directory == "":
            directory = "/"
        return directory, last
    parent, _, seg = path.rpartition("/")
    directory = parent if parent.startswith("/") else ("/" + parent if parent else "/")
    return directory, seg


def url_with_path(url: str, new_path: str) -> str:
    p = urlparse(url)
    if not new_path.startswith("/"):
        new_path = "/" + new_path
    return urlunparse(p._replace(path=new_path))


def merge_target_path(target: str, new_path: str) -> str:
    p = urlparse(target)
    if "?" in new_path:
        path_part, _, q = new_path.partition("?")
        if not path_part.startswith("/"):
            path_part = "/" + path_part
        return urlunparse(p._replace(path=path_part, query=q))
    return url_with_path(target, new_path)


def _url_for_raw_request(url: str) -> str:
    p = urlparse(url)
    raw_path = unquote(p.path or "/")
    enc_path = quote(raw_path, safe="/")
    if p.query:
        raw_q = unquote(p.query)
        enc_query = quote(raw_q, safe="=&%+/:?-._~!$'()*,;@[]")
    else:
        enc_query = ""
    return urlunparse(p._replace(path=enc_path, query=enc_query))


def apply_path_suffix(url: str, suffix: str) -> str:
    p = urlparse(url)
    if suffix.startswith("?"):
        q = suffix[1:]
        new_q = q if not p.query else f"{p.query}&{q}"
        return urlunparse(p._replace(query=new_q))
    return urlunparse(p._replace(path=(p.path or "/") + suffix))


def join_path_mid(directory: str, mid: str, last: str) -> str:
    left = directory.rstrip("/")
    if mid:
        path = f"{left}/{mid}/{last}" if left else f"/{mid}/{last}"
    else:
        path = f"{left}/{last}" if left else f"/{last}"
    if not path.startswith("/"):
        path = "/" + path
    return path


def join_path_end(directory: str, last: str, end: str) -> str:
    return join_path_mid(directory, "", last) + end


def case_flip_variants(last_segment: str) -> list[str]:
    if not last_segment:
        return []
    chars = list(last_segment)
    out: list[str] = []
    for i, ch in enumerate(chars):
        if not ch.isalpha():
            continue
        c = chars[:]
        c[i] = ch.swapcase()
        out.append("".join(c))
    return out


def percent_encode_first_alpha(segment: str) -> str | None:
    for i, ch in enumerate(segment):
        if ch.isalpha():
            enc = f"%{ord(ch):02x}"
            return segment[:i] + enc + segment[i + 1:]
    return None


def extra_obfuscation_paths(parsed: urlparse) -> list[tuple[str, str]]:
    directory, last = path_directory_and_last(parsed)
    if not last:
        return []
    d = directory.rstrip("/")
    prefix = d if d else ""
    rows: list[tuple[str, str]] = []

    def add(label: str, path: str) -> None:
        if not path.startswith("/"):
            path = "/" + path
        rows.append((label, path))

    add("%2e/", join_path_mid(directory, "%2e", last))
    add("unicode-slash", join_path_mid(directory, "%ef%bc%8f", last))
    add("trail-?", join_path_end(directory, last, "?"))
    add("trail-??", join_path_end(directory, last, "??"))
    add("trail-//", join_path_end(directory, last, "//"))
    add("trail-/", join_path_end(directory, last, "/"))
    add("././", f"/./{last}/./" if prefix == "" else f"{prefix}/./{last}/./")
    add("dot-random", join_path_end(directory, last, "/.randomstring"))
    add("trail-..;/", join_path_end(directory, last, "..;/"))
    add("trail-..;", join_path_end(directory, last, "..;"))
    add(".;/", join_path_mid(directory, ".;", last))
    add(".;/./", join_path_mid(directory, ".;", last) + "/./")
    add(";foo=bar/", join_path_mid(directory, ";foo=bar", last))
    raw_last = last.rstrip("/")
    keep_slash = last.endswith("/")
    pe = percent_encode_first_alpha(raw_last)
    if pe:
        new_last = pe + ("/" if keep_slash else "")
        add("pct-first-alpha", join_path_mid(directory, "", new_last))

    return rows


def _adapt_raw_to_requests_like(raw) -> requests.Response:
    r = requests.Response()
    r.status_code = raw.status
    r._content = raw.content
    r.headers = CaseInsensitiveDict(dict(raw.headers))
    r.url = raw.url
    return r


class Pt403Bypass:
    RAW_TYPES = frozenset({"path", "path_mid", "path_end", "path_ext", "path_case", "path_extra"})

    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.args = args
        self.findings = []
        self.output_width = 34
        self._raw_client = RawHttpClient() if RawHttpClient is not None else None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        target = self._normalize_target(self.args.url)
        baseline = self._send(target, "GET", self.args.headers.copy(), use_raw=False)

        if baseline.status_code == 0:
            detail = (baseline.content or b"").decode("utf-8", "replace").strip() or None
            self.ptjsonlib.end_error(
                "Error retrieving initial responses:",
                self.args.json,
                details=detail,
            )

        tests = self._build_tests(target)
        if self.args.max_tests > 0:
            tests = tests[: self.args.max_tests]
        self.output_width = self._compute_output_width(tests, extra_labels=[target])

        baseline_status = baseline.status_code
        if not self.args.json:
            self._print_baseline_warnings(baseline_status)
            self._print_tested_url(target, baseline)

        # Group tests by section, then execute each section with threads
        sections: list[tuple[str, list[dict]]] = []
        current_section: str | None = None
        current_group: list[dict] = []
        for test in tests:
            section = self._get_section_title(test["type"])
            if section != current_section:
                if current_group:
                    sections.append((current_section, current_group))
                current_section = section
                current_group = []
            current_group.append(test)
        if current_group:
            sections.append((current_section, current_group))

        for section_title, section_tests in sections:
            self._run_section(section_title, section_tests, baseline_status)

        self._emit_results(len(tests))

    # ------------------------------------------------------------------
    # Section execution with threads + immediate output
    # ------------------------------------------------------------------

    def _run_section(
        self,
        section_title: str,
        tests: list[dict],
        baseline_status: int,
    ) -> None:
        """Run all tests in a section using a thread pool; print results as they arrive."""
        # Submit all requests concurrently; preserve arrival order for output via future map
        max_workers = min(10, len(tests))
        futures: list = []  # (future, test)

        header_printed = False

        # We need results in submission order so that the same-type tests stay grouped.
        # Use a simple ordered-results approach: collect (index, test, response) tuples.
        results: list[tuple[int, dict, requests.Response]] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx: dict = {}
            for idx, test in enumerate(tests):
                f = executor.submit(
                    self._send,
                    test["url"],
                    test["method"],
                    test["headers"],
                    None,
                    use_raw=test.get("use_raw", False),
                    http_proto=test.get("http_proto"),
                )
                future_to_idx[f] = idx

            for f in as_completed(future_to_idx):
                idx = future_to_idx[f]
                test = tests[idx]
                try:
                    response = f.result()
                except Exception as exc:
                    response = requests.Response()
                    response.status_code = 0
                    response._content = str(exc).encode()
                    response.url = test["url"]

                results.append((idx, test, response))

                status_code = response.status_code

                # Findings
                if self._is_bypass(baseline_status, status_code):
                    finding = {
                        "type": test["type"],
                        "method": test["method"],
                        "url": test["url"],
                        "status": status_code,
                        "headers": test["headers"],
                    }
                    if test.get("http_proto"):
                        finding["http_proto"] = test["http_proto"]
                    self.findings.append(finding)

                # Immediate CLI output
                if not self.args.json:
                    should_print, as_addition = self._should_print_result(test, response, baseline_status)
                    if should_print:
                        if not header_printed:
                            ptprint(f"Testing {section_title}:", "INFO", condition=True, colortext=True)
                            header_printed = True
                        if as_addition:
                            self._print_addition_line(test, response)
                        else:
                            self._print_test_line(test, baseline_status, response, respect_show_filter=False)

    # ------------------------------------------------------------------
    # Visibility / filter helpers
    # ------------------------------------------------------------------

    def _is_default_hidden_status(self, status_code: int) -> bool:
        """401/403/404 are never printed unless explicitly whitelisted via -s."""
        if status_code not in DEFAULT_HIDE_STATUSES:
            return False
        if self.args.show_statuses is not None and status_code in self.args.show_statuses:
            return False
        return True

    def _is_suppressed_by_hide_flag(self, status_code: int) -> bool:
        if not self.args.hide_statuses or status_code not in self.args.hide_statuses:
            return False
        if self.args.show_statuses is not None and status_code in self.args.show_statuses:
            return False
        return True

    def _is_status_hidden(self, status_code: int) -> bool:
        if self._is_default_hidden_status(status_code):
            return True
        if self.args.verbose:
            return False
        return self._is_suppressed_by_hide_flag(status_code)

    def _should_print_result(
        self,
        test: dict,
        response: requests.Response,
        baseline_status: int,
    ) -> tuple[bool, bool]:
        """Return (should_print, as_addition).

        Rules (in priority order):
        1. status_code == 0  → always print as ADDITIONS (no filter applied).
        2. 401/403/404         → never print unless listed in -s (all modes, including -vv).
        3. -vv (verbose)     → print remaining lines; same-as-baseline as ADDITIONS.
        4. -e filter         → skip in normal mode only.
        5. -s filter         → only print if status in show_statuses.
        6. Baseline status filter (no -vv): skip if status matches baseline.
        """
        status_code = response.status_code

        # Rule 1: no valid HTTP response
        if status_code == 0:
            return True, True

        # Rule 2: 401/403/404 unless explicitly -s
        if self._is_default_hidden_status(status_code):
            return False, False

        verbose = self.args.verbose

        # Rule 3: verbose mode — show everything else; same status as baseline as ADDITIONS
        if verbose:
            return True, status_code == baseline_status

        # Rule 4: -e (normal mode only; -s overrides -e for the same code)
        if self._is_suppressed_by_hide_flag(status_code):
            return False, False

        # Rule 5: -s (show_statuses whitelist; -s overrides baseline-status dedup)
        if self.args.show_statuses is not None:
            return status_code in self.args.show_statuses, False

        # Rule 6: same HTTP status as baseline
        if status_code == baseline_status:
            return False, False

        return True, False

    def _status_visible(self, status_code: int) -> bool:
        if self._is_status_hidden(status_code):
            return False
        if self.args.show_statuses is not None:
            return status_code in self.args.show_statuses
        return True

    def _emit_results(self, tested_count: int) -> None:
        if self.findings:
            self.ptjsonlib.add_vulnerability("PTV-WEB-403-BYPASS")
            for finding in self.findings:
                details = (
                    f"type={finding['type']} method={finding['method']} status={finding['status']} "
                    f"url={finding['url']} headers={finding['headers']}"
                )
                self.ptjsonlib.add_vulnerability("PTV-WEB-403-BYPASS", details)
        else:
            ptprint("No bypass found with the current payload set.", "INFO", condition=not self.args.json)

        self.ptjsonlib.set_status("finished")
        result = self.ptjsonlib.get_result_json()
        ptprint(result, "", self.args.json)

    def _effective_methods(self, tdir: str) -> list[str]:
        base = [m.upper() for m in self.args.methods]
        file_methods = load_methods(tdir)
        merged: list[str] = []
        seen: set[str] = set()
        for m in file_methods + base:
            u = m.upper()
            if u and u not in seen:
                seen.add(u)
                merged.append(u)
        return merged

    def _path_uses_raw(self) -> bool:
        return self._raw_client is not None

    def _build_tests(self, target: str) -> list:
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        base_path = parsed.path if parsed.path else "/admin"
        stripped = base_path.lstrip("/") or "admin"
        tdir = _templates_dir(self.args.templates_dir)
        base_headers = self.args.headers.copy()
        raw_ok = self._path_uses_raw()

        tests: list[dict] = []

        def add(
            t_type: str,
            method: str,
            url: str,
            headers: dict,
            *,
            header: dict | None = None,
            label: str | None = None,
            use_raw: bool | None = None,
            http_proto: str | None = None,
        ) -> None:
            if use_raw is None:
                ur = raw_ok and t_type in Pt403Bypass.RAW_TYPES
            else:
                ur = use_raw and raw_ok
            tests.append(
                {
                    "type": t_type,
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "header": header,
                    "label": label,
                    "use_raw": ur,
                    "http_proto": http_proto,
                }
            )

        # 1) HTTP methods
        for method in self._effective_methods(tdir):
            add("method", method, target, base_headers.copy(), label=f"Method: {method}", use_raw=False)

        # 2) source_ip_headers.txt × ip.txt
        for hname, hval in load_header_ip_pairs(tdir):
            formatted = _format_ip_for_header(hname, hval)
            hdr = {hname: formatted}
            m = base_headers.copy()
            m.update(hdr)
            add("header", "GET", target, m, header=hdr, label=f"{hname}: {formatted}", use_raw=False)

        for hdrs in load_static_header_payloads(tdir):
            rendered = {k: v.format(path=base_path, origin=origin) for k, v in hdrs.items()}
            m = base_headers.copy()
            m.update(rendered)
            key = next(iter(rendered))
            val = rendered[key]
            lbl = f"{key}: {val}" if len(val) < 64 else f"{key}: {val[:60]}..."
            add("header", "GET", target, m, header=rendered, label=lbl, use_raw=False)

        for combo_tpl in load_header_combo_sets(tdir):
            rendered = {k: v.format(path=base_path, origin=origin) for k, v in combo_tpl.items()}
            m = base_headers.copy()
            m.update(rendered)
            lbl = " + ".join(rendered.keys())
            add("header", "GET", target, m, header=rendered, label=lbl, use_raw=False)

        root_url = urlunparse(parsed._replace(path="/", params="", query="", fragment=""))
        rewrite_variants: list[str] = [stripped, "/" + stripped]
        seen_rw: set[str] = set()
        for rewrite_val in rewrite_variants:
            if rewrite_val in seen_rw:
                continue
            seen_rw.add(rewrite_val)
            m_rw = base_headers.copy()
            m_rw["X-Rewrite-URL"] = rewrite_val
            add(
                "header",
                "GET",
                root_url,
                m_rw,
                header={"X-Rewrite-URL": rewrite_val},
                label=f"X-Rewrite-URL @ origin → {rewrite_val}",
                use_raw=False,
            )

        m_cl = base_headers.copy()
        m_cl["Content-Length"] = "0"
        add(
            "header",
            "POST",
            target,
            m_cl,
            label="POST Content-Length: 0",
            use_raw=False,
        )

        for h_strip in load_connection_strip_header_names(tdir):
            m = base_headers.copy()
            m["Connection"] = f"close, {h_strip}"
            add("connection_hop", "GET", target, m, label=f"Connection: close, {h_strip}", use_raw=False)

        # 3) User-Agents
        for ua in load_user_agents(tdir):
            m = base_headers.copy()
            m["User-Agent"] = ua
            lbl = ua if len(ua) <= 72 else ua[:69] + "..."
            add("user_agent", "GET", target, m, label=f"UA: {lbl}", use_raw=False)

        # 4) path_patterns.txt
        for pattern in load_path_payloads(tdir):
            candidate = pattern.format(
                path=base_path,
                stripped=stripped,
                stripped_upper=stripped.upper(),
                stripped_lower=stripped.lower(),
                long_dot_prefix=LONG_DOT_PREFIX,
                long_encoded_dot_prefix=LONG_ENCODED_DOT_PREFIX,
            )
            if not candidate.startswith("/"):
                candidate = "/" + candidate
            u = url_with_path(target, candidate)
            add("path", "GET", u, base_headers.copy(), label=u)

        # 5) path_mid.txt
        directory, last = path_directory_and_last(parsed)
        if last:
            for mid in load_midpaths(tdir):
                new_path = join_path_mid(directory, mid, last)
                u = url_with_path(target, new_path)
                add("path_mid", "GET", u, base_headers.copy(), label=u)

        # 6) path_end.txt
        if last:
            for end in load_endpaths(tdir):
                new_path = join_path_end(directory, last, end)
                u = merge_target_path(target, new_path)
                add("path_end", "GET", u, base_headers.copy(), label=u)

        # 7) extensions.txt
        for ext in load_extensions(tdir):
            u = apply_path_suffix(target, ext)
            add("path_ext", "GET", u, base_headers.copy(), label=u)

        # 8) Case variations
        if last.rstrip("/"):
            raw_last = last.rstrip("/")
            keep_slash = last.endswith("/")
            for variant in case_flip_variants(raw_last):
                new_last = variant + ("/" if keep_slash else "")
                new_path = join_path_mid(directory, "", new_last)
                u = url_with_path(target, new_path)
                add("path_case", "GET", u, base_headers.copy(), label=u)

        # 9) Path tricks
        for _label, new_path in extra_obfuscation_paths(parsed):
            u = merge_target_path(target, new_path)
            add("path_extra", "GET", u, base_headers.copy(), label=u)

        # 10) HTTP protocol versions
        for tok in load_http_protocol_versions(tdir):
            lbl = _PROTOCOL_VERSION_LABELS.get(tok, f"GET HTTP/{tok}")
            add(
                "protocol",
                "GET",
                target,
                base_headers.copy(),
                label=lbl,
                use_raw=False,
                http_proto=tok,
            )

        return tests

    def _get_section_title(self, test_type: str) -> str:
        if test_type == "method":
            return "HTTP methods"
        if test_type in ("header",):
            return "HTTP request headers"
        if test_type == "user_agent":
            return "User-Agents"
        if test_type == "path":
            return "URL paths"
        if test_type == "path_mid":
            return "mid-path payloads"
        if test_type == "path_end":
            return "end-path payloads"
        if test_type == "path_ext":
            return "extensions"
        if test_type == "path_case":
            return "case variations"
        if test_type == "path_extra":
            return "path tricks"
        if test_type == "connection_hop":
            return "Connection hop-by-hop"
        if test_type == "protocol":
            return "HTTP protocol version"
        return "other tests"

    def _print_baseline_warnings(self, status_code: int) -> None:
        if self.args.json:
            return
        if status_code == 404:
            ptprint(
                "Baseline URL returned 404; the target may not exist. Continuing with tests.",
                "WARNING",
                condition=True,
                colortext=True,
            )
        elif status_code == 200:
            ptprint(
                "Baseline URL returned 200; access may not be restricted. Continuing with tests.",
                "WARNING",
                condition=True,
                colortext=True,
            )

    def _print_tested_url(self, url: str, response: requests.Response) -> None:
        if self.args.json:
            return
        status_code = response.status_code
        ptprint("Tested URL", "INFO", condition=True, colortext=True)
        if status_code == 0:
            line = f"{url:<{self.output_width}}  {_format_status_suffix(response)}"
            ptprint(line, "ADDITIONS", condition=not self.args.json, indent=4, colortext=True)
        else:
            self._print_result_line(url, _format_status_suffix(response))

    def _print_result_line(self, label: str, suffix: str, *, colorize: bool = False) -> None:
        indent = "    "
        prefix = f"{WHITE}{indent}" if colorize else indent
        reset = RESET if colorize else ""
        suffix_part = f"  {suffix}"
        link_url = label if _is_web_url(label) else None
        link_id = _link_id_for_url(link_url) if link_url else None

        if len(label) <= self.output_width:
            line = f"{_format_label_text(label, self.output_width, link_url=link_url, link_id=link_id)}{suffix_part}"
            print(f"{prefix}{line}{reset}")
            return

        prefix_lines, last_segment = _split_label_for_output(label, self.output_width)
        padded_last = last_segment + (" " * max(0, self.output_width - len(last_segment)))

        if link_url:
            link_visible = prefix_lines[0]
            for chunk in prefix_lines[1:]:
                link_visible += f"\n{indent}{chunk}"
            if prefix_lines:
                link_visible += f"\n{indent}{padded_last}"
            else:
                link_visible = padded_last
            linked = _osc8_hyperlink(link_url, link_visible, link_id=link_id)
            print(f"{prefix}{linked}{suffix_part}{reset}")
            return

        for chunk in prefix_lines:
            print(f"{prefix}{chunk}{reset}")
        print(f"{prefix}{padded_last}{suffix_part}{reset}")

    def _test_label(self, test: dict) -> str:
        if test.get("label"):
            return test["label"]
        if test["type"] == "path":
            return test["url"]
        if test["type"] == "header":
            header = test.get("header") or {}
            if header:
                k, v = next(iter(header.items()))
                return f"{k}: {v}"
        if test["type"] == "method":
            return f"Method: {test['method']}"
        return f"{test['type']} {test['method']}"

    def _print_test_line(
        self,
        test: dict,
        baseline_status: int,
        response: requests.Response,
        *,
        respect_show_filter: bool = True,
    ) -> None:
        if self.args.json:
            return
        status_code = response.status_code
        if respect_show_filter and not self._status_visible(status_code):
            return
        interesting = status_code != baseline_status
        label = self._test_label(test)
        suffix = _format_status_suffix(response, colorize=interesting)
        self._print_result_line(label, suffix, colorize=interesting)

    def _print_addition_line(self, test: dict, response: requests.Response) -> None:
        if self.args.json:
            return
        label = self._test_label(test)
        suffix = _display_http_status(response.status_code)
        detail = (response.content or b"").decode("utf-8", "replace").strip()
        if detail:
            detail = " ".join(detail.split())
            if len(detail) > 72:
                detail = detail[:69] + "..."
            suffix = f"{suffix} {detail}"
        if len(label) <= self.output_width:
            line = f"{label:<{self.output_width}}  {suffix}"
            ptprint(line, "ADDITIONS", condition=not self.args.json, indent=4, colortext=True)
        else:
            self._print_result_line(label, suffix)

    def _compute_output_width(self, tests: list, extra_labels: list | None = None) -> int:
        labels = list(extra_labels) if extra_labels else []
        for test in tests:
            labels.append(self._test_label(test))
        if not labels:
            return 34
        return max(34, min(96, max(len(label) for label in labels) + 2))

    def _is_bypass(self, baseline: int, candidate: int) -> bool:
        if candidate == 0:
            return False
        if candidate in BLOCKED_STATUS_CODES:
            return False
        if baseline in BLOCKED_STATUS_CODES and candidate not in BLOCKED_STATUS_CODES:
            return True
        return candidate < baseline

    def _proxy_url(self) -> str | None:
        if not self.args.proxy:
            return None
        p = self.args.proxy.get("https") or self.args.proxy.get("http")
        if not p:
            return None
        return _normalize_proxy_url(p)

    def _adapt_httpx_to_requests(self, resp) -> requests.Response:
        r = requests.Response()
        r.status_code = resp.status_code
        r._content = resp.content
        r.headers = CaseInsensitiveDict(dict(resp.headers))
        r.url = str(resp.url)
        return r

    def _send_http2_via_connect_tunnel(
        self,
        url: str,
        method: str,
        headers: dict,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        dummy = requests.Response()
        dummy.url = url
        if scheme not in ("http", "https"):
            dummy.status_code = 0
            dummy._content = b"HTTP/2: unsupported URL scheme"
            return dummy

        host = parsed.hostname
        if not host:
            dummy.status_code = 0
            dummy._content = b"HTTP/2: missing hostname"
            return dummy

        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        proxy_url = self._proxy_url()
        if not proxy_url:
            dummy.status_code = 0
            dummy._content = b"HTTP/2: proxy URL missing"
            return dummy

        hdrs: dict[str, str] = {str(k): str(v) for k, v in headers.items()}
        if auth is not None:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            hdrs["Authorization"] = f"Basic {token}"

        timeout = self.args.timeout
        tunneled_sock: socket.socket | None = None

        try:
            if scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                ssl_ctx.set_alpn_protocols(["http/1.1"])

                tunneled_sock = _open_plain_target_socket(
                    host, port, proxy_url=proxy_url, timeout=timeout,
                )
                conn = _http_client_connection_from_socket(
                    tunneled_sock,
                    host,
                    port,
                    1,
                    1,
                    timeout,
                    scheme="https",
                    ssl_context=ssl_ctx,
                )
                conn.request(method.upper(), path, body=None, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read()
                negotiated = None
                if getattr(conn, "sock", None) is not None:
                    negotiated = conn.sock.selected_alpn_protocol()
                conn.close()
                r = requests.Response()
                r.status_code = resp.status
                r._content = data
                r.headers = CaseInsensitiveDict(dict(resp.headers))
                if negotiated:
                    r.headers["X-Negotiated-Protocol"] = negotiated
                r.url = url
                return r

            tunneled_sock = _open_plain_target_socket(
                host, port, proxy_url=proxy_url, timeout=timeout,
            )
            hdrs.setdefault("Host", host)
            h2_settings = "AAMAAABkAAQCAAQA="
            lines = [f"{method.upper()} {path} HTTP/1.1"]
            for key, value in hdrs.items():
                if key.lower() == "connection":
                    continue
                lines.append(f"{key}: {value}")
            lines.extend([
                "Connection: Upgrade, HTTP2-Settings",
                "Upgrade: h2c",
                f"HTTP2-Settings: {h2_settings}",
                "",
                "",
            ])
            tunneled_sock.sendall("\r\n".join(lines).encode("ascii", errors="strict"))
            raw = _recv_http_bytes(tunneled_sock, timeout)
            r = _parse_http_response(raw, url)
            r.headers["X-Requested-Protocol"] = "h2c"
            return r
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            dummy.status_code = 0
            dummy._content = str(exc).encode()
            if self.args.verbose:
                ptprint(f"HTTP/2 (CONNECT) request failed ({url}): {exc}", "INFO", condition=True, colortext=True)
            return dummy
        finally:
            if tunneled_sock is not None:
                try:
                    tunneled_sock.close()
                except OSError:
                    pass

    def _send_http2_httpx(
        self,
        url: str,
        method: str,
        headers: dict,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        if self._proxy_url():
            return self._send_http2_via_connect_tunnel(url, method, headers, auth)

        dummy = requests.Response()
        dummy.url = url
        try:
            import httpx
        except ImportError:
            dummy.status_code = 0
            dummy._content = b"HTTP/2: install httpx and h2 (e.g. pip install 'httpx[http2]')"
            return dummy
        try:
            client_kw: dict = {
                "http2": True,
                "verify": False,
                "timeout": self.args.timeout,
                "trust_env": False,
            }
            proxy = self._proxy_url()
            if proxy:
                client_kw["proxy"] = proxy
            with httpx.Client(**client_kw) as client:
                r = client.request(method.upper(), url, headers=headers, auth=auth)
            return self._adapt_httpx_to_requests(r)
        except Exception as exc:
            dummy.status_code = 0
            dummy._content = str(exc).encode()
            if self.args.verbose:
                ptprint(f"HTTP/2 request failed ({url}): {exc}", "INFO", condition=True, colortext=True)
            return dummy

    def _send_via_http_client(
        self,
        url: str,
        method: str,
        headers: dict,
        auth: tuple[str, str] | None,
        *,
        major: int,
        minor: int,
        no_host: bool,
    ) -> requests.Response:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        dummy = requests.Response()
        dummy.url = url
        if scheme not in ("http", "https"):
            dummy.status_code = 0
            dummy._content = b"http.client: unsupported URL scheme"
            return dummy

        host = parsed.hostname
        if not host:
            dummy.status_code = 0
            dummy._content = b"http.client: missing hostname"
            return dummy

        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        hdrs: dict[str, str] = {str(k): str(v) for k, v in headers.items()}
        if auth is not None:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            hdrs["Authorization"] = f"Basic {token}"

        timeout = self.args.timeout
        ssl_ctx: ssl.SSLContext | None = None
        if scheme == "https":
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        proxy_url = self._proxy_url()
        tunneled_sock: socket.socket | None = None

        try:
            if proxy_url:
                tunneled_sock = _open_plain_target_socket(
                    host,
                    port,
                    proxy_url=proxy_url,
                    timeout=timeout,
                )
                conn = _http_client_connection_from_socket(
                    tunneled_sock,
                    host,
                    port,
                    major,
                    minor,
                    timeout,
                    scheme=scheme,
                    ssl_context=ssl_ctx if scheme == "https" else None,
                )
            else:
                conn_http, conn_https = _cached_http_connection_pair(major, minor)
                conn_cls = conn_https if scheme == "https" else conn_http
                conn_kw: dict = {"host": host, "port": port, "timeout": timeout}
                if scheme == "https" and ssl_ctx is not None:
                    conn_kw["context"] = ssl_ctx
                conn = conn_cls(**conn_kw)
            if no_host or (major == 1 and minor == 0):
                strip = _headers_without_keys(hdrs, frozenset({"host", "connection"}))
                conn.putrequest(method.upper(), path, skip_host=True)
                if not no_host and host:
                    conn.putheader("Host", host)
                for k, v in strip.items():
                    conn.putheader(k, v)
                conn.endheaders()
                resp = conn.getresponse()
            else:
                conn.request(method.upper(), path, body=None, headers=hdrs)
                resp = conn.getresponse()
            data = resp.read()
            conn.close()
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            dummy.status_code = 0
            dummy._content = str(exc).encode()
            if self.args.verbose:
                ptprint(f"HTTP/{major}.{minor} request failed ({url}): {exc}", "INFO", condition=True, colortext=True)
            return dummy
        else:
            r = requests.Response()
            r.status_code = resp.status
            r._content = data
            r.headers = CaseInsensitiveDict(dict(resp.headers))
            r.url = url
            return r
        finally:
            if tunneled_sock is not None:
                try:
                    tunneled_sock.close()
                except OSError:
                    pass

    def _send_http09(
        self,
        url: str,
        headers: dict,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        dummy = requests.Response()
        dummy.url = url
        if auth is not None:
            dummy.status_code = 0
            dummy._content = b"HTTP/0.9: omitting auth (add dedicated basic tests)"
            return dummy

        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        if scheme not in ("http", "https"):
            dummy.status_code = 0
            dummy._content = b"HTTP/0.9: unsupported scheme"
            return dummy

        host = parsed.hostname
        if not host:
            dummy.status_code = 0
            dummy._content = b"HTTP/0.9: missing hostname"
            return dummy

        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        proxy_url = self._proxy_url()
        timeout = self.args.timeout

        if proxy_url and scheme == "http":
            if self.args.verbose:
                ptprint(
                    "HTTP/0.9 via proxy sends non-standard request line; proxy may reject it.",
                    "INFO",
                    condition=True,
                    colortext=True,
                )
            hdrs = {str(k): str(v) for k, v in headers.items()}
            raw = _proxy_forward_request("GET", url, "HTTP/0.9", hdrs, proxy_url, timeout)
            return _response_from_http09_raw(raw, url)

        try:
            ssl_ctx: ssl.SSLContext | None = None
            if scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            sock = _open_target_socket(
                host,
                port,
                scheme,
                proxy_url=proxy_url,
                timeout=timeout,
                ssl_context=ssl_ctx,
            )
        except (OSError, ValueError) as exc:
            dummy.status_code = 0
            dummy._content = str(exc).encode()
            return dummy

        try:
            sock.sendall(_http09_wire_payload(path))
            raw = _recv_http_bytes(sock, timeout)
        finally:
            sock.close()

        return _response_from_http09_raw(raw, url)

    def _send_by_protocol_version(
        self,
        url: str,
        method: str,
        headers: dict,
        token: str,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        if token == "2":
            return self._send_via_http_client(url, method, headers, auth, major=2, minor=0, no_host=False)
        if token == "1.1":
            return self._send_via_http_client(url, method, headers, auth, major=1, minor=1, no_host=False)
        if token == "1.0":
            return self._send_via_http_client(url, method, headers, auth, major=1, minor=0, no_host=False)
        if token == "1.0-no-host":
            return self._send_via_http_client(url, method, headers, auth, major=1, minor=0, no_host=True)
        if token == "0.9":
            return self._send_via_http_client(url, method, headers, auth, major=0, minor=9, no_host=False)

        d = requests.Response()
        d.status_code = 0
        d.url = url
        d._content = f"unknown protocol token: {token}".encode()
        return d

    def _send_via_requests(
        self,
        url: str,
        method: str,
        headers: dict,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        try:
            kw: dict = {
                "method": method,
                "url": url,
                "headers": headers,
                "timeout": self.args.timeout,
                "proxies": self.args.proxy,
                "allow_redirects": self.args.redirects,
                "verify": False,
            }
            if auth is not None:
                kw["auth"] = auth
            return requests.request(**kw)
        except requests.RequestException as exc:
            remapped = _remap_requests_exception_ptlibs(exc)
            dummy = requests.Response()
            dummy.status_code = 0
            dummy._content = str(remapped).encode()
            dummy.url = url
            return dummy

    def _send(
        self,
        url: str,
        method: str,
        headers: dict,
        auth: tuple[str, str] | None = None,
        *,
        use_raw: bool = False,
        http_proto: str | None = None,
    ) -> requests.Response:
        if http_proto:
            return self._send_by_protocol_version(url, method, headers, http_proto, auth)
        if use_raw and self._raw_client is not None:
            try:
                hdrs = dict(headers)
                if auth is not None:
                    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
                    hdrs["Authorization"] = f"Basic {token}"
                raw_url = _url_for_raw_request(url)
                raw = self._raw_client._send_raw_request(
                    url=raw_url,
                    method=method,
                    headers=hdrs,
                    timeout=self.args.timeout,
                    proxies=self.args.proxy if self.args.proxy else None,
                )
                return _adapt_raw_to_requests_like(raw)
            except Exception as exc:
                if self.args.verbose:
                    u = url if len(url) <= 80 else url[:77] + "..."
                    ptprint(f"Raw HTTP failed ({u}): {exc}", "INFO", condition=True, colortext=True)
                return self._send_via_requests(url, method, headers, auth)
        return self._send_via_requests(url, method, headers, auth)

    def _normalize_target(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"https://{url}"
        if not parsed.path:
            parsed = parsed._replace(path="/admin")
        return urlunparse(parsed)


def get_help():
    return [
        {"description": ["Penterep 401/403 bypass testing tool"]},
        {"usage": ["pt403bypass <options>"]},
        {"usage_example": [
            "pt403bypass -u https://www.example.com/admin",
            "pt403bypass -u https://www.example.com/private -vv -m 500",
            "pt403bypass -u https://www.example.com/api -s 200",
            "pt403bypass -u https://www.example.com/api -e 404 500",
        ]},
        {"options": [
            ["-u",  "--url",                   "<url>",           "Protected URL to test"],
            ["-p",  "--proxy",                 "<proxy>",         "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",               "<seconds>",       "Set timeout (default 10)"],
            ["-c",  "--cookie",                "<cookie>",        "Set cookie"],
            ["-a",  "--user-agent",            "<a>",             "Set User-Agent header"],
            ["-H",  "--headers",               "<header:value>",  "Set custom header(s)"],
            ["-r",  "--redirects",             "",                "Follow redirects (default False)"],
            ["-s",  "--show-status",           "<code...>",       "Only print result lines with these HTTP status codes"],
            ["-e",  "--hide-status",           "<code...>",       "Hide extra status codes in normal mode (default: 401 403 404; use -s to show them)"],
            ["-x",  "--methods",               "<method...>",     "HTTP methods (default: templates/methods.txt); merged with methods.txt"],
            ["-m",  "--max-tests",             "<n>",             "Limit payload count (default 0 = unlimited)"],
            ["-C",  "--cache",                 "",                "Cache compatibility flag"],
            ["-vv", "--verbose",               "",                "Verbose: show all lines except 401/403/404 (unless -s); same-as-baseline as ADDITIONS"],
            ["-v",  "--version",               "",                "Show script version and exit"],
            ["-h",  "--help",                  "",                "Show this help message and exit"],
            ["-j",  "--json",                  "",                "Output in JSON format"],
            ["",    "--templates-dir",         "<dir>",           "Directory for *.txt payload lists (default: package templates/)"],
        ]}
    ]


def parse_args():
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",            type=str, required=True)
    parser.add_argument("-p",  "--proxy",          type=str)
    parser.add_argument("-T",  "--timeout",        type=int, default=10)
    parser.add_argument("-a",  "--user-agent",     type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie",         type=str)
    parser.add_argument("-H",  "--headers",        type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-r",  "--redirects",      action="store_true")
    parser.add_argument(
        "-s",
        "--show-status",
        dest="show_statuses",
        type=int,
        nargs="+",
        default=None,
        metavar="CODE",
    )
    parser.add_argument(
        "-e",
        "--hide-status",
        dest="hide_statuses",
        type=int,
        nargs="+",
        default=sorted(DEFAULT_HIDE_STATUSES),
        metavar="CODE",
    )
    parser.add_argument("-x",  "--methods",        type=lambda s: s.upper(), nargs="+", default=default_methods_for_argparse())
    parser.add_argument("-m",  "--max-tests",      type=int, default=0)
    parser.add_argument("-C",  "--cache",          action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-vv", "--verbose",        action="store_true", dest="verbose")

    parser.add_argument("--socket-address", type=str, default=None)
    parser.add_argument("--socket-port", type=str, default=None)
    parser.add_argument("--process-ident", type=str, default=None)
    parser.add_argument("--templates-dir", type=str, default=None)

    parser.add_argument("-v", "--version", action="version", version=f"{SCRIPTNAME} {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    args.hide_statuses = frozenset(args.hide_statuses)
    if args.show_statuses is not None:
        args.show_statuses = frozenset(args.show_statuses)

    if args.proxy:
        args.proxy = {"http": args.proxy, "https": args.proxy}
    else:
        args.proxy = {}

    args.headers = ptnethelper.get_request_headers(args)

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "pt403bypass"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = Pt403Bypass(args)
    script.run()


if __name__ == "__main__":
    main()