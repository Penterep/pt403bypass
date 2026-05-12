#!/usr/bin/python3
"""
Copyright (c) 2026 Penterep Security s.r.o.

pt403bypass - testing tool for 401/403 authorization bypass techniques.

Template *.txt under templates/: source_ip_headers × ip, methods, path_patterns /
(path_patterns placeholders: {path}, {stripped}, {stripped_upper}, {stripped_lower}),
path_mid / path_end, extensions, static_headers, header_combos, user_agents,
connection_strip_headers (hop-by-hop Connection fuzzing), http_protocol_versions.
Logic and CLI live in this module.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import ssl
import sys
import unicodedata

sys.path.append(__file__.rsplit("/", 1)[0])
from urllib.parse import quote, unquote, urlparse, urlunparse

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


GRAY = "\033[90m"
WHITE = "\033[97m"
RESET = "\033[0m"

BLOCKED_STATUS_CODES: frozenset[int] = frozenset({401, 403})


def _display_http_status(code: int) -> str:
    """CLI suffix: ``[code]`` including ``[0]`` when there is no valid HTTP response."""
    return f"[{code}]"


def _remap_requests_exception_ptlibs(exc: requests.RequestException) -> requests.RequestException:
    """Same short messages as pttechnologies (ptlibs HttpClient._remap_requests_exception)."""
    try:
        # `self` is unused inside _remap_requests_exception
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
    """Default -x list is templates/methods.txt (merged at runtime with explicit -x)."""
    return load_methods(_templates_dir(None))


def load_user_agents(templates_dir: str) -> list[str]:
    path = os.path.join(templates_dir, "user_agents.txt")
    return [x.strip() for x in _read_lines(path, skip_comment_lines=True) if x.strip()]


def load_connection_strip_header_names(templates_dir: str) -> list[str]:
    """Header names to pair with ``Connection: close, <name>`` (hop-by-hop strip fuzzing)."""
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


def _http_client_connection_pair(major: int, minor: int) -> tuple[type[http.client.HTTPConnection], type[http.client.HTTPSConnection]]:
    """Build ``HTTP/x.y`` request line classes for a specific minor protocol version."""
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
    """Normalize one template line to: ``2`` | ``1.1`` | ``1.0`` | ``1.0-no-host`` | ``0.9``."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    sl = s.strip().lower().replace(" ", "")
    if sl in ("2", "http/2", "h2", "https/2"):
        return "2"
    if sl in ("1.1", "http/1.1"):
        return "1.1"
    if sl in ("1.0", "http/1.0"):
        return "1.0"
    if sl in ("1.0-no-host", "http/1.0-no-host", "1.0nohost", "1.0+nohost"):
        return "1.0-no-host"
    if sl in ("0.9", "http/0.9"):
        return "0.9"
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
    "2": "GET HTTP/2",
    "1.1": "GET HTTP/1.1",
    "1.0": "GET HTTP/1.0",
    "1.0-no-host": "GET HTTP/1.0 (no Host)",
    "0.9": "GET HTTP/0.9",
}


def load_midpaths(templates_dir: str) -> list[str]:
    return _read_lines(os.path.join(templates_dir, "path_mid.txt"), skip_comment_lines=False)


def load_endpaths(templates_dir: str) -> list[str]:
    return _read_lines(os.path.join(templates_dir, "path_end.txt"), skip_comment_lines=False)


def _strip_unicode_format_chars(s: str) -> str:
    """Remove Cf category chars (ZWSP, LRM, BOM, etc.) that break raw HTTP paths and confuse diffs."""
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
    """Split path into (parent directory path, final segment). Final keeps trailing / if present."""
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
    """Apply path (and optional ?query inside new_path) to target's origin."""
    p = urlparse(target)
    if "?" in new_path:
        path_part, _, q = new_path.partition("?")
        if not path_part.startswith("/"):
            path_part = "/" + path_part
        return urlunparse(p._replace(path=path_part, query=q))
    return url_with_path(target, new_path)


def _url_for_raw_request(url: str) -> str:
    """Build an ASCII-only request-target for raw HTTP (spaces, Unicode/IRI → UTF-8 % escapes).

    Raw sockets send ``GET <request-target> HTTP/1.1`` using bytes that must not contain arbitrary
    Unicode: lib code paths often use ASCII. Non-ASCII in the path (e.g. ``°``) must be
    percent-encoded (RFC 3986). We normalize by *unquoting* first so existing ``%2F``-style
    sequences are not double-encoded, then *quote* path and query with UTF-8.
    """
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
    """Append suffix to path, or merge ?suffix into query if suffix starts with ?."""
    p = urlparse(url)
    if suffix.startswith("?"):
        q = suffix[1:]
        new_q = q if not p.query else f"{p.query}&{q}"
        return urlunparse(p._replace(query=new_q))
    return urlunparse(p._replace(path=(p.path or "/") + suffix))


def join_path_mid(directory: str, mid: str, last: str) -> str:
    """Join path segments without collapsing // (payloads may rely on double slashes)."""
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
    """First path character as ``%XX`` (Vidoc-style case / normalization tricks)."""
    for i, ch in enumerate(segment):
        if ch.isalpha():
            enc = f"%{ord(ch):02x}"
            return segment[:i] + enc + segment[i + 1 :]
    return None


def extra_obfuscation_paths(parsed: urlparse) -> list[tuple[str, str]]:
    """Additional path tricks (same ideas as common bypass writeups)."""
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
        if not self.args.json and self._status_visible(baseline_status):
            self._print_tested_url(target, baseline_status)

        current_section: str | None = None
        section_buffer: list[tuple[dict, int]] = []

        for test in tests:
            section = self._get_section_title(test["type"])
            if not self.args.json and section != current_section:
                self._flush_section_buffer(current_section, section_buffer, baseline_status)
                current_section = section
                section_buffer = []

            response = self._send(
                test["url"],
                test["method"],
                test["headers"],
                use_raw=test.get("use_raw", False),
                http_proto=test.get("http_proto"),
            )
            status_code = response.status_code

            if not self.args.json:
                section_buffer.append((test, status_code))

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

        if not self.args.json:
            self._flush_section_buffer(current_section, section_buffer, baseline_status)

        self._emit_results(len(tests))

    def _status_visible(self, status_code: int) -> bool:
        if self.args.hide_statuses and status_code in self.args.hide_statuses:
            return False
        if self.args.show_statuses is not None:
            return status_code in self.args.show_statuses
        return True

    def _flush_section_buffer(
        self,
        section: str | None,
        buffer: list[tuple[dict, int]],
        baseline_status: int,
    ) -> None:
        if not buffer or section is None:
            return
        rows = [(t, st) for t, st in buffer if self._status_visible(st)]
        if not rows:
            return
        verbose = self.args.verbose
        if not verbose and all(st == baseline_status for _, st in rows):
            return
        ptprint(f"Testing {section}:", "INFO", condition=True, colortext=True)
        normal = [(t, st) for t, st in rows if st != 0]
        zeros = [(t, st) for t, st in rows if st == 0]
        for test, st in normal:
            self._print_test_line(test, baseline_status, st, respect_show_filter=False)
        for test, st in zeros:
            self._print_addition_line(test, st)

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
            hdr = {hname: hval}
            m = base_headers.copy()
            m.update(hdr)
            add("header", "GET", target, m, header=hdr, label=f"{hname}: {hval}", use_raw=False)

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

        # iamj0ker/bypass-403.sh: curl $1 -H "X-rewrite-url: $2" (GET origin / only; path in header)
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

        # iamj0ker/bypass-403.sh: POST + Content-Length: 0
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

        # Hop-by-hop: ask intermediaries to strip named headers (Vidoc / Nathan Davison style)
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

        # 9) Path tricks (bug-bounty style)
        for _label, new_path in extra_obfuscation_paths(parsed):
            u = merge_target_path(target, new_path)
            add("path_extra", "GET", u, base_headers.copy(), label=u)

        # 10) HTTP protocol version (http_protocol_versions.txt): 2 / 1.1 / 1.0 / 0.9 …
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

    def _print_tested_url(self, url: str, status_code: int) -> None:
        if self.args.json:
            return
        ptprint("Tested URL", "INFO", condition=True, colortext=True)
        line = f"{url:<{self.output_width}}  {_display_http_status(status_code)}"
        if status_code == 0:
            ptprint(line, "ADDITIONS", condition=not self.args.json, indent=4, colortext=True)
        else:
            print(f"    {line}")

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
        status_code: int,
        *,
        respect_show_filter: bool = True,
    ) -> None:
        if self.args.json:
            return
        if respect_show_filter and not self._status_visible(status_code):
            return
        interesting = status_code != baseline_status
        if self.args.show_statuses is None and not interesting and not self.args.verbose:
            return
        label = self._test_label(test)
        color = WHITE if interesting else GRAY
        print(f"{color}    {label:<{self.output_width}}  {_display_http_status(status_code)}{RESET}")

    def _print_addition_line(self, test: dict, status_code: int) -> None:
        """Rows with HTTP status 0 (no valid response): informational only, not counted as findings."""
        if self.args.json:
            return
        label = self._test_label(test)
        line = f"{label:<{self.output_width}}  {_display_http_status(status_code)}"
        ptprint(line, "ADDITIONS", condition=not self.args.json, indent=4, colortext=True)

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

    def _httpx_proxies(self) -> dict | str | None:
        if not self.args.proxy:
            return None
        p = self.args.proxy.get("https") or self.args.proxy.get("http")
        if not p:
            return None
        return {"http://": p, "https://": p}

    def _adapt_httpx_to_requests(self, resp) -> requests.Response:
        """Map ``httpx.Response`` to a minimal ``requests.Response`` (status, body, headers, url)."""
        r = requests.Response()
        r.status_code = resp.status_code
        r._content = resp.content
        r.headers = CaseInsensitiveDict(dict(resp.headers))
        r.url = str(resp.url)
        return r

    def _send_http2_httpx(
        self,
        url: str,
        method: str,
        headers: dict,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        """HTTP/2 over ALPN (requires ``httpx`` + ``h2``)."""
        dummy = requests.Response()
        dummy.url = url
        try:
            import httpx
        except ImportError:
            dummy.status_code = 0
            dummy._content = b"HTTP/2: install httpx and h2 (e.g. pip install 'httpx[http2]')"
            return dummy
        try:
            with httpx.Client(
                http2=True,
                verify=False,
                proxies=self._httpx_proxies(),
                timeout=self.args.timeout,
                trust_env=False,
            ) as client:
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
        """HTTP/1.x via ``http.client`` with an explicit request-line protocol version."""
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

        conn_http, conn_https = _cached_http_connection_pair(major, minor)
        conn_cls = conn_https if scheme == "https" else conn_http
        conn_kw: dict = {"host": host, "port": port, "timeout": timeout}
        if scheme == "https" and ssl_ctx is not None:
            conn_kw["context"] = ssl_ctx

        try:
            conn = conn_cls(**conn_kw)
            if no_host:
                strip = _headers_without_keys(hdrs, frozenset({"host"}))
                conn.putrequest(method.upper(), path, skip_host=True)
                for k, v in strip.items():
                    conn.putheader(k, v)
                conn.endheaders()
                resp = conn.getresponse()
            else:
                conn.request(method.upper(), path, body=None, headers=hdrs)
                resp = conn.getresponse()
            data = resp.read()
            conn.close()
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
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

    def _send_http09(
        self,
        url: str,
        headers: dict,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        """HTTP/0.9: ``GET path`` only; response may be raw HTML or upgraded HTTP/1.x."""
        import re
        import socket as socket_mod

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

        try:
            sock = socket_mod.create_connection((host, port), timeout=self.args.timeout)
        except OSError as exc:
            dummy.status_code = 0
            dummy._content = str(exc).encode()
            return dummy

        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(f"GET {path}\r\n".encode("ascii", errors="strict"))
            sock.settimeout(self.args.timeout)
            chunks: list[bytes] = []
            while True:
                try:
                    block = sock.recv(65536)
                except socket_mod.timeout:
                    break
                if not block:
                    break
                chunks.append(block)
        finally:
            sock.close()

        raw = b"".join(chunks)
        m = re.match(rb"HTTP/\d\.\d (\d{3})", raw)
        if m:
            st = int(m.group(1))
            body = raw
            header_end = raw.find(b"\r\n\r\n")
            if header_end != -1:
                body = raw[header_end + 4 :]
            r = requests.Response()
            r.status_code = st
            r._content = body
            r.headers = CaseInsensitiveDict()
            r.url = url
            return r

        r = requests.Response()
        r.status_code = 200
        r._content = raw
        r.headers = CaseInsensitiveDict({"X-Assumed-Protocol": "HTTP/0.9"})
        r.url = url
        return r

    def _send_by_protocol_version(
        self,
        url: str,
        method: str,
        headers: dict,
        token: str,
        auth: tuple[str, str] | None,
    ) -> requests.Response:
        if token == "2":
            return self._send_http2_httpx(url, method, headers, auth)
        if token == "1.1":
            return self._send_via_http_client(url, method, headers, auth, major=1, minor=1, no_host=False)
        if token == "1.0":
            return self._send_via_http_client(url, method, headers, auth, major=1, minor=0, no_host=False)
        if token == "1.0-no-host":
            return self._send_via_http_client(url, method, headers, auth, major=1, minor=0, no_host=True)
        if token == "0.9":
            if method.upper() != "GET":
                d = requests.Response()
                d.status_code = 0
                d.url = url
                d._content = b"HTTP/0.9: only GET"
                return d
            return self._send_http09(url, headers, auth)
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
            "pt403bypass -u https://host/api -s 200",
            "pt403bypass -u https://host/api -e 404 500",
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
            ["-e",  "--hide-status",           "<code...>",       "Do not print lines with these HTTP status codes"],
            ["-x",  "--methods",               "<method...>",     "HTTP methods (default: templates/methods.txt); merged with methods.txt"],
            ["-m",  "--max-tests",             "<n>",             "Limit payload count (default 0 = unlimited)"],
            ["-C",  "--cache",                 "",                "Cache compatibility flag"],
            ["-vv", "--verbose",               "",                "Enable verbose mode (show all result lines)"],
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
        default=None,
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

    if args.hide_statuses is not None:
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
