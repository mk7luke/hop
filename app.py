"""Hop: follow a link's redirects, then strip known tracking tags."""

from __future__ import annotations

import gzip
import html
import http.client
import ipaddress
import os
import re
import socket
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit, urljoin

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
PUBLIC_HOST = os.environ.get("HOP_PUBLIC_HOST", "https://hop.hermz.xyz").rstrip("/")
BIND_HOST = os.environ.get("HOP_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("HOP_PORT", "8884"))

RATE_LIMIT = 30
RATE_WINDOW = 3600
MAX_HOPS = 6
HOP_TIMEOUT = 4.0
TOTAL_BUDGET = 16.0
MAX_URL = 2000
BODY_CAP = 32768
ALLOWED_PORTS = {80, 443}

UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
)

TRACKERS = {
    "fbclid",
    "gclid",
    "gbraid",
    "wbraid",
    "dclid",
    "msclkid",
    "twclid",
    "ttclid",
    "yclid",
    "igshid",
    "igsh",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "_hsenc",
    "_hsmi",
    "vero_id",
    "oly_anon_id",
    "oly_enc_id",
    "wickedid",
    "nr_email_referer",
    "ref_src",
    "ref_url",
    "si",
    "spm",
    "fb_action_ids",
    "fb_action_types",
    "fb_source",
    "_ga",
    "_gl",
    "_kx",
    "rb_clickid",
    "epik",
    "s_cid",
    "sc_cid",
    "trk",
    "li_fat_id",
    "irclickid",
    "zanpid",
    "mtm_source",
    "mtm_medium",
    "mtm_campaign",
    "mtm_keyword",
    "mtm_content",
    "pk_campaign",
    "pk_kwd",
    "pk_source",
    "pk_medium",
    "piwik_campaign",
    "ns_mchannel",
    "ns_source",
    "ns_campaign",
    "sc_campaign",
    "sc_channel",
    "sc_content",
    "sc_medium",
    "sc_outcome",
    "sc_geo",
    "sc_country",
    "affiliate",
    "aff_id",
}

_hits: dict[str, list[float]] = {}
_page_cache: dict[str, tuple[float, str]] = {}

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.internal",
}
BLOCKED_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".home.arpa",
    ".lan",
    ".localdomain",
)


class HopError(ValueError):
    pass


def _client_ip(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()[:64]
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    if request.client and request.client.host:
        return request.client.host
    return "local"


def _rate_ok(ip: str) -> bool:
    now = time.time()
    if len(_hits) > 4000:
        stale = [key for key, times in _hits.items() if not any(now - t < RATE_WINDOW for t in times)]
        for key in stale:
            _hits.pop(key, None)
        if len(_hits) > 4000:
            _hits.clear()
    window = [t for t in _hits.get(ip, []) if now - t < RATE_WINDOW]
    if len(window) >= RATE_LIMIT:
        _hits[ip] = window
        return False
    window.append(now)
    _hits[ip] = window
    return True


def _public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global)


def resolve_public(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        raise HopError("That host name is not usable.")
    if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
        raise HopError("Hop will not open local or private addresses.")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HopError("That host did not resolve.") from exc
    chosen = ""
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise HopError("That host did not resolve.") from exc
        if not _public_ip(ip):
            raise HopError("Hop will not open local or private addresses.")
        if not chosen:
            chosen = raw
    if not chosen:
        raise HopError("That host did not resolve.")
    return chosen


def normalize_input(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        raise HopError("Paste a link first.")
    if len(text) > MAX_URL:
        raise HopError("That link is too long.")
    if any(ch in text for ch in ("\n", "\r", "\t", " ")):
        raise HopError("Links cannot contain spaces.")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise HopError("Only http and https.")
    if parts.username or parts.password:
        raise HopError("Remove the username and password from the link first.")
    if not parts.hostname:
        raise HopError("That link has no host.")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise HopError("Hop only follows port 80 and 443.")
    return text


def _host_port(url: str) -> tuple[str, int, str]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HopError("Only http and https.")
    if parts.username or parts.password:
        raise HopError("A redirect included a username or password. Stopped.")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise HopError("A redirect left port 80 and 443. Stopped.")
    if len(url) > MAX_URL:
        raise HopError("A redirect was too long. Stopped.")
    return parts.hostname, port, parts.scheme


def _is_tracker(key: str) -> bool:
    low = key.lower()
    return low.startswith("utm_") or low in TRACKERS


def strip_trackers(url: str) -> tuple[str, list[str]]:
    parts = urlsplit(url)
    kept = []
    removed: list[str] = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if _is_tracker(key):
            if key not in removed:
                removed.append(key)
            continue
        kept.append((key, value))
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(kept), parts.fragment))
    return clean, removed


def _same_hop(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and (pa.path or "/") == (pb.path or "/")
        and pa.query == pb.query
    )


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def _title_from(body: bytes, ctype: str) -> str:
    if not body:
        return ""
    charset = "utf-8"
    match = re.search(r"charset=([A-Za-z0-9._-]+)", ctype, re.I)
    if match:
        charset = match.group(1)
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    found = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not found:
        return ""
    raw = re.sub(r"<[^>]+>", " ", found.group(1))
    raw = html.unescape(raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw[:140]


def _meta_refresh(body: bytes, ctype: str) -> str:
    if not body or "html" not in ctype.lower():
        return ""
    text = body.decode("utf-8", errors="replace")
    for tag in re.finditer(r"<meta\b[^>]{0,500}>", text[:8000], re.I):
        blob = tag.group(0)
        if not re.search(r"http-equiv\s*=\s*[\"']?refresh", blob, re.I):
            continue
        content = re.search(r"content\s*=\s*[\"']([^\"']+)[\"']", blob, re.I)
        if not content:
            continue
        url_match = re.search(r"url\s*=\s*(\S+)", content.group(1), re.I)
        if not url_match:
            continue
        return url_match.group(1).strip("\"'")
    return ""


def _fetch(url: str, timeout: float) -> dict[str, Any]:
    host, port, scheme = _host_port(url)
    ip = resolve_public(host)
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    started = time.perf_counter()
    conn: http.client.HTTPConnection
    if scheme == "https":
        conn = _PinnedHTTPS(host, ip, port, timeout)
    else:
        conn = _PinnedHTTP(host, ip, port, timeout)
    try:
        conn.request(
            "GET",
            path,
            headers={
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en",
                "Accept-Encoding": "gzip",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        status = resp.status
        location = resp.getheader("Location")
        ctype = resp.getheader("Content-Type") or ""
        encoding = (resp.getheader("Content-Encoding") or "").lower()
        body = b""
        if location is None and "html" in ctype.lower():
            body = resp.read(BODY_CAP)
        resp.close()
    finally:
        conn.close()
    elapsed = int((time.perf_counter() - started) * 1000)
    if body and "gzip" in encoding:
        try:
            body = gzip.decompress(body)
        except OSError:
            body = b""
    title = _title_from(body, ctype) if location is None else ""
    refresh = _meta_refresh(body, ctype) if location is None else ""
    return {
        "status": status,
        "location": location,
        "ms": elapsed,
        "title": title,
        "refresh": refresh,
        "final_host": host,
    }


def follow(raw: str) -> dict[str, Any]:
    current = normalize_input(raw)
    hops: list[dict[str, Any]] = []
    seen: list[str] = []
    note = ""
    deadline = time.perf_counter() + TOTAL_BUDGET
    previous_host = ""
    while len(hops) < MAX_HOPS:
        remaining = deadline - time.perf_counter()
        if remaining <= 0.4:
            note = "Stopped because the time budget ran out."
            break
        try:
            host, _port, _scheme = _host_port(current)
            resolve_public(host)
        except HopError as exc:
            if hops:
                note = str(exc)
                break
            raise
        if any(_same_hop(current, old) for old in seen):
            note = "Stopped because the chain looped."
            break
        seen.append(current)
        try:
            fetched = _fetch(current, min(HOP_TIMEOUT, remaining))
        except HopError as exc:
            if hops:
                note = str(exc)
                break
            raise
        except (TimeoutError, socket.timeout):
            if hops:
                note = "A later hop did not answer in time."
                break
            raise HopError("That hop did not answer in time.") from None
        except ssl.SSLError:
            if hops:
                note = "A later hop refused the certificate."
                break
            raise HopError("That hop refused the certificate.") from None
        except OSError:
            if hops:
                note = "A later hop refused the connection."
                break
            raise HopError("That hop refused the connection.") from None
        changed = bool(previous_host) and previous_host.lower() != host.lower()
        hop = {
            "n": len(hops) + 1,
            "url": current,
            "host": host,
            "status": fetched["status"],
            "ms": fetched["ms"],
            "host_changed": changed,
            "title": fetched["title"],
            "via": "location" if fetched["location"] else "stop",
        }
        hops.append(hop)
        previous_host = host
        location = fetched["location"]
        status = fetched["status"]
        if status in {301, 302, 303, 307, 308} and location:
            nxt = urljoin(current, location.strip())
            hops[-1]["next"] = nxt
            current = nxt
            continue
        if status in {301, 302, 303, 307, 308} and not location:
            note = "Redirect status with no next address. Stopped."
            break
        if fetched["refresh"]:
            note = "The last page has a meta refresh. Hop does not follow that."
            hops[-1]["refresh"] = urljoin(current, fetched["refresh"])
        break
    else:
        note = "Stopped after 6 hops."

    if not hops:
        raise HopError(note or "No hops.")
    final = hops[-1]["url"]
    clean, removed = strip_trackers(final)
    first_host = hops[0]["host"]
    last_host = hops[-1]["host"]
    landed = bool(hops) and hops[-1].get("via") == "stop"
    soft_note = note.startswith("The last page has a meta refresh")
    return {
        "ok": landed and (not note or soft_note),
        "input": hops[0]["url"],
        "clean": clean,
        "removed": removed,
        "hops": hops,
        "title": hops[-1].get("title") or "",
        "note": note,
        "host_changed": first_host.lower() != last_host.lower(),
        "first_host": first_host,
        "last_host": last_host,
        "refresh": hops[-1].get("refresh") or "",
    }


def _asset_version(*paths: Path) -> str:
    latest = 0.0
    for path in paths:
        try:
            latest = max(latest, path.stat().st_mtime)
        except OSError:
            pass
    return str(int(latest))


def _shell() -> str:
    html_path = STATIC / "index.html"
    css_path = STATIC / "style.css"
    js_path = STATIC / "home.js"
    stamp = max(
        html_path.stat().st_mtime,
        css_path.stat().st_mtime if css_path.exists() else 0.0,
        js_path.stat().st_mtime if js_path.exists() else 0.0,
    )
    cached = _page_cache.get("shell")
    if cached and cached[0] == stamp:
        return cached[1]
    page = html_path.read_text(encoding="utf-8")
    css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    page = re.sub(
        r"""[ \t]*<link[^>]+href=["']/static/style\.css[^"']*["'][^>]*>\s*""",
        "",
        page,
        flags=re.I,
    )
    page = re.sub(r"</head>", f'<style id="hop-css">\n{css}\n</style>\n</head>', page, count=1, flags=re.I)
    version = _asset_version(js_path, css_path)
    page = re.sub(
        r"""src=(["'])/static/home\.js(?:\?[^"']*)?\1""",
        rf"src=\1/static/home.js?v={version}\1",
        page,
    )
    _page_cache["shell"] = (stamp, page)
    return page


def _hops_html(data: dict[str, Any]) -> str:
    bits = []
    last = len(data["hops"])
    for hop in data["hops"]:
        classes = ["hop"]
        if hop.get("host_changed"):
            classes.append("changed")
        if hop["n"] == last:
            classes.append("final")
        meta = f'{hop["status"]} · {hop["ms"]} ms'
        if hop.get("host_changed"):
            meta += " · host changed"
        if hop.get("via") == "location":
            meta += " · redirect"
        bits.append(
            f'<div class="{" ".join(classes)}">'
            '<div class="rail"><span class="dot">'
            f'{hop["n"]}</span><span class="stem"></span></div>'
            '<div class="body">'
            f'<strong class="host">{html.escape(hop["host"])}</strong>'
            f'<span class="addr">{html.escape(hop["url"])}</span>'
            f'<em class="meta">{html.escape(meta)}</em>'
            "</div></div>"
        )
    return "".join(bits)


def _result_html(data: dict[str, Any]) -> str:
    removed = data.get("removed") or []
    if removed:
        tag_line = "Removed " + ", ".join(html.escape(name) for name in removed) + "."
    else:
        tag_line = "No known tracking tags on the final link."
    warn = ""
    if data.get("host_changed"):
        warn = (
            '<p class="status warn">Host changed from '
            f'{html.escape(data["first_host"])} to {html.escape(data["last_host"])}. '
            "Read the last address before you trust it.</p>"
        )
    note = ""
    if data.get("note"):
        note = f'<p class="status warn">{html.escape(data["note"])}</p>'
    title = ""
    if data.get("title"):
        title = f'<p class="title-line">Page title: {html.escape(data["title"])}</p>'
    refresh = ""
    if data.get("refresh"):
        refresh = (
            '<p class="hint">Meta refresh target, not opened: '
            f'{html.escape(data["refresh"])}</p>'
        )
    landed = data["last_host"]
    return (
        '<section class="result" id="result">'
        f'<p class="english">Landed on {html.escape(landed)}</p>'
        f"{warn}{note}{title}"
        f'<div class="chain">{_hops_html(data)}</div>'
        '<div class="clean">'
        "<span>Clean link</span>"
        f'<strong class="addr" id="clean">{html.escape(data["clean"])}</strong>'
        f'<p class="hint" id="removed">{tag_line}</p>'
        f"{refresh}"
        "</div>"
        '<div class="row-actions">'
        '<button type="button" class="btn" id="copy-clean">Copy clean link</button>'
        '<button type="button" class="btn" id="copy-page">Copy this page</button>'
        "</div>"
        "</section>"
    )


def render_page(url: str = "", status: str = "", status_class: str = "", result: str = "") -> str:
    page = _shell()
    page = page.replace("<!--URL-->", html.escape(url, quote=True))
    page = page.replace("<!--STATUS-->", html.escape(status))
    page = page.replace("<!--STATUS_CLASS-->", status_class)
    page = page.replace("<!--RESULT-->", result)
    return page


app = FastAPI(title="Hop", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.middleware("http")
async def _headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    resp: Response = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'"
    )
    if request.url.path in {"/", "/index.html"}:
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "hop"}


@app.get("/robots.txt")
def robots() -> Response:
    return Response((STATIC / "robots.txt").read_text(encoding="utf-8"), media_type="text/plain")


def _run(raw: str) -> dict[str, Any]:
    data = follow(raw)
    data["share"] = f"{PUBLIC_HOST}/?url={quote(data['input'], safe='')}"
    return data


@app.get("/api/follow")
def api_follow(request: Request, url: str = Query("")) -> JSONResponse:
    if not _rate_ok(_client_ip(request)):
        return JSONResponse({"ok": False, "error": "Too many checks from this IP. Try again later."}, status_code=429)
    try:
        return JSONResponse(_run(url))
    except HopError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.get("/", response_class=HTMLResponse)
def home(request: Request, url: str = "") -> HTMLResponse:
    if not url.strip():
        return HTMLResponse(render_page())
    if not _rate_ok(_client_ip(request)):
        page = render_page(url, "Too many checks from this IP. Try again later.", " bad")
        return HTMLResponse(page, status_code=429)
    try:
        data = _run(url)
    except HopError as exc:
        return HTMLResponse(render_page(url, str(exc), " bad"), status_code=400)
    status = ""
    status_class = ""
    if data.get("note"):
        status = data["note"]
        status_class = " warn"
    return HTMLResponse(render_page(data["input"], status, status_class, _result_html(data)))
