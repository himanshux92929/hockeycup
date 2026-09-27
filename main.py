import os
import re
import json
import base64
import asyncio
import hashlib
import base64 as _b64
from urllib.parse import urljoin, urlparse, urlunsplit, urlsplit, parse_qs

from cryptography.fernet import Fernet
from curl_cffi import requests as cffi_requests
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
import uvicorn

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("PROXY_SECRET", "SUPERM3U8")
APP_URL    = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000").rstrip("/")

_raw   = hashlib.sha256(SECRET_KEY.encode()).digest()
FERNET = Fernet(_b64.urlsafe_b64encode(_raw))

# ── Allowed hosts ─────────────────────────────────────────────────────────────
ALLOWED_HOSTS: list = json.loads(os.environ.get("ALLOWED_HOSTS", '["*"]'))
_ALLOW_ALL   = "*" in ALLOWED_HOSTS
_ALLOWED_SET = {h.lower() for h in ALLOWED_HOSTS}

_BLOCKED_HTML = (
    "<!DOCTYPE html><html><head><title>Access Denied</title>"
    "<style>body{margin:0;display:flex;align-items:center;justify-content:center;"
    "height:100vh;background:#f6f8fa;font-family:sans-serif}"
    ".box{text-align:center;padding:48px 64px;background:#fff;border-radius:8px;"
    "box-shadow:0 2px 12px rgba(0,0,0,.08)}"
    "h1{font-size:1.6rem;color:#24292f;margin:0 0 8px}"
    "p{color:#57606a;margin:0;font-size:.95rem}"
    "</style></head><body><div class='box'>"
    "<h1>Sorry!</h1><p>Your access has been blocked.</p>"
    "</div></body></html>"
)

def _origin_host(request: Request) -> str:
    origin = request.headers.get("origin", "")
    if origin:
        return urlparse(origin).hostname or ""
    return request.headers.get("host", "").split(":")[0].lower()

def _is_allowed(request: Request) -> bool:
    if _ALLOW_ALL:
        return True
    return _origin_host(request) in _ALLOWED_SET

# ── Crypto ────────────────────────────────────────────────────────────────────
def encrypt_url(url: str) -> str:
    token = FERNET.encrypt(url.encode()).decode()
    return base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")

def decrypt_token(token: str) -> str:
    pad = 4 - len(token) % 4
    if pad != 4:
        token += "=" * pad
    raw = base64.urlsafe_b64decode(token.encode()).decode()
    return FERNET.decrypt(raw.encode()).decode()

# ── curl_cffi ─────────────────────────────────────────────────────────────────
_HEADERS = {
    "Referer": "https://vidcloud.eu.org/",
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua": '"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
    "sec-ch-ua-mobile": "?0",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0"
    ),
    "Range": "bytes=0-",
}

CHUNK_SIZE = 64 * 1024  # 64 KB — tiny RAM footprint per chunk

def _split_url(url: str):
    """Return (clean_url, params_dict) splitting off query string."""
    parts      = urlsplit(url)
    raw_params = parse_qs(parts.query, keep_blank_values=True)
    flat       = {k: v[0] if len(v) == 1 else v for k, v in raw_params.items()}
    clean      = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return clean, flat or None

def _is_m3u8_ct(ct: str) -> bool:
    return "mpegurl" in ct or "m3u" in ct

def _is_m3u8_body(head: bytes) -> bool:
    return head.lstrip()[:7] == b"#EXTM3U"

# ── M3U8 rewriting (only used for tiny playlist text, never segments) ─────────
_URI_RE = re.compile(r'(URI=")([^"]+)(")')

def _proxy(url: str) -> str:
    return f"{APP_URL}/{encrypt_url(url)}"

def _resolve(path: str, base: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base, path)

def _rewrite_m3u8(content: str, base_url: str) -> str:
    out = []
    for line in content.splitlines():
        s = line.strip()
        if "URI=" in line:
            line = _URI_RE.sub(
                lambda m: m.group(1) + _proxy(_resolve(m.group(2), base_url)) + m.group(3),
                line,
            )
            out.append(line)
        elif s.startswith("#") or not s:
            out.append(line)
        elif s.startswith("http://") or s.startswith("https://"):
            out.append(_proxy(s))
        else:
            out.append(_proxy(_resolve(s, base_url)))
    return "\n".join(out)

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "*",
}

@app.options("/{path:path}")
async def options_preflight(request: Request):
    return Response(status_code=204, headers=_CORS)

@app.get("/health")
async def health():
    return Response('{"status":"ok"}', media_type="application/json", headers=_CORS)

@app.get("/{token:path}")
async def proxy(token: str, request: Request):
    # ── 1. Host gate ──────────────────────────────────────────────────────────
    if not _is_allowed(request):
        return HTMLResponse(_BLOCKED_HTML, status_code=403, headers=_CORS)

    token = token.lstrip("/")
    if not token:
        return HTMLResponse(_BLOCKED_HTML, status_code=403, headers=_CORS)

    # ── 2. Decrypt ────────────────────────────────────────────────────────────
    try:
        target_url = decrypt_token(token)
    except Exception:
        return HTMLResponse(_BLOCKED_HTML, status_code=403, headers=_CORS)

    qs = str(request.query_params)
    if qs:
        sep = "&" if "?" in target_url else "?"
        target_url += sep + qs

    clean_url, params = _split_url(target_url)

    # ── 3. Open a STREAMING request (stream=True → no body buffered in RAM) ───
    loop = asyncio.get_event_loop()

    def _open_stream():
        return cffi_requests.get(
            clean_url,
            params=params,
            headers=_HEADERS,
            impersonate="edge101",
            timeout=30,
            allow_redirects=True,
            stream=True,          # ← KEY: don't buffer body
        )

    try:
        resp = await loop.run_in_executor(None, _open_stream)
    except Exception as e:
        return Response(f"upstream error: {e}", status_code=502, headers=_CORS)

    ct = resp.headers.get("content-type", "")

    # ── 4a. M3U8 playlist → buffer only the tiny text, rewrite, return ────────
    #   Playlists are a few KB at most — safe to buffer.
    if _is_m3u8_ct(ct):
        def _read_all():
            return b"".join(resp.iter_content(CHUNK_SIZE))

        body = await loop.run_in_executor(None, _read_all)

        # double-check body magic in case CT was wrong
        if _is_m3u8_body(body[:16]) or _is_m3u8_ct(ct):
            rewritten = _rewrite_m3u8(body.decode("utf-8", errors="replace"), target_url)
            return Response(
                content=rewritten.encode(),
                media_type="application/vnd.apple.mpegurl",
                headers={**_CORS, "Cache-Control": "no-cache, no-store"},
            )

    # ── 4b. Everything else (segments, keys, images, pdfs…) → true streaming ──
    #   We never hold more than CHUNK_SIZE (64 KB) in RAM at once.
    def _iter_chunks():
        try:
            for chunk in resp.iter_content(CHUNK_SIZE):
                if chunk:
                    yield chunk
        finally:
            resp.close()

    out_headers = {
        **_CORS,
        "Content-Type": ct or "application/octet-stream",
        "Cache-Control": resp.headers.get("Cache-Control", "public, max-age=3600"),
    }
    for h in ("Content-Length", "Content-Range", "Accept-Ranges"):
        if h in resp.headers:
            out_headers[h] = resp.headers[h]

    return StreamingResponse(
        _iter_chunks(),
        status_code=resp.status_code,
        headers=out_headers,
    )

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, workers=1)
    # workers=1 on free tier — Render free = 512MB total.
    # 1 worker × streaming = handles many concurrent requests fine via async.
    # Multiple workers would multiply RAM usage for no benefit on free tier.
