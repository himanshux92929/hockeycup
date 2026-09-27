import os
import re
import json
import base64
import asyncio
import hashlib
import base64 as _b64
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from cryptography.fernet import Fernet
from curl_cffi import requests as cffi_requests   # ← exact import from your snippet
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
import uvicorn

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("PROXY_SECRET", "SUPERM3U8")
APP_URL    = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000").rstrip("/")

_raw   = hashlib.sha256(SECRET_KEY.encode()).digest()
FERNET = Fernet(_b64.urlsafe_b64encode(_raw))

# ── Allowed hosts ─────────────────────────────────────────────────────────────
# JSON array env var.  ["*"] = allow all.  ["mysite.com","other.io"] = restrict.
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

# ── curl_cffi fetch ───────────────────────────────────────────────────────────
# Using the exact same pattern as your reference snippet:
#   from curl_cffi import requests as cffi_requests
#   cffi_requests.get(url, params=..., headers=..., impersonate="edge101")
#
# Headers mirror your working curl command (Edge 153 / Chromium 153).
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

def _fetch(url: str) -> cffi_requests.Response:
    """
    Split the URL into base + params dict so curl_cffi handles
    query-string encoding exactly like your reference snippet does.
    Impersonate Edge 101 (same JA3/JA4 fingerprint as Edge 153 UA).
    """
    # Parse out any existing query string into a params dict
    # so curl_cffi re-encodes them correctly (preserves special chars)
    from urllib.parse import urlsplit, urlunsplit
    parts  = urlsplit(url)
    params = parse_qs(parts.query, keep_blank_values=True)
    # parse_qs returns lists; flatten to single values
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    clean_url   = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    return cffi_requests.get(
        clean_url,
        params=flat_params if flat_params else None,
        headers=_HEADERS,
        impersonate="edge101",   # ← TLS fingerprint: Edge 101
        timeout=20,
        allow_redirects=True,
    )

# ── M3U8 rewriting ────────────────────────────────────────────────────────────
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
                lambda m: m.group(1)
                    + _proxy(_resolve(m.group(2), base_url))
                    + m.group(3),
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

def _is_m3u8(ct: str, head: bytes) -> bool:
    if ct and ("mpegurl" in ct or "m3u" in ct):
        return True
    return head.lstrip()[:7] == b"#EXTM3U"

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Always send CORS — even on 403 — so clients see no difference
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

    # ── 2. Decrypt token → real URL ───────────────────────────────────────────
    try:
        target_url = decrypt_token(token)
    except Exception:
        return HTMLResponse(_BLOCKED_HTML, status_code=403, headers=_CORS)

    # Append any extra query params the player appended to our proxy URL
    qs = str(request.query_params)
    if qs:
        sep = "&" if "?" in target_url else "?"
        target_url += sep + qs

    # ── 3. Fetch via curl_cffi (runs in thread — keeps event loop free) ───────
    loop = asyncio.get_event_loop()
    try:
        resp = await loop.run_in_executor(None, _fetch, target_url)
    except Exception as e:
        return Response(f"upstream error: {e}", status_code=502, headers=_CORS)

    ct   = resp.headers.get("content-type", "")
    body = resp.content

    # ── 4. M3U8 → rewrite; everything else → pass-through ────────────────────
    if _is_m3u8(ct, body[:16]):
        rewritten = _rewrite_m3u8(body.decode("utf-8", errors="replace"), target_url)
        return Response(
            content=rewritten.encode(),
            media_type="application/vnd.apple.mpegurl",
            headers={**_CORS, "Cache-Control": "no-cache, no-store"},
        )

    out_headers = {
        **_CORS,
        "Content-Type": ct or "application/octet-stream",
        "Cache-Control": resp.headers.get("Cache-Control", "public, max-age=3600"),
    }
    for h in ("Content-Length", "Content-Range"):
        if h in resp.headers:
            out_headers[h] = resp.headers[h]

    return Response(content=body, status_code=resp.status_code, headers=out_headers)

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, workers=4)
