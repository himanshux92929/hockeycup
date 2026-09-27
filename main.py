import os
import re
import json
import base64
import asyncio
import hashlib
import base64 as _b64
from urllib.parse import urljoin, urlparse, urlunparse

from cryptography.fernet import Fernet
import curl_cffi.requests as curl_requests
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
import uvicorn

# ── Config ───────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("PROXY_SECRET", "SUPERM3U8")
APP_URL    = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000").rstrip("/")

# Fernet key derived from secret (stable, deterministic)
_raw   = hashlib.sha256(SECRET_KEY.encode()).digest()
FERNET = Fernet(_b64.urlsafe_b64encode(_raw))

# ── Allowed hosts ─────────────────────────────────────────────────────────────
# Edit this list to restrict access.
# Use ["*"] to allow everyone (default).
# Example: ["mysite.com", "192.168.1.10", "localhost"]
ALLOWED_HOSTS: list[str] = json.loads(
    os.environ.get("ALLOWED_HOSTS", '["*"]')
)
_ALLOW_ALL = "*" in ALLOWED_HOSTS
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

def _get_origin_host(request: Request) -> str:
    """Return the requesting host, preferring Origin header over Host."""
    origin = request.headers.get("origin", "")
    if origin:
        return urlparse(origin).hostname or ""
    host = request.headers.get("host", "")
    return host.split(":")[0].lower()

def _is_allowed(request: Request) -> bool:
    if _ALLOW_ALL:
        return True
    host = _get_origin_host(request)
    return host in _ALLOWED_SET

# ── Crypto helpers ────────────────────────────────────────────────────────────
def encrypt_url(url: str) -> str:
    token = FERNET.encrypt(url.encode()).decode()
    return base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")

def decrypt_token(token: str) -> str:
    pad = 4 - len(token) % 4
    if pad != 4:
        token += "=" * pad
    raw = base64.urlsafe_b64decode(token.encode()).decode()
    return FERNET.decrypt(raw.encode()).decode()

# ── curl_cffi (persistent session, Chrome 110 TLS fingerprint) ───────────────
SESSION = curl_requests.Session(impersonate="chrome110")

CURL_HEADERS = {
    "sec-ch-ua-platform": '"Windows"',
    "Referer": "https://vidcloud.eu.org/",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0"
    ),
    "sec-ch-ua": '"Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "Range": "bytes=0-",
}

def _fetch(url: str) -> curl_requests.Response:
    return SESSION.get(url, headers=CURL_HEADERS, timeout=20, allow_redirects=True)

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

def _is_m3u8(ct: str, head: bytes) -> bool:
    if ct and ("mpegurl" in ct or "m3u" in ct):
        return True
    return head.lstrip()[:7] == b"#EXTM3U"

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Always-present CORS headers (even on blocked responses — looks like a normal CDN)
_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "*",
}

@app.options("/{path:path}")
async def options_handler(request: Request):
    return Response(status_code=204, headers=_CORS)

@app.get("/health")
async def health():
    return Response(content='{"status":"ok"}', media_type="application/json", headers=_CORS)

@app.get("/{token:path}")
async def proxy(token: str, request: Request):
    # ── Host check (silent 403, looks like a generic block page) ──
    if not _is_allowed(request):
        return HTMLResponse(
            content=_BLOCKED_HTML,
            status_code=403,
            headers={**_CORS},   # still send CORS so origin doesn't see a CORS error
        )

    token = token.lstrip("/")
    if not token:
        return HTMLResponse(_BLOCKED_HTML, status_code=403, headers=_CORS)

    try:
        target_url = decrypt_token(token)
    except Exception:
        return HTMLResponse(_BLOCKED_HTML, status_code=403, headers=_CORS)

    # Append any extra query params the player added
    qs = str(request.query_params)
    if qs:
        sep = "&" if "?" in target_url else "?"
        target_url = target_url + sep + qs

    try:
        resp = await asyncio.get_event_loop().run_in_executor(None, _fetch, target_url)
    except Exception as e:
        return Response(f"upstream error: {e}", status_code=502, headers=_CORS)

    ct   = resp.headers.get("content-type", "")
    body = resp.content

    if _is_m3u8(ct, body[:16]):
        rewritten = _rewrite_m3u8(body.decode("utf-8", errors="replace"), target_url)
        return Response(
            content=rewritten.encode(),
            media_type="application/vnd.apple.mpegurl",
            headers={**_CORS, "Cache-Control": "no-cache, no-store"},
        )

    headers = {
        **_CORS,
        "Content-Type": ct or "application/octet-stream",
        "Cache-Control": resp.headers.get("Cache-Control", "public, max-age=3600"),
    }
    for h in ("Content-Length", "Content-Range"):
        if h in resp.headers:
            headers[h] = resp.headers[h]

    return Response(content=body, status_code=resp.status_code, headers=headers)

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, workers=4)
