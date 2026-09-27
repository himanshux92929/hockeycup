import os
import re
import base64
import asyncio
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs, quote
from cryptography.fernet import Fernet
import curl_cffi.requests as curl_requests
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import uvicorn

# ── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("PROXY_SECRET", "SUPERM3U8")
APP_URL    = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000").rstrip("/")

# Derive a valid 32-byte Fernet key from the secret
import hashlib, base64 as _b64
_raw = hashlib.sha256(SECRET_KEY.encode()).digest()
FERNET = Fernet(_b64.urlsafe_b64encode(_raw))

# ── Helpers ──────────────────────────────────────────────────────────────────
def encrypt_url(url: str) -> str:
    token = FERNET.encrypt(url.encode()).decode()
    # make it URL-path-safe
    return base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")

def decrypt_token(token: str) -> str:
    # restore padding
    pad = 4 - len(token) % 4
    if pad != 4:
        token += "=" * pad
    raw = base64.urlsafe_b64decode(token.encode()).decode()
    return FERNET.decrypt(raw.encode()).decode()

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

# ── curl_cffi session (reused, TLS fingerprint = chrome110) ─────────────────
SESSION = curl_requests.Session(impersonate="chrome110")

def fetch(url: str, extra_headers: dict = None) -> curl_requests.Response:
    h = {**CURL_HEADERS}
    if extra_headers:
        h.update(extra_headers)
    return SESSION.get(url, headers=h, timeout=20, allow_redirects=True)

# ── M3U8 rewriting ───────────────────────────────────────────────────────────
# Matches any URI= value or bare path/URL line in a playlist
_ABS_RE  = re.compile(r'(https?://[^\s"\']+)')
_URI_RE  = re.compile(r'(URI=")([^"]+)(")')

def _proxy(url: str) -> str:
    return f"{APP_URL}/{encrypt_url(url)}"

def rewrite_m3u8(content: str, base_url: str) -> str:
    lines = content.splitlines()
    out   = []
    for line in lines:
        stripped = line.strip()

        # EXT-X-KEY URI= and similar attribute URIs
        if "URI=" in line:
            line = _URI_RE.sub(lambda m: m.group(1) + _proxy(
                _resolve(m.group(2), base_url)) + m.group(3), line)
            out.append(line)
            continue

        # comment / tag lines that aren't segment references
        if stripped.startswith("#"):
            out.append(line)
            continue

        # blank
        if not stripped:
            out.append(line)
            continue

        # absolute URL segment / playlist
        if stripped.startswith("http://") or stripped.startswith("https://"):
            out.append(_proxy(stripped))
            continue

        # relative path
        resolved = _resolve(stripped, base_url)
        out.append(_proxy(resolved))

    return "\n".join(out)

def _resolve(path: str, base: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base, path)

def _base_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rsplit("/", 1)[0] + "/", "", "", ""))

def is_m3u8(content_type: str, body_start: bytes) -> bool:
    if content_type and ("mpegurl" in content_type or "m3u" in content_type):
        return True
    return body_start.lstrip()[:7] in (b"#EXTM3U", b"#EXTM3U")

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/{token:path}")
async def proxy(token: str, request: Request):
    # strip any leading slash artifacts
    token = token.lstrip("/")
    if not token:
        raise HTTPException(404)

    try:
        target_url = decrypt_token(token)
    except Exception:
        raise HTTPException(400, "Invalid token")

    # Forward any query params the client sent (edge case)
    qs = str(request.query_params)
    if qs and "?" not in target_url:
        target_url = target_url + "?" + qs
    elif qs:
        target_url = target_url + "&" + qs

    try:
        resp = await asyncio.get_event_loop().run_in_executor(None, fetch, target_url)
    except Exception as e:
        raise HTTPException(502, f"Upstream error: {e}")

    ct = resp.headers.get("content-type", "")
    body = resp.content

    # Rewrite if M3U8
    if is_m3u8(ct, body[:16]):
        text    = body.decode("utf-8", errors="replace")
        rewritten = rewrite_m3u8(text, target_url)
        return Response(
            content=rewritten.encode(),
            media_type="application/vnd.apple.mpegurl",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-cache",
            },
        )

    # Pass-through for segments / keys / anything else
    safe_headers = {
        "Content-Type": ct or "application/octet-stream",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": resp.headers.get("Cache-Control", "public, max-age=3600"),
    }
    if "Content-Length" in resp.headers:
        safe_headers["Content-Length"] = resp.headers["Content-Length"]
    if "Content-Range" in resp.headers:
        safe_headers["Content-Range"] = resp.headers["Content-Range"]

    return Response(
        content=body,
        status_code=resp.status_code,
        headers=safe_headers,
    )

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, workers=4, loop="uvloop")
