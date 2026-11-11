import ipaddress
import socket
import traceback
from urllib.parse import urljoin, urlparse

import requests
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.auth import get_user_from_session
from app.config import APP_ENV

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

MAX_REDIRECTS = 3


def is_safe_url(url: str) -> bool:
    """Allow only http/https URLs that resolve to public IP addresses."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.hostname:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except (ValueError, socket.gaierror):
        return False

    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def safe_fetch(url: str):
    """Fetch a URL, validating the initial URL and every redirect target."""
    for _ in range(MAX_REDIRECTS + 1):
        if not is_safe_url(url):
            raise ValueError("URL not allowed")
        r = requests.get(url, timeout=5, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location")
            if not location:
                return r
            url = urljoin(url, location)
            continue
        return r
    raise ValueError("Too many redirects")


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/status", response_class=HTMLResponse)
def status(request: Request):
    user = get_user_from_session(request)
    return templates.TemplateResponse(
        "status.html",
        {"request": request, "user": user, "env": APP_ENV, "python": "3.11", "service": "backend"},
    )


@router.get("/resources/import", response_class=HTMLResponse)
def import_resource_get(request: Request, url: str = ""):
    user = get_user_from_session(request)
    body = ""
    error = ""
    if url:
        try:
            r = safe_fetch(url)
            ctype = r.headers.get("Content-Type", "")
            if not ctype.startswith(("text/", "application/json")):
                raise ValueError("Unsupported content type")
            body = r.text[:2000]
        except ValueError:
            error = "This URL is not allowed. Only public http/https addresses can be imported."
        except Exception:
            error = "Could not fetch the URL."
    return templates.TemplateResponse(
        "resource_import.html",
        {"request": request, "user": user, "body": body, "url": url, "error": error},
    )


@router.post("/resources/import", response_class=HTMLResponse)
def import_resource_post(request: Request, url: str = Form(...)):
    return import_resource_get(request, url)


@router.get("/error", response_class=HTMLResponse)
def trigger_error(request: Request):
    try:
        x = 1 / 0
        return {"x": x}
    except Exception:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "details": traceback.format_exc()},
            status_code=500,
        )
