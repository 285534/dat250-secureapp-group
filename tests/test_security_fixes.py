import subprocess
import requests

BASE = "http://localhost:18181"
XSS_PAYLOAD = "<script>alert('XSS')</script>"
ALICE_ID = 4
BOB_ID = 5


def login(email, password):
    s = requests.Session()
    s.post(f"{BASE}/login", data={"email": email, "password": password})
    return s


def alice():
    return login("alice@student.uis.no", "Alice123")


def bob():
    return login("bob@student.uis.no", "Bob123")


def phppgadmin_ip():
    """Look up the internal Docker IP of phpPgAdmin (None if not found)."""
    try:
        cid = subprocess.check_output(
            ["docker", "compose", "ps", "-q", "phppgadmin"], text=True
        ).strip()
        ip = subprocess.check_output(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid],
            text=True,
        ).split()
        return ip[0] if ip else None
    except Exception:
        return None


# ---------- V3: Stored XSS ----------

def test_xss_payload_is_escaped_in_inbox():
    alice().post(f"{BASE}/messages", data={"recipient_id": BOB_ID, "content": XSS_PAYLOAD})
    html = bob().get(f"{BASE}/messages").text
    assert XSS_PAYLOAD not in html
    assert "&lt;script&gt;" in html


def test_normal_message_still_works():
    alice().post(f"{BASE}/messages", data={"recipient_id": BOB_ID, "content": "Hei Bob"})
    html = bob().get(f"{BASE}/messages").text
    assert "Hei Bob" in html


# ---------- Session cookie hardening ----------

def test_session_cookie_flags():
    r = requests.post(
        f"{BASE}/login",
        data={"email": "alice@student.uis.no", "password": "Alice123"},
        allow_redirects=False,
    )
    cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie
    assert "samesite=lax" in cookie.lower()


# ---------- V4: SSRF ----------

BLOCKED_URLS = [
    "http://127.0.0.1/",
    "http://localhost:9000",
    "http://169.254.169.254/",
    "file:///etc/passwd",
]


def test_ssrf_internal_urls_blocked():
    s = alice()
    urls = list(BLOCKED_URLS)
    ip = phppgadmin_ip()
    if ip:
        urls.append(f"http://{ip}/")
    for url in urls:
        html = s.get(f"{BASE}/resources/import", params={"url": url}).text
        assert "phpPgAdmin" not in html, url
        assert "This URL is not allowed" in html, url


def test_ssrf_public_url_still_works():
    html = alice().get(
        f"{BASE}/resources/import", params={"url": "https://example.com"}
    ).text
    assert "Example Domain" in html
