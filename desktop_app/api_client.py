"""Thin synchronous HTTP client for the ThreatLens backend API.

The desktop app calls these helpers from the UI thread (operations are fast
network calls, so blocking briefly is acceptable; a future improvement could
wrap them in a QThread if latency becomes noticeable).
"""
import httpx

BASE_URL = "http://localhost:8000/api/v1"
_TIMEOUT = 10.0


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login(email: str, password: str) -> str:
    """Returns JWT access token or raises on failure."""
    resp = httpx.post(
        f"{BASE_URL}/auth/login",
        data={"username": email, "password": password},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Scheduled scans
# ---------------------------------------------------------------------------

def list_scheduled_scans(token: str) -> list[dict]:
    resp = httpx.get(f"{BASE_URL}/scheduled-scans/", headers=_headers(token), timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def create_scheduled_scan(token: str, url: str, email_to: str, modules: list[str], interval_days: int = 7) -> dict:
    resp = httpx.post(
        f"{BASE_URL}/scheduled-scans/",
        json={"url": url, "email_to": email_to, "modules": modules, "interval_days": interval_days},
        headers=_headers(token),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def toggle_scheduled_scan(token: str, scan_id: str, is_active: bool) -> dict:
    resp = httpx.patch(
        f"{BASE_URL}/scheduled-scans/{scan_id}",
        json={"is_active": is_active},
        headers=_headers(token),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def delete_scheduled_scan(token: str, scan_id: str) -> None:
    resp = httpx.delete(
        f"{BASE_URL}/scheduled-scans/{scan_id}",
        headers=_headers(token),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
