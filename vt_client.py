"""All communication with the VirusTotal API v3 lives in this file.
The API key is read from the environment (.env) and never leaves the server."""
import base64
import os
import time
from datetime import datetime, timezone

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui"
MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # public API limit for the simple upload endpoint


class VTError(Exception):
    """Something went wrong talking to VirusTotal (message is safe to show users)."""
    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


class VTNotFound(VTError):
    """VirusTotal has no record of this item."""
    def __init__(self, message="VirusTotal has no report for this item."):
        super().__init__(message, status=404)


def _api_key():
    return os.getenv("VT_API_KEY", "").strip()


def vt_request(method, path, **kwargs):
    """Send one request to VirusTotal and return the decoded JSON."""
    key = _api_key()
    if not key or key.startswith("PASTE_"):
        raise VTError("VirusTotal API key is not configured. Add VT_API_KEY to your .env file.", 503)

    headers = kwargs.pop("headers", {})
    headers["x-apikey"] = key
    headers["accept"] = "application/json"
    try:
        resp = requests.request(method, f"{VT_BASE}{path}", headers=headers, timeout=25, **kwargs)
    except requests.RequestException:
        raise VTError("Could not reach VirusTotal. Check your internet connection.", 502)

    if resp.status_code == 404:
        raise VTNotFound()
    if resp.status_code == 429:
        raise VTError("VirusTotal rate limit reached (free keys: 4 requests/minute, 500/day). "
                      "Wait a minute and try again.", 429)
    if resp.status_code in (401, 403):
        raise VTError("VirusTotal rejected the API key. Check VT_API_KEY in .env.", 503)
    if not resp.ok:
        raise VTError(f"VirusTotal returned an error (HTTP {resp.status_code}).", 502)
    try:
        return resp.json()
    except ValueError:
        raise VTError("VirusTotal returned an unreadable response.", 502)


# ---------------------------------------------------------------- helpers
def _ts(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OSError, OverflowError):
        return None


def _clean_stats(stats):
    stats = stats or {}
    return {k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}


def _flagged(results, limit=25):
    """Engines that flagged the item (keeps the result small and relevant)."""
    out = []
    for engine, info in (results or {}).items():
        if info.get("category") in ("malicious", "suspicious"):
            out.append({"engine": engine, "category": info["category"], "result": info.get("result") or "-"})
    out.sort(key=lambda r: (r["category"] != "malicious", r["engine"].lower()))
    return out[:limit]


def _categories(attrs):
    return sorted(set((attrs.get("categories") or {}).values()))[:6]


def url_id(url):
    """VirusTotal identifies a URL as its URL-safe base64 form without '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _from_object(attrs, details, permalink):
    stats = _clean_stats(attrs.get("last_analysis_stats"))
    return {
        "found": True,
        "status": "completed",
        "stats": stats,
        "reputation": attrs.get("reputation"),
        "flagged": _flagged(attrs.get("last_analysis_results")),
        "details": {k: v for k, v in details.items() if v not in (None, "", [])},
        "permalink": permalink,
    }


# ---------------------------------------------------------------- lookups
def lookup_domain(domain):
    attrs = vt_request("GET", f"/domains/{domain}")["data"]["attributes"]
    details = {
        "Registrar": attrs.get("registrar"),
        "Created": _ts(attrs.get("creation_date")),
        "Categories": ", ".join(_categories(attrs)),
        "Last analysed": _ts(attrs.get("last_analysis_date")),
    }
    return _from_object(attrs, details, f"{GUI_BASE}/domain/{domain}")


def lookup_ip(ip):
    attrs = vt_request("GET", f"/ip_addresses/{ip}")["data"]["attributes"]
    details = {
        "Country": attrs.get("country"),
        "Owner": attrs.get("as_owner"),
        "ASN": attrs.get("asn"),
        "Network": attrs.get("network"),
        "Last analysed": _ts(attrs.get("last_analysis_date")),
    }
    return _from_object(attrs, details, f"{GUI_BASE}/ip-address/{ip}")


def lookup_file_hash(file_hash):
    attrs = vt_request("GET", f"/files/{file_hash}")["data"]["attributes"]
    details = {
        "Name": attrs.get("meaningful_name"),
        "Type": attrs.get("type_description"),
        "Size (bytes)": attrs.get("size"),
        "SHA-256": attrs.get("sha256"),
        "MD5": attrs.get("md5"),
        "Tags": ", ".join((attrs.get("tags") or [])[:8]),
        "Last analysed": _ts(attrs.get("last_analysis_date")),
    }
    return _from_object(attrs, details, f"{GUI_BASE}/file/{file_hash}")


def _url_details(attrs):
    return {
        "Title": attrs.get("title"),
        "Final URL": attrs.get("last_final_url"),
        "HTTP status": attrs.get("last_http_response_code"),
        "Categories": ", ".join(_categories(attrs)),
        "Times submitted": attrs.get("times_submitted"),
        "Last analysed": _ts(attrs.get("last_analysis_date")),
    }


def lookup_url(url):
    """1) look for an existing report  2) if none, submit the URL and poll briefly.
    Never visits the URL itself - VirusTotal does the scanning."""
    uid = url_id(url)
    permalink = f"{GUI_BASE}/url/{uid}"
    try:
        attrs = vt_request("GET", f"/urls/{uid}")["data"]["attributes"]
        if sum(_clean_stats(attrs.get("last_analysis_stats")).values()) > 0:
            return _from_object(attrs, _url_details(attrs), permalink)
    except VTNotFound:
        pass

    # No usable report yet: submit for analysis
    analysis_id = vt_request("POST", "/urls", data={"url": url})["data"]["id"]

    tries = int(os.getenv("VT_POLL_TRIES", "2"))
    delay = float(os.getenv("VT_POLL_DELAY", "6"))
    for _ in range(tries):
        time.sleep(delay)
        analysis = vt_request("GET", f"/analyses/{analysis_id}")["data"]["attributes"]
        if analysis.get("status") == "completed":
            try:
                attrs = vt_request("GET", f"/urls/{uid}")["data"]["attributes"]
                return _from_object(attrs, _url_details(attrs), permalink)
            except VTNotFound:
                return {
                    "found": True, "status": "completed",
                    "stats": _clean_stats(analysis.get("stats")), "reputation": None,
                    "flagged": _flagged(analysis.get("results")),
                    "details": {}, "permalink": permalink,
                }
    return {
        "found": True, "status": "pending", "stats": _clean_stats({}), "reputation": None,
        "flagged": [], "details": {}, "permalink": permalink,
        "message": "VirusTotal is still analysing this URL. Scan it again in about a minute.",
    }


def upload_file(filename, data):
    """Upload a file to VirusTotal. ONLY called after explicit user consent.
    The file becomes visible to the VirusTotal community."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise VTError("File is larger than 32 MB, which the free upload endpoint does not accept.", 413)
    resp = vt_request("POST", "/files", files={"file": (filename or "upload.bin", data)})
    return resp["data"]["id"]
