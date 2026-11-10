import io

import vt_client

CLEAN = {"found": True, "status": "completed",
         "stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10, "timeout": 0},
         "reputation": 0, "flagged": [], "details": {"Registrar": "Test"}, "permalink": "https://vt/x"}
BAD = {"found": True, "status": "completed",
       "stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10, "timeout": 0},
       "reputation": -3,
       "flagged": [{"engine": "EngineA", "category": "malicious", "result": "phishing"}],
       "details": {}, "permalink": "https://vt/y"}


def test_url_scan_saves_history(client, monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_url", lambda u: BAD)
    r = client.post("/api/scan/url", json={"url": "http://login-secure.example.com/verify"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["assessment"]["level"] in ("High", "Critical")
    assert data["id"] == 1

    hist = client.get("/api/history").get_json()
    assert len(hist) == 1 and hist[0]["scan_type"] == "url"
    assert client.get("/history").status_code == 200
    page = client.get(f"/report/{data['id']}")
    assert page.status_code == 200 and b"EngineA" in page.data


def test_url_scan_survives_vt_failure(client, monkeypatch):
    def boom(u): raise vt_client.VTError("VirusTotal rate limit reached", 429)
    monkeypatch.setattr(vt_client, "lookup_url", boom)
    r = client.post("/api/scan/url", json={"url": "http://192.0.2.10/login"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["vt_error"] and d["assessment"]["score"] == 45


def test_domain_ip_hash(client, monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_domain", lambda d: CLEAN)
    monkeypatch.setattr(vt_client, "lookup_ip", lambda d: CLEAN)
    monkeypatch.setattr(vt_client, "lookup_file_hash", lambda d: CLEAN)
    assert client.post("/api/scan/domain", json={"domain": "example.com"}).status_code == 200
    assert client.post("/api/scan/ip", json={"ip": "8.8.8.8"}).status_code == 200
    r = client.post("/api/scan/hash", json={"hash": "a" * 64})
    assert r.get_json()["assessment"]["level"] == "Low"


def test_hash_not_found(client, monkeypatch):
    def nf(h): raise vt_client.VTNotFound()
    monkeypatch.setattr(vt_client, "lookup_file_hash", nf)
    d = client.post("/api/scan/hash", json={"hash": "b" * 64}).get_json()
    assert d["vt"]["found"] is False and d["assessment"]["level"] == "Unknown"


def test_validation_errors(client):
    assert client.post("/api/scan/url", json={"url": "ftp://x.com"}).status_code == 400
    assert client.post("/api/scan/ip", json={"ip": "10.0.0.1"}).status_code == 400
    assert client.post("/api/scan/hash", json={"hash": "zzz"}).status_code == 400
    assert client.post("/api/scan/domain", data="not json").status_code == 400


def test_file_scan_hashes_but_does_not_upload(client, monkeypatch):
    seen = {}
    def nf(h): seen["hash"] = h; raise vt_client.VTNotFound()
    monkeypatch.setattr(vt_client, "lookup_file_hash", nf)
    monkeypatch.setattr(vt_client, "upload_file", lambda n, d: (_ for _ in ()).throw(AssertionError("uploaded!")))
    r = client.post("/api/scan/file", data={"file": (io.BytesIO(b"hello"), "hello.txt")},
                    content_type="multipart/form-data")
    assert r.status_code == 200
    assert seen["hash"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_upload_requires_consent(client, monkeypatch):
    monkeypatch.setattr(vt_client, "upload_file", lambda n, d: "analysis-1")
    no = client.post("/api/scan/file/upload", data={"file": (io.BytesIO(b"x"), "a.bin"), "consent": "false"},
                     content_type="multipart/form-data")
    assert no.status_code == 400
    yes = client.post("/api/scan/file/upload", data={"file": (io.BytesIO(b"x"), "a.bin"), "consent": "true"},
                      content_type="multipart/form-data")
    assert yes.status_code == 200 and yes.get_json()["analysis_id"] == "analysis-1"


def test_rate_limit(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "2")
    monkeypatch.setattr(vt_client, "lookup_domain", lambda d: CLEAN)
    codes = [client.post("/api/scan/domain", json={"domain": "example.com"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_delete_and_404(client, monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_domain", lambda d: CLEAN)
    sid = client.post("/api/scan/domain", json={"domain": "example.com"}).get_json()["id"]
    assert client.post(f"/report/{sid}/delete").status_code == 302
    assert client.get(f"/report/{sid}").status_code == 404
    assert client.get("/api/report/999").status_code == 404


def test_sql_injection_is_inert(client, monkeypatch):
    # 1) Through the API: spaces are rejected by validation before reaching the database
    monkeypatch.setattr(vt_client, "lookup_url", lambda u: CLEAN)
    assert client.post("/api/scan/url",
                       json={"url": "https://example.com/'; DROP TABLE scans;--"}).status_code == 400
    # 2) A URL with no spaces is accepted and stored as plain text
    client.post("/api/scan/url", json={"url": "https://example.com/';DROP/**/TABLE/**/scans;--"})
    assert len(client.get("/api/history").get_json()) == 1
    # 3) Even raw text with spaces handed straight to the database layer stays inert
    import database
    database.save_scan("url", "x'; DROP TABLE scans;--", {"score": 0, "level": "Low"}, {}, "web", {})
    assert len(database.list_scans()) == 2
    # 4) The type filter only accepts known values
    assert client.get("/history?type=url'; DROP TABLE scans;--").status_code == 400


def test_xss_is_escaped_in_report(client, monkeypatch):
    evil = dict(BAD, flagged=[{"engine": "<script>alert(1)</script>", "category": "malicious", "result": "x"}])
    monkeypatch.setattr(vt_client, "lookup_url", lambda u: evil)
    sid = client.post("/api/scan/url", json={"url": "https://example.com"}).get_json()["id"]
    body = client.get(f"/report/{sid}").data
    assert b"<script>alert(1)</script>" not in body and b"&lt;script&gt;" in body


def test_security_headers_and_cors(client):
    r = client.get("/", headers={"Origin": "chrome-extension://abc"})
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    ok = client.get("/api/history", headers={"Origin": "chrome-extension://abcdef"})
    assert ok.headers.get("Access-Control-Allow-Origin") == "chrome-extension://abcdef"
    evil = client.get("/api/history", headers={"Origin": "https://evil.com"})
    assert "Access-Control-Allow-Origin" not in evil.headers


def test_pages_render(client):
    assert client.get("/").status_code == 200
    assert b"data-prefill-url=\"https://x.com\"" in client.get("/check?url=https://x.com").data
    assert client.get("/nope").status_code == 404
    assert client.get("/health").get_json()["virustotal_configured"] is True
