"""Tests vt_client against fake HTTP responses shaped like the real VirusTotal v3 API."""
import pytest
import requests

import vt_client


class FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body or {}
        self.ok = status < 400
    def json(self):
        return self._body


def fake_network(monkeypatch, routes):
    """routes: {(method, path): [response, response, ...]}.
    Each call to a route returns the next queued response (the last one repeats)."""
    calls = []
    def fake_request(method, url, **kwargs):
        path = url.replace(vt_client.VT_BASE, "")
        calls.append((method, path, kwargs))
        queue = routes.get((method, path))
        if queue is None:
            raise AssertionError(f"unexpected call {method} {path}")
        return queue.pop(0) if len(queue) > 1 else queue[0]
    monkeypatch.setattr(requests, "request", fake_request)
    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setenv("VT_POLL_DELAY", "0")
    return calls


DOMAIN_JSON = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 60, "undetected": 20, "timeout": 0},
    "last_analysis_results": {
        "Zeta": {"category": "malicious", "result": "phishing"},
        "Alpha": {"category": "malicious", "result": "malware"},
        "Clean": {"category": "harmless", "result": "clean"}},
    "reputation": -4, "registrar": "Example Registrar", "creation_date": 1262304000,
    "categories": {"Forcepoint": "phishing", "Sophos": "phishing"}}}}


def test_domain_parsing(monkeypatch):
    calls = fake_network(monkeypatch, {("GET", "/domains/evil.com"): [FakeResp(200, DOMAIN_JSON)]})
    r = vt_client.lookup_domain("evil.com")
    assert r["stats"]["malicious"] == 2 and r["reputation"] == -4
    assert [f["engine"] for f in r["flagged"]] == ["Alpha", "Zeta"]      # sorted, clean engine excluded
    assert r["details"]["Created"] == "2010-01-01" and r["details"]["Categories"] == "phishing"
    assert calls[0][2]["headers"]["x-apikey"] == "k"


def test_error_mapping(monkeypatch):
    for status, text in [(404, "no report"), (429, "rate limit"), (401, "rejected"), (500, "error")]:
        fake_network(monkeypatch, {("GET", "/ip_addresses/8.8.8.8"): [FakeResp(status)]})
        with pytest.raises(vt_client.VTError) as exc:
            vt_client.lookup_ip("8.8.8.8")
        assert text in str(exc.value).lower()


def test_network_failure(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "k")
    def boom(*a, **k): raise requests.ConnectionError()
    monkeypatch.setattr(requests, "request", boom)
    with pytest.raises(vt_client.VTError):
        vt_client.lookup_domain("example.com")


URL_ATTRS = {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 75, "undetected": 15, "timeout": 0},
             "last_analysis_results": {}, "title": "Example", "times_submitted": 3}


def test_url_existing_report(monkeypatch):
    uid = vt_client.url_id("https://example.com/")
    calls = fake_network(monkeypatch, {("GET", f"/urls/{uid}"): [FakeResp(200, {"data": {"attributes": URL_ATTRS}})]})
    r = vt_client.lookup_url("https://example.com/")
    assert r["status"] == "completed" and r["details"]["Title"] == "Example"
    assert len(calls) == 1                                  # no submission needed


def test_url_submit_and_poll(monkeypatch):
    url = "https://new-site.example/"
    uid = vt_client.url_id(url)
    calls = fake_network(monkeypatch, {
        # first lookup -> 404 (never seen); after the analysis completes -> report exists
        ("GET", f"/urls/{uid}"): [FakeResp(404), FakeResp(200, {"data": {"attributes": URL_ATTRS}})],
        ("POST", "/urls"): [FakeResp(200, {"data": {"id": "u-abc-123"}})],
        ("GET", "/analyses/u-abc-123"): [FakeResp(200, {"data": {"attributes": {"status": "completed"}}})],
    })
    r = vt_client.lookup_url(url)
    assert r["status"] == "completed" and r["stats"]["harmless"] == 75
    assert [c[:2] for c in calls] == [("GET", f"/urls/{uid}"), ("POST", "/urls"),
                                       ("GET", "/analyses/u-abc-123"), ("GET", f"/urls/{uid}")]
    assert calls[1][2]["data"] == {"url": url}


def test_url_still_pending(monkeypatch):
    url = "https://slow.example/"
    uid = vt_client.url_id(url)
    fake_network(monkeypatch, {
        ("GET", f"/urls/{uid}"): [FakeResp(404)],
        ("POST", "/urls"): [FakeResp(200, {"data": {"id": "u-1"}})],
        ("GET", "/analyses/u-1"): [FakeResp(200, {"data": {"attributes": {"status": "queued"}}})],
    })
    r = vt_client.lookup_url(url)
    assert r["status"] == "pending" and "again" in r["message"]


def test_upload_size_limit():
    with pytest.raises(vt_client.VTError):
        vt_client.upload_file("big.bin", b"0" * (vt_client.MAX_UPLOAD_BYTES + 1))
