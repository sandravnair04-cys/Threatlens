import pytest

import scoring
import validators
import vt_client


# ------------------------------------------------------------ validators
def test_url_gets_https_added():
    assert validators.normalise_url("example.com/a") == "https://example.com/a"

@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "http://", "exa mple.com", "a" * 2100])
def test_bad_urls_rejected(bad):
    with pytest.raises(ValueError):
        validators.normalise_url(bad)

def test_domain_validation():
    assert validators.normalise_domain("Example.COM.") == "example.com"
    assert validators.normalise_domain("https://sub.example.com/path") == "sub.example.com"
    for bad in ["nodot", "-bad.com", "8.8.8.8", "exa mple.com", ""]:
        with pytest.raises(ValueError):
            validators.normalise_domain(bad)

def test_ip_validation():
    assert validators.normalise_ip("8.8.8.8") == "8.8.8.8"
    for bad in ["999.1.1.1", "192.168.1.1", "127.0.0.1", "abc"]:
        with pytest.raises(ValueError):
            validators.normalise_ip(bad)

def test_hash_validation():
    assert validators.normalise_hash("A" * 64) == "a" * 64
    for bad in ["abc", "g" * 64, "a" * 63]:
        with pytest.raises(ValueError):
            validators.normalise_hash(bad)


# ------------------------------------------------------------ scoring
def test_clean_url_scores_zero():
    pts, findings = scoring.analyse_url("https://example.com")
    assert pts == 0 and findings == []

def test_ip_login_url_is_flagged():
    pts, findings = scoring.analyse_url("http://192.0.2.10/login")
    assert pts == 10 + 20 + 15          # no https + ip host + keyword
    assert scoring.risk_level(pts) == "Medium"

def test_punycode_and_at_symbol():
    pts, _ = scoring.analyse_url("https://user@xn--pple-43d.com/")
    assert pts == 15 + 20

@pytest.mark.parametrize("score,level", [(0, "Low"), (24, "Low"), (25, "Medium"),
                                          (49, "Medium"), (50, "High"), (74, "High"),
                                          (75, "Critical"), (100, "Critical")])
def test_levels(score, level):
    assert scoring.risk_level(score) == level

def test_vt_points_and_cap():
    a = scoring.build_assessment([], {"malicious": 20, "suspicious": 10, "harmless": 5}, -50)
    assert a["score"] == 100 and a["level"] == "Critical"

def test_unknown_when_no_data():
    assert scoring.build_assessment([], {}, None)["level"] == "Unknown"


# ------------------------------------------------------------ vt client
def test_url_id_has_no_padding():
    uid = vt_client.url_id("https://example.com/")
    assert "=" not in uid and uid == "aHR0cHM6Ly9leGFtcGxlLmNvbS8"

def test_missing_key(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "")
    with pytest.raises(vt_client.VTError):
        vt_client.vt_request("GET", "/domains/example.com")
