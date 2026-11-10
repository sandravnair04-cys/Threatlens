"""Risk scoring.

Part 1: local URL heuristics (your original detection engine, now 0-100 points)
Part 2: VirusTotal evidence (engine detections + community reputation)
The final score is capped at 100 and mapped to a risk level.
"""
import ipaddress
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "password", "banking",
    "signin", "update", "secure", "confirm", "wallet",
]

# (label, points) - points are the same values used in the guide table
POINTS = {
    "no_https": 10,
    "ip_host": 20,
    "keywords": 15,
    "at_symbol": 15,
    "long_url": 10,
    "many_subdomains": 10,
    "punycode": 20,
}

LEVELS = [(75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]


def risk_level(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "Low"


def analyse_url(url):
    """Local heuristic analysis. Returns (points, findings).
    `findings` is a list of {"label": str, "points": int}."""
    findings = []

    def add(key, label):
        findings.append({"label": label, "points": POINTS[key]})

    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower()

    if parts.scheme != "https":
        add("no_https", "HTTPS is not used (connection is not encrypted)")

    try:
        ipaddress.ip_address(hostname)
        add("ip_host", "An IP address is used instead of a domain name")
    except ValueError:
        pass

    haystack = (hostname + parts.path + parts.query).lower()
    matched = [k for k in SUSPICIOUS_KEYWORDS if k in haystack]
    if matched:
        add("keywords", "Suspicious keywords found: " + ", ".join(matched))

    if "@" in parts.netloc:
        add("at_symbol", "Contains '@' - everything before it is ignored by the browser")

    if len(url) > 75:
        add("long_url", f"URL is unusually long ({len(url)} characters)")

    if hostname.count(".") >= 4:
        add("many_subdomains", "Unusually many subdomains")

    if "xn--" in hostname:
        add("punycode", "Punycode hostname (may imitate another domain with look-alike characters)")

    return sum(f["points"] for f in findings), findings


def vt_points(stats, reputation=None):
    """Convert VirusTotal evidence to points. Returns (points, breakdown)."""
    breakdown = []
    if not stats:
        return 0, breakdown
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious:
        pts = min(70, malicious * 12)
        breakdown.append({"label": f"{malicious} security engine(s) flagged it as malicious", "points": pts})
    if suspicious:
        pts = min(15, suspicious * 5)
        breakdown.append({"label": f"{suspicious} security engine(s) flagged it as suspicious", "points": pts})
    if reputation is not None and reputation < 0:
        pts = min(15, -reputation)
        breakdown.append({"label": f"Negative community reputation ({reputation})", "points": pts})
    return sum(b["points"] for b in breakdown), breakdown


def build_assessment(local_findings=None, vt_stats=None, reputation=None):
    """Combine everything into one assessment dictionary."""
    local_findings = local_findings or []
    vt_pts, vt_breakdown = vt_points(vt_stats, reputation)
    breakdown = list(local_findings) + vt_breakdown
    score = min(100, sum(b["points"] for b in breakdown))

    has_vt_data = bool(vt_stats) and sum(int(v) for v in vt_stats.values()) > 0
    if not local_findings and not has_vt_data:
        level = "Unknown"      # nothing to judge from
    else:
        level = risk_level(score)
    return {"score": score, "level": level, "breakdown": breakdown}
