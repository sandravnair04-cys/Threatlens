"""Input validation. Every value that comes from a user is checked here
BEFORE it is used, stored or sent to VirusTotal."""
import ipaddress
import re
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048

# Letters, digits and hyphens, 1-63 chars per label, labels separated by dots
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z0-9-]{{2,63}}$")
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")


def normalise_url(raw):
    """Return a clean http(s) URL or raise ValueError with a friendly message."""
    url = (raw or "").strip()
    if not url:
        raise ValueError("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise ValueError("URL must not contain spaces or control characters.")
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ValueError("That does not look like a valid URL.")
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise ValueError("Only http:// and https:// URLs are supported.")
    return url


def normalise_domain(raw):
    value = (raw or "").strip().lower().rstrip(".")
    if not value:
        raise ValueError("Please enter a domain.")
    # Accept pasted URLs by extracting the hostname
    if "://" in value:
        value = urlsplit(value).hostname or ""
    try:  # convert unicode domains to punycode
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("That does not look like a valid domain.")
    try:
        ipaddress.ip_address(value)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("That is an IP address. Use the IP scanner instead.")
    if len(value) > 253 or not _DOMAIN_RE.match(value):
        raise ValueError("That does not look like a valid domain (example: example.com).")
    return value


def normalise_ip(raw):
    value = (raw or "").strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("That does not look like a valid IPv4 or IPv6 address.")
    if not ip.is_global:
        raise ValueError("Private, loopback and reserved addresses cannot be looked up "
                         "because they are not public on the internet.")
    return str(ip)


def normalise_hash(raw):
    value = (raw or "").strip().lower()
    if not _HASH_RE.match(value):
        raise ValueError("Enter a valid MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal hash.")
    return value
