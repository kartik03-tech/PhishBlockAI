import re
import os
import tldextract
from urllib.parse import urlparse
SUSPICIOUS_WORDS = ["verify", "confirm", "webscr", "ebayisapi",
                     "signin", "update-account", "security-alert"]
_TRANCO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "raw", "tranco_top_1m.csv")
_POPULAR_DOMAINS = set()
try:
    with open(_TRANCO_PATH, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                _POPULAR_DOMAINS.add(parts[1].lower())
except FileNotFoundError:
    pass

def normalize_url(url: str) -> str:
    """Strip trailing slash so 'example.com' and 'example.com/' score identically."""
    url = str(url).strip()
    if url.endswith("/") and not url.endswith("://"):
        url = url[:-1]
    return url

def extract_features(url: str) -> dict:
    try:
        url = normalize_url(url)
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain_info = tldextract.extract(url)
        domain = domain_info.domain + "." + domain_info.suffix

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_underscores": url.count("_"),
            "num_digits": sum(c.isdigit() for c in url),
            "num_params": url.count("="),
            "num_at": url.count("@"),
            "has_https": int(parsed.scheme == "https"),
            "has_ip": int(bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain_info.domain))),
            "has_suspicious_word": int(any(w in url.lower() for w in SUSPICIOUS_WORDS)),
            "subdomain_count": domain_info.subdomain.count(".") + (1 if domain_info.subdomain else 0),
            "path_length": len(parsed.path),
            "is_shortened": int(any(s in domain for s in ["bit.ly", "tinyurl", "t.co", "goo.gl"])),
            "is_known_popular_domain": int(domain in _POPULAR_DOMAINS),
        }
    except Exception:
        return {
            "url_length": len(str(url)), "domain_length": 0, "num_dots": 0, "num_hyphens": 0,
            "num_underscores": 0, "num_digits": 0, "num_params": 0, "num_at": 0, "has_https": 0,
            "has_ip": 0, "has_suspicious_word": 0, "subdomain_count": 0, "path_length": 0,
            "is_shortened": 0, "is_known_popular_domain": 0,
        }