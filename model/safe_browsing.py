import os
import requests

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_safe_browsing(url: str):
    """Returns a dict if Google has already confirmed this URL malicious, else None."""
    if not API_KEY:
        return None
    payload = {
        "client": {"clientId": "phishblockai-project", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        }
    }
    try:
        res = requests.post(SAFE_BROWSING_URL, json=payload, timeout=3)
        data = res.json()
        if data.get("matches"):
            threat_type = data["matches"][0]["threatType"]
            return {"threat_type": threat_type}
    except Exception:
        pass
    return None
