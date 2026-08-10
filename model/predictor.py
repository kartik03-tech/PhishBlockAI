import os
import joblib
import pandas as pd
from features import extract_features, normalize_url
from safe_browsing import check_safe_browsing

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(os.path.join(MODEL_DIR, "model.pkl"))
feature_names = joblib.load(os.path.join(MODEL_DIR, "feature_names.pkl"))
model.verbose = 0

def predict_url(url: str) -> dict:
    url = normalize_url(url)

    sb_result = check_safe_browsing(url)
    if sb_result:
        return {
            "url": url, "prediction": "phishing", "risk_score": 100,
            "confidence": 1.0, "source": "api",
            "reasons": [f"Confirmed by Google Safe Browsing ({sb_result['threat_type']})"],
        }

    feats = extract_features(url)
    row = pd.DataFrame([[feats[f] for f in feature_names]], columns=feature_names)
    prob = model.predict_proba(row)[0][1]
    risk_score = round(prob * 100)

    is_trusted_structure = (
        feats["is_known_popular_domain"] == 1
        and feats["has_https"] == 1
        and feats["has_ip"] == 0
        and feats["has_suspicious_word"] == 0
        and feats["is_shortened"] == 0
    )
    if is_trusted_structure:
        risk_score = min(risk_score, 35)

    if risk_score >= 80:
        label = "phishing"
    elif risk_score >= 50:
        label = "suspicious"
    else:
        label = "safe"

    reasons = []
    if feats["has_ip"]: reasons.append("Domain uses raw IP address")
    if not feats["has_https"]: reasons.append("No HTTPS encryption")
    if feats["has_suspicious_word"]: reasons.append("Contains suspicious keywords")
    if feats["is_shortened"]: reasons.append("Uses a URL shortener")
    if feats["num_hyphens"] > 3: reasons.append("Unusually many hyphens in domain")

    return {
        "url": url, "prediction": label, "risk_score": risk_score, "source": "model",
        "confidence": round(float(max(prob, 1 - prob)), 2), "reasons": reasons,
    }
