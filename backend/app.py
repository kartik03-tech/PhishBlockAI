import sys, os, re
from dotenv import load_dotenv
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, "..", "model"))
sys.path.append(BASE_DIR)

import cv2
import numpy as np
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from predictor import predict_url
from database import init_db, save_scan, get_history

app = FastAPI(title="PhishBlockAI API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()

class URLRequest(BaseModel):
    url: str

class MessageRequest(BaseModel):
    text: str

URGENCY_PHRASES = [
    "act now", "verify immediately", "account suspended", "click here",
    "urgent action required", "your account will be closed", "confirm your identity",
    "limited time", "verify your account", "unusual activity detected",
    "claim your prize", "you have won", "update your payment",
]

@app.get("/")
def root():
    return {"status": "PhishBlockAI API is running"}

@app.post("/predict")
def predict(req: URLRequest):
    result = predict_url(req.url)
    save_scan(result)
    return result

@app.get("/history")
def history(limit: int = 100):
    return get_history(limit)

@app.get("/stats")
def stats():
    rows = get_history(10000)
    total = len(rows)
    threats = sum(1 for r in rows if r["prediction"] != "safe")
    return {
        "total_scanned": total, "threats_detected": threats, "safe": total - threats,
        "avg_risk_score": round(sum(r["risk_score"] for r in rows) / total, 1) if total else 0,
    }

@app.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    contents = await file.read()
    npimg = np.frombuffer(contents, np.uint8)
    img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

    if img is None:
        return {"error": "Could not read the uploaded image"}

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)

    if not data:
        # Retry with grayscale + threshold, helps with low-contrast or photographed QR codes
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
        thresh_bgr = cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR)
        data, points, _ = detector.detectAndDecode(thresh_bgr)

    if not data:
        return {"error": "No QR code detected in the image"}

    result = predict_url(data)
    save_scan(result)
    result["decoded_content"] = data
    return result

@app.post("/scan-message")
def scan_message(req: MessageRequest):
    text = req.text
    urls = re.findall(r'https?://[^\s<>"\']+', text)

    url_results = []
    for u in urls:
        r = predict_url(u)
        save_scan(r)
        url_results.append(r)

    found_phrases = [p for p in URGENCY_PHRASES if p in text.lower()]

    overall_risk = "safe"
    if any(r["prediction"] == "phishing" for r in url_results) or len(found_phrases) >= 2:
        overall_risk = "phishing"
    elif any(r["prediction"] == "suspicious" for r in url_results) or len(found_phrases) == 1:
        overall_risk = "suspicious"

    return {
        "urls_found": url_results,
        "urgency_phrases_detected": found_phrases,
        "overall_assessment": overall_risk,
        "url_count": len(urls),
    }
