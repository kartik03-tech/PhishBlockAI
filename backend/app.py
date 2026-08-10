from dotenv import load_dotenv
load_dotenv()
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "model"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from predictor import predict_url
from database import init_db, save_scan, get_history

app = FastAPI(title="PhishBlockAI API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()

class URLRequest(BaseModel):
    url: str

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