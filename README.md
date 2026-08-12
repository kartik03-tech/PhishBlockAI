# PhishBlockAI
### Real-Time Browser Threat Intelligence Using Machine Learning

PhishBlockAI is a full-stack phishing and malicious URL detection system. It combines a machine learning model trained on 900,000+ labeled URLs with a live Google Safe Browsing API check, wrapped in a Chrome extension that warns users automatically as they browse, plus an analytics dashboard.

**Live backend:** https://phishblockai.onrender.com

---

## Architecture

```
Browser Extension (Chrome, Manifest V3)
        │
        ▼
FastAPI Backend (deployed on Render)
        │
        ├──► Layer 1: Google Safe Browsing API (confirmed threats)
        │
        └──► Layer 2: Trained ML Model + trust-override rules
                        │
                        ▼
                  SQLite Database
                        │
                        ▼
              Streamlit Analytics Dashboard
```

**Why two detection layers:** the Safe Browsing API catches URLs Google has already confirmed malicious with 100% certainty, but can't catch brand-new phishing sites that haven't been reported yet. The ML model fills that gap by analyzing URL structure directly, so the two layers cover each other's blind spots.

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML Model | scikit-learn (RandomForestClassifier), pandas, joblib |
| Backend API | FastAPI, SQLite |
| Threat Intelligence | Google Safe Browsing API v4 |
| Browser Extension | JavaScript, Chrome Extension Manifest V3 |
| Dashboard | Streamlit, Plotly |
| Deployment | Render (backend), GitHub |

---

## Model Details

- **Training data:** 935,197 URLs merged from 5 sources:
  - Kaggle "Malicious URLs dataset" (sid321axn) — 651,191 rows
  - Kaggle "Web Page Phishing Detection" (shashwatwork) — 11,430 rows
  - PhiUSIIL Phishing URL Dataset (2024) — 235,795 rows
  - Tranco Top domains — legitimate/safe examples
  - Curated real-world safe URLs (banks, government portals, AI tools, search engines) — added specifically to fix false positives found during testing

- **Features (15 total):** URL length, domain length, dot/hyphen/digit counts, HTTPS presence, IP-address detection, suspicious keyword matching, subdomain count, path length, URL-shortener detection, and domain popularity (checked against Tranco's top domains list).

- **Algorithm:** RandomForestClassifier, tuned for a balance between accuracy and memory footprint (reduced from 300→100 trees, depth 15→10, to fit within Render's free-tier 512MB memory limit).

- **Performance:** ROC-AUC 0.948, ~88% accuracy on held-out test data.

- **Trust-override rule:** a prediction-time safety net — if a domain is known-popular (Tranco top 100k), served over HTTPS, and has none of the hard red flags (no IP address, no suspicious keywords, not a shortener), its risk score is capped at 35. This was added after testing revealed the raw model could over-flag legitimate sites like bank portals and AI tools due to superficial URL structure (long query strings, multiple subdomains) that also appears in some phishing URLs.

---

## Setup (local development)

```bash
git clone https://github.com/kartik03-tech/PhishBlockAI.git
cd PhishBlockAI
python -m venv venv
source venv/Scripts/activate   # Windows Git Bash
pip install -r requirements.txt
```

You'll also need to download these datasets separately into `dataset/raw/` (excluded from the repo due to size):
- [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)
- [Web Page Phishing Detection](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
- [PhiUSIIL Phishing URL Dataset](https://www.kaggle.com/datasets/ndarvind/phiusiil-phishing-url-dataset)
- [Tranco Top 1M](https://tranco-list.eu/)

Then build the dataset and train:
```bash
cd dataset && python build_dataset.py
cd ../model && python train.py
```

Create a `.env` file in the project root with your own [Google Safe Browsing API key](https://console.cloud.google.com/):
```
SAFE_BROWSING_API_KEY=your_key_here
```

Run the backend:
```bash
cd backend
uvicorn app:app --reload --port 8000
```

Run the dashboard:
```bash
cd dashboard
streamlit run streamlit_app.py
```

Load the extension: `chrome://extensions` → Developer mode → Load unpacked → select `extension/`

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Health check |
| `/predict` | POST | Analyze a URL, returns prediction, risk score, and reasons |
| `/history` | GET | Recent scan history |
| `/stats` | GET | Aggregate statistics (total scans, threats, avg risk score) |

Interactive docs available at `/docs` when the backend is running.

---

## Known Limitations

- **URL-only analysis** — the model doesn't inspect page content, login forms, or visual brand impersonation; it works purely from the URL string.
- **No domain-age (WHOIS) signal** — a planned but not-yet-implemented feature that would strengthen detection of newly-registered phishing domains.
- **Popular-domain feature coverage** — only covers domains within Tranco's top 100k list (trimmed from 1M to fit memory constraints); smaller legitimate sites outside that list rely on structural features alone.
- **Google Safe Browsing only catches already-reported threats** — brand-new phishing sites (minutes/hours old) depend entirely on the ML model layer until Google's crawlers catch up.
- **Render free-tier cold starts** — the backend spins down after 15 minutes of inactivity; the first request afterward can take 30-50 seconds.
- **SQLite** is used for simplicity; a production deployment with multiple concurrent users would need PostgreSQL.

---

## Development Notes

This project went through several rounds of real-world testing and bug fixing:
- An early version of the suspicious-keyword list included words like "bank," "login," and "secure" — this caused false positives on legitimate sites (e.g. flagging State Bank of India's real portal). Fixed by narrowing the keyword list to terms almost exclusively seen in phishing kits.
- The model was found to over-weight superficial URL structure (dot count, subdomain count, URL length) due to limited feature richness, causing false positives on legitimate search-engine URLs (Bing, Google search results) and AI product URLs (claude.ai). Fixed by adding a domain-popularity feature and a prediction-time trust-override rule.
- The initial trained model (207MB) and full Tranco list (1M domains) exceeded Render's free-tier memory limit during deployment. Fixed by compressing the model file and reducing both model complexity and the popularity-lookup list size.

---

## Version

1.0.0 — August 2026