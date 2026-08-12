import streamlit as st
import pandas as pd
import requests
import plotly.express as px
from datetime import datetime

API = "https://phishblockai.onrender.com"

st.set_page_config(page_title="PhishBlockAI Dashboard", layout="wide", initial_sidebar_state="expanded")
st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

@st.cache_data(ttl=5)
def get_stats():
    return requests.get(f"{API}/stats").json()

@st.cache_data(ttl=5)
def get_history(limit=2000):
    return pd.DataFrame(requests.get(f"{API}/history?limit={limit}").json())

def predict(url):
    return requests.post(f"{API}/predict", json={"url": url}).json()

def risk_color(score):
    if score >= 80: return "🔴"
    if score >= 50: return "🟠"
    return "🟢"

with st.sidebar:
    st.markdown("### 🛡️ PhishBlockAI")
    st.caption("Real-Time Protection")
    st.markdown("---")
    page = st.radio(
        "Navigate",
        ["🏠 Dashboard", "⚠️ Threats", "🔍 URL Scanner", "🕘 Browse History",
         "🔔 Alerts", "📊 Statistics", "⚙️ Settings", "ℹ️ About"],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.info("Our AI model analyzes URLs in real-time and protects you from phishing, malware & online scams.")

try:
    stats = get_stats()
    history = get_history()
except Exception:
    st.error("⚠️ Cannot reach backend API. Make sure uvicorn is running on https://phishblockai.onrender.com")
    st.stop()

if not history.empty:
    history["detected_at"] = pd.to_datetime(history["detected_at"])

if page == "🏠 Dashboard":
    st.title("PhishBlockAI — Real-Time Threat Intelligence Dashboard")
    st.caption("Monitor, Detect & Analyze Browser Threats in Real-Time")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🌐 Total URLs Scanned", stats["total_scanned"])
    c2.metric("⚠️ Threats Detected", stats["threats_detected"])
    c3.metric("✅ Safe URLs", stats["safe"])
    c4.metric("📈 Avg Risk Score", f"{stats['avg_risk_score']}/100")

    if not history.empty:
        col1, col2 = st.columns([1.6, 1])
        with col1:
            st.subheader("Threats Over Time")
            daily = history[history["prediction"] != "safe"].groupby(
                history["detected_at"].dt.date).size().reset_index(name="count")
            if not daily.empty:
                fig = px.area(daily, x="detected_at", y="count")
                fig.update_traces(line_color="#ef4444", fillcolor="rgba(239,68,68,0.2)")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No threats detected yet.")
        with col2:
            st.subheader("Threat Distribution")
            dist = history["prediction"].value_counts().reset_index()
            dist.columns = ["prediction", "count"]
            colors = {"phishing": "#ef4444", "suspicious": "#f59e0b", "safe": "#22c55e"}
            fig = px.pie(dist, names="prediction", values="count", hole=0.55,
                         color="prediction", color_discrete_map=colors)
            st.plotly_chart(fig, use_container_width=True)

        col3, col4 = st.columns([1.6, 1])
        with col3:
            st.subheader("Recent Threats Detected")
            recent = history[history["prediction"] != "safe"].sort_values("detected_at", ascending=False).head(8)
            for _, row in recent.iterrows():
                badge = "🔴 Blocked" if row["risk_score"] >= 80 else "🟠 Warned"
                st.markdown(f"{risk_color(row['risk_score'])} **{row['url'][:50]}** — "
                            f"{row['prediction']} — Risk: **{row['risk_score']}** — {badge}")
        with col4:
            st.subheader("Top Risky Domains")
            risky = history[history["prediction"] != "safe"].sort_values("risk_score", ascending=False)
            risky = risky.drop_duplicates("url").head(5)
            for _, row in risky.iterrows():
                st.progress(row["risk_score"] / 100, text=f"{row['url'][:30]} — {row['risk_score']}")
    else:
        st.info("No scans yet — browse with the extension active to populate data.")

elif page == "⚠️ Threats":
    st.title("⚠️ All Detected Threats")
    if history.empty:
        st.info("No data yet.")
    else:
        threats = history[history["prediction"] != "safe"].sort_values("detected_at", ascending=False)
        st.caption(f"{len(threats)} threats detected out of {len(history)} total scans")
        filter_type = st.multiselect("Filter by type", options=threats["prediction"].unique().tolist(),
                                       default=threats["prediction"].unique().tolist())
        filtered = threats[threats["prediction"].isin(filter_type)]
        st.dataframe(
            filtered[["url", "prediction", "risk_score", "confidence", "reasons", "detected_at"]],
            use_container_width=True, height=500
        )

elif page == "🔍 URL Scanner":
    st.title("🔍 URL Scanner")
    st.caption("Manually check any URL for phishing or malware risk")
    url_input = st.text_input("Enter a URL to scan", placeholder="https://example.com")
    if st.button("Scan URL", type="primary"):
        if url_input.strip():
            with st.spinner("Analyzing..."):
                result = predict(url_input.strip())
            get_stats.clear()
            get_history.clear()
            score = result["risk_score"]
            pred = result["prediction"]
            color = {"phishing": "🔴", "suspicious": "🟠", "safe": "🟢"}[pred]
            st.markdown(f"## {color} {pred.upper()} — Risk Score: {score}/100")
            st.progress(score / 100)
            st.write(f"**Confidence:** {result['confidence']*100:.0f}%")
            if result["reasons"]:
                st.write("**Reasons flagged:**")
                for r in result["reasons"]:
                    st.write(f"- {r}")
            else:
                st.write("No specific red flags detected.")
        else:
            st.warning("Please enter a URL first.")

elif page == "🕘 Browse History":
    st.title("🕘 Browse History")
    if history.empty:
        st.info("No scans yet.")
    else:
        st.caption(f"{len(history)} total URLs scanned")
        search = st.text_input("Search URL", placeholder="Type to filter...")
        display = history.sort_values("detected_at", ascending=False)
        if search:
            display = display[display["url"].str.contains(search, case=False, na=False)]
        st.dataframe(display[["url", "prediction", "risk_score", "detected_at"]], use_container_width=True, height=550)

elif page == "🔔 Alerts":
    st.title("🔔 High-Risk Alerts")
    st.caption("URLs scoring 80+ risk — treated as confirmed phishing/malware")
    if history.empty:
        st.info("No alerts yet.")
    else:
        alerts = history[history["risk_score"] >= 80].sort_values("detected_at", ascending=False)
        if alerts.empty:
            st.success("No high-risk alerts. All clear! ✅")
        else:
            for _, row in alerts.iterrows():
                with st.container(border=True):
                    st.markdown(f"### 🔴 {row['prediction'].upper()} detected")
                    st.write(f"**URL:** {row['url']}")
                    st.write(f"**Risk Score:** {row['risk_score']}/100")
                    st.write(f"**Detected:** {row['detected_at']}")
                    if row["reasons"]:
                        st.write(f"**Reasons:** {row['reasons']}")

elif page == "📊 Statistics":
    st.title("📊 Statistics")
    if history.empty:
        st.info("No data yet.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Risk Score Distribution")
            fig = px.histogram(history, x="risk_score", nbins=20, color_discrete_sequence=["#6366f1"])
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("Scans Per Day")
            per_day = history.groupby(history["detected_at"].dt.date).size().reset_index(name="scans")
            fig = px.bar(per_day, x="detected_at", y="scans", color_discrete_sequence=["#3b82f6"])
            st.plotly_chart(fig, use_container_width=True)
        st.subheader("Prediction Breakdown")
        breakdown = history["prediction"].value_counts().reset_index()
        breakdown.columns = ["Prediction", "Count"]
        breakdown["Percentage"] = (breakdown["Count"] / breakdown["Count"].sum() * 100).round(1)
        st.dataframe(breakdown, use_container_width=True)

elif page == "⚙️ Settings":
    st.title("⚙️ Settings")
    st.caption("Configure detection thresholds (display only for now)")
    st.slider("Suspicious threshold", 0, 100, 50)
    st.slider("Phishing threshold", 0, 100, 80)
    st.toggle("Real-Time Protection", value=True)
    st.toggle("Auto-block high-risk sites", value=True)
    st.button("Save Settings")

elif page == "ℹ️ About":
    st.title("ℹ️ About PhishBlockAI")
    st.markdown("""
    **PhishBlockAI — Real-Time Browser Threat Intelligence**

    An end-to-end machine learning system for detecting phishing and malicious URLs in real time.

    **Architecture:** RandomForestClassifier (900K+ URLs) + rule-based trust override, FastAPI + SQLite backend,
    Manifest V3 Chrome extension with automatic on-page warnings, Streamlit dashboard.

    **Model performance:** ROC-AUC ≈ 0.97

    **Version:** 1.0.0
    """)

st.markdown("---")
fcol1, fcol2, fcol3 = st.columns(3)
fcol1.caption("🛡️ Real-Time Protection: **ON**")
fcol2.caption("🗄️ Database: **Connected**")
fcol3.caption(f"🕐 Last Updated: {datetime.now().strftime('%I:%M:%S %p')}")