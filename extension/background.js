const API_URL = "http://127.0.0.1:8000/predict";

function injectBanner(tabId, data) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: (prediction, reasons) => {
      const existing = document.getElementById("phishblockai-banner");
      if (existing) existing.remove();

      const colors = { phishing: "#ef4444", suspicious: "#f59e0b", safe: "#16a34a" };
      const labels = {
        phishing: "⚠ WARNING: Likely Phishing Site",
        suspicious: "⚠ Caution: Suspicious Site",
        safe: "✓ This site looks safe",
      };

      const banner = document.createElement("div");
      banner.id = "phishblockai-banner";
      banner.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        background: ${colors[prediction] || "#f59e0b"}; color: white;
        font-family: system-ui, sans-serif; padding: 14px 20px;
        display: flex; align-items: center; justify-content: space-between;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3); font-size: 14px;
      `;
      const reasonText = reasons && reasons.length ? " — " + reasons.join(", ") : "";
      banner.innerHTML = `
        <span><strong>${labels[prediction]}</strong>${reasonText}</span>
        <button id="phishblockai-dismiss" style="background:white; color:black; border:none; padding:4px 12px; border-radius:4px; cursor:pointer; font-weight:600;">Dismiss</button>
      `;
      document.body.prepend(banner);
      document.getElementById("phishblockai-dismiss").onclick = () => banner.remove();

      if (prediction === "safe") {
        setTimeout(() => { const el = document.getElementById("phishblockai-banner"); if (el) el.remove(); }, 3000);
      }
    },
    args: [data.prediction, data.reasons],
  }).catch(err => {
    if (!err.message.includes("Frame with ID") && !err.message.includes("Cannot access")) {
      console.error("Injection failed:", err);
    }
  });
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    try {
      const res = await fetch(API_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: tab.url }),
      });
      const data = await res.json();
      await chrome.storage.local.set({ [String(tabId)]: data });

      if (data.prediction === "phishing") {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
      } else if (data.prediction === "suspicious") {
        chrome.action.setBadgeText({ text: "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId });
      } else {
        chrome.action.setBadgeText({ text: "", tabId });
      }
      injectBanner(tabId, data);
    } catch (e) {
      console.error("Prediction failed:", e);
    }
  }
});
