const ICONS = { safe: "✓", suspicious: "⚠", phishing: "✕" };
const TITLES = { safe: "Safe site", suspicious: "Suspicious site", phishing: "Phishing site" };
const ACTION_LABELS = { phishing: "Leave this site", suspicious: "Proceed with caution" };

function renderResult(data) {
  const content = document.getElementById("content");
  const pred = data.prediction;

  const reasonsHtml = (data.reasons && data.reasons.length)
    ? `<ul>${data.reasons.map(r => `<li>${r}</li>`).join("")}</ul>`
    : `<div class="no-reasons">No specific red flags detected.</div>`;

  const actionHtml = pred !== "safe"
    ? `<div class="action-wrap">
         <button class="action-btn ${pred}" id="action-btn">${ACTION_LABELS[pred]}</button>
       </div>`
    : "";

  content.innerHTML = `
    <div class="status-block">
      <div class="status-icon ${pred}">${ICONS[pred] || ""}</div>
      <div class="status-title ${pred}">${TITLES[pred] || pred}</div>
      <div class="status-url">${data.url}</div>
    </div>

    <div class="reasons-wrap">
      <div class="reasons">
        <div class="heading">Why we flagged this</div>
        ${reasonsHtml}
      </div>
    </div>

    ${actionHtml}
  `;

  if (pred !== "safe") {
    document.getElementById("action-btn").onclick = () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.tabs.goBack(tabs[0].id);
      });
    };
  }
}

function renderNoData() {
  document.getElementById("content").innerHTML = `
    <div class="loading">No scan data for this page yet.<br>Try reloading the page.</div>
  `;
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab) { renderNoData(); return; }
  chrome.storage.local.get([String(tab.id)], (result) => {
    const data = result[String(tab.id)];
    if (!data) { renderNoData(); return; }
    renderResult(data);
  });
});
