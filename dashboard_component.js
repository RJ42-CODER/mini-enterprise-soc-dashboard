// NOTE: Standalone reference copy. The active JavaScript served by Flask is in static/dashboard_component.js
(() => {
  "use strict";
  const base = (window.SOC_API_BASE || "").replace(/\\/$ /, "");
  const grid = document.getElementById("mitre-grid"), value = document.getElementById("resilience-value");
  const detail = document.getElementById("resilience-detail"), error = document.getElementById("mitre-error");
  const classes = { UNTESTED: "state-gray", DETECTED: "state-amber", MITIGATED: "state-green" };
  async function api(path, opts = {}) {
    const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
    if (window.SOC_ANALYST_TOKEN) headers.Authorization = `Bearer ${window.SOC_ANALYST_TOKEN}`;
    const r = await fetch(base + path, { ...opts, headers, credentials: "same-origin" });
    if (!r.ok) throw Error(`API HTTP ${r.status}`);
    return r.json();
  }
  function node(tag, cls, txt) { const n = document.createElement(tag); if (cls) n.className = cls; if (txt !== undefined) n.textContent = txt; return n; }
  async function requestAction(item, op) {
    if (!confirm(`${op === "block" ? "Request block" : "Request unblock"} for this technique? You must specify the exact lab IP next.`)) return;
    const ip = prompt("Enter exact authorized lab source IPv4 address:");
    if (!ip) return;
    try {
      const r = await api(op === "block" ? "/api/soc/mitigate/block" : "/api/soc/mitigate/unblock",
        { method: "POST", body: JSON.stringify({ target_ip: ip, signature: item.signature }) });
      alert(`Action ${r.action_id} queued for approval. This does not mean containment occurred.`);
    } catch (e) { alert(`Request failed: ${e.message}`); }
  }
  function render(data) {
    grid.replaceChildren();
    for (const item of data.matrix || []) {
      const card = node("article", `mitre-card ${classes[item.state] || "state-gray"}`);
      const top = node("div", "mitre-card-top");
      top.append(node("b", "", item.technique_id), node("span", "state-pill", item.state)); card.append(top);
      card.append(node("h3", "", item.technique_name));
      card.append(node("p", "muted", `${item.tactic} · ${item.signature}`));
      card.append(node("p", "", `Alerts: ${item.alert_count} · Verified mitigations: ${item.mitigated_count}`));
      const actions = node("div", "mitre-actions");
      for (const [label, op] of [["Request containment", "block"], ["Request unblock", "unblock"]]) {
        const b = node("button", "button", label); b.type = "button";
        b.addEventListener("click", () => requestAction(item, op)); actions.append(b);
      }
      card.append(actions); grid.append(card);
    }
    value.textContent = data.resilience_index == null ? "N/A" : `${Number(data.resilience_index).toFixed(2)}%`;
    detail.textContent = `${data.mitigated_techniques} mitigated / ${data.detected_techniques} detected techniques`;
  }
  async function refresh() {
    try { error.hidden = true; render(await api("/api/soc/mitre-matrix")); }
    catch (e) { error.textContent = `Unable to load matrix: ${e.message}`; error.hidden = false; }
  }
  refresh(); setInterval(refresh, 10000);
})();
