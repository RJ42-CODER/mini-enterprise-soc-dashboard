(() => {
  "use strict";

  // Base API endpoint URL (empty string indicates origin root)
  const base = (window.SOC_API_BASE || "").replace(/\/$/, "");

  // DOM Elements from MITRE component
  const grid = document.getElementById("mitre-grid");
  const value = document.getElementById("resilience-value");
  const detail = document.getElementById("resilience-detail");
  const error = document.getElementById("mitre-error");

  // Layout & Toolbar Elements
  const tokenInput = document.getElementById("analyst-token-input");
  const btnSetToken = document.getElementById("btn-set-token");
  const btnClearToken = document.getElementById("btn-clear-token");
  const btnToggleToken = document.getElementById("btn-toggle-token");
  const btnRefresh = document.getElementById("btn-refresh");
  const authStatusBadge = document.getElementById("auth-status-badge");
  const statResilience = document.getElementById("stat-resilience");
  const statDetected = document.getElementById("stat-detected");
  const statMitigated = document.getElementById("stat-mitigated");
  const statTotal = document.getElementById("stat-total");
  const clockEl = document.getElementById("soc-clock");

  // Incident Investigation Workbench Elements
  const incidentsListEl = document.getElementById("incidents-list");
  const queueCountBadgeEl = document.getElementById("queue-count-badge");
  const detailsEmptyEl = document.getElementById("incident-details-empty");
  const detailsContentEl = document.getElementById("incident-details-content");
  const btnRefreshIncidents = document.getElementById("btn-refresh-incidents");
  const filterAllBtn = document.getElementById("filter-all");
  const filterOpenBtn = document.getElementById("filter-open");
  const filterClosedBtn = document.getElementById("filter-closed");

  // Detail Fields
  const detailIncidentId = document.getElementById("detail-incident-id");
  const detailIncidentTitle = document.getElementById("detail-incident-title");
  const detailSeverityBadge = document.getElementById("detail-severity-badge");
  const detailStatusBadge = document.getElementById("detail-status-badge");
  const detailClassBadge = document.getElementById("detail-class-badge");
  const detailSourceIp = document.getElementById("detail-source-ip");
  const detailTechniqueStr = document.getElementById("detail-technique-str");
  const detailCreatedAt = document.getElementById("detail-created-at");
  const detailUpdatedAt = document.getElementById("detail-updated-at");
  const detailClosureInfo = document.getElementById("detail-closure-info");
  const detailClosedAt = document.getElementById("detail-closed-at");
  const detailClosedRationale = document.getElementById("detail-closed-rationale");
  const workflowStepper = document.getElementById("workflow-stepper");

  // Workflow Action Buttons
  const btnWfTriage = document.getElementById("btn-wf-triage");
  const btnWfInvestigating = document.getElementById("btn-wf-investigating");
  const btnWfToggleClassify = document.getElementById("btn-wf-toggle-classify");
  const btnWfRequestBlock = document.getElementById("btn-wf-request-block");
  const btnWfClose = document.getElementById("btn-wf-close");

  // Classification Drawer Elements
  const classificationDrawer = document.getElementById("classification-drawer");
  const classificationRationaleInput = document.getElementById("classification-rationale-input");
  const btnSubmitClassification = document.getElementById("btn-submit-classification");
  const btnCancelClassification = document.getElementById("btn-cancel-classification");

  // Evidence Elements
  const evTechId = document.getElementById("ev-tech-id");
  const evTechName = document.getElementById("ev-tech-name");
  const evTactic = document.getElementById("ev-tactic");
  const evSignature = document.getElementById("ev-signature");
  const evMessage = document.getElementById("ev-message");

  // Correlated & Related Elements
  const correlatedCount = document.getElementById("correlated-count");
  const correlatedAlertsBody = document.getElementById("correlated-alerts-body");
  const incidentActionsContainer = document.getElementById("incident-actions-container");

  // Timeline & Notes Elements
  const timelineFeed = document.getElementById("timeline-feed");
  const analystNoteTextarea = document.getElementById("analyst-note-textarea");
  const btnAddNote = document.getElementById("btn-add-note");

  // State
  let allIncidents = [];
  let selectedIncidentId = null;
  let currentFilter = "ALL";

  // CSS state class mapping matching component
  const classes = {
    UNTESTED: "state-gray",
    DETECTED: "state-amber",
    MITIGATED: "state-green"
  };

  const workflowOrder = [
    "NEW",
    "TRIAGE",
    "INVESTIGATING",
    "CLASSIFIED",
    "RESPONSE_REQUESTED",
    "CONTAINMENT_PENDING_APPROVAL",
    "CONTAINED",
    "CLOSED"
  ];

  /**
   * Helper to update Analyst Session Authentication status badge
   */
  function updateAuthBadge(state, message) {
    if (!authStatusBadge) return;
    authStatusBadge.className = "auth-badge";

    if (state === "authenticated") {
      authStatusBadge.classList.add("status-authenticated");
      authStatusBadge.textContent = "● Authenticated";
      authStatusBadge.title = message || "Valid analyst token verified";
    } else if (state === "checking") {
      authStatusBadge.classList.add("status-checking");
      authStatusBadge.textContent = "● Verifying...";
      authStatusBadge.title = "Connecting to backend...";
    } else if (state === "error") {
      authStatusBadge.classList.add("status-error");
      authStatusBadge.textContent = "● Unauthorized (401)";
      authStatusBadge.title = message || "Invalid or rejected analyst token";
    } else {
      authStatusBadge.classList.add("status-unauthenticated");
      authStatusBadge.textContent = "● Token Not Set";
      authStatusBadge.title = "Enter ANALYST_TOKEN above to access API";
    }
  }

  /**
   * Execute authenticated API request via Bearer header.
   */
  async function api(path, opts = {}) {
    const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };

    if (window.SOC_ANALYST_TOKEN) {
      headers.Authorization = `Bearer ${window.SOC_ANALYST_TOKEN}`;
    }

    let response;
    try {
      response = await fetch(base + path, { ...opts, headers, credentials: "same-origin" });
    } catch (networkErr) {
      throw Error(`Network error: ${networkErr.message}. Ensure backend is running at ${base || window.location.origin}`);
    }

    if (!response.ok) {
      let serverErrorMsg = "";
      try {
        const errJson = await response.json();
        if (errJson && errJson.error) {
          serverErrorMsg = errJson.error;
        }
      } catch (_) {}

      if (response.status === 401) {
        const detail = serverErrorMsg ? `: ${serverErrorMsg}` : "";
        throw Error(`Unauthorized (401)${detail}. Set ANALYST_TOKEN in the toolbar above.`);
      }

      if (response.status === 503) {
        throw Error(`Service Unavailable (503): Backend authentication is not configured.`);
      }

      const detail = serverErrorMsg ? `: ${serverErrorMsg}` : `HTTP status ${response.status}`;
      throw Error(`API Request Failed (${response.status}): ${detail}`);
    }

    return response.json();
  }

  function node(tag, cls, txt) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt !== undefined) n.textContent = txt;
    return n;
  }

  function getSeverityClass(sev) {
    const s = String(sev || "").toLowerCase();
    if (s === "critical") return "badge-severity-critical";
    if (s === "high") return "badge-severity-high";
    if (s === "medium") return "badge-severity-medium";
    if (s === "low") return "badge-severity-low";
    return "badge-severity-medium";
  }

  function getStatusBadgeClass(st) {
    const s = String(st || "").toUpperCase();
    if (s === "CONTAINED" || s === "VERIFIED") return "badge-status-contained";
    if (s === "CLOSED") return "badge-status-closed";
    if (s === "CONTAINMENT_PENDING_APPROVAL" || s === "RESPONSE_REQUESTED" || s === "PENDING") return "badge-status-pending";
    if (s === "INVESTIGATING" || s === "CLASSIFIED" || s === "TRIAGE" || s === "APPROVED") return "badge-status-active";
    if (s === "EXECUTED" || s === "DRY_RUN") return "badge-status-executed";
    return "badge-status-new";
  }

  /**
   * SOAR Containment / Rollback Action Request
   */
  async function requestAction(item, op, explicitIp = null, explicitIncId = null) {
    if (!window.SOC_ANALYST_TOKEN) {
      alert("Authentication required: Please set your Analyst Token above before submitting response actions.");
      if (tokenInput) tokenInput.focus();
      return;
    }

    const opLabel = op === "block" ? "Request containment block" : "Request containment unblock";
    const targetIp = explicitIp || prompt(`Enter authorized target IPv4 address for ${opLabel}:`);
    if (!targetIp || !targetIp.trim()) return;

    try {
      const endpoint = op === "block" ? "/api/soc/mitigate/block" : "/api/soc/mitigate/unblock";
      const payload = { target_ip: targetIp.trim() };
      if (item && item.signature) payload.signature = item.signature;
      if (explicitIncId) payload.incident_id = explicitIncId;

      const r = await api(endpoint, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      alert(`Action #${r.action_id} successfully queued with status '${r.status}'.\nNote: This queues approval for containment; verification must be confirmed via host nftables.`);
      refresh();
      if (selectedIncidentId) loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      alert(`Containment request failed:\n${e.message}`);
    }
  }

  /**
   * Render MITRE ATT&CK Matrix cards and resilience score
   */
  function render(data) {
    if (!grid) return;
    grid.replaceChildren();

    const matrix = data.matrix || [];

    if (matrix.length === 0) {
      grid.append(node("p", "muted", "No MITRE techniques registered in SOC telemetry schema."));
    }

    for (const item of matrix) {
      const card = node("article", `mitre-card ${classes[item.state] || "state-gray"}`);
      const top = node("div", "mitre-card-top");
      top.append(node("b", "", item.technique_id), node("span", "state-pill", item.state));
      card.append(top);

      card.append(node("h3", "", item.technique_name));
      card.append(node("p", "muted", `${item.tactic} · ${item.signature}`));
      card.append(node("p", "", `Alerts: ${item.alert_count} · Verified mitigations: ${item.mitigated_count}`));

      const actions = node("div", "mitre-actions");
      for (const [label, op] of [["Request containment", "block"], ["Request unblock", "unblock"]]) {
        const b = node("button", "button", label);
        b.type = "button";
        b.addEventListener("click", () => requestAction(item, op));
        actions.append(b);
      }

      // Add "Investigate Incidents" button if alerts have been observed
      if (item.alert_count > 0) {
        const invBtn = node("button", "button btn-investigate", `Investigate (${item.alert_count} Alerts)`);
        invBtn.type = "button";
        invBtn.title = "Jump to incident investigation workbench for this technique";
        invBtn.addEventListener("click", () => focusIncidentBySignature(item.signature));
        actions.append(invBtn);
      }

      card.append(actions);
      grid.append(card);
    }

    const formattedIndex = data.resilience_index == null ? "N/A" : `${Number(data.resilience_index).toFixed(2)}%`;
    if (value) value.textContent = formattedIndex;
    if (detail) detail.textContent = `${data.mitigated_techniques} mitigated / ${data.detected_techniques} detected techniques`;

    if (statResilience) statResilience.textContent = formattedIndex;
    if (statDetected) statDetected.textContent = data.detected_techniques ?? 0;
    if (statMitigated) statMitigated.textContent = data.mitigated_techniques ?? 0;
    if (statTotal) statTotal.textContent = matrix.length;
  }

  // =========================================================================
  // Incident Investigation Workflow Logic
  // =========================================================================

  /**
   * Fetch incidents list
   */
  async function fetchIncidents() {
    if (!incidentsListEl) return;
    try {
      const data = await api("/api/soc/incidents");
      allIncidents = data.incidents || [];
      if (queueCountBadgeEl) {
        queueCountBadgeEl.textContent = `${allIncidents.length} Incident${allIncidents.length === 1 ? "" : "s"}`;
      }
      renderIncidentsQueue();

      // Auto-select first incident if none currently selected
      if (!selectedIncidentId && allIncidents.length > 0) {
        selectedIncidentId = allIncidents[0].incident_id;
        loadIncidentDetails(selectedIncidentId);
      } else if (selectedIncidentId) {
        // Silently refresh current detail view without collapsing
        loadIncidentDetails(selectedIncidentId, false);
      }
    } catch (e) {
      if (incidentsListEl) {
        incidentsListEl.innerHTML = `<p class="muted p-queue-empty">Unable to load incidents: ${e.message}</p>`;
      }
    }
  }

  /**
   * Render the left-hand incidents queue
   */
  function renderIncidentsQueue() {
    if (!incidentsListEl) return;
    incidentsListEl.replaceChildren();

    const filtered = allIncidents.filter(inc => {
      if (currentFilter === "OPEN") return inc.status !== "CLOSED";
      if (currentFilter === "CLOSED") return inc.status === "CLOSED";
      return true;
    });

    if (filtered.length === 0) {
      incidentsListEl.append(node("p", "muted p-queue-empty", "No incidents match the selected filter."));
      return;
    }

    for (const inc of filtered) {
      const card = node("div", `incident-queue-card${inc.incident_id === selectedIncidentId ? " selected" : ""}`);
      card.setAttribute("role", "button");
      card.setAttribute("tabindex", "0");

      const top = node("div", "qcard-top");
      top.append(node("span", "qcard-id", `#INC-${inc.incident_id}`));

      const badges = node("div", "badge-cluster");
      badges.append(node("span", `badge ${getSeverityClass(inc.severity)}`, String(inc.severity || "MEDIUM").toUpperCase()));
      badges.append(node("span", `badge ${getStatusBadgeClass(inc.status)}`, inc.status));
      top.append(badges);
      card.append(top);

      card.append(node("h4", "qcard-title", inc.title || `${inc.technique_name} from ${inc.source_ip}`));

      const meta = node("div", "qcard-meta");
      meta.append(node("span", "mono-text", inc.source_ip || "Not available"));
      meta.append(node("span", "", `${inc.alert_count} alert${inc.alert_count === 1 ? "" : "s"}`));
      card.append(meta);

      if (inc.latest_action) {
        const actNote = node("div", "qcard-meta", `⚡ ${inc.latest_action.action_type}: ${inc.latest_action.status}`);
        actNote.style.color = inc.latest_action.status === "VERIFIED" ? "#16a34a" : (inc.latest_action.status === "PENDING" ? "#d97706" : "#475569");
        actNote.style.fontWeight = "600";
        card.append(actNote);
      }

      card.addEventListener("click", () => {
        selectedIncidentId = inc.incident_id;
        renderIncidentsQueue();
        loadIncidentDetails(inc.incident_id, true);
      });

      incidentsListEl.append(card);
    }
  }

  /**
   * Load and render deep investigation details for selected incident
   */
  async function loadIncidentDetails(incidentId, scrollIntoView = false) {
    if (!detailsContentEl || !detailsEmptyEl) return;

    try {
      const data = await api(`/api/soc/incidents/${incidentId}`);
      const inc = data.incident;
      const alerts = data.alerts || [];
      const related = data.related_alerts || [];
      const actions = data.response_actions || [];
      const timeline = data.timeline || [];

      // Update meta header
      if (detailIncidentId) detailIncidentId.textContent = `#INC-${inc.incident_id}`;
      if (detailIncidentTitle) detailIncidentTitle.textContent = inc.title || "Untitled Incident";

      if (detailSeverityBadge) {
        detailSeverityBadge.className = `badge ${getSeverityClass(inc.severity)}`;
        detailSeverityBadge.textContent = String(inc.severity || "MEDIUM").toUpperCase();
      }

      if (detailStatusBadge) {
        detailStatusBadge.className = `badge ${getStatusBadgeClass(inc.status)}`;
        detailStatusBadge.textContent = inc.status;
      }

      if (detailClassBadge) {
        if (inc.classification) {
          detailClassBadge.hidden = false;
          detailClassBadge.className = `badge ${inc.classification === "CONFIRMED_MALICIOUS" ? "badge-amber" : "badge-neutral"}`;
          detailClassBadge.textContent = inc.classification.replace(/_/g, " ");
        } else {
          detailClassBadge.hidden = true;
        }
      }

      if (detailSourceIp) detailSourceIp.textContent = inc.source_ip || "Not available";
      if (detailTechniqueStr) detailTechniqueStr.textContent = `${inc.technique_name || "Unknown"} (${inc.technique_id || "N/A"}) · ${inc.signature || "N/A"}`;
      if (detailCreatedAt) detailCreatedAt.textContent = inc.created_at || "Not available";
      if (detailUpdatedAt) detailUpdatedAt.textContent = inc.updated_at || "Not available";

      if (detailClosureInfo) {
        if (inc.status === "CLOSED") {
          detailClosureInfo.hidden = false;
          if (detailClosedAt) detailClosedAt.textContent = inc.closed_at || "Not recorded";
          if (detailClosedRationale) detailClosedRationale.textContent = inc.closure_rationale || "No rationale provided";
        } else {
          detailClosureInfo.hidden = true;
        }
      }

      // Populate Summary KPI Cards
      const summaryAlertCount = document.getElementById("summary-alert-count");
      const summaryMitigatedCount = document.getElementById("summary-mitigated-count");
      const summaryStatusVal = document.getElementById("summary-status-val");
      const summaryActionCount = document.getElementById("summary-action-count");

      if (summaryAlertCount) summaryAlertCount.textContent = alerts.length;
      if (summaryMitigatedCount) {
        const verifiedMitigations = actions.filter(a => a.status === "VERIFIED").length;
        summaryMitigatedCount.textContent = verifiedMitigations;
      }
      if (summaryStatusVal) summaryStatusVal.textContent = inc.status || "NEW";
      if (summaryActionCount) summaryActionCount.textContent = actions.length;

      // Update workflow stepper
      updateWorkflowStepper(inc.status);

      // Update Evidence summary
      if (evTechId) evTechId.textContent = inc.technique_id || "Not available";
      if (evTechName) evTechName.textContent = inc.technique_name || "Not available";
      if (evTactic) evTactic.textContent = inc.tactic || "Not available";
      if (evSignature) evSignature.textContent = inc.signature || "Not available";
      if (evMessage) {
        const latestMsg = alerts.length > 0 ? (alerts[0].message || "No raw message text") : "Not available";
        evMessage.textContent = latestMsg;
      }

      // Populate Correlated Alerts Table
      if (correlatedCount) correlatedCount.textContent = alerts.length;
      if (correlatedAlertsBody) {
        correlatedAlertsBody.replaceChildren();
        if (alerts.length === 0) {
          const tr = node("tr");
          tr.append(node("td", "text-center muted", "No alerts correlated"));
          tr.children[0].colSpan = 5;
          correlatedAlertsBody.append(tr);
        } else {
          for (const a of alerts) {
            const tr = node("tr");
            tr.append(node("td", "mono-text", a.event_id || "N/A"));
            tr.append(node("td", "mono-text text-xs", a.timestamp || "N/A"));
            const tdSev = node("td");
            tdSev.append(node("span", `badge ${getSeverityClass(a.severity)}`, String(a.severity || "medium").toUpperCase()));
            tr.append(tdSev);
            tr.append(node("td", "mono-text", a.source_ip || "N/A"));
            tr.append(node("td", "", a.message || "—"));
            correlatedAlertsBody.append(tr);
          }
        }
      }

      // Populate Response Actions History
      if (incidentActionsContainer) {
        incidentActionsContainer.replaceChildren();
        if (actions.length === 0) {
          incidentActionsContainer.append(node("p", "muted p-no-actions", "No response actions recorded for this incident. Use 'Request Containment' to initiate a block."));
        } else {
          for (const act of actions) {
            const card = node("div", `action-summary-card act-${act.status.toLowerCase()}`);
            const details = node("div", "action-details-text");
            details.append(node("strong", "", `Action #${act.action_id} — ${act.action_type}`));
            details.append(node("span", "text-xs", `Target: ${act.target_ip} · Triggered by: ${act.triggered_by}`));
            details.append(node("span", "mono-text text-xs", `Created: ${act.created_at}${act.executed_at ? ` · Executed: ${act.executed_at}` : ""}`));
            card.append(details);

            const rightCluster = node("div", "action-btn-cluster");
            rightCluster.append(node("span", `badge ${getStatusBadgeClass(act.status)}`, act.status));

            // Contextual Approval & Verification Buttons
            if (act.status === "PENDING") {
              const appBtn = node("button", "btn btn-primary btn-sm", "Approve Action");
              appBtn.type = "button";
              appBtn.addEventListener("click", () => approveResponseAction(act.action_id));
              rightCluster.append(appBtn);
            } else if (act.status === "EXECUTED" || act.status === "DRY_RUN") {
              const verBtn = node("button", "btn btn-outline btn-sm", "Verify Mitigation");
              verBtn.type = "button";
              verBtn.title = "Confirm block on host nftables to reflect as MITIGATED";
              verBtn.addEventListener("click", () => verifyResponseAction(act.action_id));
              rightCluster.append(verBtn);
            }

            card.append(rightCluster);
            incidentActionsContainer.append(card);
          }
        }
      }

      // Populate Chronological Timeline & Notes
      if (timelineFeed) {
        timelineFeed.replaceChildren();
        if (timeline.length === 0) {
          timelineFeed.append(node("p", "muted p-empty-timeline", "No timeline events recorded yet."));
        } else {
          for (const t of timeline) {
            const entry = node("div", `timeline-entry t-${t.type.toLowerCase()}`);
            const meta = node("div", "t-meta");
            meta.append(node("span", "mono-text t-time", t.timestamp));
            meta.append(node("span", "badge badge-neutral t-type-badge", t.type));
            const actor = (t.extra && (t.extra.author || t.extra.triggered_by)) || (t.type === "ALERT" ? "SECURITY_AGENT" : "SOC_ANALYST");
            meta.append(node("span", "badge badge-neutral t-actor-badge", actor));
            if (t.severity) {
              meta.append(node("span", `badge ${getSeverityClass(t.severity)}`, t.severity.toUpperCase()));
            }
            entry.append(meta);
            entry.append(node("div", "t-title", t.title));
            entry.append(node("div", "t-detail", t.detail));
            timelineFeed.append(entry);
          }
        }
      }

      // Switch pane from empty state to content
      detailsEmptyEl.hidden = true;
      detailsContentEl.hidden = false;

      if (scrollIntoView) {
        const panel = document.getElementById("incident-workbench-panel");
        if (panel) panel.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    } catch (e) {
      console.error("Failed to load incident details:", e);
    }
  }

  /**
   * Update the 8-step visual workflow stepper
   */
  function updateWorkflowStepper(currentStatus) {
    if (!workflowStepper) return;
    const currentIndex = workflowOrder.indexOf(currentStatus);
    const nodes = workflowStepper.querySelectorAll(".step-node");

    nodes.forEach(nodeEl => {
      const stepName = nodeEl.getAttribute("data-step");
      const stepIdx = workflowOrder.indexOf(stepName);

      nodeEl.classList.remove("active", "completed", "future");
      if (stepIdx === currentIndex) {
        nodeEl.classList.add("active");
      } else if (stepIdx < currentIndex) {
        nodeEl.classList.add("completed");
      } else {
        nodeEl.classList.add("future");
      }
    });
  }

  /**
   * Jump to incident matching technique signature
   */
  function focusIncidentBySignature(sig) {
    const match = allIncidents.find(i => i.signature === sig && i.status !== "CLOSED") ||
                  allIncidents.find(i => i.signature === sig);
    if (match) {
      selectedIncidentId = match.incident_id;
      renderIncidentsQueue();
      loadIncidentDetails(match.incident_id, true);
    } else {
      const panel = document.getElementById("incident-workbench-panel");
      if (panel) panel.scrollIntoView({ behavior: "smooth" });
      alert(`No open incidents found for technique signature ${sig}.`);
    }
  }

  // =========================================================================
  // Analyst Incident Actions & State Transitions
  // =========================================================================

  async function transitionIncidentStatus(status, defaultRationale = "") {
    if (!selectedIncidentId) return;
    const rationale = prompt(`Enter rationale for updating status to '${status}':`, defaultRationale);
    if (rationale === null) return; // user cancelled

    try {
      await api(`/api/soc/incidents/${selectedIncidentId}/status`, {
        method: "POST",
        body: JSON.stringify({ status, rationale: rationale.trim() })
      });
      fetchIncidents();
    } catch (e) {
      alert(`Status update failed: ${e.message}`);
    }
  }

  async function approveResponseAction(actionId) {
    if (!confirm(`Approve Containment Action #${actionId} for execution?`)) return;
    try {
      const r = await api(`/api/soc/response-actions/${actionId}/approve`, { method: "POST" });
      alert(`Action #${r.action_id} approved. Remediation poller will now pick up this action.`);
      refresh();
      if (selectedIncidentId) loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      alert(`Approval failed: ${e.message}`);
    }
  }

  async function verifyResponseAction(actionId) {
    if (!confirm(`Verify that Containment Action #${actionId} exists on host nftables?\nThis will mark the technique MITIGATED in the matrix and update incident to CONTAINED.`)) return;
    try {
      const r = await api(`/api/soc/response-actions/${actionId}/verify`, { method: "POST" });
      alert(`Action #${r.action_id} verified. Technique is now marked MITIGATED in the MITRE ATT&CK Matrix.`);
      refresh();
      if (selectedIncidentId) loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      alert(`Verification failed: ${e.message}`);
    }
  }

  // Wire Incident Buttons
  if (btnWfTriage) {
    btnWfTriage.addEventListener("click", () => transitionIncidentStatus("TRIAGE", "Triage initiated"));
  }

  if (btnWfInvestigating) {
    btnWfInvestigating.addEventListener("click", () => transitionIncidentStatus("INVESTIGATING", "Investigating correlated alerts"));
  }

  if (btnWfToggleClassify && classificationDrawer) {
    btnWfToggleClassify.addEventListener("click", () => {
      classificationDrawer.hidden = !classificationDrawer.hidden;
      if (!classificationDrawer.hidden && classificationRationaleInput) {
        classificationRationaleInput.focus();
      }
    });
  }

  if (btnCancelClassification && classificationDrawer) {
    btnCancelClassification.addEventListener("click", () => {
      classificationDrawer.hidden = true;
    });
  }

  if (btnSubmitClassification) {
    btnSubmitClassification.addEventListener("click", async () => {
      if (!selectedIncidentId) return;
      const selectedRadio = document.querySelector('input[name="incident-class-choice"]:checked');
      const classification = selectedRadio ? selectedRadio.value : "CONFIRMED_MALICIOUS";
      const rationale = (classificationRationaleInput ? classificationRationaleInput.value : "").trim();

      if (!rationale) {
        alert("Please provide an investigation rationale for this classification.");
        if (classificationRationaleInput) classificationRationaleInput.focus();
        return;
      }

      try {
        await api(`/api/soc/incidents/${selectedIncidentId}/classify`, {
          method: "POST",
          body: JSON.stringify({ classification, rationale })
        });
        if (classificationDrawer) classificationDrawer.hidden = true;
        if (classificationRationaleInput) classificationRationaleInput.value = "";
        fetchIncidents();
      } catch (e) {
        alert(`Classification failed: ${e.message}`);
      }
    });
  }

  if (btnWfRequestBlock) {
    btnWfRequestBlock.addEventListener("click", () => {
      if (!selectedIncidentId) return;
      const ip = (detailSourceIp ? detailSourceIp.textContent : "").trim();
      requestAction(null, "block", ip !== "Not available" ? ip : null, selectedIncidentId);
    });
  }

  if (btnWfClose) {
    btnWfClose.addEventListener("click", () => {
      if (!selectedIncidentId) return;
      const rationale = prompt("Enter required resolution and closure rationale to close this incident:");
      if (rationale === null) return;
      if (!rationale.trim()) {
        alert("A closure rationale is required to close an incident.");
        return;
      }
      transitionIncidentStatus("CLOSED", rationale.trim());
    });
  }

  if (btnAddNote) {
    btnAddNote.addEventListener("click", async () => {
      if (!selectedIncidentId || !analystNoteTextarea) return;
      const noteText = analystNoteTextarea.value.trim();
      if (!noteText) {
        alert("Please enter note content before submitting.");
        analystNoteTextarea.focus();
        return;
      }

      try {
        await api(`/api/soc/incidents/${selectedIncidentId}/notes`, {
          method: "POST",
          body: JSON.stringify({ note_text: noteText })
        });
        analystNoteTextarea.value = "";
        loadIncidentDetails(selectedIncidentId, false);
      } catch (e) {
        alert(`Failed to add note: ${e.message}`);
      }
    });
  }

  if (btnRefreshIncidents) {
    btnRefreshIncidents.addEventListener("click", () => {
      fetchIncidents();
    });
  }

  // Filter Buttons
  if (filterAllBtn) {
    filterAllBtn.addEventListener("click", () => {
      currentFilter = "ALL";
      filterAllBtn.classList.add("active");
      if (filterOpenBtn) filterOpenBtn.classList.remove("active");
      if (filterClosedBtn) filterClosedBtn.classList.remove("active");
      renderIncidentsQueue();
    });
  }

  if (filterOpenBtn) {
    filterOpenBtn.addEventListener("click", () => {
      currentFilter = "OPEN";
      filterOpenBtn.classList.add("active");
      if (filterAllBtn) filterAllBtn.classList.remove("active");
      if (filterClosedBtn) filterClosedBtn.classList.remove("active");
      renderIncidentsQueue();
    });
  }

  if (filterClosedBtn) {
    filterClosedBtn.addEventListener("click", () => {
      currentFilter = "CLOSED";
      filterClosedBtn.classList.add("active");
      if (filterAllBtn) filterAllBtn.classList.remove("active");
      if (filterOpenBtn) filterOpenBtn.classList.remove("active");
      renderIncidentsQueue();
    });
  }

  /**
   * Fetch matrix and handle states
   */
  async function refresh() {
    try {
      if (error) {
        error.hidden = true;
        error.textContent = "";
      }

      const data = await api("/api/soc/mitre-matrix");
      render(data);

      if (window.SOC_ANALYST_TOKEN) {
        updateAuthBadge("authenticated");
        // Also fetch incidents queue when authenticated
        fetchIncidents();
      } else {
        updateAuthBadge("unauthenticated");
      }
    } catch (e) {
      if (error) {
        error.textContent = `Unable to load matrix: ${e.message}`;
        error.hidden = false;
      }

      if (e.message.includes("401")) {
        updateAuthBadge(window.SOC_ANALYST_TOKEN ? "error" : "unauthenticated", e.message);
      } else {
        updateAuthBadge("error", e.message);
      }
    }
  }

  // =========================================================================
  // Analyst Token Management (Volatile In-Memory only; no storage persistence)
  // =========================================================================

  function applyTokenFromInput() {
    if (!tokenInput) return;
    const token = tokenInput.value.trim();
    if (!token) {
      alert("Please enter your ANALYST_TOKEN before setting.");
      tokenInput.focus();
      return;
    }

    window.SOC_ANALYST_TOKEN = token;
    updateAuthBadge("checking");
    refresh();
  }

  function clearToken() {
    window.SOC_ANALYST_TOKEN = "";
    if (tokenInput) tokenInput.value = "";
    updateAuthBadge("unauthenticated");
    refresh();
  }

  function toggleTokenVisibility() {
    if (!tokenInput || !btnToggleToken) return;
    if (tokenInput.type === "password") {
      tokenInput.type = "text";
      btnToggleToken.textContent = "Hide";
    } else {
      tokenInput.type = "password";
      btnToggleToken.textContent = "Show";
    }
  }

  // Setup DOM Event Listeners
  if (btnSetToken) btnSetToken.addEventListener("click", applyTokenFromInput);
  if (btnClearToken) btnClearToken.addEventListener("click", clearToken);
  if (btnToggleToken) btnToggleToken.addEventListener("click", toggleTokenVisibility);
  if (btnRefresh) btnRefresh.addEventListener("click", refresh);

  if (tokenInput) {
    tokenInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        applyTokenFromInput();
      }
    });
  }

  // Live UTC Clock
  function updateClock() {
    if (!clockEl) return;
    const now = new Date();
    clockEl.textContent = `UTC ${now.toISOString().substring(11, 19)}`;
  }
  updateClock();
  setInterval(updateClock, 1000);

  // Expose globally for debug or testing
  window.refreshMitreMatrix = refresh;
  window.loadIncidentDetails = loadIncidentDetails;
  window.focusIncidentBySignature = focusIncidentBySignature;

  // Initial fetch on page load
  refresh();

  // Periodic polling every 10 seconds
  setInterval(refresh, 10000);
})();
