(() => {
  "use strict";

  // Base API endpoint URL (empty string indicates origin root)
  const base = (window.SOC_API_BASE || "").replace(/\/$/, "");

  // =========================================================================
  // DOM Elements
  // =========================================================================

  // Top Bar & Global Layout
  const clockEl = document.getElementById("soc-clock");
  const pageBreadcrumbEl = document.getElementById("page-breadcrumb");
  const authStatusBadge = document.getElementById("auth-status-badge");
  const settingsAuthBadge = document.getElementById("settings-auth-badge");
  const sidebarAuthIndicator = document.getElementById("sidebar-auth-indicator");
  const unauthBanner = document.getElementById("unauth-banner");
  const btnBannerAuth = document.getElementById("btn-banner-auth");
  const btnQuickToken = document.getElementById("btn-quick-token");
  const btnRefresh = document.getElementById("btn-refresh");
  const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");
  const sidebarEl = document.querySelector(".soc-sidebar");

  // Nav Badges
  const sidebarAlertBadge = document.getElementById("sidebar-alert-badge");
  const sidebarIncBadge = document.getElementById("sidebar-inc-badge");
  const sidebarActionBadge = document.getElementById("sidebar-action-badge");

  // KPI Elements
  const statResilience = document.getElementById("stat-resilience");
  const statDetected = document.getElementById("stat-detected");
  const statMitigated = document.getElementById("stat-mitigated");
  const statTotal = document.getElementById("stat-total");

  // MITRE Matrix Elements
  const grid = document.getElementById("mitre-grid");
  const gridFull = document.getElementById("mitre-grid-full");
  const value = document.getElementById("resilience-value");
  const detail = document.getElementById("resilience-detail");
  const error = document.getElementById("mitre-error");

  // Alerts Page Elements
  const alertsGrid = document.getElementById("alerts-grid");
  const alertsSearchInput = document.getElementById("alerts-search-input");
  const alertsSigFilter = document.getElementById("alerts-sig-filter");
  const countSevAll = document.getElementById("count-sev-all");
  const btnToggleFocus = document.getElementById("btn-toggle-focus");
  const focusBtnLabel = document.getElementById("focus-btn-label");
  const btnRefreshAlerts = document.getElementById("btn-refresh-alerts");

  // Investigations Queue Elements
  const incidentsListEl = document.getElementById("incidents-list");
  const queueCountBadgeEl = document.getElementById("queue-count-badge");
  const filterAllBtn = document.getElementById("filter-all");
  const filterOpenBtn = document.getElementById("filter-open");
  const filterClosedBtn = document.getElementById("filter-closed");

  // Dedicated Incident Details Workbench Elements
  const detailsEmptyEl = document.getElementById("incident-details-empty");
  const detailsContentEl = document.getElementById("incident-details-content");
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

  // Summary KPI Cards in Incident Details
  const summaryAlertCount = document.getElementById("summary-alert-count");
  const summaryMitigatedCount = document.getElementById("summary-mitigated-count");
  const summaryStatusVal = document.getElementById("summary-status-val");
  const summaryActionCount = document.getElementById("summary-action-count");

  // Incident Navigation & Actions
  const btnBackToAlerts = document.getElementById("btn-back-to-alerts");
  const btnBackToInvestigations = document.getElementById("btn-back-to-investigations");
  const btnRefreshIncidentDetail = document.getElementById("btn-refresh-incident-detail");
  const btnEmptyGotoAlerts = document.getElementById("btn-empty-goto-alerts");
  const btnEmptyGotoIncidents = document.getElementById("btn-empty-goto-incidents");

  // Workflow Routine Transition Buttons
  const btnWfTriage = document.getElementById("btn-wf-triage");
  const btnWfInvestigating = document.getElementById("btn-wf-investigating");
  const btnWfToggleClassify = document.getElementById("btn-wf-toggle-classify");
  const btnWfRequestBlock = document.getElementById("btn-wf-request-block");
  const btnWfClose = document.getElementById("btn-wf-close");
  const btnSnapQuickContain = document.getElementById("btn-snap-quick-contain");
  const btnSnapCreateReport = document.getElementById("btn-snap-create-report");

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
  const btnCopyTelemetry = document.getElementById("btn-copy-telemetry");

  // Correlated Alerts Elements
  const correlatedCount = document.getElementById("correlated-count");
  const tabCorrelatedCount = document.getElementById("tab-correlated-count");
  const correlatedAlertsBody = document.getElementById("correlated-alerts-body");

  // Snapshot Elements
  const snapContainmentBadge = document.getElementById("snap-containment-badge");
  const snapEventCount = document.getElementById("snap-event-count");

  // Timeline & Notes Elements
  const timelineFeed = document.getElementById("timeline-feed");
  const analystNoteTextarea = document.getElementById("analyst-note-textarea");
  const btnAddNote = document.getElementById("btn-add-note");
  const incidentNotesFeed = document.getElementById("incident-notes-feed");
  const notesCountBadge = document.getElementById("notes-count-badge");
  const noteStatusMsg = document.getElementById("note-status-msg");

  // Response Actions Container
  const incidentActionsContainer = document.getElementById("incident-actions-container");

  // Reports Elements
  const reportForm = document.getElementById("report-form");
  const reportTitleInput = document.getElementById("report-title-input");
  const reportTypeSelect = document.getElementById("report-type-select");
  const reportIncidentSelect = document.getElementById("report-incident-select");
  const reportDateRangeSelect = document.getElementById("report-date-range-select");
  const reportSummaryInput = document.getElementById("report-summary-input");
  const reportFindingsInput = document.getElementById("report-findings-input");
  const btnPreviewReport = document.getElementById("btn-preview-report");
  const btnSubmitReport = document.getElementById("btn-submit-report");
  const btnPrintReport = document.getElementById("btn-print-report");
  const reportFeedbackMsg = document.getElementById("report-feedback-msg");
  const reportsHistoryBody = document.getElementById("reports-history-body");
  const btnRefreshReportsList = document.getElementById("btn-refresh-reports-list");

  // Live Report Preview Elements
  const prevTitle = document.getElementById("prev-title");
  const prevCategory = document.getElementById("prev-category");
  const prevDate = document.getElementById("prev-date");
  const prevIncidentTag = document.getElementById("prev-incident-tag");
  const prevClassification = document.getElementById("prev-classification");
  const prevSummary = document.getElementById("prev-summary");
  const prevFindings = document.getElementById("prev-findings");
  const prevSourceIp = document.getElementById("prev-source-ip");
  const prevMitre = document.getElementById("prev-mitre");
  const prevAlertCount = document.getElementById("prev-alert-count");
  const prevMitigationStatus = document.getElementById("prev-mitigation-status");

  // Settings & Authentication Elements
  const tokenInput = document.getElementById("analyst-token-input");
  const btnSetToken = document.getElementById("btn-set-token");
  const btnClearToken = document.getElementById("btn-clear-token");
  const btnToggleToken = document.getElementById("btn-toggle-token");
  const btnTestAuth = document.getElementById("btn-test-auth");

  // Modal Elements
  const modalQuickToken = document.getElementById("modal-quick-token");
  const modalTokenInput = document.getElementById("modal-token-input");
  const modalBtnSaveToken = document.getElementById("modal-btn-save-token");
  const modalBtnClearToken = document.getElementById("modal-btn-clear-token");
  const modalCloseToken = document.getElementById("modal-close-token");

  // Global Toast Container
  const toastContainer = document.getElementById("toast-container");

  // =========================================================================
  // State
  // =========================================================================
  let allAlerts = [];
  let allIncidents = [];
  let allResponseActions = [];
  let allReports = [];
  let selectedIncidentId = null;
  let currentIncidentData = null;
  let isSubmittingAction = false;
  let isGlobalRefreshing = false;
  let currentView = "dashboard";
  let alertSeverityFilter = "ALL";
  let alertSignatureFilter = "ALL";
  let alertSearchQuery = "";
  let focusMode = false;
  let incidentStatusFilter = "ALL";

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

  // Helper DOM creator
  function node(tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined && text !== null) el.textContent = text;
    return el;
  }

  // =========================================================================
  // Toast & Notifications
  // =========================================================================
  function showToast(message, type = "info", duration = 3500) {
    if (!toastContainer) return;
    const toast = node("div", `toast toast-${type}`);
    const icon = type === "success" ? "✓" : (type === "error" ? "✕" : "ℹ");
    toast.innerHTML = `<span style="font-weight:700;margin-right:6px;">${icon}</span><span>${message}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  // =========================================================================
  // Authentication & API Request Handler
  // =========================================================================
  function updateAuthBadge(state, message) {
    const badgeMap = [
      { el: authStatusBadge, defaultText: "● Token Not Set" },
      { el: settingsAuthBadge, defaultText: "● Token Not Set" }
    ];

    badgeMap.forEach(({ el, defaultText }) => {
      if (!el) return;
      el.className = "auth-badge";
      if (state === "authenticated") {
        el.classList.add("status-authenticated");
        el.textContent = "● Authenticated";
        el.title = message || "Valid analyst token verified";
      } else if (state === "checking") {
        el.classList.add("status-checking");
        el.textContent = "● Verifying...";
        el.title = "Connecting to backend...";
      } else if (state === "error") {
        el.classList.add("status-error");
        el.textContent = "● Unauthorized (401)";
        el.title = message || "Invalid or rejected analyst token";
      } else {
        el.classList.add("status-unauthenticated");
        el.textContent = defaultText;
        el.title = "Enter ANALYST_TOKEN to access API";
      }
    });

    if (sidebarAuthIndicator) {
      if (state === "authenticated") {
        sidebarAuthIndicator.textContent = "Authenticated";
        sidebarAuthIndicator.className = "session-status status-dot-online";
      } else {
        sidebarAuthIndicator.textContent = state === "error" ? "Auth Failed" : "Token Not Set";
        sidebarAuthIndicator.className = "session-status status-dot-offline";
      }
    }

    if (unauthBanner) {
      unauthBanner.hidden = (state === "authenticated");
    }
  }

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
        serverErrorMsg = errJson.error || errJson.message || "";
      } catch {
        serverErrorMsg = response.statusText;
      }
      const err = new Error(serverErrorMsg || `HTTP ${response.status}`);
      err.status = response.status;
      throw err;
    }

    return response.json();
  }

  // =========================================================================
  // Single-Page View Router
  // =========================================================================
  function switchView(targetView, param = null) {
    currentView = targetView;

    // Hide all view sections
    const views = document.querySelectorAll(".soc-view");
    views.forEach(v => {
      v.hidden = true;
      v.classList.remove("active");
    });

    // Update active nav link
    const navLinks = document.querySelectorAll(".nav-link");
    navLinks.forEach(nl => nl.classList.remove("active"));

    const matchingNav = document.getElementById(`nav-${targetView}`);
    if (matchingNav) matchingNav.classList.add("active");

    // Show target view section
    const targetSection = document.getElementById(`view-${targetView}`);
    if (targetSection) {
      targetSection.hidden = false;
      targetSection.classList.add("active");
    }

    // Update Breadcrumb
    const breadcrumbTitles = {
      dashboard: "Dashboard",
      alerts: "Alerts",
      investigations: "Incident Investigations",
      "incident-detail": param ? `Incident #${param}` : "Incident Workbench",
      trends: "Threat Intelligence & Trends",
      mitre: "MITRE ATT&CK Matrix",
      actions: "SOAR Response Actions",
      reports: "Security Reports",
      settings: "System Settings"
    };

    if (pageBreadcrumbEl) {
      pageBreadcrumbEl.textContent = breadcrumbTitles[targetView] || targetView.toUpperCase();
    }

    // Hash handling
    let newHash = targetView;
    if (targetView === "incident-detail" && param) {
      newHash = `incident/${param}`;
    }
    if (window.location.hash.replace("#", "") !== newHash) {
      window.location.hash = newHash;
    }

    // View-specific initialization triggers
    if (targetView === "incident-detail" && param) {
      selectedIncidentId = parseInt(param, 10);
      loadIncidentDetails(selectedIncidentId, true);
    } else if (targetView === "alerts") {
      fetchAlerts();
    } else if (targetView === "investigations") {
      fetchIncidents();
    } else if (targetView === "reports") {
      fetchReports();
      populateReportIncidentSelect();
      updateReportPreview();
    } else if (targetView === "trends") {
      renderTrends();
    } else if (targetView === "actions") {
      renderAllActionsTable();
    }

    // Close mobile sidebar if open
    if (sidebarEl && sidebarEl.classList.contains("open")) {
      sidebarEl.classList.remove("open");
    }

    // Scroll to top
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function handleHashChange() {
    const rawHash = (window.location.hash || "").replace(/^#\/?/, "");
    if (!rawHash || rawHash === "dashboard") {
      switchView("dashboard");
    } else if (rawHash.startsWith("incident/")) {
      const incId = rawHash.split("/")[1];
      switchView("incident-detail", incId);
    } else if (rawHash === "alerts") {
      switchView("alerts");
    } else if (rawHash === "investigations") {
      switchView("investigations");
    } else if (rawHash === "trends") {
      switchView("trends");
    } else if (rawHash === "mitre") {
      switchView("mitre");
    } else if (rawHash === "actions") {
      switchView("actions");
    } else if (rawHash === "reports") {
      switchView("reports");
    } else if (rawHash === "settings") {
      switchView("settings");
    } else {
      switchView("dashboard");
    }
  }

  window.addEventListener("hashchange", handleHashChange);

  // =========================================================================
  // Severity & Status Badge Helpers
  // =========================================================================
  function getSeverityClass(sev) {
    switch (String(sev || "").toLowerCase().trim()) {
      case "critical": return "badge-critical";
      case "high": return "badge-high";
      case "medium": return "badge-medium";
      case "low": return "badge-low";
      case "info": return "badge-info";
      default: return "badge-neutral";
    }
  }

  function getStatusBadgeClass(status) {
    const s = String(status || "").toUpperCase().trim().replace(/ /g, "_");
    switch (s) {
      case "NEW": return "badge-neutral";
      case "TRIAGE": return "badge-amber";
      case "INVESTIGATING": return "badge-purple";
      case "CLASSIFIED": return "badge-purple";
      case "RESPONSE_REQUESTED": return "badge-amber";
      case "CONTAINMENT_PENDING_APPROVAL": return "badge-amber";
      case "CONTAINED": return "badge-verified";
      case "CLOSED": return "badge-neutral";
      case "APPROVED": return "badge-purple";
      case "EXECUTED": return "badge-cyan";
      case "PENDING": return "badge-amber";
      // 6 Core Defensive Lifecycle States
      case "DETECTED": return "badge-amber";
      case "MITIGATION_APPLIED": return "badge-cyan";
      case "VERIFICATION_PENDING": return "badge-purple";
      case "VERIFIED":
      case "MITIGATED": return "badge-verified";
      case "VERIFICATION_FAILED": return "badge-red";
      case "EXPIRED": return "badge-slate";
      case "UNTESTED": return "badge-neutral";
      default: return "badge-neutral";
    }
  }

  function getMitreStateCardClass(state) {
    const s = String(state || "").toUpperCase().trim().replace(/ /g, "_");
    switch (s) {
      case "MITIGATED":
      case "VERIFIED":
        return "state-green";
      case "DETECTED":
        return "state-amber";
      case "MITIGATION_APPLIED":
        return "state-cyan";
      case "VERIFICATION_PENDING":
        return "state-purple";
      case "VERIFICATION_FAILED":
        return "state-red";
      case "EXPIRED":
        return "state-slate";
      default:
        return "state-gray";
    }
  }

  function formatCountdown(seconds) {
    if (seconds === null || seconds === undefined || seconds === "") return "N/A";
    const sec = Number(seconds);
    if (isNaN(sec)) return "N/A";
    if (sec <= 0) return "Expired";
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return `${m}m ${s < 10 ? '0' : ''}${s}s`;
  }

  function parseIsoTimestamp(ts) {
    if (!ts) return null;
    if (typeof ts === "number") return isNaN(ts) ? null : ts;
    let str = String(ts).trim();
    if (!str || str === "N/A" || str === "None" || str === "null" || str === "undefined") {
      return null;
    }
    // Handle double-suffix such as +00:00Z by removing trailing Z
    if (/[+-]\d{2}:?\d{2}Z$/i.test(str)) {
      str = str.slice(0, -1);
    }
    let d = new Date(str);
    if (!isNaN(d.getTime())) return d.getTime();
    if (!str.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(str)) {
      d = new Date(str.replace(" ", "T") + "Z");
      if (!isNaN(d.getTime())) return d.getTime();
    } else {
      d = new Date(str.replace(" ", "T"));
      if (!isNaN(d.getTime())) return d.getTime();
    }
    return null;
  }

  function getRelativeTime(timestamp) {
    if (!timestamp) return "Unknown";
    try {
      const ms = parseIsoTimestamp(timestamp);
      if (ms === null || isNaN(ms)) return timestamp;
      const diffSec = Math.floor((Date.now() - ms) / 1000);
      if (diffSec < 60) return "Just now";
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch {
      return timestamp;
    }
  }

  // =========================================================================
  // ALERTS PAGE: Card-Based Responsive Grid & Filtering
  // =========================================================================
  async function fetchAlerts() {
    if (!alertsGrid) return;
    try {
      const data = await api("/api/soc/alerts?limit=200");
      allAlerts = data.alerts || [];
    } catch {
      // Fallback: build alert collection from incidents if /api/soc/alerts fails or token expired
      allAlerts = [];
      allIncidents.forEach(inc => {
        if (inc.correlated_alerts) {
          allAlerts.push(...inc.correlated_alerts);
        }
      });
    }

    if (sidebarAlertBadge) {
      sidebarAlertBadge.textContent = allAlerts.length;
    }
    if (countSevAll) {
      countSevAll.textContent = allAlerts.length;
    }

    renderAlertsGrid();
  }

  function renderAlertsGrid() {
    if (!alertsGrid) return;
    alertsGrid.replaceChildren();

    const filtered = allAlerts.filter(a => {
      // Severity filter
      if (alertSeverityFilter !== "ALL" && String(a.severity).toUpperCase() !== alertSeverityFilter) {
        return false;
      }
      // Signature filter
      if (alertSignatureFilter !== "ALL" && a.signature !== alertSignatureFilter) {
        return false;
      }
      // Search query
      if (alertSearchQuery) {
        const q = alertSearchQuery.toLowerCase();
        const matchIp = (a.source_ip || "").toLowerCase().includes(q);
        const matchSig = (a.signature || "").toLowerCase().includes(q);
        const matchMsg = (a.message || "").toLowerCase().includes(q);
        const matchTech = (a.technique_name || "").toLowerCase().includes(q);
        const matchPath = (a.requested_path || "").toLowerCase().includes(q);
        if (!matchIp && !matchSig && !matchMsg && !matchTech && !matchPath) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      alertsGrid.innerHTML = `
        <div class="empty-state-card" style="grid-column: span 2; padding: 40px; text-align: center;">
          <p class="muted">No alerts match the selected filters or query.</p>
        </div>
      `;
      return;
    }

    for (const alert of filtered) {
      const card = node("article", `alert-item-card${focusMode ? " focus-compact" : ""}`);
      card.setAttribute("data-event-id", alert.event_id || "");

      // Top Row: Severity, Source, Relative Time
      const top = node("div", "alert-card-header");
      const leftTop = node("div", "d-flex align-center gap-8");
      leftTop.style.display = "flex";
      leftTop.style.alignItems = "center";
      leftTop.style.gap = "8px";
      leftTop.append(node("span", `badge ${getSeverityClass(alert.severity)}`, String(alert.severity || "medium").toUpperCase()));
      leftTop.append(node("span", "alert-source-type", alert.signature || "SUSPICIOUS"));
      top.append(leftTop);

      const timeSpan = node("span", "alert-time-relative", getRelativeTime(alert.timestamp));
      timeSpan.title = `UTC: ${alert.timestamp}`;
      top.append(timeSpan);
      card.append(top);

      // Alert Title
      const title = alert.technique_name ? `${alert.technique_name} from ${alert.source_ip}` : (alert.message || "Security Telemetry Alert");
      card.append(node("h3", "alert-title", title));

      // Description / Message
      if (!focusMode && alert.message) {
        card.append(node("p", "alert-desc", alert.message));
      }

      // Metadata Chips (IP, HTTP Method, Path, Status)
      const chips = node("div", "alert-meta-chips");
      const ipChip = node("span", "meta-chip meta-chip-ip mono-text", `IP: ${alert.source_ip}`);
      chips.append(ipChip);

      if (alert.http_method) {
        chips.append(node("span", "meta-chip mono-text", alert.http_method));
      }
      if (alert.requested_path) {
        chips.append(node("span", "meta-chip mono-text", alert.requested_path));
      }
      if (alert.response_status) {
        chips.append(node("span", "meta-chip mono-text", `HTTP ${alert.response_status}`));
      }
      if (alert.mitre_id) {
        chips.append(node("span", "meta-chip", `${alert.mitre_id} (${alert.tactic || "Adversary Tactic"})`));
      }
      card.append(chips);

      // Footer: Incident Status & Primary Action Button
      const footer = node("div", "alert-card-footer");
      const incInfo = node("span", "alert-inc-status");
      if (alert.incident_id) {
        incInfo.innerHTML = `Correlated: <strong style="color:#c7d2fe;">#INC-${alert.incident_id}</strong> ${alert.incident_status ? `(${alert.incident_status})` : ""}`;
      } else {
        incInfo.textContent = "Uncorrelated alert";
      }
      footer.append(incInfo);

      const actionCluster = node("div", "alert-action-cluster");

      // Copy IP action
      const copyBtn = node("button", "btn btn-outline btn-xs", "Copy IP");
      copyBtn.type = "button";
      copyBtn.title = "Copy Source IP to clipboard";
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(alert.source_ip).then(() => showToast(`Copied ${alert.source_ip} to clipboard`, "info"));
      });
      actionCluster.append(copyBtn);

      // Primary "Investigate / View Details" Action Button
      const invBtn = node("button", "btn btn-primary btn-sm", "Investigate");
      invBtn.type = "button";
      invBtn.title = alert.incident_id ? `Open dedicated dossier for Incident #${alert.incident_id}` : "Investigate correlated incidents";
      invBtn.addEventListener("click", () => {
        if (alert.incident_id) {
          switchView("incident-detail", alert.incident_id);
        } else {
          // If no linked incident, find by source_ip or signature
          const match = allIncidents.find(i => i.source_ip === alert.source_ip) ||
                        allIncidents.find(i => i.signature === alert.signature);
          if (match) {
            switchView("incident-detail", match.incident_id);
          } else {
            switchView("investigations");
          }
        }
      });
      actionCluster.append(invBtn);

      footer.append(actionCluster);
      card.append(footer);

      alertsGrid.append(card);
    }
  }

  // =========================================================================
  // INVESTIGATIONS: Incidents Queue & Dashboard Cards
  // =========================================================================
  async function fetchIncidents() {
    try {
      const data = await api("/api/soc/incidents");
      allIncidents = data.incidents || [];
      if (queueCountBadgeEl) {
        queueCountBadgeEl.textContent = `${allIncidents.length} Incident${allIncidents.length === 1 ? "" : "s"}`;
      }
      if (sidebarIncBadge) {
        sidebarIncBadge.textContent = allIncidents.length;
      }
      renderIncidentsQueue();
      renderDashboardRecent();
    } catch (e) {
      if (incidentsListEl) {
        incidentsListEl.innerHTML = `<p class="muted p-queue-empty">Unable to load incidents: ${e.message}</p>`;
      }
    }
  }

  function renderIncidentsQueue() {
    if (!incidentsListEl) return;
    incidentsListEl.replaceChildren();

    const filtered = allIncidents.filter(inc => {
      if (incidentStatusFilter === "OPEN") return inc.status !== "CLOSED";
      if (incidentStatusFilter === "CLOSED") return inc.status === "CLOSED";
      return true;
    });

    if (filtered.length === 0) {
      incidentsListEl.innerHTML = '<p class="muted p-queue-empty">No incidents match the selected filter.</p>';
      return;
    }

    for (const inc of filtered) {
      const card = node("div", "incident-item-card");
      card.style.background = "var(--bg-card)";
      card.style.border = "1px solid var(--border-card)";
      card.style.borderRadius = "var(--radius-lg)";
      card.style.padding = "18px";
      card.style.display = "flex";
      card.style.flexDirection = "column";
      card.style.gap = "10px";

      const top = node("div", "d-flex justify-between align-center");
      top.style.display = "flex";
      top.style.justifyContent = "space-between";
      top.style.alignItems = "center";

      const idBadge = node("span", "incident-id-tag", `#INC-${inc.incident_id}`);
      const badges = node("div", "header-badge-cluster");
      badges.append(node("span", `badge ${getSeverityClass(inc.severity)}`, String(inc.severity || "MEDIUM").toUpperCase()));
      badges.append(node("span", `badge ${getStatusBadgeClass(inc.status)}`, inc.status));
      top.append(idBadge, badges);
      card.append(top);

      card.append(node("h3", "alert-title", inc.title || `Incident from ${inc.source_ip}`));

      const meta = node("div", "alert-meta-chips");
      meta.append(node("span", "meta-chip meta-chip-ip mono-text", `Target: ${inc.source_ip}`));
      meta.append(node("span", "meta-chip", `${inc.alert_count} Correlated Alert${inc.alert_count === 1 ? "" : "s"}`));
      meta.append(node("span", "meta-chip mono-text", `Created: ${inc.created_at || "N/A"}`));
      card.append(meta);

      const btm = node("div", "d-flex justify-between align-center");
      btm.style.display = "flex";
      btm.style.justifyContent = "space-between";
      btm.style.alignItems = "center";
      btm.style.marginTop = "auto";
      btm.style.paddingTop = "8px";
      btm.style.borderTop = "1px solid rgba(255,255,255,0.05)";

      const tech = node("span", "text-xs muted", `${inc.technique_name || "Unknown"} (${inc.technique_id || "N/A"})`);
      const openBtn = node("button", "btn btn-primary btn-sm", "Open Dedicated Workbench →");
      openBtn.type = "button";
      openBtn.addEventListener("click", () => switchView("incident-detail", inc.incident_id));

      btm.append(tech, openBtn);
      card.append(btm);

      incidentsListEl.append(card);
    }
  }

  function renderDashboardRecent() {
    const dashActiveInc = document.getElementById("dash-active-incidents");
    const dashRecentAlerts = document.getElementById("dash-recent-alerts");

    if (dashActiveInc) {
      dashActiveInc.replaceChildren();
      const openInc = allIncidents.filter(i => i.status !== "CLOSED").slice(0, 5);
      if (openInc.length === 0) {
        dashActiveInc.innerHTML = '<p class="muted p-empty">No active security incidents currently open.</p>';
      } else {
        openInc.forEach(inc => {
          const item = node("div", "dash-item-row");
          item.style.display = "flex";
          item.style.alignItems = "center";
          item.style.justifyContent = "space-between";
          item.style.padding = "8px 10px";
          item.style.background = "rgba(0,0,0,0.2)";
          item.style.borderRadius = "var(--radius-sm)";
          item.style.marginBottom = "6px";

          const left = node("div", "d-flex align-center gap-8");
          left.style.display = "flex";
          left.style.alignItems = "center";
          left.style.gap = "8px";
          left.append(node("span", "incident-id-tag", `#INC-${inc.incident_id}`));
          left.append(node("span", "mono-text text-sm", inc.source_ip));

          const right = node("div", "d-flex align-center gap-8");
          right.style.display = "flex";
          right.style.alignItems = "center";
          right.style.gap = "8px";
          right.append(node("span", `badge ${getSeverityClass(inc.severity)}`, String(inc.severity || "medium").toUpperCase()));

          const btn = node("button", "btn btn-outline btn-xs", "Inspect");
          btn.type = "button";
          btn.addEventListener("click", () => switchView("incident-detail", inc.incident_id));
          right.append(btn);

          item.append(left, right);
          dashActiveInc.append(item);
        });
      }
    }

    if (dashRecentAlerts) {
      dashRecentAlerts.replaceChildren();
      const recent = allAlerts.slice(0, 5);
      if (recent.length === 0) {
        dashRecentAlerts.innerHTML = '<p class="muted p-empty">No telemetry alerts ingested yet.</p>';
      } else {
        recent.forEach(alt => {
          const item = node("div", "dash-item-row");
          item.style.display = "flex";
          item.style.alignItems = "center";
          item.style.justifyContent = "space-between";
          item.style.padding = "8px 10px";
          item.style.background = "rgba(0,0,0,0.2)";
          item.style.borderRadius = "var(--radius-sm)";
          item.style.marginBottom = "6px";

          const left = node("div", "d-flex align-center gap-8");
          left.style.display = "flex";
          left.style.alignItems = "center";
          left.style.gap = "8px";
          left.append(node("span", `badge ${getSeverityClass(alt.severity)}`, String(alt.severity || "medium").toUpperCase()));
          left.append(node("span", "mono-text text-sm", alt.source_ip));
          left.append(node("span", "text-xs muted", alt.signature));

          const right = node("span", "text-xs muted", getRelativeTime(alt.timestamp));
          item.append(left, right);
          dashRecentAlerts.append(item);
        });
      }
    }
  }

  // =========================================================================
  // DEDICATED INCIDENT INVESTIGATION WORKBENCH
  // =========================================================================
  async function loadIncidentDetails(incidentId, scrollIntoView = false) {
    if (!incidentId) return;

    try {
      const data = await api(`/api/soc/incidents/${incidentId}`);
      const inc = data.incident;
      currentIncidentData = inc;
      const alerts = data.alerts || [];
      const actions = data.response_actions || [];
      const timeline = data.timeline || [];
      const notes = data.notes || [];

      // A. Populate Header
      if (detailIncidentId) detailIncidentId.textContent = `#INC-${inc.incident_id}`;
      if (detailIncidentTitle) detailIncidentTitle.textContent = inc.title || "Security Incident";

      if (detailSeverityBadge) {
        detailSeverityBadge.className = `badge ${getSeverityClass(inc.severity)}`;
        detailSeverityBadge.textContent = String(inc.severity || "MEDIUM").toUpperCase();
      }

        if (detailStatusBadge) {
          detailStatusBadge.className = `badge ${getStatusBadgeClass(inc.status)}`;
          detailStatusBadge.textContent = inc.status;
        }

        const detailDefenseBadge = document.getElementById("detail-defense-status-badge");
        if (detailDefenseBadge) {
          detailDefenseBadge.className = `badge ${getStatusBadgeClass(inc.defense_status || "DETECTED")}`;
          detailDefenseBadge.textContent = (inc.defense_status || "DETECTED").toUpperCase();
        }

        if (detailClassBadge) {
          if (inc.classification) {
            detailClassBadge.hidden = false;
            detailClassBadge.className = `badge ${inc.classification === "CONFIRMED_MALICIOUS" ? "badge-critical" : "badge-neutral"}`;
            detailClassBadge.textContent = inc.classification.replace(/_/g, " ");
          } else {
            detailClassBadge.hidden = true;
          }
        }

        if (detailSourceIp) detailSourceIp.textContent = inc.source_ip || "Not available";

        const detailDestStr = document.getElementById("detail-destination-str");
        if (detailDestStr) {
          const firstA = alerts[0] || {};
          const dst = firstA.destination_ip || "Perimeter";
          const dport = firstA.destination_port ? `:${firstA.destination_port}` : "";
          const proto = firstA.protocol || "TCP";
          detailDestStr.textContent = `${dst}${dport} · ${proto}`;
        }

        const detailExpiryStr = document.getElementById("detail-expiry-str");
        if (detailExpiryStr) {
          const activeTemp = (inc.active_temporary_controls && inc.active_temporary_controls.length > 0) ? inc.active_temporary_controls[0] : null;
          if (activeTemp) {
            detailExpiryStr.textContent = `Active (${Math.max(0, activeTemp.time_remaining_seconds || 0)}s remaining)`;
          } else if (actions.some(a => a.status === "EXPIRED" || a.is_expired)) {
            detailExpiryStr.textContent = "Expired";
          } else {
            detailExpiryStr.textContent = "None / Permanent";
          }
        }

        if (detailTechniqueStr) detailTechniqueStr.textContent = `${inc.technique_name || "Unknown"} (${inc.technique_id || "N/A"}) · ${inc.signature || "N/A"}`;
        if (detailCreatedAt) detailCreatedAt.textContent = inc.created_at || "Not available";
        if (detailUpdatedAt) detailUpdatedAt.textContent = inc.updated_at || "Not available";

        // Closure Banner
        if (detailClosureInfo) {
          if (inc.status === "CLOSED") {
            detailClosureInfo.hidden = false;
            const isVer = inc.defense_status === "Verified";
            detailClosureInfo.className = `closure-banner ${isVer ? "closure-verified" : "closure-unverified"}`;
            const iconEl = detailClosureInfo.querySelector(".closure-icon");
            if (iconEl) iconEl.textContent = isVer ? "✓" : "ℹ️";
            const strongEl = detailClosureInfo.querySelector("strong");
            if (strongEl) {
              strongEl.textContent = isVer ? "Incident Resolved & Verified:" : "Incident Closed (Workflow Resolution — Containment Unverified):";
            }
            if (detailClosedAt) detailClosedAt.textContent = inc.closed_at || "Not recorded";
            if (detailClosedRationale) detailClosedRationale.textContent = inc.closure_rationale || "No rationale provided";
          } else {
            detailClosureInfo.hidden = true;
          }
        }

        // B. Populate Summary KPI Cards
        if (summaryAlertCount) summaryAlertCount.textContent = alerts.length;

        const summaryDefVal = document.getElementById("summary-defense-status-val");
        const summaryDefSub = document.getElementById("summary-defense-sub");
        if (summaryDefVal) {
          summaryDefVal.textContent = (inc.defense_status || "DETECTED").toUpperCase();
          summaryDefVal.className = `inc-kpi-val status-kpi-text ${getStatusBadgeClass(inc.defense_status || "DETECTED")}`;
        }
        if (summaryDefSub) {
          summaryDefSub.textContent = `Lifecycle: ${inc.defense_status || "Detected"}`;
        }

        if (summaryMitigatedCount) {
          const verifiedMitigations = actions.filter(a => a.status === "VERIFIED" && !a.is_expired).length;
          summaryMitigatedCount.textContent = verifiedMitigations;
        }
        if (summaryStatusVal) summaryStatusVal.textContent = inc.status || "NEW";
        if (summaryActionCount) summaryActionCount.textContent = actions.length;

        // C. Update 8-Stage Workflow Stepper
        updateWorkflowStepper(inc.status, inc.defense_status, actions);

        // Snapshot Quick Items
        if (snapEventCount) snapEventCount.textContent = alerts.length;
        if (snapContainmentBadge) {
          const latestAct = actions.length > 0 ? actions[0] : null;
          if (latestAct) {
            snapContainmentBadge.className = `badge ${getStatusBadgeClass(latestAct.defense_status || latestAct.status)}`;
            snapContainmentBadge.textContent = `${latestAct.action_type}: ${latestAct.defense_status || latestAct.status}`;
          } else {
            snapContainmentBadge.className = "badge badge-neutral";
            snapContainmentBadge.textContent = "NONE QUEUED";
          }
        }

        // D. Populate Overview & Evidence Pane
        if (evTechId) evTechId.textContent = inc.technique_id || "Not available";
        if (evTechName) evTechName.textContent = inc.technique_name || "Not available";
        if (evTactic) evTactic.textContent = inc.tactic || "Not available";
        if (evSignature) evSignature.textContent = inc.signature || "Not available";

        const evDestInfo = document.getElementById("ev-destination-info");
        const evProtoInfo = document.getElementById("ev-protocol-info");
        const evStructuredMeta = document.getElementById("ev-structured-metadata");
        const evMetaCount = document.getElementById("ev-meta-count");

        const firstAlert = alerts[0] || {};
        if (evDestInfo) {
          const dst = firstAlert.destination_ip || "Perimeter";
          const dport = firstAlert.destination_port ? `:${firstAlert.destination_port}` : "";
          evDestInfo.textContent = `${dst}${dport}`;
        }
        if (evProtoInfo) {
          evProtoInfo.textContent = firstAlert.protocol || "TCP";
        }
        if (evStructuredMeta) {
          let metaObj = firstAlert.metadata;
          if (!metaObj && firstAlert.metadata_json) {
            try { metaObj = JSON.parse(firstAlert.metadata_json); } catch {}
          }
          if (metaObj && typeof metaObj === "object" && Object.keys(metaObj).length > 0) {
            evStructuredMeta.textContent = JSON.stringify(metaObj, null, 2);
            if (evMetaCount) evMetaCount.textContent = `${Object.keys(metaObj).length} parameter(s)`;
          } else {
            evStructuredMeta.textContent = "No extra detection parameters recorded for this event.";
            if (evMetaCount) evMetaCount.textContent = "0 attributes";
          }
        }

        if (evMessage) {
          const latestMsg = alerts.length > 0 ? (alerts[0].message || "No telemetry message") : "Not available";
          evMessage.textContent = latestMsg;
        }

        // Populate Attack-Specific Response Policy Card & Dynamic Actions
        const incPolicyCard = document.getElementById("inc-policy-card");
        const incPolicyStatusPill = document.getElementById("inc-policy-status-pill");
        const incPolicySig = document.getElementById("inc-policy-sig");
        const incPolicyAttackType = document.getElementById("inc-policy-attack-type");
        const incPolicyResponse = document.getElementById("inc-policy-response");
        const incPolicyDuration = document.getElementById("inc-policy-duration");
        const incPolicyVerification = document.getElementById("inc-policy-verification");
        const incPolicyDescription = document.getElementById("inc-policy-description");

        const policy = inc.response_policy;
        if (policy && incPolicyCard) {
          incPolicyCard.hidden = false;
          if (incPolicySig) incPolicySig.textContent = policy.signature || inc.signature || "N/A";
          if (incPolicyAttackType) incPolicyAttackType.textContent = policy.attack_type || "Attack Vector";
          if (incPolicyResponse) incPolicyResponse.textContent = policy.selected_response || "LOG_MONITOR";
          if (incPolicyDuration) {
            incPolicyDuration.textContent = policy.duration_seconds
              ? `${policy.duration_seconds}s (${Math.round(policy.duration_seconds / 60)} min)`
              : "Immediate / Transactional";
          }
          if (incPolicyVerification) incPolicyVerification.textContent = policy.verification_method || "N/A";
          if (incPolicyDescription) incPolicyDescription.textContent = policy.description || "N/A";
          if (incPolicyStatusPill) {
            if (policy.is_supported) {
              incPolicyStatusPill.className = "badge badge-verified";
              incPolicyStatusPill.textContent = "SUPPORTED ENFORCEMENT";
            } else {
              incPolicyStatusPill.className = "badge badge-purple";
              incPolicyStatusPill.textContent = "APP-LAYER PROTECTION (PENDING IMPLEMENTATION)";
            }
          }
        }

        // Dynamically update containment action button text and tooltips
        if (btnWfRequestBlock) {
          if (policy && !policy.is_supported) {
            btnWfRequestBlock.textContent = `Apply Policy (${policy.selected_response})`;
            btnWfRequestBlock.title = `Apply ${policy.selected_response} policy (Application-layer protection — pending instrumentation)`;
          } else if (policy && policy.is_supported) {
            const durMin = policy.duration_seconds ? ` (${Math.round(policy.duration_seconds / 60)}m)` : "";
            btnWfRequestBlock.textContent = `Request ${policy.selected_response}${durMin}`;
            btnWfRequestBlock.title = `Queue supported host containment: ${policy.selected_response}`;
          } else {
            btnWfRequestBlock.textContent = "Request Containment";
            btnWfRequestBlock.title = "Queue SOAR Containment Block";
          }
        }
        if (btnSnapQuickContain) {
          if (policy && !policy.is_supported) {
            btnSnapQuickContain.textContent = `⚡ Policy: ${policy.selected_response}`;
          } else if (policy && policy.is_supported) {
            btnSnapQuickContain.textContent = `⚡ Contain: ${policy.selected_response}`;
          }
        }

      // E. Populate Correlated Alerts Table
      if (correlatedCount) correlatedCount.textContent = alerts.length;
      if (tabCorrelatedCount) tabCorrelatedCount.textContent = alerts.length;

      if (correlatedAlertsBody) {
        correlatedAlertsBody.replaceChildren();
        if (alerts.length === 0) {
          const tr = node("tr");
          const td = node("td", "text-center muted", "No alerts correlated");
          td.colSpan = 5;
          tr.append(td);
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
            tr.append(node("td", "mono-text text-xs", a.message || "—"));
            correlatedAlertsBody.append(tr);
          }
        }
      }

      // F. Populate Chronological Timeline Feed
      if (timelineFeed) {
        timelineFeed.replaceChildren();
        if (timeline.length === 0) {
          timelineFeed.innerHTML = '<p class="muted p-empty-timeline">No timeline events recorded yet.</p>';
        } else {
          for (const t of timeline) {
            const entry = node("div", `timeline-entry t-${String(t.type || "").toLowerCase()}`);
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

      // G. Populate Analyst Notes Feed
      if (incidentNotesFeed) {
        incidentNotesFeed.replaceChildren();
        const analystNotesOnly = notes.filter(n => n.note_type === "ANALYST_NOTE");
        if (notesCountBadge) notesCountBadge.textContent = `${analystNotesOnly.length} note${analystNotesOnly.length === 1 ? "" : "s"}`;

        if (analystNotesOnly.length === 0) {
          incidentNotesFeed.innerHTML = '<p class="muted p-empty-notes">No analyst investigation notes recorded yet. Use the form on the left to add findings.</p>';
        } else {
          analystNotesOnly.forEach(n => {
            const noteCard = node("div", "note-entry-card");
            const head = node("div", "note-entry-header");
            head.append(node("span", "note-author", n.author || "SOC_ANALYST"));
            head.append(node("span", "note-time mono-text", n.created_at || ""));
            noteCard.append(head);
            noteCard.append(node("div", "note-content-text", n.note_text || n.note || ""));
            incidentNotesFeed.append(noteCard);
          });
        }
      }

      // H. Populate Response Actions History & Containment Console
      if (incidentActionsContainer) {
        // Active Temporary Control Timer Banner in Incident Pane
        const incActiveBanner = document.getElementById("inc-active-control-banner");
        const incTempActId = document.getElementById("inc-temp-act-id");
        const incTempTargetIp = document.getElementById("inc-temp-target-ip");
        const incTempCountdown = document.getElementById("inc-temp-countdown");
        const incTempExpiryAt = document.getElementById("inc-temp-expiry-at");

        const activeTemp = (inc.active_temporary_controls && inc.active_temporary_controls.length > 0) ? inc.active_temporary_controls[0] : null;
        if (activeTemp && incActiveBanner) {
          incActiveBanner.hidden = false;
          if (incTempActId) incTempActId.textContent = activeTemp.action_id;
          if (incTempTargetIp) incTempTargetIp.textContent = activeTemp.target_ip;
          if (incTempCountdown) {
            incTempCountdown.setAttribute("data-expires-at", activeTemp.expires_at || "");
            incTempCountdown.textContent = `${formatCountdown(activeTemp.time_remaining_seconds || 0)} remaining`;
          }
          if (incTempExpiryAt) incTempExpiryAt.textContent = `Expires at: ${activeTemp.expires_at || "N/A"}`;
        } else if (incActiveBanner) {
          incActiveBanner.hidden = true;
        }

        // Verification Evidence Box in Incident Pane
        const incVerBox = document.getElementById("inc-verification-evidence-box");
        const incEvidenceRaw = document.getElementById("inc-evidence-raw");
        const incVerifiedAtTag = document.getElementById("inc-verified-at-tag");
        const incEvidencePill = document.getElementById("inc-evidence-status-pill");

        const verifiedAction = actions.find(a => (a.status === "VERIFIED" || a.defense_status === "Verified") && a.verification_evidence);
        const failedAction = actions.find(a => (a.status === "VERIFICATION_FAILED" || a.defense_status === "Verification Failed") && a.message);

        if (verifiedAction && incVerBox && incEvidenceRaw) {
          incVerBox.hidden = false;
          incVerBox.style.background = "rgba(16, 185, 129, 0.08)";
          incVerBox.style.borderColor = "rgba(16, 185, 129, 0.3)";
          if (incEvidencePill) {
            incEvidencePill.className = "badge badge-verified";
            incEvidencePill.textContent = "VERIFIED";
          }
          if (incVerifiedAtTag) incVerifiedAtTag.textContent = `Verified at: ${verifiedAction.verified_at || verifiedAction.created_at || "N/A"}`;
          let evDisplay = verifiedAction.verification_evidence;
          try {
            const parsed = JSON.parse(evDisplay);
            evDisplay = JSON.stringify(parsed, null, 2);
          } catch {}
          incEvidenceRaw.textContent = evDisplay;
          incEvidenceRaw.style.color = "#a7f3d0";
        } else if (failedAction && incVerBox && incEvidenceRaw) {
          incVerBox.hidden = false;
          incVerBox.style.background = "rgba(239, 68, 68, 0.08)";
          incVerBox.style.borderColor = "rgba(239, 68, 68, 0.3)";
          if (incEvidencePill) {
            incEvidencePill.className = "badge badge-red";
            incEvidencePill.textContent = "VERIFICATION FAILED";
          }
          if (incVerifiedAtTag) incVerifiedAtTag.textContent = `Evaluated: ${failedAction.created_at || "N/A"}`;
          incEvidenceRaw.textContent = `Verification failure reason: ${failedAction.message || "Target IP not found in host nftables set."}`;
          incEvidenceRaw.style.color = "#fca5a5";
        } else if (incVerBox) {
          incVerBox.hidden = true;
        }

        incidentActionsContainer.replaceChildren();
        if (actions.length === 0) {
          incidentActionsContainer.innerHTML = '<p class="muted p-no-actions">No response actions recorded for this incident. Use \'Request Containment\' to initiate a block.</p>';
        } else {
          for (const act of actions) {
            const card = node("div", `action-summary-card act-${String(act.status).toLowerCase()}`);
            const details = node("div", "action-details-text");
            details.append(node("strong", "", `Action #${act.action_id} — ${act.action_type}`));
            details.append(node("span", "text-xs", `Target: ${act.target_ip} · Triggered by: ${act.triggered_by}`));

            const timeoutText = act.timeout_seconds ? ` · Timeout: ${act.timeout_seconds}s` : " · Permanent";
            details.append(node("span", "mono-text text-xs", `Created: ${act.created_at}${act.executed_at ? ` · Executed: ${act.executed_at}` : ""}${timeoutText}`));

            if (act.is_temporary) {
              const timerSpan = node("span", `countdown-pill ${act.is_expired ? "countdown-expired" : ""}`);
              if (!act.is_expired && act.expires_at) {
                timerSpan.setAttribute("data-expires-at", act.expires_at);
                timerSpan.textContent = `⏱️ ${formatCountdown(act.time_remaining_seconds || 0)} remaining`;
              } else {
                timerSpan.textContent = "⏱️ Expired";
              }
              details.append(timerSpan);
            }
            card.append(details);

            const rightCluster = node("div", "action-btn-cluster");
            rightCluster.append(node("span", `badge ${getStatusBadgeClass(act.defense_status || act.status)}`, act.defense_status || act.status));

            // Contextual Approval & Verification Buttons
            if (act.status === "PENDING") {
              const appBtn = node("button", "btn btn-primary btn-sm", "Approve Action");
              appBtn.type = "button";
              appBtn.addEventListener("click", () => approveResponseAction(act.action_id));
              rightCluster.append(appBtn);
            } else if (act.status === "VERIFIED") {
              const reVerBtn = node("button", "btn btn-outline btn-xs", "Re-verify");
              reVerBtn.type = "button";
              reVerBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
              rightCluster.append(reVerBtn);
            } else if (act.status === "VERIFICATION_FAILED") {
              const retryBtn = node("button", "btn btn-primary btn-xs", "Retry Verification");
              retryBtn.type = "button";
              retryBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
              rightCluster.append(retryBtn);
            } else {
              const verBtn = node("button", "btn btn-outline btn-sm", "Verify Mitigation");
              verBtn.type = "button";
              verBtn.title = "Verify containment rule against host nftables";
              verBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
              rightCluster.append(verBtn);

              const pendBtn = node("button", "btn btn-secondary btn-xs", "Mark Pending");
              pendBtn.type = "button";
              pendBtn.title = "Mark as Verification Pending";
              pendBtn.addEventListener("click", () => markActionVerificationPending(act.action_id));
              rightCluster.append(pendBtn);
            }

            card.append(rightCluster);
            incidentActionsContainer.append(card);
          }
        }
      }

      // Switch pane visibility from empty state to content
      if (detailsEmptyEl) detailsEmptyEl.hidden = true;
      if (detailsContentEl) detailsContentEl.hidden = false;

      if (scrollIntoView) {
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    } catch (e) {
      showToast(`Failed to load incident #${incidentId}: ${e.message}`, "error");
    }
  }

  function updateWorkflowStepper(currentStatus, defenseStatus = null, actions = []) {
    if (!workflowStepper) return;
    const currentIndex = workflowOrder.indexOf(currentStatus);
    const nodes = workflowStepper.querySelectorAll(".step-node");
    const connectors = workflowStepper.querySelectorAll(".step-connector");

    // Has verified containment occurred?
    const hasVerifiedContainment = (actions && actions.some(a => a.status === "VERIFIED" && !a.is_expired)) ||
                                   defenseStatus === "Verified";

    nodes.forEach(nodeEl => {
      const stepName = nodeEl.getAttribute("data-step");
      const stepIdx = workflowOrder.indexOf(stepName);

      nodeEl.classList.remove("active", "completed", "future", "skipped");
      if (stepIdx === currentIndex) {
        nodeEl.classList.add("active");
      } else if (stepIdx < currentIndex) {
        // If this step is CONTAINED, only mark completed if containment was actually verified!
        if (stepName === "CONTAINED" && !hasVerifiedContainment) {
          nodeEl.classList.add("skipped");
        } else {
          nodeEl.classList.add("completed");
        }
      } else {
        nodeEl.classList.add("future");
      }
    });

    connectors.forEach((connEl, idx) => {
      if (idx < currentIndex) {
        connEl.classList.add("completed");
      } else {
        connEl.classList.remove("completed");
      }
    });
  }

  // =========================================================================
  // WORKFLOW TRANSITIONS & CONTAINMENT ACTIONS
  // =========================================================================
  async function transitionIncidentStatus(status, defaultRationale = "") {
    if (!selectedIncidentId) return;
    const rationale = prompt(`Enter rationale for transitioning status to '${status}':`, defaultRationale);
    if (rationale === null) return;

    try {
      await api(`/api/soc/incidents/${selectedIncidentId}/status`, {
        method: "POST",
        body: JSON.stringify({ status, rationale: rationale.trim() })
      });
      showToast(`Incident #${selectedIncidentId} transitioned to ${status}`, "success");
      fetchIncidents();
      loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      showToast(`Status update failed: ${e.message}`, "error");
    }
  }

  async function requestContainmentBlock(targetIp = null) {
    if (isSubmittingAction) return;
    if (!selectedIncidentId) {
      showToast("Select an incident to request containment", "error");
      return;
    }
    const ip = targetIp || (detailSourceIp ? detailSourceIp.textContent : "").trim();
    if (!ip || ip === "Not available") {
      showToast("Target IP not available for containment", "error");
      return;
    }

    const currentInc = currentIncidentData || allIncidents.find(i => String(i.incident_id) === String(selectedIncidentId));
    const policy = currentInc && currentInc.response_policy;
    const isAppLayer = policy && !policy.is_supported;

    if (isAppLayer) {
      if (!confirm(`Apply attack-specific policy ${policy.selected_response} for incident #${selectedIncidentId} (${policy.signature})?\n\nNotice: This attack vector requires application-layer controls (${policy.attack_type}). The action will enter PENDING_IMPLEMENTATION without claiming a firewall block.`)) {
        return;
      }
    } else {
      const respName = (policy && policy.selected_response) || "BLOCK_IP";
      const dur = (policy && policy.duration_seconds) || 1800;
      if (!confirm(`Queue SOAR Containment ${respName} action for target ${ip}?\nDuration: ${dur}s.\nAction will enter PENDING status awaiting explicit analyst approval.`)) {
        return;
      }
    }

    isSubmittingAction = true;
    try {
      const r = await api("/api/soc/mitigate/apply-policy", {
        method: "POST",
        body: JSON.stringify({ target_ip: ip, incident_id: selectedIncidentId })
      });
      if (r.status === "PENDING_IMPLEMENTATION" || r.defense_status === "Untested") {
        showToast(r.message || `Policy action recorded (PENDING_IMPLEMENTATION)`, "info");
      } else {
        showToast(`Containment Action #${r.action_id} queued (PENDING approval)`, "success");
      }
      await fetchIncidents();
      await fetchResponseActions();
      await loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      showToast(`Containment request failed: ${e.message}`, "error");
    } finally {
      isSubmittingAction = false;
    }
  }

  async function approveResponseAction(actionId) {
    if (!confirm(`Approve Containment Action #${actionId} for execution?`)) return;
    try {
      const r = await api(`/api/soc/response-actions/${actionId}/approve`, { method: "POST" });
      showToast(`Action #${r.action_id} approved for execution`, "success");
      refresh();
      if (selectedIncidentId) loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      showToast(`Approval failed: ${e.message}`, "error");
    }
  }

  let pendingVerifyActionId = null;
  let pendingVerifyTargetIp = null;

  function openVerificationModal(actionId, targetIp) {
    pendingVerifyActionId = actionId;
    pendingVerifyTargetIp = targetIp || "127.0.0.1";
    const modal = document.getElementById("modal-verify-evidence");
    const actIdSpan = document.getElementById("modal-verify-act-id");
    const targetSpan = document.getElementById("modal-verify-target-ip");
    const input = document.getElementById("modal-verify-input");

    if (actIdSpan) actIdSpan.textContent = actionId;
    if (targetSpan) targetSpan.textContent = pendingVerifyTargetIp;
    if (input) {
      input.value = `table inet filter {\n    set blocked_ips {\n        type ipv4_addr\n        elements = { ${pendingVerifyTargetIp} }\n    }\n}`;
    }
    if (modal) modal.hidden = false;
  }

  function closeVerificationModal() {
    const modal = document.getElementById("modal-verify-evidence");
    if (modal) modal.hidden = true;
    pendingVerifyActionId = null;
    pendingVerifyTargetIp = null;
  }

  async function markActionVerificationPending(actionId) {
    try {
      await api(`/api/soc/response-actions/${actionId}/pending-verification`, { method: "POST" });
      showToast(`Action #${actionId} marked VERIFICATION PENDING`, "info");
      refresh();
      if (selectedIncidentId) loadIncidentDetails(selectedIncidentId);
    } catch (e) {
      showToast(`Failed to update status: ${e.message}`, "error");
    }
  }

  async function verifyResponseAction(actionId, targetIp = null) {
    openVerificationModal(actionId, targetIp);
  }

  // =========================================================================
  // SOAR MODE BADGE MANAGER
  // =========================================================================
  function updateSoarModeBadges(soarMode) {
    const mode = (soarMode || window.SOC_SOAR_MODE || "DRY-RUN").toUpperCase();
    const isEnforced = mode === "ENFORCEMENT" || mode === "ACTIVE" || mode === "ENABLED";
    const label = isEnforced ? "SOAR: ENFORCEMENT" : "SOAR: DRY-RUN";
    const badgeClass = isEnforced ? "badge badge-verified" : "badge badge-amber";

    ["soar-mode-badge", "soar-mode-badge-actions", "soar-mode-badge-poller", "soar-mode-badge-detail"].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = label;
        el.className = badgeClass;
      }
    });
    const footerEl = document.getElementById("soar-mode-footer");
    if (footerEl) {
      footerEl.textContent = label;
    }
  }

  // =========================================================================
  // MITRE ATT&CK MATRIX
  // =========================================================================
  function renderMitreMatrix(data) {
    if (data && data.soar_mode) {
      updateSoarModeBadges(data.soar_mode);
    }
    const matrix = data.matrix || [];
    const targetGrids = [grid, gridFull].filter(Boolean);

    targetGrids.forEach(g => {
      g.replaceChildren();
      for (const item of matrix) {
        // Use defense_status if present to provide specific visual indication (e.g. state-purple for verification pending)
        const visualState = item.defense_status || item.state;
        const card = node("div", `mitre-card ${getMitreStateCardClass(visualState)}`);

        const top = node("div", "mitre-card-top");
        top.append(node("span", "mitre-id mono-text", item.technique_id));
        
        const badgeCluster = node("div", "mitre-badge-cluster");
        badgeCluster.append(node("span", `badge ${getStatusBadgeClass(item.state)}`, item.state.replace(/_/g, " ")));
        if (item.defense_status && item.defense_status !== item.state) {
          badgeCluster.append(node("span", `badge ${getStatusBadgeClass(item.defense_status)}`, item.defense_status.replace(/_/g, " ")));
        }
        top.append(badgeCluster);
        card.append(top);

        card.append(node("h3", "mitre-name", item.technique_name));
        card.append(node("p", "text-xs muted", `${item.tactic} · ${item.signature}`));
        card.append(node("p", "text-sm", `Observed: ${item.alert_count} alerts · Mitigated: ${item.mitigated_count}`));

        const actions = node("div", "mitre-actions");
        if (item.alert_count > 0) {
          const invBtn = node("button", "btn btn-investigate btn-xs", `Investigate (${item.alert_count})`);
          invBtn.type = "button";
          invBtn.addEventListener("click", () => {
            const match = allIncidents.find(i => i.signature === item.signature && i.status !== "CLOSED") ||
                          allIncidents.find(i => i.signature === item.signature);
            if (match) {
              switchView("incident-detail", match.incident_id);
            } else {
              switchView("alerts");
            }
          });
          actions.append(invBtn);
        }
        card.append(actions);
        g.append(card);
      }
    });

    const detCount = data.detected_techniques ?? 0;
    const mitCount = data.mitigated_techniques ?? 0;
    let formattedIndex = "N/A";
    let detailText = "No detected techniques";
    let cardSubtext = "No attack techniques detected";

    if (detCount > 0 && data.resilience_index != null) {
      const pct = Number(data.resilience_index).toFixed(2);
      formattedIndex = `${pct}%`;
      detailText = `${formattedIndex} — ${mitCount} of ${detCount} detected techniques mitigated`;
      cardSubtext = `${mitCount} of ${detCount} detected techniques mitigated`;
    } else if (detCount > 0) {
      formattedIndex = "0.00%";
      detailText = `0.00% — 0 of ${detCount} detected techniques mitigated`;
      cardSubtext = `0 of ${detCount} detected techniques mitigated`;
    }

    if (value) {
      value.textContent = formattedIndex;
      value.title = "Purple Team Resilience Index = (Distinct detected techniques with verified mitigations / Distinct detected techniques) × 100";
    }
    if (detail) {
      detail.textContent = detailText;
      detail.title = "Distinct MITRE techniques: only detected techniques are counted in denominator";
    }
    if (statResilience) {
      statResilience.textContent = formattedIndex;
      statResilience.title = "Purple Team Resilience Index: authoritative backend calculation";
    }
    const cardResilience = document.getElementById("card-stat-resilience");
    if (cardResilience) {
      const sub = cardResilience.querySelector(".kpi-subtext");
      if (sub) sub.textContent = cardSubtext;
    }
    if (statDetected) statDetected.textContent = detCount;
    if (statMitigated) statMitigated.textContent = mitCount;
    if (statTotal) statTotal.textContent = matrix.length;
  }

  // =========================================================================
  // DEDICATED REPORTS WORKFLOW (Form, Live Preview, Validation, Real Submission)
  // =========================================================================
  async function fetchReports() {
    if (!reportsHistoryBody) return;
    try {
      const data = await api("/api/soc/reports");
      allReports = data.reports || [];
      renderReportsHistory();
    } catch {
      allReports = [];
      renderReportsHistory();
    }
  }

  function renderReportsHistory() {
    if (!reportsHistoryBody) return;
    reportsHistoryBody.replaceChildren();

    if (allReports.length === 0) {
      reportsHistoryBody.innerHTML = '<tr><td colspan="7" class="text-center muted">No reports generated yet. Use the form above to draft and submit a report.</td></tr>';
      return;
    }

    allReports.forEach(rep => {
      const tr = node("tr");
      tr.append(node("td", "mono-text", `#REP-${rep.report_id}`));
      tr.append(node("td", "mono-text text-xs", rep.created_at || ""));
      tr.append(node("td", "", rep.title || "Untitled Report"));
      tr.append(node("td", "", rep.report_type || "General"));
      tr.append(node("td", "mono-text", rep.incident_id ? `#INC-${rep.incident_id}` : "Unlinked"));
      tr.append(node("td", "", rep.author || "SOC_ANALYST"));

      const tdAct = node("td");
      const viewBtn = node("button", "btn btn-outline btn-xs", "Load Preview");
      viewBtn.type = "button";
      viewBtn.addEventListener("click", () => {
        if (reportTitleInput) reportTitleInput.value = rep.title;
        if (reportTypeSelect) reportTypeSelect.value = rep.report_type;
        if (reportSummaryInput) reportSummaryInput.value = rep.summary;
        if (reportFindingsInput) reportFindingsInput.value = rep.findings || "";
        if (reportIncidentSelect) reportIncidentSelect.value = rep.incident_id || "";
        updateReportPreview();
        showToast(`Loaded Report #${rep.report_id} into preview`, "info");
      });
      tdAct.append(viewBtn);
      tr.append(tdAct);

      reportsHistoryBody.append(tr);
    });
  }

  function populateReportIncidentSelect() {
    if (!reportIncidentSelect) return;
    const currentVal = reportIncidentSelect.value;
    reportIncidentSelect.replaceChildren();

    const defOpt = node("option", "", "General SOC Report (Unlinked)");
    defOpt.value = "";
    reportIncidentSelect.append(defOpt);

    allIncidents.forEach(inc => {
      const opt = node("option", "", `#INC-${inc.incident_id}: ${inc.title || inc.signature}`);
      opt.value = inc.incident_id;
      reportIncidentSelect.append(opt);
    });

    if (currentVal) reportIncidentSelect.value = currentVal;
  }

  function updateReportPreview() {
    if (!prevTitle) return;

    const title = (reportTitleInput ? reportTitleInput.value : "").trim() || "Incident Investigation Dossier";
    const category = (reportTypeSelect ? reportTypeSelect.value : "") || "Incident Investigation Dossier";
    const summary = (reportSummaryInput ? reportSummaryInput.value : "").trim() || "Enter executive summary on the left to preview findings.";
    const findings = (reportFindingsInput ? reportFindingsInput.value : "").trim() || "Technical evidence and telemetry details will appear here.";
    const incId = reportIncidentSelect ? reportIncidentSelect.value : "";

    prevTitle.textContent = title;
    if (prevCategory) prevCategory.textContent = category;
    if (prevSummary) prevSummary.textContent = summary;
    if (prevFindings) prevFindings.textContent = findings;
    if (prevDate) prevDate.textContent = new Date().toISOString().substring(0, 19).replace("T", " ") + " UTC";

    if (incId) {
      const linked = allIncidents.find(i => String(i.incident_id) === String(incId));
      if (prevIncidentTag) prevIncidentTag.textContent = `#INC-${incId}`;
      if (prevClassification) prevClassification.textContent = (linked && linked.classification) ? linked.classification.replace(/_/g, " ") : "UNCLASSIFIED";
      if (prevSourceIp) prevSourceIp.textContent = linked ? linked.source_ip : "—";
      if (prevMitre) prevMitre.textContent = linked ? `${linked.technique_name || "Unknown"} (${linked.technique_id || "N/A"})` : "—";
      if (prevAlertCount) prevAlertCount.textContent = linked ? (linked.alert_count || 1) : 0;
      if (prevMitigationStatus) prevMitigationStatus.textContent = linked ? (linked.status === "CONTAINED" ? "VERIFIED HOST MITIGATION" : "DRY-RUN / UNVERIFIED") : "DRY-RUN";
    } else {
      if (prevIncidentTag) prevIncidentTag.textContent = "General Assessment";
      if (prevClassification) prevClassification.textContent = "N/A";
      if (prevSourceIp) prevSourceIp.textContent = "Enterprise Perimeter";
      if (prevMitre) prevMitre.textContent = "Multi-Technique Assessment";
      if (prevAlertCount) prevAlertCount.textContent = allAlerts.length;
      if (prevMitigationStatus) prevMitigationStatus.textContent = "DRY-RUN ACTIVE";
    }
  }

  async function submitReport() {
    const title = (reportTitleInput ? reportTitleInput.value : "").trim();
    const reportType = (reportTypeSelect ? reportTypeSelect.value : "").trim();
    const summary = (reportSummaryInput ? reportSummaryInput.value : "").trim();
    const findings = (reportFindingsInput ? reportFindingsInput.value : "").trim();
    const dateRange = (reportDateRangeSelect ? reportDateRangeSelect.value : "").trim();
    const incidentId = (reportIncidentSelect ? reportIncidentSelect.value : "") || null;

    if (!title) {
      showToast("Report title is required", "error");
      if (reportTitleInput) reportTitleInput.focus();
      return;
    }
    if (!summary) {
      showToast("Executive summary is required", "error");
      if (reportSummaryInput) reportSummaryInput.focus();
      return;
    }

    if (btnSubmitReport) {
      btnSubmitReport.disabled = true;
      btnSubmitReport.textContent = "Generating...";
    }

    try {
      const res = await api("/api/soc/reports", {
        method: "POST",
        body: JSON.stringify({
          title,
          report_type: reportType,
          summary,
          findings,
          date_range: dateRange,
          incident_id: incidentId
        })
      });

      showToast(`Report #${res.report_id} generated and saved successfully!`, "success");
      fetchReports();
    } catch (e) {
      showToast(`Report generation failed: ${e.message}`, "error");
    } finally {
      if (btnSubmitReport) {
        btnSubmitReport.disabled = false;
        btnSubmitReport.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:5px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          Submit &amp; Save Report
        `;
      }
    }
  }

  // =========================================================================
  // TRENDS VIEW COMPUTATION
  // =========================================================================
  function renderTrends() {
    const sigBars = document.getElementById("trends-signature-bars");
    const sevBars = document.getElementById("trends-severity-bars");
    const srcTbody = document.getElementById("trends-source-tbody");

    // 1. Signature Distribution
    if (sigBars) {
      sigBars.replaceChildren();
      const counts = {};
      allAlerts.forEach(a => {
        const sig = a.signature || "UNKNOWN";
        counts[sig] = (counts[sig] || 0) + 1;
      });

      const maxCount = Math.max(...Object.values(counts), 1);
      const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);

      if (sorted.length === 0) {
        sigBars.innerHTML = '<p class="muted">No telemetry observed yet.</p>';
      } else {
        sorted.forEach(([sig, cnt]) => {
          const pct = Math.round((cnt / maxCount) * 100);
          const row = node("div", "trend-bar-row");
          const meta = node("div", "trend-bar-meta");
          meta.append(node("strong", "", sig));
          meta.append(node("span", "mono-text", `${cnt} alert${cnt === 1 ? "" : "s"}`));
          row.append(meta);

          const track = node("div", "trend-bar-track");
          const fill = node("div", "trend-bar-fill");
          fill.style.width = `${pct}%`;
          fill.style.background = "linear-gradient(90deg, #6366f1 0%, #8b5cf6 100%)";
          track.append(fill);
          row.append(track);

          sigBars.append(row);
        });
      }
    }

    // 2. Severity Profile
    if (sevBars) {
      sevBars.replaceChildren();
      const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      allAlerts.forEach(a => {
        const sev = String(a.severity || "medium").toLowerCase();
        if (sevCounts[sev] !== undefined) sevCounts[sev]++;
      });

      const maxSev = Math.max(...Object.values(sevCounts), 1);
      const sevColors = {
        critical: "#ef4444",
        high: "#f97316",
        medium: "#f59e0b",
        low: "#3b82f6",
        info: "#06b6d4"
      };

      Object.entries(sevCounts).forEach(([sev, cnt]) => {
        const pct = Math.round((cnt / maxSev) * 100);
        const row = node("div", "trend-bar-row");
        const meta = node("div", "trend-bar-meta");
        meta.append(node("strong", "", sev.toUpperCase()));
        meta.append(node("span", "mono-text", `${cnt} (${Math.round((cnt / (allAlerts.length || 1)) * 100)}%)`));
        row.append(meta);

        const track = node("div", "trend-bar-track");
        const fill = node("div", "trend-bar-fill");
        fill.style.width = `${pct}%`;
        fill.style.background = sevColors[sev] || "#6366f1";
        track.append(fill);
        row.append(track);

        sevBars.append(row);
      });
    }

    // 3. Top Sources Table
    if (srcTbody) {
      srcTbody.replaceChildren();
      const ipMap = {};
      allAlerts.forEach(a => {
        const ip = a.source_ip || "Unknown";
        if (!ipMap[ip]) ipMap[ip] = { count: 0, sigs: new Set(), incId: a.incident_id };
        ipMap[ip].count++;
        ipMap[ip].sigs.add(a.signature);
      });

      const sortedIps = Object.entries(ipMap).sort((a, b) => b[1].count - a[1].count);
      if (sortedIps.length === 0) {
        srcTbody.innerHTML = '<tr><td colspan="5" class="text-center muted">No source IP activity recorded</td></tr>';
      } else {
        sortedIps.forEach(([ip, data]) => {
          const tr = node("tr");
          tr.append(node("td", "mono-text font-bold", ip));
          tr.append(node("td", "mono-text", data.count));
          tr.append(node("td", "", Array.from(data.sigs).join(", ")));
          tr.append(node("td", "", data.incId ? `Linked #INC-${data.incId}` : "Uncorrelated"));

          const tdAct = node("td");
          const invBtn = node("button", "btn btn-outline btn-xs", "Investigate");
          invBtn.type = "button";
          invBtn.addEventListener("click", () => {
            if (data.incId) {
              switchView("incident-detail", data.incId);
            } else {
              switchView("alerts");
            }
          });
          tdAct.append(invBtn);
          tr.append(tdAct);

          srcTbody.append(tr);
        });
      }
    }
  }

  // =========================================================================
  // RESPONSE ACTIONS & TEMPORARY CONTROLS VIEW
  // =========================================================================
  async function fetchResponseActions() {
    try {
      const data = await api("/api/soc/response-actions");
      allResponseActions = data.actions || [];
      if (data && data.soar_mode) {
        updateSoarModeBadges(data.soar_mode);
      }
    } catch {
      allResponseActions = [];
      allIncidents.forEach(inc => {
        if (inc.response_actions) {
          allResponseActions.push(...inc.response_actions);
        }
      });
    }

    renderAllActionsTable();
    renderTemporaryControlsCards();
  }

  function renderTemporaryControlsCards() {
    const dashContainer = document.getElementById("dash-temp-controls-container");
    const dashBadge = document.getElementById("dash-temp-controls-badge");
    const statTempControls = document.getElementById("stat-temp-controls");
    const actionsContainer = document.getElementById("actions-temp-controls-container");
    const actionsBadge = document.getElementById("actions-temp-controls-badge");

    const activeList = allResponseActions.filter(a => {
      if (!a.is_temporary) return false;
      if (a.is_expired) return false;
      if (["EXPIRED", "CANCELLED", "FAILED", "VERIFICATION_FAILED", "UNSUPPORTED"].includes(a.status)) return false;
      if (a.time_remaining_seconds !== null && a.time_remaining_seconds !== undefined && a.time_remaining_seconds <= 0) return false;
      return true;
    });

    if (statTempControls) statTempControls.textContent = activeList.length;
    if (dashBadge) dashBadge.textContent = `${activeList.length} Active Control${activeList.length === 1 ? "" : "s"}`;
    if (actionsBadge) actionsBadge.textContent = `${activeList.length} Active`;

    [dashContainer, actionsContainer].filter(Boolean).forEach(container => {
      container.replaceChildren();
      if (activeList.length === 0) {
        container.innerHTML = '<p class="muted p-empty">No active temporary containment controls running.</p>';
      } else {
        activeList.forEach(act => {
          const card = node("div", `temp-control-card ${act.is_dry_run ? "temp-control-simulated" : ""}`);

          const head = node("div", "temp-card-header");
          const targetWrapper = node("div", "d-flex align-center gap-6");
          targetWrapper.style.display = "flex";
          targetWrapper.style.alignItems = "center";
          targetWrapper.style.gap = "6px";
          targetWrapper.append(node("span", "temp-target-ip mono-text", act.target_ip));
          if (act.is_dry_run || act.status === "DRY_RUN") {
            targetWrapper.append(node("span", "badge badge-amber text-xs", "SIMULATED (DRY-RUN)"));
          }
          head.append(targetWrapper);

          const timer = node("span", "countdown-pill");
          if (act.expires_at) {
            timer.setAttribute("data-expires-at", act.expires_at);
            const initialSec = (act.time_remaining_seconds !== null && act.time_remaining_seconds !== undefined)
              ? act.time_remaining_seconds
              : (act.timeout_seconds || null);
            if (initialSec !== null) {
              timer.textContent = `⏱️ ${formatCountdown(initialSec)} remaining`;
            } else {
              timer.textContent = "⏱️ Active";
            }
          } else if (act.is_temporary && !act.is_expired) {
            timer.textContent = act.timeout_seconds ? `⏱️ ${formatCountdown(act.timeout_seconds)} (Pending)` : "⏱️ Active";
          } else {
            timer.textContent = "⏱️ Expired";
            timer.classList.add("countdown-expired");
          }
          head.append(timer);
          card.append(head);

          const meta1 = node("div", "temp-meta-row");
          meta1.append(node("span", "", `Action #${act.action_id} (${act.action_type})`));
          const defState = act.defense_status || act.status;
          meta1.append(node("span", `badge ${getStatusBadgeClass(defState)}`, defState));
          card.append(meta1);

          const meta2 = node("div", "temp-meta-row");
          meta2.append(node("span", "mono-text text-xs", act.incident_id ? `#INC-${act.incident_id}` : "Global"));
          const expText = act.expires_at ? act.expires_at.replace("T", " ").substring(0, 19) + " UTC" : (act.timeout_seconds ? `On execution (${act.timeout_seconds}s)` : "N/A");
          meta2.append(node("span", "mono-text text-xs", `Expires: ${expText}`));
          card.append(meta2);

          const actionsRow = node("div", "d-flex gap-8 justify-end mt-4");
          actionsRow.style.marginTop = "6px";
          actionsRow.style.display = "flex";
          actionsRow.style.gap = "6px";
          actionsRow.style.justifyContent = "flex-end";

          if (act.status !== "VERIFIED") {
            const verBtn = node("button", "btn btn-outline btn-xs", act.is_dry_run ? "Verify (Simulated)" : "Verify");
            verBtn.type = "button";
            verBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
            actionsRow.append(verBtn);
          }

          if (act.incident_id) {
            const incBtn = node("button", "btn btn-secondary btn-xs", "View Incident");
            incBtn.type = "button";
            incBtn.addEventListener("click", () => switchView("incident-detail", act.incident_id));
            actionsRow.append(incBtn);
          }

          card.append(actionsRow);
          container.append(card);
        });
      }
    });
  }

  function renderAllActionsTable() {
    const allActionsBody = document.getElementById("all-actions-body");
    if (!allActionsBody) return;
    allActionsBody.replaceChildren();

    if (sidebarActionBadge) {
      sidebarActionBadge.textContent = allResponseActions.length;
    }

    if (allResponseActions.length === 0) {
      allActionsBody.innerHTML = '<tr><td colspan="10" class="text-center muted">No response actions queued or executed.</td></tr>';
      return;
    }

    allResponseActions.forEach(act => {
      const tr = node("tr");
      tr.append(node("td", "mono-text", `#ACT-${act.action_id}`));
      tr.append(node("td", "mono-text", act.incident_id ? `#INC-${act.incident_id}` : "Global"));

      // Target IP with simulation indicator if dry-run
      const tdTarget = node("td", "mono-text font-bold");
      tdTarget.textContent = act.target_ip;
      if (act.is_dry_run || act.status === "DRY_RUN") {
        const simBadge = node("span", "badge badge-amber text-xs ml-1", "DRY-RUN");
        simBadge.style.marginLeft = "6px";
        tdTarget.append(simBadge);
      }
      tr.append(tdTarget);

      // Action Type
      const tdType = node("td", "mono-text");
      tdType.textContent = act.action_type;
      tr.append(tdType);

      // 5. Defense Status
      const tdDefStatus = node("td");
      const defState = act.defense_status || act.status;
      tdDefStatus.append(node("span", `badge ${getStatusBadgeClass(defState)}`, defState));
      tr.append(tdDefStatus);

      // 6. Timeout / Expiry
      const tdExpiry = node("td");
      if (act.is_temporary) {
        const pill = node("span", `countdown-pill ${act.is_expired ? "countdown-expired" : ""}`);
        if (!act.is_expired && act.expires_at) {
          pill.setAttribute("data-expires-at", act.expires_at);
          const initialSec = (act.time_remaining_seconds !== null && act.time_remaining_seconds !== undefined)
            ? act.time_remaining_seconds
            : (act.timeout_seconds || null);
          pill.textContent = initialSec !== null ? `⏱️ ${formatCountdown(initialSec)} remaining` : "⏱️ Active";
        } else if (!act.is_expired) {
          pill.textContent = act.timeout_seconds ? `⏱️ ${formatCountdown(act.timeout_seconds)} (Pending)` : "⏱️ Active";
        } else {
          pill.textContent = "⏱️ Expired";
        }
        tdExpiry.append(pill);
      } else {
        tdExpiry.append(node("span", "text-xs muted", "Permanent"));
      }
      tr.append(tdExpiry);

      // 7. Verification Evidence
      const tdEv = node("td");
      if (act.verification_evidence) {
        const evBtn = node("button", "btn btn-outline btn-xs mono-text", "Proof ✓");
        evBtn.type = "button";
        evBtn.title = "View independent firewall verification evidence";
        evBtn.addEventListener("click", () => {
          openVerificationModal(act.action_id, act.target_ip);
          const input = document.getElementById("modal-verify-input");
          if (input) {
            try {
              input.value = JSON.stringify(JSON.parse(act.verification_evidence), null, 2);
            } catch {
              input.value = act.verification_evidence;
            }
          }
        });
        tdEv.append(evBtn);
      } else if (act.status === "VERIFICATION_FAILED") {
        tdEv.append(node("span", "badge badge-red text-xs", "Failed"));
      } else {
        tdEv.append(node("span", "text-xs muted", "Unverified"));
      }
      tr.append(tdEv);

      // 8. Triggered By
      tr.append(node("td", "", act.triggered_by));

      // 9. Executed
      tr.append(node("td", "mono-text text-xs", act.executed_at ? act.executed_at.replace("T", " ").substring(0, 19) : (act.created_at ? act.created_at.replace("T", " ").substring(0, 19) + " (Created)" : "Pending")));

      // 10. Actions
      const tdAct = node("td");
      const btnCluster = node("div", "d-flex gap-4");
      btnCluster.style.display = "flex";
      btnCluster.style.gap = "4px";

      if (act.status === "PENDING") {
        const appBtn = node("button", "btn btn-primary btn-xs", "Approve");
        appBtn.type = "button";
        appBtn.addEventListener("click", () => approveResponseAction(act.action_id));
        btnCluster.append(appBtn);
      } else if (act.status === "VERIFIED") {
        const reBtn = node("button", "btn btn-outline btn-xs", "Re-verify");
        reBtn.type = "button";
        reBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
        btnCluster.append(reBtn);
      } else if (act.status === "VERIFICATION_FAILED") {
        const retryBtn = node("button", "btn btn-primary btn-xs", "Retry Verify");
        retryBtn.type = "button";
        retryBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
        btnCluster.append(retryBtn);
      } else {
        const verBtn = node("button", "btn btn-outline btn-xs", act.is_dry_run ? "Verify (Simulated)" : "Verify nftables");
        verBtn.type = "button";
        verBtn.addEventListener("click", () => openVerificationModal(act.action_id, act.target_ip));
        btnCluster.append(verBtn);
      }
      if (act.incident_id) {
        const viewIncBtn = node("button", "btn btn-secondary btn-xs", "Incident");
        viewIncBtn.type = "button";
        viewIncBtn.addEventListener("click", () => switchView("incident-detail", act.incident_id));
        btnCluster.append(viewIncBtn);
      }
      tdAct.append(btnCluster);
      tr.append(tdAct);

      allActionsBody.append(tr);
    });
  }

  // =========================================================================
  // GLOBAL REFRESH
  // =========================================================================
  async function refresh(isManual = false) {
    if (isGlobalRefreshing) return;
    isGlobalRefreshing = true;

    if (btnRefresh) {
      btnRefresh.classList.add("refreshing");
      btnRefresh.disabled = true;
    }

    try {
      if (error) {
        error.hidden = true;
        error.textContent = "";
      }

      const data = await api("/api/soc/mitre-matrix");
      renderMitreMatrix(data);
      if (data.soar_mode) {
        updateSoarModeBadges(data.soar_mode);
      }

      if (window.SOC_ANALYST_TOKEN) {
        updateAuthBadge("authenticated");
        await Promise.allSettled([
          fetchIncidents(),
          fetchAlerts(),
          fetchResponseActions(),
          fetchReports()
        ]);
        if (selectedIncidentId) {
          await loadIncidentDetails(selectedIncidentId).catch(() => {});
        }
      } else {
        updateAuthBadge("unauthenticated");
      }
      if (isManual === true) {
        showToast("Dashboard telemetry refreshed", "success");
      }
    } catch (e) {
      if (error) {
        error.textContent = `Unable to load matrix: ${e.message}`;
        error.hidden = false;
      }

      if (e.message && e.message.includes("401")) {
        updateAuthBadge(window.SOC_ANALYST_TOKEN ? "error" : "unauthenticated", e.message);
      } else {
        updateAuthBadge("error", e.message);
      }
      if (isManual === true) {
        showToast(`Refresh failed: ${e.message}`, "error");
      }
    } finally {
      isGlobalRefreshing = false;
      if (btnRefresh) {
        btnRefresh.classList.remove("refreshing");
        btnRefresh.disabled = false;
      }
    }
  }

  // =========================================================================
  // TOKEN MANAGEMENT
  // =========================================================================
  function setToken(token) {
    const cleanToken = (token || "").trim();
    if (!cleanToken) {
      showToast("Please enter an ANALYST_TOKEN before setting.", "error");
      return;
    }

    window.SOC_ANALYST_TOKEN = cleanToken;
    try {
      sessionStorage.setItem("SOC_ANALYST_TOKEN", cleanToken);
      localStorage.setItem("SOC_ANALYST_TOKEN", cleanToken);
    } catch (_) {}

    if (tokenInput) tokenInput.value = cleanToken;
    if (modalTokenInput) modalTokenInput.value = cleanToken;
    updateAuthBadge("checking");
    refresh(true);
    showToast("Analyst token configured and saved", "success");
  }

  function clearToken() {
    window.SOC_ANALYST_TOKEN = "";
    try {
      sessionStorage.removeItem("SOC_ANALYST_TOKEN");
      localStorage.removeItem("SOC_ANALYST_TOKEN");
    } catch (_) {}

    if (tokenInput) tokenInput.value = "";
    if (modalTokenInput) modalTokenInput.value = "";
    updateAuthBadge("unauthenticated");
    refresh(true);
    showToast("Analyst session cleared", "info");
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

  // =========================================================================
  // EVENT LISTENERS INITIALIZATION
  // =========================================================================
  function setupEventListeners() {
    // Navigation Links
    document.querySelectorAll(".nav-link").forEach(link => {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        const targetView = link.getAttribute("id").replace("nav-", "");
        switchView(targetView);
      });
    });

    // Mobile Sidebar Toggle
    if (sidebarToggleBtn && sidebarEl) {
      sidebarToggleBtn.addEventListener("click", () => {
        sidebarEl.classList.toggle("open");
      });
    }

    // Refresh Buttons with loading states and debounce/in-flight guards
    if (btnRefresh) {
      btnRefresh.addEventListener("click", () => refresh(true));
    }

    if (btnRefreshAlerts) {
      let isAlertsRefreshing = false;
      btnRefreshAlerts.addEventListener("click", async () => {
        if (isAlertsRefreshing) return;
        isAlertsRefreshing = true;
        btnRefreshAlerts.disabled = true;
        btnRefreshAlerts.classList.add("refreshing");
        try {
          await fetchAlerts();
          showToast("Alerts refreshed", "success");
        } catch (e) {
          showToast(`Alerts refresh failed: ${e.message}`, "error");
        } finally {
          isAlertsRefreshing = false;
          btnRefreshAlerts.disabled = false;
          btnRefreshAlerts.classList.remove("refreshing");
        }
      });
    }

    if (btnRefreshIncidentDetail) {
      let isDetailRefreshing = false;
      btnRefreshIncidentDetail.addEventListener("click", async () => {
        if (isDetailRefreshing) return;
        if (!selectedIncidentId) {
          showToast("No active incident selected to refresh", "info");
          return;
        }
        isDetailRefreshing = true;
        btnRefreshIncidentDetail.disabled = true;
        btnRefreshIncidentDetail.classList.add("refreshing");
        try {
          await loadIncidentDetails(selectedIncidentId);
          showToast(`Incident #${selectedIncidentId} refreshed`, "success");
        } catch (e) {
          showToast(`Incident refresh failed: ${e.message}`, "error");
        } finally {
          isDetailRefreshing = false;
          btnRefreshIncidentDetail.disabled = false;
          btnRefreshIncidentDetail.classList.remove("refreshing");
        }
      });
    }

    if (btnRefreshReportsList) {
      let isReportsRefreshing = false;
      btnRefreshReportsList.addEventListener("click", async () => {
        if (isReportsRefreshing) return;
        isReportsRefreshing = true;
        btnRefreshReportsList.disabled = true;
        btnRefreshReportsList.classList.add("refreshing");
        try {
          await fetchReports();
          showToast("Reports history refreshed", "success");
        } catch (e) {
          showToast(`Reports refresh failed: ${e.message}`, "error");
        } finally {
          isReportsRefreshing = false;
          btnRefreshReportsList.disabled = false;
          btnRefreshReportsList.classList.remove("refreshing");
        }
      });
    }

    // Back to Alerts / Investigations Buttons
    if (btnBackToAlerts) {
      btnBackToAlerts.addEventListener("click", () => switchView("alerts"));
    }
    if (btnBackToInvestigations) {
      btnBackToInvestigations.addEventListener("click", () => switchView("investigations"));
    }
    if (btnEmptyGotoAlerts) {
      btnEmptyGotoAlerts.addEventListener("click", () => switchView("alerts"));
    }
    if (btnEmptyGotoIncidents) {
      btnEmptyGotoIncidents.addEventListener("click", () => switchView("investigations"));
    }

    // Alerts Filters
    document.querySelectorAll(".filter-pill-group .filter-pill").forEach(pill => {
      pill.addEventListener("click", () => {
        document.querySelectorAll(".filter-pill-group .filter-pill").forEach(p => p.classList.remove("active"));
        pill.classList.add("active");
        alertSeverityFilter = pill.getAttribute("data-sev");
        renderAlertsGrid();
      });
    });

    if (alertsSigFilter) {
      alertsSigFilter.addEventListener("change", () => {
        alertSignatureFilter = alertsSigFilter.value;
        renderAlertsGrid();
      });
    }

    if (alertsSearchInput) {
      alertsSearchInput.addEventListener("input", () => {
        alertSearchQuery = alertsSearchInput.value.trim();
        renderAlertsGrid();
      });
    }

    if (btnToggleFocus && focusBtnLabel) {
      btnToggleFocus.addEventListener("click", () => {
        focusMode = !focusMode;
        focusBtnLabel.textContent = focusMode ? "Standard View" : "Focus Mode";
        btnToggleFocus.classList.toggle("btn-primary", focusMode);
        renderAlertsGrid();
      });
    }

    // Incident Filter Buttons
    if (filterAllBtn) {
      filterAllBtn.addEventListener("click", () => {
        incidentStatusFilter = "ALL";
        filterAllBtn.classList.add("active");
        if (filterOpenBtn) filterOpenBtn.classList.remove("active");
        if (filterClosedBtn) filterClosedBtn.classList.remove("active");
        renderIncidentsQueue();
      });
    }
    if (filterOpenBtn) {
      filterOpenBtn.addEventListener("click", () => {
        incidentStatusFilter = "OPEN";
        filterOpenBtn.classList.add("active");
        if (filterAllBtn) filterAllBtn.classList.remove("active");
        if (filterClosedBtn) filterClosedBtn.classList.remove("active");
        renderIncidentsQueue();
      });
    }
    if (filterClosedBtn) {
      filterClosedBtn.addEventListener("click", () => {
        incidentStatusFilter = "CLOSED";
        filterClosedBtn.classList.add("active");
        if (filterAllBtn) filterAllBtn.classList.remove("active");
        if (filterOpenBtn) filterOpenBtn.classList.remove("active");
        renderIncidentsQueue();
      });
    }

    // Incident Tabs Switching
    document.querySelectorAll(".inc-tab-btn").forEach(tab => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".inc-tab-btn").forEach(t => {
          t.classList.remove("active");
          t.setAttribute("aria-selected", "false");
        });
        tab.classList.add("active");
        tab.setAttribute("aria-selected", "true");

        const targetPaneId = tab.getAttribute("data-target");
        document.querySelectorAll(".incident-pane").forEach(p => {
          p.hidden = true;
          p.classList.remove("active");
        });

        const targetPane = document.getElementById(targetPaneId);
        if (targetPane) {
          targetPane.hidden = false;
          targetPane.classList.add("active");
        }
      });
    });

    // Workflow Action Buttons
    if (btnWfTriage) {
      btnWfTriage.addEventListener("click", () => transitionIncidentStatus("TRIAGE", "Triage initiated"));
    }
    if (btnWfInvestigating) {
      btnWfInvestigating.addEventListener("click", () => transitionIncidentStatus("INVESTIGATING", "Deep investigation underway"));
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
          showToast("Classification rationale is mandatory", "error");
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
          showToast(`Incident #${selectedIncidentId} classified as ${classification}`, "success");
          fetchIncidents();
          loadIncidentDetails(selectedIncidentId);
        } catch (e) {
          showToast(`Classification failed: ${e.message}`, "error");
        }
      });
    }
    if (btnWfRequestBlock) {
      btnWfRequestBlock.addEventListener("click", () => requestContainmentBlock());
    }
    if (btnSnapQuickContain) {
      btnSnapQuickContain.addEventListener("click", () => requestContainmentBlock());
    }
    if (btnSnapCreateReport) {
      btnSnapCreateReport.addEventListener("click", () => {
        switchView("reports");
        if (reportIncidentSelect && selectedIncidentId) {
          reportIncidentSelect.value = selectedIncidentId;
          updateReportPreview();
        }
      });
    }
    if (btnWfClose) {
      btnWfClose.addEventListener("click", () => {
        if (!selectedIncidentId) return;
        const rationale = prompt("Enter resolution rationale to close this incident:");
        if (rationale === null) return;
        if (!rationale.trim()) {
          showToast("A closure rationale is required to close an incident", "error");
          return;
        }
        transitionIncidentStatus("CLOSED", rationale.trim());
      });
    }

    // Copy Telemetry Button
    if (btnCopyTelemetry && evMessage) {
      btnCopyTelemetry.addEventListener("click", () => {
        navigator.clipboard.writeText(evMessage.textContent).then(() => {
          showToast("Copied raw message to clipboard", "info");
        });
      });
    }

    // Add Note Button
    if (btnAddNote && analystNoteTextarea) {
      btnAddNote.addEventListener("click", async () => {
        if (!selectedIncidentId) return;
        const noteText = analystNoteTextarea.value.trim();
        if (!noteText) {
          showToast("Note content cannot be empty", "error");
          analystNoteTextarea.focus();
          return;
        }

        btnAddNote.disabled = true;
        if (noteStatusMsg) noteStatusMsg.textContent = "Posting note...";

        try {
          await api(`/api/soc/incidents/${selectedIncidentId}/notes`, {
            method: "POST",
            body: JSON.stringify({ note_text: noteText })
          });
          analystNoteTextarea.value = "";
          showToast("Investigation note recorded", "success");
          if (noteStatusMsg) noteStatusMsg.textContent = "Note saved to audit trail.";
          loadIncidentDetails(selectedIncidentId, false);
        } catch (e) {
          showToast(`Failed to add note: ${e.message}`, "error");
          if (noteStatusMsg) noteStatusMsg.textContent = `Error: ${e.message}`;
        } finally {
          btnAddNote.disabled = false;
        }
      });
    }

    // Reports Form Inputs & Preview
    if (reportTitleInput) reportTitleInput.addEventListener("input", updateReportPreview);
    if (reportTypeSelect) reportTypeSelect.addEventListener("change", updateReportPreview);
    if (reportSummaryInput) reportSummaryInput.addEventListener("input", updateReportPreview);
    if (reportFindingsInput) reportFindingsInput.addEventListener("input", updateReportPreview);
    if (reportIncidentSelect) {
      reportIncidentSelect.addEventListener("change", () => {
        const incId = reportIncidentSelect.value;
        if (incId) {
          const inc = allIncidents.find(i => String(i.incident_id) === String(incId));
          if (inc) {
            if (reportTitleInput && (!reportTitleInput.value || reportTitleInput.value.startsWith("Incident #"))) {
              reportTitleInput.value = `Incident #${inc.incident_id}: ${inc.title || inc.signature} Dossier`;
            }
            if (reportSummaryInput && !reportSummaryInput.value) {
              reportSummaryInput.value = `Investigation of ${inc.technique_name || inc.signature} activity observed from host ${inc.source_ip}. Incident is in ${inc.status} state with ${inc.alert_count} correlated alerts.`;
            }
          }
        }
        updateReportPreview();
      });
    }

    if (btnPreviewReport) {
      btnPreviewReport.addEventListener("click", updateReportPreview);
    }
    if (btnSubmitReport) {
      btnSubmitReport.addEventListener("click", submitReport);
    }
    if (btnPrintReport) {
      btnPrintReport.addEventListener("click", () => {
        updateReportPreview();
        window.print();
      });
    }

    // Settings Token Form
    if (btnSetToken) {
      btnSetToken.addEventListener("click", () => {
        if (tokenInput) setToken(tokenInput.value);
      });
    }
    if (btnClearToken) btnClearToken.addEventListener("click", clearToken);
    if (btnToggleToken) btnToggleToken.addEventListener("click", toggleTokenVisibility);
    if (btnTestAuth) {
      btnTestAuth.addEventListener("click", async () => {
        try {
          await api("/api/soc/mitre-matrix");
          showToast("Analyst token successfully verified by backend!", "success");
        } catch (e) {
          showToast(`Token verification failed: ${e.message}`, "error");
        }
      });
    }

    if (tokenInput) {
      tokenInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          setToken(tokenInput.value);
        }
      });
    }

    // Quick Token Modal
    if (btnQuickToken && modalQuickToken) {
      btnQuickToken.addEventListener("click", () => {
        modalQuickToken.hidden = false;
        if (modalTokenInput) {
          modalTokenInput.value = window.SOC_ANALYST_TOKEN || "";
          modalTokenInput.focus();
        }
      });
    }
    if (btnBannerAuth && modalQuickToken) {
      btnBannerAuth.addEventListener("click", () => {
        modalQuickToken.hidden = false;
        if (modalTokenInput) {
          modalTokenInput.value = window.SOC_ANALYST_TOKEN || "";
          modalTokenInput.focus();
        }
      });
    }
    if (modalCloseToken && modalQuickToken) {
      modalCloseToken.addEventListener("click", () => {
        modalQuickToken.hidden = true;
      });
    }
    if (modalBtnSaveToken && modalQuickToken) {
      modalBtnSaveToken.addEventListener("click", () => {
        if (modalTokenInput) setToken(modalTokenInput.value);
        modalQuickToken.hidden = true;
      });
    }
    if (modalBtnClearToken && modalQuickToken) {
      modalBtnClearToken.addEventListener("click", () => {
        clearToken();
        modalQuickToken.hidden = true;
      });
    }

    // Close modal on escape or background click
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modalQuickToken && !modalQuickToken.hidden) {
        modalQuickToken.hidden = true;
      }
    });

    if (modalQuickToken) {
      modalQuickToken.addEventListener("click", (e) => {
        if (e.target === modalQuickToken) {
          modalQuickToken.hidden = true;
        }
      });
    }

    // Verify Mitigation Evidence Modal Listeners
    const modalVerifyEvidence = document.getElementById("modal-verify-evidence");
    const modalCloseVerify = document.getElementById("modal-close-verify");
    const modalBtnCancelVerify = document.getElementById("modal-btn-cancel-verify");
    const modalBtnConfirmVerify = document.getElementById("modal-btn-confirm-verify");
    const btnHelperNft = document.getElementById("btn-helper-nft-proof");
    const btnHelperDryRun = document.getElementById("btn-helper-dryrun-reject");

    if (modalCloseVerify) modalCloseVerify.addEventListener("click", closeVerificationModal);
    if (modalBtnCancelVerify) modalBtnCancelVerify.addEventListener("click", closeVerificationModal);

    if (btnHelperNft) {
      btnHelperNft.addEventListener("click", () => {
        const input = document.getElementById("modal-verify-input");
        const ip = pendingVerifyTargetIp || "127.0.0.1";
        if (input) {
          input.value = `table inet filter {\n    set blocked_ips {\n        type ipv4_addr\n        elements = { ${ip} }\n    }\n}`;
        }
      });
    }

    if (btnHelperDryRun) {
      btnHelperDryRun.addEventListener("click", () => {
        const input = document.getElementById("modal-verify-input");
        if (input) {
          input.value = `[DRY_RUN] Action completed via agent simulation. Target not found in kernel nftables set.`;
        }
      });
    }

    if (modalBtnConfirmVerify) {
      modalBtnConfirmVerify.addEventListener("click", async () => {
        if (!pendingVerifyActionId) return;
        const input = document.getElementById("modal-verify-input");
        const evidence = (input ? input.value : "").trim();
        if (!evidence) {
          showToast("Please enter verification evidence before confirming.", "error");
          return;
        }

        modalBtnConfirmVerify.disabled = true;
        try {
          const res = await api(`/api/soc/response-actions/${pendingVerifyActionId}/verify`, {
            method: "POST",
            body: JSON.stringify({ evidence: evidence })
          });
          if (res.verified) {
            showToast(`Action #${res.action_id} verified against host nftables! (Defense Status: VERIFIED)`, "success");
          } else {
            showToast(`Verification FAILED for Action #${res.action_id}: ${res.error || res.message}`, "error");
          }
          closeVerificationModal();
          refresh();
          if (selectedIncidentId) loadIncidentDetails(selectedIncidentId);
        } catch (e) {
          showToast(`Verification request failed: ${e.message}`, "error");
        } finally {
          modalBtnConfirmVerify.disabled = false;
        }
      });
    }

    if (modalVerifyEvidence) {
      modalVerifyEvidence.addEventListener("click", (e) => {
        if (e.target === modalVerifyEvidence) closeVerificationModal();
      });
    }
  }

  // Live UTC Clock
  function updateClock() {
    if (!clockEl) return;
    const now = new Date();
    clockEl.textContent = `UTC ${now.toISOString().substring(11, 19)}`;
  }

  // Live 1-Second Countdown Ticker for Active Temporary Controls
  function updateTemporaryControlCountdowns() {
    document.querySelectorAll("[data-expires-at]").forEach(el => {
      const expIso = el.getAttribute("data-expires-at");
      if (!expIso || expIso === "N/A" || expIso === "None" || expIso === "null" || expIso === "undefined") {
        el.textContent = "⏱️ Active";
        return;
      }
      const expMs = parseIsoTimestamp(expIso);
      if (expMs === null || isNaN(expMs)) {
        el.textContent = "⏱️ Active";
        return;
      }
      const diffSec = Math.floor((expMs - Date.now()) / 1000);
      if (diffSec <= 0) {
        el.textContent = "⏱️ Expired";
        el.classList.add("countdown-expired");
      } else {
        el.textContent = `⏱️ ${formatCountdown(diffSec)} remaining`;
        el.classList.remove("countdown-expired");
      }
    });
  }

  // =========================================================================
  // INITIALIZATION
  // =========================================================================
  setupEventListeners();
  updateClock();
  setInterval(updateClock, 1000);
  setInterval(updateTemporaryControlCountdowns, 1000);

  // Restore persisted auth token
  try {
    const savedToken = sessionStorage.getItem("SOC_ANALYST_TOKEN") || localStorage.getItem("SOC_ANALYST_TOKEN") || "";
    if (savedToken && !window.SOC_ANALYST_TOKEN) {
      window.SOC_ANALYST_TOKEN = savedToken;
      if (tokenInput) tokenInput.value = savedToken;
      if (modalTokenInput) modalTokenInput.value = savedToken;
    }
  } catch (_) {}

  // Check initial hash route
  handleHashChange();

  // Initial data fetch
  refresh();

  // Periodic polling every 10 seconds
  setInterval(refresh, 10000);

  // Expose helpers globally
  window.refresh = refresh;
  window.switchView = switchView;
  window.loadIncidentDetails = loadIncidentDetails;
  window.openVerificationModal = openVerificationModal;
  window.closeVerificationModal = closeVerificationModal;
  window.verifyResponseAction = verifyResponseAction;
})();
