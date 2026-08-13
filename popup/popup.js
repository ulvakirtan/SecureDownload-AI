/**
 * @file popup.js
 * @description Secure presentation & interaction layer for the SecureDownload AI Popup.
 */

import { getHistory, getStats, getSettings, saveSettings } from "../services/storageService.js";
import { WEIGHTS } from "../services/config.js";
import "../types/typedefs.js";

const FACTOR_META = [
  { key: "officialWebsite", label: "Official Website", from: (r) => r.details.source.officialWebsiteScore, applicable: () => true },
  { key: "publisherVerification", label: "Publisher Trust", from: (r) => r.details.publisher.publisherVerificationScore, applicable: () => true },
  { key: "virusTotal", label: "VirusTotal", from: (r) => r.details.virusTotal.vtScore, applicable: (r) => r.details.virusTotal.status !== "not_configured" },
  { key: "vulnerability", label: "Vulnerabilities", from: (r) => r.details.vulnerability.vulnerabilityScore, applicable: (r) => !["no_version_detected", "error"].includes(r.details.vulnerability.status) },
  { key: "https", label: "HTTPS Security", from: (r) => r.details.https.httpsScore, applicable: () => true },
  { key: "fileIntegrity", label: "File Integrity", from: (r) => r.details.integrity.integrityScore, applicable: (r) => ["matches_known_good", "hash_mismatch_possible_tampering"].includes(r.details.integrity.status) },
  { key: "sourceReputation", label: "Source Rep.", from: (r) => r.details.source.sourceReputationScore, applicable: () => true }
];

const GAUGE_R = 82;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_R;

const els = {
  tabDownload: document.getElementById("tabDownload"),
  tabWebsite: document.getElementById("tabWebsite"),
  tabHistory: document.getElementById("tabHistory"),

  downloadView: document.getElementById("downloadView"),
  websiteView: document.getElementById("websiteView"),
  historyPanel: document.getElementById("historyPanel"),

  emptyState: document.getElementById("emptyState"),
  resultView: document.getElementById("resultView"),
  fileExtBadge: document.getElementById("fileExtBadge"),
  fileName: document.getElementById("fileName"),
  fileDomain: document.getElementById("fileDomain"),

  gaugeProgress: document.getElementById("gaugeProgress"),
  gaugeScore: document.getElementById("gaugeScore"),
  gaugeRiskBadge: document.getElementById("gaugeRiskBadge"),
  gaugeRiskLabel: document.getElementById("gaugeRiskLabel"),

  recommendationBanner: document.getElementById("recommendationBanner"),
  recHeadline: document.getElementById("recHeadline"),
  recDetail: document.getElementById("recDetail"),
  factorList: document.getElementById("factorList"),

  resumeBtn: document.getElementById("resumeBtn"),
  deleteBtn: document.getElementById("deleteBtn"),
  detailsBtn: document.getElementById("detailsBtn"),

  scanActiveTabBtn: document.getElementById("scanActiveTabBtn"),
  scanBtnText: document.getElementById("scanBtnText"),
  webDomain: document.getElementById("webDomain"),
  webSslBadge: document.getElementById("webSslBadge"),
  webScoreRing: document.getElementById("webScoreRing"),
  webScoreBadge: document.getElementById("webScoreBadge"),
  hstsStatus: document.getElementById("hstsStatus"),
  cspStatus: document.getElementById("cspStatus"),
  corsStatus: document.getElementById("corsStatus"),
  xfoStatus: document.getElementById("xfoStatus"),
  vulnList: document.getElementById("vulnList"),

  historyList: document.getElementById("historyList"),
  statsLine: document.getElementById("statsLine"),
  optionsBtn: document.getElementById("optionsBtn"),
  themeToggleBtn: document.getElementById("themeToggleBtn")
};

let currentRecord = null;
let displayedScore = 0;
let animationFrameId = null;

init();

async function init() {
  await setupTheme();
  wireTabsAndButtons();

  if (els.gaugeProgress) {
    els.gaugeProgress.style.strokeDasharray = `${GAUGE_CIRCUMFERENCE}`;
    els.gaugeProgress.style.strokeDashoffset = `${GAUGE_CIRCUMFERENCE}`;
  }

  const { pending } = await chrome.runtime.sendMessage({ type: "SD_GET_PENDING" }).catch(() => ({ pending: [] }));

  if (pending && pending.length) {
    renderResult(pending[0]);
  } else {
    const history = await getHistory();
    if (history.length) {
      renderResult(history[0], { readOnly: true });
    } else {
      showEmptyState();
    }
  }

  renderStatsLine();
  scanActiveTab();
}

async function setupTheme() {
  const settings = await getSettings();
  document.documentElement.setAttribute("data-theme", settings.theme || "dark");

  if (els.themeToggleBtn) {
    els.themeToggleBtn.addEventListener("click", async () => {
      const current = document.documentElement.getAttribute("data-theme");
      const next = current === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      await saveSettings({ theme: next });
    });
  }
}

function wireTabsAndButtons() {
  els.tabDownload.addEventListener("click", () => switchTab("download"));
  els.tabWebsite.addEventListener("click", () => switchTab("website"));
  els.tabHistory.addEventListener("click", () => {
    switchTab("history");
    renderHistoryView();
  });

  els.optionsBtn.addEventListener("click", () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL("options/options.html"));
    }
  });

  els.scanActiveTabBtn.addEventListener("click", scanActiveTab);

  els.resumeBtn.addEventListener("click", () => resolveCurrent("resumed"));
  els.deleteBtn.addEventListener("click", () => resolveCurrent("deleted"));
  els.detailsBtn.addEventListener("click", () => chrome.tabs.create({ url: "chrome://downloads" }));
}

function switchTab(target) {
  [els.tabDownload, els.tabWebsite, els.tabHistory].forEach((btn) => btn.classList.remove("active"));
  [els.downloadView, els.websiteView, els.historyPanel].forEach((view) => view.classList.add("hidden"));

  if (target === "download") {
    els.tabDownload.classList.add("active");
    els.downloadView.classList.remove("hidden");
  } else if (target === "website") {
    els.tabWebsite.classList.add("active");
    els.websiteView.classList.remove("hidden");
  } else if (target === "history") {
    els.tabHistory.classList.add("active");
    els.historyPanel.classList.remove("hidden");
  }
}

function showEmptyState() {
  els.emptyState.classList.remove("hidden");
  els.resultView.classList.add("hidden");
}

function scoreColor(score) {
  if (score >= 80) return "var(--color-safe)";
  if (score >= 65) return "var(--color-low)";
  if (score >= 50) return "var(--color-medium)";
  return "var(--color-danger)";
}

/**
 * Render Scan Result with strict textContent assignment (Fix for Bug 1 XSS).
 * @param {import("../types/typedefs.js").ScanRecord} record
 * @param {Object} [options]
 * @param {boolean} [options.readOnly=false]
 */
function renderResult(record, { readOnly = false } = {}) {
  currentRecord = record;
  els.emptyState.classList.add("hidden");
  els.resultView.classList.remove("hidden");

  // Secure Text Content Assignment (Prevents XSS)
  els.fileExtBadge.textContent = (record.extension || "file").toUpperCase();
  els.fileName.textContent = record.filename || "download";
  els.fileName.title = record.filename || "";
  els.fileDomain.textContent = record.domain || "local";

  animateGauge(record.trustScore);
  setRiskBadge(record.riskLevel, record.trustScore);
  setRecommendationBanner(record.recommendation);
  renderFactorList(record);

  if (readOnly || record.action !== "pending") {
    els.resumeBtn.classList.add("hidden");
    els.deleteBtn.classList.add("hidden");
  } else {
    els.resumeBtn.classList.remove("hidden");
    els.deleteBtn.classList.remove("hidden");
  }

  if (record.websiteSecurity) {
    renderWebAuditView(record.websiteSecurity);
  } else {
    renderInternalWebAuditView(record.url || record.domain);
  }
}

function animateGauge(targetScore) {
  if (animationFrameId) cancelAnimationFrame(animationFrameId);

  const startScore = displayedScore;
  const startTime = performance.now();
  const duration = 600;

  function step(now) {
    const progress = Math.min(1, (now - startTime) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    displayedScore = Math.round(startScore + (targetScore - startScore) * eased);

    els.gaugeScore.textContent = displayedScore;
    const color = scoreColor(displayedScore);
    const offset = GAUGE_CIRCUMFERENCE * (1 - displayedScore / 100);

    els.gaugeProgress.style.strokeDashoffset = `${offset}`;
    els.gaugeProgress.style.stroke = color;
    els.gaugeScore.style.color = color;

    if (progress < 1) {
      animationFrameId = requestAnimationFrame(step);
    }
  }

  animationFrameId = requestAnimationFrame(step);
}

function setRiskBadge(riskLevel, score) {
  els.gaugeRiskBadge.className = `gauge-risk-pill risk-${riskLevel}`;
  let label = "SAFE";
  if (riskLevel === "low_risk") label = "LOW RISK";
  else if (riskLevel === "medium_risk") label = "MEDIUM RISK";
  else if (riskLevel === "dangerous") label = "HIGH RISK";

  els.gaugeRiskLabel.textContent = label;
}

function setRecommendationBanner(rec) {
  if (!rec) return;
  els.recommendationBanner.className = `recommendation-banner banner-${rec.riskLevel}`;
  els.recHeadline.textContent = rec.headline || "Analysis Complete";
  els.recDetail.textContent = rec.summary || "";
}

/**
 * Render security factors list where factor row container itself is the solid progress bar.
 * @param {import("../types/typedefs.js").ScanRecord} record
 */
function renderFactorList(record) {
  els.factorList.textContent = "";

  for (const factor of FACTOR_META) {
    if (!factor.applicable(record)) continue;
    const val = factor.from(record);
    const weightPct = Math.round((WEIGHTS[factor.key] || 0) * 100);

    const row = document.createElement("div");
    row.className = "factor-row";

    // Factor Row Solid Progress Fill
    const fill = document.createElement("div");
    if (val !== null && val !== undefined) {
      fill.className = "factor-row-fill";
      const clampedVal = Math.max(0, Math.min(100, val));
      const color = scoreColor(clampedVal);
      fill.style.width = `${clampedVal}%`;
      fill.style.backgroundColor = color;
    } else {
      fill.className = "factor-row-fill na";
    }
    row.appendChild(fill);

    const labelWrap = document.createElement("div");
    labelWrap.className = "factor-label-wrap";

    const label = document.createElement("span");
    label.className = "factor-label";
    label.textContent = factor.label;

    const weight = document.createElement("span");
    weight.className = "factor-weight";
    weight.textContent = `${weightPct}% weight`;

    labelWrap.appendChild(label);
    labelWrap.appendChild(weight);

    const scoreBadge = document.createElement("span");
    scoreBadge.className = "factor-score";
    scoreBadge.textContent = val !== null && val !== undefined ? `${val}` : "N/A";

    row.appendChild(labelWrap);
    row.appendChild(scoreBadge);
    els.factorList.appendChild(row);
  }
}

async function scanActiveTab() {
  els.scanBtnText.textContent = "Scanning...";
  const res = await chrome.runtime.sendMessage({ type: "SD_GET_ACTIVE_TAB_SECURITY" }).catch(() => null);
  els.scanBtnText.textContent = "Scan Current Webpage";

  if (res && res.audit) {
    renderWebAuditView(res.audit);
  } else if (res && (res.isInternal || res.error)) {
    renderInternalWebAuditView(res.url || "");
  }
}

/**
 * Render Web Audit for Internal or non-HTTP browser pages.
 * @param {string} [rawUrl=""]
 */
function renderInternalWebAuditView(rawUrl = "") {
  let displayDomain = "Internal Browser Page";
  if (rawUrl) {
    try {
      const parsed = new URL(rawUrl);
      displayDomain = `${parsed.protocol.replace(":", "")}:// page`;
    } catch {
      displayDomain = rawUrl;
    }
  }

  els.webDomain.textContent = displayDomain;
  els.webSslBadge.textContent = "SYSTEM PAGE";
  els.webSslBadge.className = "badge";
  els.webSslBadge.style.backgroundColor = "var(--bg-card)";
  els.webSslBadge.style.color = "var(--text-muted)";
  els.webSslBadge.style.border = "1px solid var(--border-color)";

  els.webScoreBadge.textContent = "N/A";
  els.webScoreRing.style.background = "var(--bg-card)";

  setValPill(els.hstsStatus, false, "N/A");
  setValPill(els.cspStatus, false, "N/A");
  setValPill(els.corsStatus, false, "N/A");
  setValPill(els.xfoStatus, false, "N/A");

  els.vulnList.textContent = "";
  const infoCard = document.createElement("div");
  infoCard.className = "vuln-card clean";

  const title = document.createElement("div");
  title.className = "v-title";
  title.textContent = "Browser Internal / Non-HTTP Page";

  const desc = document.createElement("p");
  desc.className = "v-harm text-muted";
  desc.textContent = "Internal browser URLs (chrome://, chrome-extension://, newtab, about:) are restricted system pages and cannot be audited for external web security headers.";

  infoCard.appendChild(title);
  infoCard.appendChild(desc);
  els.vulnList.appendChild(infoCard);
}

/**
 * Render Website Vulnerability Audit (Fix for Bug 1 XSS).
 * @param {import("../types/typedefs.js").WebAuditResult} audit
 */
function renderWebAuditView(audit) {
  if (!audit) return;

  els.webDomain.textContent = audit.domain || "Website Audit";
  els.webSslBadge.textContent = audit.isHttps ? "HTTPS SSL" : "HTTP INSECURE";
  els.webSslBadge.className = `badge ${audit.isHttps ? "badge-safe" : "badge-danger"}`;

  const score = audit.webSecurityScore ?? 50;
  els.webScoreBadge.textContent = score;
  els.webScoreRing.style.background = scoreColor(score);

  const sh = audit.headersPresent || {};
  setValPill(els.hstsStatus, sh.hsts, sh.hsts ? "Active" : "Missing");
  setValPill(els.cspStatus, sh.csp, sh.csp ? "Active" : "Missing");
  setValPill(els.corsStatus, sh.cors, sh.cors ? "Configured" : "Wildcard/*");
  setValPill(els.xfoStatus, sh.xfo, sh.xfo ? "Active" : "Missing");

  // Secure DOM Element Construction (Fix for Bug 1 XSS)
  els.vulnList.textContent = "";
  const vulns = audit.vulnerabilities || [];

  if (!vulns.length) {
    const cleanCard = document.createElement("div");
    cleanCard.className = "vuln-card clean";

    const title = document.createElement("div");
    title.className = "v-title";
    title.textContent = "No Critical Vulnerabilities Detected";

    const desc = document.createElement("p");
    desc.className = "v-harm text-muted";
    desc.textContent = "The website enforces HTTPS, security headers, and domain trust parameters.";

    cleanCard.appendChild(title);
    cleanCard.appendChild(desc);
    els.vulnList.appendChild(cleanCard);
    return;
  }

  for (const v of vulns) {
    const card = document.createElement("div");
    card.className = "vuln-card";

    const header = document.createElement("div");
    header.className = "vuln-header";

    const vTitle = document.createElement("span");
    vTitle.className = "v-title";
    vTitle.textContent = v.title || "Vulnerability Alert";

    const tag = document.createElement("span");
    tag.className = `threat-tag level-${(v.severity || "medium").toLowerCase()}`;
    tag.textContent = `${(v.severity || "MEDIUM").toUpperCase()} THREAT`;

    header.appendChild(vTitle);
    header.appendChild(tag);
    card.appendChild(header);

    if (v.description) {
      const owasp = document.createElement("div");
      owasp.className = "owasp-badge";
      owasp.textContent = v.description;
      card.appendChild(owasp);
    }

    const harmBox = document.createElement("div");
    harmBox.className = "harm-box";

    const harmTitle = document.createElement("span");
    harmTitle.className = "harm-title";
    harmTitle.textContent = "Unethical Harm & Exploit Risk";

    const harmDesc = document.createElement("p");
    harmDesc.className = "v-harm";
    harmDesc.textContent = v.harmScenario || "";

    harmBox.appendChild(harmTitle);
    harmBox.appendChild(harmDesc);
    card.appendChild(harmBox);

    els.vulnList.appendChild(card);
  }
}

function setValPill(el, isGood, text) {
  el.textContent = text || (isGood ? "Active" : "Missing");
  el.className = `h-val ${isGood ? "val-good" : "val-warn"}`;
}

async function resolveCurrent(action) {
  if (!currentRecord) return;
  await chrome.runtime.sendMessage({
    type: "SD_RESOLVE_DOWNLOAD",
    downloadId: currentRecord.downloadId,
    action
  });
  currentRecord.action = action;
  els.resumeBtn.classList.add("hidden");
  els.deleteBtn.classList.add("hidden");
  renderStatsLine();
}

async function renderStatsLine() {
  const stats = await getStats();
  els.statsLine.textContent = `${stats.totalScans} scanned · ${stats.dangerousBlocked} blocked`;
}

/**
 * Render scan audit history with secure DOM element creation (Fix for Bug 1 XSS & Bug 7 duplication).
 */
async function renderHistoryView() {
  const history = await getHistory();
  els.historyList.textContent = "";

  if (!history.length) {
    const emptyNotice = document.createElement("p");
    emptyNotice.style.color = "var(--text-muted)";
    emptyNotice.style.fontSize = "12px";
    emptyNotice.style.padding = "12px 6px";
    emptyNotice.textContent = "No scan audit history recorded yet.";
    els.historyList.appendChild(emptyNotice);
    return;
  }

  for (const record of history) {
    const item = document.createElement("div");
    item.className = "history-item";

    const meta = document.createElement("div");
    meta.className = "h-meta";

    const name = document.createElement("span");
    name.className = "h-name";
    name.textContent = record.filename || "download";
    name.title = record.filename || "";

    const sub = document.createElement("span");
    sub.className = "h-sub";
    sub.textContent = `${record.domain || "local"} · ${(record.extension || "file").toUpperCase()}`;

    meta.appendChild(name);
    meta.appendChild(sub);

    const badge = document.createElement("span");
    badge.className = "h-score-badge";
    const badgeColor = scoreColor(record.trustScore);
    badge.style.background = `${badgeColor}20`;
    badge.style.color = badgeColor;
    badge.style.border = `1px solid ${badgeColor}40`;
    badge.textContent = `${record.trustScore}`;

    item.appendChild(meta);
    item.appendChild(badge);

    item.addEventListener("click", () => {
      switchTab("download");
      renderResult(record, { readOnly: true });
    });

    els.historyList.appendChild(item);
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SD_ANALYSIS_COMPLETE") {
    renderResult(message.record);
    renderStatsLine();
  }
});
