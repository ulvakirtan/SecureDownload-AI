/**
 * @file background/main.js
 * @description Primary orchestration logic for SecureDownload AI background service worker.
 */

import { parseDownloadItem } from "../services/downloadManager.js";
import { verifySource, verifyHttps, analyzeWebsiteVulnerabilities, fetchSiteHeaders, isAuditableWebUrl } from "../services/webAuditService.js";
import { verifyPublisher } from "../services/publisherService.js";
import { checkFileIntegrity } from "../services/fileIntegrityService.js";
import { checkVirusTotal, checkSafeBrowsing } from "../services/threatService.js";
import { checkVulnerabilities } from "../services/vulnerabilityService.js";
import { calculateTrustScore } from "../services/trustEngine.js";
import { getRecommendation } from "../services/recommendationEngine.js";
import { saveScanRecord, getSettings, getCached, setCached } from "../services/storageService.js";
import { notifyResult } from "../services/notificationService.js";
import { setInFlightScan, getInFlightScan, removeInFlightScan, getAllInFlightScans } from "./stateStore.js";
import { CACHE_TTL_MS } from "../services/config.js";
import "../types/typedefs.js";

// Initialize download monitor listener
chrome.downloads.onCreated.addListener(async (item) => {
  console.log("[SecureDownload AI] onCreated fired:", item.id, item.url, item.filename);

  const settings = await getSettings();
  if (!settings.autoAnalyze) {
    console.log("[SecureDownload AI] autoAnalyze disabled — skipping.");
    return;
  }

  let freshItem = item;
  try {
    const [searched] = await chrome.downloads.search({ id: item.id });
    if (searched) freshItem = searched;
  } catch (err) {
    console.warn("[SecureDownload AI] downloads.search failed, using raw item", err);
  }

  const parsed = parseDownloadItem(freshItem);

  try {
    await chrome.downloads.pause(item.id);
    console.log("[SecureDownload AI] paused download", item.id);
  } catch (err) {
    console.warn("[SecureDownload AI] could not pause (may already be complete):", err);
  }

  runAnalysisPipeline(parsed, settings)
    .then(() => console.log("[SecureDownload AI] pipeline complete for", parsed.filename))
    .catch(async (err) => {
      // Fix for Bug 15: Handle pipeline failure gracefully instead of failing silently
      console.error("[SecureDownload AI] pipeline failed:", err);
      try {
        await chrome.downloads.resume(parsed.downloadId);
      } catch {}
      chrome.notifications.create(`sd_err_${parsed.downloadId}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "Scan Error — Download Resumed",
        message: `Security pipeline encountered an error for ${parsed.filename}. Download resumed unscanned.`,
        priority: 1
      });
    });
});

/**
 * Runs multi-signal security pipeline.
 * @param {import("../types/typedefs.js").DownloadItemParsed} parsed
 * @param {import("../types/typedefs.js").ExtensionSettings} settings
 */
async function runAnalysisPipeline(parsed, settings) {
  const headers = await fetchSiteHeaders(parsed.url);
  const websiteSecurity = analyzeWebsiteVulnerabilities(parsed.url, headers, settings.extraTrustedDomains);

  // Fix for Bug 4: Run integrity check first so SHA-256 is threaded into VirusTotal lookup
  const integrityResult = await checkFileIntegrity(parsed.url, settings.knownGoodHashes, parsed.filename);

  const [sourceResult, httpsResult, publisherResult, vtResult, sbResult, vulnResult] =
    await Promise.all([
      Promise.resolve(verifySource(parsed.domain, settings.extraTrustedDomains)),
      Promise.resolve(verifyHttps(parsed.url)),
      Promise.resolve(verifyPublisher(parsed, settings.extraTrustedDomains)),
      cachedThreatCheck("vt", parsed.url, () =>
        checkVirusTotal({ url: parsed.url, sha256: integrityResult.calculatedHash }, settings.virusTotalApiKey)
      ),
      cachedThreatCheck("sb", parsed.url, () => checkSafeBrowsing(parsed.url, settings.safeBrowsingApiKey)),
      cachedThreatCheck("nvd", parsed.filename, () => checkVulnerabilities(parsed.filename, settings.nvdApiKey))
    ]);

  const trustResult = calculateTrustScore({
    officialWebsiteScore: sourceResult.officialWebsiteScore,
    publisherVerificationScore: publisherResult.publisherVerificationScore,
    vtScore: vtResult.vtScore,
    vtApplicable: vtResult.status !== "not_configured",
    vulnerabilityScore: vulnResult.vulnerabilityScore,
    vulnerabilityApplicable: !["no_version_detected", "error"].includes(vulnResult.status),
    httpsScore: httpsResult.httpsScore,
    integrityScore: integrityResult.integrityScore,
    integrityApplicable: ["matches_known_good", "hash_mismatch_possible_tampering"].includes(integrityResult.status),
    sourceReputationScore: sourceResult.sourceReputationScore,
    safeBrowsingFlagged: sbResult.flagged,
    isDangerousNative: parsed.isDangerousNative // Bug 6 fix
  });

  const recommendation = getRecommendation(trustResult, {
    looksLikeTyposquat: sourceResult.looksLikeTyposquat,
    integrityStatus: integrityResult.status,
    isDangerousNative: parsed.isDangerousNative
  });

  const record = {
    downloadId: parsed.downloadId,
    filename: parsed.filename,
    extension: parsed.extension,
    category: parsed.category,
    url: parsed.url,
    domain: parsed.domain,
    scannedAt: new Date().toISOString(),
    trustScore: trustResult.trustScore,
    contributions: trustResult.contributions,
    checksApplicable: trustResult.checksApplicable,
    checksTotal: trustResult.checksTotal,
    riskLevel: recommendation.riskLevel,
    recommendation,
    websiteSecurity,
    details: {
      source: sourceResult,
      https: httpsResult,
      publisher: publisherResult,
      integrity: integrityResult,
      virusTotal: vtResult,
      safeBrowsing: sbResult,
      vulnerability: vulnResult,
      websiteSecurity
    },
    action: "pending"
  };

  // Fix for Bug 5: Depend strictly on recommendation.riskLevel rather than redundant trustScore >= 80 check
  const isSafe = recommendation.riskLevel === "safe" || recommendation.riskLevel === "low_risk";
  let autoResumed = false;

  if (isSafe) {
    try {
      await chrome.downloads.resume(parsed.downloadId);
      console.log("[SecureDownload AI] auto-resumed safe download", parsed.downloadId);
      record.action = "resumed";
      autoResumed = true;
    } catch (err) {
      console.warn("[SecureDownload AI] could not auto-resume download:", err);
    }
  } else {
    record.action = "paused";
  }

  await setInFlightScan(parsed.downloadId, { parsed, record });
  await saveScanRecord(record);

  const settingsNow = await getSettings();
  if (settingsNow.blockDangerousByDefault && recommendation.riskLevel === "dangerous") {
    await resolveDownload(parsed.downloadId, "deleted");
    record.action = "deleted";
  }

  notifyResult(record, autoResumed);
  chrome.runtime.sendMessage({ type: "SD_ANALYSIS_COMPLETE", record, autoResumed }).catch(() => {});
}

async function cachedThreatCheck(prefix, keyMaterial, fn) {
  const cacheKey = `${prefix}:${keyMaterial}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;
  const result = await fn();
  await setCached(cacheKey, result, CACHE_TTL_MS[prefix === "vt" ? "virusTotal" : prefix === "sb" ? "safeBrowsing" : "nvd"]);
  return result;
}

async function resolveDownload(downloadId, action) {
  const entry = await getInFlightScan(downloadId);
  if (entry) {
    entry.record.action = action;
    await saveScanRecord(entry.record);
  }

  if (action === "resumed") {
    await chrome.downloads.resume(downloadId).catch(() => {});
  } else if (action === "deleted") {
    await chrome.downloads.cancel(downloadId).catch(() => {});
    await chrome.downloads.removeFile(downloadId).catch(() => {});
  }
  await removeInFlightScan(downloadId);
}

// Runtime message dispatcher
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "SD_GET_PENDING") {
    getAllInFlightScans().then((pending) => sendResponse({ pending }));
    return true;
  }
  if (message.type === "SD_RESOLVE_DOWNLOAD") {
    resolveDownload(message.downloadId, message.action).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (message.type === "SD_ANALYZE_WEBSITE") {
    (async () => {
      if (!isAuditableWebUrl(message.url)) {
        sendResponse({ audit: null, error: "Internal or non-HTTP page cannot be audited." });
        return;
      }
      const settings = await getSettings();
      const headers = await fetchSiteHeaders(message.url);
      const audit = analyzeWebsiteVulnerabilities(message.url, headers, settings.extraTrustedDomains);
      sendResponse({ audit });
    })();
    return true;
  }
  if (message.type === "SD_GET_ACTIVE_TAB_SECURITY") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || !isAuditableWebUrl(tab.url)) {
          sendResponse({ error: "Internal browser or non-HTTP page cannot be audited.", isInternal: true, url: tab ? tab.url : "" });
          return;
        }
        const settings = await getSettings();
        const headers = await fetchSiteHeaders(tab.url);
        const audit = analyzeWebsiteVulnerabilities(tab.url, headers, settings.extraTrustedDomains);
        sendResponse({ tabUrl: tab.url, tabTitle: tab.title, audit });
      } catch (err) {
        sendResponse({ error: String(err) });
      }
    })();
    return true;
  }
  return false;
});

// Desktop notification interactions
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  const downloadId = Number(notificationId.replace("sd_", ""));
  const entry = await getInFlightScan(downloadId);
  if (!entry) return;

  const isDangerous = entry.record.riskLevel === "dangerous";
  if (isDangerous && buttonIndex === 0) {
    await resolveDownload(downloadId, "deleted");
  } else {
    chrome.action.openPopup().catch(() => {});
  }
});
