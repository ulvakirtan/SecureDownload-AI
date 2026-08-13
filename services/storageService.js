/**
 * @file storageService.js
 * @description Central storage management for options, history, and transient cache.
 */

import "../types/typedefs.js";

/** @type {import("../types/typedefs.js").ExtensionSettings} */
export const DEFAULT_SETTINGS = {
  autoAnalyze: true,
  blockDangerousByDefault: false,
  virusTotalApiKey: "",
  safeBrowsingApiKey: "",
  nvdApiKey: "",
  extraTrustedDomains: [],
  knownGoodHashes: {},
  theme: "dark"
};

const MAX_HISTORY_ITEMS = 100;

/**
 * Get current settings merged with default values.
 * @returns {Promise<import("../types/typedefs.js").ExtensionSettings>}
 */
export async function getSettings() {
  const result = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(result.settings || {}) };
}

/**
 * Save settings to chrome.storage.local.
 * @param {Partial<import("../types/typedefs.js").ExtensionSettings>} patch
 * @returns {Promise<import("../types/typedefs.js").ExtensionSettings>}
 */
export async function saveSettings(patch) {
  const current = await getSettings();
  const updated = { ...current, ...patch };
  await chrome.storage.local.set({ settings: updated });
  return updated;
}

/**
 * Save a scan record into local history.
 * @param {import("../types/typedefs.js").ScanRecord} record
 */
export async function saveScanRecord(record) {
  const result = await chrome.storage.local.get("scanHistory");
  /** @type {import("../types/typedefs.js").ScanRecord[]} */
  const history = result.scanHistory || [];

  const existingIdx = history.findIndex((item) => item.downloadId === record.downloadId);
  if (existingIdx >= 0) {
    history[existingIdx] = record;
  } else {
    history.unshift(record);
    if (history.length > MAX_HISTORY_ITEMS) {
      history.pop();
    }
  }

  await chrome.storage.local.set({ scanHistory: history });
}

/**
 * Retrieve scan history.
 * @returns {Promise<import("../types/typedefs.js").ScanRecord[]>}
 */
export async function getHistory() {
  const result = await chrome.storage.local.get("scanHistory");
  return result.scanHistory || [];
}

/**
 * Calculate historical aggregate scan statistics.
 * @returns {Promise<{totalScans: number, dangerousBlocked: number, averageTrustScore: number, highTrustCount: number}>}
 */
export async function getStats() {
  const history = await getHistory();
  if (!history.length) {
    return { totalScans: 0, dangerousBlocked: 0, averageTrustScore: 0, highTrustCount: 0 };
  }

  const totalScans = history.length;
  const dangerousBlocked = history.filter(
    (h) => h.riskLevel === "dangerous" && (h.action === "deleted" || h.action === "paused")
  ).length;
  const highTrustCount = history.filter((h) => h.trustScore >= 80).length;
  const sumScores = history.reduce((acc, h) => acc + (h.trustScore || 0), 0);
  const averageTrustScore = Math.round(sumScores / totalScans);

  return { totalScans, dangerousBlocked, averageTrustScore, highTrustCount };
}

/**
 * Clear scan history.
 */
export async function clearHistory() {
  await chrome.storage.local.set({ scanHistory: [] });
}

/**
 * Transient memory/storage cache lookup.
 * @param {string} key
 * @returns {Promise<any|null>}
 */
export async function getCached(key) {
  const storageKey = `cache_${key}`;
  const result = await chrome.storage.local.get(storageKey);
  const cached = result[storageKey];
  if (!cached) return null;
  if (Date.now() > cached.expiresAt) {
    await chrome.storage.local.remove(storageKey);
    return null;
  }
  return cached.data;
}

/**
 * Set transient memory/storage cache.
 * @param {string} key
 * @param {any} data
 * @param {number} ttlMs
 */
export async function setCached(key, data, ttlMs) {
  const storageKey = `cache_${key}`;
  const payload = { data, expiresAt: Date.now() + ttlMs };
  await chrome.storage.local.set({ [storageKey]: payload });
}
