/**
 * @file stateStore.js
 * @description chrome.storage.session backed state store for MV3 Service Worker lifecycle resilience.
 */

import "../types/typedefs.js";

/**
 * Save an in-flight download entry into chrome.storage.session.
 * @param {number} downloadId
 * @param {Object} entry
 */
export async function setInFlightScan(downloadId, entry) {
  const key = `inflight_${downloadId}`;
  await chrome.storage.session.set({ [key]: entry });
}

/**
 * Retrieve an in-flight download entry.
 * @param {number} downloadId
 * @returns {Promise<Object|null>}
 */
export async function getInFlightScan(downloadId) {
  const key = `inflight_${downloadId}`;
  const result = await chrome.storage.session.get(key);
  return result[key] || null;
}

/**
 * Remove an in-flight download entry.
 * @param {number} downloadId
 */
export async function removeInFlightScan(downloadId) {
  const key = `inflight_${downloadId}`;
  await chrome.storage.session.remove(key);
}

/**
 * Get all active in-flight pending scans.
 * @returns {Promise<import("../types/typedefs.js").ScanRecord[]>}
 */
export async function getAllInFlightScans() {
  const all = await chrome.storage.session.get(null);
  const records = [];
  for (const [key, val] of Object.entries(all)) {
    if (key.startsWith("inflight_") && val && val.record) {
      records.push(val.record);
    }
  }
  return records;
}
