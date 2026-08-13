/**
 * @file notificationService.js
 * @description Creates precise desktop notifications reflecting actual download action state.
 */

import "../types/typedefs.js";

/**
 * Triggers a Chrome notification with accurate status indicators.
 * @param {import("../types/typedefs.js").ScanRecord} record
 * @param {boolean} autoResumed
 */
export function notifyResult(record, autoResumed) {
  const isDangerous = record.riskLevel === "dangerous";
  const notificationId = `sd_${record.downloadId}`;

  let title = "SecureDownload AI";
  let message = `${record.filename} — Trust Score: ${record.trustScore}/100`;
  const buttons = [];

  if (isDangerous) {
    if (record.action === "deleted") {
      title = "Dangerous Download Blocked & Deleted";
      message = `Threat detected for ${record.filename}. The file was automatically removed.`;
      buttons.push({ title: "View Details" });
    } else {
      title = "Dangerous Download Paused for Review";
      message = `Threat indicators found for ${record.filename}. Action required in extension menu.`;
      buttons.push({ title: "Delete File" }, { title: "Review Details" });
    }
  } else if (autoResumed) {
    title = "Download Verified & Resumed";
    message = `${record.filename} passed all security checks (Score: ${record.trustScore}/100).`;
  } else {
    title = "Download Analysis Complete";
    message = `${record.filename} scanned (Score: ${record.trustScore}/100). Click to review.`;
    buttons.push({ title: "Open Dashboard" });
  }

  chrome.notifications.create(notificationId, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title,
    message,
    buttons,
    priority: isDangerous ? 2 : 0
  });
}
