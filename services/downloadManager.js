/**
 * @file downloadManager.js
 * @description Normalizes raw chrome.downloads.DownloadItem instances and extracts metadata.
 */

import {
  EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  DOCUMENT_EXTENSIONS,
  SCRIPT_EXTENSIONS,
  MEDIA_EXTENSIONS,
  CODE_EXTENSIONS
} from "./config.js";
import "../types/typedefs.js";

function getExtension(filename = "") {
  const match = /\.([a-zA-Z0-9]+)$/.exec(filename);
  return match ? match[1].toLowerCase() : "";
}

function getExtensionFromUrl(url = "") {
  try {
    const pathname = new URL(url).pathname;
    return getExtension(pathname);
  } catch {
    return "";
  }
}

function getDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function getFileCategory(ext = "") {
  if (EXECUTABLE_EXTENSIONS.has(ext)) return "executable";
  if (ARCHIVE_EXTENSIONS.has(ext)) return "archive";
  if (DOCUMENT_EXTENSIONS.has(ext)) return "document";
  if (SCRIPT_EXTENSIONS.has(ext)) return "script";
  if (MEDIA_EXTENSIONS.has(ext)) return "media";
  if (CODE_EXTENSIONS.has(ext)) return "code";
  return "other";
}

/**
 * Normalizes Chrome DownloadItem and checks native danger flags.
 * @param {chrome.downloads.DownloadItem} item
 * @returns {import("../types/typedefs.js").DownloadItemParsed}
 */
export function parseDownloadItem(item) {
  const rawFilename = (item.filename || "").split(/[\\/]/).pop();
  const url = item.finalUrl || item.url || "";
  const extension = getExtension(rawFilename || "") || getExtensionFromUrl(url);
  const filename = rawFilename || (url.split("/").pop().split("?")[0] || "download");
  const domain = getDomain(url);
  const category = getFileCategory(extension);
  
  // Native Chrome danger classification signal (Bug 6 fix)
  const danger = item.danger || "safe";
  const isDangerousNative = danger !== "safe" && danger !== "accepted";

  return {
    downloadId: item.id,
    url,
    domain,
    filename,
    extension,
    category,
    mime: item.mime || "application/octet-stream",
    bytesTotal: item.fileSize ?? item.totalBytes ?? -1,
    danger,
    isDangerousNative
  };
}
