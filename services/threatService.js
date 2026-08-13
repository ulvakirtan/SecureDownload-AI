/**
 * @file threatService.js
 * @description Integrates with VirusTotal API v3 (URL & SHA-256 hash reports) and Google Safe Browsing API.
 */

import { ENDPOINTS } from "./config.js";
import "../types/typedefs.js";

function toBase64Url(str) {
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Check VirusTotal threat intelligence for URL or File SHA-256 hash.
 * @param {{url: string, sha256?: string|null}} params
 * @param {string} apiKey
 * @returns {Promise<import("../types/typedefs.js").VirusTotalResult>}
 */
export async function checkVirusTotal({ url, sha256 }, apiKey) {
  if (!apiKey) {
    return { vtScore: 50, status: "not_configured", malicious: 0, suspicious: 0, harmless: 0 };
  }

  try {
    // Prefer direct file SHA-256 lookup when available (Fix for Bug 4)
    if (sha256) {
      const res = await fetch(`${ENDPOINTS.virusTotalFileReport}/${sha256}`, {
        headers: { "x-apikey": apiKey }
      });
      if (res.status === 404) {
        return { vtScore: 60, status: "unseen_by_virustotal", malicious: 0, suspicious: 0, harmless: 0 };
      }
      if (!res.ok) throw new Error(`VirusTotal file lookup failed: ${res.status}`);
      const data = await res.json();
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      return scoreFromStats(stats, "file_hash");
    }

    // Fall back to URL report
    if (url) {
      const id = toBase64Url(url);
      const res = await fetch(`${ENDPOINTS.virusTotalUrlReport}/${id}`, {
        headers: { "x-apikey": apiKey }
      });
      if (res.status === 404) {
        return { vtScore: 60, status: "unseen_by_virustotal", malicious: 0, suspicious: 0, harmless: 0 };
      }
      if (!res.ok) throw new Error(`VirusTotal URL lookup failed: ${res.status}`);
      const data = await res.json();
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      return scoreFromStats(stats, "url");
    }

    return { vtScore: 50, status: "no_data_provided", malicious: 0, suspicious: 0, harmless: 0 };
  } catch (err) {
    return { vtScore: 50, status: "error", error: String(err), malicious: 0, suspicious: 0, harmless: 0 };
  }
}

function scoreFromStats(stats, source) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const total = malicious + suspicious + harmless + (stats.undetected || 0);

  let vtScore;
  if (total === 0) vtScore = 55;
  else if (malicious > 0) vtScore = Math.max(0, 40 - malicious * 5);
  else if (suspicious > 0) vtScore = Math.max(40, 70 - suspicious * 5);
  else vtScore = 95;

  return { vtScore, status: `analyzed_${source}`, malicious, suspicious, harmless, total };
}

/**
 * Check Google Safe Browsing API.
 * @param {string} url
 * @param {string} apiKey
 * @returns {Promise<import("../types/typedefs.js").SafeBrowsingResult>}
 */
export async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) {
    return { safeBrowsingScore: 50, status: "not_configured", flagged: false };
  }
  try {
    const body = {
      client: { clientId: "securedownload-ai", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const res = await fetch(`${ENDPOINTS.safeBrowsing}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`Safe Browsing lookup failed: ${res.status}`);
    const data = await res.json();
    const flagged = Boolean(data.matches && data.matches.length);
    return {
      safeBrowsingScore: flagged ? 0 : 100,
      status: "analyzed",
      flagged,
      threatTypes: flagged ? data.matches.map((m) => m.threatType) : []
    };
  } catch (err) {
    return { safeBrowsingScore: 50, status: "error", error: String(err), flagged: false };
  }
}
