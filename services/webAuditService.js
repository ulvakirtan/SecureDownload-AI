/**
 * @file webAuditService.js
 * @description Audits source URLs for security headers, TLS enforceability, CORS, CSP, XFO, and typosquatting.
 */

import { KNOWN_PUBLISHERS, VULNERABILITY_DEFINITIONS } from "./config.js";
import "../types/typedefs.js";

const SUSPICIOUS_TLDS = new Set(["top", "xyz", "cc", "click", "download", "link", "gq", "work", "cf", "tk", "ml", "ga"]);
const levenshteinCache = new Map();

function levenshtein(a, b) {
  const cacheKey = `${a}:${b}`;
  if (levenshteinCache.has(cacheKey)) return levenshteinCache.get(cacheKey);

  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array(b.length + 1).fill(0).map((_, j) => (i === 0 ? j : 0))
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  const result = dp[a.length][b.length];
  levenshteinCache.set(cacheKey, result);
  return result;
}

function registrableDomain(hostname) {
  const parts = hostname.split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}

/**
 * Checks source domain against official publishers and typosquatting.
 * @param {string} domain
 * @param {string[]} [extraTrustedDomains=[]]
 * @returns {import("../types/typedefs.js").SourceCheckResult}
 */
export function verifySource(domain, extraTrustedDomains = []) {
  const reg = registrableDomain(domain);
  const trustedList = [
    ...KNOWN_PUBLISHERS.flatMap((p) => p.domains),
    ...extraTrustedDomains
  ];

  const isKnownOfficial = trustedList.some((d) => reg === d || domain === d || domain.endsWith(`.${d}`));

  let closestMatch = null;
  let closestDistance = Infinity;
  if (!isKnownOfficial) {
    for (const d of trustedList) {
      // Optimization (Bug 9): Only calculate Levenshtein distance for close-length domains
      if (Math.abs(reg.length - d.length) > 2) continue;
      const dist = levenshtein(reg, d);
      if (dist < closestDistance) {
        closestDistance = dist;
        closestMatch = d;
      }
    }
  }

  const looksLikeTyposquat = !isKnownOfficial && closestMatch !== null &&
    closestDistance > 0 && closestDistance <= 2 && reg.length > 5;

  let officialScore;
  if (isKnownOfficial) officialScore = 100;
  else if (looksLikeTyposquat) officialScore = 0;
  else officialScore = 65;

  return {
    domain,
    registrableDomain: reg,
    isKnownOfficial,
    looksLikeTyposquat,
    suspiciouslyCloseTo: looksLikeTyposquat ? closestMatch : null,
    officialWebsiteScore: officialScore,
    sourceReputationScore: isKnownOfficial ? 100 : looksLikeTyposquat ? 0 : 65
  };
}

/**
 * Validates protocol HTTPS usage.
 * @param {string} url
 * @returns {import("../types/typedefs.js").HttpsCheckResult}
 */
export function verifyHttps(url) {
  const isHttps = url.startsWith("https://");
  return { isHttps, httpsScore: isHttps ? 100 : 0 };
}

/**
 * Fetch HTTP headers with HEAD request and fallback GET byte-range (Fix for Bug 10).
 * @param {string} url
 * @returns {Promise<Object.<string, string>>}
 */
export async function fetchSiteHeaders(url) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(url, { method: "HEAD", signal: controller.signal });
    clearTimeout(timer);

    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      headers[k.toLowerCase()] = v;
    }

    // Fallback: If HEAD yields no security headers, try range-limited GET
    if (!headers["strict-transport-security"] && !headers["content-security-policy"]) {
      const getController = new AbortController();
      const getTimer = setTimeout(() => getController.abort(), 4000);
      const getRes = await fetch(url, {
        method: "GET",
        headers: { Range: "bytes=0-10" },
        signal: getController.signal
      });
      clearTimeout(getTimer);
      for (const [k, v] of getRes.headers.entries()) {
        headers[k.toLowerCase()] = v;
      }
    }

    return headers;
  } catch (err) {
    return {};
  }
}

/**
 * Determines whether a URL is a public HTTP/HTTPS web page that can be audited.
 * Excludes internal browser schemes (chrome://, chrome-extension://, about:, file:, edge:, etc.).
 * @param {string} url
 * @returns {boolean}
 */
export function isAuditableWebUrl(url) {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Analyzes website security posture and header configurations.
 * @param {string} url
 * @param {Object.<string, string>} [headers={}]
 * @param {string[]} [extraTrustedDomains=[]]
 * @returns {import("../types/typedefs.js").WebAuditResult|null}
 */
export function analyzeWebsiteVulnerabilities(url, headers = {}, extraTrustedDomains = []) {
  if (!isAuditableWebUrl(url)) {
    return null;
  }

  let domain = "";
  try {
    domain = new URL(url).hostname.toLowerCase();
  } catch {
    domain = url;
  }

  const sourceCheck = verifySource(domain, extraTrustedDomains);
  const isHttps = url.startsWith("https://");
  const vulnerabilities = [];

  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers || {})) {
    normalizedHeaders[k.toLowerCase()] = String(v);
  }

  if (!isHttps) {
    vulnerabilities.push({ key: "NO_HTTPS", ...VULNERABILITY_DEFINITIONS.NO_HTTPS });
  }

  const hsts = normalizedHeaders["strict-transport-security"];
  if (isHttps && !hsts) {
    vulnerabilities.push({ key: "MISSING_HSTS", ...VULNERABILITY_DEFINITIONS.MISSING_HSTS });
  }

  const csp = normalizedHeaders["content-security-policy"];
  if (!csp) {
    vulnerabilities.push({ key: "MISSING_CSP", ...VULNERABILITY_DEFINITIONS.MISSING_CSP });
  }

  const corsOrigin = normalizedHeaders["access-control-allow-origin"];
  if (corsOrigin === "*") {
    vulnerabilities.push({ key: "PERMISSIVE_CORS", ...VULNERABILITY_DEFINITIONS.PERMISSIVE_CORS });
  }

  const xfo = normalizedHeaders["x-frame-options"];
  const hasFrameAncestors = csp && csp.includes("frame-ancestors");
  if (!xfo && !hasFrameAncestors) {
    vulnerabilities.push({ key: "MISSING_CLICKJACKING_PROTECTION", ...VULNERABILITY_DEFINITIONS.MISSING_CLICKJACKING_PROTECTION });
  }

  const xcto = normalizedHeaders["x-content-type-options"];
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    vulnerabilities.push({ key: "MISSING_MIME_PROTECTION", ...VULNERABILITY_DEFINITIONS.MISSING_MIME_PROTECTION });
  }

  if (sourceCheck.looksLikeTyposquat) {
    vulnerabilities.push({
      key: "TYPOSQUATTING_RISK",
      ...VULNERABILITY_DEFINITIONS.TYPOSQUATTING_RISK,
      unethicalHarm: `Phishing & Malware Delivery: Domain mimics "${sourceCheck.suspiciouslyCloseTo}".`
    });
  }

  const tld = domain.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    vulnerabilities.push({ key: "SUSPICIOUS_TLD", ...VULNERABILITY_DEFINITIONS.SUSPICIOUS_TLD });
  }

  let score = 100;
  if (!isHttps) score -= 40;
  if (sourceCheck.looksLikeTyposquat) score -= 45;
  if (!hsts) score -= 10;
  if (!csp) score -= 10;
  if (corsOrigin === "*") score -= 15;
  if (!xfo && !hasFrameAncestors) score -= 10;
  if (!xcto) score -= 5;
  if (SUSPICIOUS_TLDS.has(tld)) score -= 15;
  if (sourceCheck.isKnownOfficial) score = Math.max(score, 85);

  score = Math.max(0, Math.min(100, Math.round(score)));

  let securityGrade = "A";
  if (score < 50) securityGrade = "F";
  else if (score < 70) securityGrade = "C";
  else if (score < 85) securityGrade = "B";

  const totalChecks = 7;
  const passedChecks = totalChecks - vulnerabilities.length;

  return {
    url,
    domain,
    webSecurityScore: score,
    securityGrade,
    isHttps,
    sourceCheck,
    headersPresent: {
      hsts: Boolean(hsts),
      csp: Boolean(csp),
      cors: Boolean(corsOrigin),
      xfo: Boolean(xfo || hasFrameAncestors),
      xcto: Boolean(xcto)
    },
    vulnerabilities: vulnerabilities.map((v) => ({
      id: v.key,
      title: v.title,
      severity: v.threatLevel,
      description: v.owaspCategory,
      harmScenario: v.unethicalHarm,
      remediation: "Configure recommended HTTPS/security headers on web server."
    })),
    totalChecks,
    passedChecks: Math.max(0, passedChecks)
  };
}
