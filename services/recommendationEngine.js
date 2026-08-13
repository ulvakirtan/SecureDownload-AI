/**
 * @file recommendationEngine.js
 * @description Evaluates risk level and generates action recommendations.
 */

import "../types/typedefs.js";

/**
 * Computes recommendation and risk level from trust score result.
 * @param {import("../types/typedefs.js").TrustScoreResult} trustResult
 * @param {Object} context
 * @param {boolean} [context.looksLikeTyposquat=false]
 * @param {string} [context.integrityStatus=""]
 * @param {boolean} [context.isDangerousNative=false]
 * @returns {import("../types/typedefs.js").RecommendationResult}
 */
export function getRecommendation(trustResult, { looksLikeTyposquat = false, integrityStatus = "", isDangerousNative = false } = {}) {
  const flags = [];

  if (looksLikeTyposquat) flags.push("Domain looks like a typosquatting attempt.");
  if (integrityStatus === "hash_mismatch_possible_tampering") flags.push("SHA-256 hash mismatch — file may be tampered with.");
  if (isDangerousNative) flags.push("Chrome flagged this file as dangerous.");

  const forcedDangerous = looksLikeTyposquat || integrityStatus === "hash_mismatch_possible_tampering" || isDangerousNative;

  let riskLevel;
  if (forcedDangerous || trustResult.trustScore < 50) {
    riskLevel = "dangerous";
  } else if (trustResult.trustScore < 80) {
    riskLevel = trustResult.trustScore < 65 ? "medium_risk" : "low_risk";
  } else {
    riskLevel = "safe";
  }

  let action;
  let headline;
  let summary;

  switch (riskLevel) {
    case "safe":
      action = "allow";
      headline = "Download Verified Safe";
      summary = "File originates from a verified publisher with high security trust signals.";
      break;
    case "low_risk":
      action = "allow";
      headline = "Low Risk Download";
      summary = "No immediate threats detected, but some security checks were inconclusive.";
      break;
    case "medium_risk":
      action = "pause";
      headline = "Caution Advised";
      summary = "Download source lacks official publisher verification. Exercise caution.";
      break;
    case "dangerous":
      action = "delete";
      headline = "High Threat Download";
      summary = "File or source site exhibits critical risk indicators. Immediate action recommended.";
      break;
  }

  return { riskLevel, action, headline, summary, flags };
}
