/**
 * @file trustEngine.js
 * @description Weighted trust scoring algorithm incorporating all analysis checks.
 */

import { WEIGHTS, WEIGHT_SUM } from "./config.js";
import "../types/typedefs.js";

// Startup Assertion (Fix for Bug 11)
if (Math.abs(WEIGHT_SUM - 1.0) > 0.0001) {
  throw new Error(`[SecureDownload AI] Configuration Error: WEIGHT_SUM must equal 1.0, got ${WEIGHT_SUM}`);
}

/**
 * Calculates final composite trust score (0-100).
 * @param {Object} params
 * @param {number} params.officialWebsiteScore
 * @param {number} params.publisherVerificationScore
 * @param {number} params.vtScore
 * @param {boolean} params.vtApplicable
 * @param {number} params.vulnerabilityScore
 * @param {boolean} params.vulnerabilityApplicable
 * @param {number} params.httpsScore
 * @param {number} params.integrityScore
 * @param {boolean} params.integrityApplicable
 * @param {number} params.sourceReputationScore
 * @param {boolean} [params.safeBrowsingFlagged=false]
 * @param {boolean} [params.isDangerousNative=false]
 * @returns {import("../types/typedefs.js").TrustScoreResult}
 */
export function calculateTrustScore({
  officialWebsiteScore,
  publisherVerificationScore,
  vtScore,
  vtApplicable,
  vulnerabilityScore,
  vulnerabilityApplicable,
  httpsScore,
  integrityScore,
  integrityApplicable,
  sourceReputationScore,
  safeBrowsingFlagged = false,
  isDangerousNative = false
}) {
  // If Google Safe Browsing flags the URL or Chrome native flags danger, drop score immediately (Bug 6 & SafeBrowsing)
  if (safeBrowsingFlagged) {
    return {
      trustScore: 0,
      checksTotal: 7,
      checksApplicable: 7,
      contributions: { safeBrowsingOverride: 0 }
    };
  }

  const rawScores = {
    officialWebsite: officialWebsiteScore,
    publisherVerification: publisherVerificationScore,
    virusTotal: vtApplicable ? vtScore : null,
    vulnerability: vulnerabilityApplicable ? vulnerabilityScore : null,
    https: httpsScore,
    fileIntegrity: integrityApplicable ? integrityScore : null,
    sourceReputation: sourceReputationScore
  };

  let totalWeight = 0;
  let weightedSum = 0;
  let checksApplicable = 0;
  const contributions = {};

  for (const [key, raw] of Object.entries(rawScores)) {
    if (raw === null || raw === undefined) continue;
    const weight = WEIGHTS[key] || 0;
    totalWeight += weight;
    weightedSum += raw * weight;
    contributions[key] = Math.round(raw);
    checksApplicable++;
  }

  let finalScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 50;

  // Penalize native Chrome danger classification (Bug 6 fix)
  if (isDangerousNative) {
    finalScore = Math.min(finalScore, 25);
  }

  return {
    trustScore: Math.max(0, Math.min(100, finalScore)),
    checksTotal: Object.keys(WEIGHTS).length,
    checksApplicable,
    contributions
  };
}
