/**
 * @file fileIntegrityService.js
 * @description Fetches file stream (up to cap) and computes SHA-256 network hash for integrity verification.
 */

import "../types/typedefs.js";

const MAX_HASHABLE_BYTES = 50 * 1024 * 1024; // 50MB safety cap for memory hashing

/**
 * Computes SHA-256 hash of network resource and checks against known good hash database.
 * @param {string} url
 * @param {Object.<string, string>} [knownGoodHashes={}]
 * @param {string} [filename=""]
 * @returns {Promise<import("../types/typedefs.js").IntegrityCheckResult>}
 */
export async function checkFileIntegrity(url, knownGoodHashes = {}, filename = "") {
  if (!url || !url.startsWith("http")) {
    return { calculatedHash: null, status: "not_applicable", integrityScore: 50, matchedHash: null };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);

    if (!response.ok) {
      return { calculatedHash: null, status: "fetch_error", integrityScore: 50, matchedHash: null };
    }

    const contentLength = Number(response.headers.get("content-length") || -1);
    if (contentLength > MAX_HASHABLE_BYTES) {
      return { calculatedHash: null, status: "file_too_large_to_hash", integrityScore: 50, matchedHash: null };
    }

    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_HASHABLE_BYTES) {
      return { calculatedHash: null, status: "file_too_large_to_hash", integrityScore: 50, matchedHash: null };
    }

    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const calculatedHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

    const expectedHash = knownGoodHashes[filename] || knownGoodHashes[filename.toLowerCase()];
    if (expectedHash) {
      const isMatch = calculatedHash.toLowerCase() === expectedHash.toLowerCase();
      return {
        calculatedHash,
        status: isMatch ? "matches_known_good" : "hash_mismatch_possible_tampering",
        integrityScore: isMatch ? 100 : 0,
        matchedHash: expectedHash
      };
    }

    return {
      calculatedHash,
      status: "hash_calculated",
      integrityScore: 65,
      matchedHash: null
    };
  } catch (err) {
    return { calculatedHash: null, status: "error", integrityScore: 50, matchedHash: null };
  }
}
