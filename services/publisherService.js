/**
 * @file publisherService.js
 * @description Correlates download URLs with known official publishers and distribution CDNs.
 */

import { KNOWN_PUBLISHERS } from "./config.js";
import "../types/typedefs.js";

/**
 * Verifies domain and URL against official publishers and CDNs.
 * @param {import("../types/typedefs.js").DownloadItemParsed} parsed
 * @param {string[]} [extraTrustedDomains=[]]
 * @returns {import("../types/typedefs.js").PublisherCheckResult}
 */
export function verifyPublisher(parsed, extraTrustedDomains = []) {
  const { domain, url } = parsed;
  if (!domain) {
    return { publisherName: null, publisherVerified: false, publisherVerificationScore: 50 };
  }

  for (const pub of KNOWN_PUBLISHERS) {
    const matchesDomain = pub.domains.some((d) => domain === d || domain.endsWith(`.${d}`));
    if (matchesDomain) {
      return {
        publisherName: pub.name,
        publisherVerified: true,
        publisherVerificationScore: 100
      };
    }
  }

  const isExtraTrusted = extraTrustedDomains.some((d) => domain === d || domain.endsWith(`.${d}`));
  if (isExtraTrusted) {
    return {
      publisherName: "Custom Trusted Publisher",
      publisherVerified: true,
      publisherVerificationScore: 100
    };
  }

  const isCdnPattern = /\b(cdn|dl|download|dist|releases|static)\b/i.test(url);
  return {
    publisherName: null,
    publisherVerified: false,
    publisherVerificationScore: isCdnPattern ? 60 : 50
  };
}
