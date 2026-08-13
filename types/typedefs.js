/**
 * @file typedefs.js
 * @description Centralized JSDoc type definitions for SecureDownload AI.
 */

/**
 * @typedef {Object} DownloadItemParsed
 * @property {number} downloadId
 * @property {string} url
 * @property {string} domain
 * @property {string} filename
 * @property {string} mime
 * @property {number} bytesTotal
 * @property {string} extension
 * @property {string} category
 * @property {string} danger
 * @property {boolean} isDangerousNative
 */

/**
 * @typedef {Object} SourceCheckResult
 * @property {string} domain
 * @property {string} registrableDomain
 * @property {boolean} isKnownOfficial
 * @property {boolean} looksLikeTyposquat
 * @property {string|null} suspiciouslyCloseTo
 * @property {number} officialWebsiteScore
 * @property {number} sourceReputationScore
 */

/**
 * @typedef {Object} HttpsCheckResult
 * @property {boolean} isHttps
 * @property {number} httpsScore
 */

/**
 * @typedef {Object} PublisherCheckResult
 * @property {string|null} publisherName
 * @property {boolean} publisherVerified
 * @property {number} publisherVerificationScore
 */

/**
 * @typedef {Object} IntegrityCheckResult
 * @property {string|null} calculatedHash
 * @property {string} status
 * @property {number} integrityScore
 * @property {string|null} matchedHash
 */

/**
 * @typedef {Object} VirusTotalResult
 * @property {number} vtScore
 * @property {string} status
 * @property {number} malicious
 * @property {number} suspicious
 * @property {number} harmless
 * @property {number} [total]
 * @property {string} [error]
 */

/**
 * @typedef {Object} SafeBrowsingResult
 * @property {number} safeBrowsingScore
 * @property {string} status
 * @property {boolean} flagged
 * @property {string[]} [threatTypes]
 * @property {string} [error]
 */

/**
 * @typedef {Object} VulnerabilityCheckResult
 * @property {number} vulnerabilityScore
 * @property {string} status
 * @property {number} cveCount
 * @property {Array<{id: string, severity: string, summary: string}>} cves
 * @property {string} [detectedSoftware]
 * @property {string} [detectedVersion]
 */

/**
 * @typedef {Object} VulnerabilityCard
 * @property {string} id
 * @property {string} title
 * @property {string} severity
 * @property {string} description
 * @property {string} harmScenario
 * @property {string} remediation
 */

/**
 * @typedef {Object} WebAuditResult
 * @property {string} url
 * @property {string} domain
 * @property {number} webSecurityScore
 * @property {string} securityGrade
 * @property {boolean} isHttps
 * @property {SourceCheckResult} sourceCheck
 * @property {Object.<string, boolean>} headersPresent
 * @property {VulnerabilityCard[]} vulnerabilities
 * @property {number} totalChecks
 * @property {number} passedChecks
 */

/**
 * @typedef {Object} TrustScoreResult
 * @property {number} trustScore
 * @property {number} checksTotal
 * @property {number} checksApplicable
 * @property {Object.<string, number>} contributions
 */

/**
 * @typedef {Object} RecommendationResult
 * @property {("safe"|"low_risk"|"medium_risk"|"dangerous")} riskLevel
 * @property {("allow"|"pause"|"cancel"|"delete")} action
 * @property {string} headline
 * @property {string} summary
 * @property {string[]} flags
 */

/**
 * @typedef {Object} ScanRecord
 * @property {number} downloadId
 * @property {string} filename
 * @property {string} extension
 * @property {string} category
 * @property {string} url
 * @property {string} domain
 * @property {string} scannedAt
 * @property {number} trustScore
 * @property {Object.<string, number>} contributions
 * @property {number} checksApplicable
 * @property {number} checksTotal
 * @property {("safe"|"low_risk"|"medium_risk"|"dangerous")} riskLevel
 * @property {RecommendationResult} recommendation
 * @property {WebAuditResult} websiteSecurity
 * @property {Object} details
 * @property {("pending"|"resumed"|"deleted"|"paused")} action
 */

/**
 * @typedef {Object} ExtensionSettings
 * @property {boolean} autoAnalyze
 * @property {boolean} blockDangerousByDefault
 * @property {string} virusTotalApiKey
 * @property {string} safeBrowsingApiKey
 * @property {string} nvdApiKey
 * @property {string[]} extraTrustedDomains
 * @property {Object.<string, string>} knownGoodHashes
 * @property {("dark"|"light"|"system")} theme
 */

export {};
