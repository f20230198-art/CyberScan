/**
 * Domain Ownership Verification
 *
 * Before active payload testing (SQLi / XSS) can run, the caller must prove
 * they control the target domain by publishing a DNS TXT record.
 *
 * Flow:
 *   1. POST /api/verify/challenge  { domain }
 *      → Returns a unique token: cyberscan-verify=<token>
 *   2. User adds TXT record:  _cyberscan-verify.<domain>  →  <token>
 *   3. POST /api/verify/confirm  { domain }
 *      → Server resolves the TXT record and marks domain as verified
 *   4. Active scans check isVerified(domain) before proceeding
 *
 * Tokens expire after 24 hours if not confirmed.
 * Verified domains expire after 7 days (re-verification required).
 */

const dns = require('dns').promises;
const crypto = require('crypto');

// In-memory stores (sufficient for a portfolio/demo deployment)
const pendingChallenges = new Map();   // domain → { token, issuedAt }
const verifiedDomains  = new Map();   // domain → { verifiedAt }

const CHALLENGE_TTL_MS = 24 * 60 * 60 * 1000;  // 24 hours
const VERIFIED_TTL_MS  =  7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Generate (or reuse) a challenge token for a domain.
 * Returns the token the user must publish as a TXT record.
 */
function generateChallenge(domain) {
    domain = normalizeDomain(domain);

    // Reuse an un-expired pending challenge so the token stays stable
    const existing = pendingChallenges.get(domain);
    if (existing && Date.now() - existing.issuedAt < CHALLENGE_TTL_MS) {
        return { domain, token: existing.token, recordName: `_cyberscan-verify.${domain}`, recordValue: existing.token };
    }

    const token = `cyberscan-verify=${crypto.randomBytes(20).toString('hex')}`;
    pendingChallenges.set(domain, { token, issuedAt: Date.now() });

    return {
        domain,
        token,
        recordName: `_cyberscan-verify.${domain}`,
        recordValue: token,
        instructions: [
            `Add the following DNS TXT record to prove you own ${domain}:`,
            `  Name:  _cyberscan-verify.${domain}`,
            `  Type:  TXT`,
            `  Value: ${token}`,
            `DNS changes can take a few minutes to propagate.`,
            `Call POST /api/verify/confirm with { "domain": "${domain}" } once the record is live.`
        ]
    };
}

/**
 * Attempt to confirm ownership by resolving the TXT record.
 * Returns { verified: true } on success or { verified: false, reason } on failure.
 */
async function confirmChallenge(domain) {
    domain = normalizeDomain(domain);

    const challenge = pendingChallenges.get(domain);
    if (!challenge) {
        return { verified: false, reason: 'No pending challenge found. Call /api/verify/challenge first.' };
    }

    if (Date.now() - challenge.issuedAt > CHALLENGE_TTL_MS) {
        pendingChallenges.delete(domain);
        return { verified: false, reason: 'Challenge token expired. Request a new one.' };
    }

    const recordName = `_cyberscan-verify.${domain}`;

    try {
        const txtRecords = await dns.resolveTxt(recordName);
        // resolveTxt returns string[][] — flatten to string[]
        const flatRecords = txtRecords.flat();

        if (flatRecords.includes(challenge.token)) {
            // Mark domain as verified
            verifiedDomains.set(domain, { verifiedAt: Date.now() });
            pendingChallenges.delete(domain);
            return { verified: true, domain, message: `Domain ${domain} verified. Active scanning is now enabled for 7 days.` };
        }

        return {
            verified: false,
            reason: `TXT record found but token does not match. Expected: "${challenge.token}"`,
            hint: `Make sure the record value is exactly: ${challenge.token}`
        };
    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            return {
                verified: false,
                reason: `TXT record _cyberscan-verify.${domain} not found. DNS may still be propagating — try again in a few minutes.`
            };
        }
        return { verified: false, reason: `DNS lookup error: ${err.message}` };
    }
}

/**
 * Check whether a domain is currently verified.
 */
function isVerified(domain) {
    domain = normalizeDomain(domain);
    const entry = verifiedDomains.get(domain);
    if (!entry) return false;
    if (Date.now() - entry.verifiedAt > VERIFIED_TTL_MS) {
        verifiedDomains.delete(domain);
        return false;
    }
    return true;
}

/**
 * Express middleware — rejects active-scan requests for unverified domains.
 * Attach to routes that perform payload injection.
 */
function requireVerifiedDomain(req, res, next) {
    let { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL is required' });

    let domain;
    try {
        domain = normalizeDomain(new URL(url.startsWith('http') ? url : `https://${url}`).hostname);
    } catch {
        return res.status(400).json({ success: false, error: 'Invalid URL' });
    }

    if (!isVerified(domain)) {
        return res.status(403).json({
            success: false,
            error: 'Domain ownership not verified',
            domain,
            message: `Active scanning (SQLi / XSS payload injection) requires proof of domain ownership.`,
            howToVerify: [
                `Step 1: POST /api/verify/challenge  with { "domain": "${domain}" }`,
                `Step 2: Add the returned TXT record to your DNS settings`,
                `Step 3: POST /api/verify/confirm    with { "domain": "${domain}" }`
            ],
            documentation: 'This prevents unauthorized scanning of third-party websites.'
        });
    }

    next();
}

/**
 * Normalise a domain string: strip www., lowercase, remove trailing dot.
 */
function normalizeDomain(domain) {
    return domain.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
}

module.exports = { generateChallenge, confirmChallenge, isVerified, requireVerifiedDomain };
