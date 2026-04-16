/**
 * Domain Verification Routes
 *
 * Implements a DNS TXT-record ownership challenge — the same mechanism used
 * by Google Search Console, Cloudflare, and Qualys SSL Labs to ensure only
 * domain owners can run active security tests against a target.
 */

const express = require('express');
const router = express.Router();
const { generateChallenge, confirmChallenge, isVerified } = require('../middleware/domainVerification');

/**
 * Normalise a raw domain/URL string into a plain hostname.
 */
function extractDomain(input) {
    if (!input || typeof input !== 'string') return null;
    input = input.trim();
    if (!input.startsWith('http')) input = 'https://' + input;
    try {
        return new URL(input).hostname.toLowerCase().replace(/^www\./, '');
    } catch {
        return null;
    }
}

/**
 * POST /api/verify/challenge
 * Body: { domain: "example.com" }
 *
 * Issues a DNS TXT challenge token for the given domain.
 * The caller must publish this token before calling /confirm.
 */
router.post('/challenge', (req, res) => {
    const domain = extractDomain(req.body.domain);

    if (!domain) {
        return res.status(400).json({ success: false, error: 'A valid domain is required (e.g. "example.com")' });
    }

    // Block localhost / private ranges — same logic as the URL validator
    if (['localhost', '127.0.0.1', '0.0.0.0'].includes(domain)) {
        return res.status(400).json({ success: false, error: 'Cannot verify ownership of localhost' });
    }

    const challenge = generateChallenge(domain);

    res.json({
        success: true,
        ...challenge
    });
});

/**
 * POST /api/verify/confirm
 * Body: { domain: "example.com" }
 *
 * Resolves _cyberscan-verify.<domain> TXT record and marks the domain
 * as verified if the token matches.
 */
router.post('/confirm', async (req, res) => {
    const domain = extractDomain(req.body.domain);

    if (!domain) {
        return res.status(400).json({ success: false, error: 'A valid domain is required' });
    }

    const result = await confirmChallenge(domain);

    if (result.verified) {
        res.json({ success: true, ...result });
    } else {
        res.status(400).json({ success: false, ...result });
    }
});

/**
 * GET /api/verify/status?domain=example.com
 *
 * Returns whether a domain is currently verified (useful for UI polling).
 */
router.get('/status', (req, res) => {
    const domain = extractDomain(req.query.domain);

    if (!domain) {
        return res.status(400).json({ success: false, error: 'domain query parameter required' });
    }

    const verified = isVerified(domain);

    res.json({
        success: true,
        domain,
        verified,
        message: verified
            ? `${domain} is verified. Active scanning is enabled.`
            : `${domain} is not verified. Complete the DNS challenge to enable active scanning.`
    });
});

module.exports = router;
