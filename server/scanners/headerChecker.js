/**
 * Security Headers Checker
 * Analyzes HTTP security headers for best practices
 */

const axios = require('axios');
const { securityHeaders } = require('../utils/payloads');

async function checkHeaders(targetUrl) {
    try {
        const response = await axios.get(targetUrl, {
            timeout: 15000,
            maxRedirects: 5,
            validateStatus: () => true, // Accept any status code
            headers: {
                'User-Agent': 'CyberScan Security Scanner/1.0'
            }
        });

        const responseHeaders = response.headers;
        const present = [];
        const missing = [];

        securityHeaders.forEach(header => {
            const headerValue = responseHeaders[header.key];
            if (headerValue) {
                present.push({
                    name: header.name,
                    value: headerValue,
                    importance: header.importance,
                    description: header.description,
                    points: header.points
                });
            } else {
                missing.push({
                    name: header.name,
                    importance: header.importance,
                    description: header.description,
                    points: header.points
                });
            }
        });

        // Additional analysis for specific headers
        const analysis = analyzeHeaderValues(present);

        return {
            success: true,
            statusCode: response.status,
            present,
            missing,
            analysis,
            score: calculateHeadersScore(present, missing),
            totalChecked: securityHeaders.length
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            present: [],
            missing: securityHeaders,
            analysis: {},
            score: 0,
            totalChecked: securityHeaders.length
        };
    }
}

function analyzeHeaderValues(presentHeaders) {
    const analysis = {};

    presentHeaders.forEach(header => {
        switch (header.name) {
            case 'Content-Security-Policy':
                analysis.csp = analyzeCSP(header.value);
                break;
            case 'Strict-Transport-Security':
                analysis.hsts = analyzeHSTS(header.value);
                break;
            case 'X-Frame-Options':
                analysis.xfo = analyzeXFO(header.value);
                break;
        }
    });

    return analysis;
}

function analyzeCSP(value) {
    const issues = [];
    const strengths = [];

    if (value.includes("'unsafe-inline'")) {
        issues.push("Allows unsafe-inline scripts (XSS risk)");
    }
    if (value.includes("'unsafe-eval'")) {
        issues.push("Allows unsafe-eval (code injection risk)");
    }
    if (value.includes('default-src')) {
        strengths.push("Has default-src directive");
    }
    if (value.includes('script-src')) {
        strengths.push("Has script-src directive");
    }
    if (value.includes('report-uri') || value.includes('report-to')) {
        strengths.push("Has CSP violation reporting enabled");
    }

    return { issues, strengths, rating: issues.length === 0 ? 'good' : 'needs-improvement' };
}

function analyzeHSTS(value) {
    const issues = [];
    const strengths = [];

    const maxAgeMatch = value.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1]);
        if (maxAge >= 31536000) { // 1 year
            strengths.push(`Strong max-age (${Math.floor(maxAge / 86400)} days)`);
        } else if (maxAge < 2592000) { // Less than 30 days
            issues.push(`Weak max-age (only ${Math.floor(maxAge / 86400)} days)`);
        }
    }

    if (value.includes('includeSubDomains')) {
        strengths.push("Includes subdomains");
    } else {
        issues.push("Does not include subdomains");
    }

    if (value.includes('preload')) {
        strengths.push("Preload enabled");
    }

    return { issues, strengths, rating: issues.length === 0 ? 'good' : 'needs-improvement' };
}

function analyzeXFO(value) {
    const normalizedValue = value.toUpperCase();

    if (normalizedValue === 'DENY') {
        return { rating: 'excellent', description: 'Page cannot be displayed in any frame' };
    } else if (normalizedValue === 'SAMEORIGIN') {
        return { rating: 'good', description: 'Page can only be displayed in frames from same origin' };
    } else if (normalizedValue.startsWith('ALLOW-FROM')) {
        return { rating: 'moderate', description: 'Page allows framing from specific origins' };
    }

    return { rating: 'unknown', description: 'Unrecognized value' };
}

function calculateHeadersScore(present, missing) {
    const maxScore = securityHeaders.reduce((sum, h) => sum + h.points, 0);
    const earnedScore = present.reduce((sum, h) => sum + h.points, 0);
    return Math.round((earnedScore / maxScore) * 100);
}

module.exports = { checkHeaders };
