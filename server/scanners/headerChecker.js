/**
 * Security Headers Checker
 * Analyzes HTTP security headers (and Set-Cookie attributes) for best practices.
 */

const axios = require('axios');
const { securityHeaders } = require('../utils/payloads');

async function checkHeaders(targetUrl) {
    try {
        const response = await axios.get(targetUrl, {
            timeout: 15000,
            maxRedirects: 5,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberScan Security Scanner/2.0' },
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
                    points: header.points,
                });
            } else {
                missing.push({
                    name: header.name,
                    importance: header.importance,
                    description: header.description,
                    points: header.points,
                });
            }
        });

        const analysis = analyzeHeaderValues(present);

        // Parse Set-Cookie headers — axios exposes them as an array
        const rawCookies = responseHeaders['set-cookie'] || [];
        const cookies = analyzeCookies(Array.isArray(rawCookies) ? rawCookies : [rawCookies]);

        // CORS misconfiguration check
        const cors = analyzeCORS(responseHeaders);

        return {
            success: true,
            statusCode: response.status,
            present,
            missing,
            analysis,
            cookies,
            cors,
            score: calculateHeadersScore(present),
            totalChecked: securityHeaders.length,
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            present: [],
            missing: [...securityHeaders],
            analysis: {},
            cookies: { total: 0, issues: [] },
            cors: { issues: [] },
            score: 0,
            totalChecked: securityHeaders.length,
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
    const directives = parseCSPDirectives(value);

    // --- Dangerous sources ---
    if (value.includes("'unsafe-inline'")) issues.push("Allows 'unsafe-inline' (defeats XSS protection)");
    if (value.includes("'unsafe-eval'")) issues.push("Allows 'unsafe-eval' (code injection risk)");

    // --- Wildcard sources in critical directives ---
    const criticalDirectives = ['default-src', 'script-src', 'script-src-elem', 'frame-src', 'object-src', 'base-uri'];
    for (const dir of criticalDirectives) {
        const sources = directives[dir];
        if (!sources) continue;
        if (sources.includes('*')) issues.push(`${dir} uses wildcard '*' (allows any origin)`);
        if (sources.includes('data:') && (dir === 'script-src' || dir === 'default-src')) {
            issues.push(`${dir} allows data: URIs (can be abused for XSS)`);
        }
        if (sources.includes('http:')) issues.push(`${dir} allows any http: source (mixed content risk)`);
    }

    // --- Missing important directives ---
    if (!directives['default-src'] && !directives['script-src']) {
        issues.push("No default-src or script-src directive");
    } else {
        strengths.push("Has script source policy");
    }
    if (!directives['object-src']) {
        issues.push("Missing object-src (should be 'none' to block plugins)");
    } else if (directives['object-src'].includes("'none'")) {
        strengths.push("object-src 'none' blocks Flash/plugin exploits");
    }
    if (!directives['frame-ancestors']) {
        issues.push("Missing frame-ancestors (clickjacking protection weaker without it)");
    } else if (directives['frame-ancestors'].includes("'none'") || directives['frame-ancestors'].includes("'self'")) {
        strengths.push("frame-ancestors restricts framing");
    }
    if (!directives['base-uri']) {
        issues.push("Missing base-uri (attacker could inject <base> tag)");
    }

    // --- Nonce / hash usage (modern XSS-safe CSP pattern) ---
    if (/'nonce-[A-Za-z0-9+/=_-]+'/.test(value)) strengths.push('Uses nonces for script allowlisting');
    if (/'sha(256|384|512)-[A-Za-z0-9+/=]+'/.test(value)) strengths.push('Uses hash-based script allowlisting');

    // --- Reporting ---
    if (directives['report-uri'] || directives['report-to']) {
        strengths.push('Violation reporting enabled');
    }

    let rating = 'good';
    if (issues.length >= 3) rating = 'poor';
    else if (issues.length > 0) rating = 'needs-improvement';

    return { issues, strengths, rating, directives };
}

function parseCSPDirectives(value) {
    const out = {};
    value.split(';').forEach(part => {
        const tokens = part.trim().split(/\s+/);
        if (tokens.length === 0 || !tokens[0]) return;
        const name = tokens[0].toLowerCase();
        out[name] = tokens.slice(1);
    });
    return out;
}

function analyzeHSTS(value) {
    const issues = [];
    const strengths = [];

    const maxAgeMatch = value.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        if (maxAge >= 31536000) strengths.push(`Strong max-age (${Math.floor(maxAge / 86400)} days)`);
        else if (maxAge < 2592000) issues.push(`Weak max-age (only ${Math.floor(maxAge / 86400)} days)`);
    } else {
        issues.push('No max-age directive');
    }

    if (value.includes('includeSubDomains')) strengths.push('Includes subdomains');
    else issues.push('Does not include subdomains');

    if (value.includes('preload')) strengths.push('Preload enabled');

    return { issues, strengths, rating: issues.length === 0 ? 'good' : 'needs-improvement' };
}

function analyzeXFO(value) {
    const normalized = value.toUpperCase();
    if (normalized === 'DENY') return { rating: 'excellent', description: 'Page cannot be framed' };
    if (normalized === 'SAMEORIGIN') return { rating: 'good', description: 'Same-origin framing only' };
    if (normalized.startsWith('ALLOW-FROM')) return { rating: 'moderate', description: 'Specific origins allowed (deprecated directive)' };
    return { rating: 'unknown', description: `Unrecognized value: ${value}` };
}

/**
 * Parse Set-Cookie headers and flag missing security attributes.
 * Session-like cookies (name contains session/auth/token/sid) are held to a stricter standard.
 */
function analyzeCookies(cookieHeaders) {
    const issues = [];
    const cookies = cookieHeaders.filter(raw => raw && raw.includes('=')).map(raw => {
        const [nameValue, ...attrs] = raw.split(';').map(s => s.trim());
        const [name] = nameValue.split('=');
        const attrSet = new Set(attrs.map(a => a.toLowerCase().split('=')[0]));
        const sameSiteAttr = attrs.find(a => /^samesite=/i.test(a));
        const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1] : null;

        const cookie = {
            name,
            secure: attrSet.has('secure'),
            httpOnly: attrSet.has('httponly'),
            sameSite,
        };

        const isSensitive = /session|auth|token|sid|jwt|csrf/i.test(name);
        if (!cookie.secure) {
            issues.push({ name, severity: isSensitive ? 'high' : 'medium', message: 'Missing Secure attribute — cookie sent over HTTP' });
        }
        if (!cookie.httpOnly && isSensitive) {
            issues.push({ name, severity: 'high', message: 'Missing HttpOnly attribute — accessible to JavaScript (XSS risk)' });
        }
        if (!sameSite) {
            issues.push({ name, severity: isSensitive ? 'medium' : 'low', message: 'Missing SameSite attribute — CSRF risk' });
        } else if (sameSite.toLowerCase() === 'none' && !cookie.secure) {
            issues.push({ name, severity: 'high', message: 'SameSite=None requires Secure attribute' });
        }

        return cookie;
    });

    return { total: cookies.length, cookies, issues };
}

function analyzeCORS(headers) {
    const issues = [];
    const origin = headers['access-control-allow-origin'];
    const credentials = headers['access-control-allow-credentials'];

    if (origin === '*' && credentials === 'true') {
        issues.push("Access-Control-Allow-Origin: '*' with Allow-Credentials:true — invalid and insecure");
    }
    if (origin === '*') {
        issues.push("Access-Control-Allow-Origin: '*' — permits any origin (acceptable only for truly public APIs)");
    }
    return { origin, credentials, issues };
}

function calculateHeadersScore(present) {
    const maxScore = securityHeaders.reduce((sum, h) => sum + h.points, 0);
    const earnedScore = present.reduce((sum, h) => sum + h.points, 0);
    return Math.round((earnedScore / maxScore) * 100);
}

module.exports = { checkHeaders };
