/**
 * Security Score Calculator
 *
 * Each detected issue is mapped to a CVSS v3.1-inspired base score (0.0–10.0),
 * then the final posture score = 100 − sum(weighted CVSS scores), clamped [0, 100].
 *
 * CVSS base scores are standard for these vulnerability classes; see
 * https://nvd.nist.gov/vuln-metrics/cvss for the methodology. Confidence in the
 * finding scales the deduction (high=1.0, medium=0.65, low=0.35) so that
 * low-confidence findings don't tank the score.
 */

const CVSS = {
    sqli: { base: 9.8, severity: 'critical' },        // AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H
    xss: { base: 6.1, severity: 'medium' },           // AV:N/AC:L/PR:N/UI:R/C:L/I:L/A:N (reflected)
    sslInvalid: { base: 7.4, severity: 'high' },      // AV:N/AC:H/PR:N/UI:N/C:H/I:H/A:N
    sslExpired: { base: 5.3, severity: 'medium' },
    sslExpiringSoon: { base: 3.1, severity: 'low' },
    headerCriticalMissing: { base: 5.4, severity: 'medium' }, // CSP, HSTS absent
    headerMediumMissing: { base: 3.1, severity: 'low' },      // X-Frame-Options, X-Content-Type-Options
    headerLowMissing: { base: 1.8, severity: 'low' },         // Referrer-Policy, Permissions-Policy
    cookieInsecure: { base: 4.3, severity: 'medium' },
    dnsTyposquat: { base: 5.4, severity: 'medium' },
    dnsIpDomain: { base: 4.3, severity: 'medium' },
    emailNoSpf: { base: 2.6, severity: 'low' },
    emailNoDmarc: { base: 2.6, severity: 'low' },
};

const CONFIDENCE_WEIGHT = { high: 1.0, medium: 0.65, low: 0.35, none: 0 };

const CRITICAL_HEADERS = new Set(['Content-Security-Policy', 'Strict-Transport-Security']);
const MEDIUM_HEADERS = new Set(['X-Frame-Options', 'X-Content-Type-Options', 'Permissions-Policy']);

function calculateScore(results) {
    let score = 100;
    const issues = [];

    const deduct = (cvss, confidence, message, type) => {
        const w = CONFIDENCE_WEIGHT[confidence] ?? CONFIDENCE_WEIGHT.high;
        const delta = cvss.base * w;
        score -= delta;
        issues.push({
            type,
            severity: cvss.severity,
            cvss: Number(cvss.base.toFixed(1)),
            deducted: Number(delta.toFixed(1)),
            confidence: confidence || 'high',
            message,
        });
    };

    // SSL/TLS
    if (results.ssl) {
        if (results.ssl.https === false) {
            deduct(CVSS.sslInvalid, 'high', 'Site does not use HTTPS', 'ssl');
        } else if (!results.ssl.valid) {
            deduct(CVSS.sslInvalid, 'high', `Invalid SSL certificate: ${results.ssl.error || 'not trusted'}`, 'ssl');
        }
        if (results.ssl.expired) {
            deduct(CVSS.sslExpired, 'high', 'SSL certificate has expired', 'ssl');
        } else if (results.ssl.expiresSoon) {
            deduct(CVSS.sslExpiringSoon, 'high', `SSL certificate expires in ${results.ssl.daysUntilExpiry} days`, 'ssl');
        }
    }

    // Security headers
    if (results.headers?.missing) {
        results.headers.missing.forEach(h => {
            let cvss = CVSS.headerLowMissing;
            if (CRITICAL_HEADERS.has(h.name)) cvss = CVSS.headerCriticalMissing;
            else if (MEDIUM_HEADERS.has(h.name)) cvss = CVSS.headerMediumMissing;
            deduct(cvss, 'high', `Missing security header: ${h.name}`, 'header');
        });
    }

    // CSP weaknesses detected in present headers
    const cspAnalysis = results.headers?.analysis?.csp;
    if (cspAnalysis?.issues?.length) {
        cspAnalysis.issues.forEach(msg => {
            deduct({ base: 4.8, severity: 'medium' }, 'high', `CSP weakness: ${msg}`, 'header');
        });
    }

    // Cookie issues
    if (results.headers?.cookies?.issues) {
        results.headers.cookies.issues.forEach(issue => {
            deduct(CVSS.cookieInsecure, 'high', `Cookie "${issue.name}": ${issue.message}`, 'cookie');
        });
    }

    // SQL Injection — dedupe by (form + field) so duplicate payload hits don't stack
    if (results.sqli?.vulnerabilities) {
        const seen = new Set();
        results.sqli.vulnerabilities.forEach(v => {
            const key = `${v.form}|${v.field}`;
            if (seen.has(key)) return;
            seen.add(key);
            deduct(CVSS.sqli, v.confidence || 'high',
                `SQL Injection (${v.type}) in ${v.field} @ ${v.form}`, 'sqli');
        });
    }

    // XSS — dedupe by (form/url + field) + upgrade severity for JS-string / attribute contexts
    if (results.xss?.vulnerabilities) {
        const seen = new Set();
        results.xss.vulnerabilities.forEach(v => {
            const key = `${v.form || v.url}|${v.field || v.param}`;
            if (seen.has(key)) return;
            seen.add(key);
            const exploitableContexts = ['js-string', 'attribute-raw', 'html-body'];
            const base = exploitableContexts.includes(v.context) ? 7.2 : 5.4;
            deduct({ base, severity: 'high' }, v.confidence || 'high',
                `XSS (${v.type}, ${v.context || 'unknown'} context) in ${v.field || v.param}`, 'xss');
        });
    }

    // DNS / domain risks
    if (results.dns?.analysis?.risks) {
        results.dns.analysis.risks.forEach(r => {
            if (r.type === 'typosquatting') deduct(CVSS.dnsTyposquat, 'medium', r.message, 'dns');
            else if (r.type === 'ip-domain') deduct(CVSS.dnsIpDomain, 'high', r.message, 'dns');
            else if (r.type === 'suspicious-tld') deduct({ base: 2.6, severity: 'low' }, 'low', r.message, 'dns');
        });
    }

    // Email auth
    if (results.dns?.hasSPF === false) {
        deduct(CVSS.emailNoSpf, 'high', 'No SPF record (email spoofing possible)', 'dns');
    }
    if (results.dns?.hasDMARC === false) {
        deduct(CVSS.emailNoDmarc, 'high', 'No DMARC record', 'dns');
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let status;
    if (score >= 85) status = 'Secure';
    else if (score >= 70) status = 'Moderate';
    else if (score >= 50) status = 'Warning';
    else if (score >= 25) status = 'High Risk';
    else status = 'Critical';

    return {
        score,
        status,
        issues,
        summary: {
            totalIssues: issues.length,
            critical: issues.filter(i => i.severity === 'critical').length,
            high: issues.filter(i => i.severity === 'high').length,
            medium: issues.filter(i => i.severity === 'medium').length,
            low: issues.filter(i => i.severity === 'low').length,
        },
        methodology: 'CVSS v3.1 base scores weighted by finding confidence',
    };
}

function getRecommendations(results) {
    const recommendations = [];

    if (results.ssl && !results.ssl.valid) {
        recommendations.push({
            priority: 'critical',
            title: 'Install valid SSL/TLS certificate',
            description: 'Configure HTTPS with a valid certificate. Use Let\'s Encrypt for free, automated certificates.',
        });
    }

    const missingCritical = results.headers?.missing?.filter(h => CRITICAL_HEADERS.has(h.name)) || [];
    if (missingCritical.length > 0) {
        recommendations.push({
            priority: 'high',
            title: 'Add critical security headers',
            description: `Add: ${missingCritical.map(h => h.name).join(', ')}. CSP mitigates XSS; HSTS forces HTTPS.`,
        });
    }

    if (results.headers?.analysis?.csp?.issues?.length) {
        recommendations.push({
            priority: 'high',
            title: 'Harden Content-Security-Policy',
            description: `Issues: ${results.headers.analysis.csp.issues.join('; ')}. Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes.`,
        });
    }

    if (results.headers?.cookies?.issues?.length) {
        recommendations.push({
            priority: 'high',
            title: 'Secure cookie attributes',
            description: 'Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies.',
        });
    }

    if (results.sqli?.vulnerabilities?.length > 0) {
        recommendations.push({
            priority: 'critical',
            title: 'Fix SQL Injection vulnerabilities',
            description: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL.',
        });
    }

    if (results.xss?.vulnerabilities?.length > 0) {
        recommendations.push({
            priority: 'high',
            title: 'Fix XSS vulnerabilities',
            description: 'Context-encode output (HTML/attribute/JS). Enable a strict Content-Security-Policy with nonces.',
        });
    }

    if (results.dns && results.dns.hasSPF === false) {
        recommendations.push({
            priority: 'low',
            title: 'Add SPF record',
            description: 'Publish a TXT record starting with "v=spf1" to prevent email spoofing from your domain.',
        });
    }

    return recommendations;
}

module.exports = { calculateScore, getRecommendations };
