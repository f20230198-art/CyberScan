/**
 * Security Score Calculator
 * Calculates overall security score based on scan results
 */

function calculateScore(results) {
    let score = 100;
    let issues = [];

    // SSL/TLS Issues (max -25 points)
    if (results.ssl) {
        if (!results.ssl.valid) {
            score -= 15;
            issues.push({ type: 'ssl', severity: 'high', message: 'Invalid or missing SSL certificate' });
        }
        if (results.ssl.expired) {
            score -= 10;
            issues.push({ type: 'ssl', severity: 'high', message: 'SSL certificate has expired' });
        }
        if (results.ssl.expiresSoon) {
            score -= 5;
            issues.push({ type: 'ssl', severity: 'medium', message: 'SSL certificate expires soon' });
        }
    }

    // Security Headers Issues (max -50 points)
    if (results.headers && results.headers.missing) {
        results.headers.missing.forEach(header => {
            score -= header.points || 5;
            issues.push({
                type: 'header',
                severity: header.importance || 'medium',
                message: `Missing security header: ${header.name}`
            });
        });
    }

    // SQL Injection Vulnerabilities (max -45 points, -15 each, max 3)
    if (results.sqli && results.sqli.vulnerabilities) {
        const sqliCount = Math.min(results.sqli.vulnerabilities.length, 3);
        score -= sqliCount * 15;
        results.sqli.vulnerabilities.forEach(vuln => {
            issues.push({
                type: 'sqli',
                severity: 'critical',
                message: `SQL Injection vulnerability in ${vuln.form} (field: ${vuln.field})`
            });
        });
    }

    // XSS Vulnerabilities (max -36 points, -12 each, max 3)
    if (results.xss && results.xss.vulnerabilities) {
        const xssCount = Math.min(results.xss.vulnerabilities.length, 3);
        score -= xssCount * 12;
        results.xss.vulnerabilities.forEach(vuln => {
            issues.push({
                type: 'xss',
                severity: 'high',
                message: `XSS vulnerability in ${vuln.form} (field: ${vuln.field})`
            });
        });
    }

    // DNS/Domain Issues
    if (results.dns) {
        if (results.dns.domainAgeDays < 30) {
            score -= 10;
            issues.push({ type: 'dns', severity: 'medium', message: 'Domain is less than 30 days old' });
        } else if (results.dns.domainAgeDays < 90) {
            score -= 5;
            issues.push({ type: 'dns', severity: 'low', message: 'Domain is less than 90 days old' });
        }
    }

    // Ensure score is between 0 and 100
    score = Math.max(0, Math.min(100, score));

    // Determine status based on score
    let status;
    if (score >= 80) {
        status = 'Secure';
    } else if (score >= 60) {
        status = 'Moderate';
    } else if (score >= 40) {
        status = 'Warning';
    } else if (score >= 20) {
        status = 'High Risk';
    } else {
        status = 'Critical';
    }

    return {
        score,
        status,
        issues,
        summary: {
            totalIssues: issues.length,
            critical: issues.filter(i => i.severity === 'critical').length,
            high: issues.filter(i => i.severity === 'high').length,
            medium: issues.filter(i => i.severity === 'medium').length,
            low: issues.filter(i => i.severity === 'low').length
        }
    };
}

function getRecommendations(results) {
    const recommendations = [];

    if (results.ssl && !results.ssl.valid) {
        recommendations.push({
            priority: 'critical',
            title: 'Install SSL Certificate',
            description: 'Configure HTTPS with a valid SSL/TLS certificate. Use Let\'s Encrypt for free certificates.'
        });
    }

    if (results.headers && results.headers.missing && results.headers.missing.length > 0) {
        const highImportanceHeaders = results.headers.missing.filter(h => h.importance === 'high');
        if (highImportanceHeaders.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Add Critical Security Headers',
                description: `Add these headers: ${highImportanceHeaders.map(h => h.name).join(', ')}`
            });
        }
    }

    if (results.sqli && results.sqli.vulnerabilities && results.sqli.vulnerabilities.length > 0) {
        recommendations.push({
            priority: 'critical',
            title: 'Fix SQL Injection Vulnerabilities',
            description: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.'
        });
    }

    if (results.xss && results.xss.vulnerabilities && results.xss.vulnerabilities.length > 0) {
        recommendations.push({
            priority: 'high',
            title: 'Fix XSS Vulnerabilities',
            description: 'Sanitize and escape all user input before rendering. Implement Content-Security-Policy header.'
        });
    }

    return recommendations;
}

module.exports = {
    calculateScore,
    getRecommendations
};
