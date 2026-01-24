/**
 * Report Generator for CyberScan
 * Generates professional security reports in PDF and JSON formats
 */

/**
 * Generate a comprehensive JSON report
 */
function generateJSONReport(scanData, url) {
    const report = {
        reportInfo: {
            title: "CyberScan Security Assessment Report",
            generatedAt: new Date().toISOString(),
            generatedBy: "CyberScan Security Scanner v2.0",
            targetUrl: url,
            scanDuration: scanData.scanDuration || "N/A"
        },
        executiveSummary: {
            overallScore: scanData.score,
            riskLevel: getRiskLevel(scanData.score),
            totalVulnerabilities: scanData.issues?.length || 0,
            criticalFindings: countBySeverity(scanData.issues, 'critical'),
            highFindings: countBySeverity(scanData.issues, 'high'),
            mediumFindings: countBySeverity(scanData.issues, 'medium'),
            lowFindings: countBySeverity(scanData.issues, 'low'),
            recommendation: getOverallRecommendation(scanData.score)
        },
        sslAnalysis: {
            status: scanData.details?.ssl?.valid ? "PASSED" : "FAILED",
            hasHttps: scanData.details?.ssl?.hasSSL || false,
            certificateValid: scanData.details?.ssl?.valid || false,
            expiresIn: scanData.details?.ssl?.daysUntilExpiry ? `${scanData.details.ssl.daysUntilExpiry} days` : "N/A",
            issuer: scanData.details?.ssl?.issuer || "Unknown",
            protocol: scanData.details?.ssl?.protocol || "Unknown"
        },
        securityHeaders: {
            score: scanData.details?.headers?.score || 0,
            present: scanData.details?.headers?.present?.map(h => h.name) || [],
            missing: scanData.details?.headers?.missing?.map(h => ({
                name: h.name,
                importance: h.importance,
                recommendation: h.recommendation
            })) || []
        },
        vulnerabilityAssessment: {
            sqlInjection: {
                tested: scanData.details?.sqli?.tested || 0,
                vulnerable: scanData.details?.sqli?.vulnerable || false,
                vulnerabilitiesFound: scanData.details?.sqli?.vulnerabilities?.length || 0,
                details: scanData.details?.sqli?.vulnerabilities || []
            },
            crossSiteScripting: {
                tested: scanData.details?.xss?.tested || 0,
                vulnerable: scanData.details?.xss?.vulnerable || false,
                vulnerabilitiesFound: scanData.details?.xss?.vulnerabilities?.length || 0,
                details: scanData.details?.xss?.vulnerabilities || []
            }
        },
        dnsAnalysis: {
            ipAddress: scanData.details?.dns?.ip || "Unknown",
            nameservers: scanData.details?.dns?.nameservers || [],
            risks: scanData.details?.dns?.analysis?.risks || []
        },
        findings: scanData.issues || [],
        recommendations: scanData.recommendations || [],
        disclaimer: "This report is generated for informational purposes only. The security assessment is based on automated scanning and may not identify all vulnerabilities. A professional security audit is recommended for comprehensive security evaluation."
    };

    return report;
}

/**
 * Generate HTML report (for PDF conversion)
 */
function generateHTMLReport(scanData, url) {
    const report = generateJSONReport(scanData, url);
    const riskColor = getRiskColor(report.executiveSummary.overallScore);

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - ${url}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 900px; margin: 0 auto; background: white; }
        
        /* Header */
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.8; font-size: 14px; }
        .header .target-url { background: rgba(255,255,255,0.1); padding: 10px 20px; border-radius: 8px; margin-top: 20px; font-family: monospace; word-break: break-all; }
        
        /* Score Section */
        .score-section { display: flex; justify-content: center; padding: 40px; background: #fafafa; border-bottom: 1px solid #eee; }
        .score-circle { width: 180px; height: 180px; border-radius: 50%; background: ${riskColor}; display: flex; flex-direction: column; align-items: center; justify-content: center; color: white; box-shadow: 0 10px 40px ${riskColor}40; }
        .score-circle .score { font-size: 60px; font-weight: bold; }
        .score-circle .label { font-size: 14px; text-transform: uppercase; opacity: 0.9; }
        
        /* Summary Cards */
        .summary-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; padding: 30px 40px; background: white; }
        .summary-card { text-align: center; padding: 20px; border-radius: 12px; background: #f8f9fa; }
        .summary-card .count { font-size: 32px; font-weight: bold; }
        .summary-card .label { font-size: 12px; color: #666; text-transform: uppercase; }
        .summary-card.critical .count { color: #dc2626; }
        .summary-card.high .count { color: #ea580c; }
        .summary-card.medium .count { color: #ca8a04; }
        .summary-card.low .count { color: #16a34a; }
        
        /* Section */
        .section { padding: 30px 40px; border-bottom: 1px solid #eee; }
        .section h2 { font-size: 20px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; display: flex; align-items: center; gap: 10px; }
        .section h2::before { content: ''; width: 4px; height: 24px; background: ${riskColor}; border-radius: 2px; }
        
        /* Status Badge */
        .status-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .status-badge.passed { background: #dcfce7; color: #16a34a; }
        .status-badge.failed { background: #fee2e2; color: #dc2626; }
        .status-badge.warning { background: #fef3c7; color: #ca8a04; }
        
        /* Table */
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; font-size: 12px; text-transform: uppercase; color: #666; }
        tr:hover { background: #fafafa; }
        
        /* Info Grid */
        .info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }
        .info-item { padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .info-item .label { font-size: 12px; color: #666; margin-bottom: 5px; }
        .info-item .value { font-weight: 600; }
        
        /* Finding Card */
        .finding-card { background: #fff; border: 1px solid #eee; border-left: 4px solid; border-radius: 8px; padding: 15px 20px; margin-bottom: 15px; }
        .finding-card.critical { border-left-color: #dc2626; }
        .finding-card.high { border-left-color: #ea580c; }
        .finding-card.medium { border-left-color: #ca8a04; }
        .finding-card.low { border-left-color: #16a34a; }
        .finding-card .severity { font-size: 11px; font-weight: bold; text-transform: uppercase; margin-bottom: 5px; }
        .finding-card.critical .severity { color: #dc2626; }
        .finding-card.high .severity { color: #ea580c; }
        .finding-card.medium .severity { color: #ca8a04; }
        .finding-card.low .severity { color: #16a34a; }
        .finding-card .message { font-weight: 500; margin-bottom: 5px; }
        .finding-card .type { font-size: 12px; color: #666; }
        
        /* Recommendation */
        .recommendation { background: #eff6ff; border: 1px solid #bfdbfe; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .recommendation h4 { color: #1d4ed8; margin-bottom: 10px; }
        
        /* Footer */
        .footer { background: #1a1a2e; color: white; padding: 30px 40px; text-align: center; }
        .footer .disclaimer { font-size: 11px; opacity: 0.7; max-width: 700px; margin: 0 auto; }
        .footer .generated { margin-top: 15px; font-size: 12px; }
        
        /* Print styles */
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            .section { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <p class="subtitle">Generated by CyberScan Security Scanner</p>
            <div class="target-url">${url}</div>
        </div>
        
        <div class="score-section">
            <div class="score-circle">
                <div class="score">${report.executiveSummary.overallScore}</div>
                <div class="label">${report.executiveSummary.riskLevel}</div>
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card critical">
                <div class="count">${report.executiveSummary.criticalFindings}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">${report.executiveSummary.highFindings}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">${report.executiveSummary.mediumFindings}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">${report.executiveSummary.lowFindings}</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p style="margin-bottom: 20px;">${report.executiveSummary.recommendation}</p>
            <div class="info-grid">
                <div class="info-item">
                    <div class="label">Scan Duration</div>
                    <div class="value">${report.reportInfo.scanDuration}</div>
                </div>
                <div class="info-item">
                    <div class="label">Total Vulnerabilities</div>
                    <div class="value">${report.executiveSummary.totalVulnerabilities}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>SSL/TLS Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="label">Status</div>
                    <div class="value"><span class="status-badge ${report.sslAnalysis.status === 'PASSED' ? 'passed' : 'failed'}">${report.sslAnalysis.status}</span></div>
                </div>
                <div class="info-item">
                    <div class="label">Certificate Valid</div>
                    <div class="value">${report.sslAnalysis.certificateValid ? 'Yes' : 'No'}</div>
                </div>
                <div class="info-item">
                    <div class="label">Expires In</div>
                    <div class="value">${report.sslAnalysis.expiresIn}</div>
                </div>
                <div class="info-item">
                    <div class="label">Issuer</div>
                    <div class="value">${report.sslAnalysis.issuer}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Security Headers</h2>
            <p style="margin-bottom: 15px;">Score: <strong>${report.securityHeaders.score}%</strong></p>
            
            ${report.securityHeaders.present.length > 0 ? `
            <h4 style="color: #16a34a; margin: 20px 0 10px;">✓ Present Headers</h4>
            <table>
                <tr>${report.securityHeaders.present.map(h => `<td><span class="status-badge passed">${h}</span></td>`).join('')}</tr>
            </table>
            ` : ''}
            
            ${report.securityHeaders.missing.length > 0 ? `
            <h4 style="color: #dc2626; margin: 20px 0 10px;">✗ Missing Headers</h4>
            <table>
                <thead>
                    <tr><th>Header</th><th>Importance</th><th>Recommendation</th></tr>
                </thead>
                <tbody>
                    ${report.securityHeaders.missing.map(h => `
                        <tr>
                            <td><strong>${h.name}</strong></td>
                            <td>${h.importance}</td>
                            <td>${h.recommendation}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            ` : ''}
        </div>
        
        <div class="section">
            <h2>Vulnerability Assessment</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="label">SQL Injection</div>
                    <div class="value">
                        <span class="status-badge ${report.vulnerabilityAssessment.sqlInjection.vulnerable ? 'failed' : 'passed'}">
                            ${report.vulnerabilityAssessment.sqlInjection.vulnerable ? `${report.vulnerabilityAssessment.sqlInjection.vulnerabilitiesFound} FOUND` : 'SECURE'}
                        </span>
                    </div>
                </div>
                <div class="info-item">
                    <div class="label">Cross-Site Scripting (XSS)</div>
                    <div class="value">
                        <span class="status-badge ${report.vulnerabilityAssessment.crossSiteScripting.vulnerable ? 'failed' : 'passed'}">
                            ${report.vulnerabilityAssessment.crossSiteScripting.vulnerable ? `${report.vulnerabilityAssessment.crossSiteScripting.vulnerabilitiesFound} FOUND` : 'SECURE'}
                        </span>
                    </div>
                </div>
            </div>
        </div>
        
        ${report.findings.length > 0 ? `
        <div class="section">
            <h2>Detailed Findings</h2>
            ${report.findings.map(f => `
                <div class="finding-card ${f.severity}">
                    <div class="severity">${f.severity}</div>
                    <div class="message">${f.message}</div>
                    <div class="type">${f.type}</div>
                </div>
            `).join('')}
        </div>
        ` : ''}
        
        ${report.recommendations.length > 0 ? `
        <div class="section">
            <h2>Recommendations</h2>
            <ul style="margin-left: 20px;">
                ${report.recommendations.map(r => `<li style="margin-bottom: 10px;">${r}</li>`).join('')}
            </ul>
        </div>
        ` : ''}
        
        <div class="footer">
            <p class="disclaimer">${report.disclaimer}</p>
            <p class="generated">Generated on ${new Date().toLocaleString()} by CyberScan Security Scanner v2.0</p>
        </div>
    </div>
</body>
</html>`;
}

// Helper functions
function getRiskLevel(score) {
    if (score >= 80) return 'LOW RISK';
    if (score >= 60) return 'MODERATE RISK';
    if (score >= 40) return 'HIGH RISK';
    return 'CRITICAL RISK';
}

function getRiskColor(score) {
    if (score >= 80) return '#16a34a';
    if (score >= 60) return '#ca8a04';
    if (score >= 40) return '#ea580c';
    return '#dc2626';
}

function countBySeverity(issues, severity) {
    if (!issues) return 0;
    return issues.filter(i => i.severity === severity).length;
}

function getOverallRecommendation(score) {
    if (score >= 80) {
        return "This website demonstrates good security practices. Continue monitoring and maintaining current security measures. Consider implementing additional security headers for enhanced protection.";
    } else if (score >= 60) {
        return "This website has moderate security. Several improvements are recommended, particularly in security headers configuration. Address the identified issues to strengthen your security posture.";
    } else if (score >= 40) {
        return "This website has significant security concerns that require attention. Prioritize fixing the high and critical severity issues identified in this report. A comprehensive security review is recommended.";
    }
    return "This website has critical security vulnerabilities that pose immediate risk. Urgent remediation is required. Consider taking the site offline until critical issues are addressed. Engage a security professional for immediate assistance.";
}

// Export functions - make them available globally
window.CyberScanReport = {
    generateJSONReport,
    generateHTMLReport,

    // Download JSON report
    downloadJSON: function (scanData, url) {
        const report = generateJSONReport(scanData, url);
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const filename = `cyberscan-report-${new URL(url).hostname}-${Date.now()}.json`;
        downloadBlob(blob, filename);
    },

    // Download HTML report (can be printed as PDF)
    downloadHTML: function (scanData, url) {
        const html = generateHTMLReport(scanData, url);
        const blob = new Blob([html], { type: 'text/html' });
        const filename = `cyberscan-report-${new URL(url).hostname}-${Date.now()}.html`;
        downloadBlob(blob, filename);
    },

    // Open report in new window for printing as PDF
    openForPrint: function (scanData, url) {
        const html = generateHTMLReport(scanData, url);
        const printWindow = window.open('', '_blank');
        printWindow.document.write(html);
        printWindow.document.close();
        // Auto-trigger print dialog after a short delay
        setTimeout(() => {
            printWindow.print();
        }, 500);
    }
};

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
