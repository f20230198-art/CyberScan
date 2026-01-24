/**
 * Scan API Routes
 * Handles all security scanning endpoints
 */

const express = require('express');
const router = express.Router();

const { checkSSL } = require('../scanners/sslChecker');
const { checkHeaders } = require('../scanners/headerChecker');
const { crawlForms, deepCrawl } = require('../scanners/formCrawler');
const { testSQLi } = require('../scanners/sqliTester');
const { testXSS, testURLParams } = require('../scanners/xssTester');
const { lookupDNS } = require('../scanners/dnsLookup');
const { calculateScore, getRecommendations } = require('../utils/scoreCalculator');

// Validate URL
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Normalize URL
function normalizeUrl(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }
    return url;
}

/**
 * POST /api/scan
 * Full security scan
 */
router.post('/scan', async (req, res) => {
    const startTime = Date.now();

    try {
        let { url, options = {} } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        url = normalizeUrl(url);

        if (!isValidUrl(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        console.log(`\n🔍 Starting security scan for: ${url}`);

        // Create results object
        const results = {
            url,
            timestamp: new Date().toISOString(),
            ssl: null,
            headers: null,
            forms: null,
            sqli: null,
            xss: null,
            dns: null
        };

        // 1. SSL/TLS Check
        console.log('  📜 Checking SSL/TLS...');
        results.ssl = await checkSSL(url);

        // 2. Security Headers Check
        console.log('  🛡️  Checking security headers...');
        results.headers = await checkHeaders(url);

        // 3. DNS Lookup
        console.log('  🌐 Performing DNS lookup...');
        results.dns = await lookupDNS(url);

        // 4. Crawl for forms
        console.log('  🔎 Crawling for forms...');
        results.forms = await crawlForms(url);

        // 5. SQL Injection Testing (only if forms found)
        if (results.forms.forms && results.forms.forms.length > 0) {
            console.log(`  💉 Testing ${results.forms.forms.length} forms for SQL injection...`);
            results.sqli = await testSQLi(results.forms.forms, {
                maxPayloads: options.deepScan ? 15 : 8,
                timeout: 10000
            });
        } else {
            results.sqli = {
                tested: 0,
                vulnerabilities: [],
                vulnerable: false,
                summary: 'No forms found to test'
            };
        }

        // 6. XSS Testing (only if forms found)
        if (results.forms.forms && results.forms.forms.length > 0) {
            console.log(`  ⚡ Testing ${results.forms.forms.length} forms for XSS...`);
            results.xss = await testXSS(results.forms.forms, {
                maxPayloads: options.deepScan ? 10 : 5,
                timeout: 10000
            });
        } else {
            results.xss = {
                tested: 0,
                vulnerabilities: [],
                vulnerable: false,
                summary: 'No forms found to test'
            };
        }

        // Test URL parameters for XSS
        const urlParamResults = await testURLParams(url);
        if (urlParamResults.vulnerabilities && urlParamResults.vulnerabilities.length > 0) {
            results.xss.vulnerabilities.push(...urlParamResults.vulnerabilities);
            results.xss.vulnerable = true;
        }

        // Calculate overall score
        console.log('  📊 Calculating security score...');
        const scoreResult = calculateScore(results);
        const recommendations = getRecommendations(results);

        const duration = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`✅ Scan complete in ${duration}s - Score: ${scoreResult.score}/100 (${scoreResult.status})\n`);

        res.json({
            success: true,
            url,
            score: scoreResult.score,
            status: scoreResult.status,
            summary: scoreResult.summary,
            issues: scoreResult.issues,
            recommendations,
            details: {
                ssl: results.ssl,
                headers: results.headers,
                forms: {
                    total: results.forms.totalForms,
                    loginForms: results.forms.loginForms?.length || 0,
                    inputs: results.forms.totalInputs
                },
                sqli: results.sqli,
                xss: results.xss,
                dns: {
                    ip: results.dns.ip,
                    nameservers: results.dns.nameservers,
                    analysis: results.dns.analysis
                }
            },
            scanDuration: `${duration}s`
        });

    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/scan/quick
 * Quick scan - SSL and headers only
 */
router.post('/scan/quick', async (req, res) => {
    const startTime = Date.now();

    try {
        let { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        url = normalizeUrl(url);

        if (!isValidUrl(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        console.log(`⚡ Quick scan for: ${url}`);

        const [ssl, headers, dns] = await Promise.all([
            checkSSL(url),
            checkHeaders(url),
            lookupDNS(url)
        ]);

        const results = { ssl, headers, dns };
        const scoreResult = calculateScore(results);

        const duration = ((Date.now() - startTime) / 1000).toFixed(1);

        res.json({
            success: true,
            url,
            score: scoreResult.score,
            status: scoreResult.status,
            ssl,
            headers: {
                present: headers.present?.map(h => h.name) || [],
                missing: headers.missing?.map(h => h.name) || [],
                score: headers.score
            },
            dns: {
                ip: dns.ip,
                risks: dns.analysis?.risks || []
            },
            scanDuration: `${duration}s`
        });

    } catch (error) {
        console.error('Quick scan error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/scan/sqli
 * SQL Injection scan only
 */
router.post('/scan/sqli', async (req, res) => {
    try {
        let { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        url = normalizeUrl(url);

        console.log(`💉 SQLi scan for: ${url}`);

        const forms = await crawlForms(url);

        if (!forms.forms || forms.forms.length === 0) {
            return res.json({
                success: true,
                url,
                message: 'No forms found to test',
                vulnerabilities: []
            });
        }

        const sqliResults = await testSQLi(forms.forms, { maxPayloads: 15 });

        res.json({
            success: true,
            url,
            formsFound: forms.totalForms,
            ...sqliResults
        });

    } catch (error) {
        console.error('SQLi scan error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/scan/xss
 * XSS scan only
 */
router.post('/scan/xss', async (req, res) => {
    try {
        let { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        url = normalizeUrl(url);

        console.log(`⚡ XSS scan for: ${url}`);

        const forms = await crawlForms(url);
        const urlParamResults = await testURLParams(url);

        let xssResults = { tested: 0, vulnerabilities: [], vulnerable: false };

        if (forms.forms && forms.forms.length > 0) {
            xssResults = await testXSS(forms.forms, { maxPayloads: 10 });
        }

        // Combine with URL param results
        if (urlParamResults.vulnerabilities) {
            xssResults.vulnerabilities.push(...urlParamResults.vulnerabilities);
            xssResults.vulnerable = xssResults.vulnerabilities.length > 0;
        }

        res.json({
            success: true,
            url,
            formsFound: forms.totalForms,
            ...xssResults
        });

    } catch (error) {
        console.error('XSS scan error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/health
 * Health check endpoint
 */
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

module.exports = router;
