/**
 * Security Middleware for CyberScan
 * Provides rate limiting, ToS acceptance, and logging
 */

const fs = require('fs');
const path = require('path');

// In-memory storage for scan logs and ToS acceptance
const scanLogs = [];
const tosAcceptedIPs = new Set();

// Log file path
const LOG_FILE = path.join(__dirname, '..', 'scan_logs.json');

/**
 * Rate limiting configuration
 */
const rateLimitConfig = {
    windowMs: 60 * 1000, // 1 minute
    maxScans: 5,         // Max 5 scans per minute per IP
    message: {
        success: false,
        error: 'Rate limit exceeded. Please wait before scanning again.',
        retryAfter: 60
    }
};

// Track requests per IP
const requestCounts = new Map();

/**
 * Rate limiter middleware
 */
function rateLimiter(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();

    // Clean up old entries
    for (const [key, data] of requestCounts.entries()) {
        if (now - data.windowStart > rateLimitConfig.windowMs) {
            requestCounts.delete(key);
        }
    }

    // Get or create entry for this IP
    let ipData = requestCounts.get(ip);
    if (!ipData || now - ipData.windowStart > rateLimitConfig.windowMs) {
        ipData = { count: 0, windowStart: now };
        requestCounts.set(ip, ipData);
    }

    // Check rate limit
    if (ipData.count >= rateLimitConfig.maxScans) {
        const retryAfter = Math.ceil((ipData.windowStart + rateLimitConfig.windowMs - now) / 1000);
        res.set('Retry-After', retryAfter);
        return res.status(429).json({
            ...rateLimitConfig.message,
            retryAfter
        });
    }

    // Increment count
    ipData.count++;

    // Add rate limit headers
    res.set('X-RateLimit-Limit', rateLimitConfig.maxScans);
    res.set('X-RateLimit-Remaining', rateLimitConfig.maxScans - ipData.count);
    res.set('X-RateLimit-Reset', new Date(ipData.windowStart + rateLimitConfig.windowMs).toISOString());

    next();
}

/**
 * Terms of Service check middleware
 */
function requireToS(req, res, next) {
    const tosAccepted = req.headers['x-tos-accepted'] === 'true' || req.body.tosAccepted === true;

    if (!tosAccepted) {
        return res.status(403).json({
            success: false,
            error: 'Terms of Service must be accepted',
            tosRequired: true,
            terms: {
                title: 'Terms of Service',
                content: 'By using CyberScan, you agree to:\n1. Only scan websites you own or have explicit permission to test\n2. Not use this tool for malicious purposes\n3. Accept full responsibility for your actions\n4. Not attempt to circumvent rate limits or abuse the service',
                acceptHeader: 'X-ToS-Accepted: true'
            }
        });
    }

    next();
}

/**
 * Log scan activity
 */
function logScan(req, url, result) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const logEntry = {
        timestamp: new Date().toISOString(),
        ip: ip,
        url: url,
        score: result?.score || null,
        status: result?.status || 'unknown',
        userAgent: userAgent,
        duration: result?.scanDuration || null
    };

    // Add to in-memory log
    scanLogs.push(logEntry);

    // Keep only last 1000 entries in memory
    if (scanLogs.length > 1000) {
        scanLogs.shift();
    }

    // Append to log file (non-blocking)
    fs.promises.readFile(LOG_FILE, 'utf8')
        .catch(() => '[]')
        .then(content => {
            const existingLogs = JSON.parse(content);
            existingLogs.push(logEntry);
            const trimmed = existingLogs.length > 10000 ? existingLogs.slice(-10000) : existingLogs;
            return fs.promises.writeFile(LOG_FILE, JSON.stringify(trimmed, null, 2));
        })
        .catch(error => console.error('Error writing scan log:', error.message));

    // Console log
    console.log(`📝 Scan logged: ${ip} -> ${url} (Score: ${result?.score || 'N/A'})`);

    return logEntry;
}

/**
 * URL validation
 */
function validateURL(url) {
    if (!url || typeof url !== 'string') {
        return { valid: false, error: 'URL is required' };
    }

    // Trim and normalize
    url = url.trim();

    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    try {
        const urlObj = new URL(url);

        // Only allow http and https
        if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
            return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
        }

        // Block localhost and private IPs
        const hostname = urlObj.hostname.toLowerCase();
        const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
        if (blockedHosts.includes(hostname)) {
            return { valid: false, error: 'Scanning localhost is not allowed' };
        }

        // Block private IP ranges
        const privateIPPatterns = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./
        ];

        for (const pattern of privateIPPatterns) {
            if (pattern.test(hostname)) {
                return { valid: false, error: 'Scanning private IP addresses is not allowed' };
            }
        }

        return { valid: true, url: urlObj.href };
    } catch (error) {
        return { valid: false, error: 'Invalid URL format' };
    }
}

/**
 * Get scan statistics
 */
function getScanStats() {
    const now = Date.now();
    const lastHour = scanLogs.filter(log =>
        new Date(log.timestamp).getTime() > now - 60 * 60 * 1000
    );
    const lastDay = scanLogs.filter(log =>
        new Date(log.timestamp).getTime() > now - 24 * 60 * 60 * 1000
    );

    return {
        totalScans: scanLogs.length,
        scansLastHour: lastHour.length,
        scansLastDay: lastDay.length,
        uniqueIPs: new Set(scanLogs.map(l => l.ip)).size,
        averageScore: Math.round(
            scanLogs.filter(l => l.score).reduce((sum, l) => sum + l.score, 0) /
            scanLogs.filter(l => l.score).length || 0
        )
    };
}

module.exports = {
    rateLimiter,
    requireToS,
    logScan,
    validateURL,
    getScanStats,
    scanLogs
};
