/**
 * SSL/TLS Certificate Checker
 * Analyzes SSL certificate validity, expiration, and security
 */

const https = require('https');
const tls = require('tls');
const { URL } = require('url');

async function checkSSL(targetUrl) {
    return new Promise((resolve) => {
        try {
            const urlObj = new URL(targetUrl);

            // If not HTTPS, immediately flag as insecure
            if (urlObj.protocol !== 'https:') {
                resolve({
                    valid: false,
                    https: false,
                    error: 'Website does not use HTTPS',
                    issuer: null,
                    validFrom: null,
                    validTo: null,
                    daysUntilExpiry: null,
                    expired: false,
                    expiresSoon: false
                });
                return;
            }

            const options = {
                host: urlObj.hostname,
                port: urlObj.port || 443,
                method: 'GET',
                rejectUnauthorized: false, // Allow self-signed for analysis
                timeout: 10000
            };

            const req = https.request(options, (res) => {
                const cert = res.socket.getPeerCertificate();

                if (!cert || Object.keys(cert).length === 0) {
                    resolve({
                        valid: false,
                        https: true,
                        error: 'Could not retrieve certificate',
                        issuer: null,
                        validFrom: null,
                        validTo: null,
                        daysUntilExpiry: null,
                        expired: false,
                        expiresSoon: false
                    });
                    return;
                }

                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const now = new Date();
                const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
                const isExpired = now > validTo;
                const expiresSoon = daysUntilExpiry <= 30 && daysUntilExpiry > 0;

                // Check if certificate is authorized (not self-signed)
                const isAuthorized = res.socket.authorized;

                resolve({
                    valid: isAuthorized && !isExpired,
                    https: true,
                    issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN : 'Unknown',
                    subject: cert.subject ? cert.subject.CN : urlObj.hostname,
                    validFrom: validFrom.toISOString(),
                    validTo: validTo.toISOString(),
                    daysUntilExpiry,
                    expired: isExpired,
                    expiresSoon,
                    selfSigned: !isAuthorized,
                    fingerprint: cert.fingerprint,
                    serialNumber: cert.serialNumber
                });
            });

            req.on('error', (err) => {
                resolve({
                    valid: false,
                    https: true,
                    error: err.message,
                    issuer: null,
                    validFrom: null,
                    validTo: null,
                    daysUntilExpiry: null,
                    expired: false,
                    expiresSoon: false
                });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({
                    valid: false,
                    https: true,
                    error: 'Connection timeout',
                    issuer: null,
                    validFrom: null,
                    validTo: null,
                    daysUntilExpiry: null,
                    expired: false,
                    expiresSoon: false
                });
            });

            req.end();
        } catch (error) {
            resolve({
                valid: false,
                https: false,
                error: error.message,
                issuer: null,
                validFrom: null,
                validTo: null,
                daysUntilExpiry: null,
                expired: false,
                expiresSoon: false
            });
        }
    });
}

module.exports = { checkSSL };
