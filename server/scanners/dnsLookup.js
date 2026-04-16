/**
 * DNS Lookup
 * Performs DNS resolution and domain information gathering
 */

const dns = require('dns').promises;
const { URL } = require('url');

async function lookupDNS(targetUrl) {
    try {
        const urlObj = new URL(targetUrl);
        const hostname = urlObj.hostname;

        const result = {
            hostname,
            ip: null,
            ipv6: null,
            nameservers: [],
            mxRecords: [],
            txtRecords: [],
            cname: null,
            reverseDNS: null
        };

        // Get A record (IPv4)
        try {
            const addresses = await dns.resolve4(hostname);
            result.ip = addresses[0];
            result.allIPs = addresses;
        } catch (e) {
            // No A record
        }

        // Get AAAA record (IPv6)
        try {
            const addresses = await dns.resolve6(hostname);
            result.ipv6 = addresses[0];
        } catch (e) {
            // No AAAA record
        }

        // Get nameservers
        try {
            const ns = await dns.resolveNs(hostname);
            result.nameservers = ns;
        } catch (e) {
            // Try parent domain
            const parts = hostname.split('.');
            if (parts.length > 2) {
                try {
                    const parentDomain = parts.slice(-2).join('.');
                    const ns = await dns.resolveNs(parentDomain);
                    result.nameservers = ns;
                } catch (e2) {
                    // No NS record found
                }
            }
        }

        // Get MX records
        try {
            const mx = await dns.resolveMx(hostname);
            result.mxRecords = mx.map(r => ({ exchange: r.exchange, priority: r.priority }));
        } catch (e) {
            // No MX record
        }

        // Get TXT records (might contain SPF, DKIM info)
        try {
            const txt = await dns.resolveTxt(hostname);
            result.txtRecords = txt.map(r => r.join(''));

            // Check for security-related TXT records
            result.hasSPF = result.txtRecords.some(r => r.includes('v=spf1'));
            result.hasDMARC = false;

            // Check _dmarc subdomain
            try {
                const dmarcTxt = await dns.resolveTxt(`_dmarc.${hostname}`);
                result.hasDMARC = dmarcTxt.some(r => r.join('').includes('v=DMARC1'));
            } catch (e) {
                // No DMARC
            }
        } catch (e) {
            // No TXT record
        }

        // Get CNAME if any
        try {
            const cname = await dns.resolveCname(hostname);
            result.cname = cname[0];
        } catch (e) {
            // No CNAME (direct A record)
        }

        // Reverse DNS lookup
        if (result.ip) {
            try {
                const hostnames = await dns.reverse(result.ip);
                result.reverseDNS = hostnames[0];
            } catch (e) {
                // No PTR record
            }
        }

        // Analyze domain for security indicators
        result.analysis = analyzeDomain(hostname, result);

        return {
            success: true,
            ...result
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            hostname: null,
            ip: null
        };
    }
}

function analyzeDomain(hostname, dnsData) {
    const analysis = {
        risks: [],
        info: []
    };

    // Check for suspicious TLDs
    const riskyTLDs = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'];
    const tld = '.' + hostname.split('.').pop();

    if (riskyTLDs.includes(tld.toLowerCase())) {
        analysis.risks.push({
            type: 'suspicious-tld',
            message: `Domain uses potentially risky TLD: ${tld}`,
            severity: 'medium'
        });
    }

    // Check for IP-like domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        analysis.risks.push({
            type: 'ip-domain',
            message: 'Domain appears to be an IP address',
            severity: 'high'
        });
    }

    // Check for very long domain  (often phishing)
    if (hostname.length > 30) {
        analysis.risks.push({
            type: 'long-domain',
            message: 'Unusually long domain name',
            severity: 'low'
        });
    }

    // Check for many subdomains (often phishing)
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 3) {
        analysis.risks.push({
            type: 'many-subdomains',
            message: `Domain has ${subdomainCount} subdomains`,
            severity: 'medium'
        });
    }

    // Check for typosquatting patterns
    const popularDomains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix'];
    const domainBase = hostname.split('.')[0].toLowerCase();

    for (const popular of popularDomains) {
        if (domainBase !== popular && domainBase.includes(popular)) {
            analysis.risks.push({
                type: 'typosquatting',
                message: `Domain might be typosquatting ${popular}`,
                severity: 'high'
            });
            break;
        }
    }

    // Check for missing email security
    if (!dnsData.hasSPF) {
        analysis.info.push({
            type: 'no-spf',
            message: 'No SPF record found (email spoofing possible)',
            severity: 'low'
        });
    }

    if (!dnsData.hasDMARC) {
        analysis.info.push({
            type: 'no-dmarc',
            message: 'No DMARC record found',
            severity: 'low'
        });
    }

    return analysis;
}

module.exports = { lookupDNS };
