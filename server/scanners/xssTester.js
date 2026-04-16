/**
 * XSS (Cross-Site Scripting) Tester
 *
 * Detection uses a unique canary token per request so reflections are unambiguous,
 * and a context classifier to decide whether the reflection is actually exploitable
 * (raw HTML vs. already-encoded vs. inside an attribute/JS string/comment).
 *
 * Contexts classified:
 *   - html-body       : payload lands between HTML tags, NOT encoded  →  exploitable
 *   - attribute-raw   : payload lands inside an attribute value without quote-escaping → exploitable
 *   - js-string       : payload lands inside a <script> block string without escaping → exploitable
 *   - encoded         : payload appears but HTML-encoded → safe
 *   - not-reflected   : payload absent → safe
 */

const axios = require('axios');
const crypto = require('crypto');
const { xssPayloads } = require('../utils/payloads');

async function testXSS(forms, options = {}) {
    const { maxPayloads = 8, timeout = 10000 } = options;
    const vulnerabilities = [];
    const tested = [];

    const payloadsToTest = xssPayloads.slice(0, maxPayloads);

    for (const form of forms) {
        const testableInputs = form.inputs.filter(input =>
            ['text', 'search', 'url', 'email'].includes(input.type) ||
            input.tag === 'textarea'
        );
        if (testableInputs.length === 0) continue;

        for (const input of testableInputs) {
            if (!input.name) continue;

            for (const payloadTemplate of payloadsToTest) {
                try {
                    // Unique canary per request so we know the reflection came from us
                    const canary = `cs${crypto.randomBytes(6).toString('hex')}`;
                    const payload = payloadTemplate.replace(/XSS/g, canary);

                    const result = await testPayload(form, input, payload, canary, timeout);
                    tested.push({ form: form.action, field: input.name });

                    if (result.vulnerable) {
                        vulnerabilities.push({
                            form: form.action,
                            formMethod: form.method,
                            field: input.name,
                            fieldType: input.type,
                            payload,
                            evidence: result.evidence,
                            context: result.context,
                            type: result.type,
                            severity: 'high',
                            confidence: result.confidence,
                        });
                        break; // move to next field
                    }
                } catch (error) {
                    // keep trying other payloads
                }
            }
        }
    }

    return {
        tested: tested.length,
        vulnerabilities,
        vulnerable: vulnerabilities.length > 0,
        summary: generateSummary(vulnerabilities),
    };
}

async function testPayload(form, input, payload, canary, timeout) {
    const formData = {};
    form.inputs.forEach(inp => {
        if (!inp.name) return;
        if (inp.name === input.name) formData[inp.name] = payload;
        else if (inp.type === 'password') formData[inp.name] = 'Nx9k2Lp4Qr7';
        else if (inp.type === 'email') formData[inp.name] = 'test@example.invalid';
        else formData[inp.name] = 'test';
    });

    const config = {
        timeout,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: {
            'User-Agent': 'CyberScan Security Scanner/2.0',
            'Content-Type': form.method === 'POST' ? 'application/x-www-form-urlencoded' : undefined,
        },
    };

    let response;
    try {
        response = form.method === 'POST'
            ? await axios.post(form.action, new URLSearchParams(formData).toString(), config)
            : await axios.get(form.action, { ...config, params: formData });
    } catch {
        return { vulnerable: false };
    }

    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    return classifyReflection(body, payload, canary);
}

/**
 * Classify where and how the payload was reflected.
 * Only raw reflections in exploitable contexts are reported as vulnerable.
 */
function classifyReflection(body, payload, canary) {
    // Canary absent → no reflection
    if (!body.includes(canary)) {
        return { vulnerable: false, context: 'not-reflected' };
    }

    // Full payload reflected as-is → definite XSS
    if (body.includes(payload)) {
        const context = detectContext(body, payload);
        if (context === 'encoded' || context === 'comment') {
            return { vulnerable: false, context, confidence: 'none' };
        }
        return {
            vulnerable: true,
            type: 'reflected',
            context,
            evidence: `Payload reflected unchanged in ${context} context`,
            confidence: 'high',
        };
    }

    // Canary reflected but payload mangled — look for dangerous fragments still present
    const dangerousFragments = [
        '<script', '</script>', 'onerror=', 'onload=', 'onclick=',
        'javascript:', '<svg', '<iframe', '<img src',
    ];
    for (const frag of dangerousFragments) {
        if (payload.toLowerCase().includes(frag) && body.toLowerCase().includes(frag)) {
            // Check if the fragment appears near our canary (within 100 chars)
            const canaryIdx = body.indexOf(canary);
            const fragIdx = body.toLowerCase().indexOf(frag);
            if (Math.abs(canaryIdx - fragIdx) < 200) {
                return {
                    vulnerable: true,
                    type: 'reflected-partial',
                    context: 'partial',
                    evidence: `Dangerous fragment "${frag}" reflected near canary`,
                    confidence: 'medium',
                };
            }
        }
    }

    // Canary present but fully encoded / stripped → sanitized
    return { vulnerable: false, context: 'encoded-or-stripped', confidence: 'none' };
}

/**
 * Determine the surrounding syntactic context of the first payload occurrence.
 */
function detectContext(body, payload) {
    const idx = body.indexOf(payload);
    if (idx === -1) return 'unknown';

    const before = body.slice(Math.max(0, idx - 200), idx);
    const after = body.slice(idx + payload.length, idx + payload.length + 50);

    // HTML comment
    if (/<!--[^]*$/.test(before) && /^[^]*-->/.test(after)) return 'comment';

    // Inside <script>
    const lastScriptOpen = before.lastIndexOf('<script');
    const lastScriptClose = before.lastIndexOf('</script>');
    if (lastScriptOpen > lastScriptClose) return 'js-string';

    // Inside an attribute value (look for unmatched quote before)
    const tagOpenIdx = before.lastIndexOf('<');
    const tagCloseIdx = before.lastIndexOf('>');
    if (tagOpenIdx > tagCloseIdx) {
        // we're inside a tag — attribute context
        return 'attribute-raw';
    }

    // If the payload chars look HTML-encoded in surrounding area, treat as encoded
    if (/&lt;|&gt;|&quot;|&#\d+;/.test(body.slice(Math.max(0, idx - 10), idx + payload.length + 10))) {
        return 'encoded';
    }

    return 'html-body';
}

// Test URL parameters for reflected XSS
async function testURLParams(url, timeout = 10000) {
    const vulnerabilities = [];
    const payloadsToTest = xssPayloads.slice(0, 5);

    try {
        const urlObj = new URL(url);
        const params = urlObj.searchParams;

        for (const [paramName] of params) {
            for (const payloadTemplate of payloadsToTest) {
                const canary = `cs${crypto.randomBytes(6).toString('hex')}`;
                const payload = payloadTemplate.replace(/XSS/g, canary);
                const testUrl = new URL(url);
                testUrl.searchParams.set(paramName, payload);

                try {
                    const response = await axios.get(testUrl.href, {
                        timeout,
                        validateStatus: () => true,
                    });
                    const body = typeof response.data === 'string'
                        ? response.data
                        : JSON.stringify(response.data);

                    const result = classifyReflection(body, payload, canary);
                    if (result.vulnerable) {
                        vulnerabilities.push({
                            url: testUrl.href,
                            param: paramName,
                            payload,
                            context: result.context,
                            evidence: result.evidence,
                            type: 'reflected-url',
                            confidence: result.confidence,
                        });
                        break;
                    }
                } catch { /* continue */ }
            }
        }
    } catch (error) {
        return { success: false, error: error.message, vulnerabilities: [] };
    }

    return {
        success: true,
        vulnerabilities,
        vulnerable: vulnerabilities.length > 0,
    };
}

function generateSummary(vulnerabilities) {
    if (vulnerabilities.length === 0) return 'No XSS vulnerabilities detected.';
    const byContext = vulnerabilities.reduce((m, v) => { m[v.context] = (m[v.context] || 0) + 1; return m; }, {});
    const parts = Object.entries(byContext).map(([c, n]) => `${n} in ${c}`);
    return `Found ${vulnerabilities.length} potential XSS vulnerabilities: ${parts.join(', ')}.`;
}

module.exports = { testXSS, testURLParams };
