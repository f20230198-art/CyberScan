/**
 * XSS (Cross-Site Scripting) Tester
 * Tests forms and inputs for XSS vulnerabilities
 */

const axios = require('axios');
const { xssPayloads, xssSanitizationPatterns } = require('../utils/payloads');

async function testXSS(forms, options = {}) {
    const { maxPayloads = 8, timeout = 10000 } = options;
    const vulnerabilities = [];
    const tested = [];

    // Use a subset of payloads for faster scanning
    const payloadsToTest = xssPayloads.slice(0, maxPayloads);

    for (const form of forms) {
        // Focus on forms with text inputs
        const testableInputs = form.inputs.filter(input =>
            ['text', 'search', 'url', 'email'].includes(input.type) ||
            input.tag === 'textarea'
        );

        if (testableInputs.length === 0) continue;

        for (const input of testableInputs) {
            if (!input.name) continue;

            for (const payload of payloadsToTest) {
                try {
                    const result = await testPayload(form, input, payload, timeout);
                    tested.push({
                        form: form.action,
                        field: input.name,
                        payload: payload.substring(0, 30) + '...'
                    });

                    if (result.vulnerable) {
                        vulnerabilities.push({
                            form: form.action,
                            formMethod: form.method,
                            field: input.name,
                            fieldType: input.type,
                            payload,
                            evidence: result.evidence,
                            type: result.type,
                            severity: 'high',
                            confidence: result.confidence
                        });

                        // Found vulnerability in this field, move to next field
                        break;
                    }
                } catch (error) {
                    console.log(`Error testing ${input.name}: ${error.message}`);
                }
            }
        }
    }

    return {
        tested: tested.length,
        vulnerabilities,
        vulnerable: vulnerabilities.length > 0,
        summary: generateSummary(vulnerabilities)
    };
}

async function testPayload(form, input, payload, timeout) {
    const formData = {};

    // Fill all inputs with benign values, except the target
    form.inputs.forEach(inp => {
        if (inp.name) {
            if (inp.name === input.name) {
                formData[inp.name] = payload;
            } else if (inp.type === 'password') {
                formData[inp.name] = 'testpass123';
            } else if (inp.type === 'email') {
                formData[inp.name] = 'test@test.com';
            } else {
                formData[inp.name] = 'test';
            }
        }
    });

    const config = {
        timeout,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: {
            'User-Agent': 'CyberScan Security Scanner/1.0',
            'Content-Type': form.method === 'POST'
                ? 'application/x-www-form-urlencoded'
                : undefined
        }
    };

    let response;

    try {
        if (form.method === 'POST') {
            response = await axios.post(form.action, new URLSearchParams(formData).toString(), config);
        } else {
            response = await axios.get(form.action, { ...config, params: formData });
        }
    } catch (error) {
        return { vulnerable: false, evidence: null, confidence: 'none' };
    }

    const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    // Check for reflected XSS (payload appears in response unchanged)
    if (responseBody.includes(payload)) {
        return {
            vulnerable: true,
            evidence: 'Payload reflected in response without sanitization',
            type: 'reflected',
            confidence: 'high'
        };
    }

    // Check for partially reflected payload (might still be exploitable)
    // Remove closing tags and check for opening parts
    const partialPayloads = [
        '<script>',
        '<img src=x',
        '<svg onload',
        'onerror=',
        'onclick=',
        'javascript:'
    ];

    for (const partial of partialPayloads) {
        if (payload.includes(partial) && responseBody.toLowerCase().includes(partial.toLowerCase())) {
            // Check if it's sanitized
            let isSanitized = false;
            for (const pattern of xssSanitizationPatterns) {
                if (pattern.test(responseBody)) {
                    isSanitized = true;
                    break;
                }
            }

            if (!isSanitized) {
                return {
                    vulnerable: true,
                    evidence: `Partial payload reflected: ${partial}`,
                    type: 'reflected-partial',
                    confidence: 'medium'
                };
            }
        }
    }

    // Check for DOM-based XSS indicators
    const domXSSPatterns = [
        /document\.write\s*\(/i,
        /\.innerHTML\s*=/i,
        /eval\s*\(/i,
        /setTimeout\s*\([^)]*\+/i,
        /setInterval\s*\([^)]*\+/i
    ];

    for (const pattern of domXSSPatterns) {
        if (pattern.test(responseBody)) {
            // This is just an indicator, not a confirmed vulnerability
            // Would need more sophisticated testing for DOM XSS
        }
    }

    return { vulnerable: false, evidence: null, confidence: 'none' };
}

// Test URL parameters for reflected XSS
async function testURLParams(url, timeout = 10000) {
    const vulnerabilities = [];
    const payloadsToTest = xssPayloads.slice(0, 5); // Fewer payloads for URL testing

    try {
        const urlObj = new URL(url);
        const params = urlObj.searchParams;

        for (const [paramName, paramValue] of params) {
            for (const payload of payloadsToTest) {
                const testUrl = new URL(url);
                testUrl.searchParams.set(paramName, payload);

                try {
                    const response = await axios.get(testUrl.href, {
                        timeout,
                        validateStatus: () => true
                    });

                    const responseBody = typeof response.data === 'string'
                        ? response.data
                        : JSON.stringify(response.data);

                    if (responseBody.includes(payload)) {
                        vulnerabilities.push({
                            url: testUrl.href,
                            param: paramName,
                            payload,
                            type: 'reflected-url',
                            confidence: 'high'
                        });
                        break; // Found vulnerability for this param
                    }
                } catch (error) {
                    // Continue with other payloads
                }
            }
        }
    } catch (error) {
        return { success: false, error: error.message, vulnerabilities: [] };
    }

    return {
        success: true,
        vulnerabilities,
        vulnerable: vulnerabilities.length > 0
    };
}

function generateSummary(vulnerabilities) {
    if (vulnerabilities.length === 0) {
        return 'No XSS vulnerabilities detected.';
    }

    const reflected = vulnerabilities.filter(v => v.type.includes('reflected')).length;
    const dom = vulnerabilities.filter(v => v.type === 'dom').length;

    return `Found ${vulnerabilities.length} potential XSS vulnerabilities: ${reflected} reflected XSS, ${dom} DOM-based XSS.`;
}

module.exports = { testXSS, testURLParams };
