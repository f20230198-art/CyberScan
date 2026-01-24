/**
 * SQL Injection Tester
 * Tests forms for SQL injection vulnerabilities
 */

const axios = require('axios');
const { sqliPayloads, sqlErrorPatterns } = require('../utils/payloads');

async function testSQLi(forms, options = {}) {
    const { maxPayloads = 10, timeout = 10000 } = options;
    const vulnerabilities = [];
    const tested = [];

    // Use a subset of payloads for faster scanning
    const payloadsToTest = sqliPayloads.slice(0, maxPayloads);

    for (const form of forms) {
        // Focus on forms with text/password inputs
        const testableInputs = form.inputs.filter(input =>
            ['text', 'password', 'email', 'search', 'tel', 'url'].includes(input.type) ||
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
                        payload: payload.substring(0, 20) + '...'
                    });

                    if (result.vulnerable) {
                        vulnerabilities.push({
                            form: form.action,
                            formMethod: form.method,
                            field: input.name,
                            fieldType: input.type,
                            payload,
                            evidence: result.evidence,
                            severity: 'critical',
                            confidence: result.confidence
                        });

                        // Found vulnerability in this field, move to next field
                        break;
                    }
                } catch (error) {
                    // Continue testing other payloads
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
    const startTime = Date.now();

    try {
        if (form.method === 'POST') {
            response = await axios.post(form.action, new URLSearchParams(formData).toString(), config);
        } else {
            response = await axios.get(form.action, { ...config, params: formData });
        }
    } catch (error) {
        return { vulnerable: false, evidence: null, confidence: 'none' };
    }

    const responseTime = Date.now() - startTime;
    const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    // Check for SQL error messages
    for (const pattern of sqlErrorPatterns) {
        if (pattern.test(responseBody)) {
            return {
                vulnerable: true,
                evidence: `SQL error detected: ${responseBody.match(pattern)[0]}`,
                confidence: 'high',
                type: 'error-based'
            };
        }
    }

    // Check for suspicious behaviors

    // 1. Check if we got an unexpected success (authentication bypass)
    if (form.isLoginForm) {
        const successIndicators = [
            /welcome/i,
            /dashboard/i,
            /logged.?in/i,
            /my.?account/i,
            /logout/i,
            /sign.?out/i
        ];

        for (const indicator of successIndicators) {
            if (indicator.test(responseBody)) {
                return {
                    vulnerable: true,
                    evidence: 'Possible authentication bypass - login success indicators found',
                    confidence: 'medium',
                    type: 'auth-bypass'
                };
            }
        }
    }

    // 2. Check for unusually long response time (time-based blind SQLi)
    // Note: This needs a baseline, here we use a simple threshold
    if (responseTime > 5000 && payload.includes('SLEEP') || payload.includes('WAITFOR')) {
        return {
            vulnerable: true,
            evidence: `Possible time-based SQLi - response took ${responseTime}ms`,
            confidence: 'low',
            type: 'time-based'
        };
    }

    // 3. Check for different response length (boolean-based blind SQLi)
    // This would need comparison with baseline - simplified here

    return { vulnerable: false, evidence: null, confidence: 'none' };
}

function generateSummary(vulnerabilities) {
    if (vulnerabilities.length === 0) {
        return 'No SQL injection vulnerabilities detected.';
    }

    const critical = vulnerabilities.filter(v => v.confidence === 'high').length;
    const medium = vulnerabilities.filter(v => v.confidence === 'medium').length;
    const low = vulnerabilities.filter(v => v.confidence === 'low').length;

    return `Found ${vulnerabilities.length} potential SQL injection vulnerabilities: ${critical} high confidence, ${medium} medium confidence, ${low} low confidence.`;
}

// Quick test for a single URL/form
async function quickSQLiTest(url, fieldName, payload) {
    try {
        const response = await axios.get(url, {
            params: { [fieldName]: payload },
            timeout: 10000,
            validateStatus: () => true
        });

        const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

        for (const pattern of sqlErrorPatterns) {
            if (pattern.test(responseBody)) {
                return { vulnerable: true, pattern: pattern.toString() };
            }
        }

        return { vulnerable: false };
    } catch (error) {
        return { vulnerable: false, error: error.message };
    }
}

module.exports = { testSQLi, quickSQLiTest };
