/**
 * SQL Injection Tester
 *
 * Detection strategies:
 *   1. Error-based  — regex match DB error messages in the response body
 *   2. Boolean-based blind — compare response length/status for true vs. false payloads
 *      against a baseline (neutral) request
 *   3. Time-based blind — send a SLEEP/WAITFOR payload and compare response time
 *      against the baseline mean (with a safety factor)
 *   4. Auth-bypass — for login forms, look for success indicators after neutral creds fail
 */

const axios = require('axios');
const {
    sqliPayloads,
    sqliBooleanPairs,
    sqliTimePayloads,
    sqlErrorPatterns,
} = require('../utils/payloads');

const BASELINE_SAMPLES = 2;
const TIME_DELAY_SECONDS = 5;
const TIME_MARGIN_MS = 1500; // response must exceed baseline + delay - margin to count

async function testSQLi(forms, options = {}) {
    const { maxPayloads = 10, timeout = 15000 } = options;
    const vulnerabilities = [];
    const tested = [];

    const errorPayloads = sqliPayloads.slice(0, maxPayloads);

    for (const form of forms) {
        const testableInputs = form.inputs.filter(input =>
            ['text', 'password', 'email', 'search', 'tel', 'url'].includes(input.type) ||
            input.tag === 'textarea'
        );
        if (testableInputs.length === 0) continue;

        for (const input of testableInputs) {
            if (!input.name) continue;

            // --- Capture baseline (neutral input) ---
            const baseline = await captureBaseline(form, input, timeout);
            if (!baseline) continue; // network unreachable, skip

            let foundVuln = false;

            // --- 1. Error-based ---
            for (const payload of errorPayloads) {
                try {
                    const result = await sendPayload(form, input, payload, timeout);
                    tested.push({ form: form.action, field: input.name, strategy: 'error-based' });

                    const errorMatch = matchSQLError(result.body);
                    if (errorMatch) {
                        vulnerabilities.push(buildVuln(form, input, payload, {
                            evidence: `SQL error detected: ${errorMatch}`,
                            confidence: 'high',
                            type: 'error-based',
                        }));
                        foundVuln = true;
                        break;
                    }
                } catch (e) { /* continue */ }
            }
            if (foundVuln) continue;

            // --- 2. Boolean-based blind ---
            for (const pair of sqliBooleanPairs) {
                try {
                    const truthy = await sendPayload(form, input, pair.true, timeout);
                    const falsy  = await sendPayload(form, input, pair.false, timeout);
                    tested.push({ form: form.action, field: input.name, strategy: 'boolean-blind' });

                    if (isBooleanBlindHit(baseline, truthy, falsy)) {
                        vulnerabilities.push(buildVuln(form, input, `${pair.true}  /  ${pair.false}`, {
                            evidence: `Boolean-blind differential: true=${truthy.body.length}B status=${truthy.status}, false=${falsy.body.length}B status=${falsy.status}, baseline=${baseline.meanLength}B`,
                            confidence: 'medium',
                            type: 'boolean-blind',
                        }));
                        foundVuln = true;
                        break;
                    }
                } catch (e) { /* continue */ }
            }
            if (foundVuln) continue;

            // --- 3. Time-based blind ---
            for (const tpl of sqliTimePayloads) {
                try {
                    const payload = tpl.replace('{DELAY}', String(TIME_DELAY_SECONDS));
                    const result = await sendPayload(form, input, payload, timeout);
                    tested.push({ form: form.action, field: input.name, strategy: 'time-blind' });

                    const threshold = baseline.meanTime + (TIME_DELAY_SECONDS * 1000) - TIME_MARGIN_MS;
                    if (result.time >= threshold) {
                        // Confirm with a second sample to rule out a slow request
                        const confirm = await sendPayload(form, input, payload, timeout);
                        if (confirm.time >= threshold) {
                            vulnerabilities.push(buildVuln(form, input, payload, {
                                evidence: `Time-blind: response took ${result.time}ms, confirmed ${confirm.time}ms (baseline ${baseline.meanTime}ms, threshold ${Math.round(threshold)}ms)`,
                                confidence: 'medium',
                                type: 'time-blind',
                            }));
                            foundVuln = true;
                            break;
                        }
                    }
                } catch (e) { /* continue */ }
            }
            if (foundVuln) continue;

            // --- 4. Auth-bypass heuristic (login forms only, requires real differential) ---
            if (form.isLoginForm) {
                for (const payload of ["' OR '1'='1' --", "admin'--"]) {
                    try {
                        const result = await sendPayload(form, input, payload, timeout);
                        if (isAuthBypass(baseline, result)) {
                            vulnerabilities.push(buildVuln(form, input, payload, {
                                evidence: `Login response diverged from baseline (status ${baseline.status}→${result.status}, length ${baseline.meanLength}B→${result.body.length}B) with success indicators present`,
                                confidence: 'medium',
                                type: 'auth-bypass',
                            }));
                            break;
                        }
                    } catch (e) { /* continue */ }
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

// ----------------- helpers -----------------

async function captureBaseline(form, input, timeout) {
    const samples = [];
    for (let i = 0; i < BASELINE_SAMPLES; i++) {
        try {
            const r = await sendPayload(form, input, 'test', timeout);
            samples.push(r);
        } catch { /* skip */ }
    }
    if (samples.length === 0) return null;

    const meanLength = Math.round(samples.reduce((s, r) => s + r.body.length, 0) / samples.length);
    const meanTime = Math.round(samples.reduce((s, r) => s + r.time, 0) / samples.length);
    return { meanLength, meanTime, status: samples[0].status, body: samples[0].body };
}

async function sendPayload(form, input, payload, timeout) {
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

    const start = Date.now();
    const res = form.method === 'POST'
        ? await axios.post(form.action, new URLSearchParams(formData).toString(), config)
        : await axios.get(form.action, { ...config, params: formData });
    const time = Date.now() - start;

    const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    return { body, status: res.status, time };
}

function matchSQLError(body) {
    for (const pattern of sqlErrorPatterns) {
        const m = body.match(pattern);
        if (m) return m[0].slice(0, 120);
    }
    return null;
}

// Boolean-blind is considered a hit when:
//  - truthy response differs substantially from falsy response, AND
//  - one of them roughly matches baseline (confirming neutral behavior preserved)
function isBooleanBlindHit(baseline, truthy, falsy) {
    if (truthy.status !== falsy.status) {
        // different status codes for logically equivalent inputs → likely injected
        return true;
    }
    const diff = Math.abs(truthy.body.length - falsy.body.length);
    const ratio = diff / Math.max(baseline.meanLength, 1);
    // require >5% response-length divergence AND >200 bytes absolute to reduce noise
    return ratio > 0.05 && diff > 200;
}

function isAuthBypass(baseline, result) {
    // A bypass should CHANGE the response meaningfully from baseline (failed login)
    const statusChanged = baseline.status !== result.status;
    const lengthChanged = Math.abs(baseline.meanLength - result.body.length) > 500;
    if (!statusChanged && !lengthChanged) return false;

    const indicators = [/logout/i, /sign.?out/i, /my.?account/i, /dashboard/i];
    return indicators.some(p => p.test(result.body) && !p.test(baseline.body));
}

function buildVuln(form, input, payload, extra) {
    return {
        form: form.action,
        formMethod: form.method,
        field: input.name,
        fieldType: input.type,
        payload,
        severity: 'critical',
        ...extra,
    };
}

function generateSummary(vulns) {
    if (vulns.length === 0) return 'No SQL injection vulnerabilities detected.';
    const byType = vulns.reduce((m, v) => { m[v.type] = (m[v.type] || 0) + 1; return m; }, {});
    const parts = Object.entries(byType).map(([t, n]) => `${n} ${t}`);
    return `Found ${vulns.length} potential SQL injection vulnerabilities: ${parts.join(', ')}.`;
}

// Quick test for a single URL/form
async function quickSQLiTest(url, fieldName, payload) {
    try {
        const response = await axios.get(url, {
            params: { [fieldName]: payload },
            timeout: 10000,
            validateStatus: () => true,
        });
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const match = matchSQLError(body);
        return match ? { vulnerable: true, evidence: match } : { vulnerable: false };
    } catch (error) {
        return { vulnerable: false, error: error.message };
    }
}

module.exports = { testSQLi, quickSQLiTest };
