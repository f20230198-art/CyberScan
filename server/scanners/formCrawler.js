/**
 * Form Crawler
 * Crawls a webpage to find forms and input fields for testing
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

async function crawlForms(targetUrl) {
    try {
        const response = await axios.get(targetUrl, {
            timeout: 15000,
            maxRedirects: 5,
            validateStatus: () => true,
            headers: {
                'User-Agent': 'CyberScan Security Scanner/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
        });

        const $ = cheerio.load(response.data);
        const forms = [];
        const baseUrl = new URL(targetUrl);

        $('form').each((index, element) => {
            const form = $(element);
            const formData = {
                index,
                action: resolveUrl(form.attr('action') || '', baseUrl),
                method: (form.attr('method') || 'GET').toUpperCase(),
                id: form.attr('id') || null,
                name: form.attr('name') || null,
                inputs: [],
                isLoginForm: false,
                isSearchForm: false
            };

            // Find all input fields
            form.find('input, textarea, select').each((i, input) => {
                const $input = $(input);
                const inputData = {
                    tag: input.tagName.toLowerCase(),
                    type: $input.attr('type') || 'text',
                    name: $input.attr('name') || null,
                    id: $input.attr('id') || null,
                    placeholder: $input.attr('placeholder') || null,
                    required: $input.attr('required') !== undefined,
                    value: $input.attr('value') || ''
                };
                formData.inputs.push(inputData);

                // Detect login form
                const nameLower = (inputData.name || '').toLowerCase();
                const idLower = (inputData.id || '').toLowerCase();
                const placeholderLower = (inputData.placeholder || '').toLowerCase();

                if (inputData.type === 'password' ||
                    nameLower.includes('password') ||
                    idLower.includes('password')) {
                    formData.isLoginForm = true;
                }

                if (nameLower.includes('search') ||
                    idLower.includes('search') ||
                    placeholderLower.includes('search')) {
                    formData.isSearchForm = true;
                }
            });

            // Also check for buttons
            form.find('button, input[type="submit"]').each((i, btn) => {
                const $btn = $(btn);
                formData.submitButton = {
                    text: $btn.text().trim() || $btn.attr('value') || 'Submit',
                    type: $btn.attr('type') || 'submit'
                };
            });

            forms.push(formData);
        });

        // Also find forms that might be created dynamically (common patterns)
        const potentialLoginSelectors = [
            'input[name="username"]',
            'input[name="email"]',
            'input[name="login"]',
            'input[name="user"]',
            'input[id*="login"]',
            'input[id*="user"]',
            'input[id*="email"]'
        ];

        const loginInputsOutsideForms = [];
        potentialLoginSelectors.forEach(selector => {
            $(selector).each((i, el) => {
                const $el = $(el);
                if (!$el.closest('form').length) {
                    loginInputsOutsideForms.push({
                        selector,
                        name: $el.attr('name'),
                        id: $el.attr('id')
                    });
                }
            });
        });

        // Find links that might be login pages
        const loginLinks = [];
        $('a').each((i, el) => {
            const href = $(el).attr('href') || '';
            const text = $(el).text().toLowerCase();
            if (href.includes('login') || href.includes('signin') || href.includes('auth') ||
                text.includes('login') || text.includes('sign in') || text.includes('log in')) {
                loginLinks.push({
                    href: resolveUrl(href, baseUrl),
                    text: $(el).text().trim()
                });
            }
        });

        return {
            success: true,
            url: targetUrl,
            forms,
            loginForms: forms.filter(f => f.isLoginForm),
            searchForms: forms.filter(f => f.isSearchForm),
            loginInputsOutsideForms,
            loginLinks: [...new Set(loginLinks.map(l => l.href))].slice(0, 5),
            totalForms: forms.length,
            totalInputs: forms.reduce((sum, f) => sum + f.inputs.length, 0)
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            url: targetUrl,
            forms: [],
            loginForms: [],
            searchForms: [],
            loginInputsOutsideForms: [],
            loginLinks: [],
            totalForms: 0,
            totalInputs: 0
        };
    }
}

function resolveUrl(href, baseUrl) {
    if (!href || href === '#') return baseUrl.href;
    try {
        return new URL(href, baseUrl).href;
    } catch {
        return href;
    }
}

// Crawl additional pages for more forms
async function deepCrawl(targetUrl, maxPages = 5) {
    const visited = new Set();
    const toVisit = [targetUrl];
    const allForms = [];

    while (toVisit.length > 0 && visited.size < maxPages) {
        const url = toVisit.shift();
        if (visited.has(url)) continue;
        visited.add(url);

        const result = await crawlForms(url);
        if (result.success) {
            allForms.push(...result.forms);

            // Add login links to crawl queue
            result.loginLinks.forEach(link => {
                if (!visited.has(link) && !toVisit.includes(link)) {
                    toVisit.push(link);
                }
            });
        }
    }

    return {
        pagesScanned: visited.size,
        totalForms: allForms.length,
        forms: allForms,
        loginForms: allForms.filter(f => f.isLoginForm)
    };
}

module.exports = { crawlForms, deepCrawl };
