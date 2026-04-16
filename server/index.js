/**
 * CyberScan Security Scanner - Backend Server
 * 
 * A comprehensive security scanning API that tests websites for:
 * - SSL/TLS certificate issues
 * - Missing security headers
 * - SQL Injection vulnerabilities
 * - XSS vulnerabilities
 * - DNS/Domain security issues
 * 
 * WARNING: Only use this tool to scan websites you own or have permission to test!
 */

const express = require('express');
const cors = require('cors');
const path = require('path');

const scanRoutes = require('./routes/scan');
const verifyRoutes = require('./routes/verify');
const { getScanStats } = require('./middleware/security');

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy for correct IP detection (needed for rate limiting behind proxy)
app.set('trust proxy', 1);

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-ToS-Accepted']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from parent directory (frontend)
app.use(express.static(path.join(__dirname, '..')));

// API Routes (with rate limiting and ToS applied in routes)
app.use('/api', scanRoutes);

// Domain ownership verification routes
app.use('/api/verify', verifyRoutes);

// Stats endpoint (admin)
app.get('/api/stats', (req, res) => {
    res.json({
        success: true,
        stats: getScanStats()
    });
});

// Terms of Service endpoint
app.get('/api/terms', (req, res) => {
    res.json({
        success: true,
        terms: {
            title: 'CyberScan Terms of Service',
            version: '1.0',
            lastUpdated: '2024-01-24',
            content: [
                '1. You may only scan websites you own or have explicit permission to test.',
                '2. You will not use this tool for malicious purposes or unauthorized access.',
                '3. You accept full responsibility for your actions when using this service.',
                '4. You will not attempt to circumvent rate limits or abuse the service.',
                '5. Scan results are for informational purposes only - we are not liable for any actions taken based on results.',
                '6. We log scan activity (IP, URL, timestamp) for security and abuse prevention.'
            ],
            acceptanceRequired: true
        }
    });
});

// Root route - serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: err.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Not found'
    });
});

// Start server - bind to 0.0.0.0 for cloud deployment
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗    ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝    ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║         ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║         ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚██████╗    ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝    ║
║                                                               ║
║           Security Scanner Backend v2.0.0                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

🚀 Server running at: http://localhost:${PORT}
📡 API endpoints:
   POST /api/scan                - Full active scan  (ToS + verified domain required)
   POST /api/scan/passive        - Passive scan: SSL + headers + DNS (no payloads, no auth needed)
   POST /api/scan/quick          - Quick passive scan (SSL + headers only)
   POST /api/scan/sqli           - SQLi test only   (ToS + verified domain required)
   POST /api/scan/xss            - XSS test only    (ToS + verified domain required)
   GET  /api/health              - Health check
   GET  /api/terms               - Terms of Service
   GET  /api/stats               - Scan statistics

🔑 Domain ownership verification:
   POST /api/verify/challenge    - Get DNS TXT challenge token for a domain
   POST /api/verify/confirm      - Confirm ownership by resolving the TXT record
   GET  /api/verify/status       - Check if a domain is currently verified

🔒 Security features:
   ✓ Rate limiting: 5 scans per minute per IP
   ✓ Terms of Service acceptance required
   ✓ DNS TXT ownership verification for active (payload) scans
   ✓ Passive scanning available without verification (read-only, non-invasive)
   ✓ Scan logging enabled
   ✓ Private IP / localhost blocking

⚠️  Active payload scanning is restricted to verified domain owners only.

`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\nShutting down...');
    process.exit(0);
});

// Export for Vercel serverless
module.exports = app;
