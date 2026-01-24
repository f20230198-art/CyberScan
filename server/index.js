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

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
    origin: '*', // Allow all origins for development
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from parent directory (frontend)
app.use(express.static(path.join(__dirname, '..')));

// API Routes
app.use('/api', scanRoutes);

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

// Start server
app.listen(PORT, () => {
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
║           Security Scanner Backend v1.0.0                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

🚀 Server running at: http://localhost:${PORT}
📡 API endpoints:
   POST /api/scan       - Full security scan
   POST /api/scan/quick - Quick scan (SSL + headers only)
   POST /api/scan/sqli  - SQL Injection test only
   POST /api/scan/xss   - XSS test only
   GET  /api/health     - Health check

⚠️  WARNING: Only scan websites you own or have permission to test!

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
