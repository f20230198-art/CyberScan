# 🛡️ CyberScan - Website Security Scanner

A powerful, real-time website security scanner that tests for vulnerabilities including SQL Injection, XSS, SSL issues, and missing security headers.

![CyberScan](https://img.shields.io/badge/Security-Scanner-red?style=for-the-badge)
![Node.js](https://img.shields.io/badge/Node.js-18+-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 **SSL/TLS Analysis** | Validates certificates, expiration, and HTTPS |
| 🛡️ **Security Headers** | Checks CSP, HSTS, X-Frame-Options, and 5 more |
| 💉 **SQL Injection Testing** | Tests forms with 20+ SQLi payloads |
| ⚡ **XSS Detection** | Tests inputs with 15+ XSS payloads |
| 🌐 **DNS Analysis** | Domain age, suspicious TLDs, typosquatting detection |
| 📊 **Security Score** | Generates 0-100 score with detailed breakdown |

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd server
npm install
```

### 2. Start the Server

```bash
npm start
```

The server will start at `http://localhost:3001`

### 3. Open the Scanner

Open `index.html` in your browser or visit `http://localhost:3001`

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Full security scan |
| `/api/scan/quick` | POST | Quick scan (SSL + headers) |
| `/api/scan/sqli` | POST | SQL Injection test only |
| `/api/scan/xss` | POST | XSS test only |
| `/api/health` | GET | Health check |

### Example Request

```bash
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Example Response

```json
{
  "success": true,
  "score": 85,
  "status": "Secure",
  "issues": [],
  "details": {
    "ssl": { "valid": true },
    "headers": { "present": ["HSTS", "X-Frame-Options"] },
    "sqli": { "vulnerabilities": [] },
    "xss": { "vulnerabilities": [] }
  }
}
```

## 📁 Project Structure

```
cyberscan/
├── index.html              # Frontend UI
├── server/
│   ├── index.js            # Express server
│   ├── package.json        # Dependencies
│   ├── routes/
│   │   └── scan.js         # API endpoints
│   ├── scanners/
│   │   ├── sslChecker.js   # SSL/TLS analysis
│   │   ├── headerChecker.js # Security headers
│   │   ├── formCrawler.js  # Form detection
│   │   ├── sqliTester.js   # SQL injection tests
│   │   ├── xssTester.js    # XSS vulnerability tests
│   │   └── dnsLookup.js    # DNS analysis
│   └── utils/
│       ├── payloads.js     # Attack payloads
│       └── scoreCalculator.js # Scoring algorithm
└── README.md
```

## ⚠️ Legal Disclaimer

**This tool is for educational purposes only.**

Only scan websites you own or have explicit permission to test. Unauthorized security testing is illegal and may result in criminal charges.

## 📊 Score Calculation

| Issue Type | Points Deducted |
|------------|-----------------|
| Invalid SSL | -15 |
| Missing CSP/HSTS | -8 each |
| SQL Injection found | -15 each |
| XSS found | -12 each |
| New domain (<30 days) | -10 |

## 🛠️ Tech Stack

- **Frontend**: HTML, CSS, JavaScript, TailwindCSS, GSAP
- **Backend**: Node.js, Express
- **Libraries**: Axios, Cheerio

## 📄 License

MIT License - feel free to use and modify!

---

Made with ❤️ for security testing
