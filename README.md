# SENTRIX – Security Analysis & URL Intelligence Platform

```
   _____ ______ _   _ _______ _____  _______   __
  / ____|  ____| \ | |__   __|  __ \|_   _\ \ / /
 | (___ | |__  |  \| |  | |  | |__) | | |  \ V / 
  \___ \|  __| | . ` |  | |  |  _  /  | |   > <  
  ____) | |____| |\  |  | |  | | \ \ _| |_ / . \ 
 |_____/|______|_| \_|  |_|  |_|  \_\_____/_/ \_\
```

**TAGLINE: INVESTIGATE. ANALYZE. UNDERSTAND. PROTECT.**

**SENTRIX** is an enterprise-grade cybersecurity web intelligence and threat analysis platform built with Python Flask, Jinja2, vanilla JavaScript, Lucide icons, and Chart.js. Engineered specifically for authorized cybersecurity researchers, penetration testers, SOC analysts, CERT incident responders, and students.

SENTRIX delivers a unique **Cyber Command-Center** experience with asymmetric bento layouts, an interactive split-screen URL anatomy visualizer, real-time DNS resolution, SSL/TLS cryptographic inspection, HTTP security header auditing, an 8-category defensive OSINT/Google Dork synthesizer, an integrated AI chatbot (Google Gemini API with an in-house expert fallback), and ReportLab executive PDF reporting.

---

## 🛡️ Key Features & Capabilities

### 1. Security Intelligence Center (Dashboard)
- **Hero Command Bar:** Global target search with quick scenarios (Typosquatting, Raw IP/SSRF, Shorteners, Punycode, Clean baseline).
- **Interactive Circular Threat Risk Score Gauge (The Risk Circle):**
  - **Dynamic Radial SVG Dial:** Animated circular progress meter tracking real-time average risk scores (0–100) across monitored endpoints.
  - **Dynamic Neon Gradient:** Multi-stop SVG gradient (#00D5FF Electric Cyan -> #2878FF Cyber Blue -> #FFB547 Amber -> #FF5263 Danger Red) with real-time numeric counter.
  - **Interactive Tier Simulator:** 1-click simulation buttons (*Low 15*, *Med 38*, *High 68*, *Crit 92*, *Live*) allowing instant animated gauge verification.
- **Granular 4-Tier Threat Architecture Breakdown:**
  - **LOW RISK (0–24 pts):** Valid TLS, standard ports, low Shannon entropy, clean syntax.
  - **MEDIUM RISK (25–49 pts):** Cleartext HTTP, URL shorteners, redirect parameters, missing security headers.
  - **HIGH RISK (50–74 pts):** Nested subdomains (>3 levels), high entropy DGA patterns, non-standard ports, suspicious TLDs.
  - **CRITICAL RISK (75–100 pts):** Brand typosquatting / homoglyphs, raw IP hostnames, embedded @ userinfo, null byte injection.
  - Each tier card includes live distribution statistics, count percentages, and animated status tracks.
- **Asymmetric Bento Layout:** High-density command layout with zero repetitive generic cards.
- **Visualizations:**
  - **Circular Intelligence Radar:** Multi-vector threat surface visualization.
  - **Radial Risk Doughnut:** Live distribution across LOW, MEDIUM, HIGH, and CRITICAL risk tiers.
  - **Investigation Activity Timeline:** Live scanning volume and threat anomaly spikes.
  - **Threat Classification Bar Chart:** Aggregate vulnerability breakdown.
- **Real vs. Demo Distinction:** Clear visual tagging (DEMO DATA badge) for pre-seeded demonstration data to ensure analyst clarity.

### 2. Advanced URL Analyzer (Flagship Workspace)
- **Interactive URL Anatomy Visualizer:** Real-time decomposition into **Protocol**, **Hostname**, **Subdomain**, **Domain**, **TLD**, **Port**, **Path**, **Query Parameters**, and **Fragment**.
- **Python Heuristic Analysis Engine:**
  - Raw IP address hostname detection (IPv4 / IPv6).
  - Brand typosquatting and homoglyph detection (Levenshtein mutation & character substitution against top brands: PayPal, Apple, Google, Microsoft, Amazon, Netflix, Chase, Binance, etc.).
  - URL Shortener domain detection (bit.ly, tinyurl, t.co, is.gd, etc.).
  - Excessive subdomain nesting analysis (> 3 levels).
  - Punycode / Internationalized Domain Name (IDN `xn--`) detection and ASCII decoding.
  - Authority trickery detection (embedded userinfo `@` symbol).
  - Null byte (`%00`) injection pattern matching.
  - Shannon entropy calculation of hostname and path (detects algorithmic DGA domains).
  - High-risk / frequently abused TLD flags.
  - Suspicious query parameter inspection (`token`, `redirect`, `url`, `cmd`, Base64 payloads).
  - Cleartext HTTP vs. TLS inspection & non-standard port binding flags.
- **Risk Quantification:** Granular risk score (0–100) classified into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` with actionable defensive precautions.

### 3. Domain Intelligence
- **DNS Zone Enumeration:** Authoritative queries for `A`, `AAAA`, `MX` (with preference weighting), `NS`, `TXT`, `CNAME`, `SOA`, and reverse `PTR` lookups via `dnspython`.
- **Email Security Safeguards:** Dedicated checks for SPF (`v=spf1`) and DMARC (`_dmarc.<domain>`) records.
- **SSL/TLS Cryptographic Audit:** Connects via TLS to extract certificate validity dates, days until expiration, Issuer Organization, Subject Common Name, Subject Alternative Names (SANs), TLS protocol version, cipher suite, and key bits.
- **HTTP Security Headers Posture:** Automated grading of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Passive Technology Fingerprinting:** Web server identification, CDN / edge proxy detection (Cloudflare, AWS CloudFront), and application framework indicators.
- **WHOIS Registration Metadata:** Registrar information, creation dates, expiration timeline, and status codes.

### 4. OSINT Explorer & Query Generator
- **8 Dedicated Reconnaissance Categories:**
  1. *Publicly Indexed Files* (PDF, DOCX, XLSX, SQL dumps, .env secrets, logs)
  2. *Login & Authentication Portals* (Admin portals, SSO, OAuth, password reset, webmail)
  3. *Publicly Indexed Directories* (Apache/Nginx directory listings, open upload folders, .git repos)
  4. *Subdomain Research* (Wildcard enumeration, staging, dev, beta, VPN gateways)
  5. *Public Documentation* (Employee handbooks, Swagger/OpenAPI documentation, topology whitepapers)
  6. *Technology Identification* (WordPress, Drupal, Joomla, PHP footprints)
  7. *Configuration & Error Leaks* (SQL error traces, Django/Flask debug pages, AWS S3 buckets)
  8. *Public Contact & People Research* (Corporate email patterns, staff directories, helpdesks)
- **Supported Google Operators:** `site:`, `filetype:`, `inurl:`, `intitle:`, `intext:`, and boolean combinations.
- **Export Formats:** Direct export to TXT Research Playbook and CSV Matrix.

### 5. SENTRIX AI Assistant
- **Floating Command-Center Widget:** Glassmorphism UI with pulse radar animation, typing indicator, markdown formatting, copy-response button, and suggested prompt pills.
- **Dual Engine Architecture:**
  - **Google Gemini API:** Direct connection when configured with `GEMINI_API_KEY`.
  - **In-House Security Analyst Brain:** Expert fallback engine capable of deep static URL inspection, explaining DNS records, elaborating on phishing indicators, and clarifying Google Dork syntax offline without crashing.

### 6. Executive Report Generation
- **ReportLab PDF Engine:** Generates high-resolution, print-ready cybersecurity audit reports complete with case UUID, branding, executive summaries, anatomy tables, security findings, and defensive precautions.
- **Structured Formats:** Instant export to **PDF**, **CSV**, **TXT**, and formatted print view.

### 7. Robust Cybersecurity Architecture & SSRF Guard
- **Strict SSRF Protection:** Outbound requests validate IPs against RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and carrier-grade NAT.
- **DNS Rebinding Defense:** Pre-resolves destination hostnames and validates all resolved IP addresses before socket connection.
- **Controlled Request Limits:** 3.5s socket timeouts, maximum redirect limits, and response size guards.
- **Zero Detonation Policy:** Static heuristic analysis only; downloaded payloads are never executed.

---

## ⚙️ Technology Stack

| Component | Technology |
|---|---|
| **Backend Framework** | Python 3.12, Flask 3.1.3 |
| **Database ORM** | Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.0.58 (PostgreSQL-compatible SQLite default) |
| **Frontend Templates** | Jinja2, HTML5, CSS3, Vanilla JavaScript (No React, Vue, or heavy node frameworks) |
| **Visualizations** | Chart.js 4.4.2 (Theme-aware Dark & Light Mode) |
| **Icons** | Lucide Icons |
| **Network & DNS** | `dnspython`, `urllib.parse`, `socket`, `ipaddress`, `ssl`, `cryptography`, `requests` |
| **WHOIS** | `python-whois` |
| **PDF Generation** | `reportlab` |
| **Environment** | `python-dotenv` |

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- Git (optional)

### 2. Setup Virtual Environment (Recommended)
```bash
# Clone or navigate to the SENTRIX workspace
cd SENTRIX

# Create virtual environment
python -m venv venv

# Activate on Windows:
venv\Scripts\activate
# Activate on Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
To enable live external AI queries via Google Gemini, get a free API key at [Google AI Studio](https://aistudio.google.com/) and paste it into `.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(Note: If no API key is set, SENTRIX AI will automatically utilize its internal cybersecurity reasoning engine seamlessly!)*

### 5. Launch the Application
```bash
python app.py
```
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Running the Verification Test Suite
SENTRIX includes an automated test suite verifying all 9 core subsystems:
```bash
python test_suite.py
```

Expected output:
```
======================================================================
RUNNING SENTRIX VERIFICATION & SECURITY ASSURANCE TEST SUITE
======================================================================
[*] 1. URL Analyzer API: PASSED (Risk Score: 85/100, Class: CRITICAL)
[*] 2. SSRF Protection Guardrails: PASSED (RFC 1918, Loopback, Link-Local all blocked)
[*] 3. SENTRIX AI Chatbot Engine: PASSED (Contextual reply generated)
[*] 4. ReportLab PDF Generation: PASSED (3842 bytes generated)
[*] 5. Investigation CSV Export: PASSED
[*] 6. Investigation TXT Export: PASSED
[*] 7. OSINT TXT Playbook Export: PASSED
[*] 8. OSINT CSV Matrix Export: PASSED
[*] 9. Analyst Settings Persistence: PASSED
======================================================================
ALL 9 VERIFICATION CHECKS PASSED WITH ZERO ERRORS!
======================================================================
```

---

## 📁 Project Structure

```
SENTRIX/
├── app.py                     # Flask application factory, routes, and API endpoints
├── config.py                  # Application configuration & branding metadata
├── requirements.txt           # Python package dependencies
├── .env.example               # Environment variables template
├── README.md                  # Comprehensive documentation
├── test_suite.py              # Automated verification test suite
│
├── database/
│   ├── __init__.py
│   ├── db.py                  # SQLAlchemy instance
│   └── models.py              # Schema: Investigation, URLAnalysis, DomainInvestigation, etc.
│
├── modules/
│   ├── __init__.py
│   ├── ssrf_guard.py          # SSRF prevention, IP network validator, DNS rebinding guard
│   ├── risk_engine.py         # 0-100 heuristic scoring, severity classification & explanations
│   ├── url_analysis.py        # Syntactical anatomy, entropy, typosquatting & brand spoof checks
│   ├── dns_analysis.py        # dnspython zone record queries, SPF & DMARC audit
│   ├── domain_intelligence.py # SSL/TLS certificate inspection, HTTP security headers, WHOIS
│   ├── redirect_analysis.py   # Hop-by-hop HTTP redirect chain tracing with SSRF validation
│   ├── osint_generator.py     # 8-category defensive Google Dork synthesis and exporter
│   ├── chatbot.py             # SENTRIX AI orchestrator (Gemini API + in-house security brain)
│   └── report_generator.py    # ReportLab PDF, CSV, and TXT report compilation
│
├── templates/
│   ├── base.html              # Fixed top navbar, mobile drawer, AI widget, search modal
│   ├── dashboard.html         # Security intelligence center overview & Chart.js visualizations
│   ├── url_analyzer.html      # Split-screen URL anatomy and heuristic findings workspace
│   ├── domain_intel.html      # DNS enumeration, SSL certificate, and security header audit
│   ├── osint.html             # Three-panel defensive OSINT workspace
│   ├── query_generator.html   # Interactive dork builder with search operator presets
│   ├── reports.html           # Investigation audit archive with direct export options
│   ├── settings.html          # Analyst preferences, Gemini API key, and data cleanup
│   └── errors/
│       ├── 404.html           # Cyber-themed 404 Not Found error page
│       └── 500.html           # Cyber-themed 500 Internal Error page
│
├── static/
│   ├── css/
│   │   ├── style.css          # Design system, CSS variables (dark/light), cards, buttons
│   │   ├── dashboard.css      # Asymmetric bento grid, radar containers, scanning bars
│   │   └── responsive.css     # Tablet and mobile breakpoints, adaptive split panels
│   ├── js/
│   │   ├── main.js            # Theme switcher, mobile drawer, modal, clipboard, toasts
│   │   ├── analyzer.js        # Dynamic URL anatomy breakdown, findings renderer, risk meter
│   │   ├── charts.js          # Chart.js radar, doughnut, timeline, and bar charts
│   │   └── chatbot.js         # Floating chat drawer, typing indicator, markdown formatting
│   └── images/
│       ├── sentrix-logo.svg   # Full horizontal logo with wordmark & tagline
│       ├── sentrix-icon.svg   # Geometric security shield with circuit traces & 'S' reticle
│       ├── sentrix-wordmark.svg # High-tech wordmark
│       └── favicon.svg        # Browser tab favicon
│
└── instance/
    └── sentrix.db             # SQLite development database
```

---

## ⚖️ Legal & Ethical Usage Notice
SENTRIX is strictly engineered for authorized defensive security research, website administration, vulnerability assessment, educational demonstration, and blue-team incident response. Generating search queries does not authorize attacking, probing, or exploiting third-party computer systems without prior explicit written permission.
