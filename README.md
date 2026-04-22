<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=750&amp;lines=BASTION;OWASP+Web+Application+Security+Auditor;Headers+%7C+Cookies+%7C+Content+%7C+OWASP+Mapping;Security+Grading+A%2B+to+F" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![OWASP](https://img.shields.io/badge/OWASP-Top_10_2021-FF0000?style=for-the-badge)](https://owasp.org/Top10/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Passive OWASP Top 10 2021 web application auditor: HTTP headers, cookie security, content analysis, and security grading A+ to F.**

<br/>

[![Modules](https://img.shields.io/badge/Audit_Modules-4_Analyzers-64ffda?style=flat-square)](.)
[![Checks](https://img.shields.io/badge/Checks-30+-64ffda?style=flat-square)](.)
[![OWASP](https://img.shields.io/badge/OWASP-A01--A10_Mapped-64ffda?style=flat-square)](.)
[![Passive](https://img.shields.io/badge/Mode-Passive_Only-22c55e?style=flat-square)](.)

</div>

> ⚠️ **AUTHORIZED USE ONLY** — Audit only web applications you own or have explicit written authorization to test.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Purpose

Web application security reviews require systematic coverage of the OWASP Top 10. BASTION automates the passive analysis phase — no payload injection, no active exploitation:

| Module | Checks | OWASP Categories |
|--------|--------|-----------------|
| `header_analyzer` | HSTS, CSP, CORS, X-Frame-Options, Referrer-Policy, Permissions-Policy + 3 more | A02, A03, A04, A05 |
| `cookie_analyzer` | Secure, HttpOnly, SameSite per-cookie + persistent session detection | A01, A02, A07 |
| `content_analyzer` | HTML comments, HTTP scripts, eval()/innerHTML, mixed content, autocomplete | A02, A03, A05, A07 |
| `owasp_checker` | Maps all findings → OWASP Top 10 2021, composite score, letter grade | All 10 categories |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Target URL
     │  POST /api/audit
     ▼
┌─────────────────────────────────────────────────────┐
│           HTTP Client (passive — no payloads)        │
│   Fetch headers + cookies + HTML (max 200KB)         │
└──────────────────────┬──────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
┌────────────┐  ┌────────────┐  ┌────────────────┐
│  Header    │  │  Cookie    │  │  Content       │
│  Analyzer  │  │  Analyzer  │  │  Analyzer      │
│  Score 100 │  │  Per-cookie│  │  HTML patterns │
│  -pts each │  │  4 checks  │  │  JS analysis   │
└─────┬──────┘  └─────┬──────┘  └──────┬─────────┘
      └───────────────┴────────────────┘
                      │
       ┌──────────────▼──────────────┐
       │   OWASP Checker             │
       │   Top 10 2021 mapping       │
       │   Composite score (0–100)   │
       │   Letter grade A+ to F      │
       └──────────────┬──────────────┘
                      │
       ┌──────────────▼──────────────┐
       │  Dashboard + JSON Report    │
       │  WebSocket audit complete   │
       └─────────────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Audit Modules

<details>
<summary><b>🔒 header_analyzer — HTTP Security Headers</b></summary>

| Check | Severity | Score Impact | OWASP |
|-------|----------|-------------|-------|
| Missing Strict-Transport-Security | HIGH | -15 pts | A02 |
| Missing Content-Security-Policy | HIGH | -15 pts | A03 |
| Missing X-Content-Type-Options | MEDIUM | -5 pts | A05 |
| Missing X-Frame-Options | MEDIUM | -5 pts | A04 |
| Missing Referrer-Policy | LOW | -3 pts | A05 |
| Missing Permissions-Policy | LOW | -2 pts | A05 |
| CSP with `unsafe-inline` | MEDIUM | -5 pts | A03 |
| HSTS max-age < 1 year | LOW | -3 pts | A02 |
| Wildcard CORS (`*`) | MEDIUM | -10 pts | A01 |

Grades: ≥95 = A+ · ≥85 = A · ≥75 = B · ≥60 = C · ≥50 = D · else F

</details>

<details>
<summary><b>🍪 cookie_analyzer — Per-Cookie Attribute Checks</b></summary>

| Check | Severity | OWASP |
|-------|----------|-------|
| Missing Secure flag | HIGH | A02:2021 |
| Missing HttpOnly flag | HIGH | A03:2021 |
| Missing SameSite attribute | MEDIUM | A01:2021 |
| SameSite=None without Secure | HIGH | A02:2021 |
| Persistent session cookie | MEDIUM | A07:2021 |

</details>

<details>
<summary><b>📄 content_analyzer — HTML & JavaScript Patterns</b></summary>

| Pattern | Severity | OWASP |
|---------|----------|-------|
| Sensitive HTML comment (password/key/secret) | MEDIUM | A05 |
| Script loaded over HTTP | HIGH | A02 |
| `eval()` in inline script | MEDIUM | A03 |
| `innerHTML +=` concatenation | MEDIUM | A03 |
| `document.write()` usage | MEDIUM | A03 |
| HTTP links on HTTPS page (mixed content) | LOW | A02 |
| Password input without `autocomplete=off` | LOW | A07 |

</details>

<details>
<summary><b>🛡️ OWASP Top 10 2021 Mapping</b></summary>

| OWASP ID | Category | Checks Covered |
|----------|----------|----------------|
| A01:2021 | Broken Access Control | Wildcard CORS, missing SameSite |
| A02:2021 | Cryptographic Failures | Missing HSTS, HTTP scripts, mixed content, missing Secure cookie |
| A03:2021 | Injection | Missing CSP, unsafe-inline, eval()/innerHTML |
| A04:2021 | Insecure Design | Missing X-Frame-Options (clickjacking) |
| A05:2021 | Security Misconfiguration | Missing headers, exposed Server/X-Powered-By, sensitive comments |
| A07:2021 | Auth Failures | Missing HttpOnly, persistent session cookie, missing autocomplete |

</details>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/bastion.git
cd bastion

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5008
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/bastion.git
cd bastion
docker build -t bastion .
docker run -p 5008:5008 bastion
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Start an audit
POST /api/audit
{"url": "https://example.com"}
# → {"audit_id": "<id>", "status": "running"}

# Get audit results
GET /api/audit/<audit_id>

# Download JSON report
GET /api/report/<audit_id>/json

# Health check
GET /health
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
bastion/
├── app.py                       # Flask application & REST API
├── wsgi.py                      # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── header_analyzer.py       # 9 HTTP security header checks
│   ├── cookie_analyzer.py       # Per-cookie attribute validation
│   ├── content_analyzer.py      # HTML content security analysis
│   └── owasp_checker.py         # OWASP Top 10 2021 mapping + scoring
│
├── proxy/
│   └── http_client.py           # Passive HTTP client (no payloads)
│
├── templates/
│   ├── index.html               # Auditor dashboard
│   ├── audit_detail.html        # OWASP breakdown + findings table
│   └── reports.html             # Report archive
│
├── static/                      # CSS + JavaScript
└── tests/                       # 22 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"OWASP Top 10 2021 is the universal language of web security. Built to map every finding directly to a category so developers understand not just what's wrong but why it matters."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/bastion?style=social)](https://github.com/RohitKumarReddySakam/bastion)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
