# PhishGuard v2 — Phishing Intelligence Dashboard
<img width="1917" height="1078" alt="Screenshot 2026-10-25 224412" src="https://github.com/user-attachments/assets/070a24b8-4379-4465-87f1-178a32075594" />
<img width="1917" height="1078" alt="Screenshot 2026-10-25 224430" src="https://github.com/user-attachments/assets/185f1d25-0f0f-4d37-9ee8-d04a29e56b5e" />
<img width="1917" height="1078" alt="Screenshot 2026-10-25 224437" src="https://github.com/user-attachments/assets/0d772225-564f-4400-989a-3dca1844011a" />




Full-stack cybersecurity platform for detecting fake/phishing domains.

## API Key Safety
Threat-intelligence API keys are optional and should be stored only in
`backend/.env`, which is excluded from Git and Docker build context. Copy
`backend/.env.example` to `backend/.env` and add keys locally. Never commit real
keys. If a key has already been exposed, revoke it with its provider and create
a replacement; removing it from the latest files does not erase Git history.

## Features
- Domain typo and lookalike variant generation
- DNS, HTTPS, WHOIS, and page metadata checks
- Optional integrations with six threat intelligence sources
- Persistent MongoDB storage with in-memory fallback
- Standalone dashboard that can also run against the local API

## Folder Structure
```
phishing-intelligence-v2/
├── backend/
│   ├── main.py                  # FastAPI entry point
│   ├── config.py                # Settings from .env
│   ├── requirements.txt
│   ├── .env.example             # Copy to .env, add keys
│   ├── Dockerfile
│   ├── routes/
│   │   ├── detect.py            # POST /api/v1/detect
│   │   ├── history.py           # GET /api/v1/history
│   │   └── stats.py             # GET /api/v1/stats
│   ├── services/
│   │   ├── detector.py          # Main pipeline orchestrator
│   │   ├── domain_generator.py  # 12 typosquatting techniques
│   │   ├── dns_checker.py       # Async DNS resolution
│   │   ├── threat_intel.py      # All 6 threat intel services
│   │   ├── risk_scorer.py       # 0-100 risk scoring engine
│   │   ├── scraper.py           # WHOIS + page metadata
│   │   └── database.py          # MongoDB + memory fallback
│   ├── models/
│   │   └── schemas.py           # Pydantic models
│   └── tests/
│       ├── test_detection.py
│       ├── test_domain_validation.py
│       └── test_database.py
│
├── frontend/
│   ├── index.html               # Standalone dashboard
│   ├── server.js                # Static server and local API proxy
│   ├── package.json
│   ├── Dockerfile
│   └── nginx.conf
│
├── docker-compose.yml
├── HOW_TO_RUN.md               ← Start here
└── README.md
```

## Threat Intel Services

| Service | API Key | What It Detects |
|---------|---------|-----------------|
| VirusTotal | Required (free) | Malware/phishing by 70+ engines |
| Google Safe Browsing | Required (free) | Known threat URLs |
| URLhaus | ❌ Not needed | Malware URLs database |
| OpenPhish | ❌ Not needed | Live phishing feed |
| URLScan.io | Required (free) | URL scanning & verdicts |
| AbuseIPDB | Required (free) | Malicious IP reputation |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/detect | Scan a domain |
| GET | /api/v1/history | Recent scans |
| GET | /api/v1/stats | Dashboard stats |
| GET | /api/v1/detection/{id} | Single scan detail |
| GET | /health | Server health check |

## Risk Score Weights

| Signal | Weight |
|--------|--------|
| VirusTotal detected | +35 |
| Google Safe Browsing flagged | +25 |
| URLhaus flagged | +20 |
| OpenPhish flagged | +15 |
| URLScan flagged | +10 |
| AbuseIPDB flagged | +10 |
| Newly registered (<30d) | +10 |
| High similarity (>85%) | +8 |
| Phishing keyword in name | +7 |
| No HTTPS | +5 |

**Levels:** SAFE (0) → LOW (1-15) → MEDIUM (16-40) → HIGH (41-70) → CRITICAL (71-100)

## Free API Key Links
- VirusTotal: https://virustotal.com → Sign Up → Account → API Key
- Google Safe Browsing: https://console.cloud.google.com → Enable API → Credentials
- URLScan.io: https://urlscan.io → Sign Up → Profile → API Key
- AbuseIPDB: https://abuseipdb.com → Sign Up → Account → API Keys

## Run and Test
See [HOW_TO_RUN.md](HOW_TO_RUN.md) for Windows, Docker, and local setup commands.
The frontend uses Node.js built-ins and does not require `npm install`.
