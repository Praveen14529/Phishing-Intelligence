# ▶ HOW TO RUN — PhishGuard v2

## Quickest Way (Zero Setup)
Open `frontend/index.html` directly in Chrome/Edge.
Works in full demo mode — no installation needed.

---

## Full Stack in VS Code

### Step 1 — Open project in VS Code
```
File → Open Folder → select phishing-intelligence-v2
```

### Step 2 — Open Terminal (Ctrl + `)

### Step 3 — Terminal 1: Backend
Use Python 3.11 for the pinned backend dependencies.
```cmd
cd backend
py -3.11 -m venv venv
venv\Scripts\activate 
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 4 — Terminal 2: Frontend (Ctrl+Shift+`)
```cmd
cd frontend
npm start
```

### Step 5 — Open Browser
- Dashboard  → http://localhost:4200
- API Docs   → http://localhost:8000/docs
- Health     → http://localhost:8000/health

### Step 6 — Terminal 3: Tests (Ctrl+Shift+`)
```cmd
cd backend
venv\Scripts\activate
python -m pytest tests/ -v
```
---

## Add API Keys (optional — works without them)
Edit `backend/.env`:
```
VIRUSTOTAL_API_KEY=        → https://virustotal.com (free)
GOOGLE_SAFE_BROWSING_API_KEY= → https://console.cloud.google.com (free)
URLSCAN_API_KEY=           → https://urlscan.io (free)
ABUSEIPDB_API_KEY=         → https://abuseipdb.com (free)
```
URLhaus and OpenPhish work automatically — no keys needed.

`backend/.env` is local-only and is excluded from Git. The checked-in
`backend/.env.example` contains empty placeholders. Never paste real keys into
`.env.example`, source code, or commits. If a real key has already been shared
or committed, revoke it with its provider and create a replacement; deleting it
from the latest version alone does not remove it from Git history.

---

## Docker (optional)
```cmd
copy backend\.env.example backend\.env
docker-compose up --build
```
→ http://localhost:4200

---

## Every Time You Reopen VS Code
Terminal 1: `cd backend` then `venv\Scripts\activate` then `python -m uvicorn main:app --reload --port 8000`
Terminal 2: `cd frontend` then `npm start`
