# QuadSeer v3.0 — Phase 2 Complete

**Merged codebase**: Original v3.0 (21 bugs fixed, working auth/templates) + Validated Phase 2 Services (Breach, Ransomware, Dark Web)

## Quick Start

```bash
# 1. Extract the zip and cd into the folder
cd quadseer

# 2. Start everything
docker-compose up -d

# 3. Wait 30 seconds for first build, then seed the database
docker-compose run --rm seed

# 4. Check health
curl http://localhost:8000/api/health

# 5. Open browser → http://localhost:8000
# Login: admin@quadseer.local / admin123
```

## Windows PowerShell Commands (copy-paste ready)

```powershell
# Step 1: Login
$resp = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -Headers @{"Content-Type"="application/json"} -Body '{"email":"admin@quadseer.local","password":"admin123"}'
$token = $resp.access_token
Write-Host "Token: $token"

# Step 2: Configure HIBP API Key (replace YOUR_HIBP_KEY)
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/configs/hibp_api_key" -Method PUT -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"config_value":"YOUR_HIBP_KEY","config_type":"secret"}'

# Step 3: Configure DeHashed (replace credentials)
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/configs/dehashed_email" -Method PUT -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"config_value":"your@email.com","config_type":"secret"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/configs/dehashed_api_key" -Method PUT -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"config_value":"YOUR_DEHASHED_KEY","config_type":"secret"}'

# Step 4: Create a target
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/targets/" -Method POST -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"name":"Example Corp","domain":"example.com"}'

# Step 5: Run Phase 2 scans
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/" -Method POST -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"target_id":1,"scan_type":"breach"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/" -Method POST -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"target_id":1,"scan_type":"ransomware"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/" -Method POST -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body '{"target_id":1,"scan_type":"darkweb"}'

# Step 6: Check results
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/1/results" -Headers @{"Authorization"="Bearer $token"}
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/1/findings/summary" -Headers @{"Authorization"="Bearer $token"}
```

## Architecture

```
Frontend (Alpine.js + Tailwind + Jinja2)
  ├── /login, /register, /dashboard, /targets, /scans, /admin

FastAPI Backend
  ├── /api/v1/auth      (JWT, bcrypt direct)
  ├── /api/v1/targets  (CRUD)
  ├── /api/v1/scans    (Create + Results + Findings Summary)
  ├── /api/v1/admin    (Config/Users/Stats)
  ├── /api/health, /api/version

Celery Workers
  ├── run_scan_task    (dispatches to correct handler)
  ├── check_pending_scans (every 5 min)
  ├── monitor_ssl_expiry (daily)

Phase 2 Services
  ├── breach_checker.py      → HIBP v3 + DeHashed
  ├── ransomware_tracker.py  → ransomware.live API
  └── darkweb_monitor.py     → TOR proxy + paste sites + ransomware leaks

Database
  ├── PostgreSQL (asyncpg)
  ├── Redis (Celery broker)
  └── system_configs table (25+ DB-stored settings)
```

## API Keys Needed

| Service | Where to Get | Free Tier |
|---------|-------------|-----------|
| HIBP API Key | https://haveibeenpwned.com/API/Key | $3.50/mo (required for email/domain search) |
| DeHashed | https://www.dehashed.com/pricing | Starts at ~$10 |
| Ransomware.live | https://www.ransomware.live/api | **Free, no key needed** |

## Phase 2 Scan Types

| Scan Type | What It Does | Data Sources |
|-----------|-------------|--------------|
| `breach` | Checks email/domain for data breaches | HIBP breachedAccount, HIBP breachedDomain, DeHashed search |
| `ransomware` | Checks if target is a ransomware victim | ransomware.live recent victims, group stats |
| `darkweb` | Monitors dark web mentions | Ransomware leak sites, HIBP pastes, DeHashed dark web index |

## What's Validated

- ✅ HIBP API v3 — tested live, returns 1018 breaches, proper auth flow
- ✅ ransomware.live API — tested live, returns 100 recent victims with full metadata
- ✅ DeHashed API — structure validated, ready for credentials
- ✅ Celery task wiring — all Phase 2 scan types dispatch correctly
- ✅ Finding model — unified storage with severity, risk_score, confidence
- ✅ Frontend — Alpine.js templates with loading states, toasts, auto-refresh

## Next Steps to SOCRadar Parity

1. **Subdomain Enumeration** — integrate `amass` or `subfinder`
2. **Vulnerability Scanning** — integrate `nuclei` templates
3. **Alerting System** — Email/Slack/Discord webhooks on critical findings
4. **Certificate Transparency** — crt.sh API monitoring
5. **Executive Dashboard** — Risk scoring charts, trend analysis
