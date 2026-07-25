# QuadSeer v3.0 — Phase 1 EASM Complete

## ✅ What Was Built

### New Files Added (12 files)

| # | File | Purpose |
|---|------|---------|
| 1 | `app/models/asset.py` | Asset model with 9 asset types, risk scoring, geo-location |
| 2 | `app/schemas/asset.py` | Pydantic schemas for Asset CRUD + ReconRequest |
| 3 | `app/api/v1/assets.py` | REST API: list, get, create assets + start recon + stats |
| 4 | `app/services/recon_service.py` | Main EASM orchestrator — 6-phase discovery pipeline |
| 5 | `app/services/dns_enum.py` | DNS enumeration: subdomains, records, zone transfer checks |
| 6 | `app/services/port_scanner.py` | Async TCP port scanner with service banner detection |
| 7 | `app/services/ssl_monitor.py` | SSL/TLS certificate analysis + vulnerability detection |
| 8 | `app/services/tech_fingerprint.py` | Web technology fingerprinting (50+ signatures) |
| 9 | `app/services/shodan_client.py` | Shodan InternetDB + API integration |
| 10 | `app/services/censys_client.py` | Censys Search API v2 integration |
| 11 | `app/tasks/recon_tasks.py` | Celery tasks for recon + scheduled scanning |
| 12 | `templates/assets.html` | Full asset inventory UI with detail modals |

### Modified Files (5 files)

| File | Changes |
|------|---------|
| `app/models/__init__.py` | Added Asset import |
| `app/tasks/celery_app.py` | Added recon_tasks include + scheduled_recon_scan beat schedule |
| `app/main.py` | Added assets router + /assets page route |
| `templates/partials/sidebar.html` | Added Asset Inventory navigation |
| `static/css/quadseer.css` | Added asset-specific styles |
| `requirements.txt` | Added dnspython, pyopenssl |

## 📊 Current Project Stats

```
Total files:     69
Total size:      171 KB
Models:          8 (User, Target, Scan, ScanResult, Report, ThreatActor, Plan, Subscription, Asset)
API routes:      11 modules
Services:        10 (recon, dns, port, ssl, tech, shodan, censys, scan, report, threat)
Templates:        9
Celery tasks:    3 modules
```

## 🧪 Testing Phase 1 EASM

### Step 1: Start the stack
```bash
cd quadseer
docker compose up --build -d
```

### Step 2: Verify seed data
```bash
docker exec -it quadseer-db psql -U quadseer -d quadseer -c "\dt"
# Should show: assets, plans, scan_results, scans, subscriptions, targets, threat_actors, users
```

### Step 3: Login and get token
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
echo $TOKEN
```

### Step 4: Create a target
```bash
curl -s -X POST http://localhost:8000/api/v1/targets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Target","value":"example.com","target_type":"domain"}' \
  | python -m json.tool
# Save the target_id from response
```

### Step 5: Run reconnaissance
```bash
curl -s -X POST http://localhost:8000/api/v1/assets/recon \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_id":1,"scan_depth":"standard"}' \
  | python -m json.tool
```

### Step 6: Check assets (poll until populated)
```bash
# Wait 30-60 seconds for recon to complete
curl -s http://localhost:8000/api/v1/assets?target_id=1 \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Check stats
curl -s http://localhost:8000/api/v1/assets/stats/1 \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool
```

### Step 7: View in UI
Open http://localhost:8000/assets in browser. Select target → Click "Run Recon" → View discovered assets.

## 🔍 EASM Discovery Pipeline

```
Target (domain/IP)
    │
    ├── Phase 1: DNS Enumeration
    │   ├── Subdomain brute force (50+ wordlist)
    │   ├── A/AAAA/MX/NS/TXT/SOA records
    │   └── Zone transfer vulnerability check
    │
    ├── Phase 2: Port Scanning
    │   ├── Async TCP scan (top 100 ports)
    │   ├── Service banner grabbing
    │   └── Technology inference from banners
    │
    ├── Phase 3: SSL Certificate Analysis
    │   ├── Certificate extraction (subject, issuer, SANs)
    │   ├── Expiry detection
    │   ├── TLS version check (flag TLS 1.0/1.1)
    │   └── Cipher strength assessment
    │
    ├── Phase 4: Technology Fingerprinting
    │   ├── HTTP header analysis
    │   ├── Body content matching (50+ signatures)
    │   ├── Cookie analysis
    │   └── Security header scoring
    │
    ├── Phase 5: External Intelligence
    │   ├── Shodan InternetDB (free, no key)
    │   ├── Shodan API (if key configured)
    │   └── Censys API (if credentials configured)
    │
    └── Phase 6: Risk Scoring
        ├── SSL issues (expired, self-signed, weak TLS)
        ├── Exposed risky ports (RDP, SSH, DBs)
        ├── Outdated technology detection
        └── Composite 0-100 risk score
```

## 🔧 External API Configuration

Add to `.env` or `docker-compose.override.yml`:

```bash
SHODAN_API_KEY=your_shodan_key_here
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
```

Without keys, Shodan InternetDB still works (free, no auth required).

## 📋 Next Steps (Phase 2: Dark Web Monitoring)

1. `app/services/darkweb_monitor.py` — TOR proxy, paste sites, hacker forums
2. `app/services/breach_checker.py` — Have I Been Pwned, DeHashed APIs
3. `app/services/ransomware_tracker.py` — LockBit, ALPHV leak sites
4. `app/models/darkweb_finding.py` — Leaked credentials, exposed data
5. `templates/darkweb.html` — Dark web findings dashboard
