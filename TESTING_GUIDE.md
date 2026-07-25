# QuadSeer v3.0 — Complete Testing Guide & SOCRadar Gap Analysis

> Generated: 2026-07-18 | Target: Production-ready SOCRadar-class threat intelligence platform

---

## PART 1: TESTING PROCEDURES

### 1.1 Pre-Flight Checklist

Before running tests, ensure:

```bash
# 1. Docker & Docker Compose installed
docker --version
docker compose version

# 2. Ports 8000, 5432, 6379, 5555 are free
lsof -i :8000 :5432 :6379 :5555

# 3. At least 4GB RAM available (8GB recommended)
free -h

# 4. Disk space: ~2GB for images + data
df -h
```

### 1.2 Full Stack Launch

```bash
cd /mnt/agents/output/quadseer

# Build and start all services
docker compose up --build -d

# Or for development (logs in foreground)
docker compose up --build

# Verify all containers are healthy
docker compose ps
```

Expected output:
```
NAME              STATUS    PORTS
quadseer-api      Up        0.0.0.0:8000->8000/tcp
quadseer-db       Up (healthy)  5432/tcp
quadseer-redis    Up (healthy)  6379/tcp
quadseer-worker   Up
quadseer-beat     Up
quadseer-flower   Up        0.0.0.0:5555->5555/tcp
```

### 1.3 Layered Testing Protocol

#### LAYER 0: Infrastructure Health

```bash
# Test 0.1: API Health Endpoint
curl -s http://localhost:8000/api/health | python -m json.tool

# Expected: {"status": "healthy", "version": "3.0.0", "services": {"database": "connected", "redis": "connected"}}

# Test 0.2: Database Connectivity
docker exec -it quadseer-db psql -U quadseer -d quadseer -c "\dt"

# Expected: 8 tables (users, targets, scans, scan_results, reports, threat_actors, plans, subscriptions)

# Test 0.3: Redis Connectivity
docker exec -it quadseer-redis redis-cli ping

# Expected: PONG

# Test 0.4: Celery Worker Status
docker logs quadseer-worker --tail 20

# Expected: "Connected to redis://redis:6379/1" and "Ready"

# Test 0.5: Flower Dashboard
curl -s -u admin:admin http://localhost:5555/api/workers | python -m json.tool

# Expected: Worker list with active status
```

#### LAYER 1: Authentication & Users

```bash
# Test 1.1: Register New User
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"testuser","password":"testpass123","full_name":"Test User"}' \
  | python -m json.tool

# Expected: 200 OK with user object (id, email, username, is_active, etc.)

# Test 1.2: Login (OAuth2 Password Flow)
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass123" \
  | python -m json.tool

# Expected: {"access_token": "eyJ...", "token_type": "bearer"}
# Save token: TOKEN=$(curl -s -X POST ... | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Test 1.3: Get Current User
export TOKEN="your_token_here"
curl -s http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Expected: User profile matching registered user

# Test 1.4: Default Admin Login
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" \
  | python -m json.tool

# Expected: Valid token for admin user
```

#### LAYER 2: Core CRUD Operations

```bash
# Test 2.1: Create Target
export TOKEN="your_token"
curl -s -X POST http://localhost:8000/api/v1/targets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Example Corp","value":"example.com","target_type":"domain","description":"Primary domain","tags":["production"]}' \
  | python -m json.tool

# Expected: Target object with id, owner_id matching your user
# Save target_id from response

# Test 2.2: List Targets
curl -s http://localhost:8000/api/v1/targets \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Test 2.3: Create Scan
export TARGET_ID=1  # from previous response
curl -s -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{"name":"Initial Recon","scan_type":"surface","target_id":$TARGET_ID,"config":{"depth":1}}" \
  | python -m json.tool

# Expected: Scan object with status "queued", progress 0.0
# Save scan_id

# Test 2.4: Monitor Scan Progress
curl -s http://localhost:8000/api/v1/scans/1 \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Poll every 5 seconds until status is "completed"
watch -n 5 'curl -s http://localhost:8000/api/v1/scans/1 -H "Authorization: Bearer '$TOKEN'" | python -c "import sys,json;d=json.load(sys.stdin);print(f"Status: {d[chr(39)+chr(39)]status]} | Progress: {d[chr(39)+chr(39)]progress]}% | Findings: {d[chr(39)+chr(39)]findings_count]}")"'

# Test 2.5: Get Scan Results
curl -s http://localhost:8000/api/v1/scans/1/results \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Expected: Array of findings with severity, category, title, cvss_score
```

#### LAYER 3: Threat Intelligence

```bash
# Test 3.1: List Threat Actors (should be pre-seeded)
curl -s http://localhost:8000/api/v1/threats/actors \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool | head -50

# Expected: 5 threat actors (APT29, Lazarus, MageCart, FIN7, Sandworm)

# Test 3.2: Search Threat Actors
curl -s "http://localhost:8000/api/v1/threats/actors?q=Russia&min_threat_level=8.0" \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Expected: Filtered list matching query

# Test 3.3: Get Threat Stats
curl -s http://localhost:8000/api/v1/threats/stats \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Expected: {"total_actors": 5, "high_threat_actors": 4}

# Test 3.4: Create Threat Actor (Admin Only)
export ADMIN_TOKEN="admin_token"
curl -s -X POST http://localhost:8000/api/v1/threats/actors \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Actor","threat_level":5.0,"description":"Test threat actor"}' \
  | python -m json.tool

# Test 3.5: Non-Admin Cannot Create (403)
curl -s -w "\nHTTP Status: %{http_code}\n" -X POST http://localhost:8000/api/v1/threats/actors \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Actor","threat_level":5.0}'

# Expected: HTTP Status: 403
```

#### LAYER 4: Reports & PDF Generation

```bash
# Test 4.1: Create Report
export SCAN_IDS="[1]"
curl -s -X POST http://localhost:8000/api/v1/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{"title":"Security Assessment Report","scan_ids":$SCAN_IDS,"format":"pdf","template":"default"}" \
  | python -m json.tool

# Expected: Report object with status pending (generates in background)

# Test 4.2: List Reports
curl -s http://localhost:8000/api/v1/reports \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Test 4.3: Verify PDF Generated (wait 10s then check)
sleep 10
curl -s http://localhost:8000/api/v1/reports/1 \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Expected: file_path populated, file_size > 0

# Test 4.4: Download PDF
curl -s -o /tmp/test_report.pdf http://localhost:8000/static/reports/report_1_*.pdf
file /tmp/test_report.pdf

# Expected: PDF document, version 1.4
```

#### LAYER 5: Dashboard & Analytics

```bash
# Test 5.1: Dashboard Stats
curl -s http://localhost:8000/api/v1/dashboard/stats \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool

# Expected: scans, targets, reports, findings, threat_actors counts

# Test 5.2: Recent Scans
curl -s "http://localhost:8000/api/v1/dashboard/recent-scans?limit=5" \
  -H "Authorization: Bearer $TOKEN" \
  | python -m json.tool
```

#### LAYER 6: WebSocket Real-Time

```bash
# Test 6.1: WebSocket Connection (using wscat or websocat)
# Install: npm install -g wscat
wscat -c ws://localhost:8000/ws/scan/1

# Send: ping
# Expected: pong

# Start a new scan in another terminal, watch live updates:
# {"scan_id": 1, "progress": 10.0, "status": "running", "message": "Initializing reconnaissance..."}
# ...updates every 0.5-1.5s until completion
```

#### LAYER 7: Frontend UI Testing

```bash
# Test 7.1: Dashboard Page
curl -s http://localhost:8000/ | head -20

# Expected: HTML with Alpine.js directives, sidebar, stats grid

# Test 7.2: Login Page
curl -s http://localhost:8000/login | grep -o "loginForm"

# Expected: "loginForm" found (Alpine.js component)

# Test 7.3: Static Assets
curl -s http://localhost:8000/static/css/quadseer.css | head -5
curl -s http://localhost:8000/static/js/quadseer.js | head -5

# Expected: CSS and JS content
```

#### LAYER 8: Celery Background Tasks

```bash
# Test 8.1: Trigger Scan Task via API
curl -s -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{"name":"Celery Test","scan_type":"surface","target_id":$TARGET_ID}"

# Test 8.2: Check Flower for Task
curl -s -u admin:admin http://localhost:5555/api/tasks | python -m json.tool | head -30

# Expected: Task entries with state SUCCESS/STARTED/PENDING

# Test 8.3: Worker Logs
docker logs quadseer-worker --tail 50 | grep -E "(Received task|Task succeeded|Task failed)"
```

### 1.4 Automated Test Suite

```bash
# Run pytest suite
docker exec -it quadseer-api pytest tests/ -v --tb=short

# Expected: All tests pass (test_health.py, test_auth.py)
```

### 1.5 Security Testing

```bash
# Test: Missing auth returns 401
curl -s -w "\nHTTP: %{http_code}\n" http://localhost:8000/api/v1/scans
# Expected: HTTP: 401

# Test: Invalid token returns 401
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer invalid_token" http://localhost:8000/api/v1/scans
# Expected: HTTP: 401

# Test: Security headers present
curl -sI http://localhost:8000/ | grep -E "(X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security)"
# Expected: All three headers present

# Test: SQL Injection attempt blocked
curl -s "http://localhost:8000/api/v1/threats/actors?q=';DROP+TABLE+users;--" \
  -H "Authorization: Bearer $TOKEN"
# Expected: Returns empty results, no crash, table intact
```

### 1.6 Performance Baseline

```bash
# Load test with hey (install: brew install hey / apt install hey)
hey -n 1000 -c 50 http://localhost:8000/api/health

# Expected: p95 < 100ms, 0 errors

# Scan creation load test
hey -n 100 -c 10 -m POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Load Test","scan_type":"surface","target_id":1}' \
  http://localhost:8000/api/v1/scans

# Expected: All 202 Accepted, tasks queued
```

### 1.7 Troubleshooting Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Connection refused` on :8000 | API container not ready | `docker compose logs api` |
| `database "quadseer" does not exist` | DB not initialized | Wait for healthcheck, restart |
| Celery tasks stuck in PENDING | Worker not connected | `docker compose restart worker` |
| PDF generation fails | Missing ReportLab/WeasyPrint | Check `WEASYPRINT_ENABLED` env |
| WebSocket disconnects immediately | Missing `accept()` | Check `scan_progress.py` |
| Alpine.js not reactive | Script loading order | Verify `defer` attribute on CDN link |
| `_x_dataStack` errors | Old code pattern | Use `$store` instead (already fixed) |
| `broker_connection_retry` warning | Celery config | Already fixed in `celery_app.py` |

---

## PART 2: SOCRADAR GAP ANALYSIS

### 2.1 SOCRadar Feature Matrix vs QuadSeer v3.0

Based on Gartner reviews and platform documentation, SOCRadar Extended Threat Intelligence Platform includes these modules: citeweb_search:23#0

| # | Feature Module | SOCRadar | QuadSeer v3.0 | Gap Status | Priority |
|---|----------------|----------|---------------|------------|----------|
| 1 | **Attack Surface Management (EASM)** | ✅ Full | ⚠️ Basic | **HIGH** | P0 |
| 2 | **Threat Intelligence Feed Aggregation** | ✅ Multi-source | ✅ Seeded data | **MEDIUM** | P1 |
| 3 | **Dark Web Monitoring** | ✅ Continuous | ❌ Missing | **HIGH** | P0 |
| 4 | **Brand Protection / Phishing Detection** | ✅ AI-powered | ❌ Missing | **HIGH** | P0 |
| 5 | **Credential Leak Detection** | ✅ Automated | ❌ Missing | **HIGH** | P0 |
| 6 | **Supply Chain / Vendor Risk** | ✅ Full suite | ❌ Missing | **MEDIUM** | P2 |
| 7 | **Vulnerability Intelligence (VulnDB)** | ✅ Integrated | ⚠️ Mock data | **MEDIUM** | P1 |
| 8 | **MITRE ATT&CK Mapping** | ✅ Native | ✅ Partial | **LOW** | P2 |
| 9 | **IOC Enrichment & Correlation** | ✅ Real-time | ⚠️ Static JSON | **MEDIUM** | P1 |
| 10 | **Alerting & Notification** | ✅ Multi-channel | ⚠️ WebSocket only | **MEDIUM** | P1 |
| 11 | **API-First Architecture** | ✅ Full REST | ✅ Complete | ✅ **DONE** | — |
| 12 | **Report Generation (PDF/HTML)** | ✅ Customizable | ✅ ReportLab + WeasyPrint | ✅ **DONE** | — |
| 13 | **Role-Based Access Control** | ✅ Granular | ⚠️ Basic (admin/user) | **LOW** | P3 |
| 14 | **SSO/SAML Integration** | ✅ Enterprise | ❌ Missing | **LOW** | P3 |
| 15 | **Multi-tenant Architecture** | ✅ Yes | ❌ Single tenant | **MEDIUM** | P2 |

### 2.2 Detailed Gap Breakdown

#### GAP 1: Attack Surface Management (EASM) — HIGH PRIORITY

**What SOCRadar does:**
- Continuous automated discovery of internet-facing assets (domains, IPs, subdomains, cloud resources, APIs)
- Shadow IT detection
- SSL/TLS certificate monitoring
- Port scanning and service fingerprinting
- Technology stack identification
- Exposure scoring and risk rating

**What QuadSeer has:**
- Manual target creation (domain/IP/URL/CIDR/ASN)
- Simulated scan execution with mock findings
- No actual external reconnaissance

**Implementation needed:**
```python
# New service: app/services/recon_service.py
# - DNS enumeration (subdomain brute force, zone transfers, certificate transparency logs)
# - Port scanning (masscan/nmap integration via subprocess or python-nmap)
# - WHOIS lookup and historical DNS
# - Cloud asset discovery (AWS/Azure/GCP public resource enumeration)
# - SSL certificate parsing and expiry monitoring
# - Technology fingerprinting (Wappalyzer-style detection)
# - Shodan/Censys API integration for exposed service discovery
```

**Files to add:**
- `app/services/recon_service.py` — Asset discovery engine
- `app/services/dns_enum.py` — DNS enumeration
- `app/services/port_scanner.py` — Async port scanning
- `app/services/ssl_monitor.py` — Certificate monitoring
- `app/tasks/recon_tasks.py` — Scheduled reconnaissance
- `app/models/asset.py` — Discovered asset model
- `templates/assets.html` — Asset inventory UI

---

#### GAP 2: Dark Web Monitoring — HIGH PRIORITY

**What SOCRadar does:**
- Continuous monitoring of TOR hidden services, paste sites, hacker forums
- Credential leak detection (breached databases, combo lists)
- Data leak monitoring (source code, documents, credentials)
- Ransomware group tracking (victim announcements, leak sites)
- Automated alerting when organization data appears

**What QuadSeer has:**
- Nothing

**Implementation needed:**
```python
# New service: app/services/darkweb_monitor.py
# - TOR proxy integration (requests via SOCKS5)
# - Pastebin/paste sites scraping (Pastebin, Ghostbin, etc.)
# - Breach database API integration (Have I Been Pwned, DeHashed)
# - Ransomware leak site monitoring (LockBit, ALPHV, etc.)
# - Telegram channel monitoring for threat actor chatter
# - Automated keyword matching for organization assets
```

**Files to add:**
- `app/services/darkweb_monitor.py`
- `app/services/breach_checker.py`
- `app/services/ransomware_tracker.py`
- `app/models/darkweb_finding.py`
- `app/tasks/darkweb_tasks.py`
- `templates/darkweb.html`

---

#### GAP 3: Brand Protection / Phishing Detection — HIGH PRIORITY

**What SOCRadar does:**
- AI-powered detection of lookalike domains (homoglyph attacks, typosquats)
- Newly registered domain monitoring for brand terms
- Phishing site detection and takedown assistance
- Mobile app impersonation detection
- Social media brand impersonation

**What QuadSeer has:**
- Nothing

**Implementation needed:**
```python
# New service: app/services/brand_protection.py
# - Domain similarity scoring (Levenshtein distance, homoglyph detection)
# - WHOIS monitoring for brand-related registrations
# - Certificate transparency log monitoring
# - Visual similarity detection (screenshot comparison using Pillow/OpenCV)
# - Phishing kit detection (HTML structure analysis)
# - Automated abuse reporting to registrars/hosting providers
```

**Files to add:**
- `app/services/brand_protection.py`
- `app/services/domain_similarity.py`
- `app/services/phishing_detector.py`
- `app/models/brand_alert.py`
- `app/tasks/brand_monitor_tasks.py`
- `templates/brand_protection.html`

---

#### GAP 4: Credential Leak Detection — HIGH PRIORITY

**What SOCRadar does:**
- Monitor breached databases for organization emails/domains
- Detect leaked API keys, database credentials, source code
- Alert on credential exposure in public repositories (GitHub, GitLab)
- Track leaked internal documents

**What QuadSeer has:**
- Nothing

**Implementation needed:**
```python
# New service: app/services/credential_monitor.py
# - Have I Been Pwned API integration (k-anonymity protocol)
# - GitHub code search API for leaked credentials
# - GitLeaks-style pattern matching (regex for API keys, tokens)
# - Google Dorking automation for exposed documents
# - S3 bucket/public cloud storage exposure detection
```

**Files to add:**
- `app/services/credential_monitor.py`
- `app/services/github_leak_scanner.py`
- `app/services/cloud_exposure_scanner.py`
- `app/models/credential_leak.py`
- `app/tasks/credential_tasks.py`

---

#### GAP 5: Vulnerability Intelligence (VulnDB) — MEDIUM PRIORITY

**What SOCRadar does:**
- CVE database with exploitability scoring
- EPSS (Exploit Prediction Scoring System) integration
- Vendor advisory aggregation
- Patch availability tracking
- Vulnerability-to-asset mapping

**What QuadSeer has:**
- Mock findings with hardcoded CVE references
- No live CVE database

**Implementation needed:**
```python
# New service: app/services/vuln_intel.py
# - NVD (National Vulnerability Database) API integration
# - EPSS API integration for probability scoring
# - CISA KEV (Known Exploited Vulnerabilities) catalog
# - Vendor-specific advisory feeds (Microsoft, Cisco, etc.)
# - Asset-to-CVE correlation (match discovered tech stack to known vulns)
```

**Files to add:**
- `app/services/vuln_intel.py`
- `app/services/nvd_client.py`
- `app/services/epss_client.py`
- `app/models/vulnerability.py`
- `app/tasks/vuln_sync_tasks.py`

---

#### GAP 6: Supply Chain / Vendor Risk — MEDIUM PRIORITY

**What SOCRadar does:**
- Third-party vendor monitoring
- Vendor breach notification
- Supply chain attack tracking (SolarWinds-style)
- Vendor security score calculation

**What QuadSeer has:**
- Nothing

**Implementation needed:**
- Vendor entity model
- External security rating API integration (BitSight, SecurityScorecard)
- Vendor breach correlation
- Dependency vulnerability scanning (SBOM analysis)

---

#### GAP 7: Alerting & Notification — MEDIUM PRIORITY

**What SOCRadar does:**
- Email, Slack, Teams, webhook, SMS, PagerDuty integrations
- Alert severity-based routing
- Alert deduplication and correlation
- Incident case management

**What QuadSeer has:**
- WebSocket real-time updates only
- Toast notifications in UI

**Implementation needed:**
```python
# New service: app/services/alerting.py
# - Email notification (SMTP/SendGrid/AWS SES)
# - Slack webhook integration
# - Microsoft Teams webhook
# - PagerDuty/EventBridge integration
# - Webhook callbacks for custom integrations
# - Alert rules engine (configurable thresholds)
```

**Files to add:**
- `app/services/alerting.py`
- `app/services/slack_notifier.py`
- `app/services/email_service.py`
- `app/models/alert_rule.py`
- `app/models/notification.py`
- `templates/settings/alerts.html`

---

#### GAP 8: Multi-tenant Architecture — MEDIUM PRIORITY

**What SOCRadar does:**
- Organization isolation
- White-label capabilities
- Per-tenant data segregation
- Tenant-level API keys

**What QuadSeer has:**
- Single-tenant with user ownership
- Basic admin/user roles

**Implementation needed:**
- `Organization` model with tenant isolation
- Row-level security or schema-per-tenant
- Tenant-aware middleware
- Organization onboarding flow

---

### 2.3 Implementation Roadmap

#### Phase 1: Core EASM (Weeks 1-3)
1. Implement `recon_service.py` with DNS enumeration, port scanning, SSL monitoring
2. Add `asset.py` model and CRUD endpoints
3. Integrate Shodan/Censys APIs for external discovery
4. Build asset inventory UI
5. Add scheduled recon tasks to Celery Beat

#### Phase 2: Dark Web & Credentials (Weeks 4-6)
1. Implement TOR proxy and dark web scrapers
2. Integrate HIBP and breach databases
3. Build GitHub leak scanner
4. Create dark web findings dashboard
5. Add credential leak alerting

#### Phase 3: Brand Protection (Weeks 7-8)
1. Build domain similarity engine
2. Implement CT log monitoring
3. Add phishing detection (visual + structural)
4. Create brand protection dashboard
5. Add takedown workflow

#### Phase 4: Vuln Intel & Alerting (Weeks 9-10)
1. Integrate NVD and EPSS APIs
2. Build vulnerability database sync
3. Implement multi-channel alerting
4. Add alert rules engine
5. Create notification preferences UI

#### Phase 5: Polish & Scale (Weeks 11-12)
1. Multi-tenant architecture
2. Performance optimization (caching, DB indexing)
3. Advanced reporting templates
4. SSO/SAML integration
5. Production hardening (secrets management, rate limiting)

### 2.4 Estimated Final File Count

| Phase | New Files | Cumulative Total |
|-------|-----------|------------------|
| Current v3.0 | 60 | 60 |
| Phase 1 (EASM) | +15 | 75 |
| Phase 2 (Dark Web) | +12 | 87 |
| Phase 3 (Brand) | +10 | 97 |
| Phase 4 (Vuln/Alerts) | +12 | 109 |
| Phase 5 (Scale) | +8 | **~117** |

---

## PART 3: CONFIGURATION FOR TESTING

### 3.1 Environment Variables

Create `.env` file in project root:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://quadseer:quadseer_secret@db:5432/quadseer

# Redis
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# Security
SECRET_KEY=your-256-bit-secret-key-here-change-in-production
ENVIRONMENT=development

# Optional: WeasyPrint for better PDF rendering
WEASYPRINT_ENABLED=false

# Optional: External API keys (for Phase 1+ features)
SHODAN_API_KEY=your_shodan_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
HIBP_API_KEY=your_hibp_key
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### 3.2 Docker Compose Overrides

For testing with external APIs, create `docker-compose.override.yml`:

```yaml
version: "3.9"

services:
  api:
    environment:
      - SHODAN_API_KEY=${SHODAN_API_KEY}
      - CENSYS_API_ID=${CENSYS_API_ID}
      - CENSYS_API_SECRET=${CENSYS_API_SECRET}
      - HIBP_API_KEY=${HIBP_API_KEY}
    volumes:
      - ./reports:/app/static/reports
```

### 3.3 Test Data Setup

```bash
# After first startup, verify seed data:
docker exec -it quadseer-db psql -U quadseer -d quadseer -c "
SELECT 'Plans' as entity, COUNT(*) as count FROM plans
UNION ALL
SELECT 'Threat Actors', COUNT(*) FROM threat_actors
UNION ALL
SELECT 'Users', COUNT(*) FROM users
UNION ALL
SELECT 'Subscriptions', COUNT(*) FROM subscriptions;
"

# Expected:
#    entity     | count
# --------------+-------
# Plans         |     3
# Threat Actors |     5
# Users         |     1
# Subscriptions |     1
```

### 3.4 Monitoring Stack

```bash
# View all logs
docker compose logs -f

# View specific service
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f beat

# Database queries
docker exec -it quadseer-db psql -U quadseer -d quadseer

# Redis inspection
docker exec -it quadseer-redis redis-cli

# Celery task inspection
docker exec -it quadseer-worker celery -A app.tasks.celery_app inspect active
docker exec -it quadseer-worker celery -A app.tasks.celery_app inspect scheduled
```

---

## SUMMARY

**QuadSeer v3.0 is a solid foundation** with:
- ✅ Full API infrastructure (FastAPI, async PostgreSQL, Redis, Celery)
- ✅ Authentication & authorization
- ✅ Basic scan orchestration with WebSocket real-time updates
- ✅ Report generation (PDF/HTML/JSON/CSV)
- ✅ Threat actor database with MITRE ATT&CK mapping
- ✅ Dashboard with stats and recent activity
- ✅ Seed data (plans, threat actors, admin user)
- ✅ Docker Compose for one-command deployment

**To reach SOCRadar parity, the critical next steps are:**
1. **Real external reconnaissance** (DNS, port scanning, SSL, cloud assets)
2. **Dark web monitoring** (TOR, breaches, ransomware trackers)
3. **Brand protection** (typosquat detection, phishing site identification)
4. **Credential leak detection** (HIBP, GitHub, exposed cloud storage)
5. **Vulnerability intelligence** (NVD, EPSS, CISA KEV)
6. **Multi-channel alerting** (email, Slack, webhooks)

These 6 modules represent approximately **80% of SOCRadar's commercial value proposition** and would require an estimated **12 weeks** of focused development to implement at production quality.
