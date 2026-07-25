#!/usr/bin/env python3
"""Test all imports to find what's failing."""
import sys
sys.path.insert(0, '/app')

errors = []

print("=== Testing Imports ===")

try:
    from app.core.database import engine, async_session, Base
    print("✓ app.core.database")
except Exception as e:
    print(f"✗ app.core.database: {e}")
    errors.append(("database", e))

try:
    from app.core.security import hash_password, verify_password, create_access_token
    print("✓ app.core.security")
except Exception as e:
    print(f"✗ app.core.security: {e}")
    errors.append(("security", e))

try:
    from app.core.config import ConfigManager
    print("✓ app.core.config")
except Exception as e:
    print(f"✗ app.core.config: {e}")
    errors.append(("config", e))

try:
    from app.models.user import User
    print("✓ app.models.user")
except Exception as e:
    print(f"✗ app.models.user: {e}")
    errors.append(("user model", e))

try:
    from app.models.target import Target
    print("✓ app.models.target")
except Exception as e:
    print(f"✗ app.models.target: {e}")
    errors.append(("target model", e))

try:
    from app.models.scan import Scan, ScanStatus, ScanType
    print("✓ app.models.scan")
except Exception as e:
    print(f"✗ app.models.scan: {e}")
    errors.append(("scan model", e))

try:
    from app.models.finding import Finding, FindingSeverity, FindingType
    print("✓ app.models.finding")
except Exception as e:
    print(f"✗ app.models.finding: {e}")
    errors.append(("finding model", e))

try:
    from app.models.report import Report
    print("✓ app.models.report")
except Exception as e:
    print(f"✗ app.models.report: {e}")
    errors.append(("report model", e))

try:
    from app.models.system_config import SystemConfig
    print("✓ app.models.system_config")
except Exception as e:
    print(f"✗ app.models.system_config: {e}")
    errors.append(("system_config model", e))

try:
    from app.api.v1.auth import router as auth_router
    print("✓ app.api.v1.auth")
except Exception as e:
    print(f"✗ app.api.v1.auth: {e}")
    errors.append(("auth router", e))

try:
    from app.api.v1.targets import router as targets_router
    print("✓ app.api.v1.targets")
except Exception as e:
    print(f"✗ app.api.v1.targets: {e}")
    errors.append(("targets router", e))

try:
    from app.api.v1.scans import router as scans_router
    print("✓ app.api.v1.scans")
except Exception as e:
    print(f"✗ app.api.v1.scans: {e}")
    errors.append(("scans router", e))

try:
    from app.api.v1.admin import router as admin_router
    print("✓ app.api.v1.admin")
except Exception as e:
    print(f"✗ app.api.v1.admin: {e}")
    errors.append(("admin router", e))

try:
    from app.api.v1.reports import router as reports_router
    print("✓ app.api.v1.reports")
except Exception as e:
    print(f"✗ app.api.v1.reports: {e}")
    errors.append(("reports router", e))

try:
    from app.api.health import router as health_router
    print("✓ app.api.health")
except Exception as e:
    print(f"✗ app.api.health: {e}")
    errors.append(("health router", e))

try:
    from app.tasks.scan_tasks import run_scan_task
    print("✓ app.tasks.scan_tasks")
except Exception as e:
    print(f"✗ app.tasks.scan_tasks: {e}")
    errors.append(("scan tasks", e))

print(f"
=== {len(errors)} errors found ===")
for name, err in errors:
    print(f"  {name}: {err}")
