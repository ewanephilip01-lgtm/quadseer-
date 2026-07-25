#!/usr/bin/env python3
"""
End-to-end test script for Phase 2 services.
Validates Breach Checker, Ransomware Tracker, and Dark Web Monitor.
"""
import sys
import os
import asyncio
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.breach_checker import breach_service
from app.services.ransomware_tracker import ransomware_service
from app.services.darkweb_monitor import darkweb_service


async def test_breach_checker():
    """Test HIBP and DeHashed integration."""
    print("\n" + "="*60)
    print("TEST 1: BREACH CHECKER")
    print("="*60)

    # Test HIBP - check a known breached email (test domain)
    print("\n[1a] Testing HIBP email check...")
    result = await breach_service.check_email_hibp("test@example.com")
    print(f"  Status: {'FOUND' if result['found'] else 'NOT FOUND'}")
    if result.get('error'):
        print(f"  Error: {result['error']}")
    else:
        print(f"  Breaches: {result['breach_count']}")

    # Test HIBP - all breaches list (unauthenticated)
    print("\n[1b] Testing HIBP all breaches...")
    # This is tested implicitly via the API
    print("  (Requires API key for full test)")

    # Test DeHashed
    print("\n[1c] Testing DeHashed search...")
    result = await breach_service.search_dehashed("domain:example.com")
    print(f"  Status: {'FOUND' if result['found'] else 'NOT FOUND'}")
    if result.get('error'):
        print(f"  Error: {result['error']}")
    else:
        print(f"  Entries: {result.get('total', 0)}")

    await breach_service.close()
    print("\n✅ Breach Checker tests complete")


async def test_ransomware_tracker():
    """Test ransomware.live API integration."""
    print("\n" + "="*60)
    print("TEST 2: RANSOMWARE TRACKER")
    print("="*60)

    # Test recent victims
    print("\n[2a] Testing recent victims fetch...")
    victims = await ransomware_service.get_recent_victims(hours=168)
    print(f"  Recent victims (7d): {len(victims)}")
    if victims:
        print(f"  Sample: {victims[0].get('victim', 'N/A')} ({victims[0].get('group', 'N/A')})")

    # Test group stats
    print("\n[2b] Testing group stats...")
    stats = await ransomware_service.get_group_stats()
    print(f"  Active groups: {stats['active_groups']}")
    print(f"  Total recent victims: {stats['total_recent_victims']}")

    # Test domain search
    print("\n[2c] Testing domain search...")
    matches = await ransomware_service.search_victims_by_domain("example.com")
    print(f"  Matches for 'example.com': {len(matches)}")

    await ransomware_service.close()
    print("\n✅ Ransomware Tracker tests complete")


async def test_darkweb_monitor():
    """Test dark web monitoring."""
    print("\n" + "="*60)
    print("TEST 3: DARK WEB MONITOR")
    print("="*60)

    # Test ransomware mentions (primary dark web source)
    print("\n[3a] Testing ransomware leak site monitoring...")
    mentions = await darkweb_service.search_ransomware_mentions("example.com")
    print(f"  Ransomware mentions: {len(mentions)}")

    # Test paste site search (requires HIBP key)
    print("\n[3b] Testing paste site search...")
    pastes = await darkweb_service.search_paste_sites("test@example.com")
    print(f"  Pastes found: {len(pastes)}")

    await darkweb_service.close()
    print("\n✅ Dark Web Monitor tests complete")


async def test_api_endpoints():
    """Test that API endpoints are importable and valid."""
    print("\n" + "="*60)
    print("TEST 4: API ENDPOINTS")
    print("="*60)

    try:
        from app.main import app
        print("  ✅ FastAPI app imports successfully")

        # Check routes
        routes = [r.path for r in app.routes]
        required = [
            "/api/health",
            "/api/version",
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/targets/",
            "/api/v1/scans/",
            "/api/v1/admin/configs",
            "/api/v1/reports/{report_id}/download",
        ]

        for route in required:
            found = any(route in r for r in routes)
            status = "✅" if found else "❌"
            print(f"  {status} {route}")

    except Exception as e:
        print(f"  ❌ API import failed: {e}")


async def main():
    print("\n" + "="*60)
    print("QUADSEER v3.0 - PHASE 2 END-TO-END VALIDATION")
    print("="*60)

    await test_breach_checker()
    await test_ransomware_tracker()
    await test_darkweb_monitor()
    await test_api_endpoints()

    print("\n" + "="*60)
    print("ALL TESTS COMPLETE")
    print("="*60)
    print("""
Next steps:
1. Configure API keys in /admin dashboard:
   - HIBP API Key
   - DeHashed Email + API Key

2. Create a target and run scans:
   POST /api/v1/targets/ -> {name, domain}
   POST /api/v1/scans/ -> {target_id, scan_type: "breach"}

3. Check results:
   GET /api/v1/scans/{id}/results
    """)


if __name__ == "__main__":
    asyncio.run(main())
