#!/bin/bash
# QuadSeer Diagnostic Script

echo "═══════════════════════════════════════════════════════"
echo "  QUADSEER DIAGNOSTICS"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "1. Docker Compose Status:"
echo "───────────────────────────────────────────────────────"
docker-compose ps
echo ""

echo "2. API Container Logs (last 30 lines):"
echo "───────────────────────────────────────────────────────"
docker logs --tail 30 quadseer-api-1 2>&1
echo ""

echo "3. Seed Container Logs:"
echo "───────────────────────────────────────────────────────"
docker logs --tail 20 quadseer-seed-1 2>&1
echo ""

echo "4. Port Mapping:"
echo "───────────────────────────────────────────────────────"
docker port quadseer-api-1
echo ""

echo "5. Health Check from inside container:"
echo "───────────────────────────────────────────────────────"
docker exec quadseer-api-1 curl -s http://localhost:8000/api/health 2>&1 || echo "Container not running or curl not available"
echo ""

echo "6. Database connectivity from API:"
echo "───────────────────────────────────────────────────────"
docker exec quadseer-api-1 python -c "import asyncpg; print('asyncpg OK')" 2>&1 || echo "asyncpg not installed"
echo ""

echo "═══════════════════════════════════════════════════════"
echo "  END OF DIAGNOSTICS"
echo "═══════════════════════════════════════════════════════"
