@echo off
echo ==========================================
echo QuadSeer v3.0 - Windows Test Script
echo ==========================================
echo.

REM Step 1: Rebuild containers with no cache
echo [1/6] Rebuilding containers...
docker-compose down
docker-compose build --no-cache api seed celery-worker celery-beat
docker-compose up -d

echo.
echo [2/6] Waiting 30 seconds for services to start...
timeout /t 30 /nobreak >nul

echo.
echo [3/6] Seeding database...
docker-compose run --rm seed

echo.
echo [4/6] Checking health...
curl -s http://localhost:8000/api/health

echo.
echo [5/6] Testing login...
curl -s -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/json" -d "{\"email\":\"admin@quadseer.local\",\"password\":\"admin123\"}"

echo.
echo [6/6] Getting version...
curl -s http://localhost:8000/api/version

echo.
echo ==========================================
echo Setup complete! Open http://localhost:8000
echo Login: admin@quadseer.local / admin123
echo ==========================================
pause
