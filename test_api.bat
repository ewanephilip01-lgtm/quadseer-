@echo off
echo QuadSeer API Test Script for Windows CMD
echo ==========================================
echo.

REM Get token
echo Step 1: Login...
curl -s -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/json" -d "{\"email\":\"admin@quadseer.local\",\"password\":\"admin123\"}"

echo.
echo.
echo Step 2: Health check...
curl -s http://localhost:8000/api/health

echo.
echo.
echo Step 3: Version...
curl -s http://localhost:8000/api/version

echo.
echo.
echo Step 4: List targets (requires token - paste yours below)
REM curl -s http://localhost:8000/api/v1/targets/ -H "Authorization: Bearer YOUR_TOKEN_HERE"

echo.
pause
