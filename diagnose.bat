@echo off
echo ==========================================
echo QuadSeer API Diagnostic
echo ==========================================
echo.

echo [1] Container status:
docker-compose ps
echo.

echo [2] API container logs (last 30 lines):
docker-compose logs --tail=30 api
echo.

echo [3] Checking for port conflicts:
netstat -ano | findstr :8000
echo.

echo [4] Try to exec into API container and test Python imports:
docker-compose exec api python -c "from app.main import app; print('Import OK')" 2>&1
echo.

echo [5] Check if uvicorn is running inside API container:
docker-compose exec api ps aux 2>&1 | findstr uvicorn
echo.

echo ==========================================
pause
