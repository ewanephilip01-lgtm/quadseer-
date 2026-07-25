"""QUADSEER v3.1 — Cyber Threat Intelligence Platform"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.core.database import create_tables
from app.routes import auth, scans, admin, alerts, billing, dashboard, monitoring, organizations, reports, threat_intel

settings = get_settings()

app = FastAPI(
    title="QUADSEER",
    description="Cyber Threat Intelligence Platform",
    version="3.1.0"
)

# Session middleware
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# API Routes
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(admin.router)
app.include_router(alerts.router)
app.include_router(billing.router)
app.include_router(dashboard.router)
app.include_router(monitoring.router)
app.include_router(organizations.router)
app.include_router(reports.router)
app.include_router(threat_intel.router)

@app.get("/")
async def root():
    return {"message": "QUADSEER v3.1 — Cyber Threat Intelligence Platform"}

@app.on_event("startup")
async def startup():
    await create_tables()