"""
Celery Application Configuration
Fixed: Import chain resolved by fixing report_service.py SyntaxError
"""
from celery import Celery
from celery.signals import worker_ready
import os

# Use Redis as broker and backend
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "quadseer",
    broker=redis_url,
    backend=redis_url,
    include=["app.tasks.scan_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    worker_prefetch_multiplier=1,
    result_expires=3600 * 24,  # Results expire after 24 hours
    beat_schedule={
        "periodic-scan-check": {
            "task": "app.tasks.scan_tasks.check_pending_scans",
            "schedule": 300.0,  # Every 5 minutes
        },
        "ssl-monitor-check": {
            "task": "app.tasks.scan_tasks.monitor_ssl_expiry",
            "schedule": 86400.0,  # Daily
        },
    },
)


@worker_ready.connect
def on_worker_ready(**kwargs):
    """Log when worker is ready."""
    print("✅ Celery worker is ready and accepting tasks")
