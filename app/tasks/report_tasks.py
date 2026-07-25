"""Celery tasks for report generation."""
from celery import shared_task
import asyncio
from app.core.config import settings
from app.services.report_service import generate_report
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
async_session = async_sessionmaker(engine, expire_on_commit=False)


@shared_task(bind=True, max_retries=2)
def generate_report_task(self, report_id: int):
    async def _run():
        async with async_session() as db:
            await generate_report(db, report_id)
    asyncio.run(_run())
