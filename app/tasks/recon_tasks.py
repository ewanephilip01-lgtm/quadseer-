"""Celery tasks for EASM reconnaissance."""
import asyncio
from celery import shared_task
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.core.config import settings
from app.services.recon_service import ReconService

engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
async_session = async_sessionmaker(engine, expire_on_commit=False)


@shared_task(bind=True, max_retries=2, time_limit=1800)
def run_recon_task(self, target_id: int, owner_id: int):
    """Execute full asset discovery for a target."""
    async def _run():
        async with async_session() as db:
            service = ReconService(db)
            try:
                assets = await service.discover_assets(target_id, owner_id, scan_id=None)
                return {"status": "completed", "assets_discovered": len(assets)}
            except Exception as exc:
                raise self.retry(exc=exc, countdown=120)

    return asyncio.run(_run())


@shared_task
def scheduled_recon_scan():
    """Periodic task: run recon on all monitored targets."""
    async def _run():
        async with async_session() as db:
            from sqlalchemy import select
            from app.models.target import Target
            from app.models.asset import Asset
            from datetime import datetime, timedelta

            # Find targets with assets that haven't been scanned recently
            cutoff = datetime.utcnow() - timedelta(hours=24)
            result = await db.execute(
                select(Target).where(
                    Target.is_active == True,
                    Target.id.in_(
                        select(Asset.target_id).where(
                            (Asset.is_monitored == True) &
                            ((Asset.last_scan_at < cutoff) | (Asset.last_scan_at == None))
                        )
                    )
                )
            )
            targets = result.scalars().all()

            for target in targets:
                service = ReconService(db)
                try:
                    await service.discover_assets(target.id, target.owner_id)
                except Exception as e:
                    print(f"Scheduled recon failed for target {target.id}: {e}")

    asyncio.run(_run())
