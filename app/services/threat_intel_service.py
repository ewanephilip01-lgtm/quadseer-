"""Threat intelligence aggregation service."""
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.threat_actor import ThreatActor


async def search_threat_actors(db: AsyncSession, query: Optional[str] = None, 
                                min_threat_level: float = 0.0, 
                                limit: int = 50) -> List[ThreatActor]:
    stmt = select(ThreatActor).where(ThreatActor.is_active == True)
    if query:
        stmt = stmt.where((ThreatActor.name.ilike(f"%{query}%")) | (ThreatActor.description.ilike(f"%{query}%")))
    if min_threat_level > 0:
        stmt = stmt.where(ThreatActor.threat_level >= min_threat_level)
    stmt = stmt.order_by(ThreatActor.threat_level.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_threat_actor(db: AsyncSession, actor_id: int) -> Optional[ThreatActor]:
    result = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    return result.scalar_one_or_none()


async def get_threat_stats(db: AsyncSession) -> dict:
    total = await db.execute(select(func.count(ThreatActor.id)).where(ThreatActor.is_active == True))
    high_threat = await db.execute(select(func.count(ThreatActor.id)).where((ThreatActor.threat_level >= 7.0) & (ThreatActor.is_active == True)))
    return {"total_actors": total.scalar(), "high_threat_actors": high_threat.scalar()}
