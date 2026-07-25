"""Threat intelligence endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from app.db.session import get_db
from app.api.v1.auth import get_current_user, get_current_admin
from app.models.user import User
from app.schemas.threat_actor import ThreatActorRead, ThreatActorCreate
from app.services.threat_intel_service import search_threat_actors, get_threat_actor, get_threat_stats
from app.models.threat_actor import ThreatActor

router = APIRouter()


@router.get("/threats/actors", response_model=List[ThreatActorRead])
async def list_threat_actors(q: Optional[str] = None, min_threat_level: float = 0.0, limit: int = 50,
                              db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await search_threat_actors(db, q, min_threat_level, limit)


@router.get("/threats/actors/{actor_id}", response_model=ThreatActorRead)
async def read_threat_actor(actor_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    actor = await get_threat_actor(db, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return actor


@router.get("/threats/stats")
async def threat_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await get_threat_stats(db)


@router.post("/threats/actors", response_model=ThreatActorRead)
async def create_threat_actor(actor_in: ThreatActorCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin)):
    actor = ThreatActor(
        name=actor_in.name, aliases=actor_in.aliases, origin=actor_in.origin, motivation=actor_in.motivation,
        sophistication=actor_in.sophistication, threat_level=actor_in.threat_level, description=actor_in.description,
        tactics=actor_in.tactics, techniques=actor_in.techniques, targets=actor_in.targets,
        iocs=actor_in.iocs, sources=actor_in.sources
    )
    db.add(actor)
    await db.commit()
    await db.refresh(actor)
    return actor
