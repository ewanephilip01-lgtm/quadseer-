"""Threat Intelligence routes: Threat Actors, IOCs, YARA Rules."""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.threat_intel import ThreatActor, IOC, YARARule, IOCType
from app.schemas import ThreatActorResponse, IOCResponse, YARARuleResponse

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

@router.get("/actors", response_model=List[ThreatActorResponse])
async def list_threat_actors(
    search: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List threat actors with optional filters."""
    query = select(ThreatActor).where(ThreatActor.is_active == True)
    if search:
        query = query.where(ThreatActor.name.ilike(f"%{search}%"))
    if country:
        query = query.where(ThreatActor.country == country)
    query = query.order_by(desc(ThreatActor.last_seen)).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/actors/{actor_id}", response_model=ThreatActorResponse)
async def get_threat_actor(
    actor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get threat actor details with IOCs and YARA rules."""
    result = await db.execute(
        select(ThreatActor).where(ThreatActor.id == actor_id, ThreatActor.is_active == True)
    )
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return actor

@router.get("/iocs", response_model=List[IOCResponse])
async def list_iocs(
    ioc_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List IOCs with filters."""
    query = select(IOC).where(IOC.is_active == True)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if search:
        query = query.where(IOC.value.ilike(f"%{search}%"))
    if confidence:
        query = query.where(IOC.confidence == confidence)
    query = query.order_by(desc(IOC.last_seen)).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/iocs/check")
async def check_ioc(
    value: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Check if a value matches any known IOC."""
    result = await db.execute(
        select(IOC).where(IOC.value == value, IOC.is_active == True)
    )
    ioc = result.scalar_one_or_none()

    if ioc:
        return {
            "matched": True,
            "ioc": IOCResponse.model_validate(ioc),
            "threat_actor": ioc.threat_actor.name if ioc.threat_actor else None,
        }
    return {"matched": False, "ioc": None}

@router.get("/yara-rules", response_model=List[YARARuleResponse])
async def list_yara_rules(
    tag: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List YARA rules."""
    query = select(YARARule).where(YARARule.is_active == True)
    if tag:
        query = query.where(YARARule.tags.contains([tag]))
    query = query.order_by(desc(YARARule.match_count)).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/yara-rules/{rule_id}", response_model=YARARuleResponse)
async def get_yara_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get YARA rule details."""
    result = await db.execute(
        select(YARARule).where(YARARule.id == rule_id, YARARule.is_active == True)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    return rule

@router.post("/yara-rules/{rule_id}/match")
async def match_yara_rule(
    rule_id: UUID,
    sample_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test YARA rule against sample data (simulated)."""
    result = await db.execute(
        select(YARARule).where(YARARule.id == rule_id, YARARule.is_active == True)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")

    # Simple string matching simulation
    content = sample_data.get("content", "")
    matched = any(tag.lower() in content.lower() for tag in rule.tags)

    if matched:
        rule.match_count += 1
        await db.commit()

    return {"matched": matched, "rule_name": rule.name, "match_count": rule.match_count}
