"""Alert routes with email + Slack + webhook support."""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.alert import AlertRule, AlertLog
from app.schemas import AlertRuleCreate, AlertRuleResponse, AlertLogResponse

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.post("/rules", response_model=AlertRuleResponse)
async def create_alert_rule(
    rule_data: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new alert rule."""
    rule = AlertRule(
        owner_id=current_user.id,
        **rule_data.model_dump()
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule

@router.get("/rules", response_model=List[AlertRuleResponse])
async def list_alert_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List alert rules."""
    result = await db.execute(
        select(AlertRule).where(AlertRule.owner_id == current_user.id).order_by(desc(AlertRule.created_at))
    )
    return result.scalars().all()

@router.get("/rules/{rule_id}", response_model=AlertRuleResponse)
async def get_alert_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get alert rule details."""
    result = await db.execute(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.owner_id == current_user.id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.put("/rules/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: UUID,
    rule_data: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update alert rule."""
    result = await db.execute(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.owner_id == current_user.id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    for field, value in rule_data.model_dump().items():
        setattr(rule, field, value)

    await db.commit()
    await db.refresh(rule)
    return rule

@router.delete("/rules/{rule_id}")
async def delete_alert_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete alert rule."""
    result = await db.execute(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.owner_id == current_user.id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    await db.delete(rule)
    await db.commit()
    return {"message": "Rule deleted"}

@router.get("/logs", response_model=List[AlertLogResponse])
async def list_alert_logs(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List alert logs for user's rules."""
    result = await db.execute(
        select(AlertLog)
        .join(AlertRule)
        .where(AlertRule.owner_id == current_user.id)
        .order_by(desc(AlertLog.created_at))
        .limit(limit)
    )
    return result.scalars().all()

@router.post("/rules/{rule_id}/test")
async def test_alert_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test alert rule by sending a test notification."""
    result = await db.execute(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.owner_id == current_user.id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    from app.services.email import email_service
    from app.services.slack import slack_service

    test_results = []

    if rule.channel_email and rule.email_recipients:
        success = await email_service.send_alert_email(
            rule.email_recipients,
            "Test Alert from QuadSeer",
            "This is a test alert to verify your notification configuration.",
            dashboard_url="http://localhost:8000/alerts"
        )
        test_results.append({"channel": "email", "success": success})

    if rule.channel_slack and rule.slack_webhook_url:
        success = await slack_service.send_alert(
            rule.slack_webhook_url,
            "Test Alert",
            "This is a test alert from QuadSeer.",
            severity="info",
            scan_url="http://localhost:8000/alerts"
        )
        test_results.append({"channel": "slack", "success": success})

    return {"message": "Test completed", "results": test_results}
