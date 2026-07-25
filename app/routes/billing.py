"""Billing routes with Flutterwave HMAC-SHA256 webhook verification."""
import hmac
import hashlib
import json
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.billing import Plan, Subscription, Payment, SubscriptionStatus, PlanInterval
from app.schemas import PlanResponse, SubscriptionResponse, PaymentResponse, CheckoutRequest, CheckoutResponse
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/billing", tags=["Billing"])

@router.get("/plans", response_model=List[PlanResponse])
async def list_plans(db: AsyncSession = Depends(get_db)):
    """List active pricing plans."""
    result = await db.execute(select(Plan).where(Plan.is_active == True).order_by(Plan.price_monthly))
    return result.scalars().all()

@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    checkout: CheckoutRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create Flutterwave checkout session."""
    result = await db.execute(select(Plan).where(Plan.id == checkout.plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    amount = float(plan.price_monthly) if checkout.interval == "monthly" else float(plan.price_yearly)
    tx_ref = f"QS-{current_user.id}-{plan.id}-{checkout.interval}-{datetime.utcnow().timestamp()}"

    # Create pending subscription
    subscription = Subscription(
        user_id=current_user.id,
        plan_id=plan.id,
        status=SubscriptionStatus.TRIAL,
        interval=PlanInterval.MONTHLY if checkout.interval == "monthly" else PlanInterval.YEARLY,
        flutterwave_tx_ref=tx_ref,
    )
    db.add(subscription)
    await db.commit()

    # Build Flutterwave payment link
    payment_link = None
    if settings.FLUTTERWAVE_SECRET_KEY:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.flutterwave.com/v3/payments",
                headers={"Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}"},
                json={
                    "tx_ref": tx_ref,
                    "amount": amount,
                    "currency": plan.currency,
                    "redirect_url": f"{settings.APP_URL}/pricing/success",
                    "customer": {"email": checkout.email, "name": current_user.full_name},
                    "customizations": {"title": f"QuadSeer {plan.name}", "description": plan.description or ""},
                }
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                payment_link = data.get("link")

    return CheckoutResponse(
        payment_link=payment_link,
        transaction_ref=tx_ref,
        public_key=settings.FLUTTERWAVE_PUBLIC_KEY or "",
        message="Checkout initiated" if payment_link else "Simulated checkout (no Flutterwave key configured)",
    )

@router.post("/webhook")
async def flutterwave_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle Flutterwave webhook with HMAC-SHA256 verification."""
    payload = await request.body()
    signature = request.headers.get("verif-hash", "")

    # HMAC-SHA256 verification
    if settings.FLUTTERWAVE_WEBHOOK_HASH:
        expected = hmac.new(
            settings.FLUTTERWAVE_WEBHOOK_HASH.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

    data = json.loads(payload)
    tx_ref = data.get("txRef") or data.get("tx_ref")
    status = data.get("status")

    # Update subscription
    result = await db.execute(select(Subscription).where(Subscription.flutterwave_tx_ref == tx_ref))
    subscription = result.scalar_one_or_none()

    if subscription and status == "successful":
        subscription.status = SubscriptionStatus.ACTIVE
        subscription.current_period_start = datetime.utcnow()
        subscription.current_period_end = datetime.utcnow() + timedelta(days=30 if subscription.interval == PlanInterval.MONTHLY else 365)

        # Create payment record
        payment = Payment(
            subscription_id=subscription.id,
            user_id=subscription.user_id,
            amount=data.get("amount", 0),
            currency=data.get("currency", "USD"),
            status="completed",
            provider="flutterwave",
            provider_tx_id=data.get("id"),
            provider_ref=tx_ref,
        )
        db.add(payment)
        await db.commit()

    return {"status": "received"}

@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current user subscription."""
    result = await db.execute(
        select(Subscription)
        .where(Subscription.user_id == current_user.id)
        .order_by(desc(Subscription.created_at))
    )
    subscription = result.scalar_one_or_none()
    if not subscription:
        raise HTTPException(status_code=404, detail="No active subscription")
    return subscription

@router.get("/payments", response_model=List[PaymentResponse])
async def list_payments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List payment history."""
    result = await db.execute(
        select(Payment).where(Payment.user_id == current_user.id).order_by(desc(Payment.created_at))
    )
    return result.scalars().all()

from datetime import datetime, timedelta
