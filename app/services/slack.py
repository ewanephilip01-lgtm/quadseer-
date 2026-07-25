"""Slack webhook notification service."""
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import httpx
from app.config import get_settings

settings = get_settings()

class SlackService:
    """Send security alerts to Slack via webhooks."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0)

    async def send_alert(
        self,
        webhook_url: str,
        title: str,
        message: str,
        severity: str = "medium",
        findings: Optional[List[Dict]] = None,
        scan_url: str = "",
        color_map: Optional[Dict[str, str]] = None
    ) -> bool:
        """Send formatted alert to Slack webhook."""
        if not webhook_url:
            return False

        colors = color_map or {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#22c55e",
            "info": "#3b82f6",
        }

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"QuadSeer Alert: {title}", "emoji": True}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Severity:* `{severity.upper()}` | *Time:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}
                ]
            }
        ]

        if findings:
            finding_text = "\n".join([
                f"• *{f.get('severity', 'info').upper()}*: {f.get('title', 'Unknown')}"
                for f in findings[:10]
            ])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Findings:*\n{finding_text}"}
            })

        if scan_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View in Dashboard", "emoji": True},
                        "url": scan_url,
                        "style": "primary"
                    }
                ]
            })

        payload = {
            "attachments": [{
                "color": colors.get(severity, "#3b82f6"),
                "blocks": blocks
            }]
        }

        try:
            resp = await self.client.post(webhook_url, json=payload)
            return resp.status_code == 200
        except Exception as e:
            print(f"[SLACK ERROR] {e}")
            return False

    async def send_scan_complete(
        self,
        webhook_url: str,
        scan_type: str,
        target: str,
        risk_score: float,
        findings_count: int,
        scan_url: str = ""
    ) -> bool:
        """Send scan completion notification."""
        severity = "high" if risk_score > 60 else "medium" if risk_score > 30 else "low"
        message = f"*{scan_type.replace('_', ' ').title()}* scan on `{target}` completed with risk score *{risk_score:.1f}/100* and *{findings_count}* findings."
        return await self.send_alert(webhook_url, "Scan Complete", message, severity, scan_url=scan_url)

# Singleton
slack_service = SlackService()
