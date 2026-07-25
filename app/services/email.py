"""Email service with SMTP/SendGrid support."""
import asyncio
from datetime import datetime
from typing import List, Optional
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template
from app.config import get_settings

settings = get_settings()

# HTML email templates
ALERT_EMAIL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 12px; overflow: hidden; border: 1px solid #334155; }
        .header { background: linear-gradient(135deg, #0ea5e9, #8b5cf6); padding: 30px; text-align: center; }
        .header h1 { margin: 0; color: white; font-size: 24px; }
        .content { padding: 30px; }
        .severity-critical { color: #ef4444; font-weight: bold; }
        .severity-high { color: #f97316; font-weight: bold; }
        .severity-medium { color: #eab308; font-weight: bold; }
        .severity-low { color: #22c55e; font-weight: bold; }
        .finding { background: #0f172a; border-left: 4px solid #0ea5e9; padding: 15px; margin: 15px 0; border-radius: 0 8px 8px 0; }
        .footer { padding: 20px; text-align: center; color: #64748b; font-size: 12px; border-top: 1px solid #334155; }
        .btn { display: inline-block; background: linear-gradient(135deg, #0ea5e9, #8b5cf6); color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ QuadSeer Security Alert</h1>
        </div>
        <div class="content">
            <h2>{{ subject }}</h2>
            <p>{{ message }}</p>
            {% if findings %}
            <h3>Findings:</h3>
            {% for finding in findings %}
            <div class="finding">
                <strong class="severity-{{ finding.severity }}">{{ finding.severity.upper() }}</strong>: {{ finding.title }}
                <p>{{ finding.description or "No description available." }}</p>
            </div>
            {% endfor %}
            {% endif %}
            <a href="{{ dashboard_url }}" class="btn">View Dashboard</a>
        </div>
        <div class="footer">
            <p>QuadSeer Threat Intelligence Platform</p>
            <p>{{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
"""

SCAN_COMPLETE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 12px; overflow: hidden; border: 1px solid #334155; }
        .header { background: linear-gradient(135deg, #0ea5e9, #8b5cf6); padding: 30px; text-align: center; }
        .header h1 { margin: 0; color: white; font-size: 24px; }
        .content { padding: 30px; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat { text-align: center; padding: 15px; background: #0f172a; border-radius: 8px; min-width: 80px; }
        .stat-value { font-size: 28px; font-weight: bold; }
        .stat-label { font-size: 12px; color: #94a3b8; margin-top: 5px; }
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #eab308; }
        .low { color: #22c55e; }
        .footer { padding: 20px; text-align: center; color: #64748b; font-size: 12px; border-top: 1px solid #334155; }
        .btn { display: inline-block; background: linear-gradient(135deg, #0ea5e9, #8b5cf6); color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Scan Complete</h1>
        </div>
        <div class="content">
            <h2>{{ scan_type.replace('_', ' ').title() }} Scan Finished</h2>
            <p>Target: <strong>{{ target }}</strong></p>
            <p>Risk Score: <strong>{{ risk_score }}/100</strong></p>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value critical">{{ critical }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value high">{{ high }}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-value medium">{{ medium }}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-value low">{{ low }}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            <a href="{{ scan_url }}" class="btn">View Full Report</a>
        </div>
        <div class="footer">
            <p>QuadSeer Threat Intelligence Platform</p>
            <p>{{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
"""

class EmailService:
    """Async email service with SMTP support."""

    def __init__(self):
        self.host = settings.SMTP_HOST
        self.port = settings.SMTP_PORT
        self.user = settings.SMTP_USER
        self.password = settings.SMTP_PASSWORD
        self.from_addr = settings.SMTP_FROM
        self.use_tls = settings.SMTP_TLS
        self.enabled = bool(self.password)

    async def send_email(
        self,
        to_addresses: List[str],
        subject: str,
        html_body: str,
        text_body: Optional[str] = None
    ) -> bool:
        """Send email via SMTP. Returns True on success."""
        if not self.enabled:
            # Log to console as fallback
            print(f"[EMAIL CONSOLE] To: {to_addresses}")
            print(f"[EMAIL CONSOLE] Subject: {subject}")
            print(f"[EMAIL CONSOLE] Body: {html_body[:500]}...")
            return True

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(to_addresses)

            if text_body:
                msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            await aiosmtplib.send(
                msg,
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                start_tls=self.use_tls,
            )
            return True
        except Exception as e:
            print(f"[EMAIL ERROR] Failed to send email: {e}")
            return False

    async def send_alert_email(
        self,
        to_addresses: List[str],
        subject: str,
        message: str,
        findings: Optional[List[dict]] = None,
        dashboard_url: str = ""
    ) -> bool:
        """Send security alert email."""
        template = Template(ALERT_EMAIL_TEMPLATE)
        html = template.render(
            subject=subject,
            message=message,
            findings=findings or [],
            dashboard_url=dashboard_url or f"{settings.APP_URL}/",
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        )
        return await self.send_email(to_addresses, subject, html, message)

    async def send_scan_complete_email(
        self,
        to_addresses: List[str],
        scan_type: str,
        target: str,
        risk_score: float,
        critical: int,
        high: int,
        medium: int,
        low: int,
        scan_url: str = ""
    ) -> bool:
        """Send scan completion email."""
        template = Template(SCAN_COMPLETE_TEMPLATE)
        html = template.render(
            scan_type=scan_type,
            target=target,
            risk_score=risk_score,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            scan_url=scan_url or f"{settings.APP_URL}/scans",
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        )
        subject = f"Scan Complete: {scan_type.replace('_', ' ').title()} - {target}"
        return await self.send_email(to_addresses, subject, html)

# Singleton
email_service = EmailService()
