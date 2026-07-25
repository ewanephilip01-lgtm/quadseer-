"""Report generation service: PDF, CSV, JSON, Markdown."""
import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# Optional imports - graceful degradation
WEASYPRINT_AVAILABLE = False
REPORTLAB_AVAILABLE = False

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    pass

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    pass

from app.models.scan import Scan, ScanFinding
from app.models.report import Report, ReportFormat, ReportStatus
from app.config import get_settings

settings = get_settings()

class ReportService:
    """Generate downloadable threat reports."""

    REPORTS_DIR = "/app/reports"

    def __init__(self):
        os.makedirs(self.REPORTS_DIR, exist_ok=True)

    async def generate_report(
        self,
        db: AsyncSession,
        report_id: UUID,
        scan_id: Optional[UUID] = None,
        report_format: str = "pdf",
        filters: Optional[Dict] = None
    ) -> str:
        """Generate report file and return path."""

        # Fetch scan data
        scan = None
        findings = []
        if scan_id:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                f_result = await db.execute(
                    select(ScanFinding).where(ScanFinding.scan_id == scan_id)
                )
                findings = f_result.scalars().all()

        # Apply filters
        if filters:
            min_severity = filters.get("min_severity")
            if min_severity:
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                min_val = severity_order.get(min_severity, 0)
                findings = [f for f in findings if severity_order.get(f.severity, 0) >= min_val]

        # Generate based on format
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{report_id}_{timestamp}"

        if report_format == "pdf":
            return await self._generate_pdf(report_id, scan, findings, filename)
        elif report_format == "csv":
            return await self._generate_csv(report_id, scan, findings, filename)
        elif report_format == "json":
            return await self._generate_json(report_id, scan, findings, filename)
        elif report_format == "markdown":
            return await self._generate_markdown(report_id, scan, findings, filename)
        else:
            raise ValueError(f"Unsupported format: {report_format}")

    async def _generate_pdf(self, report_id, scan, findings, filename) -> str:
        """Generate PDF report using ReportLab (fallback to HTML if available)."""
        filepath = os.path.join(self.REPORTS_DIR, f"{filename}.pdf")

        if REPORTLAB_AVAILABLE:
            return self._generate_pdf_reportlab(filepath, scan, findings)
        elif WEASYPRINT_AVAILABLE:
            return self._generate_pdf_weasyprint(filepath, scan, findings)
        else:
            # Fallback: generate HTML and note PDF unavailable
            html_path = os.path.join(self.REPORTS_DIR, f"{filename}.html")
            self._generate_html_content(html_path, scan, findings)
            return html_path

    def _generate_pdf_reportlab(self, filepath: str, scan, findings) -> str:
        """Generate PDF using ReportLab."""
        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor("#0ea5e9"),
            spaceAfter=30,
        )

        story = []

        # Title
        story.append(Paragraph("QuadSeer Threat Intelligence Report", title_style))
        story.append(Spacer(1, 12))

        # Meta
        meta_data = [
            ["Generated:", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
            ["Scan Type:", scan.scan_type.replace("_", " ").title() if scan else "N/A"],
            ["Target:", scan.target if scan else "N/A"],
            ["Risk Score:", f"{scan.risk_score:.1f}/100" if scan else "N/A"],
        ]
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))

        # Findings
        story.append(Paragraph("Findings", styles["Heading2"]))
        story.append(Spacer(1, 12))

        if findings:
            finding_data = [["Severity", "Title", "Category", "Port"]]
            for f in findings:
                finding_data.append([
                    f.severity.upper(),
                    f.title[:60],
                    f.category or "N/A",
                    str(f.port) if f.port else "N/A"
                ])

            f_table = Table(finding_data, colWidths=[1.2*inch, 3*inch, 1.3*inch, 0.8*inch])
            f_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#1e293b"), colors.HexColor("#0f172a")]),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.whitesmoke),
            ]))
            story.append(f_table)
        else:
            story.append(Paragraph("No findings recorded.", styles["Normal"]))

        story.append(PageBreak())
        story.append(Paragraph("Detailed Findings", styles["Heading2"]))

        for f in findings:
            story.append(Spacer(1, 10))
            sev_color = "#ef4444" if f.severity == "critical" else "#f97316" if f.severity == "high" else "#eab308"
            story.append(Paragraph(f"<b>{f.title}</b> <font color='{sev_color}'>[{f.severity.upper()}]</font>", styles["Heading3"]))
            if f.description:
                story.append(Paragraph(f.description, styles["Normal"]))
            if f.remediation:
                story.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", styles["Normal"]))
            story.append(Spacer(1, 5))

        doc.build(story)
        return filepath

    def _generate_pdf_weasyprint(self, filepath: str, scan, findings) -> str:
        """Generate PDF using WeasyPrint."""
        html_content = self._build_html_report(scan, findings)
        HTML(string=html_content).write_pdf(filepath)
        return filepath

    def _generate_html_content(self, filepath: str, scan, findings):
        """Generate HTML report file."""
        html = self._build_html_report(scan, findings)
        with open(filepath, "w") as f:
            f.write(html)
        return filepath

    def _build_html_report(self, scan, findings) -> str:
        """Build HTML report content."""
        parts = []
        for f in findings:
            color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e", "info": "#3b82f6"}.get(f.severity, "#94a3b8")
            remediation = f"<p style='margin: 5px 0; color: #94a3b8;'><b>Remediation:</b> {f.remediation}</p>" if f.remediation else ""
            cve = f"<p style='margin: 5px 0; color: #94a3b8;'><b>CVE:</b> {f.cve_id}</p>" if f.cve_id else ""
            port = f"<p style='margin: 5px 0; color: #94a3b8;'><b>Port:</b> {f.port} | <b>Service:</b> {f.service}</p>" if f.port else ""
            parts.append(f"""<div style="border-left: 4px solid {color}; padding: 15px; margin: 15px 0; background: #0f172a; border-radius: 0 8px 8px 0;">
                <h3 style="margin: 0; color: {color};">[{f.severity.upper()}] {f.title}</h3>
                <p style="margin: 8px 0; color: #cbd5e1;">{f.description or "No description"}</p>
                {remediation}
                {cve}
                {port}
            </div>""")

        findings_html = "".join(parts)

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }}
.container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 40px; border: 1px solid #334155; }}
h1 {{ color: #0ea5e9; margin-top: 0; }}
h2 {{ color: #8b5cf6; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
.meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }}
.meta-item {{ background: #0f172a; padding: 15px; border-radius: 8px; }}
.meta-label {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
.meta-value {{ color: #e2e8f0; font-size: 18px; font-weight: bold; margin-top: 5px; }}
.footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; color: #64748b; font-size: 12px; text-align: center; }}
</style></head><body>
<div class="container">
<h1>QuadSeer Threat Intelligence Report</h1>
<div class="meta">
    <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">{datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div></div>
    <div class="meta-item"><div class="meta-label">Scan Type</div><div class="meta-value">{scan.scan_type.replace("_", " ").title() if scan else "N/A"}</div></div>
    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{scan.target if scan else "N/A"}</div></div>
    <div class="meta-item"><div class="meta-label">Risk Score</div><div class="meta-value">{f"{scan.risk_score:.1f}/100" if scan else "N/A"}</div></div>
</div>
<h2>Findings ({len(findings)})</h2>
{findings_html if findings else "<p style='color: #94a3b8;'>No findings recorded.</p>"}
<div class="footer">
    <p>Generated by QuadSeer Threat Intelligence Platform</p>
    <p>Confidential - For authorized use only</p>
</div>
</div></body></html>"""

    async def _generate_csv(self, report_id, scan, findings, filename) -> str:
        """Generate CSV report."""
        filepath = os.path.join(self.REPORTS_DIR, f"{filename}.csv")

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Title", "Description", "Category", "CVE", "Port", "Service", "IP Address", "Country", "Remediation", "Created At"])
            for fnd in findings:
                writer.writerow([
                    fnd.severity,
                    fnd.title,
                    fnd.description or "",
                    fnd.category or "",
                    fnd.cve_id or "",
                    fnd.port or "",
                    fnd.service or "",
                    fnd.ip_address or "",
                    fnd.country or "",
                    fnd.remediation or "",
                    fnd.created_at.isoformat() if fnd.created_at else "",
                ])

        return filepath

    async def _generate_json(self, report_id, scan, findings, filename) -> str:
        """Generate JSON report."""
        filepath = os.path.join(self.REPORTS_DIR, f"{filename}.json")

        data = {
            "report_meta": {
                "generated_at": datetime.utcnow().isoformat(),
                "scan_type": scan.scan_type if scan else None,
                "target": scan.target if scan else None,
                "risk_score": scan.risk_score if scan else None,
            },
            "findings": [
                {
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "category": f.category,
                    "cve_id": f.cve_id,
                    "port": f.port,
                    "service": f.service,
                    "ip_address": f.ip_address,
                    "country": f.country,
                    "city": f.city,
                    "latitude": f.latitude,
                    "longitude": f.longitude,
                    "remediation": f.remediation,
                    "mitre_tactic": f.mitre_tactic,
                    "mitre_technique": f.mitre_technique,
                }
                for f in findings
            ]
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return filepath

    async def _generate_markdown(self, report_id, scan, findings, filename) -> str:
        """Generate Markdown report."""
        filepath = os.path.join(self.REPORTS_DIR, f"{filename}.md")

        md = f"""# QuadSeer Threat Intelligence Report

**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
**Scan Type:** {scan.scan_type.replace("_", " ").title() if scan else "N/A"}
**Target:** `{scan.target if scan else "N/A"}`
**Risk Score:** {f"{scan.risk_score:.1f}/100" if scan else "N/A"}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {sum(1 for f in findings if f.severity == 'critical')} |
| High | {sum(1 for f in findings if f.severity == 'high')} |
| Medium | {sum(1 for f in findings if f.severity == 'medium')} |
| Low | {sum(1 for f in findings if f.severity == 'low')} |
| Info | {sum(1 for f in findings if f.severity == 'info')} |

## Detailed Findings

"""
        for f in findings:
            md += f"### [{f.severity.upper()}] {f.title}\n\n"
            md += f"{f.description or 'No description available.'}\n\n"
            if f.remediation:
                md += f"**Remediation:** {f.remediation}\n\n"
            if f.cve_id:
                md += f"**CVE:** {f.cve_id}\n\n"
            if f.port:
                md += f"**Port:** {f.port} | **Service:** {f.service or 'Unknown'}\n\n"
            md += "---\n\n"

        md += "\n---\n*Generated by QuadSeer Threat Intelligence Platform*"

        with open(filepath, "w") as f:
            f.write(md)

        return filepath

# Singleton
report_service = ReportService()
