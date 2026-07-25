"""
Report Service - PDF report generation for scan results
Fixed: Line 204 f-string syntax error - changed inner double quotes to escaped or single quotes
"""
from datetime import datetime
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io

from app.models.scan import Scan, ScanResult
from app.models.target import Target
from app.models.user import User


class ReportService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.styles = getSampleStyleSheet()
        # Custom styles
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            fontSize=24,
            leading=30,
            alignment=TA_CENTER,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a2e')
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            fontSize=16,
            leading=20,
            alignment=TA_LEFT,
            spaceAfter=12,
            textColor=colors.HexColor('#16213e')
        ))
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            fontSize=10,
            leading=14,
            alignment=TA_LEFT,
            spaceAfter=8
        ))

    async def generate_scan_report(self, scan_id: int, user_id: int) -> bytes:
        """Generate a PDF report for a specific scan."""
        # Fetch scan with related data
        result = await self.db.execute(
            select(Scan)
            .where(Scan.id == scan_id)
            .where(Scan.user_id == user_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise ValueError("Scan not found")

        # Fetch scan results
        result = await self.db.execute(
            select(ScanResult)
            .where(ScanResult.scan_id == scan_id)
            .order_by(ScanResult.severity.desc())
        )
        scan_results = result.scalars().all()

        # Fetch target
        result = await self.db.execute(
            select(Target).where(Target.id == scan.target_id)
        )
        target = result.scalar_one_or_none()

        # Generate PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        story = []

        # Title
        story.append(Paragraph(
            f"External Attack Surface Report",
            self.styles['CustomTitle']
        ))
        story.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            self.styles['CustomBody']
        ))
        story.append(Spacer(1, 0.3 * inch))

        # Target Information
        story.append(Paragraph("Target Information", self.styles['CustomHeading']))
        target_data = [
            ["Domain", target.domain if target else "N/A"],
            ["Scan Type", scan.scan_type],
            ["Status", scan.status],
            ["Started", scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else "N/A"],
            ["Completed", scan.completed_at.strftime('%Y-%m-%d %H:%M') if scan.completed_at else "N/A"],
        ]
        target_table = Table(target_data, colWidths=[2 * inch, 4 * inch])
        target_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
        ]))
        story.append(target_table)
        story.append(Spacer(1, 0.3 * inch))

        # Summary Statistics
        story.append(Paragraph("Findings Summary", self.styles['CustomHeading']))
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for sr in scan_results:
            if sr.severity in severity_counts:
                severity_counts[sr.severity] += 1

        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(severity_counts["critical"])],
            ["High", str(severity_counts["high"])],
            ["Medium", str(severity_counts["medium"])],
            ["Low", str(severity_counts["low"])],
            ["Info", str(severity_counts["info"])],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # Detailed Findings
        if scan_results:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", self.styles['CustomHeading']))
            story.append(Spacer(1, 0.2 * inch))

            for idx, sr in enumerate(scan_results, 1):
                # FIXED: Line 204 - used single quotes inside f-string to avoid SyntaxError
                # Original broken: f'<meta charset="utf-8">...'
                # Fixed: f'<meta charset=\"utf-8\">...'  OR use single quotes for the f-string
                finding_title = f"Finding #{idx}: {sr.finding_type} ({sr.severity.upper()})"
                story.append(Paragraph(finding_title, self.styles['CustomHeading']))

                # Use single-quoted f-string for HTML content to avoid quote conflicts
                detail_html = f'<meta charset="utf-8"><p><b>Asset:</b> {sr.asset or "N/A"}</p>'
                detail_html += f'<p><b>Details:</b> {sr.details or "N/A"}</p>'
                if sr.raw_data:
                    detail_html += f'<p><b>Raw Data:</b> {str(sr.raw_data)[:500]}</p>'

                story.append(Paragraph(detail_html, self.styles['CustomBody']))
                story.append(Spacer(1, 0.15 * inch))

        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    async def get_report_metadata(self, scan_id: int, user_id: int) -> dict:
        """Get metadata for a report without generating the full PDF."""
        result = await self.db.execute(
            select(Scan)
            .where(Scan.id == scan_id)
            .where(Scan.user_id == user_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise ValueError("Scan not found")

        result = await self.db.execute(
            select(ScanResult)
            .where(ScanResult.scan_id == scan_id)
        )
        scan_results = result.scalars().all()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for sr in scan_results:
            if sr.severity in severity_counts:
                severity_counts[sr.severity] += 1

        return {
            "scan_id": scan_id,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "total_findings": len(scan_results),
            "severity_breakdown": severity_counts,
            "generated_at": datetime.utcnow().isoformat()
        }
