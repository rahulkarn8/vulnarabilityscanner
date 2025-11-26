"""
PDF Report Generator for Vulnerability Scan & Automotive Compliance
- Uses ReportLab (letter/A4 friendly layout)
- Preserves Stratum/Daifend logo aspect ratio
- Executive-grade compliance summary (ISO 21434 & UN R155)
- Charts are centered and placed on separate lines
"""

import io
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart


class PDFReportGenerator:
    """Generate PDF reports for vulnerability scan & compliance results."""

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    # ------------------------------------------------------------------ #
    # Styles
    # ------------------------------------------------------------------ #

    def _setup_custom_styles(self) -> None:
        """Setup custom paragraph styles."""

        # Main title
        self.styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=self.styles["Heading1"],
                fontSize=18,
                leading=22,
                textColor=colors.HexColor("#111827"),
                spaceAfter=18,
                alignment=TA_CENTER,
            )
        )

        # Section heading
        self.styles.add(
            ParagraphStyle(
                name="CustomHeading",
                parent=self.styles["Heading2"],
                fontSize=14,
                leading=18,
                textColor=colors.HexColor("#1D4ED8"),
                spaceBefore=14,
                spaceAfter=10,
            )
        )

        # Subheading / label
        self.styles.add(
            ParagraphStyle(
                name="Label",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=colors.HexColor("#374151"),
                spaceAfter=4,
            )
        )

        # Normal body
        self.styles.add(
            ParagraphStyle(
                name="Body",
                parent=self.styles["Normal"],
                fontSize=10,
                leading=13,
                textColor=colors.HexColor("#111827"),
                spaceAfter=6,
            )
        )

        # Code style
        self.styles.add(
            ParagraphStyle(
                name="CodeStyle",
                parent=self.styles["Code"],
                fontSize=8,
                fontName="Courier",
                textColor=colors.HexColor("#111827"),
                backColor=colors.HexColor("#F3F4F6"),
                leftIndent=8,
                rightIndent=8,
                spaceBefore=4,
                spaceAfter=8,
            )
        )

    # ------------------------------------------------------------------ #
    # Shared helpers
    # ------------------------------------------------------------------ #

    def _get_severity_color(self, severity: str) -> colors.Color:
        severity_colors = {
            "critical": colors.HexColor("#DC2626"),  # Red
            "high": colors.HexColor("#EA580C"),      # Orange
            "medium": colors.HexColor("#F59E0B"),    # Amber
            "low": colors.HexColor("#10B981"),       # Green
        }
        return severity_colors.get(severity.lower(), colors.HexColor("#6B7280"))

    def _create_compliance_gauge(
        self,
        score: int,
        width: float = 1.8 * inch,
        height: float = 1.2 * inch,
    ) -> Drawing:
        """Small circular gauge with score in the center (center-aligned)."""
        from reportlab.graphics.shapes import Circle

        drawing = Drawing(width, height)
        drawing.hAlign = "CENTER"

        cx = width / 2.0
        cy = height / 2.0
        radius = min(width, height) / 2.8

        # Color based on score
        if score >= 90:
            gauge_color = colors.HexColor("#10B981")
        elif score >= 70:
            gauge_color = colors.HexColor("#F59E0B")
        else:
            gauge_color = colors.HexColor("#DC2626")

        # Outer circle (background)
        bg = Circle(
            cx,
            cy,
            radius,
            fillColor=colors.HexColor("#E5E7EB"),
            strokeColor=colors.HexColor("#E5E7EB"),
            strokeWidth=1,
        )
        drawing.add(bg)

        # Inner circle (filled) radius scaled by score (minimum radius to keep visible)
        inner_radius = max(radius * 0.35, radius * (score / 100.0))
        fill = Circle(
            cx,
            cy,
            inner_radius,
            fillColor=gauge_color,
            strokeColor=gauge_color,
            strokeWidth=1,
        )
        drawing.add(fill)

        # Score text
        drawing.add(
            String(
                cx,
                cy - 4,
                f"{score}%",
                textAnchor="middle",
                fontSize=14,
                fontName="Helvetica-Bold",
                fillColor=colors.white,
            )
        )
        drawing.add(
            String(
                cx,
                cy + 10,
                "Compliance",
                textAnchor="middle",
                fontSize=7,
                fontName="Helvetica",
                fillColor=colors.HexColor("#F9FAFB"),
            )
        )

        return drawing

    def _create_pie_chart(
        self,
        data: Dict[str, int],
        title: str,
        width: float = 2.3 * inch,
        height: float = 1.9 * inch,
    ) -> Drawing:
        """Compact pie chart for severity distribution (center-aligned)."""
        drawing = Drawing(width, height)
        drawing.hAlign = "CENTER"

        non_zero_items = [(k, v) for k, v in data.items() if v > 0]
        if not non_zero_items:
            return drawing

        labels = [k.upper() for k, _ in non_zero_items]
        values = [v for _, v in non_zero_items]

        palette: List[colors.Color] = []
        for sev, _ in non_zero_items:
            palette.append(self._get_severity_color(sev))

        pie = Pie()
        pie.x = width / 2.0 - 0.8 * inch
        pie.y = height / 2.0 - 0.8 * inch
        pie.width = 1.6 * inch
        pie.height = 1.6 * inch

        pie.data = values
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = colors.white
        pie.simpleLabels = 1
        pie.sideLabels = 0

        for i, col in enumerate(palette):
            if i < len(pie.slices):
                pie.slices[i].fillColor = col

        drawing.add(pie)

        # Title (moved left by 2 lines)
        drawing.add(
            String(
                width / 2.0 - 0.2 * inch,  # Moved left by ~2 lines (0.2 inch)
                height - 12,
                title,
                textAnchor="middle",
                fontSize=9,
                fontName="Helvetica-Bold",
                fillColor=colors.HexColor("#111827"),
            )
        )

        return drawing

    def _create_area_bar_chart(
        self,
        data: Dict[str, int],
        title: str,
        width: float = 3.0 * inch,
        height: float = 1.8 * inch,
    ) -> Drawing:
        """
        Compact bar chart per requirement area (center-aligned).
        Only shows up to ~8 areas to avoid clutter, with small fonts.
        """
        drawing = Drawing(width, height)
        drawing.hAlign = "CENTER"

        non_zero_items = [(k, v) for k, v in data.items() if v > 0]
        if not non_zero_items:
            return drawing

        # Limit categories to first 8 for readability
        non_zero_items = non_zero_items[:8]

        labels = [k for k, _ in non_zero_items]
        values = [v for _, v in non_zero_items]

        bc = VerticalBarChart()
        bc.x = 28
        bc.y = 20
        bc.width = width - 40
        bc.height = height - 40

        bc.data = [values]
        bc.categoryAxis.categoryNames = labels

        # Subtle, narrow bars
        bc.barWidth = max(5, (bc.width / max(1, len(values))) * 0.5)
        bc.groupSpacing = 3
        bc.strokeColor = colors.HexColor("#E5E7EB")

        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = max(values) + 1
        bc.valueAxis.valueStep = max(1, int(max(values) / 4))

        bc.bars[0].fillColor = colors.HexColor("#3B82F6")

        # Fonts
        bc.categoryAxis.labels.fontName = "Helvetica"
        bc.categoryAxis.labels.fontSize = 6
        bc.categoryAxis.labels.angle = 35
        bc.categoryAxis.labels.dy = -10
        bc.categoryAxis.labels.dx = -0.2 * inch  # Move category labels left by 2 lines

        bc.valueAxis.labels.fontName = "Helvetica"
        bc.valueAxis.labels.fontSize = 6

        drawing.add(bc)

        # Title (moved left by 2 lines)
        drawing.add(
            String(
                width / 2.0 - 0.2 * inch,  # Moved left by ~2 lines (0.2 inch)
                height - 10,
                title,
                textAnchor="middle",
                fontSize=9,
                fontName="Helvetica-Bold",
                fillColor=colors.HexColor("#111827"),
            )
        )

        return drawing

    # ------------------------------------------------------------------ #
    # Header (Stratum/Daifend logo & layout)
    # ------------------------------------------------------------------ #

    def _draw_header(self, canvas_obj, doc) -> None:
        """Draw header with Stratum/Daifend logo (preserving aspect ratio) + tagline."""
        canvas_obj.saveState()

        # Logo search paths
        base_dir = os.path.dirname(__file__)
        logo_paths = [
            os.path.join(base_dir, "..", "frontend", "public", "assets", "daifend-logo.png"),
            os.path.join(base_dir, "..", "frontend", "src", "assets", "daifend-logo.png"),
            os.path.join(base_dir, "assets", "daifend-logo.png"),
        ]

        left_margin = doc.leftMargin
        top_y = doc.height + doc.topMargin

        # Draw logo with preserved aspect ratio
        logo_drawn = False
        for path in logo_paths:
            if os.path.exists(path):
                try:
                    img = ImageReader(path)
                    iw, ih = img.getSize()
                    target_h = 0.45 * inch  # Controlled height
                    scale = target_h / float(ih)
                    target_w = iw * scale

                    canvas_obj.drawImage(
                        img,
                        left_margin,
                        top_y - target_h - 8,
                        width=target_w,
                        height=target_h,
                        mask="auto",
                        preserveAspectRatio=True,
                        anchor="sw",
                    )
                    logo_drawn = True
                    break
                except Exception:
                    continue

        # If logo missing, print STRATUM text
        if not logo_drawn:
            canvas_obj.setFont("Helvetica-Bold", 16)
            canvas_obj.setFillColor(colors.HexColor("#2563EB"))
            canvas_obj.drawString(left_margin, top_y - 24, "STRATUM")

        # Tagline under logo
        canvas_obj.setFont("Helvetica", 9)
        canvas_obj.setFillColor(colors.HexColor("#6B7280"))
        canvas_obj.drawString(
            left_margin,
            top_y - 40,
            "STRATUM by Daifend · AI CYBERSECURITY · AUTOMOTIVE & AUTOSAR SECURITY",
        )

        # Page number right side
        page_num = canvas_obj.getPageNumber()
        canvas_obj.setFont("Helvetica", 9)
        canvas_obj.setFillColor(colors.HexColor("#9CA3AF"))
        canvas_obj.drawRightString(
            doc.leftMargin + doc.width,
            top_y - 24,
            f"Page {page_num}",
        )

        # Divider line slightly higher; content will start lower due to Spacer
        canvas_obj.setStrokeColor(colors.HexColor("#E5E7EB"))
        canvas_obj.setLineWidth(0.8)
        canvas_obj.line(
            left_margin,
            top_y - 48,
            doc.leftMargin + doc.width,
            top_y - 48,
        )

        canvas_obj.restoreState()

    # ------------------------------------------------------------------ #
    # Vulnerability report (non-compliance, core scan)
    # ------------------------------------------------------------------ #

    def generate_report(
        self,
        results: Dict[str, Any],
        output_path: Optional[str] = None,
        scan_type: str = "Code Scan",
        scan_target: str = "Unknown",
    ) -> bytes:
        """
        Generate generic vulnerability scan PDF (non-compliance specific).
        `results` is same dict you already use in the app.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=120,  # Increased from 70 to 120 to push content down on all pages
            bottomMargin=50,
        )

        story: List[Any] = []

        # Push content 5 lines below header line (additional spacing for first page)
        story.append(Spacer(1, 0.5 * inch))

        # Title
        story.append(
            Paragraph("Vulnerability Scan Report", self.styles["CustomTitle"])
        )
        story.append(Spacer(1, 0.2 * inch))

        # Count AI attack vulnerabilities
        ai_attack_count = 0
        total_vulns = 0
        for file_data in results.values():
            if isinstance(file_data, dict) and "vulnerabilities" in file_data:
                for v in file_data.get("vulnerabilities", []):
                    total_vulns += 1
                    if v.get("scanner") == "ai_attack":
                        ai_attack_count += 1
        
        # Metadata
        meta_data = [
            ["Scan Type:", scan_type],
            ["Scan Target:", scan_target],
            ["Scan Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Total Files Scanned:", str(len(results))],
            [
                "Total Vulnerabilities:",
                str(sum(r.get("total_vulnerabilities", 0) for r in results.values())),
            ],
        ]
        
        # Add AI attack count if there are any
        if ai_attack_count > 0:
            meta_data.append(
                [
                    "AI Attack Vulnerabilities:",
                    f"<font color='#8b5cf6'><b>{ai_attack_count}</b></font>",
                ]
            )
        meta_table = Table(meta_data, colWidths=[2 * inch, 4 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F9FAFB")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 0.25 * inch))

        # Severity summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for file_data in results.values():
            if isinstance(file_data, dict) and "vulnerabilities" in file_data:
                for v in file_data.get("vulnerabilities", []):
                    sev = (v.get("severity") or "medium").lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1

        story.append(
            Paragraph("Summary by Severity", self.styles["CustomHeading"])
        )

        summary_data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low"]:
            val = severity_counts[sev]
            if val > 0:
                col = self._get_severity_color(sev)
                sev_para = Paragraph(
                    f"<font color='{col.hexval()}'><b>{sev.upper()}</b></font>",
                    self.styles["Body"],
                )
                summary_data.append([sev_para, str(val)])

        if len(summary_data) > 1:
            summary_table = Table(summary_data, colWidths=[2 * inch, 1 * inch])
            summary_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4ED8")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                         [colors.white, colors.HexColor("#F9FAFB")]),
                    ]
                )
            )
            story.append(summary_table)
            story.append(Spacer(1, 0.4 * inch))  # Increased from 0.2 to 0.4 (2 lines more)
            
            # Add severity pie chart (25% bigger)
            try:
                severity_pie = self._create_pie_chart(
                    severity_counts,
                    "Vulnerabilities by Severity",
                    width=2.875 * inch,  # 25% bigger: 2.3 * 1.25
                    height=2.375 * inch  # 25% bigger: 1.9 * 1.25
                )
                story.append(severity_pie)
                story.append(Spacer(1, 0.3 * inch))
            except Exception as e:
                print(f"Warning: Could not create severity pie chart: {e}")
        
        # Vulnerabilities by file chart
        file_vuln_counts = {}
        for file_path, file_data in results.items():
            if isinstance(file_data, dict) and "vulnerabilities" in file_data:
                vuln_count = len(file_data.get("vulnerabilities", []))
                if vuln_count > 0:
                    # Truncate long file paths for display
                    display_name = file_path
                    if len(display_name) > 30:
                        display_name = "..." + display_name[-27:]
                    file_vuln_counts[display_name] = vuln_count
        
        if file_vuln_counts and len(file_vuln_counts) > 1:
            story.append(
                Paragraph("Vulnerabilities by File", self.styles["CustomHeading"])
            )
            try:
                # Limit to top 10 files for readability
                sorted_files = sorted(file_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                top_files_dict = dict(sorted_files)
                
                file_bar_chart = self._create_area_bar_chart(
                    top_files_dict,
                    "Top Files by Vulnerability Count",
                    width=3.75 * inch,  # 25% bigger: 3.0 * 1.25
                    height=2.25 * inch  # 25% bigger: 1.8 * 1.25
                )
                story.append(Spacer(1, 0.4 * inch))  # Increased from 0.2 to 0.4 (2 lines more)
                story.append(file_bar_chart)
                story.append(Spacer(1, 0.3 * inch))
            except Exception as e:
                print(f"Warning: Could not create file bar chart: {e}")
        
        # Vulnerability type breakdown
        vuln_type_counts = {}
        for file_data in results.values():
            if isinstance(file_data, dict) and "vulnerabilities" in file_data:
                for v in file_data.get("vulnerabilities", []):
                    vuln_type = v.get("vulnerability_type") or v.get("type") or "Unknown"
                    vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
        
        if vuln_type_counts:
            story.append(
                Paragraph("Vulnerability Types Breakdown", self.styles["CustomHeading"])
            )
            # Show top vulnerability types
            sorted_types = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            top_types_dict = dict(sorted_types)
            
            try:
                type_bar_chart = self._create_area_bar_chart(
                    top_types_dict,
                    "Most Common Vulnerability Types",
                    width=3.75 * inch,  # 25% bigger: 3.0 * 1.25
                    height=2.25 * inch  # 25% bigger: 1.8 * 1.25
                )
                story.append(Spacer(1, 0.4 * inch))  # Increased from 0.2 to 0.4 (2 lines more)
                story.append(type_bar_chart)
                story.append(Spacer(1, 0.3 * inch))
            except Exception as e:
                print(f"Warning: Could not create vulnerability type chart: {e}")

        # AI Attack Vulnerabilities Summary (if any)
        if ai_attack_count > 0:
            story.append(Spacer(1, 0.3 * inch))
            story.append(
                Paragraph(
                    f"<font color='#8b5cf6'><b>AI Attack Vulnerabilities: {ai_attack_count} Found</b></font>",
                    self.styles["CustomHeading"]
                )
            )
            story.append(
                Paragraph(
                    "The following vulnerabilities make your code susceptible to AI-powered attacks "
                    "including prompt injection, model security issues, adversarial attacks, data poisoning, "
                    "and AI code generation security risks.",
                    self.styles["Body"],
                )
            )
            story.append(Spacer(1, 0.2 * inch))
        
        # Detailed findings (moved 5 lines down from current position)
        story.append(Spacer(1, 0.7 * inch))  # Increased to 0.7 inch (approximately 5 lines more)
        story.append(Paragraph("Detailed Findings", self.styles["CustomHeading"]))

        first_file = True
        for file_path, file_data in results.items():
            if not isinstance(file_data, dict):
                continue
            if file_data.get("error"):
                continue

            vulns = file_data.get("vulnerabilities", [])
            if not vulns:
                continue

            if not first_file:
                story.append(PageBreak())
                story.append(Spacer(1, 0.5 * inch))  # Add spacing after page break
            first_file = False

            story.append(
                Paragraph(f"File: {file_path}", self.styles["CustomHeading"])
            )
            story.append(
                Paragraph(
                    f"Language: {file_data.get('language', 'Unknown')}",
                    self.styles["Body"],
                )
            )
            story.append(
                Paragraph(
                    f"Total Vulnerabilities: {file_data.get('total_vulnerabilities', len(vulns))}",
                    self.styles["Body"],
                )
            )
            story.append(Spacer(1, 0.15 * inch))

            for idx, vuln in enumerate(vulns, 1):
                sev = (vuln.get("severity") or "medium").lower()
                col = self._get_severity_color(sev)
                scanner = vuln.get("scanner") or ""
                is_ai_attack = scanner == "ai_attack"

                title = vuln.get("vulnerability_type") or vuln.get("type") or "Vulnerability"
                
                # For AI attacks, add a visual indicator in the title
                if is_ai_attack:
                    story.append(
                        Paragraph(
                            f"{idx}. <font color='#8b5cf6'><b>{title}</b></font> "
                            f"<font color='#6366f1'>(AI Attack)</font>",
                            self.styles["Body"],
                        )
                    )
                else:
                    story.append(
                        Paragraph(f"{idx}. {title}", self.styles["Body"])
                    )

                story.append(
                    Paragraph(
                        f"<b>Severity:</b> "
                        f"<font color='{col.hexval()}'>{sev.upper()}</font>",
                        self.styles["Body"],
                    )
                )

                line_no = vuln.get("line_number", 0)
                story.append(
                    Paragraph(f"<b>Line:</b> {line_no}", self.styles["Body"])
                )

                # For AI attacks, show category and attack type
                if is_ai_attack:
                    category = vuln.get("category") or ""
                    if category:
                        # Format category name nicely (e.g., "prompt_injection" -> "Prompt Injection")
                        category_display = category.replace("_", " ").title()
                        story.append(
                            Paragraph(
                                f"<b>Attack Category:</b> <font color='#8b5cf6'>{category_display}</font>",
                                self.styles["Body"],
                            )
                        )
                    
                    rule_id = vuln.get("rule_id") or ""
                    cwe_id = vuln.get("cwe_id") or ""
                    if rule_id or cwe_id:
                        ref_parts = []
                        if rule_id:
                            ref_parts.append(f"<b>Rule ID:</b> <font color='#6366f1'>{rule_id}</font>")
                        if cwe_id:
                            ref_parts.append(f"<b>CWE:</b> <font color='#6366f1'>{cwe_id}</font>")
                        if ref_parts:
                            story.append(
                                Paragraph(" | ".join(ref_parts), self.styles["Body"])
                            )

                desc = vuln.get("description") or "No description available."
                story.append(
                    Paragraph(f"<b>Description:</b> {desc}", self.styles["Body"])
                )

                # For AI attacks, show the matched pattern
                if is_ai_attack:
                    match_pattern = vuln.get("match") or ""
                    if match_pattern:
                        # Truncate very long matches
                        display_match = match_pattern
                        if len(display_match) > 100:
                            display_match = display_match[:97] + "..."
                        esc_match = (
                            display_match.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                        )
                        story.append(
                            Paragraph("<b>Matched Pattern:</b>", self.styles["Body"])
                        )
                        story.append(
                            Paragraph(
                                f"<font face='Courier' color='#8b5cf6'>{esc_match}</font>",
                                self.styles["CodeStyle"],
                            )
                        )

                snippet = vuln.get("code_snippet") or ""
                if snippet:
                    esc = (
                        snippet.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                    )
                    story.append(
                        Paragraph("<b>Code Snippet:</b>", self.styles["Body"])
                    )
                    story.append(
                        Paragraph(
                            f"<font face='Courier'>{esc}</font>",
                            self.styles["CodeStyle"],
                        )
                    )

                fix = vuln.get("suggested_fix") or ""
                if fix:
                    esc_fix = (
                        fix.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                    )
                    story.append(
                        Paragraph("<b>Suggested Fix:</b>", self.styles["Body"])
                    )
                    # Format suggested fix with better styling for AI attacks
                    if is_ai_attack:
                        story.append(
                            Paragraph(
                                f"<font color='#10b981'>{esc_fix}</font>",
                                self.styles["Body"],
                            )
                        )
                    else:
                        story.append(Paragraph(esc_fix, self.styles["Body"]))

                if scanner:
                    # Highlight AI attack scanner findings
                    if is_ai_attack:
                        scanner_version = vuln.get("scanner_version") or ""
                        version_text = f" v{scanner_version}" if scanner_version else ""
                        story.append(
                            Paragraph(
                                f"<b>Detected by:</b> <font color='#8b5cf6'><b>{scanner.upper()}</b></font>"
                                f"{version_text} <font color='#6366f1'>(AI Attack Vulnerability)</font>",
                                self.styles["Body"],
                            )
                        )
                    else:
                        story.append(
                            Paragraph(
                                f"<b>Detected by:</b> {scanner}",
                                self.styles["Body"],
                            )
                        )

                story.append(Spacer(1, 0.18 * inch))

        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph(
                f"<i>Report generated by Stratum (Daifend) "
                f"on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
                self.styles["Body"],
            )
        )

        doc.build(story, onFirstPage=self._draw_header, onLaterPages=self._draw_header)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)

        return pdf_bytes

    # ------------------------------------------------------------------ #
    # Automotive Compliance report (ISO 21434 & UN R155)
    # ------------------------------------------------------------------ #

    def generate_compliance_report(
        self,
        compliance_data: Dict[str, Any],
        output_path: Optional[str] = None,
        scan_type: str = "Automotive Compliance Scan",
        scan_target: str = "Unknown",
    ) -> bytes:
        """
        Generate an executive-grade compliance PDF for OEM-style audit reviews.
        Expects the dict produced by ComplianceReportGenerator.generate_compliance_report().
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=120,  # Increased from 70 to 120 to push content down on ALL pages
            bottomMargin=50,
        )

        story: List[Any] = []

        # Additional spacing for first page (topMargin handles spacing on all pages)
        story.append(Spacer(1, 0.5 * inch))

        summary = compliance_data.get("summary", {}) or {}
        iso = compliance_data.get("iso21434", {}) or {}
        r155 = compliance_data.get("unr155", {}) or {}

        # ---------- Cover / Executive Summary ----------
        story.append(
            Paragraph(
                "Automotive Cybersecurity Compliance Report",
                self.styles["CustomTitle"],
            )
        )
        story.append(Spacer(1, 0.1 * inch))

        overall_status = summary.get("overall_compliance", "UNKNOWN")
        overall_score = summary.get("overall_score", 0.0)

        # Color for overall status
        if "COMPLIANT" in overall_status and "NON" not in overall_status:
            overall_color = colors.HexColor("#10B981")
        elif "PARTIALLY" in overall_status:
            overall_color = colors.HexColor("#F59E0B")
        else:
            overall_color = colors.HexColor("#DC2626")

        # Metadata table
        meta_data = [
            ["Scan Type:", scan_type],
            ["Scan Target:", scan_target],
            ["Scan Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Total Files Analyzed:", str(summary.get("total_files_analyzed", 0))],
            ["Total Vulnerabilities:", str(summary.get("total_vulnerabilities", 0))],
            ["Automotive Vulnerabilities:", str(summary.get("automotive_vulnerabilities", 0))],
            [
                "Overall Compliance Status:",
                Paragraph(
                    f"<font color='{overall_color.hexval()}'><b>{overall_status}</b></font>",
                    self.styles["Body"],
                ),
            ],
            ["Overall Compliance Score:", f"{overall_score:.2f}%"],
        ]

        meta_table = Table(meta_data, colWidths=[2.6 * inch, 3.4 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F9FAFB")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 0.25 * inch))

        # Executive summary bullets (OEM-friendly)
        story.append(
            Paragraph("Executive Summary", self.styles["CustomHeading"])
        )

        exec_points: List[str] = []

        exec_points.append(
            f"• Overall compliance is <b>{overall_status}</b> with an aggregate score of "
            f"<b>{overall_score:.2f}%</b> across ISO 21434 and UN R155."
        )

        exec_points.append(
            f"• ISO 21434 score: <b>{iso.get('compliance_score', 0)}%</b> "
            f"({iso.get('compliance_status', 'UNKNOWN')}), "
            f"violations: <b>{iso.get('total_violations', 0)}</b>."
        )

        exec_points.append(
            f"• UN R155 score: <b>{r155.get('compliance_score', 0)}%</b> "
            f"({r155.get('compliance_status', 'UNKNOWN')}), "
            f"violations: <b>{r155.get('total_violations', 0)}</b>."
        )

        if iso.get("total_violations", 0) > 0:
            exec_points.append(
                "• ISO 21434 key gaps are concentrated in the most frequently violated requirement areas."
            )
        if r155.get("total_violations", 0) > 0:
            exec_points.append(
                "• UN R155 gaps indicate needed improvements in CSMS, SUMS, and secure V2X/boot implementations."
            )

        if not (iso.get("total_violations", 0) or r155.get("total_violations", 0)):
            exec_points.append(
                "• No significant standard-specific violations were detected; maintain current controls."
            )

        for p in exec_points:
            story.append(Paragraph(p, self.styles["Body"]))

        story.append(Spacer(1, 0.3 * inch))

        # ---------- ISO 21434 Detailed Section ----------
        story.append(PageBreak())
        story.append(Spacer(1, 0.5 * inch))  # Add spacing after page break
        story.append(
            Paragraph("ISO 21434:2021 Compliance", self.styles["CustomHeading"])
        )

        iso_score = iso.get("compliance_score", 0)
        iso_status = iso.get("compliance_status", "UNKNOWN")
        if iso_score >= 90:
            iso_color = colors.HexColor("#10B981")
        elif iso_score >= 70:
            iso_color = colors.HexColor("#F59E0B")
        else:
            iso_color = colors.HexColor("#DC2626")

        iso_status_para = Paragraph(
            f"<font color='{iso_color.hexval()}'><b>{iso_status}</b></font>",
            self.styles["Body"],
        )

        iso_status_data = [
            ["Standard:", iso.get("standard", "ISO 21434:2021")],
            ["Compliance Score:", f"{iso_score}%"],
            ["Compliance Status:", iso_status_para],
            ["Total Violations:", str(iso.get("total_violations", 0))],
        ]

        iso_status_table = Table(iso_status_data, colWidths=[2.2 * inch, 3.0 * inch])
        iso_status_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F9FAFB")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(iso_status_table)

        # Gauge on the next line, centered (moved 2 lines lower)
        gauge_iso = self._create_compliance_gauge(int(iso_score))
        story.append(Spacer(1, 0.3 * inch))  # Increased from 0.1 to 0.3 (2 lines more)
        story.append(gauge_iso)
        story.append(Spacer(1, 0.2 * inch))

        # Violations by requirement area (table + chart on next line)
        iso_by_area = iso.get("violations_by_area", {}) or {}
        if iso_by_area:
            story.append(
                Paragraph(
                    "ISO 21434 Violations by Requirement Area",
                    self.styles["Label"],
                )
            )

            area_rows = [["Security Area", "Violations"]]
            for area, count in iso_by_area.items():
                if count > 0:
                    area_rows.append([area, str(count)])

            if len(area_rows) > 1:
                iso_area_table = Table(area_rows, colWidths=[3.0 * inch, 0.8 * inch])
                iso_area_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4ED8")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                             [colors.white, colors.HexColor("#F9FAFB")]),
                        ]
                    )
                )
                story.append(iso_area_table)

                iso_area_chart = self._create_area_bar_chart(
                    iso_by_area,
                    "ISO 21434 – Violations by Area",
                )
                story.append(Spacer(1, 0.3 * inch))  # Increased from 0.1 to 0.3 (2 lines more)
                story.append(iso_area_chart)
                story.append(Spacer(1, 0.25 * inch))

        # Severity distribution (table + chart on next line)
        iso_by_sev = iso.get("violations_by_severity", {}) or {}
        if iso_by_sev and sum(iso_by_sev.values()) > 0:
            story.append(
                Paragraph(
                    "ISO 21434 Violations by Severity",
                    self.styles["Label"],
                )
            )

            sev_rows = [["Severity", "Count"]]
            for sev in ["critical", "high", "medium", "low"]:
                val = iso_by_sev.get(sev, 0)
                if val > 0:
                    col = self._get_severity_color(sev)
                    sev_para = Paragraph(
                        f"<font color='{col.hexval()}'><b>{sev.upper()}</b></font>",
                        self.styles["Body"],
                    )
                    sev_rows.append([sev_para, str(val)])

            if len(sev_rows) > 1:
                sev_table = Table(sev_rows, colWidths=[1.8 * inch, 0.8 * inch])
                sev_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4ED8")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                             [colors.white, colors.HexColor("#F9FAFB")]),
                        ]
                    )
                )
                story.append(sev_table)

                iso_pie = self._create_pie_chart(
                    iso_by_sev,
                    "ISO 21434 – Severity Mix",
                )
                story.append(Spacer(1, 0.3 * inch))  # Increased from 0.1 to 0.3 (2 lines more)
                story.append(iso_pie)

        # ---------- UN R155 Detailed Section ----------
        story.append(PageBreak())
        story.append(Spacer(1, 0.5 * inch))  # Add spacing after page break
        story.append(Paragraph("UN R155 Compliance", self.styles["CustomHeading"]))

        r155_score = r155.get("compliance_score", 0)
        r155_status = r155.get("compliance_status", "UNKNOWN")

        if r155_score >= 90:
            r155_color = colors.HexColor("#10B981")
        elif r155_score >= 70:
            r155_color = colors.HexColor("#F59E0B")
        else:
            r155_color = colors.HexColor("#DC2626")

        r155_status_para = Paragraph(
            f"<font color='{r155_color.hexval()}'><b>{r155_status}</b></font>",
            self.styles["Body"],
        )

        r155_status_data = [
            ["Standard:", r155.get("standard", "UN Regulation No. 155")],
            ["Compliance Score:", f"{r155_score}%"],
            ["Compliance Status:", r155_status_para],
            ["Total Violations:", str(r155.get("total_violations", 0))],
        ]

        r155_status_table = Table(r155_status_data, colWidths=[2.2 * inch, 3.0 * inch])
        r155_status_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F9FAFB")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(r155_status_table)

        r155_gauge = self._create_compliance_gauge(int(r155_score))
        story.append(Spacer(1, 0.3 * inch))  # Increased from 0.1 to 0.3 (2 lines more)
        story.append(r155_gauge)
        story.append(Spacer(1, 0.2 * inch))

        # Violations by requirement area
        r155_by_area = r155.get("violations_by_area", {}) or {}
        if r155_by_area:
            story.append(
                Paragraph(
                    "UN R155 Violations by Requirement Area",
                    self.styles["Label"],
                )
            )

            r155_area_rows = [["Requirement Area", "Violations"]]
            for area, count in r155_by_area.items():
                if count > 0:
                    r155_area_rows.append([area, str(count)])

            if len(r155_area_rows) > 1:
                r155_area_table = Table(
                    r155_area_rows,
                    colWidths=[3.0 * inch, 0.8 * inch],
                )
                r155_area_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4ED8")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                             [colors.white, colors.HexColor("#F9FAFB")]),
                        ]
                    )
                )
                story.append(r155_area_table)

                r155_area_chart = self._create_area_bar_chart(
                    r155_by_area,
                    "UN R155 – Violations by Area",
                )
                story.append(Spacer(1, 0.3 * inch))  # Increased from 0.1 to 0.3 (2 lines more)
                story.append(r155_area_chart)
                story.append(Spacer(1, 0.25 * inch))

        # Severity distribution
        r155_by_sev = r155.get("violations_by_severity", {}) or {}
        if r155_by_sev and sum(r155_by_sev.values()) > 0:
            story.append(
                Paragraph(
                    "UN R155 Violations by Severity",
                    self.styles["Label"],
                )
            )

            r155_sev_rows = [["Severity", "Count"]]
            for sev in ["critical", "high", "medium", "low"]:
                val = r155_by_sev.get(sev, 0)
                if val > 0:
                    col = self._get_severity_color(sev)
                    sev_para = Paragraph(
                        f"<font color='{col.hexval()}'><b>{sev.upper()}</b></font>",
                        self.styles["Body"],
                    )
                    r155_sev_rows.append([sev_para, str(val)])

            if len(r155_sev_rows) > 1:
                r155_sev_table = Table(
                    r155_sev_rows,
                    colWidths=[1.8 * inch, 0.8 * inch],
                )
                r155_sev_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4ED8")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                             [colors.white, colors.HexColor("#F9FAFB")]),
                        ]
                    )
                )
                story.append(r155_sev_table)

                r155_pie = self._create_pie_chart(
                    r155_by_sev,
                    "UN R155 – Severity Mix",
                )
                story.append(Spacer(1, 0.3 * inch))  # Increased from 0.1 to 0.3 (2 lines more)
                story.append(r155_pie)

        # ---------- Recommendations ----------
        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph("Remediation Recommendations", self.styles["CustomHeading"])
        )

        reco_list: List[str] = []

        if iso_score < 90:
            reco_list.append(
                "• Prioritize remediation of ISO 21434 high and critical findings, "
                "focusing first on secure communication, storage, and update paths."
            )
        if r155_score < 90:
            reco_list.append(
                "• Align CSMS and SUMS implementations with UN R155 requirements, "
                "ensuring secure boot, vulnerability management, and incident handling are formalized."
            )
        if iso.get("total_violations", 0) > 0 or r155.get("total_violations", 0) > 0:
            reco_list.append(
                "• Establish a recurring automotive cybersecurity assessment cadence to ensure "
                "continuous compliance during development and post-production."
            )
        if not reco_list:
            reco_list.append(
                "• Maintain current security controls and schedule periodic independent assessments "
                "to preserve compliance posture."
            )

        for r in reco_list:
            story.append(Paragraph(r, self.styles["Body"]))

        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph(
                f"<i>Compliance report generated by Stratum (Daifend) "
                f"on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
                self.styles["Body"],
            )
        )

        doc.build(story, onFirstPage=self._draw_header, onLaterPages=self._draw_header)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)

        return pdf_bytes
