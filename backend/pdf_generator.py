from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch
from io import BytesIO
import logging
from report_parsers import get_parser

logger = logging.getLogger(__name__)

def generate_pdf_report(scan_data, summary, target):
    """
    Generate a comprehensive PDF report from scan data with structured tables.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=20,
    )
    
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#3b82f6'),
        spaceAfter=10,
        spaceBefore=15,
    )
    
    subsection_style = ParagraphStyle(
        'SubsectionTitle',
        parent=styles['Heading3'],
        fontSize=13,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=8,
        spaceBefore=10,
    )
    
    # Title and Target
    story.append(Paragraph("LiteRecon_AI Scan Report", title_style))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    # Get tool results
    tool_results = scan_data.get('tool_results', [])
    
    if not tool_results:
        story.append(Paragraph("No scan results available.", styles['Normal']))
    else:
        # Process each tool's results
        for tool_result in tool_results:
            tool_name = tool_result.get('tool', 'Unknown')
            
            # Get parser for this tool
            parser = get_parser(tool_result)
            
            if not parser:
                # Skip tools without parsers
                continue
            
            # Parse the tool result
            parsed_data = parser.parse()
            tables = parsed_data.get('tables', [])
            
            if not tables:
                continue
            
            # Add tool section header
            tool_display_name = _format_tool_name(tool_name)
            story.append(Paragraph(tool_display_name, section_style))
            story.append(Spacer(1, 0.1*inch))
            
            # Add each table for this tool
            for table_data in tables:
                table_name = table_data.get('name', 'Results')
                columns = table_data.get('columns', [])
                rows = table_data.get('rows', [])
                
                # Add table title
                story.append(Paragraph(table_name, subsection_style))
                
                # Create table
                if rows:
                    # Prepare table data with headers
                    table_content = [columns] + rows
                    
                    # Calculate column widths dynamically
                    num_cols = len(columns)
                    available_width = 7.5 * inch  # Letter width minus margins
                    col_width = available_width / num_cols
                    col_widths = [col_width] * num_cols
                    
                    # Create and style table
                    t = Table(table_content, colWidths=col_widths, repeatRows=1)
                    t.setStyle(TableStyle([
                        # Header styling
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                        ('TOPPADDING', (0, 0), (-1, 0), 10),
                        # Body styling
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('TOPPADDING', (0, 1), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        # Grid
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                        # Alternating row colors
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.HexColor('#ffffff')]),
                    ]))
                    
                    story.append(t)
                else:
                    story.append(Paragraph("No data available", styles['Normal']))
                
                story.append(Spacer(1, 0.15*inch))
            
            # Add space between tool sections
            story.append(Spacer(1, 0.2*inch))
    
    # AI Analysis Summary (moved to the end)
    story.append(PageBreak())
    story.append(Paragraph("AI Analysis Summary", section_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Clean up markdown formatting for PDF
    if summary:
        summary_clean = summary.replace('**', '').replace('##', '').replace('#', '')
        for line in summary_clean.split('\n'):
            if line.strip():
                story.append(Paragraph(line.strip(), styles['BodyText']))
                story.append(Spacer(1, 0.05*inch))
    else:
        story.append(Paragraph("No AI summary available.", styles['Normal']))
    
    # Build PDF
    try:
        doc.build(story)
        buffer.seek(0)
        return buffer
    except Exception as e:
        logger.error(f"Error building PDF: {e}")
        raise


def _format_tool_name(tool_name: str) -> str:
    """Format tool name for display"""
    name_map = {
        "nmap_tcp": "Nmap TCP Scan",
        "nmap_udp": "Nmap UDP Scan",
        "whatweb": "WhatWeb - Web Technology Detection",
        "feroxbuster": "Feroxbuster - Directory Enumeration (HTTP)",
        "feroxbuster_https": "Feroxbuster - Directory Enumeration (HTTPS)",
        "enum4linux-ng": "Enum4linux-ng - SMB Enumeration",
        "enum4linux_classic": "Enum4linux Classic - SMB Enumeration",
        "sslyze": "SSLyze - SSL/TLS Analysis",
        "nbtscan": "Nbtscan - NetBIOS Scanning",
        "onesixtyone": "Onesixtyone - SNMP Community Scanner",
        "snmpwalk": "Snmpwalk - SNMP MIB Walker",
        "snmpwalk_v1": "Snmpwalk v1 - SNMP MIB Walker",
        "dnsrecon": "DNSRecon - DNS Enumeration",
        "autorecon": "AutoRecon - Automated Enumeration"
    }
    
    return name_map.get(tool_name, tool_name.replace('_', ' ').title())
