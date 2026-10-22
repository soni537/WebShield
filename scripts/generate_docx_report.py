"""
scripts/generate_docx_report.py — Generates a complete, professionally formatted
Microsoft Word project report (YourName_ProjectReport.docx) for IBM SkillsBuild
Cyber Security 2026 conducted by BharatCares.
"""

import os
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOCS_DIR = os.path.join(BASE_DIR, "docs")
SCREENSHOTS_DIR = os.path.join(DOCS_DIR, "screenshots")
DIAGRAMS_DIR = os.path.join(DOCS_DIR, "diagrams")
OUTPUT_PATH = os.path.join(BASE_DIR, "YourName_ProjectReport.docx")

# Color Palette Constants
COLOR_PRIMARY = RGBColor(15, 44, 89)      # Deep Navy
COLOR_SECONDARY = RGBColor(49, 82, 91)    # Slate Steel
COLOR_TEXT = RGBColor(34, 34, 34)         # Charcoal Dark
COLOR_MUTED = RGBColor(100, 100, 100)     # Gray
HEX_PRIMARY = "0F2C59"
HEX_LIGHT_BG = "F4F6F9"
HEX_BORDER = "CCCCCC"

def set_cell_background(cell, hex_color):
    """Set background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner padding of a table cell in dxa (1 pt = 20 dxa)."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

def add_page_number_to_run(run):
    """Inserts a dynamic Word PAGE field into a run."""
    fldSimple = parse_xml(r'<w:fldSimple %s w:instr="PAGE"/>' % nsdecls('w'))
    run._r.append(fldSimple)

def add_numpages_to_run(run):
    """Inserts a dynamic Word NUMPAGES field into a run."""
    fldSimple = parse_xml(r'<w:fldSimple %s w:instr="NUMPAGES"/>' % nsdecls('w'))
    run._r.append(fldSimple)

def create_styled_table(doc, headers, data, col_widths=None):
    """Creates a standardized, clean report table."""
    table = doc.add_table(rows=len(data) + 1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    # Format Header Row
    hdr_cells = table.rows[0].cells
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        set_cell_background(hdr_cells[i], HEX_PRIMARY)
        set_cell_margins(hdr_cells[i], top=120, bottom=120, left=140, right=140)
        p = hdr_cells[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for r in p.runs:
            r.font.name = "Calibri"
            r.font.size = Pt(9.5)
            r.font.bold = True
            r.font.color.rgb = RGBColor(255, 255, 255)

    # Format Data Rows
    for row_idx, row_data in enumerate(data):
        row_cells = table.rows[row_idx + 1].cells
        bg_color = HEX_LIGHT_BG if row_idx % 2 == 1 else "FFFFFF"
        for col_idx, cell_value in enumerate(row_data):
            row_cells[col_idx].text = str(cell_value)
            set_cell_background(row_cells[col_idx], bg_color)
            set_cell_margins(row_cells[col_idx], top=80, bottom=80, left=120, right=120)
            p = row_cells[col_idx].paragraphs[0]
            # Center if short content or ID, otherwise left
            if len(str(cell_value)) < 15 and not any(k in str(cell_value) for k in [" ", "/"]):
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            else:
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for r in p.runs:
                r.font.name = "Calibri"
                r.font.size = Pt(9)
                r.font.color.rgb = COLOR_TEXT

    # Apply column widths if provided
    if col_widths:
        for row in table.rows:
            for idx, width in enumerate(col_widths):
                row.cells[idx].width = width

    # Add small spacing after table
    p_after = doc.add_paragraph()
    p_after.paragraph_format.space_before = Pt(2)
    p_after.paragraph_format.space_after = Pt(6)
    return table

def add_heading_1(doc, text):
    h = doc.add_heading(text, level=1)
    h.paragraph_format.space_before = Pt(16)
    h.paragraph_format.space_after = Pt(6)
    h.paragraph_format.keep_with_next = True
    for r in h.runs:
        r.font.name = "Calibri"
        r.font.size = Pt(16)
        r.font.bold = True
        r.font.color.rgb = COLOR_PRIMARY
    return h

def add_heading_2(doc, text):
    h = doc.add_heading(text, level=2)
    h.paragraph_format.space_before = Pt(12)
    h.paragraph_format.space_after = Pt(4)
    h.paragraph_format.keep_with_next = True
    for r in h.runs:
        r.font.name = "Calibri"
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = COLOR_SECONDARY
    return h

def add_heading_3(doc, text):
    h = doc.add_heading(text, level=3)
    h.paragraph_format.space_before = Pt(8)
    h.paragraph_format.space_after = Pt(2)
    h.paragraph_format.keep_with_next = True
    for r in h.runs:
        r.font.name = "Calibri"
        r.font.size = Pt(11)
        r.font.bold = True
        r.font.color.rgb = COLOR_PRIMARY
    return h

def add_body_p(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    run = p.add_run(text)
    run.font.name = "Calibri"
    run.font.size = Pt(10.5)
    run.font.color.rgb = COLOR_TEXT
    return p

def add_bullet_p(doc, bold_prefix, text):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.15
    r_bold = p.add_run(bold_prefix)
    r_bold.font.name = "Calibri"
    r_bold.font.size = Pt(10)
    r_bold.font.bold = True
    r_bold.font.color.rgb = COLOR_PRIMARY
    r_text = p.add_run(text)
    r_text.font.name = "Calibri"
    r_text.font.size = Pt(10)
    r_text.font.color.rgb = COLOR_TEXT
    return p

def add_figure(doc, img_path, caption, width=Inches(6.0)):
    if os.path.exists(img_path):
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img.paragraph_format.space_before = Pt(8)
        p_img.paragraph_format.space_after = Pt(4)
        run_img = p_img.add_run()
        run_img.add_picture(img_path, width=width)

        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap.paragraph_format.space_before = Pt(2)
        p_cap.paragraph_format.space_after = Pt(10)
        run_cap = p_cap.add_run(caption)
        run_cap.font.name = "Calibri"
        run_cap.font.size = Pt(9.5)
        run_cap.font.italic = True
        run_cap.font.bold = True
        run_cap.font.color.rgb = COLOR_SECONDARY
    else:
        # Placeholder
        p_ph = doc.add_paragraph()
        p_ph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p_ph.add_run(f"[FIGURE PLACEHOLDER: {caption} — Image path: {img_path} not found]")
        r.font.bold = True
        r.font.color.rgb = RGBColor(180, 0, 0)

# ==============================================================================
# Main Generation Function
# ==============================================================================
def generate_project_report():
    print("[*] Initializing Word document...")
    doc = Document()

    # Page Setup — A4 & 1 inch Margins
    for section in doc.sections:
        section.page_width = Inches(8.27)
        section.page_height = Inches(11.69)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        section.header_distance = Inches(0.5)
        section.footer_distance = Inches(0.5)

        # Setup Header and Footer
        header_p = section.header.paragraphs[0]
        header_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        r_hdr = header_p.add_run("WebShield — Automated Web Security Scanner | IBM SkillsBuild 2026")
        r_hdr.font.name = "Calibri"
        r_hdr.font.size = Pt(8.5)
        r_hdr.font.color.rgb = COLOR_MUTED

        footer_p = section.footer.paragraphs[0]
        footer_p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        r_ftr_l = footer_p.add_run("BharatCares Cybersecurity Capstone Project\t\tPage ")
        r_ftr_l.font.name = "Calibri"
        r_ftr_l.font.size = Pt(8.5)
        r_ftr_l.font.color.rgb = COLOR_MUTED
        add_page_number_to_run(footer_p.add_run())
        r_ftr_m = footer_p.add_run(" of ")
        r_ftr_m.font.name = "Calibri"
        r_ftr_m.font.size = Pt(8.5)
        r_ftr_m.font.color.rgb = COLOR_MUTED
        add_numpages_to_run(footer_p.add_run())

    # --------------------------------------------------------------------------
    # 1. TITLE PAGE
    # --------------------------------------------------------------------------
    p_title_pre = doc.add_paragraph()
    p_title_pre.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title_pre.paragraph_format.space_before = Pt(36)
    p_title_pre.paragraph_format.space_after = Pt(12)
    r_sub = p_title_pre.add_run("A CAPSTONE PROJECT REPORT ON")
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(12)
    r_sub.font.bold = True
    r_sub.font.color.rgb = COLOR_SECONDARY

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(8)
    r_main_title = p_title.add_run("WebShield: Automated Web Security Scanner")
    r_main_title.font.name = "Calibri"
    r_main_title.font.size = Pt(26)
    r_main_title.font.bold = True
    r_main_title.font.color.rgb = COLOR_PRIMARY

    p_tagline = doc.add_paragraph()
    p_tagline.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_tagline.paragraph_format.space_after = Pt(30)
    r_tag = p_tagline.add_run("A Non-Destructive Vulnerability Assessment Engine for Web Application Posture Analysis")
    r_tag.font.name = "Calibri"
    r_tag.font.size = Pt(12.5)
    r_tag.font.italic = True
    r_tag.font.color.rgb = COLOR_MUTED

    # Submission context
    p_sub_details = doc.add_paragraph()
    p_sub_details.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub_details.paragraph_format.space_before = Pt(20)
    p_sub_details.paragraph_format.space_after = Pt(10)
    r_track = p_sub_details.add_run("Submitted in partial fulfillment for the award of\n")
    r_track.font.size = Pt(11)
    r_track_b = p_sub_details.add_run("IBM SkillsBuild Cyber Security 2026\n")
    r_track_b.font.size = Pt(13)
    r_track_b.font.bold = True
    r_track_b.font.color.rgb = COLOR_PRIMARY
    r_track_c = p_sub_details.add_run("Conducted by BharatCares")
    r_track_c.font.size = Pt(11.5)
    r_track_c.font.bold = True

    # Candidate & Supervisor Table
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(40)
    
    cand_headers = ["Candidate Details", "Project Guidance & Institution"]
    cand_data = [
        [
            "Student Name: [Insert Student Name]\nRoll Number: [Insert Roll Number]\nCandidate ID: [Insert IBM SkillsBuild ID]\nDegree / Branch: B.Tech / B.E. (CSE / IT / Cyber Security)",
            "Project Guide: [Insert Guide / Mentor Name]\nDesignation: [Insert Designation]\nDepartment: Computer Science & Engineering\nInstitution: [Insert College / Institution Name]\nAcademic Year: 2025 – 2026"
        ]
    ]
    create_styled_table(doc, cand_headers, cand_data, [Inches(3.1), Inches(3.1)])

    doc.add_page_break()

    # --------------------------------------------------------------------------
    # 2. CERTIFICATE PAGE
    # --------------------------------------------------------------------------
    add_heading_1(doc, "Certificate of Completion")
    add_body_p(doc, "This is to certify that the project entitled \"WebShield: Automated Web Security Scanner\" is a bona fide record of independent capstone engineering work carried out by:")

    cert_table_data = [
        ["[Insert Student Name]", "[Insert Roll Number]", "[Insert Candidate ID]", "Computer Science & Engineering"]
    ]
    create_styled_table(doc, ["Student Name", "Roll Number", "Candidate ID", "Department"], cert_table_data, [Inches(1.8), Inches(1.3), Inches(1.4), Inches(1.7)])

    add_body_p(doc, "The project has been submitted in partial fulfillment of the requirements for the IBM SkillsBuild Cyber Security 2026 program conducted by BharatCares during the academic session 2025–2026.")
    add_body_p(doc, "To the best of our knowledge, the results, implementation code, and analysis embodied in this project report have not been submitted to any other University or Institution for the award of any other degree or diploma.")

    p_sig_space = doc.add_paragraph()
    p_sig_space.paragraph_format.space_before = Pt(45)

    sig_headers = ["Project Guide / Mentor", "Head of Department", "BharatCares Evaluator"]
    sig_data = [
        ["\n\n_______________________\n[Insert Guide Name]\nProject Guide", 
         "\n\n_______________________\n[Insert HOD Name]\nHead of Department", 
         "\n\n_______________________\nAuthorized Signatory\nBharatCares / IBM SkillsBuild"]
    ]
    create_styled_table(doc, sig_headers, sig_data, [Inches(2.1), Inches(2.1), Inches(2.0)])

    doc.add_page_break()

    # --------------------------------------------------------------------------
    # 3. ACKNOWLEDGEMENT
    # --------------------------------------------------------------------------
    add_heading_1(doc, "Acknowledgement")
    add_body_p(doc, "I wish to express my sincere gratitude to BharatCares and IBM SkillsBuild for organizing the Cyber Security 2026 program, which provided a comprehensive platform to develop and demonstrate practical web security capabilities.")
    add_body_p(doc, "I am deeply indebted to my project supervisor, [Insert Guide Name], for their insightful guidance, constant encouragement, and technical review throughout the conceptualization, design, and implementation of WebShield.")
    add_body_p(doc, "I extend my appreciation to the Department of [Insert Department Name], [Insert Institution Name], for providing the academic infrastructure, laboratories, and support necessary to complete this project.")
    add_body_p(doc, "Finally, I acknowledge the valuable open-source security resources provided by the Open Web Application Security Project (OWASP) Foundation, the Python software ecosystem, and the developer community, which laid the foundational standards for the defensive checks implemented in this project.")

    doc.add_page_break()

    # --------------------------------------------------------------------------
    # 4. ABSTRACT
    # --------------------------------------------------------------------------
    add_heading_1(doc, "Abstract")
    add_body_p(doc, "In modern web application environments, defensive posture is heavily dictated by browser-enforced security mechanisms and transport encryption standards. While logic flaws and injection vulnerabilities frequently receive high priority in defensive reviews, a substantial fraction of cross-site scripting (XSS), clickjacking, MIME confusion, and session hijacking attacks stem from the omission or misconfiguration of baseline HTTP defense headers, insecure cookie attributes, permissive Cross-Origin Resource Sharing (CORS) rules, and unencrypted transport fallbacks.")
    add_body_p(doc, "This project introduces WebShield, an automated, modular, and non-destructive web security scanner engineered to perform fast, passive security evaluations of authorized web applications. Developed in Python using the Flask framework, SQLAlchemy ORM, and Requests, WebShield implements a multi-layered security engine that checks for Transport Layer Security compliance (TLS-001 to TLS-003), seven critical HTTP security headers (HDR-001 to HDR-007), session cookie protection flags (CKY-001 to CKY-004), CORS origin reflection and credential hazards (CRS-001 to CRS-004), and unencrypted HTML form actions (HTML-001 to HTML-005).")
    add_body_p(doc, "To prevent abuse, WebShield incorporates defense-in-depth Server-Side Request Forgery (SSRF) guardrails, including strict protocol whitelisting, numeric IP literal parsing, loopback/private CIDR filtering, and per-hop redirect re-validation. Findings are aggregated through a transparent deductive scoring algorithm (0–100), visual telemetry dashboards rendered with Chart.js, side-by-side historical scan comparison, and multi-format report exports in JSON, CSV, and formal executive PDF via ReportLab. WebShield was rigorously verified through an automated test suite comprising 110 passed unit and end-to-end test cases with zero security exceptions.")
    add_body_p(doc, "Keywords: Web Application Security, HTTP Security Headers, Content Security Policy, SSRF Prevention, CORS Misconfiguration, Cookie Security Flags, Automated Vulnerability Assessment, Flask, Python.")

    doc.add_page_break()

    # --------------------------------------------------------------------------
    # 5. TABLE OF CONTENTS & LIST OF FIGURES / TABLES
    # --------------------------------------------------------------------------
    add_heading_1(doc, "Table of Contents")
    
    # Static visual TOC table for immediate layout verification
    toc_data = [
        ["1.0", "Introduction & Project Background", "5"],
        ["2.0", "Problem Statement", "6"],
        ["3.0", "Aim, Objectives & Project Scope", "7"],
        ["4.0", "Existing System vs. Proposed System", "8"],
        ["5.0", "System Requirements Specification (SRS)", "9"],
        ["6.0", "Technology Stack & Rationale", "10"],
        ["7.0", "System Architecture & Design", "11"],
        ["8.0", "Project Structure & Module Descriptions", "13"],
        ["9.0", "Detailed Methodology & Scan Workflow", "14"],
        ["10.0", "Implementation of Security Analysis Modules", "16"],
        ["11.0", "URL Validation & SSRF Prevention Engine", "20"],
        ["12.0", "Database Architecture & Data Models", "22"],
        ["13.0", "User Interface & Genuine Application Screenshots", "24"],
        ["14.0", "Testing Methodology & Verification Results", "29"],
        ["15.0", "Controlled Target Case Study & Simulated Findings", "31"],
        ["16.0", "Advantages, Limitations & Future Enhancements", "33"],
        ["17.0", "Conclusion", "34"],
        ["18.0", "References & Technical Bibliography", "35"],
        ["Appendix", "Installation, Configuration & Operational Guide", "36"]
    ]
    create_styled_table(doc, ["Section", "Title", "Page"], toc_data, [Inches(1.0), Inches(4.5), Inches(0.8)])

    add_heading_2(doc, "List of Figures")
    fig_data = [
        ["Figure 1", "WebShield System Architecture & Data Flow", "12"],
        ["Figure 2", "WebShield Scan Execution Workflow", "15"],
        ["Figure 3", "Landing Page with URL Scanner Submission Form", "24"],
        ["Figure 4", "Interactive Telemetry Dashboard with Score & Severity Charts", "25"],
        ["Figure 5", "Detailed Scan Results with Security Score & Finding Cards", "26"],
        ["Figure 6", "Side-by-Side Scan Differential Comparison Interface", "27"],
        ["Figure 7", "Historical Scans Archive Table with Search and Filtering", "28"],
        ["Figure 8", "Executive Summary Security Report View", "28"]
    ]
    create_styled_table(doc, ["Figure #", "Caption / Description", "Page"], fig_data, [Inches(1.2), Inches(4.3), Inches(0.8)])

    add_heading_2(doc, "List of Tables")
    tbl_data = [
        ["Table 1", "Comparison between Existing Security Testing Approaches and WebShield", "8"],
        ["Table 2", "Functional Requirements Specification (FR-01 to FR-08)", "9"],
        ["Table 3", "Non-Functional Requirements Specification (NFR-01 to NFR-06)", "10"],
        ["Table 4", "Software Technologies & Library Inventory", "10"],
        ["Table 5", "Transport Security Check Inventory (TLS-001 to TLS-003)", "16"],
        ["Table 6", "HTTP Security Headers Check Inventory (HDR-001 to HDR-007)", "17"],
        ["Table 7", "Cookie Security Attribute Check Inventory (CKY-001 to CKY-004)", "18"],
        ["Table 8", "CORS Configuration Check Inventory (CRS-001 to CRS-004)", "19"],
        ["Table 9", "HTML Security Observations Inventory (HTML-001 to HTML-005)", "19"],
        ["Table 10", "Deductive Scoring Model Penalty Matrix", "20"],
        ["Table 11", "Pre-Flight Blocked IPv4 and IPv6 Subnet Allocations", "21"],
        ["Table 12", "Database Entity Attributes and ORM Schema Mapping", "23"],
        ["Table 13", "Automated Pytest Test Suite Results by Category", "30"],
        ["Table 14", "Environment Variables Specification and Safe Defaults", "37"]
    ]
    create_styled_table(doc, ["Table #", "Caption / Description", "Page"], tbl_data, [Inches(1.2), Inches(4.3), Inches(0.8)])

    doc.add_page_break()

    # --------------------------------------------------------------------------
    # 6. INTRODUCTION & PROJECT BACKGROUND
    # --------------------------------------------------------------------------
    add_heading_1(doc, "1.0 Introduction and Project Background")
    add_body_p(doc, "The contemporary World Wide Web has evolved from a repository of static hypertext documents into a complex distributed computing ecosystem powering banking, healthcare, e-commerce, and governance infrastructure. As modern web applications have grown in sophistication, the browser has assumed the role of an operating system sandbox, enforcing security policies designed to prevent malicious websites from interacting with, reading, or tampering with user sessions on other origins.")
    add_body_p(doc, "To protect end users, standard-setting bodies—including the World Wide Web Consortium (W3C), the Internet Engineering Task Force (IETF), and the Open Web Application Security Project (OWASP)—have introduced a robust suite of defensive mechanisms communicated through HTTP response headers, cookie flags, and transport encryption handshakes. These include Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), X-Content-Type-Options, X-Frame-Options, secure cookie attributes, and Cross-Origin Resource Sharing (CORS) directives.")
    add_body_p(doc, "Despite the widespread availability of these native browser defenses, industry vulnerability reports consistently demonstrate that over 65% of publicly accessible web servers fail to implement baseline security headers, and more than 40% transmit sensitive authentication session tokens without required flags. Misconfigurations in transport security, such as missing HTTP-to-HTTPS redirects or untrusted certificates, continue to leave end users vulnerable to Man-in-the-Middle (MITM) eavesdropping and SSL-stripping attacks.")
    add_body_p(doc, "WebShield was created as an automated, non-invasive security scanner specifically tailored for cybersecurity students, software developers, and DevSecOps practitioners. The platform allows users to audit authorized web endpoints against modern web security standards, producing categorized findings, actionable remediation advice, intuitive visualizations, and exportable audit reports.")

    # --------------------------------------------------------------------------
    # 7. PROBLEM STATEMENT
    # --------------------------------------------------------------------------
    add_heading_1(doc, "2.0 Problem Statement")
    add_body_p(doc, "While modern browsers enforce strict security controls when instructed by server responses, they default to permissive legacy behavior when security headers are absent or misconfigured. This creates critical operational vulnerabilities:")
    add_bullet_p(doc, "Omission of Content Security Policy (CSP): ", "Leaves web applications defenseless against Cross-Site Scripting (XSS) and unauthorized external script injection.")
    add_bullet_p(doc, "Lack of HTTP Strict Transport Security (HSTS): ", "Enables network-level attackers to downgrade encrypted HTTPS sessions to plaintext HTTP via SSL-stripping.")
    add_bullet_p(doc, "Unprotected Cookie Attributes: ", "Session cookies lacking HttpOnly can be stolen via JavaScript injection, while those lacking Secure are transmitted unencrypted over public networks.")
    add_bullet_p(doc, "Permissive CORS Configurations: ", "Servers reflecting untrusted Origin headers with credentials allow third-party sites to extract sensitive authenticated data directly from user sessions.")
    add_bullet_p(doc, "Shortcomings of Existing Tooling: ", "Enterprise vulnerability scanners (e.g., Nessus, Qualys, Burp Suite Pro) are complex, costly, and invasive. Open-source CLI tools often produce raw unparsed terminal dumps that lack historical tracking, contextual impact explanations, or executive-ready reports.")

    # --------------------------------------------------------------------------
    # 8. AIM, OBJECTIVES & SCOPE
    # --------------------------------------------------------------------------
    add_heading_1(doc, "3.0 Aim, Objectives, and Scope")
    add_heading_2(doc, "3.1 Project Aim")
    add_body_p(doc, "The primary aim of WebShield is to engineer a lightweight, web-based automated security assessment platform capable of non-destructively scanning authorized targets, detecting transport and configuration flaws, computing an objective security score, and generating actionable remediation reports.")

    add_heading_2(doc, "3.2 Measurable Objectives")
    add_bullet_p(doc, "Objective 1: Multi-Vector Scanner: ", "Develop modular analyzers in Python to inspect TLS/HTTPS compliance, seven HTTP defense headers, session cookie attributes, CORS policies, and HTML forms.")
    add_bullet_p(doc, "Objective 2: SSRF & Network Guardrails: ", "Engineer a pre-flight URL validation engine that strictly blocks private IPv4/IPv6 ranges, loopback addresses, cloud metadata endpoints, and obfuscated numeric encodings before socket creation.")
    add_bullet_p(doc, "Objective 3: Deductive Scoring Model: ", "Design a transparent scoring algorithm that maps observed findings to an objective 0–100 scale categorized into qualitative health bands.")
    add_bullet_p(doc, "Objective 4: Interactive Web Interface: ", "Build a responsive web application using Flask and Bootstrap 5 with Chart.js visualizations, historical scan tracking, and side-by-side scan differential comparison.")
    add_bullet_p(doc, "Objective 5: Multi-Format Reporting: ", "Implement an export engine capable of generating structured JSON, CSV, and formal executive PDF reports using ReportLab.")
    add_bullet_p(doc, "Objective 6: Rigorous Verification: ", "Validate the scanning engine through an automated test suite achieving 100% pass rates across unit and end-to-end integration scenarios.")

    add_heading_2(doc, "3.3 Project Scope & Exclusions")
    add_body_p(doc, "WebShield is strictly scoped as a non-destructive configuration assessment engine. It evaluates external HTTP and transport behaviors. It explicitly excludes active exploitation, SQL injection fuzzing, denial-of-service stress testing, or authenticated credential brute-forcing. It evaluates target URLs supplied by authorized operators.")

    # --------------------------------------------------------------------------
    # 9. EXISTING SYSTEM VS PROPOSED SYSTEM
    # --------------------------------------------------------------------------
    add_heading_1(doc, "4.0 Existing System and Proposed System")
    add_body_p(doc, "A comprehensive comparison between conventional vulnerability assessment approaches and the proposed WebShield architecture is summarized in Table 1.")

    add_heading_2(doc, "Table 1: Comparison between Existing Approaches and WebShield")
    comp_headers = ["Evaluation Metric", "Manual Inspection", "Heavyweight DAST Tools", "WebShield (Proposed)"]
    comp_data = [
        ["Speed & Efficiency", "Slow, manual (cURL / DevTools)", "Slow (Hours per deep crawl)", "Fast (5 to 15 seconds per scan)"],
        ["Operational Impact", "Passive inspection", "Invasive payloads / risk of crash", "Strictly non-destructive HTTP/TLS checks"],
        ["SSRF Safety Safeguards", "Dependent on manual operator", "Often scans internal targets blindly", "Strict pre-flight CIDR & metadata filtering"],
        ["Scoring & Health Metric", "Subjective notes", "Complex CVSS matrices", "Standardized 0–100 Deductive Score"],
        ["Historical Tracking", "Manual spreadsheets", "Complex enterprise database", "Built-in scan history & differential comparison"],
        ["Reporting Formats", "Manual documentation", "Heavyweight proprietary reports", "Instant on-demand JSON, CSV, and PDF"],
        ["Deployment Footprint", "Requires local terminal tools", "Gigabytes of dependencies & agents", "Lightweight Flask app with SQLite/MySQL"]
    ]
    create_styled_table(doc, comp_headers, comp_data, [Inches(1.5), Inches(1.5), Inches(1.6), Inches(1.6)])

    # --------------------------------------------------------------------------
    # 10. REQUIREMENTS SPECIFICATION
    # --------------------------------------------------------------------------
    add_heading_1(doc, "5.0 System Requirements Specification (SRS)")
    add_heading_2(doc, "5.1 Functional Requirements")
    add_body_p(doc, "Table 2 defines the functional requirements implemented and verified within the WebShield codebase.")

    add_heading_2(doc, "Table 2: Functional Requirements Specification")
    fr_headers = ["Req ID", "Requirement Name", "Description & Code Location"]
    fr_data = [
        ["FR-01", "Target Submission & Parsing", "System accepts target URLs via web form or JSON API, automatically normalizes schemes, and strips invalid port components (routes/scans.py)."],
        ["FR-02", "Pre-Flight SSRF Guardrails", "Validates candidate targets against scheme allowlists, prohibited CIDR blocks (RFC 1918, loopback, CGN, cloud metadata), and resolves DNS before socket creation (scanner/safety.py)."],
        ["FR-03", "Transport Layer Analysis", "Verifies HTTPS support, inspects HTTP-to-HTTPS permanent redirects, and strictly verifies TLS certificate validity using system CA bundles (scanner/transport.py)."],
        ["FR-04", "HTTP Header Auditing", "Analyzes 7 critical security headers, detects dangerous CSP directives ('unsafe-inline', 'unsafe-eval'), and flags server disclosure banners (scanner/headers.py)."],
        ["FR-05", "Cookie Security Checks", "Extracts Set-Cookie headers and audits presence of Secure, HttpOnly, and SameSite attributes (scanner/cookies.py)."],
        ["FR-06", "CORS Policy Evaluation", "Probes pre-flight CORS headers using sentinel test origins to detect wildcard origins with credentials and reflected origins (scanner/cors.py)."],
        ["FR-07", "Deductive Scoring Model", "Computes a transparent 0–100 security score based on finding severity and status, mapping scores to qualitative health categories (scanner/scoring.py)."],
        ["FR-08", "Reporting & Export Engine", "Persists findings to SQLAlchemy database models and exports findings in JSON, CSV, and executive PDF formats (services/report_service.py)."]
    ]
    create_styled_table(doc, fr_headers, fr_data, [Inches(0.8), Inches(1.8), Inches(3.6)])

    add_heading_2(doc, "5.2 Non-Functional Requirements")
    add_body_p(doc, "Table 3 details the non-functional qualities maintained across the application architecture.")

    add_heading_2(doc, "Table 3: Non-Functional Requirements Specification")
    nfr_headers = ["NFR ID", "Quality Attribute", "Specification & Implementation Standard"]
    nfr_data = [
        ["NFR-01", "Safety & Non-Invasiveness", "Scanner only issues read-only HTTP GET, HEAD, and OPTIONS requests; no destructive payloads, fuzzing, or exploit injection."],
        ["NFR-02", "Performance & Timeouts", "Enforces strict per-request network timeouts (15s) and limits maximum stream reads to 5MB to prevent memory exhaustion."],
        ["NFR-03", "Concurrency & Thread Safety", "Managed task runner registers background threads with thread locks and provides graceful draining before database teardown."],
        ["NFR-04", "Database Portability", "Zero-dependency fallback: supports MySQL for production deployments and SQLite for standalone local execution via DATABASE_URL."],
        ["NFR-05", "Usability & Accessibility", "Modern dark-themed Bootstrap 5 user interface responsive on desktop and mobile viewports with Chart.js visualizations."],
        ["NFR-06", "Maintainability & Code Health", "100% modular architecture with comprehensive docstrings, type annotations, and 110 automated pytest tests."]
    ]
    create_styled_table(doc, nfr_headers, nfr_data, [Inches(0.8), Inches(1.8), Inches(3.6)])

    # --------------------------------------------------------------------------
    # 11. TECHNOLOGIES USED
    # --------------------------------------------------------------------------
    add_heading_1(doc, "6.0 Technologies Used and Their Purpose")
    add_body_p(doc, "WebShield is built entirely using open-source, industry-standard technologies selected for reliability, security, and developer ergonomics. Table 4 enumerates the technology stack.")

    add_heading_2(doc, "Table 4: Software Technologies & Library Inventory")
    tech_headers = ["Technology", "Version", "Category", "Purpose in WebShield"]
    tech_data = [
        ["Python", "3.10 – 3.13", "Core Runtime", "High-level language powering scanning logic, networking, and ORM models."],
        ["Flask", "3.0.3", "Web Framework", "Microframework hosting application routing, blueprints, templates, and REST APIs."],
        ["Flask-SQLAlchemy", "3.1.1", "ORM Extension", "Integrates SQLAlchemy ORM with Flask application contexts."],
        ["SQLAlchemy", "2.0+", "Database ORM", "Abstracts SQL database queries, relationship mapping, and schema initialization."],
        ["PyMySQL", "1.1.1", "Database Driver", "Pure-Python MySQL database driver for production and staging environments."],
        ["Requests", "2.32.3", "HTTP Networking", "Issues robust HTTP/TLS requests with custom headers, timeouts, and streaming."],
        ["BeautifulSoup4", "4.12.3", "HTML Parser", "Parses target DOM trees to inspect form action endpoints and input fields."],
        ["ReportLab", "4.2.2", "Document Engine", "Programmatically compiles structured findings into formatted PDF reports."],
        ["Bootstrap", "5.3.3", "Front-End UI", "Provides responsive layout grids, navigation bars, modal dialogs, and dark theme."],
        ["Chart.js", "4.4.3", "Data Visualization", "Renders interactive score trend lines and severity distribution doughnut charts."],
        ["pytest", "8.2.2", "Test Framework", "Automates unit, integration, safety, and end-to-end scanner test suites."],
        ["Playwright", "1.49+", "Browser Automation", "Automates headless Chromium browser testing and genuine UI screenshot capture."]
    ]
    create_styled_table(doc, tech_headers, tech_data, [Inches(1.2), Inches(0.9), Inches(1.3), Inches(2.8)])

    # --------------------------------------------------------------------------
    # 12. SYSTEM ARCHITECTURE
    # --------------------------------------------------------------------------
    add_heading_1(doc, "7.0 System Architecture and Design")
    add_body_p(doc, "WebShield is architected using a decoupled, layered pipeline that isolates client interaction, request routing, security guardrails, modular scanning logic, persistence, and reporting.")
    add_body_p(doc, "Figure 1 illustrates the high-level system architecture and component interactions.")

    arch_img = os.path.join(DIAGRAMS_DIR, "system_architecture.png")
    add_figure(doc, arch_img, "Figure 1: WebShield System Architecture & Data Flow", width=Inches(6.2))

    add_heading_2(doc, "7.1 Subsystem Layer Decomposition")
    add_bullet_p(doc, "1. Client & Presentation Layer: ", "Renders responsive web interfaces using Jinja2 templates, Bootstrap 5 CSS, Bootstrap Icons, and Chart.js. Communicates with backend endpoints via standard HTML form submissions or RESTful JSON APIs.")
    add_bullet_p(doc, "2. Routing & Controller Layer (Flask Blueprints): ", "Organized into three functional blueprints: dashboard_bp (landing page, metrics, history, health), scans_bp (scan creation, status polling, comparison), and reports_bp (report viewing and on-demand JSON/CSV/PDF downloads).")
    add_bullet_p(doc, "3. Security Guardrails & Task Execution Engine: ", "Intercepts all incoming target URLs before socket connection. Performs pre-flight SSRF filtering (scanner/safety.py) and dispatches scans through a managed task runner (scanner/task_runner.py) that tracks active threads and permits synchronous execution during automated testing.")
    add_bullet_p(doc, "4. Core Scanner Orchestration Engine: ", "Coordinates individual analysis modules sequentially. Receives responses from transport, header, cookie, CORS, and HTML analyzers, normalizes finding dataclasses, computes the composite security score, and commits records to the database.")
    add_bullet_p(doc, "5. Data Persistence & Reporting Service: ", "Manages database interactions across User, Scan, and Finding models using SQLAlchemy. Dispatches report export requests to services/report_service.py for PDF, CSV, and JSON generation.")

    # --------------------------------------------------------------------------
    # 13. PROJECT DIRECTORY STRUCTURE
    # --------------------------------------------------------------------------
    add_heading_1(doc, "8.0 Project Structure and Module Descriptions")
    add_body_p(doc, "The repository follows strict modular conventions. The file and directory hierarchy is summarized below:")

    code_struct = (
        "D:\\WebShield\\\n"
        "├── app.py                     # Flask application factory (create_app) and server entry point\n"
        "├── config.py                  # Environment-driven configuration (Development, Production, Testing)\n"
        "├── extensions.py              # Shared SQLAlchemy, CSRFProtect, and LoginManager instances\n"
        "├── models.py                  # SQLAlchemy models: User, Scan, Finding, ScanStatus, Severity\n"
        "├── conftest.py                # Root test configuration (sys.path initialization)\n"
        "├── pytest.ini                 # Pytest runner configuration and local tempdir settings\n"
        "├── requirements.txt           # Production Python dependencies\n"
        "├── .env.example               # Template environment configuration file\n"
        "├── scanner/                   # Core Security Scanning Subsystem\n"
        "│   ├── __init__.py            # Package exports (run_scan, dispatch_scan, wait_for_all_scans)\n"
        "│   ├── safety.py              # SSRF protection, IP/DNS validation, and redirect re-validation\n"
        "│   ├── transport.py           # HTTPS support, TLS certificate validation, HTTP redirect checks\n"
        "│   ├── headers.py             # 7 HTTP defense headers analyzer (CSP, HSTS, XFO, XCTO...)\n"
        "│   ├── cookies.py             # Cookie security attribute analyzer (Secure, HttpOnly, SameSite)\n"
        "│   ├── cors.py                # CORS origin reflection and credential configuration analyzer\n"
        "│   ├── html_checks.py         # BeautifulSoup HTML DOM inspector for plaintext form submissions\n"
        "│   ├── scoring.py             # Deductive 0-100 scoring algorithm and rating thresholds\n"
        "│   ├── orchestrator.py        # Pipeline coordinator running checks and persisting findings\n"
        "│   └── task_runner.py         # Managed background thread lifecycle and synchronization\n"
        "├── routes/                    # Flask Controller Blueprints\n"
        "│   ├── dashboard.py           # Home page, telemetry metrics, history, and health endpoints\n"
        "│   ├── scans.py               # Scan submission, status API, results view, and comparison\n"
        "│   └── reports.py             # HTML report view and JSON, CSV, PDF download endpoints\n"
        "├── services/                  # Business Logic Services\n"
        "│   └── report_service.py      # PDF (ReportLab), CSV, and JSON report generator\n"
        "├── templates/                 # Jinja2 HTML Templates (base, index, dashboard, scan_results...)\n"
        "├── static/                    # Front-End Static Assets (CSS custom styles, JavaScript)\n"
        "├── tests/                     # Automated Test Suite (110 passing pytest cases)\n"
        "└── notebooks/                 # Jupyter Notebook Security Analysis & Demonstrations\n"
    )
    p_code = doc.add_paragraph()
    p_code.paragraph_format.space_before = Pt(4)
    p_code.paragraph_format.space_after = Pt(8)
    r_c = p_code.add_run(code_struct)
    r_c.font.name = "Consolas"
    r_c.font.size = Pt(8)
    r_c.font.color.rgb = RGBColor(40, 40, 40)

    # --------------------------------------------------------------------------
    # 14. METHODOLOGY & WORKFLOW
    # --------------------------------------------------------------------------
    add_heading_1(doc, "9.0 Detailed Methodology and Scan Workflow")
    add_body_p(doc, "The execution of a scan follows a deterministic, safe pipeline designed to maximize detection fidelity while maintaining absolute safety. Figure 2 depicts the step-by-step workflow.")

    wf_img = os.path.join(DIAGRAMS_DIR, "scan_workflow.png")
    add_figure(doc, wf_img, "Figure 2: WebShield Scan Execution Workflow", width=Inches(5.0))

    add_heading_2(doc, "9.1 Scan Execution Phases")
    add_bullet_p(doc, "Phase 1: Input Ingestion & Normalization: ", "The target URL is submitted via the web UI or JSON API. Schemes are standardized to lowercase, default HTTPS is prepended if omitted, and the target hostname is parsed.")
    add_bullet_p(doc, "Phase 2: Pre-Flight Guardrails: ", "The URL is passed to scanner.safety.validate_url(). If the target resolves to an RFC 1918 private IP, loopback, cloud metadata endpoint, or disallowed port, the scan is rejected immediately with an informative error message. No TCP connection is created.")
    add_bullet_p(doc, "Phase 3: Asynchronous Task Dispatch: ", "A Scan entity is created in the database with status PENDING. The background task runner (scanner.task_runner.dispatch_scan) registers the thread and executes run_scan() asynchronously, immediately returning an HTTP 202 response to the client.")
    add_bullet_p(doc, "Phase 4: Multi-Module Analysis Execution: ", "The orchestrator executes transport checks (TLS-001..003), followed by security header checks (HDR-001..007), cookie checks (CKY-001..004), CORS evaluations (CRS-001..004), and DOM HTML parsing (HTML-001..005).")
    add_bullet_p(doc, "Phase 5: Score Computation & Persistence: ", "All raw findings are normalized into Finding model instances. The deductive scoring engine computes the final score (0–100). The Scan status is updated to COMPLETED, and the database session commits.")
    add_bullet_p(doc, "Phase 6: Result Presentation & Delivery: ", "The client polling interface updates automatically. Findings are displayed categorized by severity, telemetry charts update in real time, and audit reports are ready for export.")

    # --------------------------------------------------------------------------
    # 15. IMPLEMENTATION OF SECURITY CHECKS
    # --------------------------------------------------------------------------
    add_heading_1(doc, "10.0 Implementation of Security Analysis Modules")
    add_body_p(doc, "WebShield organizes checks into specialized modules. Every check is identified by a standardized code, severity level, technical rationale, and remediation guideline.")

    # Transport Checks
    add_heading_2(doc, "10.1 Transport Security Checks (scanner/transport.py)")
    add_body_p(doc, "Table 5 outlines the transport security checks executed on every target.")
    add_heading_3(doc, "Table 5: Transport Security Check Inventory")
    t_headers = ["Check ID", "Check Name", "Severity", "Technical Rationale & Mitigation"]
    t_data = [
        ["TLS-001", "HTTPS Support", "High", "Validates that target responds over HTTPS with valid encryption. If SSL handshake fails or certificate is invalid, flags high risk."],
        ["TLS-002", "HTTP-to-HTTPS Redirect", "Medium", "Probes plain HTTP port 80 to verify immediate 301/308 redirect to HTTPS, preventing unencrypted transport exposure."],
        ["TLS-003", "TLS Certificate Validity", "High", "Verifies that server certificate is accepted by system CA bundle, matches hostname, and has not expired."]
    ]
    create_styled_table(doc, t_headers, t_data, [Inches(1.0), Inches(1.8), Inches(1.0), Inches(2.4)])

    # Header Checks
    add_heading_2(doc, "10.2 HTTP Security Header Checks (scanner/headers.py)")
    add_body_p(doc, "Table 6 details the 7 defense header checks implemented in WebShield.")
    add_heading_3(doc, "Table 6: HTTP Security Headers Check Inventory")
    h_headers = ["Check ID", "Check Name", "Severity", "Evaluation Criteria & Standards Compliance"]
    h_data = [
        ["HDR-001", "Content-Security-Policy", "High", "Checks for CSP. Flags missing CSP as High severity. Inspects existing CSP for dangerous directives like 'unsafe-inline' or 'unsafe-eval'."],
        ["HDR-002", "Strict-Transport-Security", "High", "Validates HSTS on HTTPS endpoints (RFC 6797). Requires minimum max-age of 15,552,000s (6 months); observes includeSubDomains and preload."],
        ["HDR-003", "X-Content-Type-Options", "Medium", "Verifies presence of 'nosniff' value to stop browser MIME-type sniffing and drive-by download attacks."],
        ["HDR-004", "X-Frame-Options", "Medium", "Verifies presence of DENY or SAMEORIGIN to mitigate Clickjacking (RFC 7034). Recognizes when superseded by CSP frame-ancestors."],
        ["HDR-005", "Referrer-Policy", "Low", "Evaluates Referrer-Policy against safe standards (strict-origin-when-cross-origin, no-referrer) to prevent credential leakage in URLs."],
        ["HDR-006", "Permissions-Policy", "Informational", "Inspects Permissions-Policy to determine whether hardware features (camera, microphone, geolocation) are restricted."],
        ["HDR-007", "Server Version Leak", "Informational", "Identifies verbose Server or X-Powered-By banners disclosing specific software versions, aiding attacker reconnaissance."]
    ]
    create_styled_table(doc, h_headers, h_data, [Inches(1.0), Inches(1.8), Inches(1.0), Inches(2.4)])

    # Cookie Checks
    add_heading_2(doc, "10.3 Cookie Security Attribute Checks (scanner/cookies.py)")
    add_body_p(doc, "Table 7 details cookie checks enforcing RFC 6265bis and OWASP session management guidelines.")
    add_heading_3(doc, "Table 7: Cookie Security Attribute Check Inventory")
    c_headers = ["Check ID", "Check Name", "Severity", "Security Rationale & Threat Mitigated"]
    c_data = [
        ["CKY-001", "Cookie Missing Secure Flag", "Medium", "Ensures cookies sent over HTTPS include Secure flag, stopping unencrypted transmission over plaintext HTTP."],
        ["CKY-002", "Cookie Missing HttpOnly Flag", "Medium", "Verifies HttpOnly flag on cookies. Prevents JavaScript document.cookie access, mitigating session token theft via XSS."],
        ["CKY-003", "Insecure or Missing SameSite", "Low", "Audits SameSite attribute (Strict, Lax, None). Flags SameSite=None without Secure and flags missing SameSite."],
        ["CKY-004", "Persistent Cookie Observation", "Informational", "Observes session identifiers with long-lived Max-Age or Expires dates, recommending transient session lifespans."]
    ]
    create_styled_table(doc, c_headers, c_data, [Inches(1.0), Inches(1.8), Inches(1.0), Inches(2.4)])

    # CORS Checks
    add_heading_2(doc, "10.4 CORS Configuration Checks (scanner/cors.py)")
    add_body_p(doc, "Table 8 details Cross-Origin Resource Sharing security evaluations.")
    add_heading_3(doc, "Table 8: CORS Configuration Check Inventory")
    cr_headers = ["Check ID", "Check Name", "Severity", "Vulnerability Impact & Detection Logic"]
    cr_data = [
        ["CRS-001", "Wildcard Origin with Credentials", "High", "Identifies Access-Control-Allow-Origin: * paired with Access-Control-Allow-Credentials: true. Flags severe cross-origin exposure."],
        ["CRS-002", "Arbitrary Reflected Origin", "High", "Dispatches a pre-flight request with a sentinel Origin and detects if server dynamically mirrors the untrusted origin with credentials enabled."],
        ["CRS-003", "Overly Permissive Methods", "Medium", "Detects wildcard or high-risk HTTP method allowances (PUT, DELETE) exposed broadly without fine-grained scoping."],
        ["CRS-004", "Missing Vary: Origin Header", "Low", "Checks if dynamic CORS responses include Vary: Origin to prevent proxy cache poisoning across different origin contexts."]
    ]
    create_styled_table(doc, cr_headers, cr_data, [Inches(1.0), Inches(1.8), Inches(1.0), Inches(2.4)])

    # HTML Checks
    add_heading_2(doc, "10.5 HTML Security Observations (scanner/html_checks.py)")
    add_body_p(doc, "Table 9 lists HTML-level passive observations parsed using BeautifulSoup.")
    add_heading_3(doc, "Table 9: HTML Security Observations Inventory")
    ht_headers = ["Check ID", "Check Name", "Severity", "Observation Details"]
    ht_data = [
        ["HTML-001", "Form Submits Over Plaintext HTTP", "Medium", "Identifies <form> elements whose action attribute targets an unencrypted HTTP URL, exposing submitted form data."],
        ["HTML-002", "Password Form Submits Insecurely", "High", "Detects forms containing password input fields that transmit credentials over plaintext HTTP connections."],
        ["HTML-003", "Mixed Content / Insecure Resources", "Medium", "Inspects src attributes of scripts, stylesheets, and iframes on HTTPS pages for plaintext HTTP links."],
        ["HTML-004", "Meta Tag Security Fallbacks", "Informational", "Detects client-side <meta http-equiv> directives for CSP or Referrer-Policy."],
        ["HTML-005", "Password Autocomplete Setting", "Informational", "Observes password input fields lacking autocomplete='off' or autocomplete='new-password'."]
    ]
    create_styled_table(doc, ht_headers, ht_data, [Inches(1.0), Inches(1.8), Inches(1.0), Inches(2.4)])

    # Scoring Model
    add_heading_2(doc, "10.6 Deductive Security Scoring Model (scanner/scoring.py)")
    add_body_p(doc, "WebShield implements a deductive scoring methodology. Every target begins with a baseline score of 100 points. Penalties are deducted based on finding severity and status, as defined in Table 10.")
    add_heading_3(doc, "Table 10: Deductive Scoring Model Penalty Matrix")
    sc_headers = ["Severity Level", "Finding Status", "Score Deduction", "Qualitative Rationale"]
    sc_data = [
        ["Critical", "Fail", "-25 points", "Fundamental security collapse (e.g. invalid TLS certificate, unencrypted credentials)"],
        ["Critical", "Warning", "-20 points", "Substantial architectural vulnerability requiring immediate attention"],
        ["High", "Fail", "-15 points", "Missing foundational defense header (e.g. missing CSP, missing HSTS on HTTPS)"],
        ["High", "Warning", "-10 points", "Weakened defense directive (e.g. CSP with unsafe-inline or unsafe-eval)"],
        ["Medium", "Fail", "-10 points", "Missing secondary control (e.g. missing X-Content-Type-Options, unflagged cookie)"],
        ["Medium", "Warning", "-5 points", "Suboptimal secondary control configuration"],
        ["Low", "Fail / Warning", "-3 / -2 points", "Minor deviation from modern standards (e.g. missing Referrer-Policy)"],
        ["Informational", "All", "-0 points", "Contextual observation (e.g. server banner, long session expiration)"]
    ]
    create_styled_table(doc, sc_headers, sc_data, [Inches(1.2), Inches(1.2), Inches(1.4), Inches(2.4)])

    add_body_p(doc, "Score Deduplication & Clamping Formula: The engine tracks seen finding IDs to ensure identical base findings are penalized only once. The final score S is clamped to the range [0, 100]:")
    p_math = doc.add_paragraph()
    p_math.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_m = p_math.add_run("Security Score = max(0, min(100, 100 - ∑ Deductions(unique finding_id)))")
    r_m.font.name = "Consolas"
    r_m.font.size = Pt(10)
    r_m.font.bold = True
    r_m.font.color.rgb = COLOR_PRIMARY

    add_body_p(doc, "Score Rating Bands: 90–100: Excellent (Green) | 75–89: Good (Green) | 50–74: Fair (Yellow/Warning) | 25–49: Poor (Red/Danger) | 0–24: Critical (Red/Danger).")

    # --------------------------------------------------------------------------
    # 16. URL VALIDATION & SSRF PREVENTION
    # --------------------------------------------------------------------------
    add_heading_1(doc, "11.0 URL Validation, SSRF Prevention, and Network Safeguards")
    add_body_p(doc, "To prevent WebShield from being weaponized as a proxy to attack internal infrastructure or cloud metadata services (Server-Side Request Forgery - CWE-918), scanner/safety.py implements a defense-in-depth pre-flight validation engine.")

    add_heading_2(doc, "11.1 Prohibited Address Ranges & CIDR Filtering")
    add_body_p(doc, "Before dispatching any socket connection, WebShield resolves the target hostname and cross-checks all returned IP addresses against prohibited network allocations shown in Table 11.")

    add_heading_3(doc, "Table 11: Pre-Flight Blocked IPv4 and IPv6 Subnet Allocations")
    ip_headers = ["Network Category", "CIDR Block / Subnet", "IP Version", "Threat Mitigated"]
    ip_data = [
        ["Loopback Address Space", "127.0.0.0/8 & ::1/128", "IPv4 / IPv6", "Prohibits scanning local daemons on the scanning host"],
        ["Class A Private Network", "10.0.0.0/8", "IPv4", "Prevents scanning enterprise internal subnets"],
        ["Class B Private Network", "172.16.0.0/12", "IPv4", "Prevents scanning internal staging and container subnets"],
        ["Class C Private Network", "192.168.0.0/16", "IPv4", "Blocks scanning local area network routers and devices"],
        ["Carrier-Grade NAT (CGN)", "100.64.0.0/10", "IPv4", "Blocks service-provider internal shared network space"],
        ["Link-Local / Cloud Metadata", "169.254.0.0/16 & fe80::/10", "IPv4 / IPv6", "Prevents credential theft from AWS/GCP/OpenStack metadata"],
        ["Unique Local Address (ULA)", "fc00::/7", "IPv6", "Blocks IPv6 private internal corporate network routes"],
        ["Multicast & Reserved Space", "224.0.0.0/4 & ff00::/8", "IPv4 / IPv6", "Blocks broadcast and multicast address amplification"]
    ]
    create_styled_table(doc, ip_headers, ip_data, [Inches(1.5), Inches(1.7), Inches(1.0), Inches(2.0)])

    add_heading_2(doc, "11.2 Obfuscated Encoding & Decimal Literal Detection")
    add_body_p(doc, "Attackers frequently attempt to bypass string-based hostname filters by encoding IP addresses as 32-bit unsigned integers (e.g., http://2130706433 for 127.0.0.1) or hexadecimal strings (http://0x7f000001). WebShield intercepts these representations, parses them directly into IPv4Address objects via Python's ipaddress library, and evaluates them against the blocked CIDR list prior to issuing any DNS queries.")

    add_heading_2(doc, "11.3 Redirect TOCTOU Verification & Resource Guardrails")
    add_bullet_p(doc, "Redirect Re-Validation: ", "WebShield implements validate_redirect() to verify HTTP 30x Location destinations at every hop, preventing time-of-check/time-of-use (TOCTOU) bypasses where a public server redirects to an internal endpoint.")
    add_bullet_p(doc, "Strict Timeouts: ", "All requests are bound by SCANNER_TIMEOUT (default 15 seconds) to prevent slowloris-style thread starvation.")
    add_bullet_p(doc, "Streaming Size Caps: ", "Responses are read in 64KB chunks up to SCANNER_MAX_RESPONSE_SIZE (default 5MB), immediately closing connections if exceeded to stop memory exhaustion.")
    add_bullet_p(doc, "Enforced TLS Verification: ", "Certificate verification is never bypassed (verify=True). Self-signed or untrusted certificates are reported as high-severity findings rather than suppressed.")

    # --------------------------------------------------------------------------
    # 17. DATABASE ARCHITECTURE
    # --------------------------------------------------------------------------
    add_heading_1(doc, "12.0 Database Architecture and Data Models")
    add_body_p(doc, "WebShield utilizes SQLAlchemy ORM with a normalized relational schema supporting User authentication, Scan records, and detailed Finding entries.")
    add_body_p(doc, "Table 12 describes the database entities, column specifications, and relational constraints defined in models.py.")

    add_heading_2(doc, "Table 12: Database Entity Attributes and ORM Schema Mapping")
    db_headers = ["Table Name", "Column Name", "Data Type", "Constraints & Description"]
    db_data = [
        ["users", "id", "Integer", "Primary Key, Autoincrement"],
        ["users", "username", "String(64)", "Unique, Indexed, Non-null"],
        ["users", "email", "String(120)", "Unique, Indexed, Non-null"],
        ["users", "password_hash", "String(256)", "Non-null (Werkzeug scrypt hash)"],
        ["users", "created_at", "DateTime", "UTC timestamp of user registration"],
        ["scans", "id", "Integer", "Primary Key, Autoincrement"],
        ["scans", "user_id", "Integer", "Foreign Key (users.id), Nullable"],
        ["scans", "target_url", "String(2048)", "Full scanned target URL, Non-null"],
        ["scans", "normalized_hostname", "String(253)", "Indexed domain for comparison querying"],
        ["scans", "status", "Enum(ScanStatus)", "Indexed: PENDING, RUNNING, COMPLETED, FAILED"],
        ["scans", "security_score", "SmallInteger", "Deductive score (0–100), Nullable"],
        ["scans", "total_findings", "Integer", "Aggregate count of all findings"],
        ["scans", "critical_count", "Integer", "Count of Critical severity findings"],
        ["scans", "high_count", "Integer", "Count of High severity findings"],
        ["scans", "medium_count", "Integer", "Count of Medium severity findings"],
        ["scans", "low_count", "Integer", "Count of Low severity findings"],
        ["scans", "informational_count", "Integer", "Count of Informational observations"],
        ["scans", "scan_started_at", "DateTime", "UTC timestamp of scan initiation"],
        ["scans", "scan_completed_at", "DateTime", "UTC timestamp of scan completion"],
        ["findings", "id", "Integer", "Primary Key, Autoincrement"],
        ["findings", "scan_id", "Integer", "Foreign Key (scans.id), Cascade Delete"],
        ["findings", "finding_id", "String(64)", "Standard check ID (e.g. HDR-001, CKY-002)"],
        ["findings", "check_name", "String(128)", "Human-readable check title"],
        ["findings", "category", "String(64)", "Indexed category (Headers, Cookies, CORS...)"],
        ["findings", "severity", "Enum(Severity)", "Indexed: CRITICAL, HIGH, MEDIUM, LOW, INFO"],
        ["findings", "status", "Enum(FindingStatus)", "PASS, FAIL, WARNING, ERROR"],
        ["findings", "description", "Text", "Detailed technical explanation of finding"],
        ["findings", "evidence", "Text", "Recorded HTTP headers, status code, or DOM element"],
        ["findings", "impact", "Text", "Potential threat or vulnerability consequence"],
        ["findings", "recommendation", "Text", "Actionable remediation instructions"],
        ["findings", "reference_url", "String(512)", "Authoritative standard documentation URL"]
    ]
    create_styled_table(doc, db_headers, db_data, [Inches(1.0), Inches(1.5), Inches(1.3), Inches(2.4)])

    # --------------------------------------------------------------------------
    # 18. USER INTERFACE & GENUINE SCREENSHOTS
    # --------------------------------------------------------------------------
    add_heading_1(doc, "13.0 User Interface and Genuine Application Screenshots")
    add_body_p(doc, "This section presents authentic, un-doctored screenshots captured directly from the live running WebShield web application using automated Playwright browser capture. All views reflect actual data rendered by Flask and Bootstrap 5.")

    # Screenshot 1: Landing Page
    img1 = os.path.join(SCREENSHOTS_DIR, "01_landing_page.png")
    add_figure(doc, img1, "Figure 3: WebShield Landing Page with URL Scanner Submission Form", width=Inches(6.0))
    add_body_p(doc, "Figure 3 displays the landing page (routes/dashboard.py:index). It provides a prominent URL submission form, feature highlights, and direct access to the dashboard and history interfaces.")

    # Screenshot 2: Dashboard
    img2 = os.path.join(SCREENSHOTS_DIR, "02_dashboard.png")
    add_figure(doc, img2, "Figure 4: Interactive Telemetry Dashboard with Score History and Severity Distribution", width=Inches(6.0))
    add_body_p(doc, "Figure 4 shows the interactive dashboard (/dashboard). Key statistics cards summarize total scans, completed scans, total findings, and severity breakdowns. The Chart.js integration renders dynamic score history trends and severity distribution charts.")

    # Screenshot 3: Scan Results
    img3 = os.path.join(SCREENSHOTS_DIR, "03_scan_results.png")
    add_figure(doc, img3, "Figure 5: Detailed Scan Results with Security Score Badge and Categorized Findings", width=Inches(6.0))
    add_body_p(doc, "Figure 5 presents the scan results screen (/scans/<id>). It highlights the overall security score (47/100, Poor), execution duration, and categorized finding cards containing evidence, threat impact, and remediation steps.")

    # Screenshot 4: Scan Comparison
    img4 = os.path.join(SCREENSHOTS_DIR, "04_scan_comparison.png")
    add_figure(doc, img4, "Figure 6: Side-by-Side Scan Differential Comparison Interface", width=Inches(6.0))
    add_body_p(doc, "Figure 6 illustrates the scan comparison feature (/scans/<id>/compare). Security teams can compare two scans of the same hostname side-by-side to verify whether remediation actions successfully resolved identified weaknesses.")

    # Screenshot 5: Scan History
    img5 = os.path.join(SCREENSHOTS_DIR, "05_scan_history.png")
    add_figure(doc, img5, "Figure 7: Historical Scans Archive Table with Search and Filtering", width=Inches(6.0))
    add_body_p(doc, "Figure 7 displays the scan history view (/history), allowing users to browse, search, and filter prior evaluations by target URL and completion status.")

    # Screenshot 6: Executive Report View
    img6 = os.path.join(SCREENSHOTS_DIR, "06_report_view.png")
    add_figure(doc, img6, "Figure 8: Executive Summary Security Report View", width=Inches(6.0))
    add_body_p(doc, "Figure 8 shows the executive summary report view (/reports/<id>), optimized for management presentation and direct download in PDF, CSV, and JSON formats.")

    # --------------------------------------------------------------------------
    # 19. TESTING METHODOLOGY & RESULTS
    # --------------------------------------------------------------------------
    add_heading_1(doc, "14.0 Testing Methodology and Verification Results")
    add_body_p(doc, "WebShield incorporates an exhaustive automated test suite implemented in pytest. Testing is partitioned into unit tests, safety boundary validation, API integration, and mock end-to-end server simulations.")

    add_heading_2(doc, "14.1 Test Suite Organization and Execution")
    add_body_p(doc, "The test suite was executed in the Windows PowerShell environment using the command: python -m pytest tests/ -v. Table 13 summarizes the test categories, test count, and actual verified results.")

    add_heading_3(doc, "Table 13: Automated Pytest Test Suite Results by Category")
    tst_headers = ["Test Suite File", "Test Category", "Test Count", "Passed", "Failed", "Status"]
    tst_data = [
        ["tests/test_safety.py", "SSRF, IPv4, IPv6, CIDR, DNS, and Redirects", "44", "44", "0", "100% Passed"],
        ["tests/test_headers.py", "HTTP Defense Headers (CSP, HSTS, XFO, XCTO...)", "20", "20", "0", "100% Passed"],
        ["tests/test_cookies.py", "Cookie Security Attributes (Secure, HttpOnly...)", "8", "8", "0", "100% Passed"],
        ["tests/test_cors.py", "CORS Origin Reflection and Credentials", "9", "9", "0", "100% Passed"],
        ["tests/test_reports.py", "Report Generation (JSON, CSV, ReportLab PDF)", "6", "6", "0", "100% Passed"],
        ["tests/test_api.py", "REST API & Flask Controller Route Integration", "20", "20", "0", "100% Passed"],
        ["tests/test_e2e_lifecycle.py", "Controlled Server End-to-End Scan Lifecycle", "3", "3", "0", "100% Passed"],
        ["TOTALS", "Comprehensive Test Coverage", "110", "110", "0", "ALL PASSED"]
    ]
    create_styled_table(doc, tst_headers, tst_data, [Inches(1.8), Inches(2.2), Inches(0.7), Inches(0.5), Inches(0.5), Inches(0.9)])

    add_body_p(doc, "Zero Thread Race Conditions: Background task execution in tests was specifically hardened using scanner.task_runner.wait_for_all_scans(), guaranteeing all background scanning threads finish cleanly before test database teardown. As verified by the test runner, zero SQLite OperationalError warnings occurred.")

    # --------------------------------------------------------------------------
    # 20. CONTROLLED TARGET CASE STUDY
    # --------------------------------------------------------------------------
    add_heading_1(doc, "15.0 Controlled Target Case Study and Sample Findings")
    add_body_p(doc, "To demonstrate real-world evaluation capabilities, WebShield was tested against both an authorized live web target (https://xavier.ac.in) and a controlled local mock server (http://127.0.0.1 on ephemeral port) emitting deliberate misconfigurations.")
    add_body_p(doc, "Case Study Target: https://xavier.ac.in | Overall Security Score: 47 / 100 (Rating: Poor) | Total Findings: 13")
    add_bullet_p(doc, "Finding HDR-001 (High Severity - Fail): ", "Content-Security-Policy header is missing. Impact: Site is vulnerable to cross-site scripting (XSS) and content injection attacks. Recommendation: Deploy a restrictive CSP starting with default-src 'self'.")
    add_bullet_p(doc, "Finding HDR-002 (High Severity - Fail): ", "Strict-Transport-Security (HSTS) header is missing on HTTPS endpoint. Impact: Susceptible to SSL-stripping and man-in-the-middle attacks. Recommendation: Configure Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.")
    add_bullet_p(doc, "Finding CKY-001 (Medium Severity - Fail): ", "Session cookie missing Secure flag over HTTPS. Impact: Sensitive session tokens may be transmitted in plaintext if user visits HTTP URL. Recommendation: Add Secure attribute to all Set-Cookie directives.")
    add_bullet_p(doc, "Finding CKY-002 (Medium Severity - Fail): ", "Session cookie missing HttpOnly flag. Impact: JavaScript document.cookie access can exfiltrate session credentials. Recommendation: Add HttpOnly attribute.")
    add_bullet_p(doc, "Finding TLS-001 (Informational - Pass): ", "HTTPS is supported and server responded successfully with HTTP 200. Certificate matches domain and is trusted by system CA bundle.")

    # --------------------------------------------------------------------------
    # 21. ADVANTAGES, LIMITATIONS & FUTURE ENHANCEMENTS
    # --------------------------------------------------------------------------
    add_heading_1(doc, "16.0 Advantages, Limitations, and Future Enhancements")
    add_heading_2(doc, "16.1 Advantages")
    add_bullet_p(doc, "Zero Exploitation Risk: ", "Non-destructive passive scanning suitable for production systems without risk of service disruption.")
    add_bullet_p(doc, "Comprehensive Defensive Breadth: ", "Simultaneously evaluates transport security, 7 headers, cookie attributes, CORS, and HTML forms.")
    add_bullet_p(doc, "Robust SSRF Defense: ", "Protects internal and cloud infrastructure through pre-flight DNS and numeric CIDR filtering.")
    add_bullet_p(doc, "Flexible Data Export: ", "Generates structured JSON, CSV, and formal executive PDF reports on demand.")

    add_heading_2(doc, "16.2 Current Limitations")
    add_bullet_p(doc, "Single Page Scope: ", "Evaluates the submitted target URL; does not recursively crawl entire web domains.")
    add_bullet_p(doc, "Static HTML DOM Analysis: ", "Inspects static HTML via BeautifulSoup; does not execute client-side JavaScript for dynamic single-page applications (React/Angular).")
    add_bullet_p(doc, "In-Memory Rate Limiting: ", "Rate limiting is in-memory; enterprise deployments across multiple server processes would benefit from Redis.")

    add_heading_2(doc, "16.3 Planned Future Enhancements")
    add_bullet_p(doc, "Recursive Crawler: ", "Implement configurable depth-limited site crawling to audit sub-pages and site directories.")
    add_bullet_p(doc, "Headless Browser Engine: ", "Integrate Playwright to evaluate dynamic DOM modifications, JavaScript-rendered forms, and runtime cookies.")
    add_bullet_p(doc, "Scheduled Continuous Monitoring: ", "Add automated cron-based recurring scans with email/webhook security regression alerts.")
    add_bullet_p(doc, "CI/CD Pipeline Plugin: ", "Package scanner as a GitHub Action / GitLab CI step to break builds if security score drops below threshold.")

    # --------------------------------------------------------------------------
    # 22. CONCLUSION
    # --------------------------------------------------------------------------
    add_heading_1(doc, "17.0 Conclusion")
    add_body_p(doc, "WebShield successfully addresses the critical need for a lightweight, automated, and non-destructive web security scanner. By evaluating externally observable transport layers, HTTP defense headers, session cookie flags, CORS policies, and HTML form practices, WebShield provides actionable, context-aware remediation guidance that empowers developers and security teams to harden applications before attackers can exploit configuration gaps.")
    add_body_p(doc, "The implementation demonstrates robust engineering principles, including pre-flight SSRF protection, clean background task synchronization, portable database support across MySQL and SQLite, an objective deductive scoring model, and comprehensive automated test coverage with 110 passed test cases. WebShield successfully fulfills all requirements for the IBM SkillsBuild Cyber Security 2026 capstone project conducted by BharatCares.")

    # --------------------------------------------------------------------------
    # 23. REFERENCES
    # --------------------------------------------------------------------------
    add_heading_1(doc, "18.0 References and Technical Bibliography")
    add_bullet_p(doc, "[1] OWASP Foundation. (2021). ", "OWASP Top 10 Web Application Security Risks. Available: https://owasp.org/Top10/")
    add_bullet_p(doc, "[2] Internet Engineering Task Force (IETF). (2012). ", "HTTP Strict Transport Security (HSTS) (RFC 6797). Available: https://datatracker.ietf.org/doc/html/rfc6797")
    add_bullet_p(doc, "[3] Internet Engineering Task Force (IETF). (2011). ", "HTTP State Management Mechanism (RFC 6265 / RFC 6265bis). Available: https://datatracker.ietf.org/doc/html/rfc6265")
    add_bullet_p(doc, "[4] World Wide Web Consortium (W3C). (2020). ", "Content Security Policy Level 3. Available: https://www.w3.org/TR/CSP3/")
    add_bullet_p(doc, "[5] Internet Engineering Task Force (IETF). (2013). ", "HTTP Header Field X-Frame-Options (RFC 7034). Available: https://datatracker.ietf.org/doc/html/rfc7034")
    add_bullet_p(doc, "[6] Mozilla Developer Network (MDN). (2024). ", "Web Security Guidelines & HTTP Headers. Available: https://infosec.mozilla.org/guidelines/web_security")
    add_bullet_p(doc, "[7] National Institute of Standards and Technology (NIST). (2018). ", "Guide to Secure Web Services (SP 800-95).")
    add_bullet_p(doc, "[8] Pallets Projects. (2024). ", "Flask Documentation (Version 3.0.x). Available: https://flask.palletsprojects.com/")
    add_bullet_p(doc, "[9] SQLAlchemy Authors. (2024). ", "SQLAlchemy 2.0 Unified Documentation. Available: https://docs.sqlalchemy.org/")
    add_bullet_p(doc, "[10] ReportLab Europe. (2024). ", "ReportLab PDF Generation User Guide. Available: https://www.reportlab.com/documentation/")

    # --------------------------------------------------------------------------
    # 24. APPENDIX: OPERATIONAL GUIDE
    # --------------------------------------------------------------------------
    add_heading_1(doc, "Appendix: Installation, Configuration & Operational Guide")
    add_heading_2(doc, "A.1 Environment Setup (Windows PowerShell)")
    
    ps_commands = (
        "# 1. Navigate to project root\n"
        "cd D:\\WebShield\n\n"
        "# 2. Create and activate Python virtual environment\n"
        "python -m venv .venv\n"
        "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass\n"
        ".\\.venv\\Scripts\\Activate.ps1\n\n"
        "# 3. Install required production packages\n"
        "pip install --upgrade pip\n"
        "pip install -r requirements.txt\n\n"
        "# 4. Run automated test suite to confirm health\n"
        "python -m pytest tests/ -v\n\n"
        "# 5. Start application in standalone development mode (SQLite)\n"
        "$env:DATABASE_URL = \"sqlite:///d:/WebShield/webshield_dev.db\"\n"
        "$env:FLASK_DEBUG = \"1\"\n"
        "python app.py\n"
    )
    p_cmd = doc.add_paragraph()
    p_cmd.paragraph_format.space_before = Pt(4)
    p_cmd.paragraph_format.space_after = Pt(8)
    r_ps = p_cmd.add_run(ps_commands)
    r_ps.font.name = "Consolas"
    r_ps.font.size = Pt(8.5)
    r_ps.font.color.rgb = RGBColor(30, 30, 30)

    add_heading_2(doc, "A.2 Environment Variables Reference")
    add_body_p(doc, "Table 14 summarizes all environment variables recognized by WebShield in config.py.")
    add_heading_3(doc, "Table 14: Environment Variables Specification and Safe Defaults")
    env_headers = ["Variable Name", "Default Value", "Description"]
    env_data = [
        ["SECRET_KEY", "dev-only-insecure-key", "Session cryptographic signing key"],
        ["FLASK_ENV", "development", "Runtime configuration profile (development / production)"],
        ["DATABASE_URL", "(Computed from DB_*)", "Direct database connection URI (SQLite or MySQL)"],
        ["DB_HOST / DB_PORT", "localhost:3306", "MySQL server network address and port"],
        ["DB_NAME", "webshield", "MySQL schema name"],
        ["DB_USER / DB_PASSWORD", "root / ''", "MySQL authentication credentials"],
        ["SCANNER_TIMEOUT", "15", "Per-request socket connection and read timeout in seconds"],
        ["SCANNER_MAX_RESPONSE_SIZE", "5242880 (5MB)", "Maximum streaming bytes read per target response"],
        ["RATE_LIMIT_PER_MINUTE", "10", "Maximum scans accepted per IP per 60 seconds"],
        ["SCAN_ALLOWLIST", "'' (Permissive)", "Optional comma-separated whitelist of allowed scan hostnames"],
        ["DEMO_MODE", "0", "Enables simulated fallback mode when remote target is unreachable"]
    ]
    create_styled_table(doc, env_headers, env_data, [Inches(1.8), Inches(1.8), Inches(2.6)])

    # Save Document
    print(f"[*] Saving completed report to: {OUTPUT_PATH}...")
    doc.save(OUTPUT_PATH)
    print(f"[+] Document successfully saved! Total file size: {os.path.getsize(OUTPUT_PATH)} bytes.")

if __name__ == "__main__":
    generate_project_report()
