"""
QRshield - Simplified Presentation & Summary PDF Generator
Generates a clean, straightforward, easy-to-read document for the professor.
"""
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_decorations(self, total_pages):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages after page 1)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "QRshield — Simplified Project Summary & Presentation Guide")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 40, letter[0] - 54, letter[1] - 40)
            
        # Footer
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 42, letter[0] - 54, 42)
        self.drawString(54, 30, "Team Black Sparrow | SPIT Mumbai — Cryptography & Network Security (ISE-2)")
        self.drawRightString(letter[0] - 54, 30, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()


def build_simple_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()
    
    # Clean Color Palette
    c_primary = colors.HexColor("#1E3A8A")    # Classic Navy
    c_secondary = colors.HexColor("#0284C7")  # Sky Blue
    c_dark = colors.HexColor("#1F2937")       # Charcoal
    c_bg = colors.HexColor("#F8FAFC")         # Soft light gray
    c_border = colors.HexColor("#E2E8F0")     # Light border

    # Styles
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=22, leading=26,
        textColor=c_primary, spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle', parent=styles['Normal'],
        fontName='Helvetica', fontSize=11, leading=15,
        textColor=c_secondary, spaceAfter=8
    )
    meta_style = ParagraphStyle(
        'Meta', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=12,
        textColor=colors.HexColor("#475569")
    )
    h1_style = ParagraphStyle(
        'Heading1', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=12, leading=15,
        textColor=c_primary, spaceBefore=10, spaceAfter=4,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=10, leading=13,
        textColor=c_secondary, spaceBefore=6, spaceAfter=3,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=12,
        textColor=c_dark, spaceAfter=4
    )
    bullet_style = ParagraphStyle(
        'Bullet', parent=body_style,
        leftIndent=12, firstLineIndent=-8, spaceAfter=2.5
    )
    table_header = ParagraphStyle(
        'TH', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=8, leading=10,
        textColor=colors.white
    )
    table_cell = ParagraphStyle(
        'TC', parent=styles['Normal'],
        fontName='Helvetica', fontSize=7.5, leading=10,
        textColor=c_dark
    )
    table_cell_bold = ParagraphStyle(
        'TCB', parent=table_cell,
        fontName='Helvetica-Bold'
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("QRshield 🛡️ — Project Summary", title_style))
    story.append(Paragraph("A Three-Layer Detector for Malicious & Tampered QR Codes (Quishing)", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_secondary, spaceBefore=0, spaceAfter=6))

    meta_text = """
    <b>Course:</b> Cryptography & Network Security (CE305 / CS305) &nbsp;|&nbsp; <b>Evaluation:</b> ISE-2<br/>
    <b>College:</b> Sardar Patel Institute of Technology (SPIT), Mumbai<br/>
    <b>Team:</b> Black Sparrow (10 Members) &nbsp;|&nbsp; <b>Team Lead:</b> Akshit Sharma
    """
    story.append(Paragraph(meta_text, meta_style))
    story.append(Spacer(1, 6))

    # Executive Summary Box
    summary_box = [
        [Paragraph("<b>Status:</b> Working End-to-End System with 49 Passed Tests", table_cell_bold),
         Paragraph("<b>Key Idea:</b> Check Link (ML) + Check Physical Sticker (CV) + Verify Signature (Crypto)", table_cell_bold)]
    ]
    t_box = Table(summary_box, colWidths=[250, 254])
    t_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_bg),
        ('BOX', (0,0), (-1,-1), 1, c_secondary),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_box)
    story.append(Spacer(1, 6))

    # 1. The Problem
    story.append(Paragraph("1. The Problem in Simple Words", h1_style))
    story.append(Paragraph(
        "When people scan QR codes on phones, the phone <b>blindly opens the website or payment app</b>. "
        "Scammers exploit this trust through <b>Quishing (QR Phishing)</b>:", body_style))
    story.append(Paragraph("• <b>Fake / Zero-Day Links:</b> Scammers make brand-new lookalike sites (e.g. <i>phonepe-refund.xyz</i>) that antivirus blocklists haven't seen yet.", bullet_style))
    story.append(Paragraph("• <b>Physical Sticker Swapping:</b> Scammers print paper/vinyl stickers and paste them over real QR codes on parking meters, restaurant stands, or shop UPI soundboxes. <b>Online link scanners cannot see the physical sticker!</b>", bullet_style))
    story.append(Paragraph("• <b>No Proof of Origin:</b> Anyone can print a QR code claiming to be a bank or college because standard QR codes have no digital signatures.", bullet_style))

    # 2. What We Have Built
    story.append(Paragraph("2. What We Have Done (The 3-Layer Solution)", h1_style))
    story.append(Paragraph(
        "Instead of 'scan and auto-open', QRshield does <b>'scan, verify, then decide'</b> using 3 simple checks:", body_style))

    layers_data = [
        [Paragraph("<b>Layer</b>", table_header), Paragraph("<b>What it Does (Simple Explanation)</b>", table_header), Paragraph("<b>Result / Output</b>", table_header)],
        [Paragraph("<b>1. Link Check (ML)</b>", table_cell_bold), 
         Paragraph("Inspects the URL for brand typos (e.g. 'ph0nepe'), suspicious new extensions (.xyz), and malicious patterns without opening the page.", table_cell),
         Paragraph("Safe or Fake URL score", table_cell)],
        [Paragraph("<b>2. Camera Check (CV)</b>", table_cell_bold), 
         Paragraph("Analyzes the photo to see if someone physically pasted a sticker over the original board. Looks for cut edges, small shadows, and highlights them in red on a heatmap.", table_cell),
         Paragraph("Sticker Tamper score + Heatmap", table_cell)],
        [Paragraph("<b>3. Digital Signatures</b>", table_cell_bold), 
         Paragraph("Authentic businesses (like smart city parking) digitally sign their QR code. If the signature matches our verified root authority, it gives a green Verified badge.", table_cell),
         Paragraph("Valid / Fake / Unsigned badge", table_cell)],
        [Paragraph("<b>4. Decision Engine</b>", table_cell_bold), 
         Paragraph("Combines all 3 checks. Never opens the link automatically. Shows a clear Green (SAFE), Yellow (SUSPICIOUS), or Red (BLOCK) screen.", table_cell),
         Paragraph("SAFE / SUSPICIOUS / BLOCK banner", table_cell)]
    ]
    t_layers = Table(layers_data, colWidths=[90, 294, 120])
    t_layers.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg]),
        ('VALIGN', (0,0), (-1,-1), 'TOP')
    ]))
    story.append(t_layers)
    story.append(Spacer(1, 6))

    # 3. Technologies Used
    story.append(Paragraph("3. Technologies Used (High-Level Overview)", h1_style))
    tech_data = [
        [Paragraph("<b>Area</b>", table_header), Paragraph("<b>Technology / Tool</b>", table_header), Paragraph("<b>Why We Used It (Plain Reason)</b>", table_header)],
        [Paragraph("Programming", table_cell_bold), Paragraph("Python 3.12", table_cell), Paragraph("Simple, fast to build with, and standard for AI and security projects.", table_cell)],
        [Paragraph("Cryptography", table_cell_bold), Paragraph("Ed25519 (PyCA Cryptography)", table_cell), Paragraph("Very small 64-byte signature that fits neatly inside a QR code without making it dense or hard to scan.", table_cell)],
        [Paragraph("Computer Vision", table_cell_bold), Paragraph("OpenCV & Pillow", table_cell), Paragraph("Industry standard for reading camera pictures and finding sticker edges and cutlines.", table_cell)],
        [Paragraph("Machine Learning", table_cell_bold), Paragraph("LightGBM & Scikit-Learn", table_cell), Paragraph("Lightweight AI that runs in under 3 milliseconds to spot fake links instantly.", table_cell)],
        [Paragraph("Web Server", table_cell_bold), Paragraph("FastAPI & Uvicorn", table_cell), Paragraph("Fast, modern Python web server to connect the scanner to our backend.", table_cell)],
        [Paragraph("Frontend / UI", table_cell_bold), Paragraph("HTML, CSS, JavaScript (Vanilla)", table_cell), Paragraph("Runs right in any phone or laptop browser with camera access without installing bulky software.", table_cell)],
        [Paragraph("Database & Testing", table_cell_bold), Paragraph("SQLite & Pytest", table_cell), Paragraph("Lightweight storage for certified keys; 49 automated tests to ensure everything works.", table_cell)]
    ]
    t_tech = Table(tech_data, colWidths=[80, 140, 284])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg]),
        ('VALIGN', (0,0), (-1,-1), 'TOP')
    ]))
    story.append(t_tech)
    story.append(Spacer(1, 6))

    # 4. How to Present
    story.append(Paragraph("4. How to Present in Front of Your Professor (Simple Guide)", h1_style))
    story.append(Paragraph("Keep your presentation around <b>5 to 7 minutes</b>. Speak confidently and follow these 4 simple steps:", body_style))

    p_step1 = "<b>Step 1: The Problem (1 Min):</b><br/>" \
              "<i>'Good morning Professor. We are Team Black Sparrow. Our project is QRshield. " \
              "When people scan QR codes, their phones open the website without checking. Fraudsters paste physical stickers over real parking meters or send fake payment links. " \
              "Antivirus can't see physical stickers. That's why we created QRshield.'</i>"
    story.append(Paragraph(p_step1, bullet_style))

    p_step2 = "<b>Step 2: How QRshield Solves It (1.5 Min):</b><br/>" \
              "<i>'We check 3 things in parallel before anything opens: " \
              "First, AI checks the URL for scams. " \
              "Second, Computer Vision looks at the camera feed to see if a sticker is pasted over the board, lighting up cutlines in red. " \
              "Third, for official organizations, we check a digital cryptographic signature. If all checks pass, it's SAFE. If tampered, it's BLOCKED.'</i>"
    story.append(Paragraph(p_step2, bullet_style))

    p_step3 = "<b>Step 3: Live Demo (2 Min):</b><br/>" \
              "Show the web app on your laptop (or run <code>run_demo.bat</code>) and click the test buttons:<br/>" \
              "• <b>1. Clean Unsigned:</b> SPIT College link &rarr; Shows <b>SAFE (Green)</b>. Explains normal codes aren't blocked.<br/>" \
              "• <b>2. Phishing URL:</b> Lookalike link &rarr; Shows <b>BLOCK (Red)</b>. Caught by URL AI.<br/>" \
              "• <b>3. Signed City Parking:</b> Real parking QR &rarr; Shows <b>SAFE with 'QRSHIELD CERTIFIED' Badge</b>.<br/>" \
              "• <b>4. Sticker Swap:</b> Sticker pasted on meter &rarr; Shows <b>SUSPICIOUS</b> with red heatmap on sticker edges.<br/>" \
              "• <b>5. Forged Token:</b> Fake signature &rarr; Shows <b>BLOCK</b>. Crypto caught the fake key."
    story.append(Paragraph(p_step3, bullet_style))

    p_step4 = "<b>Step 4: Conclusion & Tests (1 Min):</b><br/>" \
              "<i>'The entire scan runs in less than 0.7 seconds. We have 49 automated unit tests covering security and attack scenarios, all passing.'</i>"
    story.append(Paragraph(p_step4, bullet_style))
    story.append(Spacer(1, 6))

    # 5. Quick Viva Questions
    story.append(Paragraph("5. Likely Questions the Professor Will Ask (Cheat Sheet)", h1_style))
    story.append(Paragraph("<b>Q1: Why use digital signatures inside QR codes?</b><br/>"
                           "<b>Ans:</b> Because anyone can print a fake QR code claiming to be official. A digital signature gives mathematically unbreakable proof of who created the QR code.", body_style))
    story.append(Paragraph("<b>Q2: What if someone copies a real signed QR code and pastes it elsewhere?</b><br/>"
                           "<b>Ans:</b> We include the merchant's location ID and an expiry time inside the code, plus our camera layer (CV) checks if it's pasted as a sticker.", body_style))
    story.append(Paragraph("<b>Q3: Why not just use Google Safe Browsing?</b><br/>"
                           "<b>Ans:</b> Google only knows a bad link hours or days after victims report it. It misses brand-new scams registered today, and it cannot see physical stickers on a wall.", body_style))
    story.append(Spacer(1, 6))

    # 6. Future Plans
    story.append(Paragraph("6. Future Plans (What Can We Do to Make This Better?)", h1_style))
    story.append(Paragraph("• <b>Native Mobile App:</b> Build a direct Android & iOS camera app so users don't need a browser to scan.", bullet_style))
    story.append(Paragraph("• <b>100% Offline On-Device AI:</b> Run the camera and URL checks directly inside the phone without sending images to a server.", bullet_style))
    story.append(Paragraph("• <b>Dynamic Rotating QR Codes:</b> Support moving QR codes (like OTPs that change every 30 seconds) on shop billing screens so nobody can screenshot or reuse them.", bullet_style))
    story.append(Paragraph("• <b>UPI Payment App Partnerships:</b> Integrate directly into Google Pay, PhonePe, and Paytm to verify merchants before money is transferred.", bullet_style))
    story.append(Paragraph("• <b>Public Trust Registry:</b> Allow municipalities and verified stores to register their public keys in an open public ledger.", bullet_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Simplified PDF created at: {output_path}")

if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(out_dir, ".."))
    
    build_simple_pdf(os.path.join(root_dir, "docs", "QRshield_ISE2_Presentation_Guide.pdf"))
    build_simple_pdf(os.path.join(root_dir, "QRshield_ISE2_Presentation_Guide.pdf"))
