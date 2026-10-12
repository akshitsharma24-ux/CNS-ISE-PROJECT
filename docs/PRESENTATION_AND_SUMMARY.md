# QRshield 🛡️ — Project Summary & Presentation Guide
**Course:** Cryptography & Network Security (CE305 / CS305)  
**Evaluation:** ISE-2 Presentation & Evaluation | Sardar Patel Institute of Technology (SPIT), Mumbai  
**Team:** Black Sparrow (10 Members) | **Team Leader:** Akshit Sharma  
**Ready PDF:** [QRshield_ISE2_Presentation_Guide.pdf](../QRshield_ISE2_Presentation_Guide.pdf)

---

## 1. The Problem in Plain English

When a person scans a QR code with their mobile phone, the phone **blindly opens the website or payment app**. Scammers exploit this behavior through **Quishing (QR Phishing)**:

1. **Fake Links (Zero-Day Phishing):** Scammers create brand-new websites (e.g. `secure-phonepe-refund.xyz`) that haven't been blacklisted by Google yet.
2. **Physical Sticker Swapping:** Fraudsters print paper or vinyl stickers and paste them directly over real QR codes on parking meters, restaurant tables, or shop payment stands. **Traditional antivirus tools cannot see a physical sticker on a wall.**
3. **No Proof of Origin:** Anyone with a printer can make a QR code claiming to be from a bank or municipal office because regular QR codes have no digital signatures.

---

## 2. What We Have Built (The 3-Layer Solution)

Instead of "scan and auto-open", QRshield enforces **"scan, verify, then decide"** by running three simple checks before opening anything:

* **Layer 1: Link Inspection (Machine Learning):**  
  Checks if the web link is a fake lookalike (e.g., misspelled brand names like `ph0nepe`, suspicious `.xyz` domains, or brand-new domains) without opening the dangerous page.
* **Layer 2: Camera Sticker Check (Computer Vision):**  
  Analyzes the camera picture of the QR code to detect if someone pasted an adhesive sticker over the original placard. It finds sticker cut edges and subtle micro-shadows, and lights them up in red on a visual heatmap.
* **Layer 3: Digital Signatures (Cryptography):**  
  Genuine organizations (like Smart City Parking) digitally sign their QR codes. When scanned, QRshield checks the digital signature against a trusted authority. If verified, it gives a green **"QRSHIELD CERTIFIED"** badge.
* **Decision Engine & Web App:**  
  Combines all three checks and displays a clear **SAFE (Green)**, **SUSPICIOUS (Yellow)**, or **BLOCK (Red)** banner. The link is locked so it never auto-opens dangerously.

---

## 3. Technologies Used (Simplified)

| Area | Technology | Why We Used It |
|---|---|---|
| **Programming** | Python 3.12 | Standard language for security, AI, and rapid application development. |
| **Digital Signatures** | Ed25519 Cryptography | Creates tiny 64-byte signatures that fit easily inside QR codes without making them dense or hard to scan. |
| **Camera & Vision** | OpenCV | Standard tool for reading camera pictures and detecting sticker edges and cutlines. |
| **Machine Learning** | LightGBM / Scikit-Learn | Super-fast AI model (runs in under 3 ms) that spots fake URLs and typosquatting. |
| **Web Server** | FastAPI & Uvicorn | High-speed Python server to connect the camera app to our security checks. |
| **User Interface** | HTML, CSS, JavaScript | Clean web app that runs in any browser with camera support; no app installation needed. |
| **Testing** | Pytest | 49 automated security tests that verify everything works properly. |

---

## 4. How to Present to Your Professor (5-Minute Script)

Follow these simple steps in front of your professor:

### Step 1: The Problem (1 Minute)
> *"Good morning, Professor. We are Team Black Sparrow, and our project is **QRshield**.*  
> *When people scan QR codes today, phones blindly open whatever link is inside. Scammers take advantage of this by pasting fake QR stickers over real parking meters and payment stands, or by creating lookalike scam links.*  
> *Traditional antivirus can only check links on the internet—it has no idea if someone pasted a physical sticker over a billboard. That's the problem we solve."*

### Step 2: How It Works (1.5 Minutes)
> *"QRshield runs three simple checks before opening any link:*  
> *1. First, an AI model checks if the link looks like a scam or brand typosquat.*  
> *2. Second, computer vision checks the camera image to see if a physical sticker is pasted over the original placard, showing a red heatmap on the edges.*  
> *3. Third, for official organizations, we verify a digital cryptographic signature. If the signature matches our trusted authority, it proves the code is genuine.*  
> *Finally, our system gives a clear Green (Safe), Yellow (Suspicious), or Red (Block) verdict, and it never opens the link automatically."*

### Step 3: Live Demonstration (2 Minutes)
Open the app on your laptop or phone (`http://localhost:8000`) and click the quick-test buttons:
1. **Click '1. Clean Unsigned':** Show that normal websites (like college portals) show **SAFE (Green)** and are not wrongly blocked.
2. **Click '2. Phishing URL':** Show that scam lookalike links show **BLOCK (Red)** because our link AI caught it.
3. **Click '3. Signed City Parking':** Show a genuine parking QR code that displays **SAFE with a 'QRSHIELD CERTIFIED' badge** because its digital signature verified.
4. **Click '4. Physical Sticker Swap':** Show a code where a sticker was pasted over the meter. The system marks it **SUSPICIOUS/BLOCK** and displays the red heatmap highlighting the sticker edges.
5. **Click '5. Forged Token':** Show an attacker trying to use a fake signature; the crypto layer blocks it immediately.

### Step 4: Wrap-up & Test Suite (30 Seconds)
> *"The whole scan runs in under 0.7 seconds. We also built an automated test suite of 49 security and attack tests, and all 49 are currently passing."*

---

## 5. Likely Viva Questions & Simple Answers

* **Q1: Why do we need digital signatures in QR codes?**  
  *Answer:* Because anyone can print a fake QR code claiming to be official. Digital signatures give mathematically unbreakable proof of who created the code.
* **Q2: What if an attacker copies a real signed QR code and pastes it somewhere else?**  
  *Answer:* The code includes an expiration time and a registered location ID. Plus, our camera layer (CV) checks whether a sticker has been physically pasted.
* **Q3: Why not just use Google Safe Browsing?**  
  *Answer:* Google's list only knows a link hours or days after victims report it. It misses brand-new scam links, and it cannot see physical stickers on a wall.

---

## 6. Future Plans (How to Make This Better)

1. **Native Mobile App:** Build an Android / iOS app so users don't need a browser.
2. **100% Offline Scanning:** Run the AI and camera checks directly inside the phone so it works without internet.
3. **Dynamic QR Codes:** Support rolling QR codes (changing every 30 seconds, like OTPs) on shop payment screens so no one can copy them.
4. **UPI App Partnerships:** Integrate directly with apps like Google Pay, PhonePe, and Paytm to verify merchants before money transfers.
