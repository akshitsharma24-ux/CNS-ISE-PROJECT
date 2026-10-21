"""
QRshield - scan, verify, then decide.

A three-layer detector for malicious and tampered QR codes ("quishing"):
link analysis (M1) + pasted-sticker check (M2) + Ed25519 signed codes with a mini-PKI (M3),
fused by a rule-first engine (M4) and presented by a web UI (M5).

Team Black Sparrow, SPIT Mumbai.
"""

__version__ = "2.0.0"
