"""
M4: Aggregation and Scoring Engine Module
Exposes engine.decide(url_res, cv_res, sig_res) contract.
"""
from qrshield.engine.decide import decide
from qrshield.engine.reasons import generate_reasons

__all__ = ["decide", "generate_reasons"]
