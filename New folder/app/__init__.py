"""
EDR System - Three-Layered Triage Architecture
Advanced Endpoint Detection and Response System

Layers:
- Layer 1: Signature Filter (ClamAV + YARA)
- Layer 2: APSA ML Core (IsolationForest)
- Layer 3: APT Correlation (SQLite + Threat Intel)
"""

__version__ = "1.0.0"
__author__ = "EDR System Team"

# Export main classes for easier imports
from .layer1_scanner import Layer1Scanner
from .layer2_apsa import Layer2APSA
from .layer3_apt import Layer3APT
from .ml_core import MLCore

__all__ = [
    'Layer1Scanner',
    'Layer2APSA',
    'Layer3APT',
    'MLCore'
]
