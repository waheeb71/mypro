"""
Enterprise NGFW v2.0 - Data Loss Prevention (DLP)

DLP engine for detecting and preventing sensitive data leakage.
"""

from .dlp_engine import DLPEngine, DLPRule, DataClassification
from .patterns import SensitiveDataPatterns

__all__ = [
    'DLPEngine',
    'DLPRule',
    'DataClassification',
    'SensitiveDataPatterns'
]