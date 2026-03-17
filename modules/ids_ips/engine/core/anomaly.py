"""
IPS Anomaly Detection
Bridge to ML module.
"""

import sys
import os

# Adjust path to import from root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

# Import from existing ML module
# from system.ml_core.anomaly_detector import AnomalyDetector as MLAnomalyDetector

class AnomalyBridge:
    """Bridge Policy Engine to ML Module"""
    
    def __init__(self):
        # self.detector = MLAnomalyDetector()
        pass
        
    def check(self, flow_stats: dict) -> bool:
        # return self.detector.predict(flow_stats)
        return False
