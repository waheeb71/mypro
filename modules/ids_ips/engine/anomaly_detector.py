"""
Anomaly Detector Module
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import logging
import os
import importlib

logger = logging.getLogger(__name__)

@dataclass
class TrafficFeatures:
    """Features extracted from traffic for analysis (21 features)"""
    # --- Original 14 features ---
    packets_per_second: float
    bytes_per_second: float
    avg_packet_size: float
    packet_size_variance: float
    tcp_ratio: float
    udp_ratio: float
    syn_ratio: float
    unique_dst_ports: int
    unique_src_ports: int
    inter_arrival_time_mean: float
    inter_arrival_time_variance: float
    failed_connections: int
    connection_attempts: int
    reputation_score: float
    # --- 7 new features (added based on CICIDS2017 / research gaps) ---
    flow_duration: float = 0.0           # seconds; detects Slowloris/slow attacks
    payload_entropy: float = 0.5         # Shannon entropy [0-1]; detects encrypted exfil/malware
    upload_download_ratio: float = 1.0   # bytes_sent/bytes_recv; detects exfiltration
    fin_rst_ratio: float = 0.0           # (FIN+RST)/total pkts; detects failed/reset connections
    max_packet_size: int = 0             # largest packet in flow; detects fragmentation/tunneling
    small_packet_ratio: float = 0.0      # pkts<100B / total; detects C2 beaconing
    ack_ratio: float = 0.0               # ACK/total pkts; important for TCP handshake analysis

@dataclass
class AnomalyResult:
    """Result of anomaly detection"""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    details: Dict[str, float]

class AnomalyDetector:
    """
    ML-based Anomaly Detector
    """
    
    def __init__(self, contamination: float = 0.1, model_path: Optional[str] = None, l7_model_path: Optional[str] = None):
        self.contamination = contamination
        self.model = None
        self.model_type = None
        self.l7_model = None
        self.l7_model_type = None
        self.scaler = None # Stub for feature scaling
        self.anomalies_detected = 0
        logger.info(f"AnomalyDetector initialized with contamination={contamination}")
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path, is_l7=False)
            
        if l7_model_path and os.path.exists(l7_model_path):
            self.load_model(l7_model_path, is_l7=True)
    
    def load_model(self, model_path: str, is_l7: bool = False):
        """Dynamically load an ONNX, Pickle, or Joblib model"""
        try:
            ext = os.path.splitext(model_path)[1].lower()
            model_obj = None
            mod_type = None
            
            if ext == ".onnx":
                import onnxruntime as ort
                model_obj = ort.InferenceSession(model_path)
                mod_type = "onnx"
                logger.info(f"Loaded ONNX model from {model_path}")
            elif ext in [".pkl", ".pickle"]:
                import pickle
                with open(model_path, 'rb') as f:
                    model_obj = pickle.load(f)
                mod_type = "sklearn"
                logger.info(f"Loaded Pickle model from {model_path}")
            elif ext == ".joblib":
                import joblib
                model_obj = joblib.load(model_path)
                mod_type = "sklearn"
                logger.info(f"Loaded Joblib model from {model_path}")
            else:
                logger.warning(f"Unsupported model extension {ext} for {model_path}")
                return
                
            if is_l7:
                self.l7_model = model_obj
                self.l7_model_type = mod_type
            else:
                self.model = model_obj
                self.model_type = mod_type
                
        except ImportError as ie:
            logger.error(f"Missing dependency to load module: {ie}. Install onnxruntime/joblib.")
        except Exception as e:
            logger.error(f"Failed to load anomaly model {model_path}: {e}")

    def _extract_features_array(self, features: TrafficFeatures) -> list:
        """Convert dataclass features to a 21-element numerical array suitable for ML"""
        return [
            # Original 14
            features.packets_per_second,
            features.bytes_per_second,
            features.avg_packet_size,
            features.packet_size_variance,
            features.tcp_ratio,
            features.udp_ratio,
            features.syn_ratio,
            features.unique_dst_ports,
            features.unique_src_ports,
            features.inter_arrival_time_mean,
            features.inter_arrival_time_variance,
            features.failed_connections,
            features.connection_attempts,
            features.reputation_score,
            # 7 new features
            features.flow_duration,
            features.payload_entropy,
            features.upload_download_ratio,
            features.fin_rst_ratio,
            features.max_packet_size,
            features.small_packet_ratio,
            features.ack_ratio,
        ]

    def detect(self, features: TrafficFeatures) -> AnomalyResult:
        """
        Detect anomalies in traffic features
        
        Args:
            features: Extracted traffic features
            
        Returns:
            AnomalyResult object
        """
        # Optional L7 DPI Classification
        l7_result = None
        if self.l7_model:
            try:
                import numpy as np
                feature_array = self._extract_features_array(features)
                X = np.array([feature_array], dtype=np.float32)
                
                label = self.l7_model.predict(X)[0]
                # Assuming label encodes string output or specific int, e.g. 'normal', 'web_attack', 'brute_force'
                if hasattr(self.l7_model, "predict_proba"):
                    proba = self.l7_model.predict_proba(X)[0]
                    confidence = float(np.max(proba))
                else:
                    confidence = 0.9
                    
                l7_result = {
                    "classification": str(label),
                    "confidence": confidence
                }
            except Exception as e:
                logger.error(f"L7 Inference failed: {e}")

        # If a real model is loaded, use it bridging traffic logic to ML inference
        if self.model:
            try:
                feature_array = self._extract_features_array(features)
                
                # Convert feature list to the correct format and scale if needed
                import numpy as np
                X = np.array([feature_array], dtype=np.float32)
                
                if self.scaler:
                    X = self.scaler.transform(X)

                if self.model_type == "onnx":
                    input_name = self.model.get_inputs()[0].name
                    ort_outs = self.model.run(None, {input_name: X})
                    label = ort_outs[0][0]
                    anomaly_score = float(ort_outs[1][0] if len(ort_outs) > 1 else 0.5) 
                    is_anomaly = bool(label == -1 or label == 1) 
                    
                elif self.model_type == "sklearn":
                    # sklearn IF: 1 for inliers, -1 for outliers
                    label = self.model.predict(X)[0]
                    is_anomaly = bool(label == -1)
                    
                    if hasattr(self.model, "score_samples"):
                        anomaly_score = float(-self.model.score_samples(X)[0])
                    else:
                        anomaly_score = 0.8 if is_anomaly else 0.1
                
                details = {"ml_confidence": anomaly_score, "model_type": self.model_type}
                if l7_result:
                    details["l7_classification"] = l7_result["classification"]
                    details["l7_confidence"] = l7_result["confidence"]
                    
                    # Override anomaly status if L7 explicitly states it's an attack
                    if l7_result["classification"] != "normal" and l7_result["confidence"] > 0.8:
                        is_anomaly = True
                        anomaly_score = max(anomaly_score, l7_result["confidence"])
                
                if is_anomaly:
                    self.anomalies_detected += 1
                
                return AnomalyResult(
                    is_anomaly=is_anomaly,
                    anomaly_score=anomaly_score,
                    confidence=0.9 if is_anomaly else 0.95,
                    details=details
                )

            except Exception as e:
                logger.error(f"ML Inference failed, falling back to heuristics: {e}")

        # Fallback Heuristics if no model is loaded or if inference fails
        score = 0.0
        # High failure rate or very high packet rate might be anomalous
        score = 0.0
        details = {}
        
        if features.failed_connections > 100:
            score += 0.4
            details['high_failed_connections'] = features.failed_connections
            
        if features.packets_per_second > 10000:
            score += 0.3
            details['high_pps'] = features.packets_per_second
            
        if features.reputation_score < 50:
            score += 0.3
            details['low_reputation'] = features.reputation_score
            
        is_anomaly = score > 0.5
        
        if is_anomaly:
            self.anomalies_detected += 1
            
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=score,
            confidence=0.8 if is_anomaly else 0.9,
            details=details
        )
        
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about anomaly detection.
        
        Returns:
            Dictionary containing statistics.
        """
        return {
            'anomalies_detected': self.anomalies_detected
        }
