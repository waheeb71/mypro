#!/usr/bin/env python3
"""
Enterprise CyberNexus - Deep Learning Module

Neural network models for traffic analysis:
- DeepTrafficClassifier: CNN/LSTM for traffic pattern classification
- PacketSequenceAnalyzer: Sequence-based threat detection

Supports ONNX and TorchScript model formats.
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class ThreatCategory(Enum):
    """Traffic threat categories"""
    NORMAL = "normal"
    DDOS = "ddos"
    SCANNING = "scanning"
    EXFILTRATION = "exfiltration"
    C2_COMMUNICATION = "c2_communication"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """Result of traffic classification"""
    category: ThreatCategory
    confidence: float
    probabilities: Dict[str, float]
    model_name: str
    latency_ms: float = 0.0


@dataclass
class SequenceAnalysis:
    """Result of packet sequence analysis"""
    is_threat: bool
    threat_type: Optional[ThreatCategory]
    confidence: float
    anomaly_score: float
    pattern_description: str


class DeepTrafficClassifier:
    """
    CNN/LSTM Traffic Pattern Classifier

    Uses a pretrained neural network to classify traffic patterns
    into threat categories. Falls back to heuristic rules if no
    model is loaded.
    """

    FEATURE_NAMES = [
        # --- Original 14 ---
        'pps', 'bps', 'avg_size', 'size_var', 'tcp_ratio', 'udp_ratio',
        'syn_ratio', 'unique_dst', 'unique_src', 'iat_mean', 'iat_var',
        'failed_conn', 'conn_attempts', 'reputation',
        # --- 7 new features ---
        'flow_duration',        # seconds; Slowloris + slow attacks
        'payload_entropy',      # Shannon entropy [0-1]; malware/exfil
        'upload_download_ratio',# bytes_out/bytes_in; exfiltration
        'fin_rst_ratio',        # (FIN+RST)/total; failed connections
        'max_packet_size',      # largest pkt; tunneling/fragmentation
        'small_packet_ratio',   # pkts<100B/total; C2 beaconing
        'ack_ratio',            # ACK/total; TCP handshake analysis
    ]

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = model_path
        self._using_fallback = True

        if model_path:
            self._load_model(model_path)

        if self._using_fallback:
            logger.info("DeepTrafficClassifier using heuristic fallback")
        else:
            logger.info(f"DeepTrafficClassifier loaded: {model_path}")

    def _load_model(self, path: str):
        """Load ONNX or TorchScript model"""
        try:
            if path.endswith('.onnx'):
                import onnxruntime as ort
                self.model = ort.InferenceSession(path)
                self._using_fallback = False
            elif path.endswith('.pt') or path.endswith('.pth'):
                import torch
                self.model = torch.jit.load(path)
                self.model.eval()
                self._using_fallback = False
        except ImportError as e:
            logger.warning(f"Model runtime not available: {e}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")

    def classify(self, features: Dict[str, float]) -> ClassificationResult:
        """
        Classify traffic pattern

        Args:
            features: dict with keys matching FEATURE_NAMES

        Returns:
            ClassificationResult with category and confidence
        """
        start = datetime.now()

        if not self._using_fallback and self.model:
            result = self._model_inference(features)
        else:
            result = self._heuristic_classify(features)

        result.latency_ms = (datetime.now() - start).total_seconds() * 1000
        return result

    def _model_inference(self, features: Dict[str, float]) -> ClassificationResult:
        """Run inference with loaded model"""
        try:
            input_array = np.array(
                [features.get(f, 0.0) for f in self.FEATURE_NAMES],
                dtype=np.float32
            ).reshape(1, -1)

            if hasattr(self.model, 'run'):  # ONNX
                input_name = self.model.get_inputs()[0].name
                result = self.model.run(None, {input_name: input_array})
                probs = result[0][0]
            else:  # PyTorch
                import torch
                with torch.no_grad():
                    output = self.model(torch.tensor(input_array))
                    probs = torch.softmax(output, dim=1)[0].numpy()

            categories = list(ThreatCategory)
            cat_idx = int(np.argmax(probs))
            cat = categories[cat_idx] if cat_idx < len(categories) else ThreatCategory.UNKNOWN

            prob_dict = {
                c.value: float(probs[i]) if i < len(probs) else 0.0
                for i, c in enumerate(categories)
            }

            return ClassificationResult(
                category=cat,
                confidence=float(np.max(probs)),
                probabilities=prob_dict,
                model_name='deep_classifier'
            )
        except Exception as e:
            logger.error(f"Model inference error: {e}")
            return self._heuristic_classify(features)

    def _heuristic_classify(self, features: Dict[str, float]) -> ClassificationResult:
        """Heuristic fallback classification using all 21 features"""
        pps           = features.get('pps', 0)
        syn_ratio     = features.get('syn_ratio', 0)
        unique_dst    = features.get('unique_dst', 0)
        failed        = features.get('failed_conn', 0)
        reputation    = features.get('reputation', 100)
        flow_dur      = features.get('flow_duration', 0)        # NEW
        entropy       = features.get('payload_entropy', 0.5)    # NEW
        ul_dl_ratio   = features.get('upload_download_ratio', 1) # NEW
        fin_rst       = features.get('fin_rst_ratio', 0)        # NEW
        small_pkt     = features.get('small_packet_ratio', 0)   # NEW

        scores = {cat: 0.0 for cat in ThreatCategory}
        scores[ThreatCategory.NORMAL] = 0.5

        # --- DDoS (volumetric) ---
        if pps > 10000 and syn_ratio > 0.8:
            scores[ThreatCategory.DDOS] = 0.90
        elif pps > 5000:
            scores[ThreatCategory.DDOS] = 0.55

        # --- Port scanning ---
        if unique_dst > 50 and failed > 20:
            scores[ThreatCategory.SCANNING] = 0.85
        elif unique_dst > 20:
            scores[ThreatCategory.SCANNING] = 0.45

        # --- Brute force ---
        if failed > 100 and fin_rst > 0.4:
            scores[ThreatCategory.BRUTE_FORCE] = 0.85
        elif failed > 50:
            scores[ThreatCategory.BRUTE_FORCE] = 0.65

        # --- NEW: Slowloris / slow HTTP (needs flow_duration) ---
        if flow_dur > 60 and pps < 5 and syn_ratio < 0.1:
            scores[ThreatCategory.DDOS] = max(scores[ThreatCategory.DDOS], 0.75)

        # --- NEW: Data exfiltration (upload_download_ratio + entropy) ---
        if ul_dl_ratio > 5.0 and entropy > 0.7:
            scores[ThreatCategory.EXFILTRATION] = 0.85
        elif ul_dl_ratio > 3.0:
            scores[ThreatCategory.EXFILTRATION] = 0.55

        # --- NEW: C2 beaconing (small packets + regular interval) ---
        if small_pkt > 0.6 and entropy > 0.6:
            scores[ThreatCategory.C2_COMMUNICATION] = 0.75

        # --- Malware (low reputation + high entropy) ---
        if reputation < 30 and entropy > 0.75:
            scores[ThreatCategory.MALWARE] = 0.80
        elif reputation < 30:
            scores[ThreatCategory.MALWARE] = 0.60

        best_cat   = max(scores, key=scores.get)
        best_score = scores[best_cat]

        # Normalize to probabilities
        total = sum(scores.values()) or 1
        probs = {k.value: v / total for k, v in scores.items()}

        return ClassificationResult(
            category=best_cat,
            confidence=best_score,
            probabilities=probs,
            model_name='heuristic_fallback'
        )

    def batch_classify(
        self, features_list: List[Dict[str, float]]
    ) -> List[ClassificationResult]:
        """Batch classification for high throughput"""
        return [self.classify(f) for f in features_list]


class PacketSequenceAnalyzer:
    """
    Sequence-based threat detection

    Analyzes sequences of packets (time series) to detect
    temporal patterns indicating threats like C2 beaconing,
    data exfiltration, or slow attacks.
    """

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._sequences: Dict[str, List[Dict]] = {}
        logger.info(f"PacketSequenceAnalyzer initialized (window={window_size})")

    def add_packet(self, flow_id: str, packet_info: Dict):
        """Add packet to flow sequence"""
        if flow_id not in self._sequences:
            self._sequences[flow_id] = []

        self._sequences[flow_id].append({
            'timestamp': datetime.now().timestamp(),
            'size': packet_info.get('size', 0),
            'direction': packet_info.get('direction', 'out'),
            'flags': packet_info.get('flags', ''),
            'payload_entropy': packet_info.get('payload_entropy', 0.5),  # NEW
            'is_small': packet_info.get('size', 0) < 100,                # NEW: C2 beaconing
        })

        # Keep window size
        if len(self._sequences[flow_id]) > self.window_size:
            self._sequences[flow_id] = self._sequences[flow_id][-self.window_size:]

    def analyze_flow(self, flow_id: str) -> Optional[SequenceAnalysis]:
        """Analyze packet sequence for a flow using all 6 extracted metrics"""
        sequence = self._sequences.get(flow_id, [])

        if len(sequence) < 10:
            return None

        # Extract temporal features
        timestamps = [p['timestamp'] for p in sequence]
        sizes      = [p['size'] for p in sequence]

        # Inter-arrival times
        iats    = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        iat_mean = np.mean(iats)
        iat_std  = np.std(iats)

        # Size analysis
        size_mean = np.mean(sizes)
        size_std  = np.std(sizes)

        # NEW: Payload entropy (mean across sequence)
        entropies     = [p.get('payload_entropy', 0.5) for p in sequence]
        mean_entropy  = np.mean(entropies)

        # NEW: Small packet ratio (C2 beaconing)
        small_count       = sum(1 for p in sequence if p.get('is_small', False))
        small_pkt_ratio   = small_count / len(sequence)

        # Beaconing detection (regular intervals + small packets + moderate entropy)
        is_beaconing   = iat_std < iat_mean * 0.15 and len(sequence) > 20
        beaconing_score = 1.0 - min(iat_std / (iat_mean + 0.001), 1.0)
        # Boost score if also has small packets (typical C2)
        if small_pkt_ratio > 0.5:
            beaconing_score = min(beaconing_score + 0.15, 1.0)

        # Exfiltration (consistent large outbound + high entropy = encrypted exfil)
        outbound    = [p for p in sequence if p['direction'] == 'out']
        out_ratio   = len(outbound) / len(sequence)
        large_out   = [p for p in outbound if p['size'] > 1000]
        exfil_score = (len(large_out) / max(len(outbound), 1)) * out_ratio
        # NEW: Boost exfil score if high entropy (encrypted channel)
        if mean_entropy > 0.75:
            exfil_score = min(exfil_score + 0.20, 1.0)

        # Anomaly score
        anomaly_score = max(beaconing_score * 0.6, exfil_score * 0.8)

        if is_beaconing and beaconing_score > 0.75:
            return SequenceAnalysis(
                is_threat=True,
                threat_type=ThreatCategory.C2_COMMUNICATION,
                confidence=beaconing_score,
                anomaly_score=anomaly_score,
                pattern_description=(
                    f"Regular beaconing detected (interval={iat_mean:.2f}s, "
                    f"small_pkt_ratio={small_pkt_ratio:.0%}, entropy={mean_entropy:.2f})"
                )
            )

        if exfil_score > 0.65:
            return SequenceAnalysis(
                is_threat=True,
                threat_type=ThreatCategory.EXFILTRATION,
                confidence=exfil_score,
                anomaly_score=anomaly_score,
                pattern_description=(
                    f"Data exfiltration pattern ({len(large_out)} large outbound, "
                    f"entropy={mean_entropy:.2f})"
                )
            )

        return SequenceAnalysis(
            is_threat=False,
            threat_type=None,
            confidence=1.0 - anomaly_score,
            anomaly_score=anomaly_score,
            pattern_description="Normal traffic pattern"
        )

    def cleanup_flow(self, flow_id: str):
        """Remove flow sequence data"""
        self._sequences.pop(flow_id, None)

    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        return {
            'tracked_flows': len(self._sequences),
            'avg_sequence_length': np.mean(
                [len(s) for s in self._sequences.values()]
            ) if self._sequences else 0
        }
