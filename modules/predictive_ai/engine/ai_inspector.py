"""
Enterprise NGFW - AI Inspector Plugin

Uses Deep Learning models to classify traffic patterns and detect anomalies.
Integrates with the central DeepTrafficClassifier.
Enriched with real FlowTracker statistics for accurate feature extraction.
"""

import logging
import math
import time
from typing import Optional, Dict, Any, TYPE_CHECKING
from system.inspection_core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, PluginPriority,
    InspectionFinding, InspectionResult, InspectionAction
)
from system.ml_core.deep_learning import DeepTrafficClassifier, ThreatCategory
if TYPE_CHECKING:
    from system.core.flow_tracker import FlowTracker


class AIInspector(InspectorPlugin):
    """
    AI-based Traffic Inspector

    Uses DeepTrafficClassifier to analyze traffic patterns.
    When FlowTracker is injected, real flow statistics are used
    instead of placeholder values — giving the model accurate inputs.
    """

    def __init__(
        self,
        classifier: DeepTrafficClassifier,
        flow_tracker: Optional['FlowTracker'] = None,
        priority: PluginPriority = PluginPriority.NORMAL,
        logger: Optional[logging.Logger] = None
    ):
        super().__init__("ai_inspector", priority, logger)
        self.classifier = classifier
        self.flow_tracker = flow_tracker
        self.threshold = 0.8

    def set_flow_tracker(self, flow_tracker: 'FlowTracker') -> None:
        """Inject FlowTracker after initialization"""
        self.flow_tracker = flow_tracker
        self.logger.info("🔗 AIInspector linked to FlowTracker — real features enabled")

    def can_inspect(self, context: InspectionContext) -> bool:
        return True

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        """Analyze traffic using Deep Learning with real flow statistics"""
        result = InspectionResult(action=InspectionAction.ALLOW)

        features = self._extract_features(context, data)
        classification = self.classifier.classify(features)

        if classification.category != ThreatCategory.NORMAL:
            if classification.confidence >= self.threshold:
                result.action = InspectionAction.BLOCK
                result.findings.append(InspectionFinding(
                    severity='HIGH',
                    category=classification.category.value,
                    description=f"AI detected {classification.category.value} pattern",
                    plugin_name=self.name,
                    confidence=classification.confidence,
                    evidence=classification.probabilities
                ))
                result.metadata['ai_model'] = classification.model_name
                result.metadata['ai_latency_ms'] = classification.latency_ms
                result.metadata['features_source'] = (
                    'flow_tracker' if self.flow_tracker else 'packet_only'
                )

        return result

    def _extract_features(self, context: InspectionContext, data: bytes) -> Dict[str, float]:
        """
        Extract all 21 ML features.

        If FlowTracker is available, uses real accumulated flow statistics.
        Otherwise falls back to packet-level approximation.
        """
        size = len(data)
        is_tcp = 1.0 if context.protocol == 'TCP' else 0.0
        is_udp = 1.0 if context.protocol == 'UDP' else 0.0
        entropy = self._calculate_entropy(data) if size > 0 else 0.0

        # ── Real flow statistics from FlowTracker ──────────────────────────
        if self.flow_tracker and context.flow_id:
            flow = self.flow_tracker.get_flow(context.flow_id)
            if flow:
                duration    = max(flow.duration(), 0.001)  # avoid divide-by-zero
                total_bytes = flow.bytes_sent + flow.bytes_received
                total_pkts  = flow.packets_sent + flow.packets_received or 1

                pps      = total_pkts / duration
                bps      = (total_bytes * 8) / duration
                avg_size = total_bytes / total_pkts
                size_var = abs(size - avg_size)
                conn_att = float(total_pkts)
                reputation = float(context.metadata.get('reputation_score', 100.0))

                # ── New features extracted from FlowTracker ─────────────────
                # upload/download ratio (exfiltration indicator)
                ul_dl_ratio = (
                    flow.bytes_sent / max(flow.bytes_received, 1)
                    if hasattr(flow, 'bytes_sent') else 1.0
                )
                # fin+rst ratio — uses metadata if available, else 0 (conservative)
                fin_rst_ratio = float(context.metadata.get('fin_rst_ratio', 0.0))
                # max packet size seen in this flow
                max_pkt_size  = float(context.metadata.get('max_packet_size', size))
                # small packet ratio (C2 beaconing indicator)
                small_pkt_ratio = float(context.metadata.get('small_packet_ratio', 0.0))
                # ACK ratio
                ack_ratio = float(context.metadata.get('ack_ratio', 0.5))

                self.logger.debug(
                    f"AIInspector [{flow.flow_id}] — REAL 21-feature set: "
                    f"pps={pps:.1f}, bps={bps:.0f}, entropy={entropy:.2f}, "
                    f"flow_dur={duration:.1f}s, ul_dl={ul_dl_ratio:.2f}"
                )

                return {
                    # Original 14
                    'pps':            pps,
                    'bps':            bps,
                    'avg_size':       avg_size,
                    'size_var':       size_var,
                    'tcp_ratio':      is_tcp,
                    'udp_ratio':      is_udp,
                    'syn_ratio':      0.0,
                    'unique_dst':     1.0,
                    'unique_src':     1.0,
                    'iat_mean':       duration / total_pkts,
                    'iat_var':        0.0,
                    'failed_conn':    0.0,
                    'conn_attempts':  conn_att,
                    'reputation':     reputation,
                    # 7 new features
                    'flow_duration':         duration,
                    'payload_entropy':       entropy,        # FIX: was 'entropy' (wrong key)
                    'upload_download_ratio': ul_dl_ratio,
                    'fin_rst_ratio':         fin_rst_ratio,
                    'max_packet_size':       max_pkt_size,
                    'small_packet_ratio':    small_pkt_ratio,
                    'ack_ratio':             ack_ratio,
                }

        # ── Fallback: packet-level approximation ───────────────────────────
        self.logger.debug("AIInspector — using packet-only features (no FlowTracker)")
        reputation = float(context.metadata.get('reputation_score', 100.0))
        return {
            # Original 14
            'pps':            100.0,
            'bps':            size * 8.0,
            'avg_size':       float(size),
            'size_var':       0.0,
            'tcp_ratio':      is_tcp,
            'udp_ratio':      is_udp,
            'syn_ratio':      0.0,
            'unique_dst':     1.0,
            'unique_src':     1.0,
            'iat_mean':       0.1,
            'iat_var':        0.0,
            'failed_conn':    0.0,
            'conn_attempts':  1.0,
            'reputation':     reputation,
            # 7 new features (best estimates from single packet)
            'flow_duration':         0.0,    # unknown without FlowTracker
            'payload_entropy':       entropy, # FIX: was 'entropy' (wrong key)
            'upload_download_ratio': 1.0,    # assume balanced (no history)
            'fin_rst_ratio':         0.0,    # unknown without FlowTracker
            'max_packet_size':       float(size),
            'small_packet_ratio':    1.0 if size < 100 else 0.0,
            'ack_ratio':             float(context.metadata.get('ack_ratio', 0.5)),
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of payload bytes (normalized to [0, 1])"""
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0.0
        total = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        # Normalize: max entropy for 8-bit values = log2(256) = 8.0
        return entropy / 8.0
