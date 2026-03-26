#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise CyberNexus - Unit Tests for ML Inference

Tests for:
- AnomalyDetector: feature extraction, scoring, pattern recognition
- TrafficProfiler: IP profiling, reputation scoring
- AdaptivePolicyEngine: policy adjustments, feedback learning
"""

import pytest
from system.ml_core import (
    AnomalyDetector,
    TrafficFeatures,
    TrafficProfiler,
    AdaptivePolicyEngine
)
from system.ml_core.anomaly_detector import AnomalyResult


@pytest.fixture
def features_normal():
    """Normal traffic features"""
    return TrafficFeatures(
        packets_per_second=100,
        bytes_per_second=50000,
        avg_packet_size=500,
        packet_size_variance=100,
        tcp_ratio=0.7,
        udp_ratio=0.3,
        syn_ratio=0.1,
        unique_dst_ports=5,
        unique_src_ports=10,
        inter_arrival_time_mean=0.01,
        inter_arrival_time_variance=0.001,
        failed_connections=0,
        connection_attempts=10,
        reputation_score=90.0
    )


@pytest.fixture
def features_anomalous():
    """Anomalous traffic features (high failure rate, low reputation)"""
    return TrafficFeatures(
        packets_per_second=50000,
        bytes_per_second=25000000,
        avg_packet_size=64,
        packet_size_variance=10,
        tcp_ratio=0.95,
        udp_ratio=0.05,
        syn_ratio=0.9,
        unique_dst_ports=500,
        unique_src_ports=1,
        inter_arrival_time_mean=0.0001,
        inter_arrival_time_variance=0.00001,
        failed_connections=500,
        connection_attempts=1000,
        reputation_score=10.0
    )


# ==================== Anomaly Detector Tests ====================

class TestAnomalyDetector:
    """Test AnomalyDetector"""

    def setup_method(self):
        self.detector = AnomalyDetector(contamination=0.1)

    def test_initialization(self):
        """Test detector initializes correctly"""
        assert self.detector is not None
        assert self.detector.contamination == 0.1

    def test_detect_normal_traffic(self, features_normal):
        """Test that normal traffic is not flagged"""
        result = self.detector.detect(features_normal)

        assert isinstance(result, AnomalyResult)
        assert isinstance(result.is_anomaly, bool)
        assert 0.0 <= result.anomaly_score <= 1.0
        assert 0.0 <= result.confidence <= 1.0
        # Normal traffic should not be anomalous
        assert result.is_anomaly is False

    def test_detect_anomalous_traffic(self, features_anomalous):
        """Test that anomalous traffic is flagged"""
        result = self.detector.detect(features_anomalous)

        assert isinstance(result, AnomalyResult)
        # Anomalous traffic should be detected
        assert result.is_anomaly is True
        assert result.anomaly_score > 0.5

    def test_detect_returns_details(self, features_anomalous):
        """Test that detection returns details"""
        result = self.detector.detect(features_anomalous)

        assert isinstance(result.details, dict)
        assert len(result.details) > 0

    def test_different_contamination_rates(self):
        """Test with different contamination rates"""
        detector_low = AnomalyDetector(contamination=0.01)
        detector_high = AnomalyDetector(contamination=0.5)

        assert detector_low.contamination == 0.01
        assert detector_high.contamination == 0.5


# ==================== Traffic Profiler Tests ====================

class TestTrafficProfiler:
    """Test TrafficProfiler"""

    def setup_method(self):
        self.profiler = TrafficProfiler(time_window=300)

    def test_initialization(self):
        """Test profiler initializes"""
        assert self.profiler is not None

    def test_profile_connection(self):
        """Test profiling a connection"""
        pattern, confidence = self.profiler.profile_connection(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            bytes_sent=1024,
            packets_sent=5
        )

        assert pattern is not None
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0

    def test_get_ip_profile(self):
        """Test getting IP profile after profiling"""
        # Profile some connections first
        for i in range(5):
            self.profiler.profile_connection(
                src_ip="192.168.1.50",
                dst_ip=f"10.0.0.{i}",
                dst_port=80,
                protocol="TCP",
                bytes_sent=512,
                packets_sent=3
            )

        profile = self.profiler.get_ip_profile("192.168.1.50")
        # Profile may or may not be created depending on min samples
        if profile:
            assert profile.reputation_score is not None

    def test_get_statistics(self):
        """Test getting profiler statistics"""
        stats = self.profiler.get_statistics()
        assert stats is not None
        assert hasattr(stats, 'total_profiles') or isinstance(stats, dict)


# ==================== Adaptive Policy Engine Tests ====================

class TestAdaptivePolicyEngine:
    """Test AdaptivePolicyEngine"""

    def setup_method(self):
        self.engine = AdaptivePolicyEngine(learning_rate=0.1)

    def test_initialization(self):
        """Test engine initializes"""
        assert self.engine is not None

    def test_evaluate_policy(self):
        """Test policy evaluation"""
        action, confidence, reason = self.engine.evaluate(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            anomaly_score=0.1,
            reputation_score=90.0,
            pattern="NORMAL"
        )

        assert action is not None
        assert isinstance(confidence, float)
        assert isinstance(reason, str)

    def test_evaluate_suspicious_traffic(self):
        """Test policy evaluation for suspicious traffic"""
        action, confidence, reason = self.engine.evaluate(
            src_ip="203.0.113.50",
            dst_ip="192.168.1.1",
            dst_port=22,
            protocol="TCP",
            anomaly_score=0.95,
            reputation_score=10.0,
            pattern="SCANNING"
        )

        assert action is not None
        assert confidence > 0.0

    def test_add_feedback(self):
        """Test adding feedback for learning"""
        # Should not raise any exceptions
        self.engine.add_feedback(
            src_ip="192.168.1.100",
            action_taken="ALLOW",
            was_threat=False,
            threat_type=None
        )

    def test_get_metrics(self):
        """Test getting policy metrics"""
        metrics = self.engine.get_metrics()
        assert metrics is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
