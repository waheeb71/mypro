import pytest
from system.ml_core.anomaly_detector import AnomalyDetector, TrafficFeatures

def test_anomaly_heuristics():
    detector = AnomalyDetector()
    
    # Normal traffic
    normal_features = TrafficFeatures(
        packets_per_second=100,
        bytes_per_second=150000,
        avg_packet_size=1500,
        packet_size_variance=50,
        tcp_ratio=0.8,
        udp_ratio=0.2,
        syn_ratio=0.1,
        unique_dst_ports=5,
        unique_src_ports=100,
        inter_arrival_time_mean=0.01,
        inter_arrival_time_variance=0.005,
        failed_connections=2,
        connection_attempts=100,
        reputation_score=100.0 
    )
    result = detector.detect(normal_features)
    assert not result.is_anomaly
    
    # Anomalous traffic (high failed connections, high pps, and low reputation)
    anomalous_features = TrafficFeatures(
        packets_per_second=15000,
        bytes_per_second=15000000,
        avg_packet_size=1000,
        packet_size_variance=50,
        tcp_ratio=0.9,
        udp_ratio=0.1,
        syn_ratio=0.8,
        unique_dst_ports=5,
        unique_src_ports=15000,
        inter_arrival_time_mean=0.0001,
        inter_arrival_time_variance=0.00005,
        failed_connections=1000,
        connection_attempts=15000,
        reputation_score=10.0 
    )
    result = detector.detect(anomalous_features)
    assert result.is_anomaly
    assert result.details.get('high_failed_connections') is not None
    assert result.details.get('high_pps') is not None
    assert result.details.get('low_reputation') is not None
