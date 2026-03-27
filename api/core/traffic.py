from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime, timedelta
from api.rest.auth import require_admin, verify_token

router = APIRouter(prefix="/api/v1", tags=["traffic"])

class TrafficStats(BaseModel):
    timestamp: datetime
    total_packets: int
    total_bytes: int
    blocked_packets: int
    allowed_packets: int
    unique_sources: int
    unique_destinations: int
    top_protocols: Dict[str, int]

class AnomalyReport(BaseModel):
    timestamp: datetime
    src_ip: str
    anomaly_score: float
    is_anomaly: bool
    reason: str
    confidence: float

@router.get("/statistics", response_model=TrafficStats)
async def get_traffic_statistics(
    request: Request,
    time_window: int = 300,
    token: dict = Depends(verify_token)
):
    """Get traffic statistics for specified time window"""
    return TrafficStats(
        timestamp=datetime.now(),
        total_packets=1000000,
        total_bytes=500000000,
        blocked_packets=5000,
        allowed_packets=995000,
        unique_sources=500,
        unique_destinations=1000,
        top_protocols={"TCP": 800000, "UDP": 150000, "ICMP": 50000}
    )

@router.get("/anomalies", response_model=List[AnomalyReport])
async def get_anomalies(
    request: Request,
    limit: int = 100,
    token: dict = Depends(verify_token)
):
    """Get recent anomaly detections"""
    # Mock data for ML Anomaly Insights and eBPF Blocks
    return [
        AnomalyReport(
            timestamp=datetime.now() - timedelta(minutes=2),
            src_ip="192.168.1.100",
            anomaly_score=0.98,
            is_anomaly=True,
            reason="Layer 6: DDoS SYN Flood Detected (eBPF Blocked)",
            confidence=0.99
        ),
        AnomalyReport(
            timestamp=datetime.now() - timedelta(minutes=15),
            src_ip="10.0.0.5",
            anomaly_score=0.85,
            is_anomaly=True,
            reason="Analytics: High volume data exfiltration pattern",
            confidence=0.88
        ),
        AnomalyReport(
            timestamp=datetime.now() - timedelta(hours=1),
            src_ip="203.0.113.45",
            anomaly_score=0.92,
            is_anomaly=True,
            reason="eBPF Fast Path: Malicious IP Match",
            confidence=0.95
        )
    ]

@router.get("/profiles/{ip_address}")
async def get_ip_profile(
    request: Request,
    ip_address: str,
    token: dict = Depends(verify_token)
):
    """Get behavioral profile for an IP address"""
    return {
        "ip": ip_address,
        "reputation_score": 85.0,
        "total_connections": 1000,
        "patterns_detected": [],
        "first_seen": datetime.now() - timedelta(days=7),
        "last_seen": datetime.now()
    }
