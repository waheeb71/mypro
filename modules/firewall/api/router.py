from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
import logging
from api.rest.auth import require_admin, verify_token, make_permission_checker
from sqlalchemy.orm import Session
from system.database.database import get_db
from modules.firewall.models import FirewallRule as DBFirewallRule, ActionEnum

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["firewall"])

# Admins always pass. Non-admins need a DB rule with resource="firewall".
require_firewall = make_permission_checker("firewall")

class FirewallRuleBase(BaseModel):
    name: str = Field(..., description="Rule Name")
    description: Optional[str] = Field(None, description="Description")
    source_ip: str = Field("any", description="Source IP (CIDR notation)")
    destination_ip: str = Field("any", description="Destination IP (CIDR notation)")
    source_port: str = Field("any", description="Source Port(s)")
    destination_port: str = Field("any", description="Destination Port(s)")
    protocol: str = Field("any", pattern="^(tcp|udp|icmp|any|TCP|UDP|ICMP|ANY)$")
    zone_src: str = Field("any", description="Source Zone (e.g. LAN, WAN)")
    zone_dst: str = Field("any", description="Destination Zone (e.g. DMZ, WAN)")
    app_category: str = Field("any", description="Application Category (e.g. Social Media)")
    file_type: str = Field("any", description="File Type Extension (e.g. EXE, PDF)")
    schedule: str = Field("always", description="Schedule Name (e.g. WorkHours)")
    action: ActionEnum = Field(ActionEnum.ALLOW, description="ALLOW, DROP, REJECT, LOG")
    log_traffic: bool = True
    priority: int = Field(100, ge=1, le=1000)
    enabled: bool = True

class FirewallRuleCreate(FirewallRuleBase):
    pass

class FirewallRuleResponse(FirewallRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class PolicyEvaluation(BaseModel):
    action: str
    confidence: float
    reason: str
    matched_rules: List[str]

@router.get("/rules", response_model=List[FirewallRuleResponse])
async def list_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_firewall)):
    """List all firewall rules"""
    rules = db.query(DBFirewallRule).order_by(DBFirewallRule.priority.asc(), DBFirewallRule.id.asc()).offset(skip).limit(limit).all()
    return rules

@router.post("/rules", response_model=FirewallRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: FirewallRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    """Create a new firewall rule"""
    existing = db.query(DBFirewallRule).filter(DBFirewallRule.name == rule.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule name already exists")
    
    db_rule = DBFirewallRule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    logger.info(f"Created rule {db_rule.id}: {rule.dict()}")
    return db_rule

@router.get("/rules/{rule_id}", response_model=FirewallRuleResponse)
async def get_rule(rule_id: int, db: Session = Depends(get_db), token: dict = Depends(require_firewall)):
    db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return db_rule

@router.put("/rules/{rule_id}", response_model=FirewallRuleResponse)
async def update_rule(
    rule_id: int,
    rule: FirewallRuleCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    update_data = rule.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_rule, key, value)
        
    db.commit()
    db.refresh(db_rule)
    logger.info(f"Updated rule {rule_id}: {rule.dict()}")
    return db_rule

@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_rule = db.query(DBFirewallRule).filter(DBFirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    db.delete(db_rule)
    db.commit()
    logger.info(f"Deleted rule {rule_id}")
    return {"status": "success", "message": "Rule deleted"}

@router.post("/policy/evaluate", response_model=PolicyEvaluation)
async def evaluate_policy(
    request: Request,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    db: Session = Depends(get_db),
    token: dict = Depends(require_firewall),
):
    # This will be integrated with the unified policy evaluator module
    from modules.firewall.engine.evaluator import UnifiedEvaluator
    evaluator = UnifiedEvaluator(db)
    
    # We create a mock context for the evaluation based on the parameters
    context = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 0, # Or pass if necessary
        "dst_port": dst_port,
        "protocol": protocol,
        "interface": "any",
        "app_id": None,
        "domain": None
    }
    
    result = evaluator.evaluate(context)
    
    return PolicyEvaluation(
        action=result.get("action", "ALLOW"), 
        confidence=result.get("confidence", 1.0), 
        reason=result.get("reason", "No specific reason"), 
        matched_rules=[result.get("rule_name")] if result.get("rule_name") else []
    )

@router.post("/block/{ip_address}", status_code=status.HTTP_200_OK)
async def block_ip(
    request: Request,
    ip_address: str,
    duration: int = 3600,
    token: dict = Depends(require_admin)
):
    logger.info(f"Blocking IP {ip_address} for {duration} seconds")
    return {
        "status": "success",
        "ip_address": ip_address,
        "blocked_until": datetime.now() + timedelta(seconds=duration)
    }

@router.delete("/block/{ip_address}", status_code=status.HTTP_204_NO_CONTENT)
async def unblock_ip(request: Request, ip_address: str, token: dict = Depends(require_admin)):
    logger.info(f"Unblocking IP {ip_address}")
    return {"status": "success"}
