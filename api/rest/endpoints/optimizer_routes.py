"""
Enterprise CyberNexus - Smart Firewall Policy Optimizer Endpoints
Provides deterministic, algorithmic analysis of firewall rules to detect
shadowed rules, mergeable rules, dead policies, and sub-optimal ordering.
"""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from api.rest.auth import require_admin
from api.rest.endpoints.config_routes import _read_config, _write_config
from system.firewall.optimizer import (
    FirewallOptimizer,
    DictRuleRepository,
    NullTelemetrySource,
)

router = APIRouter(prefix="/api/v1/optimizer", tags=["Policy Optimization"])
logger = logging.getLogger(__name__)


class ApplyOptimizerRequest(BaseModel):
    # A list of rule IDs to remove based on the optimizer's suggestions.
    delete_rule_ids: List[int] = []


@router.get("/suggestions")
async def get_optimization_suggestions(token: dict = Depends(require_admin)):
    """
    Analyzes the active firewall configuration using the heuristic
    Smart Optimizer and returns explainable, confidence-scored suggestions.
    """
    try:
        config = _read_config("base.yaml")
        active_rules = config.get("firewall", {}).get("rules", [])

        if not active_rules:
            return {"status": "success", "suggestions": [], "message": "No rules configured"}

        repo = DictRuleRepository(active_rules)
        optimizer = FirewallOptimizer(repo, NullTelemetrySource())
        report = optimizer.analyze()
        return report

    except Exception as e:
        logger.error(f"Optimizer analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/apply")
async def apply_optimizations(request: ApplyOptimizerRequest, token: dict = Depends(require_admin)):
    """
    Accepts optimization suggestions (e.g., delete shadowed rules) and updates
    the base.yaml configuration automatically.
    """
    try:
        config = _read_config("base.yaml")
        firewall_cfg = config.get("firewall", {})
        active_rules = firewall_cfg.get("rules", [])
        
        if not active_rules:
            raise HTTPException(status_code=400, detail="No firewall rules exist to modify.")
            
        initial_count = len(active_rules)
        # Filter out the deleted rule IDs
        new_rules = [r for r in active_rules if r.get('id') not in request.delete_rule_ids]
        
        # Ensure rules still have sequential IDs
        for i, rule in enumerate(new_rules):
            rule['id'] = i + 1

        config["firewall"]["rules"] = new_rules
        _write_config(config, "base.yaml")
        
        # Hot reload would ideally happen here by signaling the engine
        return {
            "status": "success", 
            "message": f"Successfully removed {initial_count - len(new_rules)} optimized rules."
        }
    except Exception as e:
        logger.error(f"Optimizer application failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
