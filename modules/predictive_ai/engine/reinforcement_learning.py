"""
Enterprise CyberNexus - Reinforcement Learning Policy Optimizer

Uses a pre-trained Q-Learning Q-Table to determine the optimal
auto-response policy (Rate Limiting / Block) based on threat level.
"""

import os
import pickle
import logging
import numpy as np
from typing import Dict, Optional
from enum import Enum

# Path to the RL Q-Table model (centralized in ml/models/)
try:
    from ml.models import get_model_path as _get_model_path
    _RL_MODEL_PATH = _get_model_path('predictive_ai', 'rl_q_table.pkl')
except (FileNotFoundError, ValueError, ImportError):
    _MODULE_DIR = os.path.dirname(os.path.dirname(__file__))
    _RL_MODEL_PATH = os.path.join(_MODULE_DIR, 'models', 'rl_q_table.pkl')

class RLAction(Enum):
    """Available policy actions from the RL agent"""
    NO_LIMIT = 0
    SOFT_LIMIT = 1
    STRICT_LIMIT = 2
    BLOCK = 3

    @property
    def description(self) -> str:
        if self.value == 0: return "No Limit"
        if self.value == 1: return "Soft Limit"
        if self.value == 2: return "Strict Limit"
        if self.value == 3: return "Block"
        return "Unknown"

class RLAutoResponseAgent:
    """
    RL Auto-Response Agent
    
    Determines the optimal rate-limiting or blocking policy based on the current threat level.
    Uses the pre-trained `rl_q_table.pkl` Q-Table.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.q_table = None
        self._load_q_table()

    def _load_q_table(self):
        if not os.path.exists(_RL_MODEL_PATH):
            self.logger.error(f"RL Q-Table model not found at: {_RL_MODEL_PATH}")
            return
        try:
            with open(_RL_MODEL_PATH, 'rb') as f:
                self.q_table = pickle.load(f)
            self.logger.info("RL Q-Table model loaded successfully.")
        except Exception as e:
            self.logger.error(f"Failed to load RL Q-Table model: {e}")

    def get_action_for_threat(self, threat_level: int) -> RLAction:
        """
        Get the optimal action for a given threat level.
        
        Args:
            threat_level (int): 0=Low, 1=Medium, 2=High, 3=Critical
            
        Returns:
            RLAction: The recommended action
        """
        # Fallback if model isn't loaded: heuristic mapping
        if self.q_table is None:
            self.logger.warning("Q-Table not loaded, using heuristic fallback")
            if threat_level == 0: return RLAction.NO_LIMIT
            elif threat_level == 1: return RLAction.SOFT_LIMIT
            elif threat_level == 2: return RLAction.STRICT_LIMIT
            else: return RLAction.BLOCK

        # Ensure threat_level is within bounds (0 to max states in Q-table)
        # We assume the Q-table is a 2D numpy array: shape = (num_states, num_actions)
        try:
            num_states = self.q_table.shape[0]
            state = min(max(int(threat_level), 0), num_states - 1)
            
            # The optimal action is the one with the maximum Q-value for this state
            action_idx = int(np.argmax(self.q_table[state]))
            return RLAction(action_idx)
            
        except Exception as e:
            self.logger.error(f"RL Agent inference failed: {e}")
            # Fallback
            return RLAction.STRICT_LIMIT if threat_level >= 2 else RLAction.NO_LIMIT

    def apply_policy(self, current_policy: Dict, action: RLAction) -> Dict:
        """
        Apply the RL action to a policy mapping dictionary.
        Returns the updated policy limits.
        """
        new_policy = current_policy.copy()
        
        if action == RLAction.NO_LIMIT:
            new_policy['rate_limit'] = 50000
            new_policy['block'] = False
        elif action == RLAction.SOFT_LIMIT:
            new_policy['rate_limit'] = 5000
            new_policy['block'] = False
        elif action == RLAction.STRICT_LIMIT:
            new_policy['rate_limit'] = 500
            new_policy['block'] = False
        elif action == RLAction.BLOCK:
            new_policy['rate_limit'] = 0
            new_policy['block'] = True
            
        return new_policy

