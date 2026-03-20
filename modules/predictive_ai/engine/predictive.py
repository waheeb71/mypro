"""
Enterprise NGFW - Predictive Analytics

Provides attack forecasting and trend analysis using
a trained Random Forest Regressor time-series model.
"""

import os
import time
import pickle
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import numpy as np

# ── Resolve the forecaster model path robustly ─────────────────────────────
# The project root is 3 levels above this file:
#   modules/predictive_ai/engine/predictive.py → ../../.. = project root
_THIS_FILE   = os.path.abspath(__file__)
_MODULE_DIR  = os.path.dirname(os.path.dirname(_THIS_FILE))   # modules/predictive_ai/
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_MODULE_DIR)) # <project root>

# Probe in priority order — first match wins
_CANDIDATE_PATHS = [
    os.path.join(_PROJECT_ROOT, 'ml', 'models', 'predictive_ai', 'attack_forecaster.pkl'),
    os.path.join(_MODULE_DIR,   'models', 'attack_forecaster.pkl'),
    # Also attempt via the central registry (may raise if ml.models is not importable)
]

try:
    from ml.models import get_model_path as _get_model_path
    _CANDIDATE_PATHS.insert(0, _get_model_path('predictive_ai', 'attack_forecaster.pkl'))
except Exception:
    pass

# Pick the first file that actually exists on disk
_FORECASTER_MODEL_PATH = next(
    (p for p in _CANDIDATE_PATHS if os.path.exists(p)),
    _CANDIDATE_PATHS[0]   # fall back to first candidate for error message clarity
)


@dataclass
class ForecastResult:
    """Attack forecast result"""
    timestamp: float
    horizon_minutes: int
    predicted_attacks_next_minute: float = 0.0
    risk_level: str = "LOW"
    confidence: float = 0.0

class AttackForecaster:
    """
    Predicts future attacks based on a sliding window of historical data (60 minutes).
    Uses the trained `attack_forecaster.pkl` model.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.model = None
        
        # We need a 60-minute sliding window. 
        # We will keep a count of attacks per minute.
        self.history_window = [0.0] * 60  # Index 0 is t-60, index 59 is t-1
        self.current_minute_attacks = 0.0
        self.last_minute_timestamp = int(time.time() // 60)
        
        self._load_model()
        
    def _load_model(self):
        if not os.path.exists(_FORECASTER_MODEL_PATH):
            self.logger.error(f"Attack Forecaster model not found at: {_FORECASTER_MODEL_PATH}")
            return
        try:
            with open(_FORECASTER_MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
            self.logger.info("Attack Forecaster model loaded successfully.")
        except Exception as e:
            self.logger.error(f"Failed to load Attack Forecaster model: {e}")

    def _update_window(self):
        """Roll the window forward if minutes have passed"""
        current_minute = int(time.time() // 60)
        minutes_passed = current_minute - self.last_minute_timestamp
        
        if minutes_passed > 0:
            if minutes_passed >= 60:
                # Completely flush the window
                self.history_window = [0.0] * 60
            else:
                # Shift the window left by `minutes_passed`
                self.history_window = self.history_window[minutes_passed:] + [0.0] * minutes_passed
                
                # The last completed minute was `self.current_minute_attacks`
                # So we put it in the most recent slot that just passed.
                # If minutes_passed > 1, the intermediate minutes had 0 attacks.
                self.history_window[-minutes_passed] = self.current_minute_attacks
                
            self.current_minute_attacks = 0.0
            self.last_minute_timestamp = current_minute

    def record_attack(self, attack_type: str = "general") -> None:
        """Record an attack occurrence for forecasting."""
        self._update_window()
        self.current_minute_attacks += 1.0

    def forecast(self) -> ForecastResult:
        """Forecast attacks for the next minute."""
        self._update_window()
        
        result = ForecastResult(
            timestamp=time.time(),
            horizon_minutes=1,
            predicted_attacks_next_minute=0.0
        )
        
        if not self.model:
            self.logger.warning("Forecaster model not loaded. Returning empty forecast.")
            return result
            
        try:
            # Prepare feature vector: shape (1, 60)
            X = np.array([self.history_window], dtype=np.float32)
            
            prediction = self.model.predict(X)[0]
            predicted_vol = max(0.0, float(prediction))
            
            result.predicted_attacks_next_minute = predicted_vol
            
            # Determine overall risk level based on predicted volume
            if predicted_vol > 500:
                result.risk_level = "CRITICAL"
            elif predicted_vol > 200:
                result.risk_level = "HIGH"
            elif predicted_vol > 50:
                result.risk_level = "MEDIUM"
            else:
                result.risk_level = "LOW"
                
            result.confidence = 0.77  # From R^2 score
            
        except Exception as e:
            self.logger.error(f"Forecaster prediction failed: {e}")
            
        return result

