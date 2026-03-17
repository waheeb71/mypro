from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from datetime import datetime
from system.database.database import Base


class PredictiveAIConfig(Base):
    """
    Dynamic configuration for the Predictive AI module.
    """
    __tablename__ = 'predictive_ai_config'

    id = Column(Integer, primary_key=True, index=True)

    is_active = Column(Boolean, default=True)

    # Forecaster Settings
    enable_forecaster = Column(Boolean, default=True, comment="Enable Attack Forecasting")
    alert_on_high_risk = Column(Boolean, default=True)
    
    # RL Agent Settings
    enable_rl_agent = Column(Boolean, default=True, comment="Enable Reinforcement Learning Auto-Response")
    auto_apply_rl_policy = Column(Boolean, default=False, comment="If true, automatically apply the RL chosen policy (Block/Limit). If false, monitor only.")

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
