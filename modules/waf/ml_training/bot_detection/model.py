"""
Enterprise CyberNexus — Bot Detection Model (XGBoost)

Classifies HTTP sessions into:
  0 = legitimate_user
  1 = headless_browser    (Puppeteer, Playwright)
  2 = scraping_bot        (Scrapy, custom scrapers)
  3 = vulnerability_scanner (Nikto, Burp Scanner, OWASP ZAP)
  4 = spam_bot            (form fillers, credential stuffers)

Features
--------
Network-level (from FlowTracker / InspectionContext):
  request_rate          — requests per second in this session
  iat_variance          — inter-arrival time variance (bots are too regular)
  session_duration      — seconds since first request
  unique_endpoints      — number of distinct URL paths accessed

HTTP-level (computed from requests):
  user_agent_entropy    — Shannon entropy of User-Agent string
  header_count          — number of HTTP headers
  accept_language_valid — 1.0 if Accept-Language looks real, else 0.0
  cookie_count          — number of cookies present
  referer_present       — 1.0 if Referer header present
  method_diversity      — number of distinct HTTP methods used

Dependencies:
  pip install xgboost scikit-learn joblib
"""

import os
import logging
from typing import Dict, Optional, Tuple
import math

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Feature helpers
# ──────────────────────────────────────────────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    h = 0.0
    for c in freq.values():
        p = c / total
        h -= p * math.log2(p)
    return h / 8.0   # normalize


COMMON_LANGUAGES = {
    'en', 'ar', 'fr', 'de', 'es', 'zh', 'ja', 'ko', 'pt', 'ru',
    'it', 'nl', 'pl', 'tr', 'vi', 'th', 'sv', 'da', 'fi', 'no',
}


def is_valid_accept_language(header_value: str) -> bool:
    """Check if Accept-Language looks like a real browser value."""
    if not header_value:
        return False
    parts = [p.strip().split(';')[0].strip().lower()[:2]
             for p in header_value.split(',')]
    return any(p in COMMON_LANGUAGES for p in parts)


# ──────────────────────────────────────────────
#  Feature extraction
# ──────────────────────────────────────────────

def extract_bot_features(
    request_rate:        float,
    iat_variance:        float,
    session_duration:    float,
    unique_endpoints:    int,
    user_agent:          str,
    header_count:        int,
    accept_language:     str,
    cookie_count:        int,
    referer_present:     bool,
    method_diversity:    int,
) -> Dict[str, float]:
    """
    Pack all inputs into the feature dict expected by the XGBoost model.
    All values normalised to [0, ∞) — XGBoost handles scaling internally.
    """
    return {
        "request_rate":          float(request_rate),
        "iat_variance":          float(iat_variance),
        "session_duration":      float(session_duration),
        "unique_endpoints":      float(unique_endpoints),
        "user_agent_entropy":    _entropy(user_agent),
        "header_count":          float(header_count),
        "accept_language_valid": 1.0 if is_valid_accept_language(accept_language) else 0.0,
        "cookie_count":          float(cookie_count),
        "referer_present":       1.0 if referer_present else 0.0,
        "method_diversity":      float(method_diversity),
    }

FEATURE_ORDER = [
    "request_rate", "iat_variance", "session_duration", "unique_endpoints",
    "user_agent_entropy", "header_count", "accept_language_valid",
    "cookie_count", "referer_present", "method_diversity",
]

BOT_LABELS = [
    "legitimate_user",
    "headless_browser",
    "scraping_bot",
    "vulnerability_scanner",
    "spam_bot",
]


# ──────────────────────────────────────────────
#  BotDetectionModel
# ──────────────────────────────────────────────

class BotDetectionModel:
    """
    XGBoost bot classifier.

    Usage:
        model = BotDetectionModel(model_path='ml/models/waf/bot_model.json')
        score, label = model.predict(features)
    """

    def __init__(self, model_path: Optional[str] = None):
        self._model = None

        if model_path and os.path.exists(model_path):
            self._load(model_path)

    def _load(self, path: str) -> None:
        try:
            import xgboost as xgb
            self._model = xgb.XGBClassifier()
            self._model.load_model(path)
            logger.info("✅ BotDetectionModel loaded from %s", path)
        except ImportError:
            logger.warning("xgboost not installed — pip install xgboost")
        except Exception as e:
            logger.error("Failed to load BotDetectionModel: %s", e)

    def predict(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Predict whether the session is a bot.

        Returns:
            (bot_score, label)
            bot_score: 0.0 = human, 1.0 = definite bot
        """
        if self._model is None:
            return 0.0, "legitimate_user"

        try:
            import numpy as np
            x = np.array([[features.get(f, 0.0) for f in FEATURE_ORDER]])
            probs     = self._model.predict_proba(x)[0]       # shape: (num_classes,)
            bot_score = 1.0 - probs[0]                         # 1 - P(legitimate)
            best_cls  = int(probs.argmax())
            label     = BOT_LABELS[best_cls] if best_cls < len(BOT_LABELS) else "unknown"
            return float(bot_score), label
        except Exception as e:
            logger.error("BotDetectionModel.predict error: %s", e)
            return 0.0, "legitimate_user"

    def is_loaded(self) -> bool:
        return self._model is not None
