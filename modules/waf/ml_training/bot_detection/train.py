"""
Enterprise CyberNexus — Bot Detection Training Script

Trains the XGBoost bot classifier on behavioral session features.

Usage:
    python -m ml.training.bot_detection.train \
        --data datasets/bot_sessions.csv \
        --output ml/models/waf/bot_model.json
Expected CSV columns:
    request_rate, iat_variance, session_duration, unique_endpoints,
    user_agent_entropy, header_count, accept_language_valid,
    cookie_count, referer_present, method_diversity, label

Labels:
    0 = legitimate_user
    1 = headless_browser
    2 = scraping_bot
    3 = vulnerability_scanner
    4 = spam_bot
"""

import argparse
import logging
import os
import random
from typing import List, Tuple

logger = logging.getLogger(__name__)

from modules.waf.ml_training.bot_detection.model import FEATURE_ORDER, BOT_LABELS, extract_bot_features


# ──────────────────────────────────────────────
#  Synthetic data generator (bootstrapping)
# ──────────────────────────────────────────────

def generate_synthetic_sessions(n_per_class: int = 1000) -> Tuple[list, list]:
    """
    Generate synthetic bot/human sessions for training bootstrapping.
    Each class has distinct statistical signatures.
    """
    X, y = [], []

    for _ in range(n_per_class):
        # Class 0: legitimate user — irregular timing, reasonable rate
        X.append(list(extract_bot_features(
            request_rate     = random.uniform(0.1, 3.0),
            iat_variance     = random.uniform(0.5, 5.0),
            session_duration = random.uniform(30, 600),
            unique_endpoints = random.randint(2, 20),
            user_agent       = random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            ]),
            header_count         = random.randint(8, 15),
            accept_language      = random.choice(["en-US,en;q=0.9", "ar-SA,ar;q=0.8"]),
            cookie_count         = random.randint(1, 8),
            referer_present      = random.random() > 0.3,
            method_diversity     = random.randint(1, 3),
        ).values())); y.append(0)

        # Class 1: headless browser — very regular timing, low variance
        X.append(list(extract_bot_features(
            request_rate     = random.uniform(5, 30),
            iat_variance     = random.uniform(0.001, 0.05),   # too regular!
            session_duration = random.uniform(5, 60),
            unique_endpoints = random.randint(20, 100),
            user_agent       = random.choice([
                "HeadlessChrome/110.0", "puppeteer/19.0", ""
            ]),
            header_count         = random.randint(3, 6),      # fewer headers
            accept_language      = "",
            cookie_count         = 0,
            referer_present      = False,
            method_diversity     = 1,
        ).values())); y.append(1)

        # Class 2: scraping bot — high rate, many unique endpoints
        X.append(list(extract_bot_features(
            request_rate     = random.uniform(10, 100),
            iat_variance     = random.uniform(0.01, 0.1),
            session_duration = random.uniform(60, 3600),
            unique_endpoints = random.randint(50, 500),
            user_agent       = random.choice([
                "python-requests/2.28.0", "Scrapy/2.7", "curl/7.87.0"
            ]),
            header_count         = random.randint(2, 5),
            accept_language      = "",
            cookie_count         = random.randint(0, 1),
            referer_present      = False,
            method_diversity     = 1,
        ).values())); y.append(2)

        # Class 3: vulnerability scanner — very high rate, sequential paths
        X.append(list(extract_bot_features(
            request_rate     = random.uniform(50, 500),
            iat_variance     = random.uniform(0.0, 0.02),
            session_duration = random.uniform(10, 300),
            unique_endpoints = random.randint(100, 1000),
            user_agent       = random.choice([
                "Nikto/2.1.6", "sqlmap/1.7", "Mozilla/5.0 (compatible; Burp)"
            ]),
            header_count         = random.randint(4, 8),
            accept_language      = "en",
            cookie_count         = random.randint(0, 2),
            referer_present      = random.random() > 0.7,
            method_diversity     = random.randint(3, 5),    # uses GET POST PUT DELETE
        ).values())); y.append(3)

        # Class 4: spam bot — moderate rate, form focus
        X.append(list(extract_bot_features(
            request_rate     = random.uniform(1, 10),
            iat_variance     = random.uniform(0.1, 1.0),
            session_duration = random.uniform(5, 30),
            unique_endpoints = random.randint(1, 3),
            user_agent       = random.choice([
                "Mozilla/5.0 (compatible)", "spam-bot/1.0", ""
            ]),
            header_count         = random.randint(3, 6),
            accept_language      = "en",
            cookie_count         = random.randint(0, 1),
            referer_present      = random.random() > 0.5,
            method_diversity     = 1,
        ).values())); y.append(4)

    return X, y


# ──────────────────────────────────────────────
#  Training
# ──────────────────────────────────────────────

def train(X: list, y: list, output_path: str) -> None:
    try:
        import xgboost as xgb
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        import numpy as np
    except ImportError:
        logger.error("Missing deps: pip install xgboost scikit-learn")
        return

    X_arr = np.array(X)
    y_arr = np.array(y)

    X_train, X_val, y_train, y_val = train_test_split(
        X_arr, y_arr, test_size=0.1, random_state=42, stratify=y_arr
    )

    model = xgb.XGBClassifier(
        n_estimators     = 300,
        max_depth        = 6,
        learning_rate    = 0.05,
        subsample        = 0.8,
        colsample_bytree = 0.8,
        use_label_encoder= False,
        eval_metric      = 'mlogloss',
        num_class        = len(BOT_LABELS),
        objective        = 'multi:softprob',
        random_state     = 42,
    )

    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=10)

    y_pred = model.predict(X_val)
    logger.info("Validation Report:\n%s",
                classification_report(y_val, y_pred, target_names=BOT_LABELS))

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    model.save_model(output_path)
    logger.info("✅ Bot model saved → %s", output_path)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    parser = argparse.ArgumentParser(description="Train WAF Bot Detection Model")
    parser.add_argument('--data',   default=None,
                        help='Path to labeled session CSV (optional)')
    parser.add_argument('--n',      type=int, default=1000,
                        help='Synthetic samples per class (used if --data absent)')
    parser.add_argument('--output', default='ml/models/waf/bot_model.json')
    args = parser.parse_args()

    if args.data and os.path.exists(args.data):
        import csv
        X, y = [], []
        with open(args.data) as f:
            reader = csv.DictReader(f)
            for row in reader:
                X.append([float(row.get(f, 0)) for f in FEATURE_ORDER])
                y.append(int(row['label']))
        logger.info("Loaded %d samples from %s", len(X), args.data)
    else:
        logger.info("No CSV provided — using synthetic data (%d per class)", args.n)
        X, y = generate_synthetic_sessions(args.n)

    train(X, y, args.output)


if __name__ == '__main__':
    main()
