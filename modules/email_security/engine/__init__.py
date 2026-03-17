"""
Enterprise NGFW — Email Security Sub-Package

AI-Powered Email Threat Detection:
  - engine/core/settings.py         : YAML-driven config loader
  - engine/utils/preprocessor.py    : MIME parsing + content extraction
  - engine/scanners/phishing_detector.py : AI/heuristic phishing analysis
  - engine/scanners/url_scanner.py       : URL extraction + reputation check
  - engine/scanners/attachment_guard.py  : Extension + MIME type + entropy scan
  - engine/scanners/sender_reputation.py : SPF, DKIM, DMARC + IP reputation
  - engine/scanners/spam_filter.py       : Bayesian / heuristic spam scoring
  - engine/core/risk_engine.py       : Weighted score aggregator + policy decision
  - engine/core/email_inspector.py   : Main InspectorPlugin — 7-layer pipeline
"""

from modules.email_security.engine.core.settings          import EmailSettings, get_email_settings
from modules.email_security.engine.utils.preprocessor      import EmailPreprocessor
from modules.email_security.engine.scanners.phishing_detector import PhishingDetector
from modules.email_security.engine.scanners.url_scanner       import URLScanner
from modules.email_security.engine.scanners.attachment_guard  import AttachmentGuard
from modules.email_security.engine.scanners.sender_reputation import SenderReputation
from modules.email_security.engine.scanners.spam_filter       import SpamFilter
from modules.email_security.engine.core.risk_engine       import EmailRiskEngine, EmailPolicyDecision
from modules.email_security.engine.core.email_inspector   import EmailInspectorPlugin

__all__ = [
    "EmailSettings", "get_email_settings",
    "EmailPreprocessor",
    "PhishingDetector",
    "URLScanner",
    "AttachmentGuard",
    "SenderReputation",
    "SpamFilter",
    "EmailRiskEngine", "EmailPolicyDecision",
    "EmailInspectorPlugin",
]
