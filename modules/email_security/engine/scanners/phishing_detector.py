"""
Enterprise CyberNexus — Phishing Detector

Detects phishing attempts in email subject + body using:
  1. Keyword heuristics (expanded multilingual list)
  2. Urgency / social-engineering pattern matching
  3. Domain spoofing indicators (brand name ≠ link domain)
  4. Optional: NLP model inference (same architecture as WAF NLP)
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

# ── Phishing keyword lists ───────────────────────────────────────────
# (English and Arabic combined — most phishing campaigns use both)

_PHISHING_KEYWORDS = [
    # Account security / urgency
    "verify your account", "confirm your identity", "suspended account",
    "unusual activity", "account locked", "account compromised",
    "click here immediately", "urgent action required", "act immediately",
    "final notice", "last warning",
    # Credentials / password
    "reset your password", "update your credentials", "change your password",
    "confirm your email", "validate your account",
    # Financial
    "wire transfer", "bank account", "credit card", "invoice attached",
    "payment failed", "refund available", "transaction declined",
    # Prizes / social engineering
    "you have won", "congratulations", "claim your reward",
    "you are selected", "lucky winner",
    # Crypto / scam
    "bitcoin", "cryptocurrency", "investment opportunity",
    "double your money", "high returns",
    # Arabic phishing keywords
    "تحقق من حسابك", "تأكيد هويتك", "تم تعليق حسابك",
    "نشاط غير معتاد", "انقر هنا فوراً", "إجراء عاجل",
    "إعادة تعيين كلمة المرور", "تحديث بياناتك",
    "تحويل بنكي", "فاتورة مرفقة", "فرصة استثمارية",
]

# ── Brand impersonation — brand name → common legit domains
_BRAND_DOMAINS = {
    "paypal":    ["paypal.com"],
    "apple":     ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "hotmail.com"],
    "google":    ["google.com", "gmail.com", "accounts.google.com"],
    "amazon":    ["amazon.com", "amazon.co.uk", "amazon.de"],
    "facebook":  ["facebook.com", "fb.com"],
    "netflix":   ["netflix.com"],
    "dhl":       ["dhl.com", "dhl.de"],
    "fedex":     ["fedex.com"],
    "stcpay":    ["stcpay.com.sa"],
    "safat":     ["gov.sa"],
}

# ── Urgency / social engineering patterns ───────────────────────────
_URGENCY_PATTERNS = [
    re.compile(r"\b(within\s+\d+\s+hours?|خلال\s+\d+\s+ساعة|within\s+24h)\b", re.I),
    re.compile(r"\b(immediately|فوراً|urgently|عاجل)\b", re.I),
    re.compile(r"\b(account.{0,20}(suspend|terminat|delet|block))", re.I),
    re.compile(r"\b(click.{0,30}link|انقر.{0,30}الرابط)\b", re.I),
]

_DOMAIN_PATTERN = re.compile(r'https?://([^/\s<>"\']+)', re.I)


@dataclass
class PhishingResult:
    score:            float = 0.0          # 0.0=clean, 1.0=definite phishing
    matched_keywords: List[str] = None
    urgency_flags:    int = 0
    brand_spoof:      str = ""             # e.g. "paypal" spoofed
    decision:         str = "clean"        # clean | suspicious | phishing

    def __post_init__(self):
        if self.matched_keywords is None:
            self.matched_keywords = []


class PhishingDetector:
    """
    AI-enhanced phishing detector.

    Args:
        keyword_threshold: Minimum keyword hits before flagging as phishing
        nlp_enabled:       Use NLP model for deeper analysis
        nlp_model_path:    Path to trained PyTorch model
        custom_keywords:   Additional site-specific phishing keywords
    """

    def __init__(
        self,
        keyword_threshold: int = 2,
        nlp_enabled:       bool = False,
        nlp_model_path:    str = "",
        custom_keywords:   Optional[List[str]] = None,
    ):
        self.keyword_threshold = keyword_threshold
        self.nlp_enabled       = nlp_enabled
        self._nlp_model        = None

        self._keywords = list(_PHISHING_KEYWORDS) + (custom_keywords or [])

        if nlp_enabled and nlp_model_path:
            self._load_nlp(nlp_model_path)

    def _load_nlp(self, path: str) -> None:
        try:
            from ml.training.waf_nlp.model import WAFNLPInference
            self._nlp_model = WAFNLPInference.load(path)
            logger.info("PhishingDetector: NLP model loaded from %s", path)
        except Exception as e:
            logger.warning("PhishingDetector: NLP model not loaded (%s) — using heuristics only", e)

    def detect(self, subject: str, body: str, urls: List[str]) -> PhishingResult:
        """
        Analyse email content for phishing.

        Args:
            subject: Email subject line
            body:    Plain text body
            urls:    All URLs extracted from the email

        Returns:
            PhishingResult with score, matched keywords, and decision
        """
        content = (subject + " " + body).lower()
        result  = PhishingResult()

        # ── 1. Keyword matching ──────────────────────
        matched = [kw for kw in self._keywords if kw.lower() in content]
        result.matched_keywords = matched

        keyword_score = min(len(matched) / max(self.keyword_threshold * 2, 1), 1.0)

        # ── 2. Urgency patterns ──────────────────────
        urgency_hits = sum(1 for p in _URGENCY_PATTERNS if p.search(content))
        result.urgency_flags = urgency_hits
        urgency_score = min(urgency_hits * 0.2, 0.6)

        # ── 3. Brand spoofing: brand name in body ≠ URL domain ──
        spoof_score = 0.0
        for brand, legit_domains in _BRAND_DOMAINS.items():
            if brand in content:
                link_domains = [
                    m.group(1).lower().split("/")[0]
                    for m in _DOMAIN_PATTERN.finditer(content)
                ]
                suspicious_links = [
                    d for d in link_domains
                    if brand in d or any(
                        d != ld and brand in d for ld in legit_domains
                    )
                ]
                # Brand mentioned but URL not from legit domain
                if link_domains and not any(
                    any(ld in d for ld in legit_domains) for d in link_domains
                ):
                    result.brand_spoof = brand
                    spoof_score = 0.7
                    break

        # ── 4. Excessive URLs ────────────────────────
        url_score = 0.0
        if len(urls) > 5:
            url_score = min((len(urls) - 5) * 0.05, 0.3)

        # ── 5. NLP model (optional) ──────────────────
        nlp_score = 0.0
        if self.nlp_enabled and self._nlp_model:
            try:
                nlp_score, _ = self._nlp_model.predict(body[:2000])
            except Exception as e:
                logger.debug("NLP phishing inference failed: %s", e)

        # ── Aggregate ────────────────────────────────
        result.score = min(
            (keyword_score * 0.40) +
            (urgency_score * 0.25) +
            (spoof_score   * 0.25) +
            (url_score     * 0.05) +
            (nlp_score     * 0.05),
            1.0
        )

        # ── Decision ─────────────────────────────────
        if result.score >= 0.70 or (len(matched) >= self.keyword_threshold and spoof_score > 0):
            result.decision = "phishing"
        elif result.score >= 0.40 or len(matched) >= self.keyword_threshold:
            result.decision = "suspicious"
        else:
            result.decision = "clean"

        return result
