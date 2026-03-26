"""
Enterprise CyberNexus — Email Security Settings Loader

Reads `config/defaults/email.yaml` and merges with `config/email.local.yaml`.
Exposes typed settings for all email security layers.

Usage:
    from inspection.plugins.email.settings import get_email_settings

    cfg = get_email_settings()
    if cfg.enabled:
        ...
    cfg.set_enabled(False)   # runtime toggle, no restart needed
    cfg.set_mode("monitor")  # switch to shadow mode
    print(cfg.summary())
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_DIR, "..", "..", "..", ".."))

DEFAULT_CONFIG = os.path.join(_ROOT, "config", "defaults", "email.yaml")
LOCAL_CONFIG   = os.path.join(_ROOT, "config", "email.local.yaml")


# ── Sub-settings ──────────────────────────────


@dataclass
class PreprocessingSettings:
    enabled: bool = True
    decode_base64_body: bool = True
    decode_quoted_printable: bool = True
    extract_plain_text: bool = True
    max_body_bytes: int = 524288


@dataclass
class PhishingSettings:
    enabled: bool = True
    keyword_threshold: int = 2
    nlp_enabled: bool = False
    nlp_model_path: str = "ml/models/email_security/email_phishing_model.pt"
    weight: float = 0.35
    custom_keywords: List[str] = field(default_factory=list)


@dataclass
class URLScannerSettings:
    enabled: bool = True
    max_urls_per_email: int = 10
    reputation_check: bool = True
    detect_redirects: bool = True
    weight: float = 0.25
    trusted_domains: List[str] = field(default_factory=lambda: [
        "google.com", "microsoft.com", "github.com", "linkedin.com"
    ])


@dataclass
class AttachmentGuardSettings:
    enabled: bool = True
    max_attachment_size_mb: int = 25
    block_dangerous_extensions: bool = True
    entropy_analysis: bool = True
    entropy_threshold: float = 0.92
    weight: float = 0.20
    dangerous_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
        ".js", ".jar", ".msi", ".dll", ".ps1", ".psm1",
        ".hta", ".lnk", ".reg", ".inf",
    ])
    suspicious_extensions: List[str] = field(default_factory=lambda: [
        ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"
    ])


@dataclass
class SenderReputationSettings:
    enabled: bool = True
    weight: float = 0.15
    spf_check: bool = True
    dkim_check: bool = True
    dmarc_check: bool = True
    block_disposable_domains: bool = True
    ip_reputation_check: bool = True
    custom_suspicious_domains: List[str] = field(default_factory=list)


@dataclass
class SpamFilterSettings:
    enabled: bool = True
    weight: float = 0.05
    spam_threshold: float = 0.70
    keyword_threshold: int = 3


@dataclass
class SMTPCommandSettings:
    enabled: bool = True
    weight: float = 0.05
    suspicious_commands: List[str] = field(
        default_factory=lambda: ["VRFY", "EXPN", "DEBUG"]
    )


@dataclass
class RiskThresholds:
    allow:      float = 0.25
    quarantine: float = 0.55
    block:      float = 0.80


@dataclass
class EmailLoggingSettings:
    enabled: bool = True
    log_blocked: bool = True
    log_quarantined: bool = True
    log_allowed: bool = False
    log_file: str = "/var/log/CyberNexus/email_security.log"
    save_suspicious_content: bool = False


@dataclass
class AccessListSettings:
    enabled: bool = True
    emails:  List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips:     List[str] = field(default_factory=list)


# ── Master settings ────────────────────────────

@dataclass
class EmailSettings:
    """Master Email Security settings — loaded from email.yaml."""

    enabled:          bool     = True
    mode:             str      = "enforce"
    monitored_ports:  List[int] = field(
        default_factory=lambda: [25, 587, 465, 143, 993, 110, 995]
    )

    preprocessing:        PreprocessingSettings   = field(default_factory=PreprocessingSettings)
    phishing:             PhishingSettings         = field(default_factory=PhishingSettings)
    url_scanner:          URLScannerSettings       = field(default_factory=URLScannerSettings)
    attachment_guard:     AttachmentGuardSettings  = field(default_factory=AttachmentGuardSettings)
    sender_reputation:    SenderReputationSettings = field(default_factory=SenderReputationSettings)
    spam_filter:          SpamFilterSettings       = field(default_factory=SpamFilterSettings)
    smtp_commands:        SMTPCommandSettings      = field(default_factory=SMTPCommandSettings)
    thresholds:           RiskThresholds           = field(default_factory=RiskThresholds)
    logging:              EmailLoggingSettings     = field(default_factory=EmailLoggingSettings)
    whitelist:            AccessListSettings       = field(default_factory=AccessListSettings)

    _config_path: str = field(default=DEFAULT_CONFIG, repr=False)

    # ── Convenience ─────────────────────────────

    @property
    def is_blocking(self) -> bool:
        return self.enabled and self.mode == "enforce"

    def is_whitelisted_sender(self, email: str = "", domain: str = "", ip: str = "") -> bool:
        if not self.whitelist.enabled:
            return False
        if email and email.lower() in [e.lower() for e in self.whitelist.emails]:
            return True
        if domain and domain.lower() in [d.lower() for d in self.whitelist.domains]:
            return True
        if ip and ip in self.whitelist.ips:
            return True
        return False

    # ── Runtime toggles ──────────────────────────

    def set_enabled(self, value: bool) -> None:
        self.enabled = value
        logger.warning("EmailSecurity master switch → %s", "ENABLED" if value else "DISABLED")

    def set_mode(self, mode: str) -> None:
        if mode not in ("enforce", "monitor", "learning"):
            raise ValueError(f"Invalid mode: {mode}")
        self.mode = mode
        logger.info("EmailSecurity mode → %s", mode)

    def reload(self) -> None:
        fresh = EmailSettings.load(self._config_path)
        self.__dict__.update(fresh.__dict__)
        logger.info("EmailSettings reloaded from %s", self._config_path)

    def summary(self) -> str:
        on = lambda v: "✅" if v else "❌"
        lines = [
            "══════════════════════════════════════════════",
            f"  Email Security : {'🟢 ENABLED' if self.enabled else '🔴 DISABLED'}",
            f"  Mode           : {self.mode.upper()}",
            "──────────────────────────────────────────────",
            f"  Preprocessing  : {on(self.preprocessing.enabled)}",
            f"  Phishing Detect: {on(self.phishing.enabled)}  (NLP={on(self.phishing.nlp_enabled)})",
            f"  URL Scanner    : {on(self.url_scanner.enabled)}",
            f"  Attachment Guard: {on(self.attachment_guard.enabled)}",
            f"  Sender Repute  : {on(self.sender_reputation.enabled)}  (SPF={on(self.sender_reputation.spf_check)} DKIM={on(self.sender_reputation.dkim_check)})",
            f"  Spam Filter    : {on(self.spam_filter.enabled)}",
            f"  SMTP Commands  : {on(self.smtp_commands.enabled)}",
            "──────────────────────────────────────────────",
            f"  Block threshold: {self.thresholds.block:.0%}",
            "══════════════════════════════════════════════",
        ]
        return "\n".join(lines)

    # ── YAML Loader ──────────────────────────────

    @classmethod
    def load(cls, config_path: str = DEFAULT_CONFIG, local_path: str = LOCAL_CONFIG) -> "EmailSettings":
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML required: pip install pyyaml — using defaults")
            return cls()

        raw = {}
        if os.path.exists(config_path):
            with open(config_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            logger.info("Email config loaded from %s", config_path)
        else:
            logger.warning("Email config not found at %s — using defaults", config_path)

        if os.path.exists(local_path):
            with open(local_path, encoding="utf-8") as f:
                local_raw = yaml.safe_load(f) or {}
            raw = _deep_merge(raw, local_raw)
            logger.info("Email local overrides applied from %s", local_path)

        cfg = raw.get("email_security", {})
        return cls._from_dict(cfg)

    @classmethod
    def _from_dict(cls, d: dict) -> "EmailSettings":
        s = cls()
        s.enabled         = d.get("enabled", True)
        s.mode            = d.get("mode", "enforce")
        s.monitored_ports = d.get("monitored_ports", s.monitored_ports)

        pp = d.get("preprocessing", {})
        s.preprocessing = PreprocessingSettings(
            enabled               = pp.get("enabled", True),
            decode_base64_body    = pp.get("decode_base64_body", True),
            decode_quoted_printable = pp.get("decode_quoted_printable", True),
            extract_plain_text    = pp.get("extract_plain_text", True),
            max_body_bytes        = pp.get("max_body_bytes", 524288),
        )

        ph = d.get("phishing_detection", {})
        s.phishing = PhishingSettings(
            enabled            = ph.get("enabled", True),
            keyword_threshold  = ph.get("keyword_threshold", 2),
            nlp_enabled        = ph.get("nlp_enabled", False),
            nlp_model_path     = ph.get("nlp_model_path", s.phishing.nlp_model_path),
            weight             = ph.get("weight", 0.35),
            custom_keywords    = ph.get("custom_keywords", []),
        )

        us = d.get("url_scanner", {})
        s.url_scanner = URLScannerSettings(
            enabled            = us.get("enabled", True),
            max_urls_per_email = us.get("max_urls_per_email", 10),
            reputation_check   = us.get("reputation_check", True),
            detect_redirects   = us.get("detect_redirects", True),
            weight             = us.get("weight", 0.25),
            trusted_domains    = us.get("trusted_domains", s.url_scanner.trusted_domains),
        )

        ag = d.get("attachment_guard", {})
        s.attachment_guard = AttachmentGuardSettings(
            enabled                   = ag.get("enabled", True),
            max_attachment_size_mb    = ag.get("max_attachment_size_mb", 25),
            block_dangerous_extensions= ag.get("block_dangerous_extensions", True),
            entropy_analysis          = ag.get("entropy_analysis", True),
            entropy_threshold         = ag.get("entropy_threshold", 0.92),
            weight                    = ag.get("weight", 0.20),
            dangerous_extensions      = ag.get("dangerous_extensions", s.attachment_guard.dangerous_extensions),
            suspicious_extensions     = ag.get("suspicious_extensions", s.attachment_guard.suspicious_extensions),
        )

        sr = d.get("sender_reputation", {})
        s.sender_reputation = SenderReputationSettings(
            enabled                   = sr.get("enabled", True),
            weight                    = sr.get("weight", 0.15),
            spf_check                 = sr.get("spf_check", True),
            dkim_check                = sr.get("dkim_check", True),
            dmarc_check               = sr.get("dmarc_check", True),
            block_disposable_domains  = sr.get("block_disposable_domains", True),
            ip_reputation_check       = sr.get("ip_reputation_check", True),
            custom_suspicious_domains = sr.get("custom_suspicious_domains", []),
        )

        sf = d.get("spam_filter", {})
        s.spam_filter = SpamFilterSettings(
            enabled           = sf.get("enabled", True),
            weight            = sf.get("weight", 0.05),
            spam_threshold    = sf.get("spam_threshold", 0.70),
            keyword_threshold = sf.get("keyword_threshold", 3),
        )

        sc = d.get("smtp_commands", {})
        s.smtp_commands = SMTPCommandSettings(
            enabled             = sc.get("enabled", True),
            weight              = sc.get("weight", 0.05),
            suspicious_commands = sc.get("suspicious_commands", ["VRFY", "EXPN", "DEBUG"]),
        )

        thr = d.get("risk_scoring", {}).get("thresholds", {})
        s.thresholds = RiskThresholds(
            allow      = thr.get("allow",      0.25),
            quarantine = thr.get("quarantine",  0.55),
            block      = thr.get("block",       0.80),
        )

        lg = d.get("logging", {})
        s.logging = EmailLoggingSettings(
            enabled                 = lg.get("enabled", True),
            log_blocked             = lg.get("log_blocked", True),
            log_quarantined         = lg.get("log_quarantined", True),
            log_allowed             = lg.get("log_allowed", False),
            log_file                = lg.get("log_file", s.logging.log_file),
            save_suspicious_content = lg.get("save_suspicious_content", False),
        )

        wl = d.get("whitelist", {})
        s.whitelist = AccessListSettings(
            enabled = wl.get("enabled", True),
            emails  = wl.get("emails",  []),
            domains = wl.get("domains", []),
            ips     = wl.get("ips",     []),
        )

        return s


# ── Singleton ─────────────────────────────────
_instance: Optional[EmailSettings] = None

def get_email_settings() -> EmailSettings:
    global _instance
    if _instance is None:
        _instance = EmailSettings.load()
    return _instance


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
