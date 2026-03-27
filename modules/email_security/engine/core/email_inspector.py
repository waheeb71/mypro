"""
Enterprise CyberNexus — AI-Powered Email Security Inspector

Replaces and evolves the legacy `smtp_inspector.py` by routing all
email protocol traffic through a multi-layer AI security pipeline.

Protocol coverage:
  - SMTP  (port 25, 587, 465) — inbound + outbound mail
  - IMAP  (port 143, 993)     — mail retrieval
  - POP3  (port 110, 995)     — mail retrieval

7-Layer AI Detection Pipeline:
  ─────────────────────────────────────────────────────
  0. Settings / Whitelist Gate       (master on/off + trusted senders)
  1. Email Preprocessor              (MIME decode + URL + attachment extract)
  2. Phishing Detector               (keyword + urgency + brand spoof + NLP)
  3. URL Scanner                     (shorteners + TLD + IP-literal + reputation)
  4. Attachment Guard                (extension + entropy + MIME mismatch)
  5. Sender Reputation               (SPF + DKIM + DMARC + disposable domain + IP)
  6. Spam Filter                     (keyword + caps + hidden text)
  7. Risk Scoring Engine             (weighted sum → ALLOW / QUARANTINE / BLOCK)
  ─────────────────────────────────────────────────────

Integration with existing framework:
  - InspectorPlugin base class
  - InspectionContext, InspectionResult, InspectionFinding
  - core/threat_intel.py  (IP + domain reputation)
  - Replaces: smtp_inspector.py (kept in place as legacy fallback)

Settings:
  config/defaults/email.yaml    — per-feature enable/disable + weights
  config/email.local.yaml       — API keys and local overrides
"""

import logging
import time
from typing import List, Optional, TYPE_CHECKING

from system.inspection_core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionFinding,
    InspectionResult, InspectionAction, PluginPriority,
)
from modules.email_security.engine.core.settings          import EmailSettings, get_email_settings
from modules.email_security.engine.utils.preprocessor      import EmailPreprocessor
from modules.email_security.engine.scanners.phishing_detector import PhishingDetector
from modules.email_security.engine.scanners.url_scanner       import URLScanner
from modules.email_security.engine.scanners.attachment_guard  import AttachmentGuard
from modules.email_security.engine.scanners.sender_reputation import SenderReputation
from modules.email_security.engine.scanners.spam_filter       import SpamFilter
from modules.email_security.engine.core.risk_engine       import EmailRiskEngine, EmailPolicyDecision

if TYPE_CHECKING:
    from modules.ids_ips.engine.anomaly_detector import AnomalyDetector


logger = logging.getLogger(__name__)

# SMTP command patterns that indicate reconnaissance
_DANGEROUS_SMTP_COMMANDS = {"VRFY", "EXPN", "DEBUG"}


class EmailInspectorPlugin(InspectorPlugin):
    """
    AI-Powered Email Security Inspector.

    Automatically activated when traffic arrives on email ports
    (25, 587, 465, 143, 993, 110, 995). Routes packets through a
    7-layer detection pipeline driven by `config/defaults/email.yaml`.

    Args:
        settings:     EmailSettings (loaded from YAML if None)
        threat_intel: Optional ThreatIntelCache for IP + domain reputation
        priority:     Plugin execution priority
    """

    def __init__(
        self,
        settings:     Optional[EmailSettings] = None,
        threat_intel: Optional['ThreatIntelCache'] = None,
        priority:     PluginPriority = PluginPriority.HIGH,
    ):
        super().__init__(name="email_ai_inspector", priority=priority)

        # ── Load settings ─────────────────────────
        self.cfg = settings or get_email_settings()
        self.threat_intel = threat_intel

        # ── Build sub-components from settings ────
        pp_cfg = self.cfg.preprocessing
        self.preprocessor = EmailPreprocessor(
            decode_base64       = pp_cfg.decode_base64_body,
            decode_qp           = pp_cfg.decode_quoted_printable,
            extract_plain_text  = pp_cfg.extract_plain_text,
            max_body_bytes      = pp_cfg.max_body_bytes,
        )

        ph_cfg = self.cfg.phishing
        self.phishing_detector = PhishingDetector(
            keyword_threshold = ph_cfg.keyword_threshold,
            nlp_enabled       = ph_cfg.nlp_enabled,
            nlp_model_path    = ph_cfg.nlp_model_path,
            custom_keywords   = ph_cfg.custom_keywords,
        )

        us_cfg = self.cfg.url_scanner
        self.url_scanner = URLScanner(
            max_urls_per_email = us_cfg.max_urls_per_email,
            reputation_check   = us_cfg.reputation_check,
            detect_redirects   = us_cfg.detect_redirects,
            trusted_domains    = us_cfg.trusted_domains,
            threat_intel       = self.threat_intel,
        )

        ag_cfg = self.cfg.attachment_guard
        self.attachment_guard = AttachmentGuard(
            block_dangerous       = ag_cfg.block_dangerous_extensions,
            analyze_entropy       = ag_cfg.entropy_analysis,
            entropy_threshold     = ag_cfg.entropy_threshold,
            max_size_mb           = ag_cfg.max_attachment_size_mb,
            dangerous_extensions  = ag_cfg.dangerous_extensions,
            suspicious_extensions = ag_cfg.suspicious_extensions,
        )

        sr_cfg = self.cfg.sender_reputation
        self.sender_reputation = SenderReputation(
            spf_check                 = sr_cfg.spf_check,
            dkim_check                = sr_cfg.dkim_check,
            dmarc_check               = sr_cfg.dmarc_check,
            block_disposable_domains  = sr_cfg.block_disposable_domains,
            custom_suspicious_domains = sr_cfg.custom_suspicious_domains,
            threat_intel              = self.threat_intel,
        )

        sf_cfg = self.cfg.spam_filter
        self.spam_filter = SpamFilter(
            keyword_threshold = sf_cfg.keyword_threshold,
            spam_threshold    = sf_cfg.spam_threshold,
        )

        thr = self.cfg.thresholds
        self.risk_engine = EmailRiskEngine(
            w_phishing   = ph_cfg.weight,
            w_url        = us_cfg.weight,
            w_attachment = ag_cfg.weight,
            w_sender     = sr_cfg.weight,
            w_spam       = sf_cfg.weight,
            threshold_allow      = thr.allow,
            threshold_quarantine = thr.quarantine,
            threshold_block      = thr.block,
        )

        logger.info("EmailInspectorPlugin initialized | enabled=%s | mode=%s",
                    self.cfg.enabled, self.cfg.mode)
        logger.info(self.cfg.summary())

    # ── InspectorPlugin interface ─────────────────────────────

    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Route email traffic automatically.

        Activates on any packet destined for or from an email port:
          SMTP: 25, 587, 465
          IMAP: 143, 993
          POP3: 110, 995
        """
        # 🔴 Master switch
        if not self.cfg.enabled:
            return False

        ports = set(self.cfg.monitored_ports)
        return context.dst_port in ports or context.src_port in ports

    async def initialize(self) -> None:
        logger.info("EmailInspectorPlugin ready | mode=%s", self.cfg.mode)

    async def shutdown(self) -> None:
        logger.info("EmailInspectorPlugin shutdown")

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        """
        Full email inspection pipeline.

        Returns InspectionResult with:
          - action:    ALLOW / QUARANTINE / BLOCK
          - findings:  List of InspectionFinding per detected threat
          - metadata:  risk_score, breakdown, phishing details, etc.
        """
        t_start = time.time()

        # ── Master switch ────────────────────────────────────────
        if not self.cfg.enabled:
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"email_security": "disabled"})

        # ── Whitelist CHECK ──────────────────────────────────────
        if self.cfg.is_whitelisted_sender(ip=context.src_ip):
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"email_security": "whitelisted"})

        findings: List[InspectionFinding] = []
        
        # For non-DATA SMTP commands (HELO, MAIL FROM, etc.) — minimal inspection
        # Detect suspicious SMTP commands only
        command_penalty = 0.0
        sc_cfg = self.cfg.smtp_commands
        if sc_cfg.enabled:
            try:
                text = data.decode("utf-8", errors="ignore")
                first_word = text.strip().split()[0].upper() if text.strip() else ""
                if first_word in set(sc_cfg.suspicious_commands):
                    command_penalty = 0.3
                    findings.append(InspectionFinding(
                        plugin_name="email_smtp_commands",
                        severity="MEDIUM",
                        category="Email: Suspicious SMTP Command",
                        description=f"Suspicious SMTP command detected: {first_word}",
                        confidence=0.8,
                        recommends_block=False,
                    ))
            except Exception:
                pass

        # ── 1. PARSE EMAIL ──────────────────────────────────────
        parsed = None
        if self.cfg.preprocessing.enabled:
            parsed = self.preprocessor.parse(data)

        if parsed is None:
            # Not parseable as email — could be raw SMTP handshake
            # Return ALLOW with minimal metadata (let other plugins handle)
            return InspectionResult(
                action=InspectionAction.ALLOW,
                findings=findings,
                metadata={"email_security": "not_email_data",
                          "command_penalty": command_penalty},
            )

        # Check sender whitelist
        if self.cfg.is_whitelisted_sender(
            email=parsed.raw_from,
            domain=self._extract_domain(parsed.raw_from),
        ):
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"email_security": "whitelisted_sender"})

        # ── 2. PHISHING DETECTION ───────────────────────────────
        phishing_score = 0.0
        if self.cfg.phishing.enabled:
            ph_result = self.phishing_detector.detect(
                subject = parsed.subject,
                body    = parsed.body_text,
                urls    = parsed.urls,
            )
            phishing_score = ph_result.score

            if ph_result.decision in ("phishing", "suspicious"):
                findings.append(InspectionFinding(
                    plugin_name="email_phishing",
                    severity="CRITICAL" if ph_result.decision == "phishing" else "HIGH",
                    category=f"Email: Phishing ({ph_result.decision.title()})",
                    description=(
                        f"Phishing indicators found (score={ph_result.score:.2f}). "
                        f"Keywords: {', '.join(ph_result.matched_keywords[:5])}"
                        + (f" | Brand spoof: {ph_result.brand_spoof}" if ph_result.brand_spoof else "")
                    ),
                    confidence=ph_result.score,
                    recommends_block=ph_result.decision == "phishing",
                    metadata={
                        "phishing_score":    ph_result.score,
                        "matched_keywords":  ph_result.matched_keywords,
                        "brand_spoof":       ph_result.brand_spoof,
                        "urgency_flags":     ph_result.urgency_flags,
                    },
                ))

        # ── 3. URL SCANNING ─────────────────────────────────────
        url_score = 0.0
        if self.cfg.url_scanner.enabled and parsed.urls:
            url_result = self.url_scanner.scan(parsed.urls)
            url_score   = url_result.score

            if url_result.flagged_urls or url_result.excessive_urls:
                findings.append(InspectionFinding(
                    plugin_name="email_url_scanner",
                    severity="HIGH" if url_score > 0.6 else "MEDIUM",
                    category="Email: Malicious URL",
                    description=(
                        f"{len(url_result.flagged_urls)} suspicious URL(s) found. "
                        f"Total URLs: {url_result.total_urls}"
                        + (" (EXCESSIVE)" if url_result.excessive_urls else "")
                    ),
                    confidence=url_score,
                    recommends_block=url_score > 0.7,
                    metadata={
                        "url_score":     url_score,
                        "total_urls":    url_result.total_urls,
                        "flagged_urls":  [
                            {"url": s.url[:80], "flags": s.flags}
                            for s in url_result.flagged_urls[:5]
                        ],
                    },
                ))

        # ── 4. ATTACHMENT GUARD ─────────────────────────────────
        attachment_score = 0.0
        force_block      = False
        if self.cfg.attachment_guard.enabled and parsed.attachments:
            att_result      = self.attachment_guard.scan(parsed.attachments)
            attachment_score = att_result.score
            force_block     = att_result.blocked

            if att_result.findings:
                worst = att_result.findings[0]
                findings.append(InspectionFinding(
                    plugin_name="email_attachment_guard",
                    severity="CRITICAL" if force_block else "HIGH",
                    category="Email: Dangerous Attachment",
                    description=(
                        f"Suspicious attachment: {worst.filename} "
                        f"({', '.join(worst.flags)})"
                    ),
                    confidence=attachment_score,
                    recommends_block=force_block,
                    metadata={
                        "attachment_score": attachment_score,
                        "attachments": [
                            {"filename": f.filename, "flags": f.flags, "score": f.score}
                            for f in att_result.findings[:5]
                        ],
                    },
                ))

        # ── 5. SENDER REPUTATION ────────────────────────────────
        sender_score = 0.0
        if self.cfg.sender_reputation.enabled:
            sr_result    = self.sender_reputation.check(parsed)
            sender_score = sr_result.score

            if sr_result.flags:
                findings.append(InspectionFinding(
                    plugin_name="email_sender_reputation",
                    severity="HIGH" if sender_score > 0.5 else "MEDIUM",
                    category="Email: Sender Reputation",
                    description=f"Sender reputation issues: {', '.join(sr_result.flags[:3])}",
                    confidence=sender_score,
                    recommends_block=sender_score > 0.7,
                    metadata={
                        "sender_score":  sender_score,
                        "spf_status":   sr_result.spf_status,
                        "dkim_present": sr_result.dkim_present,
                        "dmarc_policy": sr_result.dmarc_policy,
                        "is_disposable":sr_result.is_disposable,
                        "flags":        sr_result.flags,
                    },
                ))

        # ── 6. SPAM FILTER ──────────────────────────────────────
        spam_score = 0.0
        if self.cfg.spam_filter.enabled:
            sf_result  = self.spam_filter.score(
                subject   = parsed.subject,
                body_text = parsed.body_text,
                body_html = parsed.body_html,
            )
            spam_score = sf_result.score

            if sf_result.decision == "spam":
                findings.append(InspectionFinding(
                    plugin_name="email_spam_filter",
                    severity="MEDIUM",
                    category="Email: Spam",
                    description=(
                        f"Spam detected (score={sf_result.score:.2f}). "
                        f"Keywords: {', '.join(sf_result.matched_keywords[:4])}"
                    ),
                    confidence=sf_result.score,
                    recommends_block=False,
                    metadata={
                        "spam_score":       sf_result.score,
                        "matched_keywords": sf_result.matched_keywords,
                        "flags":            sf_result.flags,
                    },
                ))

        # ── 7. RISK SCORING + POLICY DECISION ──────────────────
        breakdown = self.risk_engine.calculate(
            phishing_score   = phishing_score,
            url_score        = url_score,
            attachment_score = attachment_score,
            sender_score     = sender_score,
            spam_score       = spam_score,
            command_penalty  = command_penalty,
            force_block      = force_block,
        )

        # Map email decision to framework InspectionAction
        if not self.cfg.is_blocking:
            # Monitor mode: log only, never block
            action = InspectionAction.ALLOW
        elif breakdown.decision == EmailPolicyDecision.BLOCK:
            action = InspectionAction.BLOCK
        elif breakdown.decision == EmailPolicyDecision.QUARANTINE:
            action = InspectionAction.QUARANTINE
        else:
            action = InspectionAction.ALLOW

        latency_ms = (time.time() - t_start) * 1000

        logger.info(
            "Email [%s → %s] → %s (risk=%.2f) | latency=%.1fms | from=%s subject=%s",
            context.src_ip, context.dst_port,
            action.name, breakdown.final_score, latency_ms,
            parsed.raw_from[:40], parsed.subject[:40]
        )

        self._inspected_count += 1
        if findings:
            self._detected_count += 1
        if action == InspectionAction.BLOCK:
            self._blocked_count += 1

        result = InspectionResult(
            action=action,
            findings=findings,
            processing_time_ms=latency_ms,
            metadata={
                "email_security":  True,
                "risk_score":      breakdown.final_score,
                "risk_decision":   breakdown.decision.value,
                "risk_breakdown":  breakdown.to_dict(),
                "from":            parsed.raw_from,
                "subject":         parsed.subject,
                "url_count":       len(parsed.urls),
                "attachment_count":len(parsed.attachments),
                "sender_ip":       parsed.sender_ip,
                "latency_ms":      round(latency_ms, 2),
            },
        )

        # Persist inspection result to DB — off the hot path
        import threading
        threading.Thread(
            target=self._log_to_db,
            args=(context, parsed, breakdown, action, phishing_score, spam_score,
                  url_score, attachment_score, sender_score, latency_ms, findings),
            daemon=True,
        ).start()

        return result

    def _log_to_db(self, context, parsed, breakdown, action, phishing_score,
                   spam_score, url_score, attachment_score, sender_score,
                   latency_ms, findings):
        """Persist an EmailLog entry. Called from a background thread."""
        try:
            from system.database.database import SessionLocal
            from modules.email_security.models import EmailLog

            matched_kw = []
            flagged_urls_list = []
            brand_spoof = ""
            categories = []
            for f in findings:
                categories.append(f.category)
                md = getattr(f, "metadata", {}) or {}
                matched_kw.extend(md.get("matched_keywords", []))
                for u in md.get("flagged_urls", []):
                    flagged_urls_list.append(u.get("url", str(u)))
                if md.get("phishing_score") and md.get("brand_spoof", ""):
                    brand_spoof = md["brand_spoof"]

            decision_str = breakdown.decision.value   # allow | quarantine | block

            with SessionLocal() as db:
                log = EmailLog(
                    src_ip           = context.src_ip,
                    dst_port         = context.dst_port,
                    sender           = parsed.raw_from[:255] if parsed.raw_from else None,
                    subject          = parsed.subject[:512] if parsed.subject else None,
                    risk_score       = round(breakdown.final_score, 4),
                    phishing_score   = round(phishing_score, 4),
                    spam_score       = round(spam_score, 4),
                    url_score        = round(url_score, 4),
                    attachment_score = round(attachment_score, 4),
                    sender_score     = round(sender_score, 4),
                    decision         = decision_str,
                    is_phishing      = phishing_score >= 0.40,
                    is_spam          = spam_score >= 0.70,
                    has_malicious_url = url_score >= 0.40,
                    has_bad_attachment = attachment_score >= 0.40,
                    brand_spoof      = brand_spoof[:64] if brand_spoof else None,
                    matched_keywords = list(set(matched_kw))[:20],
                    flagged_urls     = flagged_urls_list[:10],
                    finding_categories = categories,
                    latency_ms       = round(latency_ms, 2),
                )
                db.add(log)
                db.commit()
        except Exception as exc:
            logger.debug("EmailLog write failed: %s", exc)

    @staticmethod
    def _extract_domain(raw_from: str) -> str:
        import re
        m = re.search(r'@([\w.\-]+)', raw_from)
        return m.group(1).lower() if m else ""

