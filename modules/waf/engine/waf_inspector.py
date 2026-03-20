"""
Enterprise NGFW — AI-Powered Web Application Firewall (WAF) Inspector

Settings are loaded from:  config/defaults/waf.yaml
Local overrides from:      config/waf.local.yaml  (not committed to git)

Architecture (10-Layer AI-WAF):

  HTTP Request
       │
  0. Settings Check         — master WAF on/off switch first
       │
  1. Honeypot Check         — instant blacklist on probe of /admin_backup, /.env …
       │
  2. WAF Preprocessor       — multi-layer decode (URL+B64+Hex+HTML+Unicode+SQL comments)
       │
  3. Feature Extractor      — 10 HTTP-level numerical features
       │
  4. AI Models Layer
       ├── NLP Model         — 1D-CNN+BiLSTM payload classifier
       ├── Bot Detector      — XGBoost behavioral bot classifier
       ├── Anomaly Detector  — heuristic + ml/inference/anomaly_detector
       └── Threat Intel      — AbuseIPDB / Spamhaus / OTX / Feodo
       │
  5. Risk Scoring Engine    — weighted ensemble → score [0.0, 1.0]
       │
  6. Policy Decision        — ALLOW / CHALLENGE / SOFT_BLOCK / BLOCK
       │
  Self-Learning Logger      — stores payload + label for weekly retraining

Integration points with existing system:
  - InspectorPlugin base class (inspection/framework/plugin_base.py)
  - InspectionContext, InspectionResult, InspectionFinding, InspectionAction
  - ml/inference/anomaly_detector.py  (reused as-is)
  - modules.ids_ips.engine.core.threat_intel (new — pluggable, optional)
"""

import logging
import time
from dataclasses import dataclass
from typing import List, Optional, TYPE_CHECKING

from system.inspection_core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionFinding,
    InspectionResult, InspectionAction, PluginPriority,
)
from modules.waf.engine.core.preprocessor      import WAFPreprocessor
from modules.waf.engine.core.feature_extractor import WafFeatureExtractor
from modules.waf.engine.core.honeypot          import HoneypotGuard
from modules.waf.engine.core.risk_engine       import RiskScoringEngine, PolicyDecision
from modules.waf.engine.core.settings          import WAFSettings, get_waf_settings

# New WAAP Modules
from modules.waf.engine.core.api_schema_validator import APISchemaValidator
from modules.waf.engine.core.fingerprinting       import AdvancedFingerprinting
from modules.waf.engine.core.ato_protector        import ATOProtector
from modules.waf.engine.core.rate_limiter         import AdaptiveRateLimiter
from modules.waf.engine.core.shadow_autopilot     import ShadowAutopilot
from modules.waf.engine.core.self_learning_logger  import WAFSelfLearningLogger

if TYPE_CHECKING:
    from modules.ids_ips.engine.core.threat_intel import ThreatIntelCache
    from modules.waf.ml_training.waf_nlp.model  import WAFNLPInference
    from modules.waf.ml_training.bot_detection.model import BotDetectionModel
    from modules.waf.ml_training.waf_gnn.model  import WAFGNNInference

from modules.waf.api.live_monitor import waf_dispatcher
import asyncio

# ── Module-level singletons (used by API router for live reload) ──
_gnn_log_collector = None   # type: Optional['SessionLogCollector']
_live_gnn_model    = None   # type: Optional['WAFGNNInference']
_live_shadow_autopilot = None # type: Optional['ShadowAutopilot']


logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  WAFInspectorPlugin
# ──────────────────────────────────────────────

class WAFInspectorPlugin(InspectorPlugin):
    """
    AI-Powered WAF Inspector Plugin.

    Reads all settings from config/defaults/waf.yaml (via WAFSettings).
    Each feature can be individually toggled without code changes.

    Args:
        settings:       WAFSettings instance (loads from YAML if None)
        nlp_model:      Optional WAFNLPInference instance
        bot_model:      Optional BotDetectionModel instance
        gnn_model:      Optional WAFGNNInference instance
        threat_intel:   Optional ThreatIntelCache instance
        priority:       Plugin execution priority
    """

    def __init__(
        self,
        settings:     Optional[WAFSettings]          = None,
        nlp_model:    Optional['WAFNLPInference']    = None,
        bot_model:    Optional['BotDetectionModel']  = None,
        gnn_model:    Optional['WAFGNNInference']    = None,
        threat_intel: Optional['ThreatIntelCache']   = None,
        priority:     PluginPriority = PluginPriority.HIGH,
    ):
        super().__init__(name="waf_ai_inspector", priority=priority)

        # ── Load settings ───────────────────────
        self.cfg = settings or get_waf_settings()

        # ── Sub-components (built from settings) ─
        self.preprocessor = WAFPreprocessor(
            max_iterations=self.cfg.preprocessing.max_iterations
        )
        self.feature_ext  = WafFeatureExtractor()
        self.honeypot     = HoneypotGuard(
            score_boost           = self.cfg.honeypot.score_boost,
            blacklist_ttl_seconds = self.cfg.honeypot.blacklist_ttl_seconds,
            # tarpit_enabled=True # default
        )
        
        # ── WAAP Modules ────────────────────────
        self.api_validator = APISchemaValidator(
            max_payload_size=self.cfg.api_schema.max_payload_size
        )
        self.fingerprint_engine = AdvancedFingerprinting(
            check_ja3=self.cfg.fingerprint.check_ja3,
            check_headers=self.cfg.fingerprint.check_headers
        )
        self.ato_protector = ATOProtector(
            max_attempts_per_ip=self.cfg.ato_protector.max_attempts_per_ip,
            max_attempts_per_user=self.cfg.ato_protector.max_attempts_per_user,
            time_window_seconds=self.cfg.ato_protector.time_window_seconds
        )
        self.rate_limiter = AdaptiveRateLimiter(
            global_rate_limit=self.cfg.rate_limiter.global_rate_limit,
            ip_rate_limit=self.cfg.rate_limiter.ip_rate_limit,
            user_rate_limit=self.cfg.rate_limiter.user_rate_limit,
            time_window_seconds=self.cfg.rate_limiter.time_window_seconds
        )
        rs = self.cfg.risk_scoring.thresholds
        self.risk_engine = RiskScoringEngine(
            w_nlp        = self.cfg.nlp.weight,
            w_anomaly    = self.cfg.anomaly.weight,
            w_bot        = self.cfg.bot.weight,
            w_reputation = self.cfg.threat_intel.weight,
            w_honeypot   = 0.05,
            threshold_allow      = rs.allow,
            threshold_challenge  = rs.challenge,
            threshold_soft_block = rs.soft_block,
        )

        # ── Optional AI models ──────────────────
        self.nlp_model    = nlp_model
        self.bot_model    = bot_model
        self.gnn_model    = gnn_model
        self.threat_intel = threat_intel

        logger.info(
            "WAFInspectorPlugin initialized | enabled=%s | mode=%s",
            self.cfg.enabled, self.cfg.mode
        )
        logger.info(self.cfg.summary())

        # ─ Self-Learning Logger ─ (disabled by default, controlled by waf.yaml) ─
        self.self_logger: Optional[WAFSelfLearningLogger] = None
        if self.cfg.self_learning.enabled:
            try:
                from system.database.database import SessionLocal
                self.self_logger = WAFSelfLearningLogger(
                    settings=self.cfg.self_learning,
                    db_session_factory=SessionLocal,
                )
                logger.info("WAF Self-Learning Logger activated (max_records=%d)",
                            self.cfg.self_learning.max_records)
            except Exception as e:
                logger.warning("WAF Self-Learning Logger init failed: %s", e)

        # ── Session Log Collector (for GNN training data) ─
        global _gnn_log_collector
        if self.cfg.gnn.log_sessions:
            try:
                from modules.waf.engine.core.session_log_collector import SessionLogCollector
                _gnn_log_collector = SessionLogCollector(
                    output_path  = self.cfg.gnn.logs_path,
                    max_records  = self.cfg.gnn.max_log_records,
                )
                logger.info("GNN session log collector active → %s", self.cfg.gnn.logs_path)
            except Exception as e:
                logger.warning("Could not initialize GNN session log collector: %s", e)

        # ── Make live GNN model accessible to API router ──
        global _live_gnn_model
        if self.gnn_model:
            _live_gnn_model = self.gnn_model
            
        # ── Shadow Autopilot Initialization ────────────────
        global _live_shadow_autopilot
        self.autopilot = ShadowAutopilot(
            observation_window_hours=self.cfg.shadow_mode.observation_window_hours
        )
        _live_shadow_autopilot = self.autopilot
        
        # If enabled via settings, forcefully resume learning
        if self.cfg.shadow_mode.enabled:
            self.autopilot.start_learning(hours=self.cfg.shadow_mode.observation_window_hours)

    # ── InspectorPlugin interface ───────────────

    def can_inspect(self, context: InspectionContext) -> bool:
        """Target HTTP/HTTPS traffic on configured ports."""
        # 🔴 Master switch — if WAF is disabled, skip all inspection
        if not self.cfg.enabled:
            return False
        ports = set(self.cfg.monitored_ports)
        return context.dst_port in ports or context.src_port in ports

    async def initialize(self) -> None:
        logger.info("WAFInspectorPlugin ready | mode=%s", self.cfg.mode)

    async def shutdown(self) -> None:
        logger.info("WAFInspectorPlugin shutdown")

    def inspect(self, context: InspectionContext, data: bytes) -> InspectionResult:
        """
        Full AI-WAF inspection pipeline.

        Returns InspectionResult with:
          - action         (ALLOW / BLOCK / QUARANTINE)
          - findings       (list of InspectionFinding)
          - metadata       (risk_score, risk_breakdown, waf_features, …)
        """
        t_start = time.time()

        # ── 🔴 MASTER SWITCH ─────────────────────────────────────────
        # Double-check here in case can_inspect was bypassed
        if not self.cfg.enabled:
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"waf": "disabled"})

        # ── WHITELIST CHECK ──────────────────────────────────────────
        if self.cfg.is_ip_whitelisted(context.src_ip):
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"waf": "whitelisted"})

        # ── STATIC BLACKLIST CHECK ───────────────────────────────────
        if self.cfg.is_ip_blacklisted(context.src_ip):
            return InspectionResult(
                action=InspectionAction.BLOCK,
                findings=[InspectionFinding(
                    plugin_name="waf_blacklist",
                    severity="HIGH",
                    category="Blacklist",
                    description=f"{context.src_ip} is statically blacklisted",
                    confidence=1.0,
                    recommends_block=True,
                )],
                metadata={"waf": "blacklisted"},
            )

        # Outbound traffic is skipped (unless explicitly enabled)
        if context.direction == "outbound" and \
                not context.metadata.get("inspect_outbound_waf", False):
            return InspectionResult(action=InspectionAction.ALLOW)

        # Truncate oversized payloads
        max_bytes = self.cfg.performance.max_payload_inspect_bytes
        if len(data) > max_bytes:
            data = data[:max_bytes]

        findings: List[InspectionFinding] = []
        request_url  = context.metadata.get("request_url",  "")
        request_path = context.metadata.get("request_path", "/")

        # ── 1. HONEYPOT CHECK & TARPITTING ───────────────────────────
        honeypot_boost = 0.0
        if self.cfg.honeypot.enabled:
            hp_result = self.honeypot.check(context.src_ip, request_path)
            honeypot_boost = hp_result.score_boost if hp_result.triggered else 0.0

            if hp_result.triggered:
                # Active Deception (Tarpitting)
                if hp_result.tarpit_delay_sec > 0:
                    logger.debug("Tarpitting IP %s for %s seconds", context.src_ip, hp_result.tarpit_delay_sec)
                    time.sleep(hp_result.tarpit_delay_sec) # In production, use async sleep or tarpit socket offload

                findings.append(InspectionFinding(
                    plugin_name="waf_honeypot",
                    severity="HIGH",
                    category="Honeypot",
                    description=f"Honeypot triggered: {hp_result.path}",
                    confidence=0.99,
                    recommends_block=True,
                    metadata={"honeypot_path": hp_result.path},
                ))
                
        # ── 1.1 RATE LIMITING ─────────────────────────────────────────
        if self.cfg.rate_limiter.enabled:
             # Assume user_id is passed down from an Auth inspector upstream if available
             user_id = context.metadata.get("user_id") 
             is_allowed, rl_reason = self.rate_limiter.evaluate_request(context.src_ip, user_id)
             if not is_allowed:
                 # Rate limit exceeded. Soft Block (429)
                 return InspectionResult(
                     action=InspectionAction.BLOCK, # Translated to 429 upstream
                     findings=[InspectionFinding(
                         plugin_name="waap_rate_limiter",
                         severity="MEDIUM",
                         category="Rate Limit Exceeded",
                         description=rl_reason,
                         confidence=1.0,
                         recommends_block=True
                     )],
                     metadata={"waf": "rate_limited", "reason": rl_reason}
                 )

        # ── 1.2 ATO PROTECTOR ─────────────────────────────────────────
        ato_risk = 0.0
        if self.cfg.ato_protector.enabled and self.ato_protector.is_login_endpoint(request_path):
             username_attempt = context.metadata.get("login_username") # if parsed upstream
             is_ato_attack, ato_risk, ato_reason = self.ato_protector.track_and_evaluate(context.src_ip, username_attempt)
             if is_ato_attack:
                  findings.append(InspectionFinding(
                      plugin_name="waap_ato_protector",
                      severity="HIGH",
                      category="Account Takeover",
                      description=ato_reason,
                      confidence=ato_risk,
                      recommends_block=True
                  ))
                  # Instantly bump the honeypot boost variable to act as generic risk scalar
                  honeypot_boost += ato_risk 

        # ── 1.3 CLIENT FINGERPRINTING ─────────────────────────────────
        if self.cfg.fingerprint.enabled:
             ja3_hash = context.metadata.get("ja3_hash")
             headers = context.metadata.get("request_headers", {}) # Expecting dict of headers
             user_agent = headers.get("user-agent", "")
             
             fp_result = self.fingerprint_engine.analyze(user_agent, headers, ja3_hash)
             if fp_result.is_suspicious:
                 findings.append(InspectionFinding(
                     plugin_name="waap_fingerprint",
                     severity="MEDIUM",
                     category="Bot Fingerprint Spoofing",
                     description=fp_result.reason,
                     confidence=fp_result.risk_score,
                     recommends_block=fp_result.risk_score >= 0.8
                 ))
                 honeypot_boost += (fp_result.risk_score * 0.5) # Weight it into the final WAF risk

        # ── 1.4 API SCHEMA VALIDATION ─────────────────────────────────
        if self.cfg.api_schema.enabled:
            content_type = context.metadata.get("request_headers", {}).get("content-type", "")
            api_val = self.api_validator.validate(request_path, data, content_type)
            if not api_val.is_valid:
                 findings.append(InspectionFinding(
                     plugin_name="waap_api_validator",
                     severity="HIGH" if api_val.violation_score > 0.7 else "MEDIUM",
                     category="API Schema Violation",
                     description=api_val.violation_reason,
                     confidence=api_val.violation_score,
                     recommends_block=api_val.violation_score > 0.6
                 ))
                 honeypot_boost += api_val.violation_score

        # ── 2. PREPROCESSING ─────────────────────────────────────────
        if self.cfg.preprocessing.enabled:
            decoded_text, prep_meta = self.preprocessor.decode(data)
        else:
            decoded_text = data.decode('utf-8', errors='replace')
            prep_meta = {"encoding_layers": [], "iterations": 0,
                         "had_null_bytes": False,
                         "original_length": len(data), "decoded_length": len(data)}
                         
        # ── 2.5 SHADOW AUTOPILOT OBSERVATION ─────────────────────────
        if self.cfg.shadow_mode.enabled and self.autopilot.is_learning():
            try:
                # Capture structural data without blocking
                req_method = context.metadata.get("request_method", "GET")
                req_headers = context.metadata.get("request_headers", {})
                self.autopilot.observe(request_path, req_method, req_headers, len(data))
            except Exception as e:
                logger.debug("Shadow Autopilot Observe error: %s", e)

        # ── 3. FEATURE EXTRACTION ────────────────────────────────────
        waf_features = {}
        if self.cfg.feature_extraction.enabled:
            waf_features = self.feature_ext.extract(decoded_text, prep_meta, request_url)

        # ── 4. AI MODELS LAYER ───────────────────────────────────────

        # 4a. NLP attack detection
        nlp_score, nlp_label = 0.0, "benign"
        if self.cfg.nlp.enabled and self.nlp_model:
            nlp_score, nlp_label = self.nlp_model.predict(decoded_text)

        # 4b. Bot detection
        bot_score, bot_label  = 0.0, "legitimate_user"
        if self.cfg.bot.enabled and self.bot_model:
            bot_features = self._build_bot_features(context, waf_features)
            bot_score, bot_label = self.bot_model.predict(bot_features)

        # 4c. Threat Intelligence (async → run sync if event loop not available)
        reputation_score = 0.0
        if self.cfg.threat_intel.enabled and self.threat_intel:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Schedule as task — don't block the inspector
                    reputation_score = context.metadata.get("reputation_score_cached", 0.0)
                else:
                    reputation_score = loop.run_until_complete(
                        self.threat_intel.get_ip_score(context.src_ip)
                    )
            except Exception as e:
                logger.debug("ThreatIntel lookup failed: %s", e)

        # 4d. Quick heuristic anomaly from features (rules-based fallback)
        anomaly_score = 0.0
        if self.cfg.anomaly.enabled:
            anomaly_score = self._heuristic_anomaly_score(waf_features)

        # ── 5. RISK SCORING ──────────────────────────────────────────
        breakdown = self.risk_engine.calculate(
            nlp_score        = nlp_score,
            anomaly_score    = anomaly_score,
            bot_score        = bot_score,
            reputation_score = reputation_score,
            honeypot_boost   = honeypot_boost,
        )

        risk_score = breakdown.final_score
        decision   = breakdown.decision

        # ── 6. POLICY DECISION ───────────────────────────────────────
        # In monitor/learning mode: never block, always allow
        if not self.cfg.is_blocking:
            action = InspectionAction.ALLOW
        elif decision == PolicyDecision.BLOCK:
            action = InspectionAction.BLOCK
        elif decision == PolicyDecision.SOFT_BLOCK:
            action = InspectionAction.BLOCK     # map to framework's BLOCK
        elif decision == PolicyDecision.CHALLENGE:
            action = InspectionAction.QUARANTINE  # let upstream issue CAPTCHA
        else:
            action = InspectionAction.ALLOW

        # ── Build findings for significant threats ────────────────────
        if nlp_score > 0.5:
            findings.append(InspectionFinding(
                plugin_name="waf_nlp",
                severity=self._score_to_severity(nlp_score),
                category=f"AI-WAF: {nlp_label.replace('_', ' ').title()}",
                description=f"NLP model detected {nlp_label} pattern (score={nlp_score:.2f})",
                confidence=nlp_score,
                recommends_block=nlp_score > 0.75,
                metadata={"nlp_label": nlp_label, "nlp_score": nlp_score},
            ))

        if bot_score > 0.5:
            findings.append(InspectionFinding(
                plugin_name="waf_bot",
                severity=self._score_to_severity(bot_score),
                category=f"AI-WAF: Bot Detected ({bot_label})",
                description=f"Bot detector identified {bot_label} (score={bot_score:.2f})",
                confidence=bot_score,
                recommends_block=bot_score > 0.8,
                metadata={"bot_label": bot_label, "bot_score": bot_score},
            ))

        if reputation_score > 0.4:
            findings.append(InspectionFinding(
                plugin_name="waf_threat_intel",
                severity="HIGH" if reputation_score > 0.7 else "MEDIUM",
                category="AI-WAF: Threat Intelligence",
                description=f"IP {context.src_ip} has known bad reputation (score={reputation_score:.2f})",
                confidence=reputation_score,
                recommends_block=reputation_score > 0.7,
                metadata={"reputation_score": reputation_score},
            ))

        # ── Assemble result ──────────────────────────────────────────
        latency_ms = (time.time() - t_start) * 1000

        result = InspectionResult(
            action=action,
            findings=findings,
            processing_time_ms=latency_ms,
            metadata={
                "risk_score":       risk_score,
                "risk_decision":    decision.value,
                "risk_breakdown":   breakdown.to_dict(),
                "waf_features":     waf_features,
                "prep_meta":        prep_meta,
                "nlp_label":        nlp_label,
                "bot_label":        bot_label,
                "latency_ms":       round(latency_ms, 2),
            },
        )

        logger.info(
            "WAF [%s] → %s (risk=%.2f, decision=%s) | latency=%.1fms",
            context.src_ip, action.name, risk_score, decision.value, latency_ms
        )

        # Update plugin statistics
        self._inspected_count += 1
        if findings:
            self._detected_count += 1
        if action == InspectionAction.BLOCK:
            self._blocked_count += 1

        # ── Record session for GNN training data ──────────
        if _gnn_log_collector is not None:
            try:
                _gnn_log_collector.record(
                    src_ip        = context.src_ip,
                    path          = context.metadata.get("request_path", "/"),
                    method        = context.metadata.get("request_method", "GET"),
                    response_code = 403 if action == InspectionAction.BLOCK else 200,
                    session_id    = context.metadata.get("session_id", context.src_ip),
                    latency_ms    = latency_ms,
                    payload_bytes = len(data),
                )
            except Exception:
                pass  # never let logging break the WAF

        # ── Broadcast to Live Monitoring Dashboard ────────
        if action != InspectionAction.ALLOW or risk_score > 0.4:
            # Emit event to WebSocket clients (non-blocking)
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(waf_dispatcher.broadcast({
                        "timestamp": time.time(),
                        "src_ip": context.src_ip,
                        "path": request_path,
                        "action": action.name,
                        "risk_score": round(risk_score, 2),
                        "latency_ms": round(latency_ms, 2),
                        "triggers": [f.category for f in findings]
                    }))
            except Exception as e:
                logger.debug("Failed to dispatch live event: %s", e)

        # ─ Self-Learning Record ─ (gated by settings) ─
        if self.self_logger is not None:
            try:
                auto_label: Optional[int] = None
                label_src              = "auto"
                if action == InspectionAction.BLOCK:
                    auto_label = 1
                    label_src  = "auto_block"
                elif action == InspectionAction.ALLOW and not findings:
                    auto_label = 0
                    label_src  = "auto_allow"

                self.self_logger.record(
                    src_ip         = context.src_ip,
                    request_path   = request_path,
                    request_method = context.metadata.get("request_method", "GET"),
                    payload        = decoded_text[:4096] if decoded_text else "",
                    features       = waf_features,
                    risk_score     = risk_score,
                    decision       = decision.value,
                    nlp_score      = nlp_score,
                    bot_score      = bot_score,
                    anomaly_score  = anomaly_score,
                    reputation     = reputation_score,
                    label          = auto_label,
                    label_source   = label_src,
                )
            except Exception:
                pass  # never let the logger break the WAF

        return result

    # ── Private helpers ────────────────────────

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 0.9: return "CRITICAL"
        if score >= 0.7: return "HIGH"
        if score >= 0.5: return "MEDIUM"
        return "LOW"

    @staticmethod
    def _heuristic_anomaly_score(features: dict) -> float:
        """
        Quick rules-based anomaly score from WAF features.
        Used when the Anomaly Detector model is not available.
        Serves as a lightweight fallback.
        """
        score = 0.0

        # High entropy → possible encrypted/random payload
        if features.get("payload_entropy", 0) > 0.85:
            score += 0.2

        # Many attack keywords
        sql_kw = features.get("sql_keyword_count", 0)
        xss_kw = features.get("xss_keyword_count", 0)
        if sql_kw > 3:
            score += min(sql_kw * 0.05, 0.3)
        if xss_kw > 2:
            score += min(xss_kw * 0.05, 0.25)

        # Multiple encoding layers = obfuscation attempt
        enc_layers = features.get("encoding_layer_count", 0)
        if enc_layers > 1:
            score += min(enc_layers * 0.1, 0.3)

        # High special character ratio
        if features.get("special_char_ratio", 0) > 0.3:
            score += 0.15

        # Null byte present
        if features.get("has_null_byte", 0) > 0:
            score += 0.25

        return min(score, 1.0)

    @staticmethod
    def _build_bot_features(context: InspectionContext, waf_features: dict) -> dict:
        """Map inspection context + WAF features to bot detection features."""
        meta = context.metadata
        return {
            "request_rate":          meta.get("request_rate", 1.0),
            "iat_variance":          meta.get("iat_variance", 1.0),
            "session_duration":      meta.get("session_duration", 60.0),
            "unique_endpoints":      meta.get("unique_endpoints", 1),
            "user_agent_entropy":    meta.get("user_agent_entropy", 0.5),
            "header_count":          meta.get("header_count", 10),
            "accept_language_valid": meta.get("accept_language_valid", 1.0),
            "cookie_count":          meta.get("cookie_count", 0),
            "referer_present":       meta.get("referer_present", 0.0),
            "method_diversity":      meta.get("method_diversity", 1),
        }
