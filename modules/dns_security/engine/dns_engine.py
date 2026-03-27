"""
Enterprise CyberNexus v2.0 - DNS Security Engine (Centralized Cache)

Loads rules and config from DB once into RAM. The plugin layer uses this
engine for all per-packet decisions without touching the database.
"""

import re
import fnmatch
import logging
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from system.database.database import SessionLocal
from modules.dns_security.models import DNSFilterRule, DNSModuleConfig, FilterType, ActionEnum

logger = logging.getLogger(__name__)


@dataclass
class CachedFilterRule:
    id: int
    domain_pattern: str
    filter_type: FilterType
    action: ActionEnum
    description: str
    _compiled_regex: Optional[re.Pattern] = None  # for REGEX type only


class DNSEngine:
    """
    Singleton centralized DNS Engine.
    All config and filter rules are loaded once from the DB into RAM.
    Call `.reload()` to refresh after mutations from the API.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DNSEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._rules: List[CachedFilterRule] = []
        self._config: Optional[DNSModuleConfig] = None
        self._suspicious_tlds: Set[str] = set()
        self._reload_lock = threading.RLock()
        self.reload()
        self._initialized = True

    def reload(self):
        """Reload config and rules from DB into RAM. Thread-safe."""
        with self._reload_lock:
            with SessionLocal() as db:
                # Load config
                conf = db.query(DNSModuleConfig).first()
                if not conf:
                    conf = DNSModuleConfig()
                    db.add(conf)
                    db.commit()
                    db.refresh(conf)
                self._config = conf

                # Pre-parse TLDs
                self._suspicious_tlds = {
                    t.strip()
                    for t in (conf.suspicious_tlds or "").split(",")
                    if t.strip()
                }

                # Load filter rules
                db_rules = db.query(DNSFilterRule).filter(DNSFilterRule.enabled == True).all()
                cached = []
                for r in db_rules:
                    compiled = None
                    if r.filter_type == FilterType.REGEX:
                        try:
                            compiled = re.compile(r.domain_pattern.lower(), re.IGNORECASE)
                        except re.error as e:
                            logger.warning(f"Invalid regex in DNS rule #{r.id}: {e}")
                            continue
                    cached.append(CachedFilterRule(
                        id=r.id,
                        domain_pattern=r.domain_pattern.lower(),
                        filter_type=r.filter_type,
                        action=r.action,
                        description=r.description or r.domain_pattern,
                        _compiled_regex=compiled
                    ))
                self._rules = cached

            logger.info(
                f"DNSEngine reloaded — {len(self._rules)} filter rules, "
                f"{len(self._suspicious_tlds)} suspicious TLDs cached."
            )

    # ─────────────────────────────────────────────────────────────
    # Config accessors (no DB access)
    # ─────────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return bool(self._config and self._config.is_active)

    @property
    def enable_dga_detection(self) -> bool:
        return bool(self._config and self._config.enable_dga_detection)

    @property
    def enable_tunneling_detection(self) -> bool:
        return bool(self._config and self._config.enable_tunneling_detection)

    @property
    def enable_threat_intel(self) -> bool:
        return bool(self._config and self._config.enable_threat_intel)

    @property
    def enable_rate_limiting(self) -> bool:
        return bool(self._config and self._config.enable_rate_limiting)

    @property
    def enable_tld_blocking(self) -> bool:
        return bool(self._config and self._config.enable_tld_blocking)

    @property
    def dga_entropy_threshold(self) -> float:
        return self._config.dga_entropy_threshold if self._config else 3.8

    @property
    def tunneling_query_threshold(self) -> int:
        return self._config.tunneling_query_threshold if self._config else 50

    @property
    def rate_limit_per_minute(self) -> int:
        return self._config.rate_limit_per_minute if self._config else 100

    @property
    def suspicious_tlds(self) -> Set[str]:
        return self._suspicious_tlds

    # ─────────────────────────────────────────────────────────────
    # Domain filter rule matching (no DB access)
    # ─────────────────────────────────────────────────────────────

    def match_filter_rules(self, domain: str) -> Optional[CachedFilterRule]:
        """
        Returns the first matching cached rule or None.
        """
        domain = domain.lower()
        with self._reload_lock:
            for rule in self._rules:
                if rule.filter_type == FilterType.EXACT:
                    if domain == rule.domain_pattern:
                        return rule
                elif rule.filter_type == FilterType.WILDCARD:
                    if fnmatch.fnmatchcase(domain, rule.domain_pattern):
                        return rule
                elif rule.filter_type == FilterType.REGEX and rule._compiled_regex:
                    if rule._compiled_regex.search(domain):
                        return rule
        return None

    def update_rule_stats(self, rule_id: int):
        """Async-safe hit count update. Opens brief DB session outside inspect loop."""
        from datetime import datetime
        try:
            with SessionLocal() as db:
                db_rule = db.query(DNSFilterRule).filter(DNSFilterRule.id == rule_id).first()
                if db_rule:
                    db_rule.blocked_count = (db_rule.blocked_count or 0) + 1
                    db_rule.last_triggered = datetime.utcnow()
                    db.commit()
        except Exception as e:
            logger.warning(f"Failed to update DNS rule stats for rule #{rule_id}: {e}")
