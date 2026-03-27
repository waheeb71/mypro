import logging
import re
import threading
from typing import List, Dict, Tuple
from dataclasses import dataclass

from system.database.database import SessionLocal
from modules.dlp.models import DLPRule, DLPConfig
from modules.dlp.engine.regex_matcher import RegexMatcher

logger = logging.getLogger(__name__)

@dataclass
class CompiledDLPRule:
    id: int
    name: str
    pattern: re.Pattern
    severity: str
    description: str

class DLPEngine:
    """
    Centralized Core for Data Loss Prevention.
    Loads and caches DB rules to avoid per-packet regex compilation.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DLPEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized: return
        self._compiled_rules: List[CompiledDLPRule] = []
        self._config: DLPConfig = None
        self._reload_lock = threading.RLock()
        self.reload()
        self._initialized = True

    def reload(self):
        """Reloads config and custom rules from the database into RAM."""
        with self._reload_lock:
            with SessionLocal() as db:
                # Load Config
                conf = db.query(DLPConfig).first()
                if not conf:
                    conf = DLPConfig()
                    db.add(conf)
                    db.commit()
                    db.refresh(conf)
                self._config = conf

                # Load custom rules
                db_rules = db.query(DLPRule).filter(DLPRule.enabled == True).all()
                compiled = []
                for r in db_rules:
                    try:
                        pat = re.compile(r.pattern, re.IGNORECASE)
                        compiled.append(CompiledDLPRule(
                            id=r.id,
                            name=r.name,
                            pattern=pat,
                            severity=r.severity,
                            description=r.description or f"DLP rule '{r.name}' triggered"
                        ))
                    except Exception as e:
                        logger.error(f"Failed to compile DLP rule {r.name}: {e}")
                
                self._compiled_rules = compiled
            logger.info(f"DLPEngine reloaded: {len(self._compiled_rules)} custom rules active.")

    @property
    def is_active(self):
        return self._config.is_active if self._config else False

    @property
    def block_on_match(self):
        return self._config.block_on_match if self._config else False

    @property
    def deception_enabled(self):
        return self._config.deception_enabled if self._config else False

    def evaluate(self, text_data: str) -> List[Dict]:
        """
        Scans text against built-in and custom compiled rules.
        Returns a list of findings dicts.
        """
        findings = []
        if not text_data:
            return findings

        # 1. Built-in Regex Matcher (SSN, Credit Cards, etc.)
        # Hardcoding the assumption that built-in patterns are HIGH severity
        builtin_matches = RegexMatcher.scan_text(text_data)
        for bm in builtin_matches:
             findings.append({
                 "rule_name": f"BUILTIN_{bm['type']}",
                 "severity": "HIGH",
                 "description": f"Standard DLP Pattern matched: {bm['type']} ({bm['value_masked']})",
                 "match_count": 1 # Standard matcher reports individual matches
             })

        # 2. Custom DB Rules
        with self._reload_lock:
            for rule in self._compiled_rules:
                matches = rule.pattern.findall(text_data)
                if matches:
                    findings.append({
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "description": f"{rule.description} (Matched {len(matches)} times)",
                        "match_count": len(matches)
                    })

        return findings
