"""
Enterprise CyberNexus — WAF Feature Extractor

Extracts 10 HTTP-level numerical features from a decoded WAF payload.
These features feed the AI models (NLP, Bot, Anomaly) alongside the
network-level features already computed by ai_inspector.py.

Features
--------
  1.  request_length       — total decoded payload length
  2.  payload_entropy      — Shannon entropy (0-1), high = encrypted/encoded
  3.  special_char_ratio   — ratio of dangerous chars (; " ' < > ( ) [ ] { })
  4.  sql_keyword_count    — count of known SQL attack keywords
  5.  xss_keyword_count    — count of known XSS attack keywords
  6.  parameter_count      — number of query-string/POST parameters
  7.  encoding_layer_count — how many decode layers the preprocessor needed
  8.  sql_comment_density  — density of SQL comment markers
  9.  path_depth           — depth of URL path (number of '/')
 10.  has_null_byte        — 1.0 if null byte was present, else 0.0
"""

import math
import re
import urllib.parse
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Attack keyword dictionaries
# ──────────────────────────────────────────────

SQL_KEYWORDS = frozenset([
    'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
    'alter', 'exec', 'execute', 'from', 'where', 'having', 'group by',
    'order by', 'join', 'inner join', 'left join', 'right join', 'like',
    'cast', 'convert', 'char', 'ascii', 'substring', 'sleep', 'benchmark',
    'load_file', 'outfile', 'dumpfile', 'information_schema', 'sys.tables',
    'xp_cmdshell', 'sp_executesql', 'waitfor delay', 'pg_sleep',
])

XSS_KEYWORDS = frozenset([
    'script', 'javascript', 'vbscript', 'expression', 'onerror', 'onload',
    'onclick', 'onmouseover', 'onfocus', 'ondblclick', 'onsubmit',
    'alert(', 'confirm(', 'prompt(', 'eval(', 'document.cookie',
    'document.write', 'window.location', 'fromcharcode', 'atob(',
    'src=', 'href=javascript', 'data:text/html', 'svg onload',
])

# Characters that are heavily used in injection attacks
DANGEROUS_CHARS = frozenset(';"\'>< ()[]{}\\|&$`~')

# SQL comment patterns
_SQL_COMMENT_RE = re.compile(r'(/\*.*?\*/|--|#)', re.DOTALL)


# ──────────────────────────────────────────────
#  WafFeatureExtractor
# ──────────────────────────────────────────────

class WafFeatureExtractor:
    """
    Extracts numerical WAF-specific features from a decoded HTTP payload.

    Usage:
        extractor = WafFeatureExtractor()
        features = extractor.extract(decoded_text, prep_meta, request_url)
    """

    def extract(
        self,
        decoded_text: str,
        prep_meta: Dict[str, Any],
        request_url: str = "",
    ) -> Dict[str, float]:
        """
        Extract all 10 WAF features.

        Args:
            decoded_text:  Canonical text after WAFPreprocessor
            prep_meta:     Metadata dict returned by WAFPreprocessor.decode()
            request_url:   Raw request URL (for path_depth + parameter_count)

        Returns:
            dict of feature_name → float
        """
        text_lower = decoded_text.lower()
        length     = max(len(decoded_text), 1)  # avoid division by zero

        features = {
            "request_length":       float(length),
            "payload_entropy":      self._shannon_entropy(decoded_text),
            "special_char_ratio":   self._special_char_ratio(decoded_text, length),
            "sql_keyword_count":    float(self._keyword_count(text_lower, SQL_KEYWORDS)),
            "xss_keyword_count":    float(self._keyword_count(text_lower, XSS_KEYWORDS)),
            "parameter_count":      float(self._parameter_count(request_url, decoded_text)),
            "encoding_layer_count": float(len(set(prep_meta.get("encoding_layers", [])))),
            "sql_comment_density":  self._sql_comment_density(decoded_text, length),
            "path_depth":           float(self._path_depth(request_url)),
            "has_null_byte":        1.0 if prep_meta.get("had_null_bytes") else 0.0,
        }

        logger.debug("WAF features: %s", features)
        return features

    # ── Individual feature helpers ─────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """
        Shannon entropy of the text, normalized to [0, 1].
        max entropy for 256 values = log2(256) = 8.0
        """
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        total   = len(text)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        # Normalize against worst-case of uniformly-distributed 256 ASCII chars
        return min(entropy / 8.0, 1.0)

    @staticmethod
    def _special_char_ratio(text: str, length: int) -> float:
        """Ratio of dangerous/special characters to total length."""
        count = sum(1 for ch in text if ch in DANGEROUS_CHARS)
        return count / length

    @staticmethod
    def _keyword_count(text_lower: str, keyword_set: frozenset) -> int:
        """Count occurrences of keywords in a lowercased text."""
        count = 0
        for kw in keyword_set:
            # Use word-boundary-aware search for short keywords
            start = 0
            while True:
                idx = text_lower.find(kw, start)
                if idx == -1:
                    break
                count += 1
                start = idx + len(kw)
        return count

    @staticmethod
    def _parameter_count(url: str, body: str) -> int:
        """
        Count query-string parameters + POST body parameters.
        Handles HPP (HTTP Parameter Pollution) naturally by counting all.
        """
        count = 0
        if url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            # parse_qs collapses duplicate keys — use parse_qsl to count all
            count += len(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

        # Try to parse POST body as form-encoded
        if body and '=' in body and '&' in body:
            count += len(urllib.parse.parse_qsl(body, keep_blank_values=True))

        return count

    @staticmethod
    def _sql_comment_density(text: str, length: int) -> float:
        """Ratio of characters inside SQL comment sequences to total length."""
        total_comment_chars = sum(len(m.group()) for m in _SQL_COMMENT_RE.finditer(text))
        return total_comment_chars / length

    @staticmethod
    def _path_depth(url: str) -> int:
        """Number of path segments in the URL (depth of resource access)."""
        if not url:
            return 0
        parsed = urllib.parse.urlparse(url)
        return parsed.path.count('/')
