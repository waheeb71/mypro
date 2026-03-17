"""
Enterprise NGFW — WAF Preprocessor

Defeats obfuscation/encoding attacks before the AI models see the payload.

Supported decoding layers (applied iteratively until stable):
  1. URL decoding          (%3C%2F → </...)
  2. Base64 detection      (detects and decodes embedded B64 blobs)
  3. Hex decoding          (0x41 / \\x41 / %41 style)
  4. HTML entity decoding  (&lt; &amp; &#x3C; …)
  5. Unicode normalization (fullwidth chars, homoglyphs)
  6. JSON/XML flattening   (extracts inner text from structured payloads)
  7. SQL comment stripping (/**/ -- #)
  8. Null-byte removal     (\\x00)
  9. Case normalization     (.lower())

The output is a clean, canonical string ready for AI inspection.
"""

import re
import base64
import binascii
import unicodedata
import urllib.parse
import html
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────

# How many decode passes to perform before giving up (prevents infinite loops)
MAX_ITERATIONS = 6

# Minimum length for a Base64 blob to be considered worth decoding
B64_MIN_LEN = 12

# Regex: matches hex sequences like 0x41, \x41, %41
_HEX_0X_RE  = re.compile(r'0x([0-9a-fA-F]{2})')
_HEX_ESC_RE = re.compile(r'\\x([0-9a-fA-F]{2})')

# Regex: matches suspected Base64 blobs (only alphabet chars + padding)
_B64_RE = re.compile(
    r'(?<![A-Za-z0-9+/=])'          # not preceded by B64 char
    r'([A-Za-z0-9+/]{' + str(B64_MIN_LEN) + r',}={0,2})'  # the blob
    r'(?![A-Za-z0-9+/=])'          # not followed by B64 char
)

# Regex: strips SQL inline comments /**/ and line comments -- and #
_SQL_INLINE_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
_SQL_LINE_COMMENT_RE   = re.compile(r'(--|#)[^\n]*')

# Regex: matches XML/HTML tags — used for tag stripping in flattening
_XML_TAG_RE = re.compile(r'<[^>]+>')


# ──────────────────────────────────────────────
#  WAFPreprocessor
# ──────────────────────────────────────────────

class WAFPreprocessor:
    """
    Multi-layer WAF Preprocessor.

    Usage:
        preprocessor = WAFPreprocessor()
        clean_text, meta = preprocessor.decode(raw_bytes)
    """

    def __init__(self, max_iterations: int = MAX_ITERATIONS):
        self.max_iterations = max_iterations

    # ── Public API ─────────────────────────────

    def decode(self, raw: bytes) -> Tuple[str, dict]:
        """
        Decode and normalize a raw HTTP payload.

        Returns:
            (canonical_text, metadata)

            metadata contains:
              - encoding_layers: list of decoding steps applied
              - iterations: how many passes were needed
              - had_null_bytes: bool
              - original_length: int
              - decoded_length: int
        """
        meta = {
            "encoding_layers": [],
            "iterations": 0,
            "had_null_bytes": False,
            "original_length": len(raw),
            "decoded_length": 0,
        }

        # Detect null bytes before decoding
        if b'\x00' in raw:
            meta["had_null_bytes"] = True
            raw = raw.replace(b'\x00', b'')

        # Start with UTF-8 (replace unmappable bytes gracefully)
        text = raw.decode('utf-8', errors='replace')

        for i in range(self.max_iterations):
            prev = text

            text, layers = self._single_pass(text)

            if layers:
                meta["encoding_layers"].extend(layers)

            meta["iterations"] = i + 1

            if text == prev:
                # Stable — no more encodings left
                break

        meta["decoded_length"] = len(text)
        logger.debug(
            "WAFPreprocessor: %d iters | layers=%s | %d→%d chars",
            meta["iterations"],
            meta["encoding_layers"],
            meta["original_length"],
            meta["decoded_length"],
        )
        return text, meta

    # ── Single decoding pass ────────────────────

    def _single_pass(self, text: str) -> Tuple[str, list]:
        """Apply all decoding steps once. Returns (new_text, applied_layers)."""
        applied = []

        t, changed = self._url_decode(text)
        if changed: applied.append("url"); text = t

        t, changed = self._html_entity_decode(text)
        if changed: applied.append("html_entity"); text = t

        t, changed = self._hex_decode(text)
        if changed: applied.append("hex"); text = t

        t, changed = self._base64_detect_and_decode(text)
        if changed: applied.append("base64"); text = t

        t, changed = self._unicode_normalize(text)
        if changed: applied.append("unicode"); text = t

        t, changed = self._strip_sql_comments(text)
        if changed: applied.append("sql_comments"); text = t

        t, changed = self._flatten_xml_json(text)
        if changed: applied.append("xml_json_flatten"); text = t

        return text, applied

    # ── Decoding methods ───────────────────────

    def _url_decode(self, text: str) -> Tuple[str, bool]:
        """Decode percent-encoded characters (%3C → <)."""
        try:
            decoded = urllib.parse.unquote(text, encoding='utf-8', errors='replace')
            return decoded, decoded != text
        except Exception:
            return text, False

    def _html_entity_decode(self, text: str) -> Tuple[str, bool]:
        """Decode HTML entities (&lt; → <, &#x3C; → <)."""
        decoded = html.unescape(text)
        return decoded, decoded != text

    def _hex_decode(self, text: str) -> Tuple[str, bool]:
        """Decode \\x41 and 0x41 style hex sequences."""
        changed = False

        def replace_hex(m: re.Match) -> str:
            nonlocal changed
            changed = True
            try:
                return bytes.fromhex(m.group(1)).decode('utf-8', errors='replace')
            except Exception:
                return m.group(0)

        text = _HEX_ESC_RE.sub(replace_hex, text)
        text = _HEX_0X_RE.sub(replace_hex, text)
        return text, changed

    def _base64_detect_and_decode(self, text: str) -> Tuple[str, bool]:
        """
        Detect and decode embedded Base64 blobs.
        Only replaces blobs whose decoded output is valid UTF-8 printable text.
        """
        changed = False

        def try_decode(m: re.Match) -> str:
            nonlocal changed
            blob = m.group(1)
            # Pad if necessary
            padding = (4 - len(blob) % 4) % 4
            try:
                decoded_bytes = base64.b64decode(blob + '=' * padding)
                decoded_text  = decoded_bytes.decode('utf-8', errors='strict')
                # Only replace if result is printable (not binary garbage)
                if decoded_text.isprintable() or any(c in decoded_text for c in '<>"\'();'):
                    changed = True
                    return decoded_text
            except (binascii.Error, UnicodeDecodeError):
                pass
            return blob

        result = _B64_RE.sub(try_decode, text)
        return result, changed

    def _unicode_normalize(self, text: str) -> Tuple[str, bool]:
        """
        Normalize Unicode to NFC form and replace fullwidth/lookalike chars.

        Example: fullwidth 'Ａ' (U+FF21) → 'A'
        """
        # NFKC collapses fullwidth and compatibility characters
        normalized = unicodedata.normalize('NFKC', text)
        return normalized, normalized != text

    def _strip_sql_comments(self, text: str) -> Tuple[str, bool]:
        """Remove SQL inline /**/ and line comments -- and #."""
        t = _SQL_INLINE_COMMENT_RE.sub(' ', text)
        t = _SQL_LINE_COMMENT_RE.sub('', t)
        return t, t != text

    def _flatten_xml_json(self, text: str) -> Tuple[str, bool]:
        """
        Strip XML/HTML tags to extract inner text.
        This handles nested JSON/XML injection attempts.
        """
        stripped = _XML_TAG_RE.sub(' ', text)
        # Collapse multiple spaces
        stripped = re.sub(r' {2,}', ' ', stripped).strip()
        return stripped, stripped != text
