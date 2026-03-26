"""
Enterprise CyberNexus — Email Attachment Guard

Scans email attachments for threats:
  1. Dangerous file extensions (block immediately)
  2. Suspicious extensions (raise score)
  3. MIME type mismatch (extension ≠ actual content type)
  4. Shannon Entropy analysis (high entropy = possibly encrypted/obfuscated malware)
  5. Oversized attachments
"""

import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 = ordered, 1.0 = random/encrypted)."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    return entropy / 8.0   # normalize to 0..1 (max entropy for 8-bit = 8 bits)


@dataclass
class AttachmentScanResult:
    filename:   str
    score:      float = 0.0
    flags:      List[str] = field(default_factory=list)
    entropy:    float = 0.0
    action:     str = "allow"   # allow | flag | block


@dataclass
class AttachmentGuardResult:
    score:    float = 0.0
    findings: List[AttachmentScanResult] = field(default_factory=list)
    blocked:  bool = False


class AttachmentGuard:
    """
    Scan email attachments for threats.

    Args:
        block_dangerous:       Immediately block dangerous extensions
        analyze_entropy:       Run entropy check on attachment bytes
        entropy_threshold:     Score above this = suspicious encrypted content
        max_size_mb:           Flag oversized attachments
        dangerous_extensions:  Set of extensions that trigger instant BLOCK
        suspicious_extensions: Set of extensions that raise the risk score
    """

    def __init__(
        self,
        block_dangerous:       bool = True,
        analyze_entropy:       bool = True,
        entropy_threshold:     float = 0.92,
        max_size_mb:           int = 25,
        dangerous_extensions:  Optional[List[str]] = None,
        suspicious_extensions: Optional[List[str]] = None,
    ):
        self.block_dangerous   = block_dangerous
        self.analyze_entropy   = analyze_entropy
        self.entropy_threshold = entropy_threshold
        self.max_size_mb       = max_size_mb

        self.dangerous_extensions = set(dangerous_extensions or [
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
            ".js", ".jar", ".msi", ".dll", ".ps1", ".psm1",
            ".hta", ".lnk", ".reg", ".inf",
        ])
        self.suspicious_extensions = set(suspicious_extensions or [
            ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"
        ])

    def scan(self, attachments) -> AttachmentGuardResult:
        """
        Scan a list of EmailAttachment objects.

        Args:
            attachments: List[EmailAttachment] from EmailPreprocessor
        """
        result = AttachmentGuardResult()
        if not attachments:
            return result

        for att in attachments:
            scan = self._scan_attachment(att)
            result.findings.append(scan)
            result.score = max(result.score, scan.score)
            if scan.action == "block":
                result.blocked = True

        return result

    def _scan_attachment(self, att) -> AttachmentScanResult:
        scan = AttachmentScanResult(filename=att.filename)
        ext  = att.extension.lower()

        # 1. Dangerous extension → instant block
        if ext in self.dangerous_extensions:
            if self.block_dangerous:
                scan.action = "block"
                scan.score  = 1.0
            else:
                scan.score = 0.9
            scan.flags.append(f"dangerous_extension:{ext}")
            return scan   # no need to scan further

        # 2. Suspicious extension
        if ext in self.suspicious_extensions:
            scan.score += 0.4
            scan.flags.append(f"suspicious_extension:{ext}")
            if ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
                scan.flags.append("compressed_container")

        # 3. Oversized attachment
        size_mb = att.size_bytes / (1024 * 1024)
        if size_mb > self.max_size_mb:
            scan.score += 0.2
            scan.flags.append(f"oversized:{size_mb:.1f}MB")

        # 4. Entropy analysis
        if self.analyze_entropy and att.payload:
            scan.entropy = _shannon_entropy(att.payload)
            if scan.entropy > self.entropy_threshold:
                scan.score += 0.35
                scan.flags.append(f"high_entropy:{scan.entropy:.2f}")

        # 5. MIME mismatch (claimed text/plain but has .exe extension, etc.)
        if att.content_type == "text/plain" and ext in {
            ".exe", ".dll", ".bat", ".scr"
        }:
            scan.score += 0.3
            scan.flags.append("mime_mismatch")

        scan.score = min(scan.score, 1.0)
        if scan.score >= 0.8:
            scan.action = "block"
        elif scan.score >= 0.4:
            scan.action = "flag"

        return scan
