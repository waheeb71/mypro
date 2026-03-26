"""
Enterprise CyberNexus — Email Preprocessor

Parses MIME email messages and extracts:
  - Plain text body (from text/plain or stripped HTML)
  - Subject + headers
  - All URLs found in body
  - Attachment list with metadata
  - Decoded body (Base64 / Quoted-Printable → UTF-8)
"""

import base64
import logging
import quopri
import re
import math
from dataclasses import dataclass, field
from email import policy as email_policy
from email.parser import BytesParser
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+(?=[<"\'\s]|$)',
    re.IGNORECASE
)
_HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
_HREF_PATTERN = re.compile(r'href=["\']?(https?://[^\s"\'<>]+)', re.IGNORECASE)


@dataclass
class EmailAttachment:
    filename: str
    content_type: str
    size_bytes: int
    extension: str
    payload: bytes = field(default=b'', repr=False)   # raw bytes for entropy calc


@dataclass
class ParsedEmail:
    """Structured representation of a parsed email message."""
    raw_from:     str = ""
    raw_to:       str = ""
    subject:      str = ""
    date:         str = ""
    message_id:   str = ""
    reply_to:     str = ""
    headers:      Dict[str, str] = field(default_factory=dict)
    body_text:    str = ""         # stripped / decoded plain text
    body_html:    str = ""         # raw HTML if present
    urls:         List[str] = field(default_factory=list)
    attachments:  List[EmailAttachment] = field(default_factory=list)
    sender_ip:    str = ""         # extracted from Received headers
    encoding_used: str = ""        # base64 | quoted-printable | 7bit


class EmailPreprocessor:
    """
    Parse raw SMTP stream or raw email bytes into a structured ParsedEmail.

    Handles:
    - Full MIME multipart messages
    - Base64 and Quoted-Printable encoded bodies
    - HTML → plain text stripping (for content analysis)
    - URL extraction from body and href attributes
    - Attachment metadata extraction (filename, size, type, raw bytes for entropy)
    """

    def __init__(
        self,
        decode_base64:          bool = True,
        decode_qp:              bool = True,
        extract_plain_text:     bool = True,
        max_body_bytes:         int  = 524_288,   # 512 KB
    ):
        self.decode_base64      = decode_base64
        self.decode_qp          = decode_qp
        self.extract_plain_text = extract_plain_text
        self.max_body_bytes     = max_body_bytes

    # ── Public API ──────────────────────────────

    def parse(self, data: bytes) -> Optional[ParsedEmail]:
        """
        Parse raw bytes into a ParsedEmail.

        Returns None if the data doesn't look like an email at all.
        """
        try:
            parser = BytesParser(policy=email_policy.default)
            msg = parser.parsebytes(data[:self.max_body_bytes])

            parsed = ParsedEmail(
                raw_from   = str(msg.get("From",       "")),
                raw_to     = str(msg.get("To",         "")),
                subject    = str(msg.get("Subject",    "")),
                date       = str(msg.get("Date",       "")),
                message_id = str(msg.get("Message-ID", "")),
                reply_to   = str(msg.get("Reply-To",   "")),
                headers    = {k: str(v) for k, v in msg.items()},
            )

            # Extract sender IP from Received headers
            parsed.sender_ip = self._extract_sender_ip(parsed.headers)

            # Walk MIME parts
            if msg.is_multipart():
                for part in msg.walk():
                    self._process_part(part, parsed)
            else:
                self._process_part(msg, parsed)

            # Extract URLs from body + HTML
            parsed.urls = self._extract_urls(parsed.body_text + " " + parsed.body_html)

            return parsed

        except Exception as e:
            logger.debug("EmailPreprocessor.parse failed: %s", e)
            return None

    # ── Internal helpers ────────────────────────

    def _process_part(self, part, parsed: ParsedEmail) -> None:
        content_type = part.get_content_type()
        disposition  = part.get_content_disposition() or ""

        encoding = str(part.get("Content-Transfer-Encoding", "7bit")).lower()
        parsed.encoding_used = encoding

        # ── Attachment ───────────────────────────
        if "attachment" in disposition or "inline" in disposition:
            filename = part.get_filename() or ""
            try:
                raw_bytes = part.get_payload(decode=True) or b''
            except Exception:
                raw_bytes = b''
            ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
            parsed.attachments.append(EmailAttachment(
                filename     = filename,
                content_type = content_type,
                size_bytes   = len(raw_bytes),
                extension    = ext,
                payload      = raw_bytes,
            ))
            return

        # ── Text body ────────────────────────────
        if content_type == "text/plain":
            try:
                text = part.get_content() or ""
                parsed.body_text += text[:self.max_body_bytes]
            except Exception:
                raw = part.get_payload(decode=True) or b''
                parsed.body_text += raw.decode("utf-8", errors="replace")[:self.max_body_bytes]

        elif content_type == "text/html":
            try:
                html = part.get_content() or ""
            except Exception:
                raw = part.get_payload(decode=True) or b''
                html = raw.decode("utf-8", errors="replace")
            parsed.body_html += html[:self.max_body_bytes]
            if self.extract_plain_text:
                # Add stripped version to body_text for content analysis
                parsed.body_text += "\n" + self._html_to_text(html)

    @staticmethod
    def _html_to_text(html: str) -> str:
        """Strip HTML tags and decode common entities."""
        text = _HTML_TAG_PATTERN.sub(" ", html)
        for entity, char in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                               ("&nbsp;", " "), ("&quot;", '"'), ("&#39;", "'")]:
            text = text.replace(entity, char)
        return " ".join(text.split())

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """Extract all unique URLs from text (both plain and href attributes)."""
        urls = set(_URL_PATTERN.findall(text))
        urls |= set(_HREF_PATTERN.findall(text))
        return list(urls)

    @staticmethod
    def _extract_sender_ip(headers: Dict[str, str]) -> str:
        """
        Extract the originating IP from Received: headers.
        Looks for the last (outermost) Received header — closest to attacker.
        """
        received_headers = [v for k, v in headers.items()
                            if k.lower() == "received"]
        ip_pattern = re.compile(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]')
        for header in reversed(received_headers):
            match = ip_pattern.search(header)
            if match:
                return match.group(1)
        return ""
