import logging
import mimetypes

logger = logging.getLogger(__name__)

class FileParser:
    """ Extracts text from various file formats for DLP inspection """
    
    @classmethod
    def extract_text(cls, file_bytes: bytes, filename: str = "") -> str:
        """
        Attempts to extract plain text from binary payloads.
        In a full enterprise context, this would link to deep parsers (e.g. Apache Tika).
        For performance on an NGFW, we do quick extraction.
        """
        mime_type, _ = mimetypes.guess_type(filename)
        
        try:
            return file_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Failed extracting text from {filename}: {e}")
            return ""
