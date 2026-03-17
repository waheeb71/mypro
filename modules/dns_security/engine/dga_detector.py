import math
import logging
from collections import Counter

logger = logging.getLogger(__name__)

class DGADetector:
    """ Detects Domain Generation Algorithms (DGA) based on Shannon Entropy and n-gram analysis """
    
    @staticmethod
    def shannon_entropy(domain_str: str) -> float:
        """ Calculates the Shannon entropy of a domain string. High entropy often means DGA. """
        if not domain_str:
            return 0.0
            
        clean_str = domain_str.split('.')[0] if '.' in domain_str else domain_str
        
        counts = Counter(clean_str)
        lengths = len(clean_str)
        
        entropy = -sum((count / lengths) * math.log2(count / lengths) for count in counts.values())
        return entropy
        
    @classmethod
    def is_dga(cls, domain: str, threshold: float = 3.8) -> bool:
        """ 
        Returns True if the domain is likely DGA.
        """
        entropy = cls.shannon_entropy(domain)
        is_dga = entropy >= threshold
        if is_dga:
            logger.info(f"DGA Detected: {domain} (Entropy: {entropy:.2f})")
        return is_dga
