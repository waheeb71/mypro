import logging

logger = logging.getLogger(__name__)

class DNSTunnelingDetector:
    """ Detects DNS tunneling (e.g., iodine, dnscat2) by analyzing query lengths and types """
    
    MAX_SUBDOMAIN_LENGTH = 50
    MAX_TOTAL_LENGTH = 150
    SUSPICIOUS_TYPES = ['TXT', 'NULL', 'SRV', 'MX']
    
    @classmethod
    def is_tunneling(cls, domain: str, query_type: str = 'A') -> bool:
        """ Returns True if the DNS query exhibits tunneling characteristics """
        
        if query_type.upper() in cls.SUSPICIOUS_TYPES and len(domain) > 60:
            logger.info(f"DNS Tunneling (Suspicious Type/Length): {domain} [{query_type}]")
            return True
            
        if len(domain) > cls.MAX_TOTAL_LENGTH:
            logger.info(f"DNS Tunneling (Total Length): length {len(domain)}")
            return True
            
        labels = domain.split('.')
        for label in labels:
            if len(label) > cls.MAX_SUBDOMAIN_LENGTH:
                logger.debug(f"DNS Tunneling (Label Length): label '{label[:10]}...' is {len(label)} chars")
                return True
                
        longest_label = max(labels, key=len) if labels else ""
        if len(longest_label) > 30 and sum(c.isalpha() or c.isdigit() for c in longest_label) == len(longest_label):
            pass
            
        return False
