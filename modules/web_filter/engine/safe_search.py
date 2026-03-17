import urllib.parse
from typing import Tuple

class SafeSearchEnforcer:
    """ Enforces safe search by rewriting URLs or checking search query string parameters """
    
    SEARCH_ENGINES = {
        "google": {"param": "safe", "value": "active"},
        "bing": {"param": "adlt", "value": "strict"},
        "youtube": {"param": "restrict", "value": "true"},
        "duckduckgo": {"param": "kp", "value": "1"}
    }
    
    @classmethod
    def apply_safe_search(cls, url: str) -> Tuple[bool, str]:
        """ 
        Detects if URL is a search engine and appends the safe search flag if missing.
        Returns (was_modified, new_url)
        """
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            for engine, config in cls.SEARCH_ENGINES.items():
                if engine in domain:
                    query = urllib.parse.parse_qs(parsed.query)
                    
                    if config["param"] not in query or query[config["param"]][0] != config["value"]:
                        query[config["param"]] = [config["value"]]
                        new_query = urllib.parse.urlencode(query, doseq=True)
                        new_url = urllib.parse.urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment
                        ))
                        return True, new_url
                        
            return False, url
        except Exception:
            return False, url
