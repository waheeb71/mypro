"""
Safe Search Enforcement
Enforces safe search on Google, Bing, DuckDuckGo, etc.
"""

class SafeSearch:
    """
    Modifies DNS or HTTP requests to enforce SafeSearch.
    """
    
    SAFE_SEARCH_CNAMES = {
        "google.com": "forcesafesearch.google.com",
        "www.google.com": "forcesafesearch.google.com",
        "bing.com": "strict.bing.com",
        "www.bing.com": "strict.bing.com",
        "duckduckgo.com": "safe.duckduckgo.com",
    }
    
    @staticmethod
    def get_safe_cname(domain: str) -> str:
        """Get SafeSearch CNAME for a domain if applicable"""
        return SafeSearch.SAFE_SEARCH_CNAMES.get(domain)

    @staticmethod
    def append_safe_param(url: str) -> str:
        """Append safe search query param to URL"""
        if "google.com" in url and "safe=active" not in url:
             if "?" in url:
                 return url + "&safe=active"
             else:
                 return url + "?safe=active"
        return url
