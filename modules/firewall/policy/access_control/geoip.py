"""
Enterprise CyberNexus v2.0 - GeoIP Filter
Country-based traffic filtering using MaxMind GeoIP2 database.
"""

import logging
import ipaddress
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import threading

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    # logging.warning("geoip2 not available - GeoIP filtering disabled")

@dataclass
class CountryInfo:
    """Geographic information for an IP"""
    ip: str
    country_code: str  # ISO 3166-1 alpha-2 (e.g., 'US', 'CN')
    country_name: str
    continent_code: str  # e.g., 'NA', 'AS', 'EU'
    continent_name: str
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False

class GeoIPFilter:
    """
    GeoIP-based traffic filtering.
    Supports:
    - Country whitelist/blacklist
    - Continent-level filtering
    - ASN-based blocking
    - Anonymous proxy detection
    """
    
    def __init__(
        self,
        db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.db_path = Path(db_path) if db_path else None
        self.asn_db_path = Path(asn_db_path) if asn_db_path else None
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        self.reader: Optional[geoip2.database.Reader] = None
        self.asn_reader: Optional[geoip2.database.Reader] = None
        
        # Filtering configuration
        self._country_whitelist: Set[str] = set()
        self._country_blacklist: Set[str] = set()
        self._continent_blacklist: Set[str] = set()
        self._asn_blacklist: Set[int] = set()
        
        # Settings
        self._block_anonymous_proxies = False
        self._block_satellite_providers = False
        
        self._lock = threading.RLock()
        
        if GEOIP2_AVAILABLE:
            self._load_databases()
            
    def _load_databases(self) -> bool:
        """Load GeoIP2 databases"""
        try:
            if self.db_path and self.db_path.exists():
                self.reader = geoip2.database.Reader(str(self.db_path))
                self.logger.info(f"Loaded GeoIP database: {self.db_path}")
            
            if self.asn_db_path and self.asn_db_path.exists():
                self.asn_reader = geoip2.database.Reader(str(self.asn_db_path))
                self.logger.info(f"Loaded ASN database: {self.asn_db_path}")
                
            return self.reader is not None
        except Exception as e:
            self.logger.error(f"Failed to load GeoIP databases: {e}")
            return False
            
    def lookup(self, ip: str) -> Optional[CountryInfo]:
        """Lookup geographic information for IP"""
        if not GEOIP2_AVAILABLE or not self.reader:
            return None
            
        try:
            response = self.reader.city(ip)
            
            asn = None
            asn_org = None
            if self.asn_reader:
                try:
                    asn_response = self.asn_reader.asn(ip)
                    asn = asn_response.autonomous_system_number
                    asn_org = asn_response.autonomous_system_organization
                except:
                    pass
                    
            country_code = response.country.iso_code or 'XX'
            
            return CountryInfo(
                ip=ip,
                country_code=country_code,
                country_name=response.country.name or 'Unknown',
                continent_code=response.continent.code or 'XX',
                continent_name=response.continent.name or 'Unknown',
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                asn=asn,
                asn_org=asn_org,
                is_anonymous_proxy=response.traits.is_anonymous_proxy,
                is_satellite_provider=response.traits.is_satellite_provider
            )
        except Exception:
            return None
            
    def is_blocked(self, ip: str) -> tuple[bool, Optional[str]]:
        """Check if IP should be blocked based on GeoIP"""
        info = self.lookup(ip)
        if not info:
            return False, None
            
        with self._lock:
            if self._block_anonymous_proxies and info.is_anonymous_proxy:
                return True, "Anonymous proxy blocked"
                
            if self._block_satellite_providers and info.is_satellite_provider:
                return True, "Satellite provider blocked"
                
            if info.asn and info.asn in self._asn_blacklist:
                return True, f"ASN {info.asn} blocked"
                
            if self._country_whitelist:
                if info.country_code not in self._country_whitelist:
                    return True, f"Country {info.country_code} not whitelisted"
                    
            if info.country_code in self._country_blacklist:
                return True, f"Country {info.country_code} blacklisted"
                
            if info.continent_code in self._continent_blacklist:
                return True, f"Continent {info.continent_code} blacklisted"
                
        return False, None

    # Helper methods for blacklist/whitelist management (omitted for brevity but implied)
    def blacklist_country(self, code: str):
        self._country_blacklist.add(code.upper())
    
    def whitelist_country(self, code: str):
        self._country_whitelist.add(code.upper())
