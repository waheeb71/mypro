"""
Enterprise NGFW v2.0 - GeoIP Filter

Country-based traffic filtering using MaxMind GeoIP2 database.

Features:
- IP to country/city mapping
- Whitelist/blacklist by country
- Continent-level blocking
- ASN filtering
- GeoIP statistics

Author: Enterprise NGFW Team
License: Proprietary
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
    logging.warning("geoip2 not available - GeoIP filtering disabled")


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
        db_path: Optional[Path] = None,
        asn_db_path: Optional[Path] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.db_path = db_path
        self.asn_db_path = asn_db_path
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        self.reader: Optional[geoip2.database.Reader] = None
        self.asn_reader: Optional[geoip2.database.Reader] = None
        
        # Filtering configuration
        self._country_whitelist: Set[str] = set()  # ISO codes
        self._country_blacklist: Set[str] = set()
        self._continent_blacklist: Set[str] = set()
        self._asn_blacklist: Set[int] = set()
        
        # Settings
        self._block_anonymous_proxies = False
        self._block_satellite_providers = False
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._lookups = 0
        self._blocked_by_country = 0
        self._blocked_by_asn = 0
        self._country_stats: Dict[str, int] = {}
        
        # Initialize
        if GEOIP2_AVAILABLE:
            self._load_databases()
            
    def _load_databases(self) -> bool:
        """Load GeoIP2 databases"""
        try:
            if self.db_path and self.db_path.exists():
                self.reader = geoip2.database.Reader(str(self.db_path))
                self.logger.info(f"Loaded GeoIP database: {self.db_path}")
            else:
                self.logger.warning("GeoIP database not found, using fallback mode")
                
            if self.asn_db_path and self.asn_db_path.exists():
                self.asn_reader = geoip2.database.Reader(str(self.asn_db_path))
                self.logger.info(f"Loaded ASN database: {self.asn_db_path}")
                
            return self.reader is not None
            
        except Exception as e:
            self.logger.error(f"Failed to load GeoIP databases: {e}")
            return False
            
    def lookup(self, ip: str) -> Optional[CountryInfo]:
        """
        Lookup geographic information for IP.
        
        Args:
            ip: IP address
            
        Returns:
            CountryInfo object or None if lookup fails
        """
        if not GEOIP2_AVAILABLE or not self.reader:
            return None
            
        with self._lock:
            self._lookups += 1
            
        try:
            response = self.reader.city(ip)
            
            # Get ASN info if available
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
            
            # Update statistics
            with self._lock:
                self._country_stats[country_code] = self._country_stats.get(country_code, 0) + 1
                
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
            
        except geoip2.errors.AddressNotFoundError:
            self.logger.debug(f"IP not found in GeoIP database: {ip}")
            return None
        except Exception as e:
            self.logger.error(f"GeoIP lookup failed for {ip}: {e}")
            return None
            
    def is_blocked(self, ip: str) -> tuple[bool, Optional[str]]:
        """
        Check if IP should be blocked based on GeoIP.
        
        Args:
            ip: IP address
            
        Returns:
            (is_blocked, reason) tuple
        """
        info = self.lookup(ip)
        
        if not info:
            # No GeoIP info: apply default policy
            return False, None
            
        with self._lock:
            # Check anonymous proxy blocking
            if self._block_anonymous_proxies and info.is_anonymous_proxy:
                self.logger.info(f"Blocked anonymous proxy: {ip}")
                return True, "Anonymous proxy blocked"
                
            # Check satellite provider blocking
            if self._block_satellite_providers and info.is_satellite_provider:
                self.logger.info(f"Blocked satellite provider: {ip}")
                return True, "Satellite provider blocked"
                
            # Check ASN blacklist
            if info.asn and info.asn in self._asn_blacklist:
                self._blocked_by_asn += 1
                self.logger.info(f"Blocked by ASN: {ip} (ASN{info.asn})")
                return True, f"ASN {info.asn} blocked"
                
            # Check country whitelist (if active, only whitelisted allowed)
            if self._country_whitelist:
                if info.country_code not in self._country_whitelist:
                    self._blocked_by_country += 1
                    self.logger.info(
                        f"Blocked (not in whitelist): {ip} ({info.country_code})"
                    )
                    return True, f"Country {info.country_code} not whitelisted"
                    
            # Check country blacklist
            if info.country_code in self._country_blacklist:
                self._blocked_by_country += 1
                self.logger.info(f"Blocked by country: {ip} ({info.country_code})")
                return True, f"Country {info.country_code} blacklisted"
                
            # Check continent blacklist
            if info.continent_code in self._continent_blacklist:
                self._blocked_by_country += 1
                self.logger.info(
                    f"Blocked by continent: {ip} ({info.continent_code})"
                )
                return True, f"Continent {info.continent_code} blacklisted"
                
        return False, None
        
    def whitelist_country(self, country_code: str) -> None:
        """Add country to whitelist (ISO 3166-1 alpha-2)"""
        with self._lock:
            country_code = country_code.upper()
            self._country_whitelist.add(country_code)
            self.logger.info(f"Added country to whitelist: {country_code}")
            
    def blacklist_country(self, country_code: str) -> None:
        """Add country to blacklist"""
        with self._lock:
            country_code = country_code.upper()
            self._country_blacklist.add(country_code)
            self.logger.info(f"Added country to blacklist: {country_code}")
            
    def blacklist_continent(self, continent_code: str) -> None:
        """Add continent to blacklist (e.g., 'AS', 'EU', 'NA')"""
        with self._lock:
            continent_code = continent_code.upper()
            self._continent_blacklist.add(continent_code)
            self.logger.info(f"Added continent to blacklist: {continent_code}")
            
    def blacklist_asn(self, asn: int) -> None:
        """Add ASN to blacklist"""
        with self._lock:
            self._asn_blacklist.add(asn)
            self.logger.info(f"Added ASN to blacklist: {asn}")
            
    def remove_from_whitelist(self, country_code: str) -> None:
        """Remove country from whitelist"""
        with self._lock:
            country_code = country_code.upper()
            self._country_whitelist.discard(country_code)
            
    def remove_from_blacklist(self, country_code: str) -> None:
        """Remove country from blacklist"""
        with self._lock:
            country_code = country_code.upper()
            self._country_blacklist.discard(country_code)
            
    def set_block_anonymous_proxies(self, enabled: bool) -> None:
        """Enable/disable anonymous proxy blocking"""
        with self._lock:
            self._block_anonymous_proxies = enabled
            self.logger.info(f"Anonymous proxy blocking: {enabled}")
            
    def set_block_satellite_providers(self, enabled: bool) -> None:
        """Enable/disable satellite provider blocking"""
        with self._lock:
            self._block_satellite_providers = enabled
            self.logger.info(f"Satellite provider blocking: {enabled}")
            
    def get_top_countries(self, n: int = 10) -> List[tuple[str, int]]:
        """Get top N countries by traffic volume"""
        with self._lock:
            sorted_countries = sorted(
                self._country_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_countries[:n]
            
    def get_statistics(self) -> Dict:
        """Get GeoIP filter statistics"""
        with self._lock:
            return {
                'total_lookups': self._lookups,
                'blocked_by_country': self._blocked_by_country,
                'blocked_by_asn': self._blocked_by_asn,
                'country_whitelist_size': len(self._country_whitelist),
                'country_blacklist_size': len(self._country_blacklist),
                'continent_blacklist_size': len(self._continent_blacklist),
                'asn_blacklist_size': len(self._asn_blacklist),
                'unique_countries_seen': len(self._country_stats),
                'block_anonymous_proxies': self._block_anonymous_proxies,
                'block_satellite_providers': self._block_satellite_providers
            }
            
    def get_config(self) -> Dict:
        """Get current GeoIP configuration"""
        with self._lock:
            return {
                'country_whitelist': list(self._country_whitelist),
                'country_blacklist': list(self._country_blacklist),
                'continent_blacklist': list(self._continent_blacklist),
                'asn_blacklist': list(self._asn_blacklist),
                'block_anonymous_proxies': self._block_anonymous_proxies,
                'block_satellite_providers': self._block_satellite_providers
            }
            
    def __del__(self):
        """Cleanup GeoIP readers"""
        if self.reader:
            self.reader.close()
        if self.asn_reader:
            self.asn_reader.close()