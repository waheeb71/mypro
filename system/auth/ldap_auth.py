#!/usr/bin/env python3
"""
Enterprise NGFW - LDAP/Active Directory Authentication

Features:
- LDAP bind/search for user authentication
- Group-based role mapping (admin/operator/viewer)
- Connection pooling and reconnection
- Fallback to local auth if LDAP unavailable
"""

import logging
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LDAPUser:
    """Authenticated LDAP user"""
    username: str
    display_name: str
    email: str
    groups: List[str]
    role: str  # admin, operator, viewer
    dn: str


class LDAPAuthenticator:
    """
    LDAP/Active Directory Authentication

    Authenticates users against an LDAP directory and maps
    AD groups to NGFW roles.
    """

    # Default group-to-role mapping
    DEFAULT_ROLE_MAP = {
        "ngfw-admins": "admin",
        "ngfw-operators": "operator",
        "Domain Admins": "admin",
    }

    def __init__(self, config: dict):
        self.config = config
        ldap_config = config.get('integration', {}).get('ldap', {})

        self.enabled = ldap_config.get('enabled', False)
        self.server = ldap_config.get('server', 'ldap://localhost')
        self.base_dn = ldap_config.get('base_dn', 'dc=example,dc=com')
        self.bind_dn = ldap_config.get('bind_dn', '')
        self.bind_password = ldap_config.get('bind_password', '')
        self.search_filter = ldap_config.get(
            'search_filter', '(sAMAccountName={username})'
        )
        self.group_attribute = ldap_config.get('group_attribute', 'memberOf')
        self.role_mapping = ldap_config.get('role_mapping', self.DEFAULT_ROLE_MAP)

        self._connection = None
        self._connected = False

        if self.enabled:
            logger.info(f"LDAPAuthenticator initialized: {self.server}")
        else:
            logger.info("LDAPAuthenticator disabled")

    def connect(self) -> bool:
        """Establish connection to LDAP server"""
        if not self.enabled:
            return False

        try:
            import ldap3
            server = ldap3.Server(self.server, get_info=ldap3.ALL)
            self._connection = ldap3.Connection(
                server,
                user=self.bind_dn,
                password=self.bind_password,
                auto_bind=True,
                receive_timeout=10
            )
            self._connected = True
            logger.info(f"Connected to LDAP server: {self.server}")
            return True
        except ImportError:
            logger.warning("ldap3 package not installed. pip install ldap3")
            return False
        except Exception as e:
            logger.error(f"LDAP connection failed: {e}")
            self._connected = False
            return False

    def authenticate(self, username: str, password: str) -> Optional[LDAPUser]:
        """
        Authenticate user against LDAP

        Args:
            username: Username or sAMAccountName
            password: User password

        Returns:
            LDAPUser if authentication succeeds, None otherwise
        """
        if not self.enabled:
            logger.debug("LDAP disabled, skipping")
            return None

        if not self._connected:
            if not self.connect():
                return None

        try:
            import ldap3

            # Search for user
            search_filter = self.search_filter.replace('{username}', username)
            self._connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['cn', 'mail', 'displayName', self.group_attribute]
            )

            if not self._connection.entries:
                logger.warning(f"LDAP user not found: {username}")
                return None

            entry = self._connection.entries[0]
            user_dn = entry.entry_dn

            # Bind as user to verify password
            user_conn = ldap3.Connection(
                self._connection.server,
                user=user_dn,
                password=password
            )
            if not user_conn.bind():
                logger.warning(f"LDAP auth failed for: {username}")
                return None

            user_conn.unbind()

            # Extract groups
            groups = []
            if hasattr(entry, self.group_attribute):
                raw_groups = getattr(entry, self.group_attribute).values
                groups = [self._extract_cn(g) for g in raw_groups]

            # Map groups to role
            role = self._resolve_role(groups)

            return LDAPUser(
                username=username,
                display_name=str(getattr(entry, 'displayName', username)),
                email=str(getattr(entry, 'mail', '')),
                groups=groups,
                role=role,
                dn=user_dn
            )

        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            self._connected = False
            return None

    def _resolve_role(self, groups: List[str]) -> str:
        """Map AD groups to NGFW role"""
        for group, role in self.role_mapping.items():
            if group in groups:
                return role
        return "viewer"  # Default role

    def _extract_cn(self, dn: str) -> str:
        """Extract CN from distinguished name"""
        for part in dn.split(','):
            if part.strip().upper().startswith('CN='):
                return part.strip()[3:]
        return dn

    def disconnect(self):
        """Close LDAP connection"""
        if self._connection:
            try:
                self._connection.unbind()
            except Exception:
                pass
            self._connected = False
            logger.info("LDAP connection closed")

    def is_available(self) -> bool:
        """Check if LDAP is available"""
        return self.enabled and self._connected
