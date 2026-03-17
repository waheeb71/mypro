import time
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class ConnectionState:
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    RELATED = "RELATED"
    INVALID = "INVALID"

class StateTracker:
    """ Tracks connection states for Stateful Firewall functionality """
    def __init__(self, timeout_seconds=300):
        self.timeout_seconds = timeout_seconds
        # dict mapping (src_ip, src_port, dst_ip, dst_port, protocol) to (state, last_seen)
        self.state_table: Dict[tuple, dict] = {} 
        
    def _get_key(self, src_ip, src_port, dst_ip, dst_port, proto):
        # normalize direction
        if src_ip < dst_ip:
            return (src_ip, src_port, dst_ip, dst_port, proto)
        return (dst_ip, dst_port, src_ip, src_port, proto)
        
    def get_or_update_state(self, src_ip, src_port, dst_ip, dst_port, proto) -> str:
        key = self._get_key(src_ip, src_port, dst_ip, dst_port, proto)
        now = time.time()
        
        if key in self.state_table:
            conn = self.state_table[key]
            if now - conn['last_seen'] > self.timeout_seconds:
                # Expired
                self.state_table[key] = {'state': ConnectionState.NEW, 'last_seen': now}
                return ConnectionState.NEW
            else:
                conn['last_seen'] = now
                if conn['state'] == ConnectionState.NEW:
                    conn['state'] = ConnectionState.ESTABLISHED
                return conn['state']
        else:
            self.state_table[key] = {'state': ConnectionState.NEW, 'last_seen': now}
            return ConnectionState.NEW
            
    def cleanup(self):
        now = time.time()
        expired_keys = [k for k, v in self.state_table.items() if now - v['last_seen'] > self.timeout_seconds]
        for k in expired_keys:
            del self.state_table[k]
        logger.debug(f"StateTracker cleanup: removed {len(expired_keys)} expired connections. Active: {len(self.state_table)}")
