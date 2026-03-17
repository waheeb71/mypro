#!/usr/bin/env python3
"""
Enterprise NGFW - SIEM Integration

Connectors for sending security events to SIEM systems:
- Syslog (RFC 5424) over UDP/TCP/TLS
- Elasticsearch bulk API
- Splunk HEC (HTTP Event Collector)

Features:
- Buffered async sending with retry
- Configurable event formatting
- Health monitoring
"""

import asyncio
import json
import logging
import socket
import ssl
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SIEMEvent:
    """Normalized event for SIEM export"""
    timestamp: str
    severity: str  # info, warning, critical
    event_type: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str  # allow, block, monitor
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_syslog(self, facility: int = 1) -> str:
        """Convert to RFC 5424 syslog format"""
        severity_map = {'info': 6, 'warning': 4, 'critical': 2}
        sev = severity_map.get(self.severity, 6)
        pri = facility * 8 + sev
        return (
            f"<{pri}>1 {self.timestamp} ngfw - - - - "
            f"[ngfw action=\"{self.action}\" src=\"{self.source_ip}:{self.source_port}\" "
            f"dst=\"{self.destination_ip}:{self.destination_port}\" "
            f"proto=\"{self.protocol}\"] {self.description}"
        )

    def to_elastic(self) -> dict:
        """Convert to Elasticsearch document"""
        return {
            '@timestamp': self.timestamp,
            'severity': self.severity,
            'event_type': self.event_type,
            'source': {'ip': self.source_ip, 'port': self.source_port},
            'destination': {'ip': self.destination_ip, 'port': self.destination_port},
            'network': {'protocol': self.protocol},
            'action': self.action,
            'message': self.description,
            **self.metadata
        }

    def to_splunk_hec(self) -> dict:
        """Convert to Splunk HEC format"""
        return {
            'time': self.timestamp,
            'sourcetype': 'ngfw:security',
            'event': {
                'severity': self.severity,
                'event_type': self.event_type,
                'src_ip': self.source_ip,
                'dst_ip': self.destination_ip,
                'src_port': self.source_port,
                'dst_port': self.destination_port,
                'protocol': self.protocol,
                'action': self.action,
                'description': self.description,
                **self.metadata
            }
        }


class SIEMConnector(ABC):
    """Base SIEM connector"""

    def __init__(self, config: dict):
        self.config = config
        self._buffer: List[SIEMEvent] = []
        self._buffer_size = config.get('buffer_size', 100)
        self._flush_interval = config.get('flush_interval', 10)
        self._retry_count = config.get('retry_count', 3)
        self._running = False
        self.stats = {'sent': 0, 'failed': 0, 'buffered': 0}

    @abstractmethod
    async def _send_batch(self, events: List[SIEMEvent]) -> bool:
        """Send batch of events to SIEM"""
        pass

    async def send(self, event: SIEMEvent):
        """Buffer and send event"""
        self._buffer.append(event)
        self.stats['buffered'] = len(self._buffer)

        if len(self._buffer) >= self._buffer_size:
            await self.flush()

    async def flush(self):
        """Flush buffered events"""
        if not self._buffer:
            return

        batch = self._buffer.copy()
        self._buffer.clear()
        self.stats['buffered'] = 0

        for attempt in range(self._retry_count):
            try:
                if await self._send_batch(batch):
                    self.stats['sent'] += len(batch)
                    return
            except Exception as e:
                logger.warning(f"SIEM send attempt {attempt+1} failed: {e}")
                await asyncio.sleep(2 ** attempt)

        self.stats['failed'] += len(batch)
        logger.error(f"SIEM: Failed to send {len(batch)} events after retries")

    async def start(self):
        """Start background flush loop"""
        self._running = True
        asyncio.create_task(self._flush_loop())

    async def stop(self):
        """Stop and flush remaining"""
        self._running = False
        await self.flush()

    async def _flush_loop(self):
        """Periodic flush loop"""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            await self.flush()


class SyslogConnector(SIEMConnector):
    """Syslog connector (RFC 5424 over UDP/TCP/TLS)"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.server = config.get('server', 'localhost')
        self.port = config.get('port', 514)
        self.protocol = config.get('protocol', 'udp').lower()
        self.use_tls = config.get('use_tls', False)
        self._socket = None
        logger.info(f"SyslogConnector → {self.server}:{self.port} ({self.protocol})")

    async def _send_batch(self, events: List[SIEMEvent]) -> bool:
        """Send syslog messages"""
        try:
            if self.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for event in events:
                    msg = event.to_syslog().encode('utf-8')
                    sock.sendto(msg, (self.server, self.port))
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.use_tls:
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=self.server)
                sock.connect((self.server, self.port))
                for event in events:
                    msg = event.to_syslog().encode('utf-8') + b'\n'
                    sock.sendall(msg)
                sock.close()
            return True
        except Exception as e:
            logger.error(f"Syslog send error: {e}")
            return False


class ElasticConnector(SIEMConnector):
    """Elasticsearch connector using bulk API"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.hosts = config.get('hosts', ['http://localhost:9200'])
        self.index_prefix = config.get('index_prefix', 'ngfw-events')
        self.api_key = config.get('api_key', '')
        logger.info(f"ElasticConnector → {self.hosts}")

    async def _send_batch(self, events: List[SIEMEvent]) -> bool:
        """Send events via Elasticsearch bulk API"""
        try:
            import aiohttp
            index = f"{self.index_prefix}-{datetime.now().strftime('%Y.%m.%d')}"

            # Build bulk request body
            lines = []
            for event in events:
                lines.append(json.dumps({"index": {"_index": index}}))
                lines.append(json.dumps(event.to_elastic()))
            body = '\n'.join(lines) + '\n'

            headers = {'Content-Type': 'application/x-ndjson'}
            if self.api_key:
                headers['Authorization'] = f'ApiKey {self.api_key}'

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.hosts[0]}/_bulk",
                    data=body,
                    headers=headers
                ) as resp:
                    return resp.status < 300

        except ImportError:
            logger.error("aiohttp not installed. pip install aiohttp")
            return False
        except Exception as e:
            logger.error(f"Elasticsearch send error: {e}")
            return False


class SplunkConnector(SIEMConnector):
    """Splunk HEC (HTTP Event Collector) connector"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.url = config.get('hec_url', 'https://localhost:8088/services/collector')
        self.token = config.get('hec_token', '')
        self.verify_ssl = config.get('verify_ssl', True)
        logger.info(f"SplunkConnector → {self.url}")

    async def _send_batch(self, events: List[SIEMEvent]) -> bool:
        """Send events via Splunk HEC"""
        try:
            import aiohttp
            headers = {
                'Authorization': f'Splunk {self.token}',
                'Content-Type': 'application/json'
            }

            body = '\n'.join(json.dumps(e.to_splunk_hec()) for e in events)

            ssl_ctx = None if self.verify_ssl else False
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    data=body,
                    headers=headers,
                    ssl=ssl_ctx
                ) as resp:
                    return resp.status == 200

        except ImportError:
            logger.error("aiohttp not installed. pip install aiohttp")
            return False
        except Exception as e:
            logger.error(f"Splunk HEC send error: {e}")
            return False


def create_siem_connector(config: dict) -> Optional[SIEMConnector]:
    """Factory to create the appropriate SIEM connector"""
    siem_config = config.get('integration', {}).get('siem', {})

    if not siem_config.get('enabled', False):
        logger.info("SIEM integration disabled")
        return None

    siem_type = siem_config.get('type', 'syslog').lower()

    if siem_type == 'syslog':
        return SyslogConnector(siem_config)
    elif siem_type in ('elk', 'elasticsearch', 'elastic'):
        return ElasticConnector(siem_config)
    elif siem_type == 'splunk':
        return SplunkConnector(siem_config)
    else:
        logger.error(f"Unknown SIEM type: {siem_type}")
        return None
