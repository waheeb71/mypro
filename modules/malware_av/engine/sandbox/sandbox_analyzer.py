#!/usr/bin/env python3
"""
Enterprise NGFW - Sandbox Integration

File analysis via external sandboxes:
- VirusTotal API v3
- Cuckoo Sandbox REST API
- Custom sandbox via webhook

Features:
- Hash-first check (avoid re-submission)
- Async submission with polling
- Verdict caching (LRU)
- Configurable timeout
"""

import asyncio
import hashlib
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import OrderedDict

logger = logging.getLogger(__name__)


@dataclass
class SandboxVerdict:
    """Analysis result from sandbox"""
    file_hash: str
    malicious: bool
    score: float  # 0.0 (clean) - 1.0 (malicious)
    category: str  # clean, suspicious, malicious, unknown
    engine: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class VerdictCache:
    """LRU cache for file verdicts"""

    def __init__(self, max_size: int = 10000):
        self._cache: OrderedDict[str, SandboxVerdict] = OrderedDict()
        self._max_size = max_size

    def get(self, file_hash: str) -> Optional[SandboxVerdict]:
        if file_hash in self._cache:
            self._cache.move_to_end(file_hash)
            return self._cache[file_hash]
        return None

    def put(self, verdict: SandboxVerdict):
        if verdict.file_hash in self._cache:
            self._cache.move_to_end(verdict.file_hash)
        self._cache[verdict.file_hash] = verdict
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    @property
    def size(self) -> int:
        return len(self._cache)


class SandboxBackend(ABC):
    """Base sandbox backend"""

    @abstractmethod
    async def check_hash(self, file_hash: str) -> Optional[SandboxVerdict]:
        """Check if file hash is already known"""
        pass

    @abstractmethod
    async def submit_file(self, file_data: bytes, filename: str) -> str:
        """Submit file, return analysis ID"""
        pass

    @abstractmethod
    async def get_result(self, analysis_id: str) -> Optional[SandboxVerdict]:
        """Get analysis result"""
        pass


class VirusTotalBackend(SandboxBackend):
    """VirusTotal API v3 backend"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        logger.info("VirusTotal backend initialized")

    async def check_hash(self, file_hash: str) -> Optional[SandboxVerdict]:
        try:
            import aiohttp
            headers = {"x-apikey": self.api_key}
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers=headers
                ) as resp:
                    if resp.status == 404:
                        return None
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    stats = attrs.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values()) or 1
                    score = malicious / total

                    return SandboxVerdict(
                        file_hash=file_hash,
                        malicious=score > 0.3,
                        score=score,
                        category='malicious' if score > 0.3 else 'clean',
                        engine='virustotal',
                        details={'stats': stats}
                    )
        except ImportError:
            logger.error("aiohttp required: pip install aiohttp")
            return None
        except Exception as e:
            logger.error(f"VT hash check error: {e}")
            return None

    async def submit_file(self, file_data: bytes, filename: str) -> str:
        try:
            import aiohttp
            headers = {"x-apikey": self.api_key}
            data = aiohttp.FormData()
            data.add_field('file', file_data, filename=filename)

            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.base_url}/files",
                    headers=headers,
                    data=data
                ) as resp:
                    result = await resp.json()
                    return result.get('data', {}).get('id', '')
        except Exception as e:
            logger.error(f"VT submit error: {e}")
            return ''

    async def get_result(self, analysis_id: str) -> Optional[SandboxVerdict]:
        try:
            import aiohttp
            headers = {"x-apikey": self.api_key}
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=headers
                ) as resp:
                    data = await resp.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    if attrs.get('status') != 'completed':
                        return None
                    stats = attrs.get('stats', {})
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values()) or 1
                    score = malicious / total

                    return SandboxVerdict(
                        file_hash=analysis_id,
                        malicious=score > 0.3,
                        score=score,
                        category='malicious' if score > 0.3 else 'clean',
                        engine='virustotal',
                        details={'stats': stats}
                    )
        except Exception as e:
            logger.error(f"VT result error: {e}")
            return None


class CuckooBackend(SandboxBackend):
    """Cuckoo Sandbox REST API backend"""

    def __init__(self, base_url: str = "http://localhost:8090"):
        self.base_url = base_url
        logger.info(f"Cuckoo backend → {base_url}")

    async def check_hash(self, file_hash: str) -> Optional[SandboxVerdict]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{self.base_url}/files/view/sha256/{file_hash}"
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    return SandboxVerdict(
                        file_hash=file_hash,
                        malicious=data.get('malicious', False),
                        score=data.get('malscore', 0.0) / 10.0,
                        category=data.get('category', 'unknown'),
                        engine='cuckoo',
                        details=data
                    )
        except Exception as e:
            logger.error(f"Cuckoo hash check error: {e}")
            return None

    async def submit_file(self, file_data: bytes, filename: str) -> str:
        try:
            import aiohttp
            data = aiohttp.FormData()
            data.add_field('file', file_data, filename=filename)

            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.base_url}/tasks/create/file",
                    data=data
                ) as resp:
                    result = await resp.json()
                    return str(result.get('task_id', ''))
        except Exception as e:
            logger.error(f"Cuckoo submit error: {e}")
            return ''

    async def get_result(self, analysis_id: str) -> Optional[SandboxVerdict]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{self.base_url}/tasks/report/{analysis_id}"
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    info = data.get('info', {})
                    if info.get('status') != 'reported':
                        return None
                    score = data.get('malscore', 0.0) / 10.0
                    return SandboxVerdict(
                        file_hash=analysis_id,
                        malicious=score > 0.5,
                        score=score,
                        category='malicious' if score > 0.5 else 'clean',
                        engine='cuckoo'
                    )
        except Exception as e:
            logger.error(f"Cuckoo result error: {e}")
            return None


class SandboxAnalyzer:
    """
    File analysis orchestrator

    Workflow:
    1. Check verdict cache
    2. Check hash against sandbox (no re-upload)
    3. Submit file if unknown
    4. Poll for results
    5. Cache verdict
    """

    def __init__(self, config: dict):
        sandbox_config = config.get('integration', {}).get('sandbox', {})
        self.enabled = sandbox_config.get('enabled', False)
        self.timeout = sandbox_config.get('timeout', 300)
        self.poll_interval = sandbox_config.get('poll_interval', 10)
        self.cache = VerdictCache(
            max_size=sandbox_config.get('cache_size', 10000)
        )

        # Initialize backend
        backend_type = sandbox_config.get('type', 'virustotal')
        if backend_type == 'virustotal':
            self.backend = VirusTotalBackend(
                api_key=sandbox_config.get('api_key', '')
            )
        elif backend_type == 'cuckoo':
            self.backend = CuckooBackend(
                base_url=sandbox_config.get('url', 'http://localhost:8090')
            )
        else:
            self.backend = None
            logger.warning(f"Unknown sandbox type: {backend_type}")

        self.stats = {'submitted': 0, 'cache_hits': 0, 'verdicts': 0}

        if self.enabled:
            logger.info(f"SandboxAnalyzer initialized ({backend_type})")

    async def analyze_file(
        self,
        file_data: bytes,
        filename: str = "unknown"
    ) -> Optional[SandboxVerdict]:
        """
        Analyze a file through sandbox

        Args:
            file_data: Raw file bytes
            filename: Original filename

        Returns:
            SandboxVerdict or None
        """
        if not self.enabled or not self.backend:
            return None

        # 1. Compute hash
        file_hash = hashlib.sha256(file_data).hexdigest()

        # 2. Check cache
        cached = self.cache.get(file_hash)
        if cached:
            self.stats['cache_hits'] += 1
            logger.debug(f"Cache hit for {file_hash[:16]}...")
            return cached

        # 3. Check hash with backend
        verdict = await self.backend.check_hash(file_hash)
        if verdict:
            self.cache.put(verdict)
            self.stats['verdicts'] += 1
            return verdict

        # 4. Submit file
        analysis_id = await self.backend.submit_file(file_data, filename)
        if not analysis_id:
            return None

        self.stats['submitted'] += 1

        # 5. Poll for results
        elapsed = 0
        while elapsed < self.timeout:
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

            verdict = await self.backend.get_result(analysis_id)
            if verdict:
                verdict.file_hash = file_hash
                self.cache.put(verdict)
                self.stats['verdicts'] += 1
                return verdict

        logger.warning(f"Sandbox timeout for {filename} ({file_hash[:16]}...)")
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            **self.stats,
            'cache_size': self.cache.size,
            'enabled': self.enabled
        }
