"""
Enterprise NGFW v2.0 - HTTP Inspector Plugin

Deep inspection of HTTP/HTTPS traffic.

Features:
- HTTP method validation
- Header analysis
- URL inspection
- Body content scanning
- File upload detection
- Suspicious pattern detection

import re
import logging
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs
from sqlalchemy.orm import Session
from system.database.database import get_db, SessionLocal

from system.inspection_core.framework import (
    InspectorPlugin,
    PluginPriority,
    InspectionContext,
    InspectionResult,
    InspectionAction,
    InspectionFinding
)
from modules.http_inspection.models import HTTPSuspiciousPattern, HTTPInspectionConfig

class HTTPInspector(InspectorPlugin):
    """
    HTTP/HTTPS traffic inspector.
    
    Performs deep inspection of HTTP traffic including:
    - Method validation
    - Header analysis
    - URL inspection
    - Content scanning
    """
    
    # Dangerous HTTP methods
    DANGEROUS_METHODS = {'TRACE', 'TRACK', 'DEBUG', 'CONNECT'}
    
    def __init__(
        self,
        priority: PluginPriority = PluginPriority.HIGH,
        logger: Optional[logging.Logger] = None
    ):
        super().__init__(
            name="HTTP Inspector",
            priority=priority,
            logger=logger
        )
        
    def can_inspect(self, context: InspectionContext) -> bool:
        """Check if this is HTTP traffic"""
        http_ports = {80, 8080, 8000, 8888, 3000, 5000}
        
        return (
            context.protocol == 'TCP' and
            (context.dst_port in http_ports or context.src_port in http_ports)
        )
        
    def get_db_session(self) -> Session:
        return SessionLocal()
        
    def inspect(
        self,
        context: InspectionContext,
        data: bytes
    ) -> InspectionResult:
        """Inspect HTTP traffic"""
        result = InspectionResult(action=InspectionAction.ALLOW)
        
        try:
            # Parse HTTP request/response
            http_data = self._parse_http(data)
            
            if not http_data:
                return result
                
            # Store in metadata
            result.metadata['http'] = http_data
            
            db = self.get_db_session()
            try:
                config = db.query(HTTPInspectionConfig).first()
                if not config or not config.is_active:
                    return result
                    
                # Fetch patterns
                active_patterns = db.query(HTTPSuspiciousPattern).filter(HTTPSuspiciousPattern.enabled == True).all()
                url_patterns = [p for p in active_patterns if p.target == 'url']
                header_patterns = [p for p in active_patterns if p.target == 'header']
                body_patterns = [p for p in active_patterns if p.target == 'body']
                
                # Inspect request method
                if 'method' in http_data:
                    self._inspect_method(http_data, result, config.block_dangerous_methods)
                    
                # Inspect URL
                if 'url' in http_data:
                    self._inspect_url(http_data, result, url_patterns)
                    
                # Inspect headers
                if 'headers' in http_data and config.scan_headers:
                    self._inspect_headers(http_data, result, header_patterns)
                    
                # Inspect body
                if 'body' in http_data and config.scan_body:
                    self._inspect_body(http_data, result, body_patterns)
                    
                # Check for file uploads
                if 'content_type' in http_data:
                    self._inspect_uploads(http_data, result, config.max_upload_size_mb)
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"HTTP inspection failed: {e}")
            
        return result
        
    def _parse_http(self, data: bytes) -> Optional[Dict]:
        """Parse HTTP request/response"""
        try:
            # Decode data
            text = data.decode('utf-8', errors='ignore')
            
            lines = text.split('\r\n')
            if not lines:
                return None
                
            # Parse first line (request line or status line)
            first_line = lines[0]
            http_data = {}
            
            # Check if request or response
            if first_line.startswith('HTTP/'):
                # Response
                parts = first_line.split(' ', 2)
                http_data['type'] = 'response'
                http_data['version'] = parts[0] if len(parts) > 0 else ''
                http_data['status_code'] = parts[1] if len(parts) > 1 else ''
                http_data['status_text'] = parts[2] if len(parts) > 2 else ''
            else:
                # Request
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    http_data['type'] = 'request'
                    http_data['method'] = parts[0]
                    http_data['url'] = parts[1]
                    http_data['version'] = parts[2]
                    
            # Parse headers
            headers = {}
            body_start = 0
            
            for i, line in enumerate(lines[1:], 1):
                if not line:
                    body_start = i + 1
                    break
                    
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                    
            http_data['headers'] = headers
            
            # Get body
            if body_start < len(lines):
                http_data['body'] = '\r\n'.join(lines[body_start:])
                
            # Extract content type
            if 'Content-Type' in headers:
                http_data['content_type'] = headers['Content-Type']
                
            # Extract content length
            if 'Content-Length' in headers:
                try:
                    http_data['content_length'] = int(headers['Content-Length'])
                except:
                    pass
                    
            return http_data
            
        except Exception as e:
            self.logger.debug(f"HTTP parsing failed: {e}")
            return None
            
    def _inspect_method(self, http_data: Dict, result: InspectionResult, block_dangerous: bool) -> None:
        """Inspect HTTP method"""
        method = http_data.get('method', '').upper()
        
        if method in self.DANGEROUS_METHODS and block_dangerous:
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                severity='HIGH',
                category='http_method',
                description=f"Dangerous HTTP method: {method}",
                plugin_name=self.name,
                confidence=1.0,
                evidence={'method': method}
            ))
            
    def _inspect_url(self, http_data: Dict, result: InspectionResult, patterns: List[HTTPSuspiciousPattern]) -> None:
        """Inspect URL for suspicious patterns"""
        url = http_data.get('url', '')
        
        # Check against DB patterns
        for p in patterns:
            try:
                regex = re.compile(p.pattern, re.IGNORECASE)
                if regex.search(url):
                    result.action = InspectionAction.BLOCK
                    result.findings.append(InspectionFinding(
                        severity=p.severity,
                        category='http_url',
                        description=p.description or "Suspicious URL pattern detected",
                        plugin_name=self.name,
                        confidence=0.95,
                        evidence={
                            'url': url[:500],
                            'pattern_id': p.id
                        }
                    ))
                    break
            except Exception as e:
                self.logger.error(f"Failed to compile URL pattern ID {p.id}: {e}")
                
        if len(url) > 2048:
            result.findings.append(InspectionFinding(
                severity='MEDIUM',
                category='http_url',
                description=f"Abnormally long URL: {len(url)} bytes",
                plugin_name=self.name,
                confidence=0.8,
                evidence={'url_length': len(url)}
            ))
            
    def _inspect_headers(self, http_data: Dict, result: InspectionResult, patterns: List[HTTPSuspiciousPattern]) -> None:
        """Inspect HTTP headers"""
        headers = http_data.get('headers', {})
        
        for p in patterns:
            target_key = p.target_key
            if not target_key: continue
            
            # Case insensitive header lookup
            target_key_lower = target_key.lower()
            matching_key = next((k for k in headers.keys() if k.lower() == target_key_lower), None)
            
            if matching_key:
                val = headers[matching_key]
                try:
                    regex = re.compile(p.pattern, re.IGNORECASE)
                    if regex.search(val):
                        result.findings.append(InspectionFinding(
                            severity=p.severity,
                            category='http_header',
                            description=p.description or f"Suspicious {matching_key} header",
                            plugin_name=self.name,
                            confidence=0.8,
                            evidence={
                                'header': matching_key,
                                'value': val[:200],
                                'pattern_id': p.id
                            }
                        ))
                except Exception as e:
                    self.logger.error(f"Failed to compile Header pattern ID {p.id}: {e}")
                    
    def _inspect_body(self, http_data: Dict, result: InspectionResult, patterns: List[HTTPSuspiciousPattern]) -> None:
        """Inspect HTTP body"""
        body = http_data.get('body', '')
        
        if not body:
            return
            
        for p in patterns:
            try:
                regex = re.compile(p.pattern, re.IGNORECASE | re.DOTALL)
                if regex.search(body):
                    result.action = InspectionAction.BLOCK
                    result.findings.append(InspectionFinding(
                        severity=p.severity,
                        category='http_body',
                        description=p.description or "Suspicious body content",
                        plugin_name=self.name,
                        confidence=0.9,
                        evidence={'body_sample': body[:500], 'pattern_id': p.id}
                    ))
                    break
            except Exception as e:
                self.logger.error(f"Failed to compile Body pattern ID {p.id}: {e}")
                
    def _inspect_uploads(self, http_data: Dict, result: InspectionResult, max_upload_size_mb: int) -> None:
        """Inspect file uploads"""
        content_type = http_data.get('content_type', '')
        content_length = http_data.get('content_length', 0)
        
        if 'multipart/form-data' in content_type:
            size_mb = content_length / (1024 * 1024)
            
            result.findings.append(InspectionFinding(
                severity='INFO',
                category='http_upload',
                description=f"File upload detected ({size_mb:.2f} MB)",
                plugin_name=self.name,
                confidence=1.0,
                evidence={
                    'size_mb': size_mb,
                    'content_type': content_type
                }
            ))
            
            if size_mb > max_upload_size_mb:
                result.findings.append(InspectionFinding(
                    severity='MEDIUM',
                    category='http_upload',
                    description=f"Upload exceeds size limit",
                    plugin_name=self.name,
                    confidence=1.0,
                    evidence={
                        'size_mb': size_mb,
                        'limit_mb': max_upload_size_mb
                    }
                ))
