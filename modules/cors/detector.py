#!/usr/bin/env python3
# Author : HayliPatz
"""
CORS Misconfiguration Detection Module
Identifies overly permissive CORS policies
"""

from typing import List
from core.base_module import BaseDetector, ProbeResult
from core.engine import Finding

class Detector(BaseDetector):
    """
    CORS policy analysis with reflected origin detection
    """
    
    async def scan(self, target) -> List[Finding]:
        findings = []
        
        # Test for wildcard CORS
        wildcard_test = await self._test_cors_header(
            target, 'Origin', 'https://attacker.com'
        )
        
        if wildcard_test.get('access-control-allow-origin') == '*':
            findings.append(Finding(
                module="cors",
                vulnerability="Overly Permissive CORS (Wildcard)",
                url=target.base_url,
                method="OPTIONS",
                parameter="Access-Control-Allow-Origin",
                evidence="CORS allows any origin with wildcard (*)",
                confidence="high",
                remediation="Specify explicit origins instead of wildcard"
            ))
        
        # Test for reflected origin
        reflected_test = await self._test_cors_header(
            target, 'Origin', 'https://evil.com'
        )
        
        acao = reflected_test.get('access-control-allow-origin', '')
        if acao == 'https://evil.com':
            findings.append(Finding(
                module="cors",
                vulnerability="CORS Arbitrary Origin Reflection",
                url=target.base_url,
                method="OPTIONS",
                parameter="Access-Control-Allow-Origin",
                evidence=f"Origin reflected: {acao}",
                confidence="high",
                remediation="Implement whitelist of allowed origins"
            ))
        
        # Test for null origin
        null_test = await self._test_cors_header(
            target, 'Origin', 'null'
        )
        
        if null_test.get('access-control-allow-origin') == 'null':
            findings.append(Finding(
                module="cors",
                vulnerability="CORS Null Origin Allowed",
                url=target.base_url,
                method="OPTIONS",
                parameter="Access-Control-Allow-Origin",
                evidence="Server accepts null origin (bypasses domain checks)",
                confidence="high",
                remediation="Reject null origin requests"
            ))
        
        # Check credentials header
        if wildcard_test.get('access-control-allow-credentials') == 'true':
            findings.append(Finding(
                module="cors",
                vulnerability="CORS Credentials with Wildcard",
                url=target.base_url,
                method="OPTIONS",
                parameter="Access-Control-Allow-Credentials",
                evidence="Credentials allowed with wildcard origin (browser will reject)",
                confidence="medium",
                remediation="Remove Access-Control-Allow-Credentials when using wildcard"
            ))
        
        return findings
    
    async def _test_cors_header(self, target, header_name: str, 
                                header_value: str) -> Dict:
        """Test CORS configuration with custom origin"""
        headers = {
            header_name: header_value,
            'Access-Control-Request-Method': 'GET'
        }
        
        # Send OPTIONS preflight
        try:
            async with self.session.options(
                target.base_url, 
                headers=headers
            ) as resp:
                return {
                    'access-control-allow-origin': resp.headers.get(
                        'Access-Control-Allow-Origin', ''
                    ),
                    'access-control-allow-methods': resp.headers.get(
                        'Access-Control-Allow-Methods', ''
                    ),
                    'access-control-allow-credentials': resp.headers.get(
                        'Access-Control-Allow-Credentials', ''
                    ),
                    'status': resp.status
                }
        except Exception:
            return {}
