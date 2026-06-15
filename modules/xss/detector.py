#!/usr/bin/env python3
# Author : HayliPatz
"""
Cross-Site Scripting (XSS) Detection Module
Covers: Reflected, Stored, DOM-based XSS
"""

import re
from typing import List
from core.base_module import BaseDetector, ProbeResult
from core.engine import Finding
import html

class Detector(BaseDetector):
    """
    XSS reconnaissance with context-aware payload testing
    """
    
    def __init__(self, engine):
        super().__init__(engine)
        self.reflection_patterns = [
            r'<[^>]+>',  # HTML tags
            r'["\']',    # Quote characters
            r'javascript:',  # Protocol handlers
            r'on\w+\s*=',    # Event handlers
        ]
        
    async def scan(self, target) -> List[Finding]:
        findings = []
        
        # Test for reflected XSS points
        reflection_points = await self._find_reflection_points(target)
        for point in reflection_points:
            result = await self._test_reflection_context(point)
            if result.detected:
                findings.append(self._create_finding(target, point, result, "Reflected XSS"))
        
        # Test for DOM XSS sinks
        dom_sinks = await self._identify_dom_sinks(target)
        for sink in dom_sinks:
            result = ProbeResult(
                detected=True,
                confidence="medium",
                evidence=f"DOM sink found: {sink}",
                parameter=sink
            )
            findings.append(self._create_finding(target, sink, result, "DOM XSS Potential"))
        
        return findings
    
    async def _find_reflection_points(self, target) -> List[Dict]:
        """Find points where user input reflects in response"""
        points = []
        
        # Test common reflection parameters
        test_payloads = [
            'patzrecon_test',
            '<b>test</b>',
            '"test"'
        ]
        
        common_params = ['search', 'query', 'message', 'name', 'comment', 'q', 's', 'callback']
        
        for param in common_params:
            for payload in test_payloads:
                test_url = f"{target.base_url}?{param}={payload}"
                response = await self.safe_request(test_url)
                
                if response and payload in response['text']:
                    context = self._analyze_reflection_context(response['text'], payload)
                    points.append({
                        'parameter': param,
                        'url': test_url,
                        'context': context,
                        'payload': payload
                    })
        
        return points
    
    def _analyze_reflection_context(self, html_content: str, payload: str) -> str:
        """Determine reflection context for XSS feasibility"""
        payload_escaped = re.escape(payload)
        matches = list(re.finditer(payload_escaped, html_content))
        
        for match in matches:
            pos = match.start()
            snippet = html_content[max(0, pos-50):min(len(html_content), pos+50)]
            
            if re.search(r'<[^>]*$', html_content[max(0, pos-20):pos]):
                return "html_tag"
            elif re.search(r'=[\s"\']*$', html_content[max(0, pos-20):pos]):
                return "attribute"
            elif re.search(r'<script[^>]*>.*?$', html_content[max(0, pos-50):pos], re.DOTALL):
                return "script"
            elif re.search(r'javascript:', html_content[max(0, pos-20):pos]):
                return "javascript"
        
        return "unknown"
    
    async def _test_reflection_context(self, point: Dict) -> ProbeResult:
        """Analyze if reflection point is XSS-suitable"""
        context = point['context']
        
        # Determine confidence based on context
        context_confidence = {
            'html_tag': 'high',
            'attribute': 'high',
            'script': 'high',
            'javascript': 'medium',
            'unknown': 'low'
        }
        
        if context in ['html_tag', 'attribute', 'script']:
            return ProbeResult(
                detected=True,
                confidence=context_confidence.get(context, 'low'),
                evidence=f"Input reflects in {context} context: parameter '{point['parameter']}'",
                parameter=point['parameter']
            )
        
        return ProbeResult(detected=False, confidence="low", evidence="")
    
    async def _identify_dom_sinks(self, target) -> List[str]:
        """Identify potential DOM XSS sinks in JavaScript"""
        response = await self.safe_request(target.base_url)
        sinks = []
        
        if not response:
            return sinks
        
        # DOM XSS sink patterns
        sink_patterns = [
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'insertAdjacentHTML',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.location',
            r'history\.pushState',
            r'history\.replaceState'
        ]
        
        for pattern in sink_patterns:
            if re.search(pattern, response['text'], re.IGNORECASE):
                sinks.append(pattern)
        
        return sinks
    
    def _create_finding(self, target, point, result: ProbeResult, vuln_type: str) -> Finding:
        """Create standardized finding"""
        return Finding(
            module="xss",
            vulnerability=vuln_type,
            url=target.base_url,
            method="GET",
            parameter=result.parameter,
            evidence=result.evidence,
            confidence=result.confidence,
            remediation="Implement proper output encoding based on context"
        )
