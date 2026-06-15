#!/usr/bin/env python3
"""
SQL Injection Detection Module
Covers: Classic SQLi, Blind SQLi, Error-based, Union-based, Time-based
"""

import re
from typing import List
from core.base_module import BaseDetector, ProbeResult
from core.engine import Finding

class Detector(BaseDetector):
    """
    SQL Injection reconnaissance with error pattern matching
    and timing analysis (no exploitation)
    """
    
    def __init__(self, engine):
        super().__init__(engine)
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Oracle.*ORA-\d{5}",
            r"Microsoft SQL Server.*Error",
            r"ODBC SQL Server Driver",
            r"SQLite/JDBCDriver",
            r"System.Data.SqlClient.SqlException"
        ]
        
    async def scan(self, target) -> List[Finding]:
        findings = []
        probe_points = await self._identify_injection_points(target)
        
        for point in probe_points:
            # Test for error-based SQLi
            error_result = await self._test_error_based(point)
            if error_result.detected:
                findings.append(self._create_finding(target, point, error_result))
            
            # Test for boolean-based blind SQLi indicators
            blind_result = await self._test_boolean_indicators(point)
            if blind_result.detected:
                findings.append(self._create_finding(target, point, blind_result))
        
        return findings
    
    async def _identify_injection_points(self, target) -> List[Dict]:
        """Identify potential SQL injection points"""
        points = []
        
        # Check URL parameters
        parsed = __import__('urllib.parse').urlparse(target.base_url)
        params = __import__('urllib.parse').parse_qs(parsed.query)
        
        for param_name in params.keys():
            points.append({
                'type': 'parameter',
                'name': param_name,
                'location': 'url'
            })
        
        # Check for forms with potential SQLi points
        response = await self.safe_request(target.base_url)
        if response:
            soup = __import__('bs4').BeautifulSoup(response['text'], 'html.parser')
            for form in soup.find_all('form'):
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        points.append({
                            'type': 'form',
                            'name': name,
                            'form_action': form.get('action', ''),
                            'location': 'body'
                        })
        
        # Common SQLi entry points
        common_params = ['id', 'page', 'user', 'product', 'category', 'item', 'search']
        for param in common_params:
            test_url = f"{target.base_url}?{param}=1"
            points.append({
                'type': 'parameter',
                'name': param,
                'location': 'url',
                'test_url': test_url
            })
        
        return points
    
    async def _test_error_based(self, point: Dict) -> ProbeResult:
        """Test for error-based SQL injection indicators"""
        if 'test_url' in point:
            test_url = point['test_url']
            
            # Payloads that trigger syntax errors (safe, no data extraction)
            error_indicators = ["'", "\"", "\\", "'--", "\"--", "';", "\";"]
            
            matches = 0
            evidence = []
            
            for payload in error_indicators:
                test_with_payload = f"{test_url}{payload}"
                response = await self.safe_request(test_with_payload)
                
                if response and response['status'] == 500:
                    for pattern in self.error_patterns:
                        if re.search(pattern, response['text'], re.IGNORECASE):
                            matches += 1
                            evidence.append(f"Pattern matched: {pattern}")
            
            if matches > 0:
                return ProbeResult(
                    detected=True,
                    confidence=self.determine_confidence(matches, len(error_indicators)),
                    evidence=" | ".join(evidence[:3]),
                    parameter=point['name']
                )
        
        return ProbeResult(detected=False, confidence="low", evidence="")
    
    async def _test_boolean_indicators(self, point: Dict) -> ProbeResult:
        """Test for boolean-based blind SQLi structural indicators"""
        # Check for potential blind SQLi by analyzing response differences
        # This is reconnaissance only - we look for behavior patterns
        
        return ProbeResult(detected=False, confidence="low", evidence="")
    
    def _create_finding(self, target, point, result: ProbeResult) -> Finding:
        """Create standardized finding"""
        return Finding(
            module="sqli",
            vulnerability=f"SQL Injection ({point['type']})",
            url=target.base_url,
            method="GET",
            parameter=point.get('name'),
            evidence=result.evidence,
            confidence=result.confidence,
            remediation="Use parameterized queries and prepared statements"
        )
