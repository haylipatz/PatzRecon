#!/usr/bin/env python3
"""
CSRF Detection Module
Identifies missing tokens, weak validation, SameSite issues
"""

from typing import List
from core.base_module import BaseDetector, ProbeResult
from core.engine import Finding

class Detector(BaseDetector):
    """
    CSRF token detection and validation analysis
    """
    
    async def scan(self, target) -> List[Finding]:
        findings = []
        
        forms = await self._enumerate_forms(target)
        for form in forms:
            # Check for CSRF token presence
            token_status = self._analyze_csrf_token(form)
            
            if not token_status['present']:
                findings.append(Finding(
                    module="csrf",
                    vulnerability="Missing CSRF Token",
                    url=form['action'],
                    method=form['method'],
                    parameter=None,
                    evidence=f"Form '{form['name']}' lacks anti-CSRF token",
                    confidence="high",
                    remediation="Add CSRF tokens to all state-changing forms"
                ))
            elif token_status['weak']:
                findings.append(Finding(
                    module="csrf",
                    vulnerability="Weak CSRF Protection",
                    url=form['action'],
                    method=form['method'],
                    parameter=token_status.get('token_param'),
                    evidence=token_status['weakness_reason'],
                    confidence="medium",
                    remediation="Implement double-submit cookie pattern or Synchronizer Token"
                ))
        
        # Check SameSite cookie attribute
        samesite_issues = await self._check_samesite_cookies(target)
        findings.extend(samesite_issues)
        
        return findings
    
    async def _enumerate_forms(self, target) -> List[Dict]:
        """Extract all forms from target pages"""
        forms = []
        response = await self.safe_request(target.base_url)
        
        if not response:
            return forms
        
        soup = __import__('bs4').BeautifulSoup(response['text'], 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', target.base_url),
                'method': form.get('method', 'GET').upper(),
                'name': form.get('name', 'unnamed'),
                'inputs': [],
                'csrf_token': None
            }
            
            # Resolve relative URLs
            if form_data['action'].startswith('/'):
                parsed = __import__('urllib.parse').urlparse(target.base_url)
                form_data['action'] = f"{parsed.scheme}://{parsed.netloc}{form_data['action']}"
            
            # Check for CSRF tokens
            csrf_names = ['csrf', 'token', 'csrf_token', 'xsrf', '_token', 
                         'authenticity_token', 'anticsrf']
            
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name', '').lower()
                if any(csrf in input_name for csrf in csrf_names):
                    form_data['csrf_token'] = {
                        'name': input_tag.get('name'),
                        'value': input_tag.get('value', '')
                    }
                form_data['inputs'].append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text')
                })
            
            forms.append(form_data)
        
        return forms
    
    def _analyze_csrf_token(self, form: Dict) -> Dict:
        """Analyze CSRF token implementation"""
        result = {
            'present': False,
            'weak': False,
            'token_param': None,
            'weakness_reason': ''
        }
        
        if form.get('csrf_token'):
            result['present'] = True
            token = form['csrf_token']['value']
            result['token_param'] = form['csrf_token']['name']
            
            # Check for weak tokens
            if len(token) < 16:
                result['weak'] = True
                result['weakness_reason'] = f"Token too short ({len(token)} chars)"
            elif token.isdigit() or token.isalpha():
                result['weak'] = True
                result['weakness_reason'] = "Token lacks complexity"
        
        return result
    
    async def _check_samesite_cookies(self, target) -> List[Finding]:
        """Check for SameSite cookie misconfigurations"""
        findings = []
        response = await self.safe_request(target.base_url)
        
        if not response:
            return findings
        
        set_cookie = response['headers'].get('Set-Cookie', '')
        
        # Check for missing SameSite
        if 'samesite' not in set_cookie.lower():
            findings.append(Finding(
                module="csrf",
                vulnerability="Missing SameSite Cookie Attribute",
                url=target.base_url,
                method="GET",
                parameter="Set-Cookie",
                evidence="Cookies lack SameSite attribute (defaults to None in some browsers)",
                confidence="medium",
                remediation="Set SameSite=Strict or SameSite=Lax on session cookies"
            ))
        elif 'samesite=none' in set_cookie.lower():
            findings.append(Finding(
                module="csrf",
                vulnerability="SameSite=None (Insecure)",
                url=target.base_url,
                method="GET",
                parameter="Set-Cookie",
                evidence="SameSite=None allows cross-site cookie transmission",
                confidence="high",
                remediation="Change SameSite to Strict or Lax unless cross-site is required"
            ))
        
        return findings
