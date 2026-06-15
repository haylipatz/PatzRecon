#!/usr/bin/env python3
"""
Base module class for all vulnerability detectors
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass
import yaml
import os

@dataclass
class ProbeResult:
    """Result from individual probe"""
    detected: bool
    confidence: str
    evidence: str
    parameter: str = ""
    method: str = "GET"
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class BaseDetector(ABC):
    """Abstract base class for all 31 vulnerability modules"""
    
    def __init__(self, engine):
        self.engine = engine
        self.session = engine.session
        self.config = self._load_payloads()
        self.name = self.__class__.__module__.split('.')[-1]
        
    def _load_payloads(self) -> Dict:
        """Load YAML payload database for this module"""
        payload_path = os.path.join(
            os.path.dirname(__file__), '..', 'payloads',
            f"{self.name}.yaml"
        )
        
        if os.path.exists(payload_path):
            with open(payload_path, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    @abstractmethod
    async def scan(self, target) -> List:
        """Main scan method - must be implemented by each module"""
        pass
    
    async def safe_request(self, url: str, method: str = "GET", 
                        data: Dict = None, headers: Dict = None) -> Any:
        """Safe HTTP request with error handling"""
        try:
            if method == "GET":
                async with self.session.get(url, headers=headers) as resp:
                    return await self._process_response(resp)
            else:
                async with self.session.post(url, data=data, headers=headers) as resp:
                    return await self._process_response(resp)
        except Exception as e:
            return None
    
    async def _process_response(self, response):
        """Process HTTP response"""
        return {
            'status': response.status,
            'headers': dict(response.headers),
            'text': await response.text(),
            'url': str(response.url)
        }
    
    def determine_confidence(self, matches: int, total: int) -> str:
        """Calculate confidence score based on match ratio"""
        ratio = matches / total if total > 0 else 0
        
        if ratio >= 0.9 and matches >= 2:
            return "high"
        elif ratio >= 0.7:
            return "medium"
        return "low"
