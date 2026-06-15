#!/usr/bin/env python3
"""
PatzRecon - Web Security Academy Reconnaissance Engine
Main orchestrator for modular vulnerability detection
"""

import asyncio
import logging
import yaml
import sqlite3
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup
import time
import random

@dataclass
class Finding:
    """Standardized finding structure with confidence scoring"""
    module: str
    vulnerability: str
    url: str
    method: str
    parameter: Optional[str]
    evidence: str
    confidence: str  # high, medium, low
    remediation: str
    timestamp: float = field(default_factory=time.time)
    hash_id: str = ""
    
    def __post_init__(self):
        # Create unique hash to prevent duplicates
        content = f"{self.module}:{self.url}:{self.parameter}:{self.evidence}"
        self.hash_id = hashlib.sha256(content.encode()).hexdigest()[:16]

@dataclass
class ScanTarget:
    """Represents a target with authentication context"""
    base_url: str
    lab_id: Optional[str] = None
    session_cookies: Dict = field(default_factory=dict)
    auth_headers: Dict = field(default_factory=dict)
    proxy: Optional[str] = None
    scope: List[str] = field(default_factory=list)

class PatzReconEngine:
    """
    Main reconnaissance engine with plugin orchestration
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.modules = {}
        self.cache_db = None
        self.session = None
        self.findings: List[Finding] = []
        self.rate_limiter = asyncio.Semaphore(self.config.get('max_concurrent', 10))
        
        # Confidence thresholds to eliminate false positives
        self.confidence_thresholds = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5
        }
        
    def _load_config(self, path: str) -> Dict:
        """Load configuration with defaults"""
        default_config = {
            'max_concurrent': 10,
            'timeout': 30,
            'retries': 3,
            'rate_limit_delay': (1, 3),  # min, max seconds
            'user_agent': 'PatzRecon/1.0 (Security Research)',
            'follow_redirects': True,
            'verify_ssl': False,
            'cache_enabled': True,
            'proxy': None
        }
        
        try:
            with open(path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            pass
            
        return default_config
    
    async def initialize(self):
        """Initialize async components"""
        connector = aiohttp.TCPConnector(
            limit=self.config['max_concurrent'] * 2,
            limit_per_host=5,
            ttl_dns_cache=300
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config['timeout'])
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.config['user_agent']}
        )
        
        # Initialize cache database
        if self.config['cache_enabled']:
            self.cache_db = sqlite3.connect(':memory:')
            self.cache_db.execute('''
                CREATE TABLE IF NOT EXISTS findings_cache (
                    hash_id TEXT PRIMARY KEY,
                    timestamp REAL
                )
            ''')
        
        # Load all modules dynamically
        self._load_modules()
    
    def _load_modules(self):
        """Dynamically import and register all 31 modules"""
        import importlib
        import os
        
        modules_dir = os.path.join(os.path.dirname(__file__), '..', 'modules')
        
        if not os.path.exists(modules_dir):
            logging.warning(f"Modules directory not found: {modules_dir}")
            return
            
        for module_name in os.listdir(modules_dir):
            module_path = os.path.join(modules_dir, module_name)
            if os.path.isdir(module_path) and not module_name.startswith('_'):
                try:
                    module = importlib.import_module(f'modules.{module_name}.detector')
                    self.modules[module_name] = module.Detector(self)
                    logging.info(f"Loaded module: {module_name}")
                except Exception as e:
                    logging.error(f"Failed to load module {module_name}: {e}")
    
    async def scan(self, target: ScanTarget, selected_modules: Optional[List[str]] = None):
        """
        Execute scan against target
        
        Args:
            target: ScanTarget configuration
            selected_modules: Optional list of specific modules to run
        """
        target.scope = self._determine_scope(target)
        logging.info(f"Scanning target: {target.base_url}")
        logging.info(f"Scope: {len(target.scope)} URLs")
        
        modules_to_run = selected_modules or list(self.modules.keys())
        
        # Execute modules with anti-detection delays
        tasks = []
        for module_name in modules_to_run:
            if module_name in self.modules:
                module = self.modules[module_name]
                task = self._run_module_with_jitter(module, target)
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate findings
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    if self._validate_finding(finding):
                        self._add_finding(finding)
        
        return self.findings
    
    def _determine_scope(self, target: ScanTarget) -> List[str]:
        """Crawl and determine scan scope"""
        return [target.base_url]  # Simplified - full crawler implemented separately
    
    async def _run_module_with_jitter(self, module, target: ScanTarget):
        """Execute module with random delay to avoid rate limiting"""
        delay = random.uniform(*self.config['rate_limit_delay'])
        await asyncio.sleep(delay)
        
        async with self.rate_limiter:
            try:
                return await module.scan(target)
            except Exception as e:
                logging.error(f"Module {module.__class__.__name__} failed: {e}")
                return []
    
    def _validate_finding(self, finding: Finding) -> bool:
        """Validate finding against confidence thresholds and cache"""
        # Check cache for duplicates
        if self.cache_db:
            cursor = self.cache_db.execute(
                "SELECT 1 FROM findings_cache WHERE hash_id = ?",
                (finding.hash_id,)
            )
            if cursor.fetchone():
                return False
        
        # Validate confidence score
        confidence_scores = {'high': 3, 'medium': 2, 'low': 1}
        return confidence_scores.get(finding.confidence, 0) >= \
               confidence_scores.get(self.config.get('min_confidence', 'low'), 1)
    
    def _add_finding(self, finding: Finding):
        """Add validated finding to results"""
        if self.cache_db:
            self.cache_db.execute(
                "INSERT OR IGNORE INTO findings_cache VALUES (?, ?)",
                (finding.hash_id, finding.timestamp)
            )
            self.cache_db.commit()
        
        self.findings.append(finding)
        logging.info(f"[{finding.confidence.upper()}] {finding.vulnerability} at {finding.url}")
    
    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        if self.cache_db:
            self.cache_db.close()
