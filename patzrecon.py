#!/usr/bin/env python3
"""
PatzRecon - Web Security Academy Reconnaissance Tool
Entry point for command-line interface
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add core to path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import PatzReconEngine, ScanTarget
from utils.lab_parser import PortSwiggerLabParser
from utils.reporter import ReportGenerator

def setup_logging(verbose: bool):
    """Configure logging output"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description='PatzRecon - Advanced Web Security Reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan PortSwigger lab
  python patzrecon.py -u https://lab-id.web-security-academy.net
  
  # Scan with authentication
  python patzrecon.py -u https://target.com --cookie "session=abc123"
  
  # Specific modules only
  python patzrecon.py -u https://target.com -m sqli,xss,cors
  
  # BSCP exam mode (all modules)
  python patzrecon.py -u https://exam-id.web-security-academy.net --bscp-mode
  
  # Output to file
  python patzrecon.py -u https://target.com -o report.json --format json
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL to scan')
    parser.add_argument('-m', '--modules',
                       help='Comma-separated list of modules (default: all)',
                       default=None)
    parser.add_argument('--cookie',
                       help='Session cookie string')
    parser.add_argument('--auth-header',
                       help='Authorization header')
    parser.add_argument('--proxy',
                       help='Proxy URL (http://host:port)')
    parser.add_argument('-o', '--output',
                       help='Output file path')
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'txt'],
                       default='json', help='Report format')
    parser.add_argument('--bscp-mode', action='store_true',
                       help='Enable BSCP exam optimizations')
    parser.add_argument('--scope',
                       help='Additional scope URLs (comma-separated)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable caching')
    
    return parser

async def main():
    """Main execution flow"""
    parser = create_parser()
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    logging.info("=" * 60)
    logging.info("PatzRecon - Web Security Academy Reconnaissance")
    logging.info("=" * 60)
    
    # Parse target
    lab_parser = PortSwiggerLabParser()
    lab_info = lab_parser.parse(args.url)
    
    if lab_info:
        logging.info(f"Detected PortSwigger Lab: {lab_info.get('lab_type', 'Unknown')}")
    
    # Build scan target
    target = ScanTarget(
        base_url=args.url,
        lab_id=lab_info.get('lab_id') if lab_info else None,
        session_cookies=_parse_cookies(args.cookie),
        auth_headers={'Authorization': args.auth_header} if args.auth_header else {},
        proxy=args.proxy,
        scope=args.scope.split(',') if args.scope else []
    )
    
    # Initialize engine
    engine = PatzReconEngine()
    engine.config['max_concurrent'] = args.threads
    engine.config['timeout'] = args.timeout
    engine.config['cache_enabled'] = not args.no_cache
    
    await engine.initialize()
    
    try:
        # Determine modules to run
        selected_modules = None
        if args.modules:
            selected_modules = [m.strip() for m in args.modules.split(',')]
        
        # BSCP mode - prioritize exam-relevant modules
        if args.bscp_mode:
            logging.info("BSCP Exam Mode: Enabled")
            if not selected_modules:
                selected_modules = _get_bscp_modules()
        
        # Execute scan
        logging.info(f"Starting scan of {args.url}")
        findings = await engine.scan(target, selected_modules)
        
        # Generate report
        if findings:
            logging.info(f"\nScan complete. Found {len(findings)} potential vulnerabilities.")
            
            reporter = ReportGenerator()
            report_data = reporter.generate(findings, args.format)
            
            if args.output:
                reporter.save(report_data, args.output, args.format)
                logging.info(f"Report saved to: {args.output}")
            else:
                # Print to stdout
                print(report_data)
        else:
            logging.info("\nNo vulnerabilities detected.")
            
    finally:
        await engine.close()

def _parse_cookies(cookie_string: str) -> dict:
    """Parse cookie string into dict"""
    if not cookie_string:
        return {}
    
    cookies = {}
    for pair in cookie_string.split(';'):
        if '=' in pair:
            key, value = pair.strip().split('=', 1)
            cookies[key] = value
    return cookies

def _get_bscp_modules() -> list:
    """Return modules prioritized for BSCP exam"""
    return [
        'sqli', 'xss', 'csrf', 'cors', 'idor',
        'auth_bypass', 'access_control', 'oauth',
        'file_upload', 'lfi', 'ssrf', 'xxe',
        'jwt', 'deserialization', 'business_logic',
        'info_disclosure', 'host_header', 'clickjacking'
    ]

if __name__ == '__main__':
    asyncio.run(main())
