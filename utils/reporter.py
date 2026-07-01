#!/usr/bin/env python3
"""
Report Generator for PatzRecon
Supports JSON, CSV, HTML, and TXT output formats
"""

import json
import csv
import html
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import base64


class ReportGenerator:
    """
    Multi-format report generator for PatzRecon findings
    """
    
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'html', 'txt']
        self.report_metadata = {
            'tool': 'PatzRecon',
            'version': '1.0.0',
            'generated_at': None
        }
    
    def generate(self, findings: List[Any], format_type: str = 'json') -> str:
        """
        Generate report in specified format
        
        Args:
            findings: List of Finding objects
            format_type: Output format (json, csv, html, txt)
        
        Returns:
            Formatted report as string
        """
        self.report_metadata['generated_at'] = datetime.now().isoformat()
        
        if format_type not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format_type}. Use: {self.supported_formats}")
        
        generators = {
            'json': self._generate_json,
            'csv': self._generate_csv,
            'html': self._generate_html,
            'txt': self._generate_txt
        }
        
        return generators[format_type](findings)
    
    def _generate_json(self, findings: List[Any]) -> str:
        """Generate JSON report"""
        report_data = {
            'metadata': self.report_metadata,
            'summary': self._generate_summary(findings),
            'findings': [self._finding_to_dict(f) for f in findings]
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_csv(self, findings: List[Any]) -> str:
        """Generate CSV report"""
        if not findings:
            return "No findings"
        
        # Get fieldnames from first finding
        sample = self._finding_to_dict(findings[0])
        fieldnames = list(sample.keys())
        
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        
        writer.writeheader()
        for finding in findings:
            writer.writerow(self._finding_to_dict(finding))
        
        return output.getvalue()
    
    def _generate_html(self, findings: List[Any]) -> str:
        """Generate HTML report with styling"""
        summary = self._generate_summary(findings)
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PatzRecon Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
        }}
        
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .summary-card h3 {{
            font-size: 0.85em;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 8px;
        }}
        
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        
        .summary-card.high {{
            border-left: 4px solid #dc3545;
        }}
        
        .summary-card.medium {{
            border-left: 4px solid #ffc107;
        }}
        
        .summary-card.low {{
            border-left: 4px solid #28a745;
        }}
        
        .findings {{
            padding: 30px;
        }}
        
        .findings h2 {{
            margin-bottom: 20px;
            color: #333;
        }}
        
        .finding {{
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }}
        
        .finding.high {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .finding.medium {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        
        .finding.low {{
            border-left-color: #28a745;
            background: #f0fff4;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .finding-title {{
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
        }}
        
        .confidence-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .confidence-badge.high {{
            background: #dc3545;
            color: white;
        }}
        
        .confidence-badge.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .confidence-badge.low {{
            background: #28a745;
            color: white;
        }}
        
        .finding-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
            font-size: 0.9em;
            color: #666;
        }}
        
        .finding-meta span {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .finding-meta strong {{
            color: #333;
            min-width: 80px;
        }}
        
        .evidence {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
        }}
        
        .remediation {{
            background: #e7f3ff;
            border-left: 3px solid #0066cc;
            padding: 12px 15px;
            margin-top: 10px;
            border-radius: 0 4px 4px 0;
        }}
        
        .remediation strong {{
            color: #0066cc;
            display: block;
            margin-bottom: 5px;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        
        .no-findings h3 {{
            font-size: 1.5em;
            margin-bottom: 10px;
            color: #28a745;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 0.85em;
            border-top: 1px solid #e0e0e0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 PatzRecon Security Report</h1>
            <div class="meta">
                Generated: {self.report_metadata['generated_at']}<br>
                Tool: {self.report_metadata['tool']} v{self.report_metadata['version']}
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card high">
                <h3>High Severity</h3>
                <div class="value">{summary['high']}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Severity</h3>
                <div class="value">{summary['medium']}</div>
            </div>
            <div class="summary-card low">
                <h3>Low Severity</h3>
                <div class="value">{summary['low']}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{summary['total']}</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>📋 Detailed Findings</h2>
            {self._generate_findings_html(findings)}
        </div>
        
        <footer>
            Report generated by PatzRecon | For authorized security testing only
        </footer>
    </div>
</body>
</html>"""
        
        return html_template
    
    def _generate_txt(self, findings: List[Any]) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 70)
        lines.append(" " * 20 + "PATZRECON SECURITY REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {self.report_metadata['generated_at']}")
        lines.append(f"Tool: {self.report_metadata['tool']} v{self.report_metadata['version']}")
        lines.append("")
        
        summary = self._generate_summary(findings)
        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"  High Severity:   {summary['high']}")
        lines.append(f"  Medium Severity: {summary['medium']}")
        lines.append(f"  Low Severity:    {summary['low']}")
        lines.append(f"  Total Findings:  {summary['total']}")
        lines.append("")
        lines.append("=" * 70)
        lines.append("FINDINGS")
        lines.append("=" * 70)
        lines.append("")
        
        if not findings:
            lines.append("No vulnerabilities detected.")
            return "\n".join(lines)
        
        for i, finding in enumerate(findings, 1):
            lines.append(f"[{i}] {finding.vulnerability}")
            lines.append("-" * 70)
            lines.append(f"  Module:      {finding.module}")
            lines.append(f"  URL:         {finding.url}")
            lines.append(f"  Method:      {finding.method}")
            lines.append(f"  Parameter:   {finding.parameter or 'N/A'}")
            lines.append(f"  Confidence:  {finding.confidence.upper()}")
            lines.append(f"  Evidence:    {finding.evidence}")
            lines.append(f"  Remediation: {finding.remediation}")
            lines.append("")
        
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _generate_findings_html(self, findings: List[Any]) -> str:
        """Generate HTML for individual findings"""
        if not findings:
            return """
            <div class="no-findings">
                <h3>✅ No Vulnerabilities Detected</h3>
                <p>The scan completed successfully with no findings.</p>
            </div>
            """
        
        html_parts = []
        for finding in findings:
            f_dict = self._finding_to_dict(finding)
            
            html_parts.append(f"""
            <div class="finding {f_dict['confidence']}">
                <div class="finding-header">
                    <div class="finding-title">{html.escape(f_dict['vulnerability'])}</div>
                    <span class="confidence-badge {f_dict['confidence']}">{f_dict['confidence'].upper()}</span>
                </div>
                
                <div class="finding-meta">
                    <span><strong>Module:</strong> {html.escape(f_dict['module'])}</span>
                    <span><strong>Method:</strong> {html.escape(f_dict['method'])}</span>
                    <span><strong>Parameter:</strong> {html.escape(f_dict['parameter'] or 'N/A')}</span>
                </div>
                
                <div class="finding-meta">
                    <span><strong>URL:</strong> {html.escape(f_dict['url'])}</span>
                </div>
                
                <div class="evidence">
                    <strong>Evidence:</strong><br>
                    {html.escape(f_dict['evidence'])}
                </div>
                
                <div class="remediation">
                    <strong>💡 Remediation</strong>
                    {html.escape(f_dict['remediation'])}
                </div>
            </div>
            """)
        
        return "\n".join(html_parts)
    
    def _generate_summary(self, findings: List[Any]) -> Dict[str, int]:
        """Generate summary statistics"""
        summary = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': len(findings)
        }
        
        for finding in findings:
            confidence = getattr(finding, 'confidence', 'low').lower()
            if confidence in summary:
                summary[confidence] += 1
        
        return summary
    
    def _finding_to_dict(self, finding: Any) -> Dict[str, Any]:
        """Convert finding object to dictionary"""
        return {
            'module': getattr(finding, 'module', 'unknown'),
            'vulnerability': getattr(finding, 'vulnerability', 'Unknown'),
            'url': getattr(finding, 'url', ''),
            'method': getattr(finding, 'method', 'GET'),
            'parameter': getattr(finding, 'parameter', None),
            'evidence': getattr(finding, 'evidence', ''),
            'confidence': getattr(finding, 'confidence', 'low'),
            'remediation': getattr(finding, 'remediation', ''),
            'timestamp': getattr(finding, 'timestamp', datetime.now().isoformat())
        }
    
    def save(self, report_data: str, filepath: str, format_type: Optional[str] = None):
        """
        Save report to file
        
        Args:
            report_data: Generated report content
            filepath: Output file path
            format_type: Optional format override (auto-detected from extension)
        """
        path = Path(filepath)
        
        # Auto-detect format from extension if not specified
        if format_type is None:
            format_type = path.suffix.lower().lstrip('.')
            if format_type not in self.supported_formats:
                format_type = 'txt'
        
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write report
        with open(path, 'w', encoding='utf-8') as f:
            f.write(report_data)
        
        return path.absolute()
    
    def save_with_timestamp(self, report_data: str, directory: str, base_name: str, 
                           format_type: str = 'json') -> Path:
        """
        Save report with timestamp in filename
        
        Args:
            report_data: Report content
            directory: Output directory
            base_name: Base filename
            format_type: File extension/format
        
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{base_name}_{timestamp}.{format_type}"
        filepath = Path(directory) / filename
        
        return self.save(report_data, str(filepath), format_type)


class ConsoleReporter:
    """
    Console/terminal output formatter with colors
    """
    
    COLORS = {
        'high': '\033[91m',      # Red
        'medium': '\033[93m',    # Yellow
        'low': '\033[92m',       # Green
        'info': '\033[94m',      # Blue
        'reset': '\033[0m',      # Reset
        'bold': '\033[1m',       # Bold
        'underline': '\033[4m'   # Underline
    }
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors
    
    def _color(self, text: str, color: str) -> str:
        """Apply color to text"""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"
    
    def print_finding(self, finding: Any, index: int = 1):
        """Print a single finding to console"""
        confidence = getattr(finding, 'confidence', 'low').lower()
        
        print(f"\n{self._color('─' * 70, 'bold')}")
        print(f"{self._color(f'[{index}]', 'bold')} {self._color(finding.vulnerability, confidence)}")
        print(f"{self._color('─' * 70, 'bold')}")
        
        print(f"  Module:      {finding.module}")
        print(f"  URL:         {finding.url}")
        print(f"  Method:      {finding.method}")
        print(f"  Parameter:   {finding.parameter or 'N/A'}")
        print(f"  Confidence:  {self._color(finding.confidence.upper(), confidence)}")
        print(f"  Evidence:    {finding.evidence[:100]}{'...' if len(finding.evidence) > 100 else ''}")
        print(f"  Remediation: {finding.remediation[:80]}{'...' if len(finding.remediation) > 80 else ''}")
    
    def print_summary(self, findings: List[Any]):
        """Print scan summary"""
        high = sum(1 for f in findings if getattr(f, 'confidence', '') == 'high')
        medium = sum(1 for f in findings if getattr(f, 'confidence', '') == 'medium')
        low = sum(1 for f in findings if getattr(f, 'confidence', '') == 'low')
        
        print(f"\n{self._color('═' * 70, 'bold')}")
        print(self._color(" " * 20 + "SCAN SUMMARY", 'bold'))
        print(f"{self._color('═' * 70, 'bold')}")
        
        print(f"  {self._color('🔴 High:', 'high')}   {high}")
        print(f"  {self._color('🟡 Medium:', 'medium')} {medium}")
        print(f"  {self._color('🟢 Low:', 'low')}    {low}")
        print(f"  {self._color('📊 Total:', 'info')}  {len(findings)}")
        print(f"{self._color('═' * 70, 'bold')}\n")
    
    def print_banner(self):
        """Print tool banner"""
        banner = """
╔═════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                     ║
║   ██████   █████  ████████ ████████ ██████   ██████   ████████  ██████  ███    ██   ║
║   ██   ██ ██   ██    ██        ███  ██   ██ ██       ██     ██ ██    ██ ████   ██   ║
║   ██████  ███████    ██       ███   ██████  █████    ██        ██    ██ ██ ██  ██   ║
║   ██      ██   ██    ██     ███     ██   ██ ██       ██     ██ ██    ██ ██  ██ ██   ║
║   ██      ██   ██    ██    ████████ ██   ██  ██████   ████████  ██████  ██   ████   ║
║                                                                                     ║
║              Web Security Academy Reconnaissance Tool                               ║
╚═════════════════════════════════════════════════════════════════════════════════════╝
        """
        print(self._color(banner, 'info'))


# Example usage
if __name__ == '__main__':
    # Test with sample data
    from dataclasses import dataclass
    
    @dataclass
    class SampleFinding:
        module: str
        vulnerability: str
        url: str
        method: str
        parameter: str
        evidence: str
        confidence: str
        remediation: str
    
    # Create sample findings
    findings = [
        SampleFinding(
            module="sqli",
            vulnerability="SQL Injection (Union-based)",
            url="https://target.com/search",
            method="GET",
            parameter="category",
            evidence="UNION SELECT NULL,NULL-- returned different response",
            confidence="high",
            remediation="Use parameterized queries"
        ),
        SampleFinding(
            module="xss",
            vulnerability="Reflected XSS",
            url="https://target.com/profile",
            method="POST",
            parameter="name",
            evidence="Payload reflected without encoding: <script>alert(1)</script>",
            confidence="medium",
            remediation="Implement output encoding"
        )
    ]
    
    # Generate reports
    reporter = ReportGenerator()
    
    print("JSON Report:")
    print(reporter.generate(findings, 'json')[:500] + "...\n")
    
    print("TXT Report:")
    print(reporter.generate(findings, 'txt'))
    
    # Save HTML report
    html_report = reporter.generate(findings, 'html')
    saved_path = reporter.save(html_report, '/tmp/patzrecon_test_report.html')
    print(f"\nHTML report saved to: {saved_path}")
