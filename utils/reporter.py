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
