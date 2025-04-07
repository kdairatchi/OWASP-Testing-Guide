#!/usr/bin/env python3
"""
OWASP Test Results HTML Report Generator
----------------------------------------
Generates a comprehensive HTML report from OWASP test results
"""

import json
import os
from datetime import datetime
import logging

logger = logging.getLogger("owasp-testing")

class HTMLReportGenerator:
    """Generates HTML reports from OWASP test results"""
    
    def __init__(self, results_json, output_dir):
        self.results = results_json
        self.output_dir = output_dir
        
    def generate(self):
        """Generate the HTML report"""
        html_path = os.path.join(self.output_dir, "report.html")
        
        # Get basic info
        target = self.results.get("target", "Unknown")
        timestamp = self.results.get("timestamp", datetime.now().isoformat())
        results = self.results.get("results", {})
        summary = self.results.get("summary", {})
        
        # Prepare severity counts
        severity_counts = summary.get("issues_by_severity", {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        })
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OWASP Security Test Results - {target}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                }}
                header {{
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    border-radius: 5px 5px 0 0;
                }}
                .summary-box {{
                    display: flex;
                    justify-content: space-between;
                    margin: 20px 0;
                }}
                .summary-item {{
                    flex: 1;
                    padding: 15px;
                    border-radius: 5px;
                    text-align: center;
                    color: white;
                    margin: 0 5px;
                }}
                .critical {{
                    background-color: #7b0000;
                }}
                .high {{
                    background-color: #d9534f;
                }}
                .medium {{
                    background-color: #f0ad4e;
                }}
                .low {{
                    background-color: #5bc0de;
                }}
                .info {{
                    background-color: #5cb85c;
                }}
                .module-box {{
                    margin-bottom: 30px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                .module-header {{
                    padding: 10px 15px;
                    background-color: #f5f5f5;
                    border-bottom: 1px solid #ddd;
                    font-weight: bold;
                }}
                .finding {{
                    padding: 15px;
                    border-bottom: 1px solid #eee;
                }}
                .finding:last-child {{
                    border-bottom: none;
                }}
                .finding-title {{
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                .finding-severity {{
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 3px;
                    color: white;
                    font-size: 0.8em;
                    margin-left: 10px;
                }}
                .finding-description {{
                    margin-bottom: 10px;
                }}
                .finding-evidence {{
                    background-color: #f9f9f9;
                    padding: 10px;
                    border-radius: 3px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    overflow-x: auto;
                }}
                .no-findings {{
                    padding: 15px;
                    font-style: italic;
                    color: #777;
                }}
                footer {{
                    margin-top: 30px;
                    text-align: center;
                    color: #777;
                    font-size: 0.9em;
                }}
                .tabs {{
                    display: flex;
                    border-bottom: 1px solid #ddd;
                }}
                .tab {{
                    padding: 10px 15px;
                    cursor: pointer;
                }}
                .tab.active {{
                    border-bottom: 2px solid #2c3e50;
                    font-weight: bold;
                }}
                .tab-content {{
                    display: none;
                }}
                .tab-content.active {{
                    display: block;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>OWASP Security Test Results</h1>
                    <p>Target: {target}</p>
                    <p>Scan Date: {timestamp}</p>
                </header>
                
                <div class="summary-box">
                    <div class="summary-item critical">
                        <h3>Critical</h3>
                        <h2>{severity_counts.get("critical", 0)}</h2>
                    </div>
                    <div class="summary-item high">
                        <h3>High</h3>
                        <h2>{severity_counts.get("high", 0)}</h2>
                    </div>
                    <div class="summary-item medium">
                        <h3>Medium</h3>
                        <h2>{severity_counts.get("medium", 0)}</h2>
                    </div>
                    <div class="summary-item low">
                        <h3>Low</h3>
                        <h2>{severity_counts.get("low", 0)}</h2>
                    </div>
                    <div class="summary-item info">
                        <h3>Info</h3>
                        <h2>{severity_counts.get("info", 0)}</h2>
                    </div>
                </div>
                
                <div class="tabs">
                    <div class="tab active" onclick="changeTab('findings')">Findings</div>
                    <div class="tab" onclick="changeTab('modules')">Modules</div>
                </div>
                
                <div id="findings-tab" class="tab-content active">
                    <h2>Findings by Severity</h2>
                    
                    <!-- Critical Findings -->
                    <h3>Critical Findings</h3>
                    {self._generate_severity_findings("critical", results)}
                    
                    <!-- High Findings -->
                    <h3>High Findings</h3>
                    {self._generate_severity_findings("high", results)}
                    
                    <!-- Medium Findings -->
                    <h3>Medium Findings</h3>
                    {self._generate_severity_findings("medium", results)}
                    
                    <!-- Low Findings -->
                    <h3>Low Findings</h3>
                    {self._generate_severity_findings("low", results)}
                    
                    <!-- Info Findings -->
                    <h3>Info Findings</h3>
                    {self._generate_severity_findings("info", results)}
                </div>
                
                <div id="modules-tab" class="tab-content">
                    <h2>Results by Module</h2>
                    
                    {self._generate_module_results(results)}
                </div>
                
                <footer>
                    <p>Generated by OWASP Automated Testing Framework on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </footer>
            </div>
            
            <script>
                function changeTab(tabName) {
                    // Hide all tabs
                    document.querySelectorAll('.tab-content').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    
                    // Remove active class from all tab buttons
                    document.querySelectorAll('.tab').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    
                    // Show selected tab
                    document.getElementById(tabName + '-tab').classList.add('active');
                    
                    // Highlight selected tab button
                    document.querySelector('.tab[onclick="changeTab(\\''+tabName+'\\')"]').classList.add('active');
                }
            </script>
        </body>
        </html>
        """
        
        # Write HTML file
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {html_path}")
        return html_path
    
    def _generate_severity_findings(self, severity, results):
        """Generate HTML for findings of a specific severity"""
        findings_html = ""
        found = False
        
        for module_name, result in results.items():
            if isinstance(result, dict) and "findings" in result:
                for finding in result["findings"]:
                    if finding.get("severity", "").lower() == severity.lower():
                        found = True
                        findings_html += f"""
                        <div class="finding">
                            <div class="finding-title">
                                {finding.get("title", "Untitled Finding")}
                                <span class="finding-severity {severity.lower()}">{severity.upper()}</span>
                            </div>
                            <div class="finding-description">
                                {finding.get("description", "")}
                            </div>
                            <div class="finding-evidence">
                                {finding.get("evidence", "No evidence provided")}
                            </div>
                            <div>
                                <small>Module: {result.get("name", module_name)}</small>
                            </div>
                        </div>
                        """
        
        if not found:
            findings_html = f"""
            <div class="no-findings">
                No {severity} findings detected.
            </div>
            """
        
        return findings_html
    
    def _generate_module_results(self, results):
        """Generate HTML for module results"""
        modules_html = ""
        
        for module_name, result in results.items():
            if isinstance(result, dict):
                module_html = f"""
                <div class="module-box">
                    <div class="module-header">
                        {result.get("name", module_name)}
                    </div>
                """
                
                findings = result.get("findings", [])
                if findings:
                    for finding in findings:
                        severity = finding.get("severity", "info").lower()
                        module_html += f"""
                        <div class="finding">
                            <div class="finding-title">
                                {finding.get("title", "Untitled Finding")}
                                <span class="finding-severity {severity}">{severity.upper()}</span>
                            </div>
                            <div class="finding-description">
                                {finding.get("description", "")}
                            </div>
                            <div class="finding-evidence">
                                {finding.get("evidence", "No evidence provided")}
                            </div>
                        </div>
                        """
                else:
                    module_html += """
                    <div class="no-findings">
                        No findings for this module.
                    </div>
                    """
                
                module_html += "</div>"
                modules_html += module_html
        
        return modules_html


# Integration with main framework
def generate_html_report(results_json_path, output_dir):
    """Generate HTML report from JSON results"""
    try:
        with open(results_json_path, 'r') as f:
            results = json.load(f)
        
        generator = HTMLReportGenerator(results, output_dir)
        html_path = generator.generate()
        
        return html_path
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return None


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="OWASP HTML Report Generator")
    parser.add_argument("results_json", help="Path to OWASP test results JSON file")
    parser.add_argument("--output-dir", "-o", default=".", help="Output directory for HTML report")
    args = parser.parse_args()
    
    html_path = generate_html_report(args.results_json, args.output_dir)
    if html_path:
        print(f"HTML report generated: {html_path}")
