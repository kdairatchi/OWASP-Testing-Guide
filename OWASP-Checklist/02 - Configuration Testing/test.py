#!/usr/bin/env python3
"""
OWASP Automated Testing Framework
--------------------------------
A comprehensive tool for automating OWASP security testing across multiple categories.
"""

import argparse
import concurrent.futures
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("owasp_testing.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("owasp-testing")

class OWASPTestingFramework:
    """Main orchestrator for OWASP testing modules"""
    
    def __init__(self, target: str, output_dir: str, threads: int = 5, config_file: str = None):
        """
        Initialize the OWASP testing framework
        
        Args:
            target: Target URL or IP address
            output_dir: Directory to store results
            threads: Number of concurrent tests to run
            config_file: Optional configuration file path
        """
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.config = self._load_config(config_file)
        self.results = {}
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize test modules
        self.test_modules = {
            "network_infrastructure": NetworkInfrastructureTesting(self),
            "platform_configuration": PlatformConfigurationTesting(self),
            "file_extensions": FileExtensionsTesting(self),
            "backups": BackupFilesTesting(self),
            "admin_interfaces": AdminInterfacesTesting(self),
            "http_methods": HTTPMethodsTesting(self),
            "hsts": HTTPSecurityTesting(self),
            "cross_domain": CrossDomainTesting(self),
            "file_permissions": FilePermissionsTesting(self),
            "subdomain_takeover": SubdomainTakeoverTesting(self),
            "cloud_storage": CloudStorageTesting(self)
        }
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            "scan_timeout": 3600,  # 1 hour timeout for complete scan
            "tool_paths": {
                "nmap": "nmap",
                "nikto": "nikto",
                "sslyze": "sslyze",
                "testssl": "testssl.sh",
                "dirb": "dirb",
                "gobuster": "gobuster",
                "zap": "zap-cli",
                "aws": "aws",
                "azure": "az",
                "gcloud": "gcloud",
            },
            "scan_depth": "normal",  # Options: quick, normal, thorough
            "exclude_tests": []
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge user config with defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in default_config and isinstance(default_config[key], dict):
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
                logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.error(f"Error loading config file: {e}")
        
        return default_config
    
    def run_all_tests(self) -> Dict:
        """Run all enabled test modules concurrently"""
        start_time = time.time()
        logger.info(f"Starting OWASP security testing against {self.target}")
        
        # Filter out excluded tests
        active_modules = {k: v for k, v in self.test_modules.items() 
                         if k not in self.config.get("exclude_tests", [])}
        
        # Run tests concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_module = {executor.submit(module.run): name 
                               for name, module in active_modules.items()}
            
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    result = future.result()
                    self.results[module_name] = result
                    logger.info(f"Completed {module_name} testing")
                except Exception as e:
                    logger.error(f"Error in {module_name} testing: {e}")
                    self.results[module_name] = {"status": "error", "error": str(e)}
        
        # Generate final report
        self._generate_report()
        
        duration = time.time() - start_time
        logger.info(f"Completed all tests in {duration:.2f} seconds")
        
        return self.results
    
    def _generate_report(self) -> None:
        """Generate a comprehensive HTML and JSON report of all test results"""
        # Save JSON results
        json_path = os.path.join(self.output_dir, "owasp_results.json")
        with open(json_path, 'w') as f:
            json.dump({
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "results": self.results,
                "summary": self._generate_summary()
            }, f, indent=2)
        
        logger.info(f"Results saved to {json_path}")
        
        # TODO: Implement HTML report generation
    
    def _generate_summary(self) -> Dict:
        """Generate a summary of test results with risk ratings"""
        issues_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for module_name, result in self.results.items():
            if isinstance(result, dict) and "findings" in result:
                for finding in result["findings"]:
                    severity = finding.get("severity", "info").lower()
                    if severity in issues_count:
                        issues_count[severity] += 1
        
        return {
            "total_modules_run": len(self.results),
            "issues_by_severity": issues_count,
            "total_issues": sum(issues_count.values())
        }
    
    def run_command(self, command: List[str], timeout: int = None) -> Dict:
        """
        Run a shell command and return the result
        
        Args:
            command: Command as a list of arguments
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with command output
        """
        if timeout is None:
            timeout = self.config.get("scan_timeout", 3600)
            
        logger.debug(f"Running command: {' '.join(command)}")
        
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "error": f"Command timed out after {timeout} seconds"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }


class BaseTestModule:
    """Base class for all test modules"""
    
    def __init__(self, framework):
        self.framework = framework
        self.target = framework.target
        self.output_dir = framework.output_dir
        self.config = framework.config
    
    def run(self) -> Dict:
        """Run this test module - must be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_tool_path(self, tool_name: str) -> str:
        """Get the configured path for a tool"""
        return self.config.get("tool_paths", {}).get(tool_name, tool_name)


class NetworkInfrastructureTesting(BaseTestModule):
    """OTG-CONFIG-001: Test Network Infrastructure Configuration"""
    
    def run(self) -> Dict:
        results = {
            "name": "Network Infrastructure Testing",
            "findings": []
        }
        
        # Run Nmap scan
        nmap_path = self.get_tool_path("nmap")
        
        # Determine scan type based on scan depth
        scan_type = "-sV"  # Default to version detection
        if self.config.get("scan_depth") == "thorough":
            scan_type = "-sV -sC -O --script vuln"
        elif self.config.get("scan_depth") == "quick":
            scan_type = "-sS -F"
        
        nmap_output_file = os.path.join(self.output_dir, "nmap_scan.xml")
        
        command = [
            nmap_path,
            "-oX", nmap_output_file,
            scan_type,
            self.target
        ]
        command = ' '.join(command).split()  # Split the combined string to handle the scan_type options
        
        nmap_result = self.framework.run_command(command)
        
        if nmap_result["status"] == "success":
            # TODO: Parse nmap XML output and extract findings
            results["findings"].append({
                "title": "Network Service Discovery",
                "description": "Nmap scan completed successfully",
                "evidence": "See nmap_scan.xml for details",
                "severity": "info"
            })
        else:
            results["findings"].append({
                "title": "Network Scan Error",
                "description": f"Nmap scan failed: {nmap_result.get('error', 'Unknown error')}",
                "severity": "info"
            })
        
        # TODO: Add Wireshark/tcpdump capture option for more in-depth analysis
        
        return results


class PlatformConfigurationTesting(BaseTestModule):
    """OTG-CONFIG-002: Test Application Platform Configuration"""
    
    def run(self) -> Dict:
        results = {
            "name": "Platform Configuration Testing",
            "findings": []
        }
        
        # Run Nikto scan
        nikto_path = self.get_tool_path("nikto")
        nikto_output_file = os.path.join(self.output_dir, "nikto_scan.txt")
        
        command = [
            nikto_path,
            "-h", self.target,
            "-output", nikto_output_file
        ]
        
        nikto_result = self.framework.run_command(command)
        
        if nikto_result["status"] == "success":
            # Parse Nikto output for findings
            if os.path.exists(nikto_output_file):
                with open(nikto_output_file, 'r') as f:
                    nikto_content = f.read()
                    # Extract vulnerabilities (simplified parsing)
                    for line in nikto_content.splitlines():
                        if "+ " in line:  # Nikto prefixes findings with '+ '
                            results["findings"].append({
                                "title": "Platform Configuration Issue",
                                "description": line.strip(),
                                "evidence": line.strip(),
                                "severity": "medium"  # Default severity
                            })
        
        # Run SSLyze scan if target is HTTPS
        if self.target.startswith("https://"):
            sslyze_path = self.get_tool_path("sslyze")
            sslyze_output_file = os.path.join(self.output_dir, "sslyze_scan.json")
            
            command = [
                sslyze_path,
                "--json_out", sslyze_output_file,
                self.target.replace("https://", "").split("/")[0]  # Extract hostname
            ]
            
            sslyze_result = self.framework.run_command(command)
            
            if sslyze_result["status"] == "success":
                # TODO: Parse SSLyze JSON output and extract findings
                results["findings"].append({
                    "title": "SSL/TLS Configuration Check",
                    "description": "SSLyze scan completed successfully",
                    "evidence": "See sslyze_scan.json for details",
                    "severity": "info"
                })
        
        return results


class FileExtensionsTesting(BaseTestModule):
    """OTG-CONFIG-003: Test File Extensions Handling for Sensitive Information"""
    
    def run(self) -> Dict:
        results = {
            "name": "File Extensions Testing",
            "findings": []
        }
        
        # Define common sensitive file extensions
        sensitive_extensions = [
            ".bak", ".swp", ".old", ".backup", ".txt", ".db", 
            ".sql", ".config", ".conf", ".env", ".ini", ".log",
            ".xml", ".json", ".yml", ".yaml", ".properties"
        ]
        
        # Run Gobuster to scan for files with sensitive extensions
        gobuster_path = self.get_tool_path("gobuster")
        wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default wordlist
        
        for ext in sensitive_extensions:
            gobuster_output_file = os.path.join(self.output_dir, f"gobuster_ext{ext}.txt")
            
            command = [
                gobuster_path,
                "dir",
                "-u", self.target,
                "-w", wordlist,
                "-x", ext.lstrip("."),
                "-o", gobuster_output_file
            ]
            
            gobuster_result = self.framework.run_command(command, timeout=600)  # 10 minute timeout
            
            if gobuster_result["status"] == "success":
                # Parse Gobuster output for findings
                if os.path.exists(gobuster_output_file):
                    with open(gobuster_output_file, 'r') as f:
                        content = f.read()
                        # Extract found files
                        for line in content.splitlines():
                            if "Status: 200" in line:  # Found a file
                                results["findings"].append({
                                    "title": f"Sensitive File Extension ({ext})",
                                    "description": f"Found file with sensitive extension: {line}",
                                    "evidence": line,
                                    "severity": "medium"
                                })
        
        return results


class BackupFilesTesting(BaseTestModule):
    """OTG-CONFIG-004: Review Old Backup and Unreferenced Files for Sensitive Information"""
    
    def run(self) -> Dict:
        results = {
            "name": "Backup Files Testing",
            "findings": []
        }
        
        # Define common backup file patterns
        backup_patterns = [
            "*.bak", "*.backup", "*.old", "*.tmp", "*.swp", "*.save",
            "*~", "*.copy", "*.orig", "*.txt", "*.~*", "*.back",
            "*copy*", "*-backup*", "*_backup*", "*-save*", "*_save*",
            "backup*", "old*", "temp*", "temp/*", "backup/*"
        ]
        
        # Use DirBuster to find backup files
        dirb_path = self.get_tool_path("dirb")
        dirb_output_file = os.path.join(self.output_dir, "dirb_backup.txt")
        
        command = [
            dirb_path,
            self.target,
            "/usr/share/wordlists/dirb/common.txt",  # Default wordlist
            "-o", dirb_output_file,
            "-z", "10"  # Delay between requests
        ]
        
        dirb_result = self.framework.run_command(command, timeout=1800)  # 30 minute timeout
        
        if dirb_result["status"] == "success":
            # Parse dirb output for findings
            if os.path.exists(dirb_output_file):
                with open(dirb_output_file, 'r') as f:
                    content = f.read()
                    # Look for potential backup files
                    for line in content.splitlines():
                        for pattern in backup_patterns:
                            pattern_simple = pattern.replace("*", "")
                            if pattern_simple in line.lower() and "CODE:200" in line:
                                results["findings"].append({
                                    "title": "Potential Backup File",
                                    "description": f"Found potential backup file: {line}",
                                    "evidence": line,
                                    "severity": "high"
                                })
        
        return results


class AdminInterfacesTesting(BaseTestModule):
    """OTG-CONFIG-005: Enumerate Infrastructure and Application Admin Interfaces"""
    
    def run(self) -> Dict:
        results = {
            "name": "Admin Interfaces Testing",
            "findings": []
        }
        
        # Common admin interface paths
        admin_paths = [
            "admin", "administrator", "adm", "admin.php", "admin.html",
            "admin.asp", "admin.aspx", "administrador", "cp", "cpanel",
            "management", "manager", "manage", "control", "controlpanel",
            "console", "webadmin", "admin-console", "administrator-console",
            "wp-admin", "adminpanel", "user-admin", "phpmyadmin", "siteadmin",
            "admin-login", "admin_login", "login-admin", "login_admin",
            "admin-area", "backend", "dashboard"
        ]
        
        # Use Gobuster to scan for admin interfaces
        gobuster_path = self.get_tool_path("gobuster")
        wordlist_file = os.path.join(self.output_dir, "admin_wordlist.txt")
        
        # Create a temporary wordlist with admin paths
        with open(wordlist_file, 'w') as f:
            for path in admin_paths:
                f.write(path + "\n")
        
        gobuster_output_file = os.path.join(self.output_dir, "gobuster_admin.txt")
        
        command = [
            gobuster_path,
            "dir",
            "-u", self.target,
            "-w", wordlist_file,
            "-o", gobuster_output_file
        ]
        
        gobuster_result = self.framework.run_command(command, timeout=600)  # 10 minute timeout
        
        if gobuster_result["status"] == "success":
            # Parse Gobuster output for findings
            if os.path.exists(gobuster_output_file):
                with open(gobuster_output_file, 'r') as f:
                    content = f.read()
                    # Extract found admin interfaces
                    for line in content.splitlines():
                        if "Status: 200" in line or "Status: 302" in line or "Status: 301" in line:
                            results["findings"].append({
                                "title": "Admin Interface Discovered",
                                "description": f"Found potential admin interface: {line}",
                                "evidence": line,
                                "severity": "high"
                            })
        
        return results


class HTTPMethodsTesting(BaseTestModule):
    """OTG-CONFIG-006: Test HTTP Methods"""
    
    def run(self) -> Dict:
        results = {
            "name": "HTTP Methods Testing",
            "findings": []
        }
        
        # Check for allowed HTTP methods
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT", "PATCH"]
        
        for method in methods:
            # Use curl to test each method
            curl_path = "curl"
            output_file = os.path.join(self.output_dir, f"http_method_{method}.txt")
            
            command = [
                curl_path,
                "-X", method,
                "-I",  # Headers only
                "-s",  # Silent
                "-o", "/dev/null",  # Discard body
                "-w", "%{http_code}",  # Output status code
                self.target
            ]
            
            curl_result = self.framework.run_command(command)
            
            if curl_result["status"] == "success":
                status_code = curl_result["stdout"].strip()
                
                # Check for potentially dangerous methods
                if method in ["PUT", "DELETE"] and status_code not in ["405", "403", "401", "501"]:
                    results["findings"].append({
                        "title": f"Dangerous HTTP Method Allowed: {method}",
                        "description": f"The {method} method is allowed (status code: {status_code})",
                        "evidence": f"HTTP method: {method}, Status code: {status_code}",
                        "severity": "high"
                    })
                elif method == "TRACE" and status_code not in ["405", "403", "401", "501"]:
                    results["findings"].append({
                        "title": "TRACE Method Allowed",
                        "description": "The TRACE method is allowed, potentially enabling Cross-Site Tracing (XST) attacks",
                        "evidence": f"HTTP method: TRACE, Status code: {status_code}",
                        "severity": "medium"
                    })
                elif status_code not in ["405", "403", "401", "501"]:
                    results["findings"].append({
                        "title": f"HTTP Method Allowed: {method}",
                        "description": f"The {method} method is allowed (status code: {status_code})",
                        "evidence": f"HTTP method: {method}, Status code: {status_code}",
                        "severity": "info"
                    })
        
        return results


class HTTPSecurityTesting(BaseTestModule):
    """OTG-CONFIG-007: Test HTTP Strict Transport Security"""
    
    def run(self) -> Dict:
        results = {
            "name": "HTTP Security Testing",
            "findings": []
        }
        
        # Check for HSTS header
        curl_path = "curl"
        output_file = os.path.join(self.output_dir, "http_security_headers.txt")
        
        command = [
            curl_path,
            "-s",  # Silent
            "-I",  # Headers only
            self.target
        ]
        
        curl_result = self.framework.run_command(command)
        
        if curl_result["status"] == "success":
            headers = curl_result["stdout"]
            
            # Check for HSTS header
            if "strict-transport-security" not in headers.lower():
                results["findings"].append({
                    "title": "HSTS Header Missing",
                    "description": "The Strict-Transport-Security header is not set",
                    "evidence": "HTTP response headers do not include HSTS",
                    "severity": "medium"
                })
            
            # Check for other security headers
            security_headers = {
                "x-content-type-options": "X-Content-Type-Options header is missing",
                "x-frame-options": "X-Frame-Options header is missing",
                "x-xss-protection": "X-XSS-Protection header is missing",
                "content-security-policy": "Content-Security-Policy header is missing",
                "referrer-policy": "Referrer-Policy header is missing"
            }
            
            for header, message in security_headers.items():
                if header not in headers.lower():
                    results["findings"].append({
                        "title": f"{header.upper()} Header Missing",
                        "description": message,
                        "evidence": "HTTP response headers do not include this security header",
                        "severity": "low"
                    })
        
        # Use TestSSL for more comprehensive TLS/SSL testing
        if self.target.startswith("https://"):
            testssl_path = self.get_tool_path("testssl")
            testssl_output_file = os.path.join(self.output_dir, "testssl_output.html")
            
            command = [
                testssl_path,
                "--html", testssl_output_file,
                self.target
            ]
            
            testssl_result = self.framework.run_command(command, timeout=1800)  # 30 minute timeout
            
            if testssl_result["status"] == "success":
                results["findings"].append({
                    "title": "SSL/TLS Configuration Analysis",
                    "description": "TestSSL scan completed successfully",
                    "evidence": "See testssl_output.html for details",
                    "severity": "info"
                })
        
        return results


class CrossDomainTesting(BaseTestModule):
    """OTG-CONFIG-008: Test RIA Cross Domain Policy"""
    
    def run(self) -> Dict:
        results = {
            "name": "Cross Domain Policy Testing",
            "findings": []
        }
        
        # Check for crossdomain.xml and clientaccesspolicy.xml
        policy_files = [
            "crossdomain.xml",
            "clientaccesspolicy.xml"
        ]
        
        for policy_file in policy_files:
            # Construct URL
            if self.target.endswith("/"):
                url = f"{self.target}{policy_file}"
            else:
                url = f"{self.target}/{policy_file}"
            
            # Use curl to check if the file exists
            curl_path = "curl"
            output_file = os.path.join(self.output_dir, f"{policy_file}_response.xml")
            
            command = [
                curl_path,
                "-s",  # Silent
                "-o", output_file,
                "-w", "%{http_code}",  # Output status code
                url
            ]
            
            curl_result = self.framework.run_command(command)
            
            if curl_result["status"] == "success":
                status_code = curl_result["stdout"].strip()
                
                if status_code == "200":
                    # File exists, analyze its content
                    if os.path.exists(output_file):
                        with open(output_file, 'r') as f:
                            content = f.read()
                            
                            # Check for overly permissive policies
                            if policy_file == "crossdomain.xml":
                                if "<allow-access-from domain=\"*\"" in content:
                                    results["findings"].append({
                                        "title": "Overly Permissive crossdomain.xml",
                                        "description": "The crossdomain.xml file allows access from any domain",
                                        "evidence": "<allow-access-from domain=\"*\">",
                                        "severity": "high"
                                    })
                            
                            elif policy_file == "clientaccesspolicy.xml":
                                if "<domain uri=\"*\"" in content:
                                    results["findings"].append({
                                        "title": "Overly Permissive clientaccesspolicy.xml",
                                        "description": "The clientaccesspolicy.xml file allows access from any domain",
                                        "evidence": "<domain uri=\"*\">",
                                        "severity": "high"
                                    })
        
        return results


class FilePermissionsTesting(BaseTestModule):
    """OTG-CONFIG-009: Test File Permission"""
    
    def run(self) -> Dict:
        results = {
            "name": "File Permissions Testing",
            "findings": []
        }
        
        # This test primarily applies to server access, which web-based tools don't normally have
        results["findings"].append({
            "title": "File Permissions Testing",
            "description": "This test requires server access and cannot be performed remotely",
            "evidence": "N/A",
            "severity": "info"
        })
        
        # If target is a local server, we could add additional checks here
        
        return results


class SubdomainTakeoverTesting(BaseTestModule):
    """OTG-CONFIG-010: Test for Subdomain Takeover"""
    
    def run(self) -> Dict:
        results = {
            "name": "Subdomain Takeover Testing",
            "findings": []
        }
        
        # Extract domain from target
        from urllib.parse import urlparse
        parsed_url = urlparse(self.target)
        domain = parsed_url.netloc
        if not domain:
            domain = self.target
        
        # Run subdomain enumeration with amass
        amass_path = self.get_tool_path("amass")
        amass_output_file = os.path.join(self.output_dir, "amass_subdomains.txt")
        
        command = [
            amass_path,
            "enum",
            "-d", domain,
            "-o", amass_output_file
        ]
        
        amass_result = self.framework.run_command(command, timeout=3600)  # 1 hour timeout
        
        subdomains = []
        
        if amass_result["status"] == "success":
            # Read found subdomains
            if os.path.exists(amass_output_file):
                with open(amass_output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                
                results["findings"].append({
                    "title": "Subdomain Enumeration",
                    "description": f"Found {len(subdomains)} subdomains",
                    "evidence": f"See {amass_output_file} for details",
                    "severity": "info"
                })
        
        # Test each subdomain for potential takeover
        vulnerable_fingerprints = [
            "heroku app",
            "Github Pages",
            "Fastly error",
            "Shopify",
            "Amazon S3 Bucket",
            "AWS/S3",
            "The requested URL was not found on this server",
            "This domain is not configured"
        ]
        
        for subdomain in subdomains:
            # Use curl to fetch the content
            curl_path = "curl"
            output_file = os.path.join(self.output_dir, f"subdomain_{subdomain.replace('.', '_')}.txt")
            
            command = [
                curl_path,
                "-s",  # Silent
                "-o", output_file,
                "-L",  # Follow redirects
                f"http://{subdomain}"
            ]
            
            curl_result = self.framework.run_command(command)
            
            if curl_result["status"] == "success":
                # Check for takeover fingerprints
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        content = f.read()
                        
                        for fingerprint in vulnerable_fingerprints:
                            if fingerprint.lower() in content.lower():
                                results["findings"].append({
                                    "title": "Potential Subdomain Takeover",
                                    "description": f"Subdomain {subdomain} may be vulnerable to takeover",
                                    "evidence": f"Found fingerprint: {fingerprint}",
                                    "severity": "high"
                                })
        
        return results


class CloudStorageTesting(BaseTestModule):
    """OTG-CONFIG-011: Test Cloud Storage"""
    
    def run(self) -> Dict:
        results = {
            "name": "Cloud Storage Testing",
            "findings": []
        }
        
        # Extract domain from target for cloud bucket naming patterns
        from urllib.parse import urlparse
        parsed_url = urlparse(self.target)
        domain = parsed_url.netloc
        if not domain:
            domain = self.target
        
        # Remove TLD from domain
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            domain_base = domain_parts[-2]  # Example: from example.com, get "example"
        else:
            domain_base = domain
        
        # Common cloud storage naming patterns
        bucket_patterns = [
            domain_base,
            f"{domain_base}-backup",
            f"{domain_base}-dev",
            f"{domain_base}-production",
            f"{domain_base}-prod",
            f"{domain_base}-stage",
            f"{domain_base}-staging",
            f"{domain_base}-test",
            f"{domain_base}-assets",
            f"{domain_base}-media",
            f"{domain_base}-static",
            f"{domain_base}-content",
            f"{domain_base}-files",
            f"{domain_base}-data",
            f"{domain_base}.backup",
            f"{domain_base}.dev",
            f"{domain_base}.prod",
            f"{domain_base}.stage",
            f"{domain_base}.test"
        ]
        
        # Test AWS S3 buckets
        aws_cli = self.get_tool_path("aws")
        
        for bucket in bucket_patterns:
            # Check if bucket exists and is accessible
            command = [
                aws_cli,
                "s3",
                "ls",
                f"s3://{bucket}",
                "--no-sign-request"  # Try without credentials first
            ]
            
            aws_result = self.framework.run_command(command)
            
            if aws_result["status"] == "success" and "NoSuchBucket" not in aws_result["stderr"]:
                # Bucket exists and might be accessible
                results["findings"].append({
                    "title": "AWS S3 Bucket Found",
                    "description": f"S3 bucket '{bucket}' exists and may be accessible",
                    "evidence": aws_result["stdout"],
                    "severity": "high" if len(aws_result["stdout"]) > 0 else "medium"
                })
        
        # Test Azure Blob Storage
        azure_cli = self.get_tool_path("azure")
        
        for storage_name in bucket_patterns:
            # Format storage name according to Azure rules (lowercase, no dots, 3-24 chars)
            storage_name = storage_name.lower().replace('.', '')
            if len(storage_name) > 24:
                storage_name = storage_name[:24]
            elif len(storage_name) < 3:
                storage_name = storage_name + "000"
            
            # Test blob URL
            blob_url = f"https://{storage_name}.blob.core.windows.net"
            
            command = [
                "curl",
                "-s",
                "-I",
                blob_url
            ]
            
            curl_result = self.framework.run_command(command)
            
            if curl_result["status"] == "success":
                if "404" not in curl_result["stdout"] and "400" not in curl_result["stdout"]:
                    # Potential Azure storage found
                    results["findings"].append({
                        "title": "Azure Blob Storage Found",
                        "description": f"Azure Blob Storage '{storage_name}' may exist",
                        "evidence": curl_result["stdout"],
                        "severity": "medium"
                    })
        
        # Test Google Cloud Storage
        gcloud_cli = self.get_tool_path("gcloud")
        
        for bucket in bucket_patterns:
            # Check if bucket exists
            command = [
                gcloud_cli,
                "storage",
                "ls",
                f"gs://{bucket}",
                "--no-user-output-enabled"
            ]
            
            gcloud_result = self.framework.run_command(command)
            
            if gcloud_result["status"] == "success" and gcloud_result["returncode"] == 0:
                # Bucket exists
                results["findings"].append({
                    "title": "Google Cloud Storage Bucket Found",
                    "description": f"GCS bucket '{bucket}' exists",
                    "evidence": "Bucket accessible via gcloud CLI",
                    "severity": "high"
                })
        
        return results


def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(description="OWASP Automated Testing Framework")
    parser.add_argument("target", help="Target URL or IP address")
    parser.add_argument("--output-dir", "-o", default="owasp_results", help="Output directory for results")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Number of concurrent tests to run")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--module", "-m", help="Run only specified module(s), comma-separated")
    args = parser.parse_args()
    
    try:
        framework = OWASPTestingFramework(
            target=args.target,
            output_dir=args.output_dir,
            threads=args.threads,
            config_file=args.config
        )
        
        if args.module:
            # Run only specific modules
            modules = args.module.split(',')
            for module in modules:
                if module in framework.test_modules:
                    logger.info(f"Running module: {module}")
                    result = framework.test_modules[module].run()
                    framework.results[module] = result
                else:
                    logger.error(f"Unknown module: {module}")
            
            # Generate report
            framework._generate_report()
        else:
            # Run all modules
            framework.run_all_tests()
        
        logger.info(f"Testing completed. Results saved to {args.output_dir}")
        
    except Exception as e:
        logger.error(f"Error running OWASP tests: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
