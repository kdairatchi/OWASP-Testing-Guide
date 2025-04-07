#!/usr/bin/env python3
"""
OWASP Business Logic Testing Tool

A comprehensive automated testing tool for identifying business logic vulnerabilities
in web applications based on OWASP Testing Guide v4.2 guidelines.
"""

import argparse
import json
import os
import sys
import time
import logging
import requests
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import re
import random
import csv
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("buslogic_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("OWASP-BusLogic")

class OWASPBusinessLogicTester:
    """Main testing framework class for OWASP Business Logic Testing"""
    
    def __init__(self, target_url, config_file=None, auth=None, session=None):
        """Initialize the testing framework"""
        self.target_url = target_url
        self.config = self._load_config(config_file)
        self.auth = auth  # Dictionary with auth details if provided
        self.session = session if session else requests.Session()
        self.test_results = {}
        self.discovered_endpoints = set()
        self.discovered_params = {}
        self.discovered_workflows = []
        self.critical_paths = []
        
        # Setup session with authentication if provided
        if self.auth:
            self._setup_authentication()
    
    def _load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            "scan_depth": 3,
            "concurrent_requests": 10,
            "request_delay": 0.1,
            "timeout": 30,
            "user_agent": "OWASP-BusLogicTester/1.0",
            "follow_redirects": True,
            "test_modules": {
                "OTG-BUSLOGIC-001": True,
                "OTG-BUSLOGIC-002": True,
                "OTG-BUSLOGIC-003": True,
                "OTG-BUSLOGIC-004": True,
                "OTG-BUSLOGIC-005": True,
                "OTG-BUSLOGIC-006": True,
                "OTG-BUSLOGIC-007": True,
                "OTG-BUSLOGIC-008": True,
                "OTG-BUSLOGIC-009": True
            },
            "exclude_paths": [],
            "custom_headers": {},
            "file_upload_tests": {
                "test_files_dir": "./test_files",
                "extensions": [".pdf", ".doc", ".jpg", ".zip", ".csv", ".svg", ".html", ".js", ".php"]
            },
            "workflow_definitions": []
        }
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge user config with defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in default_config and isinstance(default_config[key], dict):
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
            except Exception as e:
                logger.error(f"Error loading config file: {e}")
                logger.info("Using default configuration")
        
        return default_config
    
    def _setup_authentication(self):
        """Setup session authentication based on provided auth details"""
        if not self.auth:
            return
            
        auth_type = self.auth.get("type", "").lower()
        
        if auth_type == "basic":
            self.session.auth = (self.auth.get("username"), self.auth.get("password"))
        
        elif auth_type == "form":
            login_url = self.auth.get("login_url")
            username_field = self.auth.get("username_field")
            password_field = self.auth.get("password_field")
            username = self.auth.get("username")
            password = self.auth.get("password")
            
            if all([login_url, username_field, password_field, username, password]):
                data = {
                    username_field: username,
                    password_field: password
                }
                
                # Add any additional form fields
                for key, value in self.auth.get("additional_fields", {}).items():
                    data[key] = value
                    
                # Perform login
                try:
                    response = self.session.post(login_url, data=data, allow_redirects=True)
                    if response.status_code == 200:
                        logger.info("Form authentication successful")
                    else:
                        logger.error(f"Form authentication failed with status code: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error during form authentication: {e}")
        
        elif auth_type == "token":
            # Set Authorization header with token
            token = self.auth.get("token")
            token_type = self.auth.get("token_type", "Bearer")
            
            if token:
                self.session.headers.update({
                    "Authorization": f"{token_type} {token}"
                })
                logger.info("Token authentication set up")
        
        # Set default headers
        self.session.headers.update({
            "User-Agent": self.config["user_agent"]
        })
        
        # Add custom headers if provided
        if self.config.get("custom_headers"):
            self.session.headers.update(self.config["custom_headers"])
    
    def run_discovery(self):
        """Discover application endpoints, parameters, and workflows"""
        logger.info(f"Starting discovery phase for {self.target_url}")
        
        # Initial crawl to discover endpoints
        self._crawl_site(self.target_url, self.config["scan_depth"])
        
        # Discover parameters for each endpoint
        self._discover_parameters()
        
        # Identify workflows and critical paths
        self._identify_workflows()
        
        logger.info(f"Discovery phase completed. Found {len(self.discovered_endpoints)} endpoints.")
        return {
            "endpoints": list(self.discovered_endpoints),
            "parameters": self.discovered_params,
            "workflows": self.discovered_workflows
        }
    
    def _crawl_site(self, url, depth, visited=None):
        """Crawl the site to discover endpoints"""
        if visited is None:
            visited = set()
            
        if depth <= 0 or url in visited:
            return
            
        visited.add(url)
        self.discovered_endpoints.add(url)
        
        try:
            response = self.session.get(url, timeout=self.config["timeout"])
            if response.status_code != 200:
                return
                
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links
            links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                # Convert relative URLs to absolute
                absolute_url = urljoin(url, href)
                
                # Only follow links to the same domain
                if urlparse(absolute_url).netloc == urlparse(self.target_url).netloc:
                    # Skip excluded paths
                    if not any(excluded in absolute_url for excluded in self.config["exclude_paths"]):
                        links.append(absolute_url)
            
            # Extract form actions
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    absolute_action = urljoin(url, action)
                    if urlparse(absolute_action).netloc == urlparse(self.target_url).netloc:
                        links.append(absolute_action)
                        
                        # Also record form fields for parameter discovery
                        form_data = {
                            "url": absolute_action,
                            "method": form.get('method', 'get').lower(),
                            "fields": []
                        }
                        
                        for input_field in form.find_all(['input', 'select', 'textarea']):
                            field_name = input_field.get('name')
                            if field_name:
                                field_type = input_field.get('type', 'text')
                                form_data["fields"].append({
                                    "name": field_name,
                                    "type": field_type
                                })
                        
                        # Store form data for later use
                        if absolute_action not in self.discovered_params:
                            self.discovered_params[absolute_action] = []
                        self.discovered_params[absolute_action].append(form_data)
            
            # Recursively crawl discovered links
            with ThreadPoolExecutor(max_workers=self.config["concurrent_requests"]) as executor:
                futures = [executor.submit(self._crawl_site, link, depth - 1, visited) for link in links]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error during crawling: {e}")
                    
                    # Add a small delay between requests
                    time.sleep(self.config["request_delay"])
                    
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
    
    def _discover_parameters(self):
        """Discover parameters for each endpoint"""
        logger.info("Starting parameter discovery")
        
        for endpoint in self.discovered_endpoints:
            # Skip if we already have form data for this endpoint
            if endpoint in self.discovered_params:
                continue
                
            # Check URL for query parameters
            parsed_url = urlparse(endpoint)
            query_params = parse_qs(parsed_url.query)
            
            if query_params:
                param_data = {
                    "url": endpoint,
                    "method": "get",
                    "params": [{"name": k, "values": v} for k, v in query_params.items()]
                }
                
                if endpoint not in self.discovered_params:
                    self.discovered_params[endpoint] = []
                self.discovered_params[endpoint].append(param_data)
                
            # Try sending sample requests to identify additional parameters
            self._probe_endpoint_parameters(endpoint)
    
    def _probe_endpoint_parameters(self, endpoint):
        """Probe an endpoint to discover additional parameters"""
        # Skip URLs with query parameters already
        if "?" in endpoint:
            return
            
        # Common parameter names to test
        common_params = [
            "id", "user_id", "page", "limit", "sort", "order", "filter", 
            "search", "query", "start", "end", "date", "type", "category",
            "status", "action", "mode", "format", "view", "lang"
        ]
        
        # Test with GET requests
        for param in common_params:
            test_url = f"{endpoint}?{param}=1"
            try:
                response = self.session.get(test_url, timeout=self.config["timeout"])
                
                # If response differs significantly from the base endpoint,
                # it might indicate the parameter is valid
                if self._is_response_different(endpoint, test_url):
                    if endpoint not in self.discovered_params:
                        self.discovered_params[endpoint] = []
                    
                    # Check if we already have this parameter
                    param_exists = False
                    for entry in self.discovered_params[endpoint]:
                        if entry.get("method") == "get" and any(p.get("name") == param for p in entry.get("params", [])):
                            param_exists = True
                            break
                    
                    if not param_exists:
                        self.discovered_params[endpoint].append({
                            "url": endpoint,
                            "method": "get",
                            "params": [{"name": param, "values": ["1"]}]
                        })
                
                time.sleep(self.config["request_delay"])
            except Exception as e:
                logger.debug(f"Error testing parameter {param} on {endpoint}: {e}")
    
    def _is_response_different(self, url1, url2):
        """Compare responses from two URLs to determine if they're significantly different"""
        try:
            resp1 = self.session.get(url1, timeout=self.config["timeout"])
            resp2 = self.session.get(url2, timeout=self.config["timeout"])
            
            # Compare status codes
            if resp1.status_code != resp2.status_code:
                return True
                
            # Compare content length (if significantly different)
            len1 = len(resp1.content)
            len2 = len(resp2.content)
            if abs(len1 - len2) / max(len1, len2) > 0.1:  # 10% difference
                return True
                
            # Compare key elements in HTML
            soup1 = BeautifulSoup(resp1.text, 'html.parser')
            soup2 = BeautifulSoup(resp2.text, 'html.parser')
            
            # Compare titles
            title1 = soup1.title.string if soup1.title else ""
            title2 = soup2.title.string if soup2.title else ""
            if title1 != title2:
                return True
                
            # Compare number of forms
            if len(soup1.find_all('form')) != len(soup2.find_all('form')):
                return True
                
            # Compare number of tables
            if len(soup1.find_all('table')) != len(soup2.find_all('table')):
                return True
                
            return False
        except Exception as e:
            logger.debug(f"Error comparing responses: {e}")
            return False
    
    def _identify_workflows(self):
        """Identify potential workflows in the application"""
        logger.info("Identifying application workflows")
        
        # Check if workflows are defined in config
        if self.config.get("workflow_definitions"):
            self.discovered_workflows = self.config["workflow_definitions"]
            logger.info(f"Loaded {len(self.discovered_workflows)} workflows from configuration")
            return
            
        # Attempt to automatically identify workflows
        # This is a simplified approach - in real applications, you'd need more sophisticated methods
        
        # Look for common workflow patterns in URLs
        common_workflows = {
            "user_registration": ["register", "signup", "create_account", "join"],
            "login_flow": ["login", "signin", "auth", "authenticate"],
            "checkout_process": ["cart", "checkout", "payment", "order", "purchase"],
            "product_management": ["product", "add_product", "edit_product", "delete_product"],
            "user_management": ["user", "profile", "settings", "account"],
            "content_creation": ["create", "new", "add", "post", "upload"]
        }
        
        # Group endpoints by potential workflows
        workflow_groups = {}
        
        for endpoint in self.discovered_endpoints:
            path = urlparse(endpoint).path.lower()
            
            for workflow_name, keywords in common_workflows.items():
                if any(keyword in path for keyword in keywords):
                    if workflow_name not in workflow_groups:
                        workflow_groups[workflow_name] = []
                    workflow_groups[workflow_name].append(endpoint)
        
        # Create workflow objects
        for workflow_name, endpoints in workflow_groups.items():
            if len(endpoints) >= 2:  # Only consider workflows with at least 2 steps
                # Try to order endpoints logically
                ordered_endpoints = self._order_workflow_endpoints(workflow_name, endpoints)
                
                workflow = {
                    "name": workflow_name,
                    "steps": [{"url": url, "method": "GET"} for url in ordered_endpoints],
                    "critical": workflow_name in ["checkout_process", "user_registration", "login_flow"]
                }
                
                self.discovered_workflows.append(workflow)
                
                # Mark critical workflows for special testing
                if workflow["critical"]:
                    self.critical_paths.append(workflow_name)
        
        logger.info(f"Identified {len(self.discovered_workflows)} potential workflows")
    
    def _order_workflow_endpoints(self, workflow_name, endpoints):
        """Attempt to order workflow endpoints in a logical sequence"""
        # This is a simplified approach based on common patterns
        
        # Keywords that might indicate ordering
        order_indicators = {
            "user_registration": ["register", "confirm", "verify", "complete"],
            "login_flow": ["login", "verify", "2fa", "security"],
            "checkout_process": ["cart", "checkout", "address", "shipping", "payment", "confirm", "complete"],
            "product_management": ["list", "view", "add", "edit", "delete"],
            "user_management": ["view", "edit", "password", "delete"],
            "content_creation": ["new", "create", "preview", "publish"]
        }
        
        # Default indicators if workflow not specifically defined
        default_indicators = ["list", "view", "new", "create", "edit", "update", "delete", "confirm", "complete"]
        
        indicators = order_indicators.get(workflow_name, default_indicators)
        
        # Score each endpoint based on indicators
        scored_endpoints = []
        for endpoint in endpoints:
            path = urlparse(endpoint).path.lower()
            
            # Start with a default score
            score = 0
            
            # Increase score based on position of indicators in the list 
            # (earlier indicators get lower scores)
            for i, indicator in enumerate(indicators):
                if indicator in path:
                    score += i
                    break
            
            scored_endpoints.append((score, endpoint))
        
        # Sort by score and return just the endpoints
        return [endpoint for _, endpoint in sorted(scored_endpoints)]
    
    def run_all_tests(self):
        """Run all selected test modules"""
        logger.info("Starting business logic testing")
        
        # First run discovery if not already done
        if not self.discovered_endpoints:
            self.run_discovery()
        
        # Initialize results
        self.test_results = {
            "summary": {
                "target": self.target_url,
                "start_time": datetime.now().isoformat(),
                "modules_run": [],
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "vulnerabilities": []
        }
        
        # Run enabled test modules
        test_modules = {
            "OTG-BUSLOGIC-001": self.test_data_validation,
            "OTG-BUSLOGIC-002": self.test_request_forgery,
            "OTG-BUSLOGIC-003": self.test_integrity_checks,
            "OTG-BUSLOGIC-004": self.test_process_timing,
            "OTG-BUSLOGIC-005": self.test_function_limits,
            "OTG-BUSLOGIC-006": self.test_workflow_circumvention,
            "OTG-BUSLOGIC-007": self.test_application_misuse,
            "OTG-BUSLOGIC-008": self.test_unexpected_file_types,
            "OTG-BUSLOGIC-009": self.test_malicious_file_upload
        }
        
        for module_id, test_function in test_modules.items():
            if self.config["test_modules"].get(module_id, True):
                logger.info(f"Running test module: {module_id}")
                try:
                    vulns = test_function()
                    if vulns:
                        self.test_results["vulnerabilities"].extend(vulns)
                        self.test_results["summary"]["modules_run"].append(module_id)
                        
                        # Update vulnerability counts
                        for vuln in vulns:
                            self.test_results["summary"]["total_vulnerabilities"] += 1
                            severity = vuln.get("severity", "info").lower()
                            self.test_results["summary"][severity] = self.test_results["summary"].get(severity, 0) + 1
                            
                except Exception as e:
                    logger.error(f"Error running test module {module_id}: {e}")
        
        # Complete summary
        self.test_results["summary"]["end_time"] = datetime.now().isoformat()
        
        return self.test_results
    
    def test_data_validation(self):
        """OTG-BUSLOGIC-001: Test Business Logic Data Validation"""
        logger.info("Running Business Logic Data Validation tests")
        vulnerabilities = []
        
        # Test each endpoint with parameters
        for endpoint, param_data_list in self.discovered_params.items():
            for param_data in param_data_list:
                method = param_data.get("method", "get").lower()
                
                # Test fields in forms
                if method == "post" and "fields" in param_data:
                    for field in param_data["fields"]:
                        field_name = field.get("name")
                        field_type = field.get("type", "text")
                        
                        # Skip submit buttons, hidden fields, etc.
                        if field_type in ["submit", "button", "hidden", "image"]:
                            continue
                            
                        # Test for boundary conditions
                        test_values = self._generate_test_values(field_type)
                        
                        for test_value in test_values:
                            # Prepare test data
                            test_data = {}
                            for f in param_data["fields"]:
                                # Fill in other fields with valid data
                                if f["name"] != field_name:
                                    test_data[f["name"]] = self._generate_valid_value(f["type"])
                            
                            # Add our test value
                            test_data[field_name] = test_value
                            
                            # Send the request
                            try:
                                response = self.session.post(
                                    endpoint, 
                                    data=test_data,
                                    allow_redirects=self.config["follow_redirects"],
                                    timeout=self.config["timeout"]
                                )
                                
                                # Check for unexpected success
                                if response.status_code == 200 and self._is_success_response(response):
                                    vulnerabilities.append({
                                        "id": f"BL-001-{len(vulnerabilities)+1}",
                                        "test_id": "OTG-BUSLOGIC-001",
                                        "name": "Business Logic Data Validation Vulnerability",
                                        "description": f"The application accepted an invalid value '{test_value}' for field '{field_name}' of type '{field_type}'",
                                        "severity": "high",
                                        "endpoint": endpoint,
                                        "method": method.upper(),
                                        "param": field_name,
                                        "value": test_value,
                                        "evidence": f"Sent invalid data but received status code {response.status_code}",
                                        "mitigation": "Implement proper data validation for business logic fields"
                                    })
                                
                                time.sleep(self.config["request_delay"])
                            except Exception as e:
                                logger.debug(f"Error testing field {field_name} on {endpoint}: {e}")
                
                # Test GET parameters
                elif method == "get" and "params" in param_data:
                    for param_info in param_data["params"]:
                        param_name = param_info.get("name")
                        
                        # Test for boundary conditions
                        test_values = self._generate_test_values("text")  # Assume text type for GET params
                        
                        for test_value in test_values:
                            # Prepare test URL
                            test_url = f"{endpoint}?{param_name}={test_value}"
                            
                            # Send the request
                            try:
                                response = self.session.get(
                                    test_url,
                                    allow_redirects=self.config["follow_redirects"],
                                    timeout=self.config["timeout"]
                                )
                                
                                # Check for unexpected success with invalid data
                                if response.status_code == 200 and self._is_success_response(response):
                                    vulnerabilities.append({
                                        "id": f"BL-001-{len(vulnerabilities)+1}",
                                        "test_id": "OTG-BUSLOGIC-001",
                                        "name": "Business Logic Data Validation Vulnerability",
                                        "description": f"The application accepted an invalid value '{test_value}' for parameter '{param_name}'",
                                        "severity": "high",
                                        "endpoint": endpoint,
                                        "method": "GET",
                                        "param": param_name,
                                        "value": test_value,
                                        "evidence": f"Sent invalid data but received status code {response.status_code}",
                                        "mitigation": "Implement proper data validation for business logic parameters"
                                    })
                                
                                time.sleep(self.config["request_delay"])
                            except Exception as e:
                                logger.debug(f"Error testing parameter {param_name} on {endpoint}: {e}")
        
        logger.info(f"Completed Business Logic Data Validation tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def _generate_test_values(self, field_type):
        """Generate test values for different field types"""
        # Common test values for all types
        common_tests = [
            "",  # Empty string
            "null",  # String "null"
            "undefined",  # String "undefined"
            "<script>alert(1)</script>",  # Simple XSS
            "' OR '1'='1",  # SQL injection
            "../../etc/passwd",  # Path traversal
            "999999999999999999999999999999",  # Very large number
            "-1",  # Negative number
            "0"    # Zero
        ]
        
        # Type-specific test values
        type_specific = {
            "text": [
                "a" * 1000,  # Very long string
                "特殊字符",   # Unicode characters
                "\u0000"     # Null byte
            ],
            "number": [
                "1e100",     # Scientific notation
                "0.1234567890123456789", # Long decimal
                "12345.67.89"  # Invalid number format
            ],
            "email": [
                "not@an@email.com",  # Invalid email format
                "email@localhost",   # Missing TLD
                "@domain.com",       # Missing username
                "a" * 100 + "@example.com" # Very long email
            ],
            "date": [
                "2099-99-99",  # Invalid date
                "1969-01-01",  # Very old date
                "2100-01-01"   # Future date
            ],
            "password": [
                "password",   # Common password
                "123456",     # Simple numeric password
                " "           # Space character
            ],
            "checkbox": [
                "on",
                "true",
                "1",
                "yes"
            ],
            "select": [
                "invalidoption",  # Option that doesn't exist
                "' OR 1=1 --"     # SQL injection in dropdown
            ]
        }
        
        # Combine common tests with type-specific tests
        if field_type.lower() in type_specific:
            return common_tests + type_specific[field_type.lower()]
        else:
            return common_tests
    
    def _generate_valid_value(self, field_type):
        """Generate a valid value for a given field type"""
        field_type = field_type.lower()
        
        if field_type == "text":
            return "test_value"
        elif field_type == "number":
            return "42"
        elif field_type == "email":
            return "test@example.com"
        elif field_type == "date":
            return "2023-01-01"
        elif field_type == "password":
            return "Password123!"
        elif field_type == "checkbox":
            return "on"
        elif field_type == "select":
            return "option1"  # Default option
        else:
            return "test_value"
    
    def _is_success_response(self, response):
        """Check if the response indicates a successful operation"""
        # This is a simple implementation - real-world scenarios need more sophisticated checks
        
        # Check for success indicators in the response body
        success_indicators = [
            "success", "successful", "succeeded", "completed", "saved", "updated", "created",
            "thank you", "confirmed", "processed", "submitted"
        ]
        
        response_text = response.text.lower()
        if any(indicator in response_text for indicator in success_indicators):
            return True
            
        # Check for error indicators
        error_indicators = [
            "error", "invalid", "failed", "failure", "warning", "exception", "denied",
            "incorrect", "rejected", "wrong", "not allowed", "forbidden"
        ]
        
        if any(indicator in response_text for indicator in error_indicators):
            return False
            
        # If no clear indicators, assume success for 200 status code
        return True
    
    def test_request_forgery(self):
        """OTG-BUSLOGIC-002: Test Ability to Forge Requests"""
        logger.info("Running Request Forgery tests")
        vulnerabilities = []
        
        # Focus on important endpoints that might handle sensitive operations
        sensitive_operations = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in [
                "admin", "profile", "account", "user", "edit", "update", "delete", 
                "transfer", "payment", "checkout", "purchase", "order", "change", "password"
            ])
        ]
        
        # Test cross-site request forgery (CSRF) vulnerabilities
        for endpoint in sensitive_operations:
            # Skip endpoints that explicitly use GET (should be safe for viewing)
            if any(data.get("method", "").lower() == "get" for data in self.discovered_params.get(endpoint, [])):
                continue
                
            # Check if a CSRF token is present in forms that submit to this endpoint
            has_csrf_protection = False
            
            # Look for forms that submit to this endpoint
            for url, param_data_list in self.discovered_params.items():
                for param_data in param_data_list:
                    if param_data.get("method", "").lower() == "post" and endpoint in param_data.get("url", ""):
                        # Check for CSRF tokens in form fields
                        for field in param_data.get("fields", []):
                            field_name = field.get("name", "").lower()
                            if any(token_name in field_name for token_name in [
                                "csrf", "token", "nonce", "_token", "security"
                            ]):
                                has_csrf_protection = True
                                break
                                
                        if has_csrf_protection:
                    break
            
            # If no CSRF protection detected, create a vulnerability
            if not has_csrf_protection:
                vulnerabilities.append({
                    "id": f"BL-002-{len(vulnerabilities)+1}",
                    "test_id": "OTG-BUSLOGIC-002",
                    "name": "Cross-Site Request Forgery (CSRF) Vulnerability",
                    "description": f"No CSRF protection detected for sensitive endpoint {endpoint}",
                    "severity": "high",
                    "endpoint": endpoint,
                    "method": "POST",
                    "evidence": "No CSRF token found in form fields",
                    "mitigation": "Implement CSRF tokens for all sensitive operations"
                })
        
        # Test for HTTP parameter pollution
        for endpoint, param_data_list in self.discovered_params.items():
            for param_data in param_data_list:
                method = param_data.get("method", "").lower()
                
                # Test on parameters
                params_to_test = []
                if method == "get" and "params" in param_data:
                    params_to_test = [p.get("name") for p in param_data.get("params", [])]
                elif method == "post" and "fields" in param_data:
                    params_to_test = [f.get("name") for f in param_data.get("fields", [])]
                
                for param_name in params_to_test:
                    # Skip CSRF tokens
                    if any(token_name in param_name.lower() for token_name in ["csrf", "token", "nonce"]):
                        continue
                        
                    # Try parameter pollution
                    if method == "get":
                        test_url = f"{endpoint}?{param_name}=valid&{param_name}=invalid"
                        try:
                            response = self.session.get(
                                test_url,
                                allow_redirects=self.config["follow_redirects"],
                                timeout=self.config["timeout"]
                            )
                            
                            # If successful, might indicate parameter pollution vulnerability
                            if response.status_code == 200 and self._is_success_response(response):
                                vulnerabilities.append({
                                    "id": f"BL-002-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-002",
                                    "name": "HTTP Parameter Pollution Vulnerability",
                                    "description": f"The application accepted duplicate parameters for '{param_name}'",
                                    "severity": "medium",
                                    "endpoint": endpoint,
                                    "method": "GET",
                                    "param": param_name,
                                    "evidence": f"Duplicate parameters accepted: {test_url}",
                                    "mitigation": "Implement proper validation of duplicate parameters"
                                })
                            
                            time.sleep(self.config["request_delay"])
                        except Exception as e:
                            logger.debug(f"Error testing parameter pollution on {endpoint}: {e}")
                    elif method == "post":
                        # Create form data with duplicate parameters
                        test_data = {}
                        for field in param_data.get("fields", []):
                            field_name = field.get("name")
                            if field_name != param_name:
                                test_data[field_name] = self._generate_valid_value(field.get("type", "text"))
                        
                        # Add duplicate parameters
                        test_data[param_name] = "valid"
                        test_data[f"{param_name}_duplicate"] = "invalid"
                        
                        try:
                            response = self.session.post(
                                endpoint,
                                data=test_data,
                                allow_redirects=self.config["follow_redirects"],
                                timeout=self.config["timeout"]
                            )
                            
                            if response.status_code == 200 and self._is_success_response(response):
                                vulnerabilities.append({
                                    "id": f"BL-002-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-002",
                                    "name": "HTTP Parameter Pollution Vulnerability",
                                    "description": f"The application may be vulnerable to parameter pollution for '{param_name}'",
                                    "severity": "medium",
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "param": param_name,
                                    "evidence": f"Request with manipulated parameters was accepted",
                                    "mitigation": "Implement proper validation of request parameters"
                                })
                            
                            time.sleep(self.config["request_delay"])
                        except Exception as e:
                            logger.debug(f"Error testing parameter pollution on {endpoint}: {e}")
        
        logger.info(f"Completed Request Forgery tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_integrity_checks(self):
        """OTG-BUSLOGIC-003: Test Integrity Checks"""
        logger.info("Running Integrity Checks tests")
        vulnerabilities = []
        
        # Focus on endpoints that involve data modification
        modification_endpoints = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in [
                "edit", "update", "modify", "change", "save", "add",
                "create", "delete", "remove", "upload", "submit"
            ])
        ]
        
        # Test for integrity issues in data manipulation
        for endpoint in modification_endpoints:
            # Look for forms or params associated with this endpoint
            param_data_list = self.discovered_params.get(endpoint, [])
            
            for param_data in param_data_list:
                method = param_data.get("method", "").lower()
                
                # Only focus on POST methods for data modification
                if method != "post":
                    continue
                    
                fields = param_data.get("fields", [])
                
                # Look for numerical or price fields to test for integrity issues
                for field in fields:
                    field_name = field.get("name", "")
                    field_type = field.get("type", "").lower()
                    
                    # Skip non-relevant fields
                    if field_type not in ["number", "text"] or not any(kw in field_name.lower() for kw in [
                        "price", "cost", "amount", "quantity", "total", "sum", "count", "id", "num"
                    ]):
                        continue
                    
                    # Test for tampering with numerical values
                    test_cases = [
                        {"value": "-1", "name": "Negative Value", "description": "Accepted negative value where positive is expected"},
                        {"value": "0", "name": "Zero Value", "description": "Accepted zero value where positive is expected"},
                        {"value": "0.01", "name": "Minimal Value", "description": "Accepted minimal value where significant value is expected"},
                        {"value": "999999", "name": "Excessive Value", "description": "Accepted excessive value without validation"}
                    ]
                    
                    for test_case in test_cases:
                        # Prepare test data
                        test_data = {}
                        for f in fields:
                            f_name = f.get("name")
                            if f_name != field_name:
                                test_data[f_name] = self._generate_valid_value(f.get("type", "text"))
                        
                        # Add our test value
                        test_data[field_name] = test_case["value"]
                        
                        try:
                            response = self.session.post(
                                endpoint,
                                data=test_data,
                                allow_redirects=self.config["follow_redirects"],
                                timeout=self.config["timeout"]
                            )
                            
                            # Check if test passed (vulnerability found)
                            if response.status_code == 200 and self._is_success_response(response):
                                vulnerabilities.append({
                                    "id": f"BL-003-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-003",
                                    "name": f"Integrity Check Bypass - {test_case['name']}",
                                    "description": f"{test_case['description']} for field '{field_name}'",
                                    "severity": "critical" if "price" in field_name.lower() else "high",
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "param": field_name,
                                    "value": test_case["value"],
                                    "evidence": f"Request with manipulated value was accepted",
                                    "mitigation": "Implement proper integrity checks for business-critical values"
                                })
                            
                            time.sleep(self.config["request_delay"])
                        except Exception as e:
                            logger.debug(f"Error testing integrity on {endpoint}: {e}")
        
        # Test for hash/checksum manipulation if any are found
        for endpoint, param_data_list in self.discovered_params.items():
            for param_data in param_data_list:
                fields = param_data.get("fields", [])
                
                # Look for checksum or hash fields
                hash_fields = [f.get("name") for f in fields if any(kw in f.get("name", "").lower() for kw in [
                    "hash", "checksum", "digest", "signature", "md5", "sha", "crc"
                ])]
                
                if hash_fields:
                    vulnerabilities.append({
                        "id": f"BL-003-{len(vulnerabilities)+1}",
                        "test_id": "OTG-BUSLOGIC-003",
                        "name": "Potential Hash/Checksum Manipulation",
                        "description": f"The application uses hash/checksum fields that might be vulnerable to manipulation: {', '.join(hash_fields)}",
                        "severity": "medium",
                        "endpoint": endpoint,
                        "method": param_data.get("method", "GET"),
                        "evidence": f"Found hash/checksum fields: {', '.join(hash_fields)}",
                        "mitigation": "Ensure server-side validation of hash/checksum values"
                    })
        
        logger.info(f"Completed Integrity Checks tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_process_timing(self):
        """OTG-BUSLOGIC-004: Test for Process Timing"""
        logger.info("Running Process Timing tests")
        vulnerabilities = []
        
        # Focus on critical workflows
        for workflow in self.discovered_workflows:
            workflow_name = workflow.get("name", "")
            steps = workflow.get("steps", [])
            
            # Only test workflows with multiple steps
            if len(steps) < 2:
                continue
                
            logger.info(f"Testing process timing for workflow: {workflow_name}")
            
            # Test skipping intermediate steps
            if len(steps) > 2:
                first_step = steps[0]
                last_step = steps[-1]
                
                # First establish a baseline session by visiting the first step
                try:
                    first_response = self.session.request(
                        first_step.get("method", "GET"),
                        first_step.get("url"),
                        timeout=self.config["timeout"]
                    )
                    
                    # Then try to directly access the last step
                    last_response = self.session.request(
                        last_step.get("method", "GET"),
                        last_step.get("url"),
                        timeout=self.config["timeout"]
                    )
                    
                    # Check if we could skip steps
                    if last_response.status_code == 200 and self._is_success_response(last_response):
                        vulnerabilities.append({
                            "id": f"BL-004-{len(vulnerabilities)+1}",
                            "test_id": "OTG-BUSLOGIC-004",
                            "name": "Process Step Skipping Vulnerability",
                            "description": f"It's possible to skip intermediate steps in the '{workflow_name}' workflow",
                            "severity": "high",
                            "workflow": workflow_name,
                            "start_step": first_step.get("url"),
                            "end_step": last_step.get("url"),
                            "evidence": f"Able to access final step without completing intermediate steps",
                            "mitigation": "Implement proper workflow state verification at each step"
                        })
                except Exception as e:
                    logger.debug(f"Error testing step skipping in {workflow_name}: {e}")
            
            # Test for race conditions in sequential operations
            if len(steps) >= 2:
                for i in range(len(steps) - 1):
                    current_step = steps[i]
                    next_step = steps[i + 1]
                    
                    # Try to execute both steps simultaneously
                    try:
                        with ThreadPoolExecutor(max_workers=2) as executor:
                            future1 = executor.submit(
                                self.session.request,
                                current_step.get("method", "GET"),
                                current_step.get("url"),
                                timeout=self.config["timeout"]
                            )
                            future2 = executor.submit(
                                self.session.request,
                                next_step.get("method", "GET"),
                                next_step.get("url"),
                                timeout=self.config["timeout"]
                            )
                            
                            response1 = future1.result()
                            response2 = future2.result()
                            
                            # If both succeed, might indicate a race condition
                            if (response1.status_code == 200 and response2.status_code == 200 and
                                self._is_success_response(response1) and self._is_success_response(response2)):
                                
                                vulnerabilities.append({
                                    "id": f"BL-004-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-004",
                                    "name": "Potential Race Condition",
                                    "description": f"Potential race condition detected in '{workflow_name}' workflow between steps {i+1} and {i+2}",
                                    "severity": "medium",
                                    "workflow": workflow_name,
                                    "step1": current_step.get("url"),
                                    "step2": next_step.get("url"),
                                    "evidence": "Both steps executed simultaneously were successful",
                                    "mitigation": "Implement proper transaction handling and state management"
                                })
                    except Exception as e:
                        logger.debug(f"Error testing race conditions in {workflow_name}: {e}")
        
        logger.info(f"Completed Process Timing tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_function_limits(self):
        """OTG-BUSLOGIC-005: Test Number of Times a Function Can Be Used Limits"""
        logger.info("Running Function Usage Limits tests")
        vulnerabilities = []
        
        # Focus on important functions that might have limits
        limited_functions = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in [
                "login", "register", "signup", "verify", "submit", "apply", "pay", "checkout",
                "purchase", "order", "download", "upload", "request", "reset", "recover"
            ])
        ]
        
        # Test rate limiting by sending multiple requests in quick succession
        for endpoint in limited_functions:
            num_requests = 10  # Number of requests to test
            
            logger.info(f"Testing function limits for: {endpoint}")
            
            # Create a list to track responses
            responses = []
            
            # Send multiple requests rapidly
            try:
                for i in range(num_requests):
                    response = self.session.get(
                        endpoint,
                        allow_redirects=self.config["follow_redirects"],
                        timeout=self.config["timeout"]
                    )
                    responses.append(response)
                    
                    # Minimal delay between requests
                    time.sleep(0.1)
                
                # Analyze responses
                success_count = sum(1 for r in responses if r.status_code == 200)
                
                # If all requests succeeded without rate limiting
                if success_count == num_requests:
                    vulnerabilities.append({
                        "id": f"BL-005-{len(vulnerabilities)+1}",
                        "test_id": "OTG-BUSLOGIC-005",
                        "name": "Missing Rate Limiting",
                        "description": f"The endpoint {endpoint} does not implement rate limiting",
                        "severity": "medium",
                        "endpoint": endpoint,
                        "method": "GET",
                        "evidence": f"Successfully sent {num_requests} requests without being rate-limited",
                        "mitigation": "Implement rate limiting for sensitive functions"
                    })
            except Exception as e:
                logger.debug(f"Error testing rate limiting on {endpoint}: {e}")
        
        # Test for circumventing account lockout (if login functionality identified)
        login_endpoints = [ep for ep in self.discovered_endpoints if any(kw in ep.lower() for kw in ["login", "signin", "authenticate"])]
        
        for login_endpoint in login_endpoints:
            # Find login form data
            login_params = []
            for param_data in self.discovered_params.get(login_endpoint, []):
                if param_data.get("method", "").lower() == "post":
                    login_params.append(param_data)
            
            if not login_params:
                continue
                
            # Test for account lockout after multiple failed attempts
            try:
                username_field = password_field = None
                
                # Find username and password fields
                for param_data in login_params:
                    for field in param_data.get("fields", []):
                        field_name = field.get("name", "").lower()
                        field_type = field.get("type", "").lower()
                        
                        if field_type == "text" or "user" in field_name or "email" in field_name:
                            username_field = field.get("name")
                        
                        if field_type == "password" or "pass" in field_name:
                            password_field = field.get("name")
                
                if not username_field or not password_field:
                    continue
                    
                # Send multiple failed login attempts
                num_attempts = 10
                test_username = "test_user_" + str(random.randint(1000, 9999))
                
                for i in range(num_attempts):
                    login_data = {
                        username_field: test_username,
                        password_field: f"wrong_password_{i}"
                    }
                    
                    response = self.session.post(
                        login_endpoint,
                        data=login_data,
                        allow_redirects=self.config["follow_redirects"],
                        timeout=self.config["timeout"]
                    )
                    
                    # If we get locked out, stop testing
                    if "locked" in response.text.lower() or "too many attempts" in response.text.lower():
                        break
                    
                    time.sleep(self.config["request_delay"])
                
                # If we didn't get locked out after multiple attempts
                if i == num_attempts - 1:
                    vulnerabilities.append({
                        "id": f"BL-005-{len(vulnerabilities)+1}",
                        "test_id": "OTG-BUSLOGIC-005",
                        "name": "Missing Account Lockout",
                        "description": f"The login function does not implement account lockout after multiple failed attempts",
                        "severity": "high",
                        "endpoint": login_endpoint,
                        "method": "POST",
                        "evidence": f"Successfully sent {num_attempts} failed login attempts without lockout",
                        "mitigation": "Implement account lockout after a reasonable number of failed login attempts"
                    })
            except Exception as e:
                logger.debug(f"Error testing account lockout on {login_endpoint}: {e}")
        
        logger.info(f"Completed Function Usage Limits tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_workflow_circumvention(self):
        """OTG-BUSLOGIC-006: Testing for the Circumvention of Work Flows"""
        logger.info("Running Workflow Circumvention tests")
        vulnerabilities = []
        
        # Test each workflow for circumvention possibilities
        for workflow in self.discovered_workflows:
            workflow_name = workflow.get("name", "")
            steps = workflow.get("steps", [])
            
            # Only test workflows with multiple steps
            if len(steps) < 2:
                continue
                
            logger.info(f"Testing workflow circumvention for: {workflow_name}")
            
            # Test direct access to later steps without completing earlier ones
            for i in range(1, len(steps)):
                current_step = steps[i]
                
                # Try to directly access this step without going through previous steps
                try:
                    # Create a fresh session to avoid state from previous requests
                    test_session = requests.Session()
                    test_session.headers.update(self.session.headers)
                    
                    response = test_session.request(
                        current_step.get("method", "GET"),
                        current_step.get("url"),
                        allow_redirects=self.config["follow_redirects"],
                        timeout=self.config["timeout"]
                    )
                    
                    # Check if we were able to access the step
                    if response.status_code == 200 and self._is_success_response(response):
                        vulnerabilities.append({
                            "id": f"BL-006-{len(vulnerabilities)+1}",
                            "test_id": "OTG-BUSLOGIC-006",
                            "name": "Workflow Circumvention Vulnerability",
                            "description": f"Step {i+1} in the '{workflow_name}' workflow can be accessed directly without completing previous steps",
                            "severity": "high",
                            "workflow": workflow_name,
                            "step": current_step.get("url"),
                            "evidence": f"Able to access step {i+1} with a fresh session",
                            "mitigation": "Implement proper workflow state verification at each step"
                        })
                except Exception as e:
                    logger.debug(f"Error testing direct access to step {i+1} in {workflow_name}: {e}")
            
            # Test skipping steps in sequential workflows
            if len(steps) >= 3:
                try:
                    # Create a fresh session
                    test_session = requests.Session()
                    test_session.headers.update(self.session.headers)
                    
                    # Access the first step
                    first_step = steps[0]
                    first_response = test_session.request(
                        first_step.get("method", "GET"),
                        first_step.get("url"),
                        allow_redirects=self.config["follow_redirects"],
                        timeout=self.config["timeout"]
                    )
                    
                    # Then try to access the third step directly
                    third_step = steps[2]
                    third_response = test_session.request(
                        third_step.get("method", "GET"),
                        third_step.get("url"),
                        allow_redirects=self.config["follow_redirects"],
                        timeout=self.config["timeout"]
                    )
                    
                    # Check if we could skip the second step
                    if third_response.status_code == 200 and self._is_success_response(third_response):
                        vulnerabilities.append({
                            "id": f"BL-006-{len(vulnerabilities)+1}",
                            "test_id": "OTG-BUSLOGIC-006",
                            "name": "Step Skipping Vulnerability",
                            "description": f"It's possible to skip step 2 in the '{workflow_name}' workflow",
                            "severity": "high",
                            "workflow": workflow_name,
                            "step_skipped": steps[1].get("url"),
                            "evidence": "Able to access step 3 after only completing step 1",
                            "mitigation": "Enforce the correct sequence of workflow steps"
                        })
                except Exception as e:
                    logger.debug(f"Error testing step skipping in {workflow_name}: {e}")
            
            # Test for forced browsing between workflows
            if self.discovered_workflows and len(self.discovered_workflows) > 1:
                for other_workflow in self.discovered_workflows:
                    # Skip comparing to the same workflow
                    if other_workflow.get("name") == workflow_name:
                        continue
                        
                    other_steps = other_workflow.get("steps", [])
                    
                    if not other_steps:
                        continue
                        
                    # Try to switch between workflows
                    try:
                        # Create a fresh session
                        test_session = requests.Session()
                        test_session.headers.update(self.session.headers)
                        
                        # Start the first workflow
                        first_step = steps[0]
                        first_response = test_session.request(
                            first_step.get("method", "GET"),
                            first_step.get("url"),
                            allow_redirects=self.config["follow_redirects"],
                            timeout=self.config["timeout"]
                        )
                        
                        # Then try to access the other workflow's last step
                        other_last_step = other_steps[-1]
                        other_response = test_session.request(
                            other_last_step.get("method", "GET"),
                            other_last_step.get("url"),
                            allow_redirects=self.config["follow_redirects"],
                            timeout=self.config["timeout"]
                        )
                        
                        # Check if we could jump between workflows
                        if other_response.status_code == 200 and self._is_success_response(other_response):
                            vulnerabilities.append({
                                "id": f"BL-006-{len(vulnerabilities)+1}",
                                "test_id": "OTG-BUSLOGIC-006",
                                "name": "Workflow Boundary Vulnerability",
                                "description": f"It's possible to jump from '{workflow_name}' workflow to '{other_workflow.get('name')}' workflow",
                                "severity": "medium",
                                "workflows": f"{workflow_name} -> {other_workflow.get('name')}",
                                "evidence": "Able to access the final step of another workflow",
                                "mitigation": "Implement proper workflow isolation and state verification"
                            })
                    except Exception as e:
                        logger.debug(f"Error testing workflow boundary between {workflow_name} and {other_workflow.get('name')}: {e}")
        
        logger.info(f"Completed Workflow Circumvention tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_application_misuse(self):
        """OTG-BUSLOGIC-007: Test Defenses Against Application Misuse"""
        logger.info("Running Application Misuse tests")
        vulnerabilities = []
        
        # Test for excessive resource usage
        resource_endpoints = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in [
                "search", "report", "download", "export", "list", "query", "find", "filter"
            ])
        ]
        
        for endpoint in resource_endpoints:
            # Test with potentially expensive search/filter parameters
            test_params = [
                {"param": "limit", "value": "1000000"},
                {"param": "page_size", "value": "1000000"},
                {"param": "size", "value": "1000000"},
                {"param": "count", "value": "1000000"},
                {"param": "q", "value": "*" * 1000},  # Very long search term
                {"param": "search", "value": "*" * 1000},
                {"param": "filter", "value": "*" * 1000},
                {"param": "sort", "value": "multiple,fields,with,many,options,ascending"}
            ]
            
            for test_param in test_params:
                test_url = f"{endpoint}?{test_param['param']}={test_param['value']}"
                
                try:
                    # Use a shorter timeout to detect resource exhaustion
                    short_timeout = min(5, self.config["timeout"] / 2)
                    response = self.session.get(
                        test_url,
                        allow_redirects=self.config["follow_redirects"],
                        timeout=short_timeout
                    )
                    
                    # Check if the request succeeded despite potential resource misuse
                    if response.status_code == 200:
                        vulnerabilities.append({
                            "id": f"BL-007-{len(vulnerabilities)+1}",
                            "test_id": "OTG-BUSLOGIC-007",
                            "name": "Missing Resource Usage Controls",
                            "description": f"The application allows potentially expensive operations with parameter '{test_param['param']}'",
                            "severity": "medium",
                            "endpoint": endpoint,
                            "method": "GET",
                            "param": test_param["param"],
                            "value": test_param["value"],
                            "evidence": f"Request with excessive resource demand was processed successfully",
                            "mitigation": "Implement resource usage limits and throttling"
                        })
                except requests.exceptions.Timeout:
                    # Timeout might indicate resource exhaustion
                    vulnerabilities.append({
                        "id": f"BL-007-{len(vulnerabilities)+1}",
                        "test_id": "OTG-BUSLOGIC-007",
                        "name": "Resource Exhaustion Vulnerability",
                        "description": f"The application may be vulnerable to resource exhaustion with parameter '{test_param['param']}'",
                        "severity": "high",
                        "endpoint": endpoint,
                        "method": "GET",
                        "param": test_param["param"],
                        "value": test_param["value"],
                        "evidence": "Request timed out, potentially indicating resource exhaustion",
                        "mitigation": "Implement resource usage limits and timeout controls"
                    })
                except Exception as e:
                    logger.debug(f"Error testing resource usage on {endpoint}: {e}")
                
                time.sleep(self.config["request_delay"])
        
        # Test for automated/bot activity detection
        sensitive_endpoints = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in [
                "login", "register", "signup", "contact", "submit", "checkout", "order"
            ])
        ]
        
        # Send rapid sequential requests to check for anti-automation controls
        for endpoint in sensitive_endpoints:
            rapid_requests = 5
            request_delay = 0.1  # Very small delay between requests
            
            try:
                # Create a fresh session with a bot-like User-Agent
                test_session = requests.Session()
                test_session.headers.update({
                    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
                })
                
                success_count = 0
                for i in range(rapid_requests):
                    response = test_session.get(
                        endpoint,
                        allow_redirects=self.config["follow_redirects"],
                        timeout=self.config["timeout"]
                    )
                    
                    if response.status_code == 200:
                        success_count += 1
                    
                    time.sleep(request_delay)
                
                # If all requests succeeded, might indicate missing anti-automation controls
                if success_count == rapid_requests:
                    vulnerabilities.append({
                        "id": f"BL-007-{len(vulnerabilities)+1}",
                        "test_id": "OTG-BUSLOGIC-007",
                        "name": "Missing Anti-Automation Controls",
                        "description": f"The application does not implement controls against rapid bot-like requests",
                        "severity": "medium",
                        "endpoint": endpoint,
                        "method": "GET",
                        "evidence": f"Successfully made {rapid_requests} rapid requests with bot-like User-Agent",
                        "mitigation": "Implement rate limiting, CAPTCHA, or other anti-automation measures"
                    })
            except Exception as e:
                logger.debug(f"Error testing anti-automation on {endpoint}: {e}")
        
        # Test for business rule enforcement
        if self.discovered_workflows:
            for workflow in self.discovered_workflows:
                if workflow.get("name") == "checkout_process" or "checkout" in workflow.get("name", "").lower():
                    # Test for price manipulation in checkout
                    checkout_steps = workflow.get("steps", [])
                    
                    if len(checkout_steps) >= 2:
                        # Try to find price parameter in final steps
                        last_step = checkout_steps[-1]
                        try:
                            for param_data in self.discovered_params.get(last_step.get("url"), []):
                                fields = param_data.get("fields", [])
                                
                                for field in fields:
                                    field_name = field.get("name", "").lower()
                                    
                                    if any(kw in field_name for kw in ["price", "total", "amount", "cost"]):
                                        # Found a price field, test for direct manipulation
                                        vulnerabilities.append({
                                            "id": f"BL-007-{len(vulnerabilities)+1}",
                                            "test_id": "OTG-BUSLOGIC-007",
                                            "name": "Potential Price Manipulation Vulnerability",
                                            "description": f"The checkout process contains a price parameter '{field.get('name')}' that might be vulnerable to manipulation",
                                            "severity": "critical",
                                            "endpoint": last_step.get("url"),
                                            "method": param_data.get("method", "POST"),
                                            "param": field.get("name"),
                                            "evidence": "Found price parameter in checkout form",
                                            "mitigation": "Implement server-side price calculation and verification"
                                        })
                        except Exception as e:
                            logger.debug(f"Error testing price manipulation: {e}")
        
        logger.info(f"Completed Application Misuse tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_unexpected_file_types(self):
        """OTG-BUSLOGIC-008: Test Upload of Unexpected File Types"""
        logger.info("Running Unexpected File Types tests")
        vulnerabilities = []
        
        # Find upload endpoints
        upload_endpoints = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in ["upload", "file", "import", "attach", "document"])
        ]
        
        if not upload_endpoints:
            logger.info("No file upload endpoints found")
            return vulnerabilities
            
        # Create test files with unexpected extensions
        test_dir = os.path.join(os.getcwd(), "test_files")
        os.makedirs(test_dir, exist_ok=True)
        
        unexpected_file_types = [
            {"name": "test.html", "content": "<html><body><script>alert('XSS')</script></body></html>", "type": "text/html"},
            {"name": "test.svg", "content": "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('XSS')\"/>", "type": "image/svg+xml"},
            {"name": "test.php", "content": "<?php echo 'PHP execution test'; ?>", "type": "application/x-php"},
            {"name": "test.htaccess", "content": "AddType application/x-httpd-php .jpg", "type": "text/plain"},
            {"name": "test.js", "content": "console.log('JavaScript execution test');", "type": "application/javascript"},
            {"name": "test.aspx", "content": "<%@ Page Language=\"C#\" %><%Response.Write(\"ASPX test\");%>", "type": "text/plain"},
            {"name": "test.csv.exe", "content": "MZ", "type": "application/octet-stream"},  # Double extension
            {"name": "test.jpg.php", "content": "<?php echo 'PHP execution test'; ?>", "type": "image/jpeg"}  # Double extension
        ]
        
        test_file_paths = []
        for file_info in unexpected_file_types:
            file_path = os.path.join(test_dir, file_info["name"])
            with open(file_path, "w") as f:
                f.write(file_info["content"])
            test_file_paths.append((file_path, file_info["type"], file_info["name"]))
        
        # Test each upload endpoint
        for endpoint in upload_endpoints:
            logger.info(f"Testing unexpected file types on {endpoint}")
            
            # Find file upload parameters
            file_upload_fields = []
            for param_data in self.discovered_params.get(endpoint, []):
                if param_data.get("method", "").lower() == "post":
                    for field in param_data.get("fields", []):
                        if field.get("type") == "file":
                            file_upload_fields.append(field.get("name"))
            
            # If no explicit file fields found, try common names
            if not file_upload_fields:
                file_upload_fields = ["file", "upload", "fileupload", "attachment", "document", "image"]
            
            # Test each unexpected file type
            for file_path, file_type, file_name in test_file_paths:
                for field_name in file_upload_fields:
                    try:
                        with open(file_path, "rb") as f:
                            files = {field_name: (file_name, f, file_type)}
                            
                            response = self.session.post(
                                endpoint,
                                files=files,
                                allow_redirects=self.config["follow_redirects"],
                                timeout=self.config["timeout"]
                            )
                            
                            # Check if upload was successful
                            if response.status_code == 200 and self._is_success_response(response):
                                vulnerabilities.append({
                                    "id": f"BL-008-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-008",
                                    "name": "Unexpected File Type Accepted",
                                    "description": f"The application accepted a file with unexpected type: {file_name}",
                                    "severity": "high",
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "field": field_name,
                                    "file_type": file_type,
                                    "evidence": f"File upload succeeded with status code {response.status_code}",
                                    "mitigation": "Implement proper file type validation and whitelist allowed file types"
                                })
                        
                        time.sleep(self.config["request_delay"])
                    except Exception as e:
                        logger.debug(f"Error testing file upload for {file_name} on {endpoint}: {e}")
        
        # Clean up test files
        for file_path, _, _ in test_file_paths:
            try:
                os.remove(file_path)
            except:
                pass
        
        logger.info(f"Completed Unexpected File Types tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def test_malicious_file_upload(self):
        """OTG-BUSLOGIC-009: Test Upload of Malicious Files"""
        logger.info("Running Malicious File Upload tests")
        vulnerabilities = []
        
        # Find upload endpoints
        upload_endpoints = [
            endpoint for endpoint in self.discovered_endpoints
            if any(kw in endpoint.lower() for kw in ["upload", "file", "import", "attach", "document"])
        ]
        
        if not upload_endpoints:
            logger.info("No file upload endpoints found")
            return vulnerabilities
            
        # Create test files with potentially malicious content
        test_dir = os.path.join(os.getcwd(), "test_files")
        os.makedirs(test_dir, exist_ok=True)
        
        malicious_files = [
            {"name": "malicious.jpg", "content": "GIF89a1\x00\x00\xff\xff\xff\x00<?php echo 'PHP code execution test'; ?>", "type": "image/jpeg"},
            {"name": "malicious.png", "content": "\x89PNG\r\n\x1a\n<?php echo 'PHP code execution test'; ?>", "type": "image/png"},
            {"name": "malicious.pdf", "content": "%PDF-1.3\n%\xE2\xE3\xCF\xD3\n<script>alert('XSS')</script>", "type": "application/pdf"},
            {"name": "malicious.zip", "content": "PK\x03\x04\x14\x00\x00\x00\x08\x00", "type": "application/zip"},
            {"name": "malicious.docx", "content": "PK\x03\x04", "type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
        ]
        
        test_file_paths = []
        for file_info in malicious_files:
            file_path = os.path.join(test_dir, file_info["name"])
            with open(file_path, "wb") as f:
                f.write(file_info["content"].encode())
            test_file_paths.append((file_path, file_info["type"], file_info["name"]))
        
        # Test each upload endpoint
        for endpoint in upload_endpoints:
            logger.info(f"Testing malicious file upload on {endpoint}")
            
            # Find file upload parameters
            file_upload_fields = []
            for param_data in self.discovered_params.get(endpoint, []):
                if param_data.get("method", "").lower() == "post":
                    for field in param_data.get("fields", []):
                        if field.get("type") == "file":
                            file_upload_fields.append(field.get("name"))
            
            # If no explicit file fields found, try common names
            if not file_upload_fields:
                file_upload_fields = ["file", "upload", "fileupload", "attachment", "document", "image"]
            
            # Test each malicious file
            for file_path, file_type, file_name in test_file_paths:
                for field_name in file_upload_fields:
                    try:
                        with open(file_path, "rb") as f:
                            files = {field_name: (file_name, f, file_type)}
                            
                            response = self.session.post(
                                endpoint,
                                files=files,
                                allow_redirects=self.config["follow_redirects"],
                                timeout=self.config["timeout"]
                            )
                            
                            # Check if upload was successful
                            if response.status_code == 200 and self._is_success_response(response):
                                vulnerabilities.append({
                                    "id": f"BL-009-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-009",
                                    "name": "Malicious File Accepted",
                                    "description": f"The application accepted a potentially malicious file: {file_name}",
                                    "severity": "critical",
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "field": field_name,
                                    "file_type": file_type,
                                    "evidence": f"File upload succeeded with status code {response.status_code}",
                                    "mitigation": "Implement proper file content validation and sanitization"
                                })
                        
                        time.sleep(self.config["request_delay"])
                    except Exception as e:
                        logger.debug(f"Error testing malicious file upload for {file_name} on {endpoint}: {e}")
        
        # Test for path traversal in filenames
        path_traversal_filenames = [
            "../../etc/passwd",
            "../../../config.php",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
        ]
        
        for endpoint in upload_endpoints:
            for field_name in file_upload_fields:
                for traversal_name in path_traversal_filenames:
                    try:
                        # Use a simple text file with a traversal filename
                        test_content = "Test content for path traversal"
                        test_file_path = os.path.join(test_dir, "traversal_test.txt")
                        with open(test_file_path, "w") as f:
                            f.write(test_content)
                            
                        with open(test_file_path, "rb") as f:
                            files = {field_name: (traversal_name, f, "text/plain")}
                            
                            response = self.session.post(
                                endpoint,
                                files=files,
                                allow_redirects=self.config["follow_redirects"],
                                timeout=self.config["timeout"]
                            )
                            
                            # Check if upload was successful
                            if response.status_code == 200 and self._is_success_response(response):
                                vulnerabilities.append({
                                    "id": f"BL-009-{len(vulnerabilities)+1}",
                                    "test_id": "OTG-BUSLOGIC-009",
                                    "name": "Path Traversal in File Upload",
                                    "description": f"The application accepted a file with path traversal in filename: {traversal_name}",
                                    "severity": "critical",
                                    "endpoint": endpoint,
                                    "method": "POST",
                                    "field": field_name,
                                    "evidence": f"File upload with traversal filename succeeded",
                                    "mitigation": "Sanitize filenames and reject path traversal attempts"
                                })
                                
                        os.remove(test_file_path)
                        time.sleep(self.config["request_delay"])
                    except Exception as e:
                        logger.debug(f"Error testing path traversal in filename on {endpoint}: {e}")
        
        # Clean up test files
        for file_path, _, _ in test_file_paths:
            try:
                os.remove(file_path)
            except:
                pass
        
        logger.info(f"Completed Malicious File Upload tests. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    def generate_report(self, output_format="html", filename=None):
        """Generate a report of the test results"""
        if not self.test_results:
            logger.error("No test results available. Run tests first.")
            return None
            
        if output_format.lower() == "html":
            report = self._generate_html_report()
        elif output_format.lower() == "json":
            report = json.dumps(self.test_results, indent=4)
        elif output_format.lower() == "csv":
            report = self._generate_csv_report()
        else:
            logger.error(f"Unsupported output format: {output_format}")
            return None
            
        if filename:
            try:
                with open(filename, "w") as f:
                    f.write(report)
                logger.info(f"Report saved to {filename}")
            except Exception as e:
                logger.error(f"Error saving report to {filename}: {e}")
                
        return report
    
    def _generate_html_report(self):
        """Generate an HTML report of the test results"""
        # Get summary data
        summary = self.test_results.get("summary", {})
        vulnerabilities = self.test_results.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_counts = {
            "critical": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
            "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
            "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
            "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
            "info": sum(1 for v in vulnerabilities if v.get("severity") == "info")
        }
        
        # Count vulnerabilities by test module
        module_counts = {}
        for v in vulnerabilities:
            test_id = v.get("test_id", "unknown")
            if test_id not in module_counts:
                module_counts[test_id] = 0
            module_counts[test_id] += 1
        
        # Generate HTML
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OWASP Business Logic Testing Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }}
                h1, h2, h3 {{
                    color: #0066cc;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-bottom: 20px;
                }}
                th, td {{
                    padding: 10px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .summary-box {{
                    background-color: #f9f9f9;
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }}
                .severity-critical {{
                    color: #fff;
                    background-color: #800000;
                    padding: 3px 6px;
                    border-radius: 3px;
                }}
                .severity-high {{
                    color: #fff;
                    background-color: #cc0000;
                    padding: 3px 6px;
                    border-radius: 3px;
                }}
                .severity-medium {{
                    color: #fff;
                    background-color: #ff9900;
                    padding: 3px 6px;
                    border-radius: 3px;
                }}
                .severity-low {{
                    color: #fff;
                    background-color: #ffcc00;
                    padding: 3px 6px;
                    border-radius: 3px;
                }}
                .severity-info {{
                    color: #fff;
                    background-color: #0099cc;
                    padding: 3px 6px;
                    border-radius: 3px;
                }}
                .vulnerability-details {{
                    display: none;
                    background-color: #f9f9f9;
                    padding: 10px;
                    border: 1px solid #ddd;
                    margin-top: 10px;
                }}
                .toggle-details {{
                    cursor: pointer;
                    color: #0066cc;
                    text-decoration: underline;
                }}
                .chart-container {{
                    width: 600px;
                    height: 300px;
                    margin: 20px auto;
                }}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <h1>OWASP Business Logic Testing Report</h1>
            
            <div class="summary-box">
                <h2>Summary</h2>
                <p><strong>Target:</strong> {summary.get("target", "Unknown")}</p>
                <p><strong>Start Time:</strong> {summary.get("start_time", "Unknown")}</p>
                <p><strong>End Time:</strong> {summary.get("end_time", "Unknown")}</p>
                <p><strong>Total Vulnerabilities:</strong> {summary.get("total_vulnerabilities", 0)}</p>
                <p><strong>Modules Run:</strong> {", ".join(summary.get("modules_run", []))}</p>
            </div>
            
            <h2>Vulnerability Distribution</h2>
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="moduleChart"></canvas>
            </div>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Test ID</th>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
        """
        
        # Add rows for each vulnerability
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            html += f"""
                <tr>
                    <td>{vuln.get("id", "N/A")}</td>
                    <td>{vuln.get("test_id", "N/A")}</td>
                    <td>{vuln.get("name", "N/A")}</td>
                    <td><span class="severity-{severity}">{severity.upper()}</span></td>
                    <td><span class="toggle-details" onclick="toggleDetails('{vuln.get("id", "N/A")}')">Show Details</span>
                        <div id="details-{vuln.get("id", "N/A")}" class="vulnerability-details">
                            <p><strong>Description:</strong> {vuln.get("description", "N/A")}</p>
                            <p><strong>Endpoint:</strong> {vuln.get("endpoint", vuln.get("workflow", "N/A"))}</p>
                            <p><strong>Method:</strong> {vuln.get("method", "N/A")}</p>
                            <p><strong>Evidence:</strong> {vuln.get("evidence", "N/A")}</p>
                            <p><strong>Mitigation:</strong> {vuln.get("mitigation", "N/A")}</p>
                        </div>
                    </td>
                </tr>
            """
        
        # Close the table and add JavaScript for interactivity
        html += f"""
            </table>
            
            <script>
                function toggleDetails(id) {{
                    const details = document.getElementById('details-' + id);
                    if (details.style.display === 'block') {{
                        details.style.display = 'none';
                    }} else {{
                        details.style.display = 'block';
                    }}
                }}
                
                // Create severity chart
                const severityCtx = document.getElementById('severityChart').getContext('2d');
                const severityChart = new Chart(severityCtx, {{
                    type: 'pie',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{{
                            data: [{severity_counts["critical"]}, {severity_counts["high"]}, {severity_counts["medium"]}, {severity_counts["low"]}, {severity_counts["info"]}],
                            backgroundColor: ['#800000', '#cc0000', '#ff9900', '#ffcc00', '#0099cc']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        title: {{
                            display: true,
                            text: 'Vulnerabilities by Severity'
                        }}
                    }}
                }});
                
                // Create module chart
                const moduleCtx = document.getElementById('moduleChart').getContext('2d');
                const moduleLabels = [{', '.join(f"'{module}'" for module in module_counts.keys())}];
                const moduleData = [{', '.join(str(count) for count in module_counts.values())}];
                const moduleChart = new Chart(moduleCtx, {{
                    type: 'bar',
                    data: {{
                        labels: moduleLabels,
                        datasets: [{{
                            label: 'Vulnerabilities by Test Module',
                            data: moduleData,
                            backgroundColor: '#0066cc'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                ticks: {{
                                    stepSize: 1
                                }}
                            }}
                        }}
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        return html
    
    def _generate_csv_report(self):
        """Generate a CSV report of the test results"""
        vulnerabilities = self.test_results.get("vulnerabilities", [])
        
        # Define CSV header
        header = [
            "ID", "Test ID", "Name", "Description", "Severity", 
            "Endpoint", "Method", "Parameter", "Evidence", "Mitigation"
        ]
        
        # Prepare CSV rows
        rows = [header]
        for vuln in vulnerabilities:
            row = [
                vuln.get("id", ""),
                vuln.get("test_id", ""),
                vuln.get("name", ""),
                vuln.get("description", ""),
                vuln.get("severity", ""),
                vuln.get("endpoint", vuln.get("workflow", "")),
                vuln.get("method", ""),
                vuln.get("param", ""),
                vuln.get("evidence", ""),
                vuln.get("mitigation", "")
            ]
            rows.append(row)
        
        # Convert to CSV
        csv_output = ""
        for row in rows:
            csv_output += ",".join([f'"{str(cell).replace(\'"\', \'""\'")}"' for cell in row]) + "\n"
            
        return csv_output


def main():
    """Main function to run the script from command line"""
    parser = argparse.ArgumentParser(description='OWASP Business Logic Testing Tool')
    parser.add_argument('target_url', help='Target URL to test')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-o', '--output', help='Path to output report file')
    parser.add_argument('-f', '--format', choices=['html', 'json', 'csv'], default='html', help='Report format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Run the tests
    tester = OWASPBusinessLogicTester(args.target_url, args.config)
    
    try:
        # Run discovery phase
        discovery_results = tester.run_discovery()
        logger.info(f"Discovery phase found {len(discovery_results['endpoints'])} endpoints")
        
        # Run all tests
        test_results = tester.run_all_tests()
        
        # Generate report
        report_filename = args.output if args.output else f"buslogic_report_{int(time.time())}.{args.format}"
        tester.generate_report(args.format, report_filename)
        
        # Print summary
        summary = test_results["summary"]
        print("\n" + "="*80)
        print(f"OWASP Business Logic Testing Report Summary:")
        print(f"Target: {summary['target']}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Critical: {summary.get('critical', 0)}")
        print(f"High: {summary.get('high', 0)}")
        print(f"Medium: {summary.get('medium', 0)}")
        print(f"Low: {summary.get('low', 0)}")
        print(f"Info: {summary.get('info', 0)}")
        print(f"Report saved to: {report_filename}")
        print("="*80 + "\n")
        
    except Exception as e:
        logger.error(f"Error running tests: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
            break
                if has_csrf_protection:
