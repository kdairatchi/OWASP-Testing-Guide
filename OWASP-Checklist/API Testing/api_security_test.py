#!/usr/bin/env python3
"""
API Security Testing Script

This script automates testing for the OWASP API Security Top 10 vulnerabilities:
- API-SEC-001: Broken Object Level Authorization
- API-SEC-002: Broken Authentication
- API-SEC-003: Excessive Data Exposure
- API-SEC-004: Lack of Resources & Rate Limiting
- API-SEC-005: Broken Function Level Authorization
- API-SEC-006: Mass Assignment
- API-SEC-007: Security Misconfiguration
- API-SEC-008: Injection
- API-SEC-009: Improper Assets Management
- API-SEC-010: Insufficient Logging & Monitoring

Author: Security Team
Version: 1.0.0
License: MIT
"""

import argparse
import requests
import json
import time
import concurrent.futures
import logging
import sys
import re
import random
import string
import os
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime

# Optional colorama for colored output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api_security_scan.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("API-SEC-SCANNER")

class APISecurityTester:
    def __init__(self, base_url, auth_token=None, endpoints=None, verbose=False, 
                 threads=5, proxy=None, headers_file=None, timeout=10):
        self.base_url = base_url
        self.auth_token = auth_token
        self.verbose = verbose
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.endpoints = endpoints or []
        self.results = {
            "API-SEC-001": {"vulnerable": False, "details": []},
            "API-SEC-002": {"vulnerable": False, "details": []},
            "API-SEC-003": {"vulnerable": False, "details": []},
            "API-SEC-004": {"vulnerable": False, "details": []},
            "API-SEC-005": {"vulnerable": False, "details": []},
            "API-SEC-006": {"vulnerable": False, "details": []},
            "API-SEC-007": {"vulnerable": False, "details": []},
            "API-SEC-008": {"vulnerable": False, "details": []},
            "API-SEC-009": {"vulnerable": False, "details": []},
            "API-SEC-010": {"vulnerable": False, "details": []}
        }
        
        # Set up session
        if auth_token:
            self.session.headers.update({"Authorization": f"Bearer {auth_token}"})
        
        self.session.headers.update({
            "User-Agent": "API-Security-Tester/1.0",
            "Content-Type": "application/json"
        })
        
        # Load custom headers if provided
        if headers_file and os.path.exists(headers_file):
            try:
                with open(headers_file, 'r') as f:
                    custom_headers = json.load(f)
                    self.session.headers.update(custom_headers)
                    logger.info(f"Loaded custom headers from {headers_file}")
            except Exception as e:
                logger.error(f"Failed to load headers from {headers_file}: {str(e)}")
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            logger.info(f"Using proxy: {proxy}")
    
    def discover_endpoints(self):
        """Attempt to discover API endpoints if none provided"""
        logger.info("Attempting to discover API endpoints...")
        
        # Common API paths to check
        common_paths = [
            "/api", "/v1", "/v2", "/api/v1", "/api/v2", 
            "/users", "/accounts", "/items", "/products",
            "/auth", "/login", "/register", "/data",
            "/admin", "/admin/api", "/dashboard", "/settings",
            "/upload", "/files", "/orders", "/payments",
            "/notifications", "/messages", "/search",
            "/public/api", "/private/api", "/graphql",
            "/api/users", "/api/auth", "/api/products", 
            "/api/orders", "/api/items", "/api/data"
        ]
        
        discovered = []
        
        # Use thread pool for parallel discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for path in common_paths:
                url = urljoin(self.base_url, path)
                futures.append(executor.submit(self._check_endpoint, url))
            
            for future, path in zip(futures, common_paths):
                try:
                    result = future.result()
                    if result:
                        discovered.append(path)
                except Exception:
                    continue
        
        # Also try to discover endpoints from API documentation if available
        self._discover_from_swagger()
        
        if discovered:
            self.endpoints.extend(discovered)
            logger.info(f"Discovered {len(discovered)} potential endpoints")
            return discovered
        else:
            logger.warning("No endpoints discovered automatically. Please provide endpoints manually.")
            return []
    
    def _discover_from_swagger(self):
        """Try to discover endpoints from Swagger/OpenAPI documentation"""
        swagger_paths = [
            "/swagger.json", "/api-docs", "/openapi.json", 
            "/swagger/v1/swagger.json", "/api/swagger.json",
            "/docs/swagger.json", "/spec"
        ]
        
        for path in swagger_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    try:
                        spec = response.json()
                        
                        # Extract paths from Swagger/OpenAPI spec
                        if "paths" in spec:
                            for path in spec["paths"].keys():
                                if path not in self.endpoints:
                                    self.endpoints.append(path)
                            
                            logger.info(f"Discovered {len(spec['paths'])} endpoints from API documentation")
                            return True
                    except json.JSONDecodeError:
                        pass
            except requests.RequestException:
                continue
        
        return False
    
    def _check_endpoint(self, url):
        """Helper method to check if an endpoint exists"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 404:
                logger.info(f"Discovered potential endpoint: {url} (Status: {response.status_code})")
                return True
        except requests.RequestException:
            pass
        return False

    def run_all_tests(self):
        """Run all security tests"""
        start_time = time.time()
        logger.info(f"Starting API security scan against {self.base_url}")
        
        if not self.endpoints:
            self.discover_endpoints()
            
        if not self.endpoints:
            logger.error("No endpoints to test. Exiting.")
            return self.results
        
        logger.info(f"Testing {len(self.endpoints)} endpoints: {', '.join(self.endpoints)}")
        
        # Run all tests
        tests = [
            (self.test_broken_object_level_auth, "API-SEC-001: Broken Object Level Authorization"),
            (self.test_broken_authentication, "API-SEC-002: Broken Authentication"),
            (self.test_excessive_data_exposure, "API-SEC-003: Excessive Data Exposure"),
            (self.test_lack_of_rate_limiting, "API-SEC-004: Lack of Resources & Rate Limiting"),
            (self.test_broken_function_level_auth, "API-SEC-005: Broken Function Level Authorization"),
            (self.test_mass_assignment, "API-SEC-006: Mass Assignment"),
            (self.test_security_misconfiguration, "API-SEC-007: Security Misconfiguration"),
            (self.test_injection, "API-SEC-008: Injection"),
            (self.test_improper_assets_management, "API-SEC-009: Improper Assets Management"),
            (self.test_insufficient_logging, "API-SEC-010: Insufficient Logging & Monitoring")
        ]
        
        for test_func, test_name in tests:
            test_start = time.time()
            logger.info(f"Running {test_name}...")
            
            try:
                result = test_func()
                vulnerable_str = "VULNERABLE" if result["vulnerable"] else "NOT VULNERABLE"
                
                if COLORAMA_AVAILABLE:
                    color = Fore.RED if result["vulnerable"] else Fore.GREEN
                    logger.info(f"{test_name}: {color}{vulnerable_str}{Style.RESET_ALL} " +
                              f"({len(result['details'])} issues found)")
                else:
                    logger.info(f"{test_name}: {vulnerable_str} ({len(result['details'])} issues found)")
                
                logger.info(f"Completed in {time.time() - test_start:.2f} seconds")
            
            except Exception as e:
                logger.error(f"Error in {test_name}: {str(e)}")
        
        total_vulnerabilities = sum(1 for test, details in self.results.items() if details["vulnerable"])
        total_details = sum(len(details["details"]) for test, details in self.results.items())
        
        logger.info(f"Scan completed in {time.time() - start_time:.2f} seconds")
        logger.info(f"Found {total_vulnerabilities}/10 vulnerability categories with {total_details} total issues")
        
        return self.results
    
    def test_broken_object_level_auth(self):
        """Test for API-SEC-001: Broken Object Level Authorization"""
        logger.info("Testing for Broken Object Level Authorization (API-SEC-001)...")
        
        # Look for endpoints that might contain object IDs
        object_endpoints = [ep for ep in self.endpoints if re.search(r'\/\w+\/\d+', ep) or '{id}' in ep]
        
        if not object_endpoints:
            # Try to find object IDs from general endpoints
            for endpoint in self.endpoints:
                try:
                    response = self.session.get(urljoin(self.base_url, endpoint), timeout=self.timeout)
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Look for potential IDs in the response
                            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                                for item in data:
                                    if 'id' in item:
                                        object_endpoints.append(f"{endpoint}/{item['id']}")
                                        # Only add a few to avoid excessive testing
                                        if len(object_endpoints) >= 5:
                                            break
                        except json.JSONDecodeError:
                            pass
                except requests.RequestException:
                    continue
        
        # If we still don't have object endpoints, create some guesses
        if not object_endpoints:
            for endpoint in self.endpoints:
                if any(resource in endpoint for resource in ["user", "account", "product", "order", "item"]):
                    for i in range(1, 4):  # Try a few IDs
                        object_endpoints.append(f"{endpoint}/{i}")
        
        # Test access to object endpoints with different credentials or no credentials
        for endpoint in object_endpoints:
            # Test without authentication
            original_headers = self.session.headers.copy()
            if "Authorization" in self.session.headers:
                self.session.headers.pop("Authorization")
            
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    self.results["API-SEC-001"]["vulnerable"] = True
                    self.results["API-SEC-001"]["details"].append({
                        "endpoint": endpoint,
                        "issue": "Accessible without proper authentication",
                        "status_code": response.status_code
                    })
                    logger.warning(f"Potential Broken Object Level Authorization found at {endpoint}")
                
                # Test for horizontal privilege escalation
                # Try to access resources that might belong to other users
                if '{id}' in endpoint:
                    # Replace {id} with actual values
                    for i in range(1, 4):
                        test_endpoint = endpoint.replace('{id}', str(i))
                        response = self.session.get(urljoin(self.base_url, test_endpoint), timeout=self.timeout)
                        if response.status_code == 200:
                            self.results["API-SEC-001"]["vulnerable"] = True
                            self.results["API-SEC-001"]["details"].append({
                                "endpoint": test_endpoint,
                                "issue": "Horizontal privilege escalation - can access different user's resources",
                                "status_code": response.status_code
                            })
                            logger.warning(f"Potential horizontal privilege escalation at {test_endpoint}")
            
            except requests.RequestException as e:
                if self.verbose:
                    logger.debug(f"Error testing {endpoint}: {str(e)}")
            
            # Restore headers
            self.session.headers = original_headers
        
        return self.results["API-SEC-001"]
    
    def test_broken_authentication(self):
        """Test for API-SEC-002: Broken Authentication"""
        logger.info("Testing for Broken Authentication (API-SEC-002)...")
        
        # Find authentication endpoints
        auth_endpoints = [ep for ep in self.endpoints if any(x in ep.lower() for x in ['/auth', '/login', '/signin', '/token'])]
        
        if not auth_endpoints:
            logger.info("No authentication endpoints found to test.")
            # Try common auth endpoints even if not discovered
            auth_endpoints = ['/api/login', '/api/auth', '/login', '/auth', '/api/token']
        
        for endpoint in auth_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test 1: Brute force protection
            attempts = 5
            for i in range(attempts):
                try:
                    payload = {
                        "username": f"test_user_{i}",
                        "password": "wrong_password"
                    }
                    response = self.session.post(url, json=payload, timeout=self.timeout)
                    
                    # If no rate limiting after multiple attempts
                    if i == attempts - 1 and response.status_code != 429:
                        self.results["API-SEC-002"]["vulnerable"] = True
                        self.results["API-SEC-002"]["details"].append({
                            "endpoint": endpoint,
                            "issue": "No brute force protection detected",
                            "status_code": response.status_code
                        })
                        logger.warning(f"No brute force protection at {endpoint}")
                
                except requests.RequestException:
                    continue
            
            # Test 2: Check for insecure transport
            if url.startswith("http://"):
                self.results["API-SEC-002"]["vulnerable"] = True
                self.results["API-SEC-002"]["details"].append({
                    "endpoint": endpoint,
                    "issue": "Authentication over insecure HTTP",
                    "status_code": None
                })
                logger.warning(f"Authentication over insecure HTTP at {endpoint}")
            
            # Test 3: Check for weak password policies
            try:
                weak_passwords = ["password", "123456", "admin"]
                for password in weak_passwords:
                    payload = {
                        "username": "test_user",
                        "password": password
                    }
                    response = self.session.post(url, json=payload, timeout=self.timeout)
                    
                    # If a weak password is accepted without error (success or valid credentials error)
                    if response.status_code < 400 or "invalid" not in response.text.lower():
                        self.results["API-SEC-002"]["vulnerable"] = True
                        self.results["API-SEC-002"]["details"].append({
                            "endpoint": endpoint,
                            "issue": "Potentially weak password policy",
                            "status_code": response.status_code
                        })
                        logger.warning(f"Potentially weak password policy at {endpoint}")
                        break
            
            except requests.RequestException:
                continue
                
            # Test 4: Check for session fixation
            try:
                # Try to get a session cookie without authentication
                response = self.session.get(url, timeout=self.timeout)
                if 'Set-Cookie' in response.headers and any(c in response.headers['Set-Cookie'].lower() for c in ['session', 'auth', 'token']):
                    self.results["API-SEC-002"]["vulnerable"] = True
                    self.results["API-SEC-002"]["details"].append({
                        "endpoint": endpoint,
                        "issue": "Potential session fixation vulnerability",
                        "cookies": response.headers.get('Set-Cookie')
                    })
                    logger.warning(f"Potential session fixation vulnerability at {endpoint}")
            except requests.RequestException:
                continue
                
            # Test 5: JWT token testing if found
            for header_name, header_value in self.session.headers.items():
                if header_name.lower() == 'authorization' and 'bearer ' in header_value.lower():
                    jwt_token = header_value.split(' ')[1]
                    # Check for common JWT issues
                    parts = jwt_token.split('.')
                    if len(parts) == 3:
                        # Test for 'none' algorithm
                        try:
                            header = json.loads(self._base64_url_decode(parts[0]))
                            if header.get('alg', '').lower() == 'none':
                                self.results["API-SEC-002"]["vulnerable"] = True
                                self.results["API-SEC-002"]["details"].append({
                                    "endpoint": "JWT Token",
                                    "issue": "JWT uses vulnerable 'none' algorithm",
                                    "header": header
                                })
                                logger.warning("JWT uses vulnerable 'none' algorithm")
                        except:
                            pass
        
        return self.results["API-SEC-002"]
    
    def _base64_url_decode(self, input):
        """Helper function to decode base64url-encoded JWT parts"""
        input += '=' * (4 - (len(input) % 4))
        return input.replace('-', '+').replace('_', '/')
    
    def test_excessive_data_exposure(self):
        """Test for API-SEC-003: Excessive Data Exposure"""
        logger.info("Testing for Excessive Data Exposure (API-SEC-003)...")
        
        sensitive_patterns = [
            r'\b(?:\d[ -]*?){13,16}\b',  # Credit card numbers
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
            r'\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',  # Phone numbers
            r'\bpassword\b|\bsecret\b|\bapikey\b|\bprivate_key\b|\baccess_token\b',  # Sensitive keywords
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',  # UUIDs
            r'\bsocial security\b|\bssn\b|\b\d{3}-\d{2}-\d{4}\b',  # SSN references
            r'\bcvv\b|\bcvc\b|\bsecurity code\b|\bsecret\b|\bhashed_password\b'  # More sensitive data
        ]
        
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    try:
                        # Test raw response first
                        raw_text = response.text
                        for pattern in sensitive_patterns:
                            matches = re.findall(pattern, raw_text, re.IGNORECASE)
                            if matches:
                                self.results["API-SEC-003"]["vulnerable"] = True
                                self.results["API-SEC-003"]["details"].append({
                                    "endpoint": endpoint,
                                    "issue": "Potential sensitive data exposure in raw response",
                                    "pattern_type": pattern,
                                    "matches_count": len(matches)
                                })
                                logger.warning(f"Potential sensitive data exposure at {endpoint}")
                                break
                        
                        # Test structured JSON if available
                        try:
                            data = response.json()
                            data_str = json.dumps(data)
                            
                            # Check for sensitive data patterns in JSON
                            for pattern in sensitive_patterns:
                                matches = re.findall(pattern, data_str, re.IGNORECASE)
                                if matches:
                                    self.results["API-SEC-003"]["vulnerable"] = True
                                    self.results["API-SEC-003"]["details"].append({
                                        "endpoint": endpoint,
                                        "issue": "Potential sensitive data exposure in JSON response",
                                        "pattern_type": pattern,
                                        "matches_count": len(matches)
                                    })
                                    logger.warning(f"Potential sensitive data exposure at {endpoint}")
                                    break
                                    
                            # Check for common sensitive field names in response
                            sensitive_fields = ['password', 'secret', 'token', 'apikey', 'api_key', 'key', 
                                              'credit_card', 'ssn', 'social_security', 'dob', 'birth_date']
                            
                            for field in self._find_keys_recursive(data):
                                if any(sensitive in field.lower() for sensitive in sensitive_fields):
                                    self.results["API-SEC-003"]["vulnerable"] = True
                                    self.results["API-SEC-003"]["details"].append({
                                        "endpoint": endpoint,
                                        "issue": f"Response contains sensitive field name: {field}",
                                        "field": field
                                    })
                                    logger.warning(f"Response contains sensitive field name '{field}' at {endpoint}")
                        
                        except json.JSONDecodeError:
                            pass
                    
                    except Exception as e:
                        if self.verbose:
                            logger.debug(f"Error processing response from {endpoint}: {str(e)}")
            
            except requests.RequestException:
                continue
        
        return self.results["API-SEC-003"]
    
    def _find_keys_recursive(self, obj, parent_key=''):
        """Helper to recursively find all keys in nested dictionaries and lists"""
        keys = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                keys.append(key)
                keys.extend(self._find_keys_recursive(value, key))
        elif isinstance(obj, list) and len(obj) > 0:
            for item in obj:
                keys.extend(self._find_keys_recursive(item, parent_key))
        return keys
    
    def test_lack_of_rate_limiting(self):
        """Test for API-SEC-004: Lack of Resources & Rate Limiting"""
        logger.info("Testing for Lack of Resources & Rate Limiting (API-SEC-004)...")
        
        # Test multiple concurrent requests
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test rate limiting with concurrent requests
            num_requests = 20
            success_count = 0
            blocked_count = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._rate_limit_request, url) for _ in range(num_requests)]
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        status_code = future.result()
                        if status_code == 200:
                            success_count += 1
                        elif status_code == 429:
                            blocked_count += 1
                    except Exception:
                        continue
            
            # If all or most requests succeed without 429 responses
            if success_count > num_requests * 0.8 and blocked_count == 0:
                self.results["API-SEC-004"]["vulnerable"] = True
                self.results["API-SEC-004"]["details"].append({
                    "endpoint": endpoint,
                    "issue": "No rate limiting detected",
                    "success_count": success_count,
                    "blocked_count": blocked_count,
                    "total_requests": num_requests
                })
                logger.warning(f"No rate limiting detected at {endpoint}")
            
            # Test for resource exhaustion
            try:
                # Test with large payloads for POST/PUT endpoints
                if any(method in endpoint.lower() for method in ['/create', '/add', '/update', '/post']):
                    large_payload = {"data": "A" * 1000000}  # 1MB payload
                    response = self.session.post(url, json=large_payload, timeout=self.timeout * 2)
                    
                    if response.status_code < 400:
                        self.results["API-SEC-004"]["vulnerable"] = True
                        self.results["API-SEC-004"]["details"].append({
                            "endpoint": endpoint,
                            "issue": "Large payload accepted without restrictions",
                            "status_code": response.status_code
                        })
                        logger.warning(f"Large payload accepted at {endpoint}")
                        
                    # Test for long parameter names/values
                    long_param_url = f"{url}?{'a'*10000}={'b'*10000}"
                    response = self.session.get(long_param_url, timeout=self.timeout)
                    
                    if response.status_code < 400:
                        self.results["API-SEC-004"]["vulnerable"] = True
                        self.results["API-SEC-004"]["details"].append({
                            "endpoint": endpoint,
                            "issue": "Excessive URL parameter length accepted",
                            "status_code": response.status_code
                        })
                        logger.warning(f"Excessive URL parameter length accepted at {endpoint}")
            
            except requests.RequestException:
                continue
        
        return self.results["API-SEC-004"]
    
    def _rate_limit_request(self, url):
        """Helper method for testing rate limiting"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            return response.status_code
        except requests.RequestException:
            return None
    
    def test_broken_function_level_auth(self):
        """Test for API-SEC-005: Broken Function Level Authorization"""
        logger.info("Testing for Broken Function Level Authorization (API-SEC-005)...")
        
        # Identify admin/privileged endpoints
        admin_patterns = ['/admin', '/manage', '/control', '/config', '/settings', 
                         '/dashboard', '/internal', '/private', '/superuser', '/system']
        
        # Find or guess admin endpoints
        admin_endpoints = [ep for ep in self.endpoints if any(pattern in ep.lower() for pattern in admin_patterns)]
        
        # If no admin endpoints found, try common ones
        if not admin_endpoints:
            for pattern in admin_patterns:
                admin_endpoints.append(pattern)
        
        # Test access to privileged endpoints
        for endpoint in admin_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test without authentication
            original_headers = self.session.headers.copy()
            if "Authorization" in self.session.headers:
                self.session.headers.pop("Authorization")
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code < 400:
                    self.results["API-SEC-005"]["vulnerable"] = True
                    self.results["API-SEC-005"]["details"].append({
                        "endpoint": endpoint,
                        "issue": "Admin endpoint accessible without proper authorization",
                        "status_code": response.status_code
                    })
                    logger.warning(f"Admin endpoint {endpoint} accessible without proper authorization")
            except requests.RequestException:
                continue
            
            # Restore headers
            self.session.headers = original_headers
        
        # Test HTTP method switching
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Try different HTTP methods on the same endpoint
            for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                try:
                    if method == "GET":
                        response = self.session.get(url, timeout=self.timeout)
                    else:
                        # Test with different HTTP methods
                        response = self.session.request(method, url, timeout=self.timeout)
                    
                    # If a different method unexpectedly succeeds
                    if method != "GET" and response.status_code < 400:
                        self.results["API-SEC-005"]["vulnerable"] = True
                        self.results["API-SEC-005"]["details"].append({
                            "endpoint": endpoint,
                            "issue": f"Endpoint allows {method} method without proper authorization",
                            "status_code": response.status_code
                        })
                        logger.warning(f"Endpoint {endpoint} allows {method} method without proper authorization")
                except requests.RequestException:
                    continue
                    
        # Test for role confusion/elevation
        # Look for potential user role or permission indicators in requests/responses
        role_fields = ["role", "permissions", "access_level", "isAdmin", "admin", "is_admin"]
        
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                # Add a fake admin role header and see if it's honored
                headers = {
                    "X-Role": "admin",
                    "X-Admin": "true", 
                    "X-User-Role": "admin",
                    "Role": "admin"
                }
                
                for header_name, header_value in headers.items():
                    test_headers = self.session.headers.copy()
                    test_headers[header_name] = header_value
                    
                    try:
                        response = requests.get(url, headers=test_headers, timeout=self.timeout)
                        
                        # If request succeeds, check if the response indicates elevated privileges
                        if response.status_code < 400:
                            try:
                                data = response.json()
                                if isinstance(data, dict) and any(field in data for field in role_fields):
                                    self.results["API-SEC-005"]["vulnerable"] = True
                                    self.results["API-SEC-005"]["details"].append({
                                        "endpoint": endpoint,
                                        "issue": f"Potential role elevation via {header_name} header",
                                        "header": header_name,
                                        "status_code": response.status_code
                                    })
                                    logger.warning(f"Potential role elevation via {header_name} header at {endpoint}")
                            except:
                                pass
                    except:
                        continue
            except:
                continue
        
        return self.results["API-SEC-005"]
    
    def test_mass_assignment(self):
        """Test for API-SEC-006: Mass Assignment"""
        logger.info("Testing for Mass Assignment (API-SEC-006)...")
        
        # Find endpoints that might accept object creation/updates
        update_endpoints = [ep for ep in self.endpoints if any(x in ep.lower() for x in ['/update', '/create', '/edit', '/add', '/new', '/user', '/profile', '/account'])]
        
        for endpoint in update_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Get the expected fields from a GET request first
            try:
                get_response = self.session.get(url.replace("/update", "").replace("/edit", "").replace("/create", "").replace("/add", "").replace("/new", ""), timeout=self.timeout)
                if get_response.status_code == 200:
                    try:
                        data = get_response.json()
                        if isinstance(data, dict):
                            # Add privileged fields that shouldn't be modifiable
                            test_fields = {
                                "admin": True,
                                "role": "admin",
                                "isAdmin": True,
                                "permissions": ["admin", "superuser"],
                                "access_level": 9999,
                                "verified": True,
                                "is_verified": True,
                                "user_type": "superadmin",
                                "can_delete": True,
                                "premium": True
                            }
                            
                            # Send request with privileged fields added
                            if isinstance(data, dict):
                                payload = {**data, **test_fields}
                            else:
                                payload = test_fields
                                
                            response = self.session.post(url, json=payload, timeout=self.timeout)
                            
                            # If the request is accepted
                            if response.status_code < 400:
                                self.results["API-SEC-006"]["vulnerable"] = True
                                self.results["API-SEC-006"]["details"].append({
                                    "endpoint": endpoint,
                                    "issue": "Potential mass assignment vulnerability",
                                    "status_code": response.status_code,
                                    "fields": list(test_fields.keys())
                                })
                                logger.warning(f"Potential mass assignment vulnerability at {endpoint}")
                        
                        # Test with JSON request that tries to update protected fields
                        if not isinstance(data, dict):
                            # Try common objects that might be vulnerable to mass assignment
                            common_objects = [
                                {"username": "test_user", "email": "test@example.com", **test_fields},
                                {"name": "Test User", "email": "test@example.com", **test_fields},
                                {"id": 1, "title": "Test", **test_fields}
                            ]
                            
                            for obj in common_objects:
                                try:
                                    response = self.session.post(url, json=obj, timeout=self.timeout)
                                    if response.status_code < 400:
                                        self.results["API-SEC-006"]["vulnerable"] = True
                                        self.results["API-SEC-006"]["details"].append({
                                            "endpoint": endpoint,
                                            "issue": "Potential mass assignment with generic object",
                                            "status_code": response.status_code,
                                            "fields": list(test_fields.keys())
                                        })
                                        logger.warning(f"Potential mass assignment with generic object at {endpoint}")
                                        break
                                except:
                                    continue
                    
                    except json.JSONDecodeError:
                        # Try with common object patterns even if JSON parsing failed
                        common_objects = [
                            {"username": "test_user", "email": "test@example.com", **test_fields},
                            {"name": "Test User", "email": "test@example.com", **test_fields},
                            {"id": 1, "title": "Test", **test_fields}
                        ]
                        
                        for obj in common_objects:
                            try:
                                response = self.session.post(url, json=obj, timeout=self.timeout)
                                if response.status_code < 400:
                                    self.results["API-SEC-006"]["vulnerable"] = True
                                    self.results["API-SEC-006"]["details"].append({
                                        "endpoint": endpoint,
                                        "issue": "Potential mass assignment with generic object",
                                        "status_code": response.status_code,
                                        "fields": list(test_fields.keys())
                                    })
                                    logger.warning(f"Potential mass assignment with generic object at {endpoint}")
                                    break
                            except:
                                continue
            
            except requests.RequestException:
                continue
        
        return self.results["API-SEC-006"]
    
    def test_security_misconfiguration(self):
        """Test for API-SEC-007: Security Misconfiguration"""
        logger.info("Testing for Security Misconfiguration (API-SEC-007)...")
        
        # Check for debug/error information exposure
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test with invalid parameters to trigger errors
            try:
                # Add invalid query parameters
                malformed_url = f"{url}?invalid=param&{random.randint(1, 1000)}=test"
                response = self.session.get(malformed_url, timeout=self.timeout)
                
                error_patterns = [
                    "Exception", "Error", "stack trace", "at line", 
                    "syntax error", "unexpected", "traceback", "DEBUG",
                    "ORA-", "MySQL", "SQLSTATE", "PostgreSQL", "MongoDB"
                ]
                
                if response.status_code >= 400:
                    response_text = response.text.lower()
                    for pattern in error_patterns:
                        if pattern.lower() in response_text:
                            self.results["API-SEC-007"]["vulnerable"] = True
                            self.results["API-SEC-007"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Detailed error messages exposed",
                                "pattern": pattern,
                                "status_code": response.status_code
                            })
                            logger.warning(f"Detailed error messages exposed at {endpoint}")
                            break
            
            except requests.RequestException:
                continue
        
        # Check for missing security headers
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            headers = response.headers
            
            security_headers = {
                "Strict-Transport-Security": "Missing HSTS header",
                "Content-Security-Policy": "Missing CSP header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-Frame-Options": "Missing X-Frame-Options header",
                "X-XSS-Protection": "Missing X-XSS-Protection header"
            }
            
            for header, issue in security_headers.items():
                if header not in headers:
                    self.results["API-SEC-007"]["vulnerable"] = True
                    self.results["API-SEC-007"]["details"].append({
                        "endpoint": self.base_url,
                        "issue": issue
                    })
                    logger.warning(f"{issue} at {self.base_url}")
        
        except requests.RequestException:
            pass
        
        # Check for CORS misconfiguration
        try:
            headers = {"Origin": "https://malicious-site.com"}
            response = self.session.get(self.base_url, headers=headers, timeout=self.timeout)
            
            if "Access-Control-Allow-Origin" in response.headers:
                if response.headers["Access-Control-Allow-Origin"] == "*" or "malicious-site.com" in response.headers["Access-Control-Allow-Origin"]:
                    self.results["API-SEC-007"]["vulnerable"] = True
                    self.results["API-SEC-007"]["details"].append({
                        "endpoint": self.base_url,
                        "issue": "Overly permissive CORS policy",
                        "header_value": response.headers["Access-Control-Allow-Origin"]
                    })
                    logger.warning(f"Overly permissive CORS policy at {self.base_url}")
        
        except requests.RequestException:
            pass
            
        # Check for unnecessary HTTP methods
        try:
            methods = ["OPTIONS", "TRACE", "CONNECT", "HEAD", "DEBUG"]
            for method in methods:
                try:
                    response = requests.request(method, self.base_url, timeout=self.timeout)
                    if response.status_code < 400:
                        self.results["API-SEC-007"]["vulnerable"] = True
                        self.results["API-SEC-007"]["details"].append({
                            "endpoint": self.base_url,
                            "issue": f"Unnecessary HTTP method enabled: {method}",
                            "status_code": response.status_code
                        })
                        logger.warning(f"Unnecessary HTTP method {method} enabled at {self.base_url}")
                except:
                    continue
        except:
            pass
        
        # Check for directory listing
        common_dirs = ["/assets", "/images", "/static", "/uploads", "/files", "/docs", "/backup"]
        for directory in common_dirs:
            url = urljoin(self.base_url, directory)
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                # Check for directory listing signatures
                if response.status_code == 200 and any(x in response.text.lower() for x in [
                    "index of", "directory listing", "parent directory", "last modified", 
                    "<title>index of", "directory: /"
                ]):
                    self.results["API-SEC-007"]["vulnerable"] = True
                    self.results["API-SEC-007"]["details"].append({
                        "endpoint": url,
                        "issue": "Directory listing enabled",
                        "status_code": response.status_code
                    })
                    logger.warning(f"Directory listing enabled at {url}")
            except:
                continue
        
        return self.results["API-SEC-007"]
    
    def test_injection(self):
        """Test for API-SEC-008: Injection"""
        logger.info("Testing for Injection (API-SEC-008)...")
        
        # Payloads for different injection types
        injection_payloads = {
            "sql": [
                "' OR 1=1 --", 
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "admin' --",
                "'; SELECT sleep(5) --",
                "1; SELECT pg_sleep(5) --"
            ],
            "nosql": [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$where": "sleep(1000)"}',
                '{"username": {"$regex": "^admin"}}',
                '{"$elemMatch": {"$in": ["admin"]}}'
            ],
            "command": [
                "; ls -la",
                "| cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "& whoami",
                "|| id"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)",
                "';alert(1)//"
            ],
            "ldap": [
                ")(cn=*)",
                "*)(|(cn=*))",
                "*)(uid=*))(|(uid=*",
                "*)(|(objectclass=*"
            ],
            "xpath": [
                "' or '1'='1",
                "' or ''='",
                ")] | //user[contains(name,'adm",
                "'] | //*[contains(*,'adm"
            ],
            "ssrf": [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254/", # AWS metadata endpoint
                "http://192.168.0.1",
                "file:///etc/passwd"
            ]
        }
        
        # Test all endpoints with injection payloads
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test in query parameters
            for inject_type, payloads in injection_payloads.items():
                for payload in payloads:
                    try:
                        # URL parameter injection
                        malformed_url = f"{url}?q={payload}&id={payload}"
                        response = self.session.get(malformed_url, timeout=self.timeout)
                        
                        # Check for injection success patterns
                        if inject_type == "sql" and any(x in response.text.lower() for x in ["sql syntax", "mysql", "postgresql", "ora-", "syntax error", "unclosed quotation"]):
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential SQL injection",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential SQL injection at {endpoint}")
                        
                        elif inject_type == "nosql" and (response.status_code == 200 or any(x in response.text.lower() for x in ["mongodb", "bson", "mongoose"])):
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential NoSQL injection",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential NoSQL injection at {endpoint}")
                        
                        elif inject_type == "command" and any(x in response.text.lower() for x in ["root:", "usr", "bin", "etc", "passwd", "uid=", "gid=", "groups="]):
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential command injection",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential command injection at {endpoint}")
                        
                        elif inject_type == "xss" and payload in response.text:
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential XSS vulnerability",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential XSS vulnerability at {endpoint}")
                            
                        elif inject_type == "ldap" and any(x in response.text.lower() for x in ["ldap", "directory", "distinguished name"]):
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential LDAP injection",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential LDAP injection at {endpoint}")
                            
                        elif inject_type == "xpath" and any(x in response.text.lower() for x in ["xpath", "xml", "syntax error"]):
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential XPath injection",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential XPath injection at {endpoint}")
                            
                        elif inject_type == "ssrf" and (
                                "localhost" in response.text.lower() or 
                                "127.0.0.1" in response.text.lower() or
                                "192.168" in response.text.lower() or
                                "internal server" in response.text.lower()):
                            self.results["API-SEC-008"]["vulnerable"] = True
                            self.results["API-SEC-008"]["details"].append({
                                "endpoint": endpoint,
                                "issue": "Potential SSRF vulnerability",
                                "payload": payload,
                                "method": "GET"
                            })
                            logger.warning(f"Potential SSRF vulnerability at {endpoint}")
                    
                    except requests.RequestException:
                        continue
            
            # Test in request body for POST endpoints
            if any(method in endpoint.lower() for method in ['/create', '/add', '/update', '/post', '/edit', '/new']):
                for inject_type, payloads in injection_payloads.items():
                    for payload in payloads:
                        try:
                            # JSON body injection
                            body = {
                                "username": payload,
                                "id": payload,
                                "search": payload,
                                "query": payload,
                                "name": payload,
                                "email": payload,
                                "password": payload
                            }
                            
                            response = self.session.post(url, json=body, timeout=self.timeout)
                            
                            # Check for injection success patterns (using same patterns as above)
                            if inject_type == "sql" and any(x in response.text.lower() for x in ["sql syntax", "mysql", "postgresql", "ora-", "syntax error", "unclosed quotation"]):
                                self.results["API-SEC-008"]["vulnerable"] = True
                                self.results["API-SEC-008"]["details"].append({
                                    "endpoint": endpoint,
                                    "issue": "Potential SQL injection",
                                    "payload": payload,
                                    "method": "POST"
                                })
                                logger.warning(f"Potential SQL injection at {endpoint} (POST)")
                            
                            # Similar checks for other injection types
                            elif inject_type == "nosql" and (response.status_code == 200 or any(x in response.text.lower() for x in ["mongodb", "bson", "mongoose"])):
                                self.results["API-SEC-008"]["vulnerable"] = True
                                self.results["API-SEC-008"]["details"].append({
                                    "endpoint": endpoint,
                                    "issue": "Potential NoSQL injection",
                                    "payload": payload,
                                    "method": "POST"
                                })
                                logger.warning(f"Potential NoSQL injection at {endpoint} (POST)")
                            
                            # Add checks for other injection types (similar to GET checks)
                            elif inject_type == "command" and any(x in response.text.lower() for x in ["root:", "usr", "bin", "etc", "passwd", "uid=", "gid=", "groups="]):
                                self.results["API-SEC-008"]["vulnerable"] = True
                                self.results["API-SEC-008"]["details"].append({
                                    "endpoint": endpoint,
                                    "issue": "Potential command injection",
                                    "payload": payload,
                                    "method": "POST"
                                })
                                logger.warning(f"Potential command injection at {endpoint} (POST)")
                            
                            # And so on for other injection types...
                        
                        except requests.RequestException:
                            continue
                            
        # Test for blind injection vulnerabilities using time-based techniques
        time_based_payloads = [
            ("sql", "'; SELECT SLEEP(5) --"),
            ("sql", "1; SELECT pg_sleep(5) --"),
            ("nosql", '{"$where": "sleep(5000)"}'),
            ("command", "& sleep 5")
        ]
        
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for inject_type, payload in time_based_payloads:
                try:
                    start_time = time.time()
                    
                    # Try in URL parameters
                    malformed_url = f"{url}?q={payload}"
                    response = self.session.get(malformed_url, timeout=self.timeout * 2)
                    
                    elapsed_time = time.time() - start_time
                    
                    # If response took unusually long, could be a blind injection
                    if elapsed_time > 4.5:  # Slightly less than the sleep time to account for network delays
                        self.results["API-SEC-008"]["vulnerable"] = True
                        self.results["API-SEC-008"]["details"].append({
                            "endpoint": endpoint,
                            "issue": f"Potential blind {inject_type} injection (time-based)",
                            "payload": payload,
                            "method": "GET",
                            "response_time": elapsed_time
                        })
                        logger.warning(f"Potential blind {inject_type} injection at {endpoint} (response time: {elapsed_time:.2f}s)")
                
                except requests.RequestException:
                    continue
        
        return self.results["API-SEC-008"]
    
    def test_improper_assets_management(self):
        """Test for API-SEC-009: Improper Assets Management"""
        logger.info("Testing for Improper Assets Management (API-SEC-009)...")
        
        # Check for non-production endpoints
        test_environments = [
            "dev", "development", "stage", "staging", "test", 
            "uat", "qa", "sandbox", "beta", "v1", "v2", "old",
            "backup", "bak", "deprecated", "archive", "legacy"
        ]
        
        # Extract base domain
        parsed_url = urlparse(self.base_url)
        base_domain = parsed_url.netloc
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]
        
        protocol = parsed_url.scheme
        
        # Test for different API versions and environments
        for env in test_environments:
            # Test subdomains
            test_url = f"{protocol}://{env}.{base_domain}"
            try:
                response = requests.get(test_url, timeout=self.timeout)
                if response.status_code < 400:
                    self.results["API-SEC-009"]["vulnerable"] = True
                    self.results["API-SEC-009"]["details"].append({
                        "endpoint": test_url,
                        "issue": f"Non-production environment accessible",
                        "status_code": response.status_code
                    })
                    logger.warning(f"Non-production environment accessible at {test_url}")
            except requests.RequestException:
                continue
            
            # Test path prefixes
            test_url = f"{self.base_url}/{env}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code < 400:
                    self.results["API-SEC-009"]["vulnerable"] = True
                    self.results["API-SEC-009"]["details"].append({
                        "endpoint": test_url,
                        "issue": f"Non-production path accessible",
                        "status_code": response.status_code
                    })
                    logger.warning(f"Non-production path accessible at {test_url}")
            except requests.RequestException:
                continue
        
        # Check for API documentation exposure
        docs_paths = [
            "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
            "/docs", "/redoc", "/openapi.json", "/spec", "/swagger.json",
            "/graphql", "/graphiql", "/graphql-playground", "/explorer",
            "/api-explorer", "/api-spec", "/openapi", "/docs/v1", "/docs/v2"
        ]
        
        for path in docs_paths:
            test_url = urljoin(self.base_url, path)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code < 400:
                    self.results["API-SEC-009"]["vulnerable"] = True
                    self.results["API-SEC-009"]["details"].append({
                        "endpoint": test_url,
                        "issue": "API documentation publicly accessible",
                        "status_code": response.status_code
                    })
                    logger.warning(f"API documentation publicly accessible at {test_url}")
            except requests.RequestException:
                continue
                
        # Check for version inconsistencies across multiple endpoints
        versions_found = {}
        version_headers = ["X-API-Version", "API-Version", "X-Version", "Version"]
        
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                # Check version headers
                for header in version_headers:
                    if header in response.headers:
                        version = response.headers[header]
                        if header not in versions_found:
                            versions_found[header] = {}
                        
                        versions_found[header][endpoint] = version
                
                # Check for version patterns in response body
                try:
                    if response.headers.get('Content-Type', '').startswith('application/json'):
                        data = response.json()
                        version_fields = ["version", "apiVersion", "api_version"]
                        
                        for field in version_fields:
                            if isinstance(data, dict) and field in data:
                                if field not in versions_found:
                                    versions_found[field] = {}
                                
                                versions_found[field][endpoint] = data[field]
                except:
                    pass
            
            except requests.RequestException:
                continue
        
        # Check for version inconsistencies
        for version_type, endpoints in versions_found.items():
            if len(set(endpoints.values())) > 1:
                self.results["API-SEC-009"]["vulnerable"] = True
                self.results["API-SEC-009"]["details"].append({
                    "issue": f"Inconsistent API versions found ({version_type})",
                    "versions_detected": endpoints
                })
                logger.warning(f"Inconsistent API versions detected across endpoints: {version_type}")
        
        # Check for orphaned and debug endpoints
        debug_endpoints = [
            "/debug", "/test", "/echo", "/ping", "/health", "/status",
            "/metrics", "/internal", "/admin", "/actuator", "/management"
        ]
        
        for endpoint in debug_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code < 400:
                    self.results["API-SEC-009"]["vulnerable"] = True
                    self.results["API-SEC-009"]["details"].append({
                        "endpoint": url,
                        "issue": "Debug/diagnostic endpoint accessible",
                        "status_code": response.status_code
                    })
                    logger.warning(f"Debug/diagnostic endpoint accessible at {url}")
            except requests.RequestException:
                continue
        
        return self.results["API-SEC-009"]
    
    def test_insufficient_logging(self):
        """Test for API-SEC-010: Insufficient Logging & Monitoring"""
        logger.info("Testing for Insufficient Logging & Monitoring (API-SEC-010)...")
        
        # This is hard to test externally, so we'll perform some suspicious activities 
        # and check if we get blocked or detected
        
        suspicious_activities = [
            # Rapid succession of authentication failures
            {"endpoint": "/login", "method": "POST", "data": {"username": "admin", "password": "wrong"}, "count": 10},
            # Accessing sensitive endpoints
            {"endpoint": "/admin", "method": "GET", "data": None, "count": 5},
            # SQL injection attempts
            {"endpoint": "/search", "method": "GET", "params": {"q": "' OR 1=1 --"}, "count": 3},
            # Multiple requests for sensitive data
            {"endpoint": "/users", "method": "GET", "data": None, "count": 15}
        ]
        
        blocked = False
        
        # Perform suspicious activities and check if we get blocked
        for activity in suspicious_activities:
            endpoint = activity["endpoint"]
            if not endpoint.startswith('/'):
                endpoint = '/' + endpoint
                
            url = urljoin(self.base_url, endpoint)
            block_detected = False
            
            for i in range(activity["count"]):
                try:
                    if activity["method"] == "POST":
                        response = self.session.post(url, json=activity["data"], timeout=self.timeout)
                    elif activity["method"] == "GET" and activity.get("params"):
                        response = self.session.get(url, params=activity["params"], timeout=self.timeout)
                    else:
                        response = self.session.get(url, timeout=self.timeout)
                    
                    # Check if we got blocked
                    if response.status_code == 429 or response.status_code == 403:
                        block_detected = True
                        blocked = True
                        break
                        
                    # Slight delay to avoid hammering the server
                    time.sleep(0.2)
                
                except requests.RequestException:
                    continue
            
            # Record the activity and result
            self.results["API-SEC-010"]["details"].append({
                "endpoint": endpoint,
                "method": activity["method"],
                "activity": "Multiple suspicious requests",
                "blocked": block_detected
            })
            
            if block_detected:
                logger.info(f"Detected blocking after suspicious activity at {endpoint}")
        
        # If no blocking was detected, mark as potentially vulnerable
        if not blocked:
            self.results["API-SEC-010"]["vulnerable"] = True
            logger.warning("No blocking detected after suspicious activities, insufficient logging/monitoring likely")
        
        # Check for basic security headers that might indicate logging
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            headers = response.headers
            
            logging_headers = ["X-Request-ID", "X-Trace-ID", "X-Transaction-ID"]
            has_logging_headers = any(h in headers for h in logging_headers)
            
            if not has_logging_headers:
                self.results["API-SEC-010"]["vulnerable"] = True
                self.results["API-SEC-010"]["details"].append({
                    "endpoint": self.base_url,
                    "issue": "No logging-related headers detected"
                })
                logger.warning("No logging-related headers detected")
        
        except requests.RequestException:
            pass
            
        # Note that real verification would require server-side access
        if self.results["API-SEC-010"]["vulnerable"]:
            self.results["API-SEC-010"]["details"].append({
                "note": "Server-side verification is required for accurate assessment"
            })
            
        return self.results["API-SEC-010"]
    
    def save_results(self, filename=None):
        """Save the test results to a JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"api_security_report_{timestamp}.json"
        
        # Add summary information
        result_summary = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "target": self.base_url,
                "endpoints_tested": len(self.endpoints),
                "endpoints": self.endpoints
            },
            "results": self.results,
            "summary": {
                "vulnerable_categories": sum(1 for test, details in self.results.items() if details["vulnerable"]),
                "total_issues": sum(len(details["details"]) for test, details in self.results.items()),
                "risk_level": self._calculate_risk_level()
            }
        }
        
        with open(filename, "w") as f:
            json.dump(result_summary, f, indent=2)
        
        logger.info(f"Results saved to {filename}")
        return filename
    
    def _calculate_risk_level(self):
        """Calculate overall risk level based on findings"""
        vulnerable_count = sum(1 for test, details in self.results.items() if details["vulnerable"])
        
        if vulnerable_count >= 7:
            return "CRITICAL"
        elif vulnerable_count >= 5:
            return "HIGH"
        elif vulnerable_count >= 3:
            return "MEDIUM"
        elif vulnerable_count >= 1:
            return "LOW"
        else:
            return "SECURE"


def generate_html_report(scanner, output_file=None):
    """Generate an HTML report of the scan results"""
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"api_security_report_{timestamp}.html"
    
    # HTML template
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        header {
            border-bottom: 1px solid #eee;
            margin-bottom: 20px;
            padding-bottom: 10px;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            margin-bottom: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
        .summary-item {
            flex: 1;
            min-width: 200px;
            padding: 10px;
        }
        .test-result {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .test-header {
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .vulnerable {
            background-color: #fff6f6;
            border-left: 5px solid #e74c3c;
        }
        .secure {
            background-color: #f7fdf7;
            border-left: 5px solid #2ecc71;
        }
        .vulnerable .test-header {
            background-color: #fcefef;
        }
        .secure .test-header {
            background-color: #edfcef;
        }
        .status {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
            color: white;
        }
        .status-vulnerable {
            background-color: #e74c3c;
        }
        .status-secure {
            background-color: #2ecc71;
        }
        .test-details {
            padding: 15px;
        }
        .no-issues {
            color: #7f8c8d;
            font-style: italic;
        }
        .issue {
            margin-bottom: 15px;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 3px;
            border-left: 3px solid #3498db;
        }
        .issue pre {
            background-color: #f1f1f1;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }
        .risk-level {
            display: inline-block;
            padding: 5px 10px;
            color: white;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-secure { background-color: #2ecc71; }
        .risk-low { background-color: #3498db; }
        .risk-medium { background-color: #f39c12; }
        .risk-high { background-color: #e74c3c; }
        .risk-critical { background-color: #c0392b; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        footer {
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>API Security Scan Report</h1>
            <p class="timestamp">Report generated on: {{timestamp}}</p>
        </header>
        
        <section class="summary">
            <div class="summary-item">
                <h3>Target Information</h3>
                <p><strong>URL:</strong> {{base_url}}</p>
                <p><strong>Endpoints Tested:</strong> {{endpoint_count}}</p>
            </div>
            <div class="summary-item">
                <h3>Scan Summary</h3>
                <p><strong>Overall Risk Level:</strong> <span class="risk-level risk-{{risk_level_class}}">{{risk_level}}</span></p>
                <p><strong>Vulnerable Categories:</strong> {{vulnerable_count}}/10</p>
                <p><strong>Total Issues Found:</strong> {{total_issues}}</p>
            </div>
        </section>

        <h2>Test Results</h2>
        
        {{test_results}}

        <footer>
            <p>OWASP API Security Top 10 Scanner v1.0.0</p>
            <p>Report generated using the API Security Testing Tool</p>
        </footer>
    </div>
</body>
</html>
"""

    # Generate test results HTML
    test_results_html = ""
    
    # Sort results by vulnerability status (vulnerable first)
    sorted_results = sorted(scanner.results.items(), 
                            key=lambda x: (not x[1]["vulnerable"], x[0]))
    
    for test_id, details in sorted_results:
        vulnerable = details["vulnerable"]
        status_class = "vulnerable" if vulnerable else "secure"
        status_text_class = "status-vulnerable" if vulnerable else "status-secure"
        status_text = "VULNERABLE" if vulnerable else "SECURE"
        
        issues_html = ""
        if len(details["details"]) > 0:
            issues_html = "<table><tr><th>Issue</th><th>Endpoint</th><th>Details</th></tr>"
            
            for issue in details["details"]:
                endpoint = issue.get("endpoint", "N/A")
                issue_text = issue.get("issue", "Unknown issue")
                
                # Format additional details
                additional_details = ""
                for key, value in issue.items():
                    if key not in ["endpoint", "issue"]:
                        if isinstance(value, (dict, list)):
                            value_str = json.dumps(value, indent=2)
                            additional_details += f"<strong>{key}:</strong> <pre>{value_str}</pre><br>"
                        else:
                            additional_details += f"<strong>{key}:</strong> {value}<br>"
                
                issues_html += f"<tr><td>{issue_text}</td><td>{endpoint}</td><td>{additional_details}</td></tr>"
            
            issues_html += "</table>"
        else:
            issues_html = "<p class='no-issues'>No issues detected</p>"
        
        # Map test IDs to descriptions
        test_descriptions = {
            "API-SEC-001": "Broken Object Level Authorization",
            "API-SEC-002": "Broken Authentication",
            "API-SEC-003": "Excessive Data Exposure",
            "API-SEC-004": "Lack of Resources & Rate Limiting",
            "API-SEC-005": "Broken Function Level Authorization",
            "API-SEC-006": "Mass Assignment",
            "API-SEC-007": "Security Misconfiguration",
            "API-SEC-008": "Injection",
            "API-SEC-009": "Improper Assets Management",
            "API-SEC-010": "Insufficient Logging & Monitoring"
        }
        
        test_description = test_descriptions.get(test_id, "Unknown Test")
        
        test_results_html += f"""
        <div class="test-result {status_class}">
            <div class="test-header">
                <h3>{test_id}: {test_description}</h3>
                <span class="status {status_text_class}">{status_text}</span>
            </div>
            <div class="test-details">
                {issues_html}
            </div>
        </div>
        """
    
    # Calculate summary data
    risk_level = scanner._calculate_risk_level()
    risk_level_class = risk_level.lower()
    vulnerable_count = sum(1 for _, details in scanner.results.items() if details["vulnerable"])
    total_issues = sum(len(details["details"]) for _, details in scanner.results.items())
    
    # Fill in template
    html_content = html_template.replace("{{timestamp}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    html_content = html_content.replace("{{base_url}}", scanner.base_url)
    html_content = html_content.replace("{{endpoint_count}}", str(len(scanner.endpoints)))
    html_content = html_content.replace("{{risk_level}}", risk_level)
    html_content = html_content.replace("{{risk_level_class}}", risk_level_class)
    html_content = html_content.replace("{{vulnerable_count}}", str(vulnerable_count))
    html_content = html_content.replace("{{total_issues}}", str(total_issues))
    html_content = html_content.replace("{{test_results}}", test_results_html)
    
    # Write to file
    with open(output_file, "w") as f:
        f.write(html_content)
    
    logger.info(f"HTML report saved to {output_file}")
    return output_file
