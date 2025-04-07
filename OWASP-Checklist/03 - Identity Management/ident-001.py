#!/usr/bin/env python3
"""
OWASP Identity Management Testing - Role Definitions Testing Script
Tests for proper role definition and authorization by attempting to access resources 
with different user permissions.
"""

import requests
import argparse
import json
import csv
import time
import sys
import re
import logging
from urllib.parse import urlparse, urljoin
from collections import defaultdict

class RolePrivilegeTester:
    def __init__(self, base_url, users_file, endpoints_file, 
                 output_file="role_testing_results.csv", proxy=None, debug=False):
        self.base_url = base_url
        self.users_file = users_file
        self.endpoints_file = endpoints_file
        self.output_file = output_file
        self.debug = debug
        self.results = []
        
        # Set up logging
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('RoleTester')
        
        # Create session
        self.session = requests.Session()
        
        # Configure proxy if specified
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        # Default request headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        # User accounts with different roles
        self.users = self.load_users()
        
        # Endpoints to test
        self.endpoints = self.load_endpoints()
        
    def load_users(self):
        """Load user credentials and roles from JSON file"""
        try:
            with open(self.users_file, 'r') as file:
                users = json.load(file)
                self.logger.info(f"Loaded {len(users)} user accounts")
                return users
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Error loading users file: {e}")
            sys.exit(1)
            
    def load_endpoints(self):
        """Load endpoints to test from JSON file"""
        try:
            with open(self.endpoints_file, 'r') as file:
                endpoints = json.load(file)
                self.logger.info(f"Loaded {len(endpoints)} endpoints to test")
                return endpoints
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Error loading endpoints file: {e}")
            sys.exit(1)
    
    def login_user(self, user):
        """Attempt to log in with the given user credentials"""
        login_url = urljoin(self.base_url, user.get('login_url', '/login'))
        
        login_data = {
            'username': user['username'],
            'password': user['password'],
            'submit': 'Login'
        }
        
        # Add any additional fields needed for login
        if 'additional_fields' in user:
            login_data.update(user['additional_fields'])
        
        try:
            self.logger.info(f"Attempting to log in as {user['username']} ({user['role']})")
            
            # First, get the login page to capture any CSRF tokens
            response = self.session.get(login_url, headers=self.headers)
            
            # Extract CSRF token if present
            csrf_token = self.extract_csrf_token(response.text)
            if csrf_token:
                login_data.update(csrf_token)
            
            # Submit login form
            response = self.session.post(login_url, data=login_data, headers=self.headers, allow_redirects=True)
            
            # Check if login was successful
            login_success = self.check_login_success(response, user)
            
            if login_success:
                self.logger.info(f"Successfully logged in as {user['username']}")
            else:
                self.logger.error(f"Failed to log in as {user['username']}")
            
            return login_success
            
        except requests.RequestException as e:
            self.logger.error(f"Error during login: {e}")
            return False
    
    def extract_csrf_token(self, html_content):
        """Extract CSRF token from HTML content"""
        # Common CSRF token patterns
        patterns = [
            r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\'](.*?)["\']',
            r'<input[^>]*name=["\']_token["\'][^>]*value=["\'](.*?)["\']',
            r'<input[^>]*name=["\'](csrf|CSRF|_csrf|XSRF)[^"\']*["\'][^>]*value=["\'](.*?)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\'](.*?)["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content)
            if match:
                if len(match.groups()) == 1:
                    token_name = 'csrf_token'
                    token_value = match.group(1)
                else:
                    token_name = match.group(1)
                    token_value = match.group(2)
                
                self.logger.debug(f"Found CSRF token: {token_name}={token_value}")
                return {token_name: token_value}
        
        return {}
    
    def check_login_success(self, response, user):
        """Check if login was successful based on response"""
        # Check for redirect to dashboard/home page
        if user.get('success_url') and user['success_url'] in response.url:
            return True
        
        # Check for success indicators in response content
        if user.get('success_indicator') and user['success_indicator'] in response.text:
            return True
        
        # Check for common success indicators
        common_success = [
            'dashboard', 'welcome', 'profile', 'account', 'logout', 'sign out',
            'you are logged in', 'successfully logged in'
        ]
        
        if any(indicator in response.text.lower() for indicator in common_success):
            return True
        
        # Check for failure indicators
        common_fail = [
            'incorrect password', 'invalid username', 'login failed',
            'please try again', 'authentication failed'
        ]
        
        if any(indicator in response.text.lower() for indicator in common_fail):
            return False
        
        # If no clear indicators, check if we're still on the login page
        login_url = urljoin(self.base_url, user.get('login_url', '/login'))
        login_path = urlparse(login_url).path
        current_path = urlparse(response.url).path
        
        return login_path != current_path
    
    def test_endpoint_access(self, endpoint, user):
        """Test if the current user can access the given endpoint"""
        url = urljoin(self.base_url, endpoint['url'])
        method = endpoint.get('method', 'GET').upper()
        data = endpoint.get('data', {})
        expected_status = endpoint.get('expected_status', {}).get(user['role'], 403)
        
        self.logger.info(f"Testing {method} {url} as {user['username']} ({user['role']})")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=self.headers, allow_redirects=False)
            elif method == 'POST':
                response = self.session.post(url, data=data, headers=self.headers, allow_redirects=False)
            else:
                self.logger.error(f"Unsupported method: {method}")
                return None
            
            result = {
                'endpoint': endpoint['url'],
                'method': method,
                'user': user['username'],
                'role': user['role'],
                'status_code': response.status_code,
                'expected_status': expected_status,
                'access_granted': self.determine_access_granted(response, endpoint, user),
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Log detailed result
            if self.debug:
                result['response_headers'] = dict(response.headers)
                if response.status_code < 300:  # Only include body for non-redirect responses
                    result['response_preview'] = response.text[:500] if response.text else ""
            
            return result
            
        except requests.RequestException as e:
            self.logger.error(f"Error testing endpoint: {e}")
            return None
    
    def determine_access_granted(self, response, endpoint, user):
        """Determine if access was granted based on response"""
        # Check status code against expected status
        expected_status = endpoint.get('expected_status', {}).get(user['role'], 403)
        
        # If we got the expected status code, access was handled correctly
        if response.status_code == expected_status:
            return expected_status < 400  # Access granted for 2xx and 3xx status codes
        
        # If redirect to login page, access was denied
        if response.status_code == 302:
            login_url = user.get('login_url', '/login')
            redirect_url = response.headers.get('Location', '')
            if login_url in redirect_url:
                return False
        
        # If success indicator is present, access was granted
        if 'success_indicator' in endpoint and endpoint['success_indicator'] in response.text:
            return True
        
        # If access denied indicator is present, access was denied
        if 'denied_indicator' in endpoint and endpoint['denied_indicator'] in response.text:
            return False
        
        # Default: access granted for 2xx and 3xx status codes
        return response.status_code < 400
    
    def run_tests(self):
        """Run the role-based access tests for all users and endpoints"""
        self.logger.info(f"Starting role testing for {self.base_url}")
        
        for user in self.users:
            # Start a new session for each user
            self.session = requests.Session()
            
            # Login with current user
            if not self.login_user(user):
                self.logger.warning(f"Skipping tests for {user['username']} due to login failure")
                continue
            
            # Test all endpoints with current user
            for endpoint in self.endpoints:
                result = self.test_endpoint_access(endpoint, user)
                if result:
                    self.results.append(result)
                    
                    # Log access issue if actual access doesn't match expected
                    expected_status = endpoint.get('expected_status', {}).get(user['role'], 403)
                    if result['status_code'] != expected_status:
                        if expected_status < 400 and result['status_code'] >= 400:
                            self.logger.warning(f"Access denied unexpectedly: {user['role']} should have access to {endpoint['url']}")
                        elif expected_status >= 400 and result['status_code'] < 400:
                            self.logger.warning(f"Access granted unexpectedly: {user['role']} should NOT have access to {endpoint['url']}")
                
                # Short delay between requests
                time.sleep(0.5)
            
            # Logout
            self.session.get(urljoin(self.base_url, '/logout'), headers=self.headers)
        
        self.analyze_results()
        self.save_results()
    
    def analyze_results(self):
        """Analyze test results to identify potential vulnerabilities"""
        self.logger.info("Analyzing test results...")
        
        # Group results by endpoint
        endpoint_results = defaultdict(list)
        for result in self.results:
            key = f"{result['method']} {result['endpoint']}"
            endpoint_results[key].append(result)
        
        # Analyze each endpoint
        self.analysis = []
        for endpoint_key, results in endpoint_results.items():
            # Check for inconsistent access control
            roles_with_access = [r['role'] for r in results if r['access_granted']]
            roles_without_access = [r['role'] for r in results if not r['access_granted']]
            
            # Find unexpected access
            unexpected_access = []
            expected_access = {}
            
            for result in results:
                expected = result['expected_status'] < 400
                actual = result['access_granted']
                
                if expected != actual:
                    unexpected_access.append({
                        'role': result['role'],
                        'expected': expected,
                        'actual': actual
                    })
                
                expected_access[result['role']] = expected
            
            # Find privilege escalation paths
            privilege_escalation = []
            for low_role in results:
                if low_role['access_granted']:
                    for high_role in results:
                        if not high_role['access_granted'] and high_role['role'] != low_role['role']:
                            # This is a privilege escalation issue - lower role can access, higher role cannot
                            privilege_escalation.append({
                                'low_role': low_role['role'],
                                'high_role': high_role['role']
                            })
            
            # Add to analysis
            self.analysis.append({
                'endpoint': endpoint_key,
                'roles_with_access': roles_with_access,
                'roles_without_access': roles_without_access,
                'unexpected_access': unexpected_access,
                'privilege_escalation': privilege_escalation
            })
    
    def save_results(self):
        """Save the test results to CSV file"""
        try:
            with open(self.output_file, 'w', newline='') as csvfile:
                # First, write the raw results
                writer = csv.writer(csvfile)
                writer.writerow(["OWASP Role Definition Testing Results"])
                writer.writerow(["Target", self.base_url])
                writer.writerow(["Date", time.strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow([])
                
                writer.writerow(["Raw Test Results"])
                writer.writerow(["Endpoint", "Method", "User", "Role", "Status Code", "Expected Status", "Access Granted"])
                for result in self.results:
                    writer.writerow([
                        result['endpoint'],
                        result['method'],
                        result['user'],
                        result['role'],
                        result['status_code'],
                        result['expected_status'],
                        result['access_granted']
                    ])
                
                writer.writerow([])
                writer.writerow(["Analysis Results"])
                
                for endpoint in self.analysis:
                    writer.writerow([f"Endpoint: {endpoint['endpoint']}"])
                    writer.writerow(["Roles with access", ", ".join(endpoint['roles_with_access'])])
                    writer.writerow(["Roles without access", ", ".join(endpoint['roles_without_access'])])
                    
                    if endpoint['unexpected_access']:
                        writer.writerow(["Unexpected Access Issues:"])
                        for issue in endpoint['unexpected_access']:
                            writer.writerow([
                                f"Role: {issue['role']}", 
                                f"Expected access: {issue['expected']}", 
                                f"Actual access: {issue['actual']}"
                            ])
                    
                    if endpoint['privilege_escalation']:
                        writer.writerow(["Potential Privilege Escalation Issues:"])
                        for issue in endpoint['privilege_escalation']:
                            writer.writerow([
                                f"Lower role ({issue['low_role']}) has access but higher role ({issue['high_role']}) does not"
                            ])
                    
                    writer.writerow([])
            
            self.logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='OWASP Identity Management - Role Definitions Testing')
    parser.add_argument('-u', '--url', required=True, help='Base URL of the application')
    parser.add_argument('-U', '--users', required=True, help='JSON file containing user credentials and roles')
    parser.add_argument('-E', '--endpoints', required=True, help='JSON file containing endpoints to test')
    parser.add_argument('-o', '--output', default='role_testing_results.csv', help='Output file for results')
    parser.add_argument('-p', '--proxy', help='Proxy to use for requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (more verbose output)')
    
    args = parser.parse_args()
    
    tester = RolePrivilegeTester(
        base_url=args.url,
        users_file=args.users,
        endpoints_file=args.endpoints,
        output_file=args.output,
        proxy=args.proxy,
        debug=args.debug
    )
    
    tester.run_tests()

if __name__ == "__main__":
    main()
