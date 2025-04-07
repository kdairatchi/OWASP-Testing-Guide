#!/usr/bin/env python3
"""
OWASP Identity Management Testing - Registration Process Testing Script
Tests for vulnerabilities in the registration process including input validation,
information disclosure, and security controls.
"""

import requests
import argparse
import json
import csv
import sys
import time
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class RegistrationTester:
    def __init__(self, target_url, output_file="registration_results.csv", 
                 proxy=None, delay=1.0, debug=False):
        self.target_url = target_url
        self.output_file = output_file
        self.delay = delay
        self.debug = debug
        self.session = requests.Session()
        self.results = []
        
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
        
        # Test payloads for input validation testing
        self.test_payloads = {
            'sql_injection': ["' OR 1=1--", "admin'--", "1'; DROP TABLE users--"],
            'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            'special_chars': ["!@#$%^&*()", "ñáéíóú", "你好世界"],
            'long_input': ["A" * 1000],
            'email_validation': ["user@example", "user@.com", "user@example.", "user @example.com", 
                                 "user+test@example.com", "user.name@example.com"]
        }

    def extract_csrf_token(self, response):
        """Extract CSRF token from the page if present"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try common CSRF token field names
        for name in ['csrf_token', 'csrf', '_csrf_token', '_token', 'token', 'csrfmiddlewaretoken']:
            # Try to find in hidden input fields
            field = soup.find('input', {'name': name})
            if field and 'value' in field.attrs:
                return {name: field['value']}
            
            # Try to find in meta tags
            meta = soup.find('meta', {'name': name})
            if meta and 'content' in meta.attrs:
                return {name: meta['content']}
        
        return {}

    def extract_form_fields(self, response):
        """Extract all form fields from the page"""
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        
        if not form:
            print("Warning: No form found on the page")
            return {}
        
        fields = {}
        for input_field in form.find_all(['input', 'select', 'textarea']):
            if 'name' in input_field.attrs:
                # For select fields, find the first option value
                if input_field.name == 'select':
                    option = input_field.find('option')
                    value = option['value'] if option and 'value' in option.attrs else ""
                    fields[input_field['name']] = value
                # For checkboxes/radio buttons with checked attribute
                elif input_field.get('type') in ['checkbox', 'radio'] and input_field.get('checked'):
                    fields[input_field['name']] = input_field.get('value', 'on')
                # For all other input types
                elif 'value' in input_field.attrs and input_field.get('type') != 'submit':
                    fields[input_field['name']] = input_field['value']
                else:
                    fields[input_field['name']] = ""
        
        return fields

    def generate_test_data(self):
        """Generate random but valid-looking registration data"""
        username = f"test_user_{random.randint(10000, 99999)}"
        email = f"{username}@example.com"
        password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(12))
        
        return {
            'username': username,
            'email': email,
            'password': password,
            'confirm_password': password,
            'first_name': 'Test',
            'last_name': 'User',
            'phone': f"+1{random.randint(1000000000, 9999999999)}"
        }

    def attempt_registration(self, data):
        """Attempt a registration with the given data"""
        try:
            # First, get the registration page to extract form fields and CSRF token
            response = self.session.get(self.target_url, headers=self.headers)
            
            # Extract CSRF token and form fields
            csrf_token = self.extract_csrf_token(response)
            form_fields = self.extract_form_fields(response)
            
            # Merge with our test data, prioritizing our test data
            form_data = {**form_fields, **csrf_token, **data}
            
            # Remove any submit button fields (we'll add our own)
            form_data = {k: v for k, v in form_data.items() if not k.lower().startswith('submit')}
            form_data['submit'] = 'Register'
            
            if self.debug:
                print(f"Submitting form with data: {json.dumps(form_data, indent=2)}")
            
            time.sleep(self.delay)  # Add delay to avoid being blocked
            
            # Submit the registration form
            response = self.session.post(self.target_url, data=form_data, headers=self.headers, allow_redirects=True)
            
            return {
                'status_code': response.status_code,
                'response_length': len(response.text),
                'redirect_url': response.url if response.url != self.target_url else None,
                'response_text': response.text if self.debug else None
            }
            
        except requests.RequestException as e:
            print(f"Error during registration attempt: {e}")
            return None

    def test_input_validation(self):
        """Test input validation on the registration form"""
        base_data = self.generate_test_data()
        validation_results = []
        
        print("\nTesting input validation...")
        fields_to_test = ['username', 'email', 'password', 'first_name', 'last_name']
        
        for field in fields_to_test:
            print(f"Testing field: {field}")
            for category, payloads in self.test_payloads.items():
                for payload in payloads:
                    test_data = base_data.copy()
                    test_data[field] = payload
                    
                    test_name = f"{field}_{category}_{payload[:20]}"
                    print(f"  - Testing {test_name}")
                    
                    response_data = self.attempt_registration(test_data)
                    if response_data:
                        validation_results.append({
                            'test_name': test_name,
                            'field': field,
                            'payload': payload,
                            'payload_type': category,
                            'status_code': response_data['status_code'],
                            'response_length': response_data['response_length'],
                            'redirect_url': response_data['redirect_url'],
                            'notes': self._analyze_validation_response(response_data, test_data)
                        })
        
        return validation_results

    def _analyze_validation_response(self, response_data, test_data):
        """Analyze the response to a validation test"""
        # Check for common indicators of validation failure
        if response_data['status_code'] >= 400:
            return "Server error or rejection (status code)"
        
        # Check if we were redirected to a success page
        if response_data['redirect_url'] and any(x in response_data['redirect_url'].lower() for x in ['success', 'thank', 'confirm', 'welcome']):
            return "Potential validation bypass - registration appeared to succeed"
        
        # If we have the response text, check for error messages
        if response_data.get('response_text'):
            text = response_data['response_text'].lower()
            
            if any(x in text for x in ['error', 'invalid', 'failed']):
                return "Validation error detected in response"
            
            if any(x in text for x in ['success', 'thank you', 'confirm', 'welcome']):
                return "Potential validation bypass - success message detected"
            
            # Check if test data appears in the response (potential XSS)
            for key, value in test_data.items():
                if isinstance(value, str) and value in response_data['response_text']:
                    if '<script>' in value or '<img' in value:
                        return f"Potential XSS vulnerability - payload reflected in response"
        
        return "Undetermined - manual review needed"

    def test_rate_limiting(self):
        """Test for rate limiting on the registration form"""
        print("\nTesting rate limiting...")
        base_data = self.generate_test_data()
        results = []
        
        for i in range(10):
            # Slightly modify the user data for each attempt
            test_data = base_data.copy()
            test_data['username'] = f"rate_test_{i}_{random.randint(1000, 9999)}"
            test_data['email'] = f"{test_data['username']}@example.com"
            
            print(f"  - Attempt {i+1}/10 with {test_data['username']}")
            response_data = self.attempt_registration(test_data)
            
            if response_data:
                blocked = False
                
                # Check if we've been rate limited
                if response_data['status_code'] in [429, 403]:
                    blocked = True
                elif response_data.get('response_text'):
                    text = response_data['response_text'].lower()
                    if any(x in text for x in ['rate limit', 'too many', 'try again', 'blocked']):
                        blocked = True
                
                results.append({
                    'attempt': i+1,
                    'status_code': response_data['status_code'],
                    'blocked': blocked,
                    'notes': "Rate limiting detected" if blocked else "No rate limiting detected"
                })
                
                if blocked:
                    print("    Rate limiting detected!")
                    break
        
        return results

    def test_account_creation(self):
        """Test if accounts can actually be created"""
        print("\nTesting account creation...")
        test_data = self.generate_test_data()
        
        print(f"  - Attempting to create account: {test_data['username']}")
        response_data = self.attempt_registration(test_data)
        
        if not response_data:
            return {
                'success': False,
                'notes': "Registration attempt failed"
            }
        
        # Check if registration was successful
        success = False
        notes = []
        
        if response_data['redirect_url'] and any(x in response_data['redirect_url'].lower() for x in ['success', 'thank', 'confirm', 'welcome']):
            success = True
            notes.append("Redirected to success page")
        
        if response_data.get('response_text'):
            text = response_data['response_text'].lower()
            if any(x in text for x in ['success', 'thank you', 'confirm', 'welcome']):
                success = True
                notes.append("Success message detected in response")
            
            if any(x in text for x in ['error', 'failed']):
                success = False
                notes.append("Error message detected in response")
        
        # Try to log in with the created account (could be implemented)
        
        return {
            'username': test_data['username'],
            'email': test_data['email'],
            'success': success,
            'status_code': response_data['status_code'],
            'notes': " | ".join(notes)
        }

    def run_tests(self):
        """Run all registration process tests"""
        print(f"Starting registration process testing for {self.target_url}")
        
        # Test account creation
        account_test = self.test_account_creation()
        self.results.append({
            'test_type': 'account_creation',
            'data': account_test
        })
        
        # Test input validation
        validation_results = self.test_input_validation()
        self.results.append({
            'test_type': 'input_validation',
            'data': validation_results
        })
        
        # Test rate limiting
        rate_limit_results = self.test_rate_limiting()
        self.results.append({
            'test_type': 'rate_limiting',
            'data': rate_limit_results
        })
        
        self.save_results()

    def save_results(self):
        """Save test results to file"""
        try:
            with open(self.output_file, 'w', newline='') as csvfile:
                # First, write summary information
                writer = csv.writer(csvfile)
                writer.writerow(["OWASP Registration Process Testing Results"])
                writer.writerow(["Target URL", self.target_url])
                writer.writerow(["Test Date", time.strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow([])
                
                # Account creation results
                account_test = next((r['data'] for r in self.results if r['test_type'] == 'account_creation'), None)
                if account_test:
                    writer.writerow(["Account Creation Test"])
                    if 'username' in account_test:
                        writer.writerow(["Username", account_test['username']])
                        writer.writerow(["Email", account_test['email']])
                    writer.writerow(["Success", account_test['success']])
                    writer.writerow(["Notes", account_test.get('notes', '')])
                    writer.writerow([])
                
                # Rate limiting results
                rate_limit_results = next((r['data'] for r in self.results if r['test_type'] == 'rate_limiting'), None)
                if rate_limit_results:
                    writer.writerow(["Rate Limiting Test"])
                    writer.writerow(["Attempt", "Status Code", "Blocked", "Notes"])
                    for result in rate_limit_results:
                        writer.writerow([
                            result['attempt'],
                            result['status_code'],
                            result['blocked'],
                            result['notes']
                        ])
                    writer.writerow([])
                
                # Input validation results
                validation_results = next((r['data'] for r in self.results if r['test_type'] == 'input_validation'), None)
                if validation_results:
                    writer.writerow(["Input Validation Tests"])
                    writer.writerow(["Test Name", "Field", "Payload", "Payload Type", "Status Code", "Notes"])
                    for result in validation_results:
                        writer.writerow([
                            result['test_name'],
                            result['field'],
                            result['payload'],
                            result['payload_type'],
                            result['status_code'],
                            result['notes']
                        ])
            
            print(f"\nResults saved to {self.output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='OWASP Identity Management - Registration Process Testing')
    parser.add_argument('-u', '--url', required=True, help='Target registration URL')
    parser.add_argument('-o', '--output', default='registration_test_results.csv', help='Output file for results')
    parser.add_argument('-p', '--proxy', help='Proxy to use for requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay between requests (seconds)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (more verbose output)')
    
    args = parser.parse_args()
    
    tester = RegistrationTester(
        target_url=args.url,
        output_file=args.output,
        proxy=args.proxy,
        delay=args.delay,
        debug=args.debug
    )
    
    tester.run_tests()

if __name__ == "__main__":
    main()
