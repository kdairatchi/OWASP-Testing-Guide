#!/usr/bin/env python3
"""
OWASP Identity Management Testing - Username Policy Testing Script
Tests for weak or unenforced username policies that could lead to username enumeration
or make usernames predictable.
"""

import requests
import argparse
import json
import csv
import sys
import time
import random
import string
import logging
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class UsernamePolicyTester:
    def __init__(self, registration_url, output_file="username_policy_results.csv", 
                 proxy=None, delay=1.0, debug=False):
        self.registration_url = registration_url
        self.output_file = output_file
        self.delay = delay
        self.debug = debug
        self.results = []
        
        # Configure logging
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('UsernameTester')
        
        # Configure session
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
        
        # Test usernames for different policy checks
        self.test_usernames = {
            'length': [
                {'value': 'a', 'description': 'Single character'},
                {'value': 'ab', 'description': '2 characters'},
                {'value': 'abc', 'description': '3 characters'},
                {'value': 'a' * 20, 'description': '20 characters'},
                {'value': 'a' * 50, 'description': '50 characters'},
                {'value': 'a' * 100, 'description': '100 characters'}
            ],
            'character_set': [
                {'value': 'user123', 'description': 'Alphanumeric'},
                {'value': 'user-123', 'description': 'With hyphen'},
                {'value': 'user_123', 'description': 'With underscore'},
                {'value': 'user.123', 'description': 'With period'},
                {'value': 'user@123', 'description': 'With @ symbol'},
                {'value': 'user#123', 'description': 'With # symbol'},
                {'value': 'user 123', 'description': 'With space'},
                {'value': 'üsér123', 'description': 'With accented characters'},
                {'value': '用户123', 'description': 'With non-Latin characters'},
                {'value': 'user\';--', 'description': 'With SQL injection characters'}
            ],
            'case_sensitivity': [
                {'value': 'testuser', 'description': 'Lowercase'},
                {'value': 'TestUser', 'description': 'Mixed case'},
                {'value': 'TESTUSER', 'description': 'Uppercase'}
            ],
            'reserved_words': [
                {'value': 'admin', 'description': 'admin'},
                {'value': 'administrator', 'description': 'administrator'},
                {'value': 'root', 'description': 'root'},
                {'value': 'system', 'description': 'system'},
                {'value': 'guest', 'description': 'guest'},
                {'value': 'anonymous', 'description': 'anonymous'}
            ]
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
            self.logger.warning("No form found on the page")
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

    def generate_test_data(self, test_username):
        """Generate random but valid-looking registration data with the test username"""
        rand_suffix = random.randint(10000, 99999)
        email = f"test{rand_suffix}@example.com"
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        return {
            'username': test_username,
            'email': email,
            'password': password,
            'confirm_password': password,
            'first_name': 'Test',
            'last_name': 'User'
        }

    def attempt_registration(self, test_username):
        """Attempt a registration with the given username"""
        try:
            # First, get the registration page to extract form fields and CSRF token
            response = self.session.get(self.registration_url, headers=self.headers)
            
            # Extract CSRF token and form fields
            csrf_token = self.extract_csrf_token(response)
            form_fields = self.extract_form_fields(response)
            
            # Generate test data with the test username
            test_data = self.generate_test_data(test_username['value'])
            
            # Merge with our test data, prioritizing our test data
            form_data = {**form_fields, **csrf_token, **test_data}
            
            # Remove any submit button fields (we'll add our own)
            form_data = {k: v for k, v in form_data.items() if not k.lower().startswith('submit')}
            form_data['submit'] = 'Register'
            
            if self.debug:
                self.logger.debug(f"Submitting form with username: {test_username['value']}")
            
            time.sleep(self.delay)  # Add delay to avoid being blocked
            
            # Submit the registration form
            response = self.session.post(self.registration_url, data=form_data, headers=self.headers, allow_redirects=True)
            
            # Analyze the response
            result = {
                'username': test_username['value'],
                'description': test_username['description'],
                'status_code': response.status_code,
                'response_length': len(response.text),
                'redirect_url': response.url if response.url != self.registration_url else None,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Check for error messages related to username
            result['error_message'] = self._extract_username_error(response.text, test_username['value'])
            
            # Determine if the username was accepted
            result['accepted'] = self._is_username_accepted(response, result['error_message'])
            
            return result
            
        except requests.RequestException as e:
            self.logger.error(f"Error during registration attempt: {e}")
            return None
    
    def _extract_username_error(self, response_text, username):
        """Extract error message related to username from response"""
        # Common error patterns related to usernames
        error_patterns = [
            rf"username.*{re.escape(username)}.*invalid",
            rf"{re.escape(username)}.*username.*invalid",
            r"username.*invalid",
            r"username.*already taken",
            r"username.*not available",
            r"username.*reserved",
            r"username.*length",
            r"username.*character",
            r"username.*allowed",
            r"username must .*",
            r"username.*too short",
            r"username.*too long",
            r"username.*minimum",
            r"username.*maximum",
            r"invalid username",
            r"username.*contains.*invalid characters",
            r"username can only contain"
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Get the surrounding context
                start = max(0, match.start() - 20)
                end = min(len(response_text), match.end() + 50)
                error_context = response_text[start:end]
                
                # Clean up the error message
                error_msg = re.sub(r'<[^>]+>', ' ', error_context)  # Remove HTML tags
                error_msg = re.sub(r'\s+', ' ', error_msg).strip()  # Clean up whitespace
                
                return error_msg
        
        return None
    
    def _is_username_accepted(self, response, error_message):
        """Determine if a username was accepted based on response"""
        # If we have an username-related error message, the username was not accepted
        if error_message:
            return False
        
        # Check status code - redirect often indicates success
        if response.status_code in [302, 303, 307]:
            return True
        
        # Check for common success indicators
        success_indicators = [
            'success', 'account created', 'registration complete',
            'verify your email', 'confirmation', 'thank you',
            'welcome', 'registered successfully'
        ]
        
        if any(indicator in response.text.lower() for indicator in success_indicators):
            return True
        
        # Check for absence of common error forms/messages
        error_indicators = [
            'error', 'invalid', 'failed', 'try again',
            'fix the following', 'required fields'
        ]
        
        if not any(indicator in response.text.lower() for indicator in error_indicators):
            return True
        
        # Default to not accepted if we're unsure
        return False
    
    def test_username_length_policy(self):
        """Test the minimum and maximum username length policy"""
        self.logger.info("Testing username length policy")
        
        length_results = []
        
        for test_username in self.test_usernames['length']:
            self.logger.info(f"Testing username length: {test_username['description']}")
            result = self.attempt_registration(test_username)
            if result:
                length_results.append(result)
        
        # Analyze the results to determine length policy
        if length_results:
            # Sort by length
            length_results.sort(key=lambda x: len(x['username']))
            
            # Find minimum accepted length
            min_length = None
            for result in length_results:
                if result['accepted']:
                    min_length = len(result['username'])
                    break
            
            # Find maximum accepted length
            max_length = None
            for result in reversed(length_results):
                if result['accepted']:
                    max_length = len(result['username'])
                    break
            
            length_analysis = {
                'test_results': length_results,
                'min_length': min_length if min_length else "No minimum detected",
                'max_length': max_length if max_length else "No maximum detected"
            }
            
            if min_length and min_length <= 3:
                length_analysis['security_recommendation'] = f"Minimum length ({min_length}) is too short. Recommend at least 4 characters."
            else:
                length_analysis['security_recommendation'] = "Length policy appears adequate."
                
            return length_analysis
        
        return {
            'test_results': [],
            'error': "Could not determine length policy due to failed tests."
        }
    
    def test_character_set_policy(self):
        """Test which characters are allowed in usernames"""
        self.logger.info("Testing username character set policy")
        
        charset_results = []
        
        for test_username in self.test_usernames['character_set']:
            self.logger.info(f"Testing character set: {test_username['description']}")
            result = self.attempt_registration(test_username)
            if result:
                charset_results.append(result)
        
        # Analyze which characters are allowed
        allowed_patterns = []
        rejected_patterns = []
        
        for result in charset_results:
            if result['accepted']:
                allowed_patterns.append(result['description'])
            else:
                rejected_patterns.append(result['description'])
        
        charset_analysis = {
            'test_results': charset_results,
            'allowed_patterns': allowed_patterns,
            'rejected_patterns': rejected_patterns
        }
        
        # Security analysis
        security_notes = []
        
        # Check for potential issues
        if 'With SQL injection characters' in allowed_patterns:
            security_notes.append("WARNING: Username accepts SQL injection characters, which may indicate insufficient input validation")
        
        if 'With space' in allowed_patterns:
            security_notes.append("Username accepts spaces, which may cause confusion or enable spoofing")
        
        if 'With non-Latin characters' in allowed_patterns:
            security_notes.append("Username accepts non-Latin characters, which may enable homograph attacks")
        
        charset_analysis['security_notes'] = security_notes
        
        return charset_analysis
    
    def test_case_sensitivity(self):
        """Test if usernames are case-sensitive"""
        self.logger.info("Testing username case sensitivity")
        
        case_results = []
        
        # First attempt with lowercase
        first_username = self.test_usernames['case_sensitivity'][0]
        lowercase_result = self.attempt_registration(first_username)
        
        if lowercase_result and lowercase_result['accepted']:
            case_results.append(lowercase_result)
            
            # Now try uppercase version of the same username
            uppercase_username = {'value': first_username['value'].upper(), 'description': 'Same username in uppercase'}
            uppercase_result = self.attempt_registration(uppercase_username)
            
            if uppercase_result:
                case_results.append(uppercase_result)
                
                case_sensitive = uppercase_result['accepted']
                
                case_analysis = {
                    'test_results': case_results,
                    'case_sensitive': case_sensitive,
                    'security_recommendation': "Case-sensitive usernames provide better security" if case_sensitive else "Case-insensitive usernames may lead to user confusion or impersonation"
                }
                
                return case_analysis
        
        return {
            'test_results': case_results,
            'error': "Could not determine case sensitivity policy due to failed tests."
        }
    
    def test_reserved_usernames(self):
        """Test if reserved or sensitive usernames are blocked"""
        self.logger.info("Testing reserved username policy")
        
        reserved_results = []
        
        for test_username in self.test_usernames['reserved_words']:
            self.logger.info(f"Testing reserved username: {test_username['description']}")
            result = self.attempt_registration(test_username)
            if result:
                reserved_results.append(result)
        
        # Count how many reserved words are blocked
        blocked_count = sum(1 for result in reserved_results if not result['accepted'])
        
        reserved_analysis = {
            'test_results': reserved_results,
            'blocked_count': blocked_count,
            'total_tested': len(reserved_results),
            'security_recommendation': ""
        }
        
        # Add security recommendations
        if blocked_count == 0:
            reserved_analysis['security_recommendation'] = "CRITICAL: No reserved usernames are blocked, allowing potential impersonation of system accounts"
        elif blocked_count < len(reserved_results):
            reserved_analysis['security_recommendation'] = f"WARNING: Only {blocked_count}/{len(reserved_results)} reserved usernames are blocked"
        else:
            reserved_analysis['security_recommendation'] = "Reserved username policy appears adequate"
        
        return reserved_analysis
    
    def test_username_enumeration(self):
        """Test if the system allows username enumeration during registration"""
        self.logger.info("Testing for username enumeration")
        
        # First, register a username
        initial_username = {'value': f"enumtest_{random.randint(10000, 99999)}", 'description': 'Initial unique username'}
        initial_result = self.attempt_registration(initial_username)
        
        if not initial_result or not initial_result['accepted']:
            return {
                'test_results': [initial_result] if initial_result else [],
                'error': "Initial username registration failed, cannot test for enumeration"
            }
        
        # Now try to register the same username again
        same_username = {'value': initial_username['value'], 'description': 'Same username (should be rejected)'}
        same_result = self.attempt_registration(same_username)
        
        # Also register a completely different username
        diff_username = {'value': f"diffuser_{random.randint(10000, 99999)}", 'description': 'Different username'}
        diff_result = self.attempt_registration(diff_username)
        
        enumeration_results = [initial_result, same_result]
        if diff_result:
            enumeration_results.append(diff_result)
        
        # Analyze the results for username enumeration vulnerability
        if not same_result:
            return {
                'test_results': enumeration_results,
                'error': "Could not test duplicate username registration"
            }
        
        # Check for different response characteristics that could indicate enumeration
        enumeration_possible = False
        enumeration_indicators = []
        
        # Check status code difference
        if same_result['status_code'] != diff_result['status_code']:
            enumeration_possible = True
            enumeration_indicators.append(f"Different status codes: {same_result['status_code']} vs {diff_result['status_code']}")
        
        # Check response length difference (more than 10% difference might indicate enumeration)
        if diff_result:
            length_diff_percent = abs(same_result['response_length'] - diff_result['response_length']) / max(same_result['response_length'], diff_result['response_length']) * 100
            if length_diff_percent > 10:
                enumeration_possible = True
                enumeration_indicators.append(f"Response length differs by {length_diff_percent:.2f}%")
        
        # Check if error message contains the username
        if same_result['error_message'] and initial_username['value'] in same_result['error_message']:
            enumeration_possible = True
            enumeration_indicators.append("Error message contains the exact username")
        
        enumeration_analysis = {
            'test_results': enumeration_results,
            'enumeration_possible': enumeration_possible,
            'enumeration_indicators': enumeration_indicators
        }
        
        if enumeration_possible:
            enumeration_analysis['security_recommendation'] = "Username enumeration may be possible during registration, which could help attackers identify valid usernames"
        else:
            enumeration_analysis['security_recommendation'] = "No obvious username enumeration indicators detected"
        
        return enumeration_analysis
    
    def test_predictable_username_policy(self):
        """Test if the system enforces policies to prevent predictable usernames"""
        self.logger.info("Testing for predictable username policy")
        
        # Test usernames that might be considered predictable
        predictable_usernames = [
            {'value': 'user123', 'description': 'Common pattern with numbers'},
            {'value': 'john1990', 'description': 'Name with birth year'},
            {'value': 'mike.smith', 'description': 'First.last format'},
            {'value': 'john.doe', 'description': 'Common name'},
            {'value': 'test', 'description': 'Generic test account'}
        ]
        
        predictable_results = []
        
        for test_username in predictable_usernames:
            self.logger.info(f"Testing predictable username: {test_username['description']}")
            result = self.attempt_registration(test_username)
            if result:
                predictable_results.append(result)
        
        # Count how many predictable usernames are accepted
        accepted_count = sum(1 for result in predictable_results if result['accepted'])
        
        predictable_analysis = {
            'test_results': predictable_results,
            'accepted_count': accepted_count,
            'total_tested': len(predictable_results)
        }
        
        # Add security recommendations
        if accepted_count == len(predictable_results):
            predictable_analysis['security_recommendation'] = "System allows all tested predictable username patterns, which might make usernames easier to guess"
        elif accepted_count > 0:
            predictable_analysis['security_recommendation'] = f"System allows {accepted_count}/{len(predictable_results)} predictable username patterns"
        else:
            predictable_analysis['security_recommendation'] = "System rejects common predictable username patterns, which is good for security"
        
        return predictable_analysis
    
    def run_tests(self):
        """Run all username policy tests"""
        self.logger.info(f"Starting username policy testing for {self.registration_url}")
        
        # Test length policy
        length_analysis = self.test_username_length_policy()
        self.results.append({
            'test_type': 'length_policy',
            'data': length_analysis
        })
        
        # Test character set policy
        charset_analysis = self.test_character_set_policy()
        self.results.append({
            'test_type': 'character_set_policy',
            'data': charset_analysis
        })
        
        # Test case sensitivity
        case_analysis = self.test_case_sensitivity()
        self.results.append({
            'test_type': 'case_sensitivity',
            'data': case_analysis
        })
        
        # Test reserved usernames
        reserved_analysis = self.test_reserved_usernames()
        self.results.append({
            'test_type': 'reserved_usernames',
            'data': reserved_analysis
        })
        
        # Test username enumeration
        enumeration_analysis = self.test_username_enumeration()
        self.results.append({
            'test_type': 'username_enumeration',
            'data': enumeration_analysis
        })
        
        # Test predictable username policy
        predictable_analysis = self.test_predictable_username_policy()
        self.results.append({
            'test_type': 'predictable_usernames',
            'data': predictable_analysis
        })
        
        self.save_results()
    
    def save_results(self):
        """Save the test results to CSV file"""
        try:
            with open(self.output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["OWASP Username Policy Testing Results"])
                writer.writerow(["Target URL", self.registration_url])
                writer.writerow(["Test Date", time.strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow([])
                
                # Length policy results
                length_data = next((r['data'] for r in self.results if r['test_type'] == 'length_policy'), {})
                writer.writerow(["Username Length Policy"])
                if 'error' in length_data:
                    writer.writerow(["Error", length_data['error']])
                else:
                    writer.writerow(["Minimum Length", length_data.get('min_length', 'Unknown')])
                    writer.writerow(["Maximum Length", length_data.get('max_length', 'Unknown')])
                    writer.writerow(["Security Recommendation", length_data.get('security_recommendation', '')])
                    writer.writerow([])
                    writer.writerow(["Length Test Results"])
                    writer.writerow(["Username", "Description", "Accepted", "Error Message"])
                    for result in length_data.get('test_results', []):
                        writer.writerow([
                            result['username'],
                            result['description'],
                            result['accepted'],
                            result.get('error_message', '')
                        ])
                writer.writerow([])
                
                # Character set policy results
                charset_data = next((r['data'] for r in self.results if r['test_type'] == 'character_set_policy'), {})
                writer.writerow(["Username Character Set Policy"])
                writer.writerow(["Allowed Patterns", ", ".join(charset_data.get('allowed_patterns', []))])
                writer.writerow(["Rejected Patterns", ", ".join(charset_data.get('rejected_patterns', []))])
                if charset_data.get('security_notes'):
                    writer.writerow(["Security Notes"])
                    for note in charset_data.get('security_notes', []):
                        writer.writerow(["", note])
                writer.writerow([])
                writer.writerow(["Character Set Test Results"])
                writer.writerow(["Username", "Description", "Accepted", "Error Message"])
                for result in charset_data.get('test_results', []):
                    writer.writerow([
                        result['username'],
                        result['description'],
                        result['accepted'],
                        result.get('error_message', '')
                    ])
                writer.writerow([])
                
                # Case sensitivity results
                case_data = next((r['data'] for r in self.results if r['test_type'] == 'case_sensitivity'), {})
                writer.writerow(["Username Case Sensitivity"])
                if 'error' in case_data:
                    writer.writerow(["Error", case_data['error']])
                else:
                    writer.writerow(["Case Sensitive", case_data.get('case_sensitive', 'Unknown')])
                    writer.writerow(["Security Recommendation", case_data.get('security_recommendation', '')])
                writer.writerow([])
                
                # Reserved usernames results
                reserved_data = next((r['data'] for r in self.results if r['test_type'] == 'reserved_usernames'), {})
                writer.writerow(["Reserved Usernames Policy"])
                writer.writerow(["Blocked Count", f"{reserved_data.get('blocked_count', 0)}/{reserved_data.get('total_tested', 0)}"])
                writer.writerow(["Security Recommendation", reserved_data.get('security_recommendation', '')])
                writer.writerow([])
                writer.writerow(["Reserved Usernames Test Results"])
                writer.writerow(["Username", "Description", "Blocked", "Error Message"])
                for result in reserved_data.get('test_results', []):
                    writer.writerow([
                        result['username'],
                        result['description'],
                        not result['accepted'],
                        result.get('error_message', '')
                    ])
                writer.writerow([])
                
                # Username enumeration results
                enum_data = next((r['data'] for r in self.results if r['test_type'] == 'username_enumeration'), {})
                writer.writerow(["Username Enumeration During Registration"])
                if 'error' in enum_data:
                    writer.writerow(["Error", enum_data['error']])
                else:
                    writer.writerow(["Enumeration Possible", enum_data.get('enumeration_possible', 'Unknown')])
                    if enum_data.get('enumeration_indicators'):
                        writer.writerow(["Enumeration Indicators"])
                        for indicator in enum_data.get('enumeration_indicators', []):
                            writer.writerow(["", indicator])
                    writer.writerow(["Security Recommendation", enum_data.get('security_recommendation', '')])
                writer.writerow([])
                
                # Predictable username policy results
                predictable_data = next((r['data'] for r in self.results if r['test_type'] == 'predictable_usernames'), {})
                writer.writerow(["Predictable Username Policy"])
                writer.writerow(["Accepted Count", f"{predictable_data.get('accepted_count', 0)}/{predictable_data.get('total_tested', 0)}"])
                writer.writerow(["Security Recommendation", predictable_data.get('security_recommendation', '')])
                writer.writerow([])
                writer.writerow(["Predictable Usernames Test Results"])
                writer.writerow(["Username", "Description", "Accepted", "Error Message"])
                for result in predictable_data.get('test_results', []):
                    writer.writerow([
                        result['username'],
                        result['description'],
                        result['accepted'],
                        result.get('error_message', '')
                    ])
            
            self.logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='OWASP Identity Management - Username Policy Testing')
    parser.add_argument('-u', '--url', required=True, help='Target registration URL')
    parser.add_argument('-o', '--output', default='username_policy_results.csv', help='Output file for results')
    parser.add_argument('-p', '--proxy', help='Proxy to use for requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay between requests (seconds)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (more verbose output)')
    
    args = parser.parse_args()
    
    tester = UsernamePolicyTester(
        registration_url=args.url,
        output_file=args.output,
        proxy=args.proxy,
        delay=args.delay,
        debug=args.debug
    )
    
    tester.run_tests()

if __name__ == "__main__":
    main()
