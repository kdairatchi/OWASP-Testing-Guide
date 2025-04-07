#!/usr/bin/env python3
"""
OWASP Identity Management Testing - User Enumeration Script
Tests for account enumeration vulnerabilities by analyzing application responses
to valid vs. invalid username attempts.
"""

import requests
import argparse
import csv
import time
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from collections import defaultdict

class UserEnumerationTester:
    def __init__(self, target_url, usernames_file, passwords_file=None, 
                 delay=0.5, threads=5, output_file="results.csv", debug=False):
        self.target_url = target_url
        self.usernames_file = usernames_file
        self.passwords_file = passwords_file
        self.delay = delay
        self.threads = threads
        self.output_file = output_file
        self.debug = debug
        self.session = requests.Session()
        self.results = []
        self.response_patterns = defaultdict(int)
        
        # Default request headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
    def load_usernames(self):
        """Load usernames from file"""
        try:
            with open(self.usernames_file, 'r') as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"Error: Usernames file '{self.usernames_file}' not found.")
            sys.exit(1)
            
    def load_passwords(self):
        """Load passwords from file if specified"""
        if not self.passwords_file:
            return ["password123"]  # Default password for testing
        
        try:
            with open(self.passwords_file, 'r') as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"Error: Passwords file '{self.passwords_file}' not found.")
            sys.exit(1)
    
    def analyze_response(self, username, password, response):
        """Analyze response for enumeration indicators"""
        indicators = {
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'response_length': len(response.text),
            'redirect_url': response.url if response.url != self.target_url else None,
        }
        
        # Create a fingerprint of the response
        fingerprint = f"{indicators['status_code']}:{indicators['response_length']}"
        
        # Store response pattern for later analysis
        self.response_patterns[fingerprint] += 1
        
        # Check for common enumeration indicators in response text
        indicators['error_messages'] = self._check_error_messages(response.text)
        
        return {
            'username': username,
            'password': password,
            'indicators': indicators,
            'fingerprint': fingerprint,
            'raw_response': response.text if self.debug else None
        }
    
    def _check_error_messages(self, response_text):
        """Check for common error messages that might indicate valid/invalid users"""
        error_indicators = {
            'invalid_user': [
                "user not found", "user doesn't exist", "no account found",
                "invalid username", "cannot find user", "user unknown"
            ],
            'valid_user_wrong_pass': [
                "invalid password", "incorrect password", "wrong password",
                "password doesn't match", "password incorrect"
            ],
            'account_locked': [
                "account locked", "too many attempts", "account disabled",
                "temporarily blocked", "account suspended"
            ]
        }
        
        found_indicators = {}
        for category, phrases in error_indicators.items():
            for phrase in phrases:
                if phrase.lower() in response_text.lower():
                    if category not in found_indicators:
                        found_indicators[category] = []
                    found_indicators[category].append(phrase)
        
        return found_indicators
    
    def test_login(self, username, password):
        """Test a single username/password combination"""
        data = {
            'username': username,
            'password': password,
            'submit': 'Login'
        }
        
        try:
            time.sleep(self.delay)  # Add delay to avoid being blocked
            response = self.session.post(self.target_url, data=data, headers=self.headers, allow_redirects=True)
            return self.analyze_response(username, password, response)
        except requests.RequestException as e:
            print(f"Error testing {username}: {e}")
            return None
    
    def run_tests(self):
        """Run tests for all usernames"""
        usernames = self.load_usernames()
        passwords = self.load_passwords()
        
        # Add a known invalid username for comparison
        usernames.append("nonexistent_user_12345")
        
        print(f"Testing {len(usernames)} usernames against {len(passwords)} passwords...")
        
        # Use the first password for all usernames to compare responses
        primary_password = passwords[0]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for username in usernames:
                futures.append(executor.submit(self.test_login, username, primary_password))
            
            for future in futures:
                result = future.result()
                if result:
                    self.results.append(result)
        
        self.analyze_results()
        self.save_results()
    
    def analyze_results(self):
        """Analyze results to detect enumeration vulnerabilities"""
        # Sort results by fingerprint to identify patterns
        self.results.sort(key=lambda x: x['fingerprint'])
        
        # Find the fingerprint for the known invalid user
        invalid_user_results = [r for r in self.results if r['username'] == "nonexistent_user_12345"]
        if not invalid_user_results:
            print("Warning: Couldn't find test results for the invalid user")
            return
        
        invalid_fingerprint = invalid_user_results[0]['fingerprint']
        
        # Compare other results with the invalid user response
        for result in self.results:
            if result['username'] == "nonexistent_user_12345":
                result['enumeration_detected'] = False
                result['notes'] = "Invalid user control"
            else:
                # If fingerprint is different from the invalid user, there might be enumeration
                result['enumeration_detected'] = result['fingerprint'] != invalid_fingerprint
                
                if result['enumeration_detected']:
                    result['notes'] = "Potential enumeration: response differs from invalid user"
                else:
                    result['notes'] = "No enumeration detected"
                    
        # Summary of findings
        enum_count = sum(1 for r in self.results if r['enumeration_detected'])
        print(f"\nResults Summary:")
        print(f"Total usernames tested: {len(self.results) - 1}")  # Exclude the invalid user
        print(f"Potential enumeration vulnerabilities: {enum_count}")
        print(f"Response patterns detected: {len(self.response_patterns)}")
        
        # Print top usernames with enumeration detected
        if enum_count > 0:
            print("\nPotential enumerable usernames:")
            for result in self.results:
                if result['enumeration_detected']:
                    print(f"  - {result['username']}")
    
    def save_results(self):
        """Save results to CSV file"""
        try:
            with open(self.output_file, 'w', newline='') as csvfile:
                fieldnames = ['username', 'status_code', 'response_length', 
                             'response_time', 'redirect_url', 'error_messages',
                             'enumeration_detected', 'notes']
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    writer.writerow({
                        'username': result['username'],
                        'status_code': result['indicators']['status_code'],
                        'response_length': result['indicators']['response_length'],
                        'response_time': result['indicators']['response_time'],
                        'redirect_url': result['indicators']['redirect_url'],
                        'error_messages': json.dumps(result['indicators']['error_messages']),
                        'enumeration_detected': result['enumeration_detected'],
                        'notes': result['notes']
                    })
                
            print(f"\nResults saved to {self.output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='OWASP Identity Management - User Enumeration Testing')
    parser.add_argument('-u', '--url', required=True, help='Target login URL')
    parser.add_argument('-U', '--usernames', required=True, help='File containing usernames to test')
    parser.add_argument('-P', '--passwords', help='File containing passwords to test')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('-o', '--output', default='user_enumeration_results.csv', help='Output file for results')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (save full responses)')
    
    args = parser.parse_args()
    
    tester = UserEnumerationTester(
        target_url=args.url,
        usernames_file=args.usernames,
        passwords_file=args.passwords,
        delay=args.delay,
        threads=args.threads,
        output_file=args.output,
        debug=args.debug
    )
    
    tester.run_tests()

if __name__ == "__main__":
    main()
