# OWASP Business Logic Testing Tool
# Usage Guide

## Overview

The OWASP Business Logic Testing Tool is an automated security testing framework designed to identify business logic vulnerabilities in web applications. The tool implements testing techniques from the OWASP Testing Guide v4.2, focusing specifically on the Business Logic Testing (OTG-BUSLOGIC) category.

## Installation

### Prerequisites

- Python 3.7 or higher
- Required Python packages:
  - requests
  - beautifulsoup4
  - termcolor

### Installation Steps

1. Clone the repository or download the source code:
```
git clone https://github.com/example/owasp-buslogic-tester.git
cd owasp-buslogic-tester
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Basic Usage

### Command Line Interface

The tool can be run from the command line with the following syntax:

```
python buslogic_tester.py <target_url> [options]
```

#### Required Arguments

- `target_url`: The base URL of the application to test

#### Optional Arguments

- `-c, --config`: Path to a configuration file (JSON format)
- `-o, --output`: Path to save the output report
- `-f, --format`: Report format (html, json, or csv)
- `-v, --verbose`: Enable verbose output logging

### Examples

Basic scan with default settings:
```
python buslogic_tester.py https://example.com
```

Scan with custom configuration:
```
python buslogic_tester.py https://example.com -c config.json
```

Generate a detailed report in CSV format:
```
python buslogic_tester.py https://example.com -f csv -o report.csv
```

## Using as a Library

The tool can also be imported and used as a Python library:

```python
from buslogic_tester import OWASPBusinessLogicTester

# Initialize the tester
tester = OWASPBusinessLogicTester("https://example.com", "config.json")

# Run discovery phase
discovery_results = tester.run_discovery()

# Run all tests
test_results = tester.run_all_tests()

# Generate a report
tester.generate_report("html", "report.html")
```

## Configuration

The tool can be configured using a JSON configuration file. Here's an explanation of the configuration options:

### Core Settings

- `scan_depth`: How deep to crawl the application (default: 3)
- `concurrent_requests`: Number of concurrent requests to make (default: 10)
- `request_delay`: Delay between requests in seconds (default: 0.1)
- `timeout`: Request timeout in seconds (default: 30)
- `user_agent`: User-Agent header to use (default: "OWASP-BusLogicTester/1.0")
- `follow_redirects`: Whether to follow HTTP redirects (default: true)

### Test Modules

Enable or disable specific test modules:

```json
"test_modules": {
    "OTG-BUSLOGIC-001": true,
    "OTG-BUSLOGIC-002": true,
    "OTG-BUSLOGIC-003": true,
    "OTG-BUSLOGIC-004": true,
    "OTG-BUSLOGIC-005": true,
    "OTG-BUSLOGIC-006": true,
    "OTG-BUSLOGIC-007": true,
    "OTG-BUSLOGIC-008": true,
    "OTG-BUSLOGIC-009": true
}
```

### Path Exclusions

Specify paths to exclude from testing:

```json
"exclude_paths": [
    "/logout",
    "/admin",
    "/static"
]
```

### Authentication

Configure authentication for authenticated testing:

```json
"auth": {
    "type": "form",  // can be "form", "basic", or "token"
    "login_url": "https://example.com/login",
    "username_field": "username",
    "password_field": "password",
    "username": "test_user",
    "password": "test_password",
    "additional_fields": {
        "csrf_token": "TOKEN_VALUE"
    }
}
```

### Workflow Definitions

Define application workflows for specific testing:

```json
"workflow_definitions": [
    {
        "name": "user_registration",
        "steps": [
            {
                "url": "https://example.com/register",
                "method": "GET"
            },
            {
                "url": "https://example.com/register/submit",
                "method": "POST"
            }
        ],
        "critical": true
    }
]
```

## Test Modules

The tool includes nine test modules based on OWASP Testing Guide v4.2:

1. **OTG-BUSLOGIC-001: Business Logic Data Validation**
   - Tests how the application validates data that influences business decisions
   - Identifies situations where validation could be bypassed

2. **OTG-BUSLOGIC-002: Request Forgery Testing**
   - Tests for CSRF vulnerabilities and parameter manipulation
   - Identifies endpoints that might allow request forgery

3. **OTG-BUSLOGIC-003: Integrity Checks**
   - Tests data integrity throughout business processes
   - Identifies issues with numerical field validation and data consistency

4. **OTG-BUSLOGIC-004: Process Timing**
   - Tests for race conditions and timing-based vulnerabilities
   - Identifies issues with process step ordering

5. **OTG-BUSLOGIC-005: Function Usage Limits**
   - Tests restrictions on how many times a function can be used
   - Identifies missing rate limiting or account lockout

6. **OTG-BUSLOGIC-006: Workflow Circumvention**
   - Tests if critical business workflows can be bypassed
   - Identifies issues with workflow step enforcement

7. **OTG-BUSLOGIC-007: Application Misuse Testing**
   - Tests defenses against intentional misuse of features
   - Identifies resource abuse vulnerabilities

8. **OTG-BUSLOGIC-008: Unexpected File Type Upload**
   - Tests handling of unexpected file types in upload functionality
   - Identifies file upload filters that can be bypassed

9. **OTG-BUSLOGIC-009: Malicious File Upload**
   - Tests for the ability to upload malicious files
   - Identifies insufficient content validation in file uploads

## Interpreting Results

The tool generates reports in HTML, JSON, or CSV format. These reports include:

1. **Summary Information**
   - Target application URL
   - Test start and end time
   - Number of vulnerabilities found by severity
   - List of test modules executed

2. **Vulnerability Details**
   - Unique vulnerability ID
   - Test module ID
   - Vulnerability name and description
   - Severity rating (Critical, High, Medium, Low, Info)
   - Affected endpoint or workflow
   - Evidence of the vulnerability
   - Recommended mitigation

For HTML reports, the tool also includes charts showing vulnerability distribution by severity and test module.

## Security Considerations

When using this tool, consider the following security aspects:

1. **Get proper authorization before testing**
   - Always obtain explicit permission before testing any application
   - Testing without permission could be illegal in many jurisdictions

2. **Use test environments when possible**
   - Prefer to test in development or staging environments
   - Testing in production could affect real users or business operations

3. **Handle credentials securely**
   - Test account credentials should not be stored in plain text
   - Consider using environment variables instead of configuration files

4. **Review test scope and intensity**
   - Adjust request rates to avoid denial of service conditions
   - Be cautious with file upload tests to avoid damaging the application

## Limitations

The tool has some limitations to be aware of:

1. **False positives and negatives**
   - Automated testing cannot replace manual verification
   - Review all findings manually before reporting

2. **Application-specific logic**
   - The tool cannot understand custom business logic without configuration
   - Define workflow steps manually for best results

3. **Dynamic content and JavaScript**
   - Limited support for JavaScript-heavy applications
   - May not discover all endpoints in single-page applications

## Troubleshooting

Common issues and solutions:

1. **Connection errors**
   - Check network connectivity and firewall settings
   - Verify the target URL is accessible

2. **Authentication failures**
   - Verify login credentials in configuration
   - Check if additional authentication steps are required

3. **Missing vulnerabilities**
   - Increase scan depth to discover more endpoints
   - Define critical workflows manually for thorough testing

4. **Slow performance**
   - Reduce concurrent requests
   - Increase request delay to avoid overloading the server

## Contributing

Contributions to improve the tool are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add or update tests as necessary
5. Submit a pull request

## License

This tool is released under the MIT License.

## Contact and Support

For questions, suggestions, or support, please open an issue on the GitHub repository or contact the maintainers at example@example.com.
