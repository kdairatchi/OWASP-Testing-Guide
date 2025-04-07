# Configuration Testing  

## Overview  
Configuration testing focuses on analyzing the security of application infrastructure, frameworks, and dependencies. This phase evaluates security controls, server configurations, and platform settings that could lead to vulnerabilities.  

## Objectives  
- Identify misconfigurations in web servers and platforms  
- Assess security header implementations  
- Review file handling configurations  
- Evaluate platform and framework security settings  
- Check deployment configuration security  

## Key Testing Areas  

### 1. Network Configuration  
- [ ] Port Scanning  
- [ ] Network Service Identification  
- [ ] SSL/TLS Configuration  
- [ ] DNS Configuration  
- [ ] Load Balancer Configuration  

### 2. Platform Configuration  
- [ ] Web Server Settings  
  - Apache  
  - Nginx  
  - IIS  
- [ ] Application Server Configuration  
- [ ] Database Server Settings  
- [ ] Container Configuration  

### 3. Security Headers  
- [ ] HTTP Security Headers  
  - Content-Security-Policy  
  - X-Frame-Options  
  - X-Content-Type-Options  
  - Strict-Transport-Security  
  - X-XSS-Protection  
- [ ] Cookie Security Attributes  
- [ ] CORS Configuration  

### 4. File Handling  
- [ ] File Permission Analysis  
- [ ] Backup File Detection  
- [ ] Directory Indexing  
- [ ] File Extension Handling  
- [ ] Upload Directory Security  

### 5. Infrastructure Security  
- [ ] Cloud Service Configuration  
- [ ] Container Security Settings  
- [ ] Kubernetes Configuration  
- [ ] Serverless Function Configuration  

## Common Tools  
- Configuration Analysis:  
  - Nmap  
  - Nikto  
  - SSL Labs Server Test  
  - SecurityHeaders.com  
- Infrastructure Testing:  
  - AWS Security Scanner  
  - Azure Security Center  
  - kubectl-audit  
  - Docker Bench Security  

## Additional Resources  
- 📁 [Testing Techniques](./techniques/)  
- 📁 [Configuration Templates](./resources/)  
- 🔗 [OWASP Configuration Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)  

## Common Misconfigurations  
1. Default Credentials  
2. Unnecessary Open Ports  
3. Weak SSL/TLS Settings  
4. Missing Security Headers  
5. Excessive Directory Permissions  
6. Exposed Version Information  
7. Debug Mode Enabled  
8. Insecure Cloud Storage Settings  

## Testing Methodology  
1. Identify Infrastructure Components  
2. Analyze Default Settings  
3. Review Security Controls  
4. Check for Known Vulnerabilities  
5. Validate Security Headers  
6. Test File Handling  
7. Assess Cloud Configuration  

## Progress Tracking  
- [ ] Network Configuration Review  
- [ ] Platform Configuration Testing  
- [ ] Security Headers Analysis  
- [ ] File Handling Assessment  
- [ ] Infrastructure Security Review  

## Notes  
- Document all configuration findings  
- Include version numbers and specific settings  
- Note deviations from security best practices  
- Maintain evidence of testing  
- Consider compliance requirements


# OWASP Automated Testing Framework

A comprehensive automated testing framework for OWASP security testing that integrates multiple security tools.

## Features

- Automated testing for all OWASP testing categories:
  - Network Infrastructure Configuration
  - Application Platform Configuration
  - File Extensions Handling
  - Backup and Unreferenced Files
  - Admin Interfaces
  - HTTP Methods
  - HTTP Security Headers
  - Cross Domain Policy
  - File Permissions
  - Subdomain Takeover
  - Cloud Storage Security

- Integration with industry-standard security tools:
  - Nmap
  - Nikto
  - SSLyze
  - TestSSL
  - Gobuster
  - OWASP ZAP
  - AWS/Azure/GCloud CLI
  - CloudSploit
  - Scout Suite
  - And more...

- Comprehensive reporting:
  - JSON output
  - HTML reports with severity-based findings
  - Detailed evidence for each finding

## Prerequisites

- Docker and Docker Compose
- Python 3.8+
- For cloud security testing:
  - AWS credentials (if testing AWS resources)
  - Azure credentials (if testing Azure resources)
  - GCloud credentials (if testing Google Cloud resources)

## Quick Start

### Using Docker Compose

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/owasp-testing-framework.git
   cd owasp-testing-framework
   ```

2. Build and run the Docker containers:
   ```
   docker-compose build
   docker-compose up -d
   ```

3. Run a scan against a target:
   ```
   docker-compose exec owasp-framework python owasp_testing_framework.py https://example.com --output-dir /app/results
   ```

4. View the HTML report:
   ```
   firefox results/report.html
   ```

### Using Python Directly

1. Install the requirements:
   ```
   pip install -r requirements.txt
   ```

2. Install the required tools:
   ```
   # Debian/Ubuntu
   sudo apt-get install nmap nikto gobuster dirb testssl.sh
   
   # AWS CLI
   pip install awscli
   
   # Azure CLI
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   
   # Google Cloud SDK
   curl https://sdk.cloud.google.com | bash
   ```

3. Run a scan:
   ```
   python owasp_testing_framework.py https://example.com --output-dir results
   ```

## Configuration

You can customize the scanning behavior using a configuration file:

```json
{
  "scan_timeout": 3600,
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
    "gcloud": "gcloud"
  },
  "scan_depth": "normal",
  "exclude_tests": []
}
```

Run with a custom configuration:
```
python owasp_testing_framework.py https://example.com --config my_config.json
```

## Running Individual Tests

You can run specific test modules instead of the full suite:

```
python owasp_testing_framework.py https://example.com --module network_infrastructure,http_methods,http_security
```

Available modules:
- `network_infrastructure`: Test Network Infrastructure Configuration
- `platform_configuration`: Test Application Platform Configuration
- `file_extensions`: Test File Extensions Handling
- `backups`: Review Old Backup and Unreferenced Files
- `admin_interfaces`: Enumerate Admin Interfaces
- `http_methods`: Test HTTP Methods
- `http_security`: Test HTTP Security Headers
- `cross_domain`: Test RIA Cross Domain Policy
- `file_permissions`: Test File Permissions
- `subdomain_takeover`: Test for Subdomain Takeover
- `cloud_storage`: Test Cloud Storage

## Understanding Results

The framework generates:

1. **JSON Results File**: Contains all raw findings and details
2. **HTML Report**: Interactive report with findings organized by severity and module
3. **Tool-specific output files**: Raw output from individual tools

Findings are categorized by severity:
- **Critical**: Issues that require immediate attention
- **High**: Serious security concerns
- **Medium**: Important issues but lower risk
- **Low**: Minor security concerns
- **Info**: Informational findings

## Extending the Framework

### Adding New Test Modules

Create a new Python class that inherits from `BaseTestModule`:

```python
class MyCustomTestModule(BaseTestModule):
    """Description of the test module"""
    
    def run(self) -> Dict:
        results = {
            "name": "My Custom Test",
            "findings": []
        }
        
        # Implement your test logic here
        
        return results
```

Then add it to the `test_modules` dictionary in the `OWASPTestingFramework` constructor.

### Integration with CI/CD

The framework can be integrated into CI/CD pipelines:

```yaml
# Example GitLab CI configuration
security_scan:
  stage: test
  image: yourusername/owasp-testing-framework
  script:
    - python owasp_testing_framework.py $CI_ENVIRONMENT_URL --output-dir results
  artifacts:
    paths:
      - results/
```

## Best Practices

1. **Start with limited scope**: Use `--module` to run specific tests initially
2. **Watch your resources**: Some tests (like subdomain enumeration) can be resource-intensive
3. **Customize scan depth**: Use the `scan_depth` setting in config to balance speed vs. thoroughness
4. **Verify findings**: Always verify findings manually to eliminate false positives
5. **Regular scanning**: Schedule regular scans to detect new vulnerabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- OWASP Foundation for their testing guidelines
- All the developers of the security tools integrated into this framework
