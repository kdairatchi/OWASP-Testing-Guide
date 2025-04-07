#!/usr/bin/env python3
"""
OWASP Test Scenarios Configuration
---------------------------------
Configure and run predefined test scenarios for common security assessments
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List

# Define test scenarios
SCENARIOS = {
    "quick": {
        "description": "Quick scan of critical security issues",
        "modules": [
            "http_security",
            "admin_interfaces",
            "platform_configuration"
        ],
        "scan_depth": "quick",
        "timeout": 900  # 15 minutes
    },
    "standard": {
        "description": "Standard security assessment",
        "modules": [
            "network_infrastructure",
            "platform_configuration",
            "file_extensions",
            "backups",
            "admin_interfaces",
            "http_methods",
            "http_security"
        ],
        "scan_depth": "normal",
        "timeout": 3600  # 1 hour
    },
    "comprehensive": {
        "description": "Comprehensive security assessment",
        "modules": "all",
        "scan_depth": "thorough",
        "timeout": 7200  # 2 hours
    },
    "cloud-focused": {
        "description": "Focus on cloud security issues",
        "modules": [
            "cloud_storage",
            "platform_configuration",
            "http_security"
        ],
        "scan_depth": "normal",
        "timeout": 1800  # 30 minutes
    },
    "subdomain-scan": {
        "description": "Subdomain enumeration and takeover testing",
        "modules": [
            "subdomain_takeover"
        ],
        "scan_depth": "thorough",
        "timeout": 3600  # 1 hour
    },
    "web-only": {
        "description": "Web application security only",
        "modules": [
            "platform_configuration",
            "file_extensions",
            "backups",
            "admin_interfaces",
            "http_methods",
            "http_security",
            "cross_domain"
        ],
        "scan_depth": "normal",
        "timeout": 2700  # 45 minutes
    }
}


def main():
    """Main entry point for scenario runner"""
    parser = argparse.ArgumentParser(description="OWASP Test Scenarios Runner")
    parser.add_argument("target", help="Target URL or IP address")
    parser.add_argument("--scenario", "-s", choices=SCENARIOS.keys(), default="standard",
                        help="Predefined test scenario to run")
    parser.add_argument("--output-dir", "-o", default="owasp_results", help="Output directory for results")
    parser.add_argument("--docker", "-d", action="store_true", help="Run using Docker container")
    args = parser.parse_args()
    
    # Get selected scenario
    scenario = SCENARIOS[args.scenario]
    print(f"Running scenario: {args.scenario} - {scenario['description']}")
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate temporary config file
    config = {
        "scan_timeout": scenario["timeout"],
        "scan_depth": scenario["scan_depth"],
        "exclude_tests": []
    }
    
    config_path = os.path.join(args.output_dir, "temp_config.json")
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Build command
    if args.docker:
        cmd = [
            "docker-compose",
            "exec",
            "owasp-framework",
            "python",
            "owasp_testing_framework.py",
            args.target,
            "--output-dir", "/app/" + args.output_dir,
            "--config", "/app/" + config_path
        ]
    else:
        cmd = [
            "python",
            "owasp_testing_framework.py",
            args.target,
            "--output-dir", args.output_dir,
            "--config", config_path
        ]
    
    # Add modules if specific ones are defined
    if scenario["modules"] != "all":
        cmd.extend(["--module", ",".join(scenario["modules"])])
    
    # Run the command
    print(f"Running command: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        print(f"Scenario {args.scenario} completed successfully")
        print(f"Results saved to {args.output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error running scenario: {e}")
        sys.exit(1)
    finally:
        # Clean up temporary config
        if os.path.exists(config_path):
            os.remove(config_path)


if __name__ == "__main__":
    main()
