#!/bin/bash
# OWASP Automated Testing Framework Installation Script
# This script installs dependencies and sets up the environment

set -e  # Exit on error

# ASCII Art Banner
echo "
 ___ _    _  _   ___ ___   ___ ___ ___ _____ ___ _  _  ___ 
/ __| |  | || | / __| _ \ |_ _|_ _| __|_   _|_ _| \| |/ __|
\__ \ |__| __ || \__ \  _/ | | | || _|  | |  | || .` | (_ |
|___/____|_||_|___/___/  |___|___|___| |_| |___|_|\_|\___|
                                                          
 ___ ___    _   __  __ _____      _____  ___ _  __
| __| _ \  /_\ |  \/  | __\ \    / / _ \| _ \ |/ /
| _||   / / _ \| |\/| | _| \ \/\/ / (_) |   / ' < 
|_| |_|_\/_/ \_\_|  |_|___| \_/\_/ \___/|_|_\_|\_\\

"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Could not detect operating system"
    exit 1
fi

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "=== Installing OWASP Automated Testing Framework ==="
echo "Operating System: $OS"

install_requirements() {
    echo "Installing Python requirements..."
    pip3 install -r requirements.txt
}

install_tools_debian() {
    echo "Installing tools for Debian/Ubuntu..."
    apt-get update
    apt-get install -y \
        nmap \
        nikto \
        dirb \
        curl \
        wget \
        git \
        python3-pip \
        jq \
        unzip \
        gcc \
        libffi-dev \
        libssl-dev \
        python3-dev

    # Install Gobuster
    go get github.com/OJ/gobuster

    # Install SSLyze
    pip3 install sslyze

    # Install TestSSL
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
    chmod +x /opt/testssl/testssl.sh

    # Install ZAP
    curl -s https://raw.githubusercontent.com/zaproxy/zap-admin/master/scripts/install-linux.sh | bash
}

install_cloud_cli() {
    echo "Installing cloud provider CLIs..."
    
    # AWS CLI
    pip3 install awscli
    
    # Azure CLI
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash
    
    # Google Cloud SDK
    export CLOUD_SDK_REPO="cloud-sdk-$OS-$VERSION_CODENAME"
    echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
    apt-get update && apt-get install -y google-cloud-sdk
}

install_docker() {
    echo "Installing Docker and Docker Compose..."
    
    # Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    
    # Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
}

setup_docker_environment() {
    echo "Setting up Docker environment..."
    docker-compose build
}

create_wordlists_dir() {
    echo "Creating wordlists directory..."
    mkdir -p wordlists
    
    # Download common wordlists
    if [ ! -f wordlists/common.txt ]; then
        echo "Downloading common wordlists..."
        curl -o wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
    fi
    
    if [ ! -f wordlists/admin-directories.txt ]; then
        curl -o wordlists/admin-directories.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
    fi
}

# Main installation flow
echo "Starting installation..."

# Install dependencies based on OS
case $OS in
    debian|ubuntu)
        install_tools_debian
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Installing only Python requirements."
        ;;
esac

# Install Python requirements
install_requirements

# Install cloud CLIs if requested
read -p "Do you want to install cloud provider CLIs? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    install_cloud_cli
fi

# Install Docker if requested
read -p "Do you want to install Docker and Docker Compose? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    install_docker
    setup_docker_environment
fi

# Create wordlists directory
create_wordlists_dir

echo "=== Installation Complete ==="
echo "
To run a scan:
  - Using Python directly:
    python3 owasp_testing_framework.py https://example.com --output-dir results
    
  - Using Docker:
    docker-compose up -d
    docker-compose exec owasp-framework python owasp_testing_framework.py https://example.com --output-dir /app/results
    
  - Using test scenarios:
    python3 test_scenarios.py https://example.com --scenario standard
"
