#!/bin/bash

# Smart Subdomain Monitoring System
# Created: April 6, 2025
# Description: Monitors domains for new subdomains using multiple tools
#              and sends notifications when new ones are discovered

# Required tools:
# - subfinder (https://github.com/projectdiscovery/subfinder)
# - amass (https://github.com/owasp-amass/amass)
# - assetfinder (https://github.com/tomnomnom/assetfinder)
# - findomain (https://github.com/Findomain/Findomain)
# - bbot (https://github.com/blacklanternsecurity/bbot)
# - notify (https://github.com/projectdiscovery/notify)
# - anew (https://github.com/tomnomnom/anew)
# - whatweb (https://github.com/urbanadventurer/whatweb)
# - webanalyze (https://github.com/rverton/webanalyze)
# - httpx (https://github.com/projectdiscovery/httpx)

# ===== CONFIGURATION =====
# Directory structure
WORKSPACE="$HOME/subdomain-monitor"
DOMAINS_FILE="$WORKSPACE/domains.txt"
RESULTS_DIR="$WORKSPACE/results"
LOGS_DIR="$WORKSPACE/logs"
TEMP_DIR="$WORKSPACE/temp"
CONFIG_DIR="$WORKSPACE/config"
TECH_DIR="$WORKSPACE/tech-data"

# Notify configuration
NOTIFY_CONFIG="$CONFIG_DIR/notify-config.yaml"

# Cooldown period between runs (in seconds, default: 1 hour)
COOLDOWN=3600

# Maximum number of parallel processes
MAX_PARALLEL=5

# API keys file
API_KEYS="$CONFIG_DIR/api-keys.txt"

# Technology scanning options
TECH_SCAN=true                  # Set to false to disable technology scanning
TECH_SCAN_TIMEOUT=30            # Timeout for technology scanning in seconds
SCAN_PORTS="80,443,8080,8443"   # Ports to scan during technology fingerprinting
BBOT_MODULES="fast"             # BBOT scan modules to use (options: passive, fast, active, aggressive)

# ===== COLORS FOR OUTPUT =====
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

# ===== FUNCTIONS =====

# Display banner
show_banner() {
    echo -e "${BLUE}"
    echo "  ███████╗██╗   ██╗██████╗ ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ "
    echo "  ██╔════╝██║   ██║██╔══██╗████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗"
    echo "  ███████╗██║   ██║██████╔╝██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝"
    echo "  ╚════██║██║   ██║██╔══██╗██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗"
    echo "  ███████║╚██████╔╝██████╔╝██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║"
    echo "  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${CYAN}Smart Subdomain Monitoring System${NC}"
    echo -e "${YELLOW}Runs every ${COOLDOWN}s and reports new discoveries${NC}"
    echo "=============================================================="
}

# Check if required tools are installed
check_requirements() {
    echo -e "${YELLOW}[*] Checking requirements...${NC}"
    
    local missing_tools=()
    
    for tool in subfinder amass assetfinder findomain bbot notify anew jq whatweb webanalyze httpx; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[*] Please install the missing tools and try again.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] All required tools are installed!${NC}"
}

# Create initial directory structure
setup_workspace() {
    echo -e "${YELLOW}[*] Setting up workspace...${NC}"
    
    # Create directories if they don't exist
    for dir in "$WORKSPACE" "$RESULTS_DIR" "$LOGS_DIR" "$TEMP_DIR" "$CONFIG_DIR" "$TECH_DIR"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            echo -e "${GREEN}[+] Created directory: $dir${NC}"
        fi
    done
    
    # Create domains file if it doesn't exist
    if [ ! -f "$DOMAINS_FILE" ]; then
        touch "$DOMAINS_FILE"
        echo -e "${YELLOW}[*] Created domains file: $DOMAINS_FILE${NC}"
        echo -e "${YELLOW}[*] Please add target domains to this file (one per line)${NC}"
    fi
    
    # Create notify config if it doesn't exist
    if [ ! -f "$NOTIFY_CONFIG" ]; then
        cat > "$NOTIFY_CONFIG" << EOF
# Notify configuration file
telegram:
  - id: "default"
    token: "TELEGRAM_BOT_TOKEN"
    chat_id: "TELEGRAM_CHAT_ID"

slack:
  - id: "default"
    token: "SLACK_TOKEN"
    channel: "SLACK_CHANNEL"

discord:
  - id: "default"
    webhook_url: "DISCORD_WEBHOOK_URL"

# Uncomment and configure the providers you want to use
EOF
        echo -e "${YELLOW}[*] Created notify config: $NOTIFY_CONFIG${NC}"
        echo -e "${YELLOW}[*] Please edit this file to configure your notification providers${NC}"
    fi
    
    # Create API keys file if it doesn't exist
    if [ ! -f "$API_KEYS" ]; then
        cat > "$API_KEYS" << EOF
# API keys for various services
# Format: SERVICE_NAME=api_key

# Subfinder API keys
VIRUSTOTAL=
SECURITYTRAILS=
CENSYS_USERNAME=
CENSYS_SECRET=
BINARYEDGE=
SHODAN=
GITHUB=

# Amass API keys
NETWORKSDB=
WHOISXMLAPI=
PASSIVETOTAL_USERNAME=
PASSIVETOTAL_KEY=
DNSDB=
EOF
        echo -e "${YELLOW}[*] Created API keys file: $API_KEYS${NC}"
        echo -e "${YELLOW}[*] Please edit this file to add your API keys${NC}"
    fi
    
    echo -e "${GREEN}[+] Workspace setup complete!${NC}"
}

# Load API keys for various services
load_api_keys() {
    echo -e "${YELLOW}[*] Loading API keys...${NC}"
    
    if [ -f "$API_KEYS" ]; then
        # Create subfinder config directory if it doesn't exist
        local subfinder_config_dir="$HOME/.config/subfinder"
        if [ ! -d "$subfinder_config_dir" ]; then
            mkdir -p "$subfinder_config_dir"
        fi
        
        # Create or update subfinder provider-config.yaml
        local subfinder_config="$subfinder_config_dir/provider-config.yaml"
        
        # Start with an empty config
        echo "# Subfinder provider configuration" > "$subfinder_config"
        
        # Parse API keys and add them to the config
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
            
            # Skip empty values
            [ -z "$value" ] && continue
            
            case "$key" in
                VIRUSTOTAL)
                    echo "virustotal:" >> "$subfinder_config"
                    echo "  - $value" >> "$subfinder_config"
                    ;;
                SECURITYTRAILS)
                    echo "securitytrails:" >> "$subfinder_config"
                    echo "  - $value" >> "$subfinder_config"
                    ;;
                CENSYS_USERNAME)
                    censys_username="$value"
                    ;;
                CENSYS_SECRET)
                    if [ ! -z "$censys_username" ]; then
                        echo "censys:" >> "$subfinder_config"
                        echo "  - $censys_username:$value" >> "$subfinder_config"
                    fi
                    ;;
                BINARYEDGE)
                    echo "binaryedge:" >> "$subfinder_config"
                    echo "  - $value" >> "$subfinder_config"
                    ;;
                SHODAN)
                    echo "shodan:" >> "$subfinder_config"
                    echo "  - $value" >> "$subfinder_config"
                    ;;
                GITHUB)
                    echo "github:" >> "$subfinder_config"
                    echo "  - $value" >> "$subfinder_config"
                    ;;
            esac
        done < "$API_KEYS"
        
        echo -e "${GREEN}[+] API keys loaded successfully!${NC}"
    else
        echo -e "${YELLOW}[*] API keys file not found: $API_KEYS${NC}"
        echo -e "${YELLOW}[*] Some tools may have limited functionality without API keys.${NC}"
    fi
}

# Run subdomain enumeration tools on a single domain
enumerate_subdomains() {
    local domain="$1"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local output_dir="$RESULTS_DIR/$domain"
    local all_subdomains="$output_dir/all-$timestamp.txt"
    local previous_all="$output_dir/all.txt"
    local new_subdomains="$output_dir/new-$timestamp.txt"
    
    # Create domain output directory if it doesn't exist
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
    fi
    
    echo -e "${BLUE}[*] Starting subdomain enumeration for: ${YELLOW}$domain${NC}"
    
    # Create temp files
    local subfinder_output="$TEMP_DIR/$domain-subfinder-$timestamp.txt"
    local amass_output="$TEMP_DIR/$domain-amass-$timestamp.txt"
    local assetfinder_output="$TEMP_DIR/$domain-assetfinder-$timestamp.txt"
    local findomain_output="$TEMP_DIR/$domain-findomain-$timestamp.txt"
    local bbot_output="$TEMP_DIR/$domain-bbot-$timestamp.txt"
    
    # Run tools in parallel
    echo -e "${CYAN}[*] Running subfinder...${NC}"
    subfinder -d "$domain" -silent | sort -u > "$subfinder_output" &
    pid_subfinder=$!
    
    echo -e "${CYAN}[*] Running amass...${NC}"
    amass enum -passive -d "$domain" -o "$amass_output" &
    pid_amass=$!
    
    echo -e "${CYAN}[*] Running assetfinder...${NC}"
    assetfinder --subs-only "$domain" | sort -u > "$assetfinder_output" &
    pid_assetfinder=$!
    
    echo -e "${CYAN}[*] Running findomain...${NC}"
    findomain --quiet -t "$domain" -u "$findomain_output" &
    pid_findomain=$!
    
    echo -e "${CYAN}[*] Running bbot...${NC}"
    bbot -t "$domain" -f subdomain-enum -m "$BBOT_MODULES" --no-scan-topdomains -o txt:"$bbot_output" &
    pid_bbot=$!
    
    # Wait for all processes to finish
    wait $pid_subfinder
    echo -e "${GREEN}[+] Subfinder finished!${NC}"
    
    wait $pid_amass
    echo -e "${GREEN}[+] Amass finished!${NC}"
    
    wait $pid_assetfinder
    echo -e "${GREEN}[+] Assetfinder finished!${NC}"
    
    wait $pid_findomain
    echo -e "${GREEN}[+] Findomain finished!${NC}"
    
    wait $pid_bbot
    echo -e "${GREEN}[+] BBOT finished!${NC}"
    
    # Combine and sort results
    echo -e "${BLUE}[*] Combining results...${NC}"
    cat "$subfinder_output" "$amass_output" "$assetfinder_output" "$findomain_output" "$bbot_output" | sort -u > "$all_subdomains"
    
    # Count subdomains found by each tool
    local subfinder_count=$(wc -l < "$subfinder_output")
    local amass_count=$(wc -l < "$amass_output")
    local assetfinder_count=$(wc -l < "$assetfinder_output")
    local findomain_count=$(wc -l < "$findomain_output")
    local bbot_count=$(wc -l < "$bbot_output")
    local total_count=$(wc -l < "$all_subdomains")
    
    echo -e "${GREEN}[+] Results combined!${NC}"
    echo -e "${BLUE}[*] Statistics:${NC}"
    echo -e "  ${PURPLE}Subfinder:${NC}    $subfinder_count subdomains"
    echo -e "  ${PURPLE}Amass:${NC}        $amass_count subdomains"
    echo -e "  ${PURPLE}Assetfinder:${NC}  $assetfinder_count subdomains"
    echo -e "  ${PURPLE}Findomain:${NC}    $findomain_count subdomains"
    echo -e "  ${PURPLE}BBOT:${NC}         $bbot_count subdomains"
    echo -e "  ${PURPLE}Total unique:${NC} $total_count subdomains"
    
    # Check for new subdomains
    if [ -f "$previous_all" ]; then
        echo -e "${BLUE}[*] Checking for new subdomains...${NC}"
        cat "$all_subdomains" | anew "$previous_all" > "$new_subdomains"
        
        local new_count=$(wc -l < "$new_subdomains")
        if [ $new_count -gt 0 ]; then
            echo -e "${GREEN}[+] Found $new_count new subdomains!${NC}"
            
            # Update the all.txt file
            cat "$new_subdomains" >> "$previous_all"
            
            # Filter live subdomains
            local new_live_subdomains="$TEMP_DIR/$domain-new-live-$timestamp.txt"
            echo -e "${BLUE}[*] Checking for live subdomains...${NC}"
            cat "$new_subdomains" | httpx -silent -timeout 10 -retries 2 -status-code -title -follow-redirects > "$new_live_subdomains"
            local live_count=$(wc -l < "$new_live_subdomains")
            echo -e "${GREEN}[+] Found $live_count live subdomains!${NC}"
            
            # Perform technology scanning if enabled
            local tech_report=""
            if [ "$TECH_SCAN" = true ] && [ $live_count -gt 0 ]; then
                tech_report=$(scan_technologies "$domain" "$new_live_subdomains" "$timestamp")
            fi
            
            # Send notification
            if [ -f "$NOTIFY_CONFIG" ]; then
                echo -e "${BLUE}[*] Sending notification...${NC}"
                
                # Create notification message
                local notification_file="$TEMP_DIR/$domain-notification-$timestamp.txt"
                {
                    echo "## 🔍 New Subdomains Discovered!"
                    echo "**Domain:** $domain"
                    echo "**Time:** $(date)"
                    echo "**New subdomains found:** $new_count"
                    echo "**Live subdomains:** $live_count"
                    echo ""
                    echo "### New Subdomains:"
                    echo '```'
                    cat "$new_subdomains"
                    echo '```'
                    echo ""
                    echo "### Statistics:"
                    echo "- Subfinder: $subfinder_count"
                    echo "- Amass: $amass_count"
                    echo "- Assetfinder: $assetfinder_count"
                    echo "- Findomain: $findomain_count"
                    echo "- BBOT: $bbot_count"
                    echo "- Total unique: $total_count"
                    
                    # Add technology report if available
                    if [ ! -z "$tech_report" ]; then
                        echo ""
                        echo "$tech_report"
                    fi
                } > "$notification_file"
                
                # Use notify to send the notification
                cat "$notification_file" | notify -bulk -config "$NOTIFY_CONFIG"
                echo -e "${GREEN}[+] Notification sent!${NC}"
            else
                echo -e "${YELLOW}[*] Notify config not found: $NOTIFY_CONFIG${NC}"
                echo -e "${YELLOW}[*] Skipping notification...${NC}"
            fi
        else
            echo -e "${YELLOW}[*] No new subdomains found.${NC}"
        fi
    else
        echo -e "${BLUE}[*] First run for this domain, saving baseline...${NC}"
        cp "$all_subdomains" "$previous_all"
    fi
    
    # Clean up temporary files
    rm -f "$subfinder_output" "$amass_output" "$assetfinder_output" "$findomain_output" "$bbot_output"
    
    echo -e "${GREEN}[+] Enumeration completed for $domain!${NC}"
    echo ""
}

# Scan technologies on subdomains
scan_technologies() {
    local domain="$1"
    local subdomains_file="$2"
    local timestamp="$3"
    local tech_dir="$TECH_DIR/$domain"
    local whatweb_output="$tech_dir/whatweb-$timestamp.json"
    local webanalyze_output="$tech_dir/webanalyze-$timestamp.json"
    local tech_summary="$tech_dir/tech-summary-$timestamp.md"
    
    # Create tech directory if it doesn't exist
    if [ ! -d "$tech_dir" ]; then
        mkdir -p "$tech_dir"
    fi
    
    echo -e "${BLUE}[*] Scanning technologies on new subdomains...${NC}"
    
    # Run whatweb
    echo -e "${CYAN}[*] Running whatweb...${NC}"
    cat "$subdomains_file" | cut -d ' ' -f 1 | whatweb --no-errors --timeout $TECH_SCAN_TIMEOUT --max-threads 10 -a 3 --log-json="$whatweb_output" > /dev/null
    
    # Run webanalyze
    echo -e "${CYAN}[*] Running webanalyze...${NC}"
    cat "$subdomains_file" | cut -d ' ' -f 1 | webanalyze -apps "$HOME/.webanalyze/apps.json" -hosts stdin -output json > "$webanalyze_output"
    
    # Generate summary report
    echo -e "${CYAN}[*] Generating technology report...${NC}"
    {
        echo "### 🔍 Technology Analysis"
        echo ""
        
        # Process whatweb results
        echo "#### WhatWeb Findings:"
        echo ""
        if [ -s "$whatweb_output" ]; then
            # Extract the most common technologies
            echo "Most common technologies detected:"
            echo ""
            jq -r '.[] | .plugins | keys[]' "$whatweb_output" 2>/dev/null | sort | uniq -c | sort -nr | head -10 | while read count tech; do
                echo "- $tech ($count instances)"
            done
            echo ""
            
            # Extract interesting findings (frameworks, CMS, etc.)
            echo "Interesting findings:"
            echo ""
            grep -i -E 'wordpress|joomla|drupal|bootstrap|jquery|react|angular|php|laravel|django|flask|nginx|apache|aws|cloudflare|waf|firewall' "$whatweb_output" | 
            jq -r '.[] | .target + " -> " + (.plugins | keys | join(", "))' 2>/dev/null | head -10 | while read line; do
                echo "- $line"
            done
        else
            echo "No WhatWeb data available"
        fi
        
        echo ""
        
        # Process webanalyze results
        echo "#### WebAnalyze Findings:"
        echo ""
        if [ -s "$webanalyze_output" ]; then
            # Extract the most common technologies
            echo "Most common technologies detected:"
            echo ""
            jq -r '.[] | .matches[] | .app' "$webanalyze_output" 2>/dev/null | sort | uniq -c | sort -nr | head -10 | while read count tech; do
                echo "- $tech ($count instances)"
            done
        else
            echo "No WebAnalyze data available"
        fi
    } > "$tech_summary"
    
    echo -e "${GREEN}[+] Technology scanning completed!${NC}"
    
    # Return the summary for notification
    cat "$tech_summary"
}

# Main function
main() {
    show_banner
    check_requirements
    setup_workspace
    load_api_keys
    
    # Check if domains file exists and has content
    if [ ! -s "$DOMAINS_FILE" ]; then
        echo -e "${RED}[!] No domains found in: $DOMAINS_FILE${NC}"
        echo -e "${YELLOW}[*] Please add target domains to this file (one per line)${NC}"
        exit 1
    fi
    
    # Create log file
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local log_file="$LOGS_DIR/run-$timestamp.log"
    
    echo -e "${BLUE}[*] Starting monitoring cycle...${NC}"
    echo -e "${YELLOW}[*] Log file: $log_file${NC}"
    
    # Process each domain
    while read -r domain; do
        # Skip empty lines and comments
        [[ "$domain" =~ ^#.*$ || -z "$domain" ]] && continue
        
        # Run enumeration
        enumerate_subdomains "$domain" | tee -a "$log_file"
    done < "$DOMAINS_FILE"
    
    echo -e "${GREEN}[+] Monitoring cycle completed!${NC}"
    echo -e "${BLUE}[*] Next cycle will run in ${YELLOW}$(($COOLDOWN / 60))${BLUE} minutes.${NC}"
}

# Set up a cron job to run this script every hour
setup_cron() {
    echo -e "${YELLOW}[*] Setting up cron job to run every hour...${NC}"
    
    # Check if the script is executable
    if [ ! -x "$0" ]; then
        chmod +x "$0"
        echo -e "${GREEN}[+] Made script executable.${NC}"
    fi
    
    # Get absolute path to this script
    local script_path=$(readlink -f "$0")
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "$script_path"; then
        echo -e "${YELLOW}[*] Cron job already exists.${NC}"
    else
        # Add cron job
        (crontab -l 2>/dev/null; echo "0 * * * * $script_path --cron") | crontab -
        echo -e "${GREEN}[+] Cron job added successfully!${NC}"
    fi
}

# Display help
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help        Show this help message"
    echo "  --setup       Set up the workspace and exit"
    echo "  --cron        Run quietly (for cron jobs)"
    echo "  --setup-cron  Set up a cron job to run this script every hour"
    echo ""
}

# Parse command line arguments
if [ $# -gt 0 ]; then
    case "$1" in
        --help)
            show_help
            exit 0
            ;;
        --setup)
            show_banner
            check_requirements
            setup_workspace
            load_api_keys
            echo -e "${GREEN}[+] Setup completed!${NC}"
            exit 0
            ;;
        --cron)
            # Run quietly for cron jobs
            main > /dev/null 2>&1
            exit 0
            ;;
        --setup-cron)
            show_banner
            setup_cron
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
else
    # Run normally
    main
fi
