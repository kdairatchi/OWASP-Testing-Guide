#!/bin/bash

# Ultimate Subdomain Monitoring System with Discord Integration
# Version: 3.0
# Created: April 8, 2025
# Description: Comprehensive subdomain monitoring with advanced Discord notifications
# Features:
# - Multi-tool subdomain discovery
# - Technology fingerprinting
# - Change detection
# - Rich Discord notifications
# - Historical tracking

# Required tools:
# - subfinder, amass, assetfinder, findomain, bbot
# - notify, anew, httpx
# - whatweb, webanalyze, eyewitness
# - jq, curl, git
# - nuclei, gau, waybackurls

# ===== CONFIGURATION =====
# Directory structure
WORKSPACE="$HOME/subdomain-monitor"
DOMAINS_FILE="$WORKSPACE/domains.txt"
RESULTS_DIR="$WORKSPACE/results"
LOGS_DIR="$WORKSPACE/logs"
TEMP_DIR="$WORKSPACE/temp"
CONFIG_DIR="$WORKSPACE/config"
TECH_DIR="$WORKSPACE/tech-data"
SCREENSHOTS_DIR="$WORKSPACE/screenshots"
DIFF_DIR="$WORKSPACE/diffs"

# Notification configuration
DISCORD_WEBHOOK=""  # Set your webhook here or in config file
NOTIFY_CONFIG="$CONFIG_DIR/notify-config.yaml"
DISCORD_CONFIG="$CONFIG_DIR/discord-config.json"

# Cooldown period between runs (in seconds, default: 1 hour)
COOLDOWN=3600

# Maximum number of parallel processes
MAX_PARALLEL=5

# API keys file (encrypted)
API_KEYS="$CONFIG_DIR/api-keys.gpg"

# Technology scanning options
TECH_SCAN=true                  # Enable technology scanning
SCREENSHOTS=true                # Enable screenshot capture
TECH_SCAN_TIMEOUT=30            # Timeout for technology scanning
SCAN_PORTS="80,443,8080,8443"   # Ports to scan
BBOT_MODULES="fast"             # BBOT scan modules

# DNS monitoring options
MONITOR_DNS=true                # Monitor DNS record changes
DNS_RESOLVERS="1.1.1.1,8.8.8.8" # DNS resolvers to use

# SSL monitoring options
MONITOR_SSL=true                # Monitor SSL certificate changes
SSL_TIMEOUT=10                  # SSL check timeout

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
    echo " ██████╗ ███████╗██████╗ ██╗   ██╗███████╗██████╗ ██████╗ ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ "
    echo "██╔═══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗"
    echo "██║   ██║███████╗██████╔╝██║   ██║█████╗  ██████╔╝██████╔╝██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝"
    echo "██║   ██║╚════██║██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗"
    echo "╚██████╔╝███████║██║  ██║ ╚████╔╝ ███████╗██║  ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║"
    echo " ╚═════╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${CYAN}Ultimate Subdomain Monitoring System${NC}"
    echo -e "${YELLOW}Advanced monitoring with rich Discord integration${NC}"
    echo "===================================================================="
}

# Check if required tools are installed
check_requirements() {
    echo -e "${YELLOW}[*] Checking requirements...${NC}"
    
    local missing_tools=()
    local critical_tools=("subfinder" "amass" "notify" "anew" "httpx" "jq" "curl")
    local optional_tools=("assetfinder" "findomain" "bbot" "whatweb" "webanalyze" "eyewitness" "nuclei" "gau" "waybackurls")
    
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing critical tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[*] Please install the missing tools and try again.${NC}"
        exit 1
    fi
    
    # Check optional tools
    missing_tools=()
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${YELLOW}[*] Missing optional tools (some features will be disabled): ${missing_tools[*]}${NC}"
    fi
    
    echo -e "${GREEN}[+] All required tools are installed!${NC}"
}

# Create initial directory structure
setup_workspace() {
    echo -e "${YELLOW}[*] Setting up workspace...${NC}"
    
    # Create directories if they don't exist
    for dir in "$WORKSPACE" "$RESULTS_DIR" "$LOGS_DIR" "$TEMP_DIR" "$CONFIG_DIR" "$TECH_DIR" "$SCREENSHOTS_DIR" "$DIFF_DIR"; do
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
    
    # Create Discord config if it doesn't exist
    if [ ! -f "$DISCORD_CONFIG" ]; then
        cat > "$DISCORD_CONFIG" << EOF
{
    "webhook_url": "$DISCORD_WEBHOOK",
    "username": "Subdomain Monitor",
    "avatar_url": "https://i.imgur.com/4M34hi2.png",
    "embed_colors": {
        "new_subdomain": 65280,
        "warning": 16776960,
        "error": 16711680,
        "info": 4886754
    },
    "monitoring": {
        "dns": true,
        "ssl": true,
        "technologies": true,
        "screenshots": true
    },
    "threat_intel": {
        "check_takeovers": true,
        "check_vulnerabilities": true,
        "check_exposures": true
    }
}
EOF
        echo -e "${YELLOW}[*] Created Discord config: $DISCORD_CONFIG${NC}"
    fi
    
    # Create notify config if it doesn't exist
    if [ ! -f "$NOTIFY_CONFIG" ] && [ -f "$DISCORD_CONFIG" ]; then
        webhook_url=$(jq -r '.webhook_url' "$DISCORD_CONFIG")
        cat > "$NOTIFY_CONFIG" << EOF
discord:
  - id: "default"
    webhook_url: "$webhook_url"
    thread_id: ""
    thread_name: ""
    format: "{{data}}"
EOF
        echo -e "${YELLOW}[*] Created notify config: $NOTIFY_CONFIG${NC}"
    fi
    
    # Create encrypted API keys file if it doesn't exist
    if [ ! -f "$API_KEYS" ]; then
        echo -e "${YELLOW}[*] Creating encrypted API keys file...${NC}"
        cat > "$TEMP_DIR/api-keys.txt" << EOF
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

# Discord webhook (alternative location)
DISCORD_WEBHOOK=
EOF
        # Encrypt the file with GPG
        gpg --symmetric --cipher-algo AES256 -o "$API_KEYS" "$TEMP_DIR/api-keys.txt"
        rm -f "$TEMP_DIR/api-keys.txt"
        echo -e "${GREEN}[+] Created encrypted API keys file: $API_KEYS${NC}"
        echo -e "${YELLOW}[*] Please edit the file with 'gpg $API_KEYS' to add your API keys${NC}"
    fi
    
    echo -e "${GREEN}[+] Workspace setup complete!${NC}"
}

# Load API keys for various services
load_api_keys() {
    echo -e "${YELLOW}[*] Loading API keys...${NC}"
    
    if [ -f "$API_KEYS" ]; then
        # Decrypt the API keys file to memory
        api_keys_content=$(gpg --quiet --decrypt "$API_KEYS" 2>/dev/null)
        
        if [ -z "$api_keys_content" ]; then
            echo -e "${RED}[!] Failed to decrypt API keys file${NC}"
            echo -e "${YELLOW}[*] Some tools may have limited functionality without API keys.${NC}"
            return
        fi
        
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
                    if [ -n "$censys_username" ]; then
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
                DISCORD_WEBHOOK)
                    if [ -z "$DISCORD_WEBHOOK" ]; then
                        DISCORD_WEBHOOK="$value"
                        # Update notify config if it exists
                        if [ -f "$NOTIFY_CONFIG" ]; then
                            yq e ".discord[0].webhook_url = \"$value\"" -i "$NOTIFY_CONFIG"
                        fi
                    fi
                    ;;
            esac
        done <<< "$api_keys_content"
        
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
    local previous_count=0
    
    # Create domain output directory if it doesn't exist
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
    fi
    
    # Get previous count if file exists
    if [ -f "$previous_all" ]; then
        previous_count=$(wc -l < "$previous_all")
    fi
    
    echo -e "${BLUE}[*] Starting subdomain enumeration for: ${YELLOW}$domain${NC}"
    
    # Create temp files
    local subfinder_output="$TEMP_DIR/$domain-subfinder-$timestamp.txt"
    local amass_output="$TEMP_DIR/$domain-amass-$timestamp.txt"
    local assetfinder_output="$TEMP_DIR/$domain-assetfinder-$timestamp.txt"
    local findomain_output="$TEMP_DIR/$domain-findomain-$timestamp.txt"
    local bbot_output="$TEMP_DIR/$domain-bbot-$timestamp.txt"
    
    # Run tools in parallel with timeout
    echo -e "${CYAN}[*] Running subfinder...${NC}"
    timeout 600 subfinder -d "$domain" -silent -pc "$HOME/.config/subfinder/provider-config.yaml" | sort -u > "$subfinder_output" &
    pid_subfinder=$!
    
    echo -e "${CYAN}[*] Running amass...${NC}"
    timeout 900 amass enum -passive -d "$domain" -o "$amass_output" &
    pid_amass=$!
    
    if command -v assetfinder &> /dev/null; then
        echo -e "${CYAN}[*] Running assetfinder...${NC}"
        timeout 300 assetfinder --subs-only "$domain" | sort -u > "$assetfinder_output" &
        pid_assetfinder=$!
    else
        touch "$assetfinder_output"
        pid_assetfinder=0
    fi
    
    if command -v findomain &> /dev/null; then
        echo -e "${CYAN}[*] Running findomain...${NC}"
        timeout 300 findomain --quiet -t "$domain" -u "$findomain_output" &
        pid_findomain=$!
    else
        touch "$findomain_output"
        pid_findomain=0
    fi
    
    if command -v bbot &> /dev/null; then
        echo -e "${CYAN}[*] Running bbot...${NC}"
        timeout 1200 bbot -t "$domain" -f subdomain-enum -m "$BBOT_MODULES" --no-scan-topdomains -o txt:"$bbot_output" &
        pid_bbot=$!
    else
        touch "$bbot_output"
        pid_bbot=0
    fi
    
    # Wait for all processes to finish
    wait $pid_subfinder && echo -e "${GREEN}[+] Subfinder finished!${NC}" || echo -e "${RED}[!] Subfinder timed out or failed${NC}"
    wait $pid_amass && echo -e "${GREEN}[+] Amass finished!${NC}" || echo -e "${RED}[!] Amass timed out or failed${NC}"
    [ $pid_assetfinder -ne 0 ] && wait $pid_assetfinder && echo -e "${GREEN}[+] Assetfinder finished!${NC}" || echo -e "${YELLOW}[-] Assetfinder skipped${NC}"
    [ $pid_findomain -ne 0 ] && wait $pid_findomain && echo -e "${GREEN}[+] Findomain finished!${NC}" || echo -e "${YELLOW}[-] Findomain skipped${NC}"
    [ $pid_bbot -ne 0 ] && wait $pid_bbot && echo -e "${GREEN}[+] BBOT finished!${NC}" || echo -e "${YELLOW}[-] BBOT skipped${NC}"
    
    # Combine and sort results
    echo -e "${BLUE}[*] Combining results...${NC}"
    cat "$subfinder_output" "$amass_output" "$assetfinder_output" "$findomain_output" "$bbot_output" | sort -u > "$all_subdomains"
    
    # Count subdomains found by each tool
    local subfinder_count=$(wc -l < "$subfinder_output")
    local amass_count=$(wc -l < "$amass_output")
    local assetfinder_count=0
    [ $pid_assetfinder -ne 0 ] && assetfinder_count=$(wc -l < "$assetfinder_output")
    local findomain_count=0
    [ $pid_findomain -ne 0 ] && findomain_count=$(wc -l < "$findomain_output")
    local bbot_count=0
    [ $pid_bbot -ne 0 ] && bbot_count=$(wc -l < "$bbot_output")
    local total_count=$(wc -l < "$all_subdomains")
    
    echo -e "${GREEN}[+] Results combined!${NC}"
    echo -e "${BLUE}[*] Statistics:${NC}"
    echo -e "  ${PURPLE}Subfinder:${NC}    $subfinder_count subdomains"
    echo -e "  ${PURPLE}Amass:${NC}        $amass_count subdomains"
    [ $pid_assetfinder -ne 0 ] && echo -e "  ${PURPLE}Assetfinder:${NC}  $assetfinder_count subdomains"
    [ $pid_findomain -ne 0 ] && echo -e "  ${PURPLE}Findomain:${NC}    $findomain_count subdomains"
    [ $pid_bbot -ne 0 ] && echo -e "  ${PURPLE}BBOT:${NC}         $bbot_count subdomains"
    echo -e "  ${PURPLE}Total unique:${NC} $total_count subdomains"
    [ -f "$previous_all" ] && echo -e "  ${PURPLE}Previous total:${NC} $previous_count subdomains"
    
    # Check for new subdomains
    if [ -f "$previous_all" ]; then
        echo -e "${BLUE}[*] Checking for new subdomains...${NC}"
        cat "$all_subdomains" | anew "$previous_all" > "$new_subdomains"
        
        local new_count=$(wc -l < "$new_subdomains")
        if [ $new_count -gt 0 ]; then
            echo -e "${GREEN}[+] Found $new_count new subdomains!${NC}"
            
            # Update the all.txt file
            cat "$new_subdomains" >> "$previous_all"
            sort -u "$previous_all" -o "$previous_all"
            
            # Filter live subdomains
            local new_live_subdomains="$TEMP_DIR/$domain-new-live-$timestamp.txt"
            echo -e "${BLUE}[*] Checking for live subdomains...${NC}"
            cat "$new_subdomains" | httpx -silent -timeout 10 -retries 2 -status-code -title -follow-redirects -tech-detect -json -o "$new_live_subdomains.json"
            jq -r '.url' "$new_live_subdomains.json" > "$new_live_subdomains"
            local live_count=$(wc -l < "$new_live_subdomains")
            echo -e "${GREEN}[+] Found $live_count live subdomains!${NC}"
            
            # Perform additional scans
            local tech_report=""
            local takeover_report=""
            local vulnerability_report=""
            local screenshot_report=""
            
            # Technology scanning
            if [ "$TECH_SCAN" = true ] && [ $live_count -gt 0 ]; then
                tech_report=$(scan_technologies "$domain" "$new_live_subdomains.json" "$timestamp")
            fi
            
            # Subdomain takeover checks
            if [ $live_count -gt 0 ] && command -v nuclei &> /dev/null; then
                takeover_report=$(check_takeovers "$domain" "$new_live_subdomains" "$timestamp")
            fi
            
            # Vulnerability scanning
            if [ $live_count -gt 0 ] && command -v nuclei &> /dev/null; then
                vulnerability_report=$(scan_vulnerabilities "$domain" "$new_live_subdomains" "$timestamp")
            fi
            
            # Screenshots
            if [ "$SCREENSHOTS" = true ] && [ $live_count -gt 0 ] && command -v eyewitness &> /dev/null; then
                screenshot_report=$(capture_screenshots "$domain" "$new_live_subdomains" "$timestamp")
            fi
            
            # DNS monitoring
            if [ "$MONITOR_DNS" = true ]; then
                dns_report=$(monitor_dns_changes "$domain" "$timestamp")
            fi
            
            # SSL monitoring
            if [ "$MONITOR_SSL" = true ] && [ $live_count -gt 0 ]; then
                ssl_report=$(monitor_ssl_changes "$domain" "$new_live_subdomains" "$timestamp")
            fi
            
            # Send notification
            send_discord_notification "$domain" "$new_subdomains" "$new_live_subdomains.json" "$timestamp" \
                "$tech_report" "$takeover_report" "$vulnerability_report" "$screenshot_report" \
                "$dns_report" "$ssl_report" "$total_count" "$previous_count"
        else
            echo -e "${YELLOW}[*] No new subdomains found.${NC}"
            
            # Still check for DNS and SSL changes even if no new subdomains
            if [ "$MONITOR_DNS" = true ]; then
                dns_report=$(monitor_dns_changes "$domain" "$timestamp")
                if [ -n "$dns_report" ]; then
                    send_discord_notification "$domain" "" "" "$timestamp" "" "" "" "" "$dns_report" "" "$total_count" "$previous_count"
                fi
            fi
            
            if [ "$MONITOR_SSL" = true ]; then
                # Check SSL for all known subdomains
                local all_live_subdomains="$TEMP_DIR/$domain-all-live-$timestamp.txt"
                cat "$previous_all" | httpx -silent -timeout 10 -retries 2 -status-code -title -follow-redirects -tech-detect -json -o "$all_live_subdomains.json"
                ssl_report=$(monitor_ssl_changes "$domain" "$previous_all" "$timestamp")
                if [ -n "$ssl_report" ]; then
                    send_discord_notification "$domain" "" "" "$timestamp" "" "" "" "" "" "$ssl_report" "$total_count" "$previous_count"
                fi
            fi
        fi
    else
        echo -e "${BLUE}[*] First run for this domain, saving baseline...${NC}"
        cp "$all_subdomains" "$previous_all"
        
        # Get live subdomains for baseline
        local live_subdomains="$output_dir/live-$timestamp.txt"
        cat "$all_subdomains" | httpx -silent -timeout 10 -retries 2 -status-code -title -follow-redirects -tech-detect -json -o "$live_subdomains.json"
        local live_count=$(jq -r '.url' "$live_subdomains.json" | wc -l)
        
        # Send initial notification
        if [ -f "$DISCORD_CONFIG" ]; then
            local webhook_url=$(jq -r '.webhook_url' "$DISCORD_CONFIG")
            if [ -n "$webhook_url" ]; then
                local message="**🔍 Initial Subdomain Scan Complete**\n"
                message+="**Domain:** $domain\n"
                message+="**Total Subdomains Found:** $total_count\n"
                message+="**Live Subdomains:** $live_count\n"
                message+="\nThis is the initial scan. Future scans will report new discoveries."
                
                curl -s -H "Content-Type: application/json" -X POST -d "{\"content\":\"$message\"}" "$webhook_url"
            fi
        fi
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
    local tech_report="$tech_dir/tech-summary-$timestamp.md"
    
    # Create tech directory if it doesn't exist
    if [ ! -d "$tech_dir" ]; then
        mkdir -p "$tech_dir"
    fi
    
    echo -e "${BLUE}[*] Analyzing technologies...${NC}"
    
    # Process httpx JSON output to extract technologies
    jq -r '. | select(.tech != null) | .url + " -> " + (.tech | join(", "))' "$subdomains_file" > "$tech_dir/tech-detailed-$timestamp.txt"
    
    # Generate summary report
    {
        echo "### 🔍 Technology Analysis"
        echo ""
        
        # Extract the most common technologies
        echo "#### Most Common Technologies:"
        echo ""
        jq -r '.tech[]?' "$subdomains_file" | sort | uniq -c | sort -nr | head -10 | while read count tech; do
            echo "- $tech ($count instances)"
        done
        
        echo ""
        
        # Extract interesting findings
        echo "#### Interesting Findings:"
        echo ""
        jq -r '. | select(.tech != null) | .url + " -> " + (.tech | join(", "))' "$subdomains_file" | 
        grep -i -E 'wordpress|joomla|drupal|bootstrap|jquery|react|angular|php|laravel|django|flask|nginx|apache|aws|cloudflare|waf|firewall' | 
        head -10 | while read line; do
            echo "- $line"
        done
        
        echo ""
        
        # Cloud providers
        echo "#### Cloud Providers:"
        echo ""
        local cloud_providers=$(jq -r '.tech[]?' "$subdomains_file" | grep -i -E 'aws|azure|gcp|googlecloud|cloudflare|digitalocean|linode' | sort | uniq -c | sort -nr)
        if [ -n "$cloud_providers" ]; then
            echo "$cloud_providers" | while read count provider; do
                echo "- $provider ($count instances)"
            done
        else
            echo "No cloud providers detected"
        fi
        
        echo ""
        
        # Web servers
        echo "#### Web Servers:"
        echo ""
        local web_servers=$(jq -r '.tech[]?' "$subdomains_file" | grep -i -E 'nginx|apache|iis|litespeed|lighttpd|tomcat' | sort | uniq -c | sort -nr)
        if [ -n "$web_servers" ]; then
            echo "$web_servers" | while read count server; do
                echo "- $server ($count instances)"
            done
        else
            echo "No web servers detected"
        fi
    } > "$tech_report"
    
    echo -e "${GREEN}[+] Technology analysis completed!${NC}"
    
    # Return the summary for notification
    cat "$tech_report"
}

# Check for subdomain takeovers
check_takeovers() {
    local domain="$1"
    local subdomains_file="$2"
    local timestamp="$3"
    local takeover_dir="$RESULTS_DIR/$domain/takeovers"
    local takeover_report="$takeover_dir/takeover-summary-$timestamp.md"
    
    # Create takeover directory if it doesn't exist
    if [ ! -d "$takeover_dir" ]; then
        mkdir -p "$takeover_dir"
    fi
    
    echo -e "${BLUE}[*] Checking for subdomain takeovers...${NC}"
    
    # Run nuclei with subdomain takeover templates
    nuclei -l "$subdomains_file" -t ~/nuclei-templates/takeovers/ -silent -json -o "$takeover_dir/takeovers-$timestamp.json" > /dev/null
    
    # Generate summary report
    {
        echo "### 🚨 Subdomain Takeover Checks"
        echo ""
        
        local takeover_count=$(jq -r '. | length' "$takeover_dir/takeovers-$timestamp.json" 2>/dev/null || echo 0)
        
        if [ "$takeover_count" -gt 0 ]; then
            echo "#### Potential Takeovers Found: $takeover_count"
            echo ""
            jq -r '. | "**" + .host + "** -> " + .info.name + ": " + .info.severity' "$takeover_dir/takeovers-$timestamp.json" | while read line; do
                echo "- $line"
            done
        else
            echo "No potential subdomain takeovers detected."
        fi
    } > "$takeover_report"
    
    echo -e "${GREEN}[+] Takeover check completed!${NC}"
    
    # Return the summary for notification
    cat "$takeover_report"
}

# Scan for vulnerabilities
scan_vulnerabilities() {
    local domain="$1"
    local subdomains_file="$2"
    local timestamp="$3"
    local vuln_dir="$RESULTS_DIR/$domain/vulnerabilities"
    local vuln_report="$vuln_dir/vuln-summary-$timestamp.md"
    
    # Create vulnerabilities directory if it doesn't exist
    if [ ! -d "$vuln_dir" ]; then
        mkdir -p "$vuln_dir"
    fi
    
    echo -e "${BLUE}[*] Scanning for vulnerabilities...${NC}"
    
    # Run nuclei with all templates (excluding takeovers)
    nuclei -l "$subdomains_file" -t ~/nuclei-templates/ -exclude-templates ~/nuclei-templates/takeovers/ -silent -json -o "$vuln_dir/vulnerabilities-$timestamp.json" > /dev/null
    
    # Generate summary report
    {
        echo "### 🛡️ Vulnerability Scan Results"
        echo ""
        
        local vuln_count=$(jq -r '. | length' "$vuln_dir/vulnerabilities-$timestamp.json" 2>/dev/null || echo 0)
        
        if [ "$vuln_count" -gt 0 ]; then
            echo "#### Vulnerabilities Found: $vuln_count"
            echo ""
            
            # Group by severity
            echo "**Critical Severity:**"
            jq -r '. | select(.info.severity == "critical") | "**" + .host + "** -> " + .info.name + " (" + .info.severity + ")"' "$vuln_dir/vulnerabilities-$timestamp.json" | while read line; do
                echo "- $line"
            done
            
            echo ""
            echo "**High Severity:**"
            jq -r '. | select(.info.severity == "high") | "**" + .host + "** -> " + .info.name + " (" + .info.severity + ")"' "$vuln_dir/vulnerabilities-$timestamp.json" | while read line; do
                echo "- $line"
            done
            
            echo ""
            echo "**Medium Severity:**"
            jq -r '. | select(.info.severity == "medium") | "**" + .host + "** -> " + .info.name + " (" + .info.severity + ")"' "$vuln_dir/vulnerabilities-$timestamp.json" | while read line; do
                echo "- $line"
            done
            
            echo ""
            echo "**Low Severity:**"
            jq -r '. | select(.info.severity == "low") | "**" + .host + "** -> " + .info.name + " (" + .info.severity + ")"' "$vuln_dir/vulnerabilities-$timestamp.json" | while read line; do
                echo "- $line"
            done
        else
            echo "No vulnerabilities detected."
        fi
    } > "$vuln_report"
    
    echo -e "${GREEN}[+] Vulnerability scan completed!${NC}"
    
    # Return the summary for notification
    cat "$vuln_report"
}

# Capture screenshots of subdomains
capture_screenshots() {
    local domain="$1"
    local subdomains_file="$2"
    local timestamp="$3"
    local screenshot_dir="$SCREENSHOTS_DIR/$domain"
    local screenshot_report="$screenshot_dir/screenshot-summary-$timestamp.md"
    
    # Create screenshot directory if it doesn't exist
    if [ ! -d "$screenshot_dir" ]; then
        mkdir -p "$screenshot_dir"
    fi
    
    echo -e "${BLUE}[*] Capturing screenshots...${NC}"
    
    # Run eyewitness
    eyewitness -f "$subdomains_file" -d "$screenshot_dir/screenshots-$timestamp" --no-prompt --threads 5 > /dev/null 2>&1
    
    # Generate summary report
    {
        echo "### 📸 Screenshots Captured"
        echo ""
        echo "Screenshots have been captured for the following subdomains:"
        echo ""
        cat "$subdomains_file" | while read subdomain; do
            echo "- $subdomain"
        done
        echo ""
        echo "Screenshots are available in: $screenshot_dir/screenshots-$timestamp"
    } > "$screenshot_report"
    
    echo -e "${GREEN}[+] Screenshot capture completed!${NC}"
    
    # Return the summary for notification
    cat "$screenshot_report"
}

# Monitor DNS changes
monitor_dns_changes() {
    local domain="$1"
    local timestamp="$2"
    local dns_dir="$RESULTS_DIR/$domain/dns"
    local current_dns="$dns_dir/dns-$timestamp.txt"
    local previous_dns="$dns_dir/dns.txt"
    local dns_report="$dns_dir/dns-changes-$timestamp.md"
    
    # Create DNS directory if it doesn't exist
    if [ ! -d "$dns_dir" ]; then
        mkdir -p "$dns_dir"
    fi
    
    echo -e "${BLUE}[*] Checking DNS records...${NC}"
    
    # Get current DNS records
    dig +nocmd +noall +answer +multiline -t ANY "$domain" @"${DNS_RESOLVERS%%,*}" > "$current_dns"
    
    # Check for changes
    if [ -f "$previous_dns" ]; then
        # Compare with previous records
        diff "$previous_dns" "$current_dns" > "$dns_dir/dns-diff-$timestamp.txt"
        
        if [ -s "$dns_dir/dns-diff-$timestamp.txt" ]; then
            echo -e "${GREEN}[+] DNS changes detected!${NC}"
            
            # Generate report
            {
                echo "### 🔄 DNS Changes Detected"
                echo ""
                echo "**Domain:** $domain"
                echo "**Time:** $(date)"
                echo ""
                echo "#### DNS Record Changes:"
                echo '```diff'
                cat "$dns_dir/dns-diff-$timestamp.txt"
                echo '```'
            } > "$dns_report"
            
            # Update the previous DNS file
            cp "$current_dns" "$previous_dns"
            
            # Return the report for notification
            cat "$dns_report"
        else
            echo -e "${YELLOW}[*] No DNS changes detected.${NC}"
            rm -f "$current_dns"
        fi
    else
        echo -e "${BLUE}[*] First DNS scan, creating baseline...${NC}"
        cp "$current_dns" "$previous_dns"
    fi
}

# Monitor SSL certificate changes
monitor_ssl_changes() {
    local domain="$1"
    local subdomains_file="$2"
    local timestamp="$3"
    local ssl_dir="$RESULTS_DIR/$domain/ssl"
    local current_ssl="$ssl_dir/ssl-$timestamp.json"
    local previous_ssl="$ssl_dir/ssl.json"
    local ssl_report="$ssl_dir/ssl-changes-$timestamp.md"
    
    # Create SSL directory if it doesn't exist
    if [ ! -d "$ssl_dir" ]; then
        mkdir -p "$ssl_dir"
    fi
    
    echo -e "${BLUE}[*] Checking SSL certificates...${NC}"
    
    # Get current SSL certificates
    cat "$subdomains_file" | while read subdomain; do
        echo | openssl s_client -connect "$subdomain:443" -servername "$subdomain" 2>/dev/null | openssl x509 -noout -dates -issuer -subject -fingerprint
    done > "$current_ssl"
    
    # Check for changes
    if [ -f "$previous_ssl" ]; then
        # Compare with previous certificates
        diff "$previous_ssl" "$current_ssl" > "$ssl_dir/ssl-diff-$timestamp.txt"
        
        if [ -s "$ssl_dir/ssl-diff-$timestamp.txt" ]; then
            echo -e "${GREEN}[+] SSL changes detected!${NC}"
            
            # Generate report
            {
                echo "### 🔐 SSL Certificate Changes Detected"
                echo ""
                echo "**Domain:** $domain"
                echo "**Time:** $(date)"
                echo ""
                echo "#### SSL Certificate Changes:"
                echo '```diff'
                cat "$ssl_dir/ssl-diff-$timestamp.txt"
                echo '```'
            } > "$ssl_report"
            
            # Update the previous SSL file
            cp "$current_ssl" "$previous_ssl"
            
            # Return the report for notification
            cat "$ssl_report"
        else
            echo -e "${YELLOW}[*] No SSL changes detected.${NC}"
            rm -f "$current_ssl"
        fi
    else
        echo -e "${BLUE}[*] First SSL scan, creating baseline...${NC}"
        cp "$current_ssl" "$previous_ssl"
    fi
}

# Send Discord notification
send_discord_notification() {
    local domain="$1"
    local new_subdomains_file="$2"
    new_live_subdomains_file="$3"
    local timestamp="$4"
    local tech_report="$5"
    local takeover_report="$6"
    local vulnerability_report="$7"
    local screenshot_report="$8"
    local dns_report="$9"
    local ssl_report="${10}"
    local total_count="${11}"
    local previous_count="${12}"
    
    if [ ! -f "$DISCORD_CONFIG" ]; then
        echo -e "${YELLOW}[*] Discord config not found: $DISCORD_CONFIG${NC}"
        echo -e "${YELLOW}[*] Skipping Discord notification...${NC}"
        return
    fi
    
    local webhook_url=$(jq -r '.webhook_url' "$DISCORD_CONFIG")
    if [ -z "$webhook_url" ]; then
        echo -e "${YELLOW}[*] Discord webhook URL not configured${NC}"
        echo -e "${YELLOW}[*] Skipping Discord notification...${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] Preparing Discord notification...${NC}"
    
    # Default embed color (info)
    local embed_color=4886754
    
    # Determine embed color based on findings
    if [ -n "$takeover_report" ] && grep -q "Potential Takeovers Found" "$takeover_report"; then
        embed_color=16711680 # Red for critical
    elif [ -n "$vulnerability_report" ] && (grep -q "Critical Severity" "$vulnerability_report" || grep -q "High Severity" "$vulnerability_report"); then
        embed_color=16711680 # Red for critical
    elif [ -n "$new_subdomains_file" ]; then
        embed_color=65280 # Green for new subdomains
    elif [ -n "$dns_report" ] || [ -n "$ssl_report" ]; then
        embed_color=16776960 # Yellow for changes
    fi
    
    # Create the base embed
    local embed=$(jq -n \
        --arg title "Subdomain Monitoring Report" \
        --arg description "Monitoring results for $domain" \
        --arg color "$embed_color" \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        '{
            "title": $title,
            "description": $description,
            "color": $color | tonumber,
            "timestamp": $timestamp,
            "fields": []
        }')
    
    # Add fields based on what's available
    if [ -n "$new_subdomains_file" ]; then
        local new_count=$(wc -l < "$new_subdomains_file")
        local live_count=$(jq -r '.url' "$new_live_subdomains_file" | wc -l)
        
        embed=$(echo "$embed" | jq \
            --arg name "New Subdomains" \
            --arg value "**Total new:** $new_count\n**Live new:** $live_count\n**Previous total:** $previous_count\n**New total:** $total_count" \
            '.fields += [{"name": $name, "value": $value, "inline": true}]')
        
        # Add top 5 new subdomains if not too many
        if [ "$new_count" -le 10 ]; then
            local subdomains_list=$(cat "$new_subdomains_file" | awk '{print "- " $0}' | head -5 | tr '\n' '\t' | sed 's/\t/\\n/g')
            embed=$(echo "$embed" | jq \
                --arg name "New Subdomains List" \
                --arg value "$subdomains_list" \
                '.fields += [{"name": $name, "value": $value, "inline": true}]')
        fi
    fi
    
    # Add technology report if available
    if [ -n "$tech_report" ]; then
        local tech_summary=$(grep -A 10 "Most Common Technologies" "$tech_report" | grep -v "###" | head -5 | tr '\n' '\t' | sed 's/\t/\\n/g')
        embed=$(echo "$embed" | jq \
            --arg name "Technologies Detected" \
            --arg value "$tech_summary" \
            '.fields += [{"name": $name, "value": $value, "inline": true}]')
    fi
    
    # Add takeover report if available and has findings
    if [ -n "$takeover_report" ] && grep -q "Potential Takeovers Found" "$takeover_report"; then
        local takeover_summary=$(grep -A 5 "Potential Takeovers Found" "$takeover_report" | grep -v "###" | head -5 | tr '\n' '\t' | sed 's/\t/\\n/g')
        embed=$(echo "$embed" | jq \
            --arg name "🚨 Potential Takeovers" \
            --arg value "$takeover_summary" \
            '.fields += [{"name": $name, "value": $value, "inline": false}]')
    fi
    
    # Add vulnerability report if available and has findings
    if [ -n "$vulnerability_report" ] && grep -q "Vulnerabilities Found" "$vulnerability_report"; then
        local vuln_summary=$(grep -A 5 "Critical Severity" "$vulnerability_report" | grep -v "###" | head -5 | tr '\n' '\t' | sed 's/\t/\\n/g')
        [ -z "$vuln_summary" ] && vuln_summary=$(grep -A 5 "High Severity" "$vulnerability_report" | grep -v "###" | head -5 | tr '\n' '\t' | sed 's/\t/\\n/g')
        embed=$(echo "$embed" | jq \
            --arg name "🛡️ Vulnerabilities Found" \
            --arg value "$vuln_summary" \
            '.fields += [{"name": $name, "value": $value, "inline": false}]')
    fi
    
    # Add DNS changes if available
    if [ -n "$dns_report" ]; then
        local dns_summary=$(grep -A 5 "DNS Record Changes" "$dns_report" | grep -v "###" | head -3 | tr '\n' '\t' | sed 's/\t/\\n/g')
        embed=$(echo "$embed" | jq \
            --arg name "🔄 DNS Changes" \
            --arg value "$dns_summary" \
            '.fields += [{"name": $name, "value": $value, "inline": true}]')
    fi
    
    # Add SSL changes if available
    if [ -n "$ssl_report" ]; then
        local ssl_summary=$(grep -A 5 "SSL Certificate Changes" "$ssl_report" | grep -v "###" | head -3 | tr '\n' '\t' | sed 's/\t/\\n/g')
        embed=$(echo "$embed" | jq \
            --arg name "🔐 SSL Changes" \
            --arg value "$ssl_summary" \
            '.fields += [{"name": $name, "value": $value, "inline": true}]')
    fi
    
    # Add footer with timestamp
    embed=$(echo "$embed" | jq \
        --arg footer_text "Subdomain Monitor • $(date +'%Y-%m-%d %H:%M:%S')" \
        '.footer = {"text": $footer_text}')
    
    # Prepare the final payload
    local payload=$(jq -n \
        --argjson embed "$embed" \
        '{
            "username": "Subdomain Monitor",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": [$embed]
        }')
    
    # Send the notification
    local response=$(curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -X POST -d "$payload" "$webhook_url")
    
    if [ "$response" -eq 204 ]; then
        echo -e "${GREEN}[+] Discord notification sent successfully!${NC}"
        
        # If we have screenshots and the notification was successful, send them
        if [ "$SCREENSHOTS" = true ] && [ -n "$screenshot_report" ] && [ -d "$SCREENSHOTS_DIR/$domain/screenshots-$timestamp" ]; then
            echo -e "${BLUE}[*] Preparing to send screenshots...${NC}"
            
            # Get list of screenshot files
            local screenshot_files=($(find "$SCREENSHOTS_DIR/$domain/screenshots-$timestamp" -name "*.png" -type f))
            
            # Send each screenshot (Discord allows up to 10 files per message)
            for ((i=0; i<${#screenshot_files[@]} && i<5; i++)); do
                local file="${screenshot_files[$i]}"
                local subdomain=$(basename "$file" .png)
                
                # Prepare the screenshot embed
                local screenshot_embed=$(jq -n \
                    --arg title "Screenshot: $subdomain" \
                    --arg color "$embed_color" \
                    --arg image_url "attachment://$(basename "$file")" \
                    '{
                        "title": $title,
                        "color": $color | tonumber,
                        "image": {"url": $image_url}
                    }')
                
                # Prepare the multipart form data
                local screenshot_payload=$(jq -n \
                    --argjson embed "$screenshot_embed" \
                    '{
                        "username": "Subdomain Monitor",
                        "avatar_url": "https://i.imgur.com/4M34hi2.png",
                        "embeds": [$embed],
                        "attachments": [{"id": 0, "description": "Screenshot"}]
                    }')
                
                # Send the screenshot
                curl -s -H "Content-Type: multipart/form-data" \
                    -F "payload_json=$screenshot_payload" \
                    -F "file=@$file" \
                    "$webhook_url" > /dev/null
                
                echo -e "${GREEN}[+] Sent screenshot for $subdomain${NC}"
                
                # Rate limiting
                sleep 1
            done
        fi
    else
        echo -e "${RED}[!] Failed to send Discord notification. HTTP status: $response${NC}"
    fi
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
        (crontab -l 2>/dev/null; echo "0 * * * * $script_path --cron >> $LOGS_DIR/cron.log 2>&1") | crontab -
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
    echo "  --update      Update the script and tools"
    echo ""
}

# Update the script and tools
update_script() {
    echo -e "${YELLOW}[*] Checking for updates...${NC}"
    
    # Check if this is a git repository
    if [ -d ".git" ]; then
        echo -e "${BLUE}[*] Found git repository, pulling updates...${NC}"
        git pull
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Script updated successfully!${NC}"
        else
            echo -e "${RED}[!] Failed to update script${NC}"
        fi
    else
        echo -e "${YELLOW}[*] Not a git repository, manual update required${NC}"
    fi
    
    # Update tools if installed via package managers
    echo -e "${BLUE}[*] Updating tools...${NC}"
    
    # Update Go tools
    if command -v go &> /dev/null; then
        echo -e "${CYAN}[*] Updating Go tools...${NC}"
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install github.com/owasp-amass/amass/v3/...@latest
        go install github.com/projectdiscovery/notify/cmd/notify@latest
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        echo -e "${GREEN}[+] Go tools updated!${NC}"
    fi
    
    # Update Python tools
    if command -v pip &> /dev/null; then
        echo -e "${CYAN}[*] Updating Python tools...${NC}"
        pip install --upgrade bbot
        echo -e "${GREEN}[+] Python tools updated!${NC}"
    fi
    
    echo -e "${GREEN}[+] Update process completed!${NC}"
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
        --update)
            show_banner
            update_script
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