#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Agent Opulence - Automated Reconnaissance Pipeline
# ═══════════════════════════════════════════════════════════════════════════════
# Runs security scanning tools and outputs to /artifacts/raw/ for enrichment.
# Designed to run inside the hexstrike-recon container (network via gluetun VPN).
#
# Usage: ./run-recon.sh <target_ip> [--quick] [--fresh]
#
# Tools: nmap → httpx → nuclei → gobuster → nikto → whatweb
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/artifacts}"
RAW_DIR="${ARTIFACTS_DIR}/raw"
LOGS_DIR="${ARTIFACTS_DIR}/logs"

# Tool timeouts (seconds) - generous to avoid incomplete scans
NMAP_TIMEOUT=900
HTTPX_TIMEOUT=180
NUCLEI_TIMEOUT=600
GOBUSTER_TIMEOUT=600
NIKTO_TIMEOUT=600
WHATWEB_TIMEOUT=180

# Thread/concurrency limits - keep low to avoid overwhelming target
HTTPX_THREADS=10
NUCLEI_THREADS=5
NUCLEI_RATE_LIMIT=50
GOBUSTER_THREADS=5
WHATWEB_THREADS=10

# Wordlists (Kali paths)
GOBUSTER_WORDLIST="${GOBUSTER_WORDLIST:-/usr/share/dirb/wordlists/common.txt}"

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)  echo -e "${BLUE}[${timestamp}]${NC} ${GREEN}[INFO]${NC} $msg" ;;
        WARN)  echo -e "${BLUE}[${timestamp}]${NC} ${YELLOW}[WARN]${NC} $msg" ;;
        ERROR) echo -e "${BLUE}[${timestamp}]${NC} ${RED}[ERROR]${NC} $msg" ;;
        SCAN)  echo -e "${BLUE}[${timestamp}]${NC} ${YELLOW}[SCAN]${NC} $msg" ;;
    esac
}

run_tool() {
    local name="$1"
    local timeout="$2"
    shift 2
    local cmd=("$@")

    log SCAN "Starting $name..."
    local start_time=$(date +%s)

    if timeout "$timeout" "${cmd[@]}" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log INFO "$name completed in ${duration}s"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log WARN "$name timed out after ${timeout}s"
        else
            log ERROR "$name failed with exit code $exit_code"
        fi
        return $exit_code
    fi
}

check_tool() {
    local tool="$1"
    if command -v "$tool" &> /dev/null; then
        return 0
    else
        log WARN "$tool not found, skipping..."
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Scan Functions
# ─────────────────────────────────────────────────────────────────────────────

scan_nmap() {
    local target="$1"
    local output_dir="$2"
    local quick="$3"

    check_tool nmap || return 1

    # -Pn: Skip host discovery (HTB boxes often block ICMP)
    local nmap_opts="-Pn -sC -sV -oA ${output_dir}/${target}_nmap"

    if [ "$quick" = "true" ]; then
        # Quick scan: top 1000 ports
        nmap_opts="-T4 --top-ports 1000 $nmap_opts"
    else
        # Full scan: all ports
        nmap_opts="-p- -T4 $nmap_opts"
    fi

    run_tool "nmap" "$NMAP_TIMEOUT" nmap $nmap_opts "$target"

    # Move XML to proper location for watcher
    if [ -f "${output_dir}/${target}_nmap.xml" ]; then
        log INFO "nmap output: ${output_dir}/${target}_nmap.xml"
    fi
}

scan_httpx() {
    local target="$1"
    local output_dir="$2"
    local ports="$3"
    local web_host="${4:-$target}"  # Use vhost if provided, else IP

    # Use httpx-toolkit (Go version from projectdiscovery)
    check_tool httpx-toolkit || return 1

    # Build URL list from discovered HTTP ports
    local urls_file="${output_dir}/.httpx_urls.txt"
    rm -f "$urls_file"

    # Parse ports from nmap or use common HTTP ports
    if [ -n "$ports" ]; then
        for port in $(echo "$ports" | tr ',' '\n'); do
            echo "http://${target}:${port}" >> "$urls_file"
            echo "https://${target}:${port}" >> "$urls_file"
            # Also scan vhost directly if different from target
            if [ "$web_host" != "$target" ]; then
                echo "http://${web_host}:${port}" >> "$urls_file"
                echo "https://${web_host}:${port}" >> "$urls_file"
            fi
        done
    else
        # Default HTTP ports
        for port in 80 443 8080 8443 8000 8888; do
            echo "http://${target}:${port}" >> "$urls_file"
            echo "https://${target}:${port}" >> "$urls_file"
        done
    fi

    run_tool "httpx" "$HTTPX_TIMEOUT" httpx-toolkit \
        -l "$urls_file" \
        -json \
        -o "${output_dir}/${target}_httpx.json" \
        -silent \
        -threads "$HTTPX_THREADS" \
        -td \
        -sc \
        -title \
        -server \
        -cl \
        -fr

    rm -f "$urls_file"

    if [ -f "${output_dir}/${target}_httpx.json" ]; then
        log INFO "httpx output: ${output_dir}/${target}_httpx.json"
    fi
}

scan_nuclei() {
    local target="$1"
    local output_dir="$2"
    local ports="$3"
    local web_host="${4:-$target}"  # Use vhost if provided, else IP

    check_tool nuclei || return 1

    # Ensure templates are available (update on first run)
    if [ ! -d "$HOME/.local/nuclei-templates" ] && [ ! -d "/root/nuclei-templates" ]; then
        log INFO "Updating nuclei templates (first run)..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi

    # Build target URLs using vhost
    local target_url="http://${web_host}"
    if [ -n "$ports" ]; then
        # Use first HTTP port found
        local first_port=$(echo "$ports" | cut -d',' -f1)
        target_url="http://${web_host}:${first_port}"
    fi

    run_tool "nuclei" "$NUCLEI_TIMEOUT" nuclei \
        -u "$target_url" \
        -jsonl \
        -o "${output_dir}/${target}_nuclei.jsonl" \
        -silent \
        -c "$NUCLEI_THREADS" \
        -rl "$NUCLEI_RATE_LIMIT" \
        -as \
        -severity low,medium,high,critical

    if [ -f "${output_dir}/${target}_nuclei.jsonl" ]; then
        log INFO "nuclei output: ${output_dir}/${target}_nuclei.jsonl"
    fi
}

scan_gobuster() {
    local target="$1"
    local output_dir="$2"
    local ports="$3"
    local web_host="${4:-$target}"  # Use vhost if provided, else IP

    check_tool gobuster || return 1

    # Check for wordlist
    if [ ! -f "$GOBUSTER_WORDLIST" ]; then
        log WARN "Wordlist not found: $GOBUSTER_WORDLIST"
        return 1
    fi

    local target_url="http://${web_host}"
    if [ -n "$ports" ]; then
        local first_port=$(echo "$ports" | cut -d',' -f1)
        target_url="http://${web_host}:${first_port}"
    fi

    run_tool "gobuster" "$GOBUSTER_TIMEOUT" gobuster dir \
        -u "$target_url" \
        -w "$GOBUSTER_WORDLIST" \
        -o "${output_dir}/${target}_gobuster.txt" \
        -q \
        -t "$GOBUSTER_THREADS" \
        --timeout 45s \
        --delay 100ms \
        --no-error \
        -r

    if [ -f "${output_dir}/${target}_gobuster.txt" ]; then
        log INFO "gobuster output: ${output_dir}/${target}_gobuster.txt"
    fi
}

scan_nikto() {
    local target="$1"
    local output_dir="$2"
    local ports="$3"
    local web_host="${4:-$target}"  # Use vhost if provided, else IP

    check_tool nikto || return 1

    # Build target URL (nikto prefers URL format)
    local target_url="http://${web_host}"
    if [ -n "$ports" ]; then
        local first_port=$(echo "$ports" | cut -d',' -f1)
        # Only add port if not standard HTTP
        if [ "$first_port" != "80" ]; then
            target_url="http://${web_host}:${first_port}"
        fi
    fi

    run_tool "nikto" "$NIKTO_TIMEOUT" nikto \
        -h "$target_url" \
        -o "${output_dir}/${target}_nikto.txt" \
        -Format txt \
        -ask no

    if [ -f "${output_dir}/${target}_nikto.txt" ]; then
        log INFO "nikto output: ${output_dir}/${target}_nikto.txt"
    fi
}

scan_whatweb() {
    local target="$1"
    local output_dir="$2"
    local ports="$3"
    local web_host="${4:-$target}"  # Use vhost if provided, else IP

    check_tool whatweb || return 1

    local target_url="http://${web_host}"
    if [ -n "$ports" ]; then
        local first_port=$(echo "$ports" | cut -d',' -f1)
        target_url="http://${web_host}:${first_port}"
    fi

    run_tool "whatweb" "$WHATWEB_TIMEOUT" whatweb \
        "$target_url" \
        --log-json="${output_dir}/${target}_whatweb.json" \
        -a 3 \
        -t "$WHATWEB_THREADS" \
        -q

    if [ -f "${output_dir}/${target}_whatweb.json" ]; then
        log INFO "whatweb output: ${output_dir}/${target}_whatweb.json"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Vhost Auto-Detection
# ─────────────────────────────────────────────────────────────────────────────
# Parses nmap output for HTTP redirects and adds discovered vhosts to /etc/hosts.
# This fixes web tools failing on sites that require Host header routing.

detect_and_add_vhosts() {
    local target="$1"
    local nmap_file="$2"

    if [ ! -f "$nmap_file" ]; then
        log WARN "nmap output not found for vhost detection: $nmap_file" >&2
        echo ""
        return 0
    fi

    log INFO "Checking for vhost redirects in nmap output..." >&2

    # Extract hostnames from redirect patterns in nmap output
    # Patterns: "Did not follow redirect to http://hostname/", "Location: http://hostname/"
    # Use || true to handle case where grep finds no matches
    local vhosts
    vhosts=$(grep -oP '(?:redirect to|Location:)\s*https?://\K[^/\s:]+' "$nmap_file" 2>/dev/null | \
                   grep -v "^${target}$" 2>/dev/null | \
                   grep -vP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' 2>/dev/null | \
                   sort -u || true)

    if [ -z "$vhosts" ]; then
        log INFO "No vhost redirects detected" >&2
        echo ""
        return 0
    fi

    log INFO "Detected vhosts: $(echo $vhosts | tr '\n' ' ')" >&2

    # Add each vhost to /etc/hosts if not already present
    local primary_vhost=""
    for vhost in $vhosts; do
        if grep -q "$vhost" /etc/hosts 2>/dev/null; then
            log INFO "  $vhost already in /etc/hosts" >&2
        else
            echo "$target $vhost" >> /etc/hosts
            log INFO "  Added: $target → $vhost" >&2
        fi
        # First vhost becomes primary
        if [ -z "$primary_vhost" ]; then
            primary_vhost="$vhost"
        fi
    done

    # Output primary vhost for capture
    echo "$primary_vhost"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Port Extraction from nmap
# ─────────────────────────────────────────────────────────────────────────────

extract_http_ports() {
    local nmap_file="$1"

    if [ ! -f "$nmap_file" ]; then
        echo ""
        return 0
    fi

    # Extract open ports with http/https services from nmap XML
    # Use || true to handle case where grep finds no matches
    local ports
    ports=$(grep -oP 'portid="\K[0-9]+(?=".*state="open".*service name="https?")' "$nmap_file" 2>/dev/null | \
        tr '\n' ',' | sed 's/,$//' || true)
    echo "$ports"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 <target_ip> [--quick] [--fresh]"
    echo ""
    echo "Options:"
    echo "  --quick    Run faster scans (top 1000 ports instead of all)"
    echo "  --fresh    Clear old scan data and CAS before scanning"
    echo ""
    echo "Environment variables:"
    echo "  ARTIFACTS_DIR     Base artifacts directory (default: /artifacts)"
    echo "  GOBUSTER_WORDLIST Wordlist for gobuster (default: /usr/share/wordlists/dirb/common.txt)"
    exit 1
}

main() {
    local target=""
    local quick="false"
    local fresh="false"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick)
                quick="true"
                shift
                ;;
            --fresh)
                fresh="true"
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                if [ -z "$target" ]; then
                    target="$1"
                else
                    echo "Unknown argument: $1"
                    usage
                fi
                shift
                ;;
        esac
    done

    if [ -z "$target" ]; then
        echo "Error: target IP required"
        usage
    fi

    # Validate target format (basic IP validation)
    if ! echo "$target" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
        log WARN "Target doesn't look like an IP address, proceeding anyway..."
    fi

    # Setup directories
    local output_dir="${RAW_DIR}/${target}"
    local cas_dir="${ARTIFACTS_DIR}/${target}"

    # Fresh mode: clear old scan data and CAS
    if [ "$fresh" = "true" ]; then
        log INFO "Fresh mode: clearing old data for $target"
        rm -rf "$output_dir"
        rm -f "${cas_dir}/context.yaml"
    fi

    mkdir -p "$output_dir"
    mkdir -p "$LOGS_DIR"

    local logfile="${LOGS_DIR}/recon_${target}_$(date +%Y%m%d_%H%M%S).log"

    log INFO "═══════════════════════════════════════════════════════════════"
    log INFO " Agent Opulence - Reconnaissance Pipeline"
    log INFO "═══════════════════════════════════════════════════════════════"
    log INFO "Target: $target"
    log INFO "Output: $output_dir"
    log INFO "Quick mode: $quick"
    log INFO "Log: $logfile"
    log INFO "═══════════════════════════════════════════════════════════════"

    local start_time=$(date +%s)
    local http_ports=""
    local web_host="$target"  # Defaults to IP, may be overridden by vhost

    # Phase 1: Network Discovery (nmap)
    log INFO ""
    log INFO "╔═══════════════════════════════════════════════════════════════╗"
    log INFO "║ Phase 1: Network Discovery                                    ║"
    log INFO "╚═══════════════════════════════════════════════════════════════╝"

    if scan_nmap "$target" "$output_dir" "$quick"; then
        # Extract HTTP ports for subsequent scans
        http_ports=$(extract_http_ports "${output_dir}/${target}_nmap.xml")
        if [ -n "$http_ports" ]; then
            log INFO "Discovered HTTP ports: $http_ports"
        fi

        # Auto-detect and add vhosts from redirect patterns
        local detected_vhost=$(detect_and_add_vhosts "$target" "${output_dir}/${target}_nmap.nmap")
        if [ -n "$detected_vhost" ]; then
            web_host="$detected_vhost"
            log INFO "Web tools will use vhost: $web_host"
        fi
    fi

    # Phase 2: Web Discovery (httpx, whatweb)
    log INFO ""
    log INFO "╔═══════════════════════════════════════════════════════════════╗"
    log INFO "║ Phase 2: Web Service Discovery                                ║"
    log INFO "╚═══════════════════════════════════════════════════════════════╝"

    scan_httpx "$target" "$output_dir" "$http_ports" "$web_host" || true
    scan_whatweb "$target" "$output_dir" "$http_ports" "$web_host" || true

    # Phase 3: Vulnerability Scanning (nuclei, nikto)
    log INFO ""
    log INFO "╔═══════════════════════════════════════════════════════════════╗"
    log INFO "║ Phase 3: Vulnerability Scanning                               ║"
    log INFO "╚═══════════════════════════════════════════════════════════════╝"

    scan_nuclei "$target" "$output_dir" "$http_ports" "$web_host" || true
    scan_nikto "$target" "$output_dir" "$http_ports" "$web_host" || true

    # Phase 4: Content Discovery (gobuster)
    log INFO ""
    log INFO "╔═══════════════════════════════════════════════════════════════╗"
    log INFO "║ Phase 4: Content Discovery                                    ║"
    log INFO "╚═══════════════════════════════════════════════════════════════╝"

    scan_gobuster "$target" "$output_dir" "$http_ports" "$web_host" || true

    # Summary
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))

    log INFO ""
    log INFO "═══════════════════════════════════════════════════════════════"
    log INFO " Reconnaissance Complete"
    log INFO "═══════════════════════════════════════════════════════════════"
    log INFO "Duration: ${total_duration}s"
    log INFO "Output files:"
    ls -la "$output_dir" 2>/dev/null | tail -n +2 | while read line; do
        log INFO "  $line"
    done
    log INFO ""
    log INFO "Enrichment pipeline will process files automatically."
    log INFO "CAS document will be written to: /artifacts/${target}/context.yaml"
    log INFO "═══════════════════════════════════════════════════════════════"
}

# Run main with all args, tee to logfile
main "$@" 2>&1 | tee -a "${LOGS_DIR:-/tmp}/recon_latest.log"
