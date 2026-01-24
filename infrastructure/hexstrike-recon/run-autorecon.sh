#!/bin/bash
# Agent Opulence - AutoRecon Wrapper Script
# Handles vhost injection, output directory, and completion logging

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ARTIFACTS_DIR="/artifacts/results"
LOGS_DIR="/artifacts/logs"

# Function to print status messages
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Function to show usage
usage() {
    echo "Usage: $0 <hostname> <target_ip> [options]"
    echo ""
    echo "Arguments:"
    echo "  hostname        Target hostname (e.g., box.htb) - used as AutoRecon target"
    echo "  target_ip       Target IP address - used for /etc/hosts and output directory"
    echo ""
    echo "Options:"
    echo "  --single        Run single target mode (default)"
    echo "  --verbose       Enable verbose output"
    echo "  --only-scans-dir Only create scans directory structure"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Why hostname first?"
    echo "  AutoRecon enables vhost enumeration only when target is a hostname."
    echo "  Many HTB boxes use vhost routing - scanning by IP misses content."
    echo ""
    echo "Examples:"
    echo "  $0 lame.htb 10.10.10.3"
    echo "  $0 conversor.htb 10.129.4.182 --verbose"
    exit 1
}

# Parse arguments
if [ $# -lt 2 ]; then
    usage
fi

HOSTNAME=""
TARGET_IP=""
VERBOSE=""
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        --verbose)
            VERBOSE="-v"
            shift
            ;;
        --single)
            # Default behavior, ignore
            shift
            ;;
        --only-scans-dir)
            EXTRA_ARGS="$EXTRA_ARGS --only-scans-dir"
            shift
            ;;
        -*)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
        *)
            # First positional arg is hostname, second is IP
            if [ -z "$HOSTNAME" ]; then
                HOSTNAME="$1"
            elif [ -z "$TARGET_IP" ]; then
                TARGET_IP="$1"
            fi
            shift
            ;;
    esac
done

# Validate both arguments provided
if [ -z "$HOSTNAME" ] || [ -z "$TARGET_IP" ]; then
    log_error "Both hostname and target IP are required"
    usage
fi

# Validate IP format (basic check)
if ! echo "$TARGET_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    log_error "Second argument doesn't look like an IPv4 address: $TARGET_IP"
    log_error "Usage: $0 <hostname> <ip>"
    exit 1
fi

# Validate hostname format (should contain at least one dot)
if ! echo "$HOSTNAME" | grep -qE '\.'; then
    log_warning "Hostname '$HOSTNAME' has no TLD - consider using box.htb format"
fi

log_info "Agent Opulence - AutoRecon Wrapper"
log_info "=================================="
log_info "Hostname: $HOSTNAME (AutoRecon target)"
log_info "IP: $TARGET_IP (for /etc/hosts & output dir)"

# Setup output directory
TARGET_DIR="${ARTIFACTS_DIR}/${TARGET_IP}"
SCANS_DIR="${TARGET_DIR}/scans"
mkdir -p "$SCANS_DIR" "$LOGS_DIR"

# Inject hostname into /etc/hosts (required for hostname resolution)
log_info "Setting up /etc/hosts: $HOSTNAME -> $TARGET_IP"

# Check if entry already exists
if grep -q "$TARGET_IP.*$HOSTNAME" /etc/hosts 2>/dev/null; then
    log_info "Entry already exists in /etc/hosts"
else
    echo "$TARGET_IP    $HOSTNAME" >> /etc/hosts
    log_success "Added to /etc/hosts"
fi

# Create metadata file
METADATA_FILE="${TARGET_DIR}/autorecon_meta.json"
cat > "$METADATA_FILE" << EOF
{
    "target": "$TARGET_IP",
    "hostname": "$HOSTNAME",
    "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "status": "running",
    "wrapper_version": "1.0.0"
}
EOF

log_info "Starting AutoRecon scan..."
log_info "Output directory: $TARGET_DIR"

# Start time for duration tracking
START_TIME=$(date +%s)

# Run AutoRecon with hostname as target (enables vhost enumeration)
# --disable-keyboard-control: allows running without TTY
# --single-target: outputs directly to -o directory
# Output organized by IP for consistency
autorecon_exit_code=0
autorecon $VERBOSE $EXTRA_ARGS \
    --disable-keyboard-control \
    --single-target \
    --no-port-dirs \
    -o "$TARGET_DIR" \
    "$HOSTNAME" 2>&1 | tee "${LOGS_DIR}/autorecon_${TARGET_IP}.log" || autorecon_exit_code=$?

# Calculate duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Update metadata with completion info
cat > "$METADATA_FILE" << EOF
{
    "target": "$TARGET_IP",
    "hostname": "$HOSTNAME",
    "started_at": "$(date -u -d @$START_TIME +%Y-%m-%dT%H:%M:%SZ)",
    "completed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "duration_seconds": $DURATION,
    "exit_code": $autorecon_exit_code,
    "status": "$([ $autorecon_exit_code -eq 0 ] && echo 'completed' || echo 'failed')",
    "wrapper_version": "1.0.0"
}
EOF

# Check for completion
if [ $autorecon_exit_code -eq 0 ]; then
    log_success "AutoRecon completed successfully"
    log_success "Results: $TARGET_DIR"
    log_success "Duration: ${DURATION}s"

    # Add completion marker to _commands.log for enrichment pipeline
    # AutoRecon writes this to stdout, but enrichment watcher checks _commands.log
    echo "" >> "${SCANS_DIR}/_commands.log"
    echo "Finished scanning target $HOSTNAME" >> "${SCANS_DIR}/_commands.log"

    # List generated files
    log_info "Generated scan files:"
    find "$SCANS_DIR" -type f -name "*.txt" -o -name "*.xml" -o -name "*.json" 2>/dev/null | head -20 | while read f; do
        echo "  - $(basename "$f")"
    done

    # Count files
    FILE_COUNT=$(find "$SCANS_DIR" -type f 2>/dev/null | wc -l)
    log_info "Total files generated: $FILE_COUNT"
else
    log_error "AutoRecon failed with exit code: $autorecon_exit_code"
    log_warning "Check logs at: ${LOGS_DIR}/autorecon_${TARGET_IP}.log"
fi

exit $autorecon_exit_code
