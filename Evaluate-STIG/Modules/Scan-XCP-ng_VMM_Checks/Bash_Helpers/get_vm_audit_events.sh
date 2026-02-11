#!/bin/bash
###############################################################################
# Bash Helper Script: Get VM Audit Events
# Purpose: Parse xen.log and xenstore for VM lifecycle audit events
# Location: Scan-XCP-ng_VMM_Checks/Bash_Helpers/get_vm_audit_events.sh
# Usage: ./get_vm_audit_events.sh [event_type] [hours_ago]
###############################################################################

set -euo pipefail

# Script parameters
EVENT_TYPE="${1:-vm_lifecycle}"  # vm_lifecycle, vm_crash, vm_reboot, all
HOURS_AGO="${2:-24}"              # Search last N hours (0 = all)

XEN_LOG="/var/log/xen/xen.log"
XENSTORE_DUMP="/tmp/xenstore-dump-$$.txt"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

###############################################################################
# FUNCTION: Print colored output
###############################################################################
print_status() {
    local status=$1
    local message=$2
    case $status in
        "ERROR")   echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
        "SUCCESS") echo -e "${GREEN}[OK]${NC} $message" ;;
        "INFO")    echo -e "${YELLOW}[INFO]${NC} $message" ;;
        *)         echo "$message" ;;
    esac
}

###############################################################################
# FUNCTION: Check if xen.log exists and is readable
###############################################################################
check_xen_log() {
    if [[ ! -f "$XEN_LOG" ]]; then
        print_status "ERROR" "xen.log not found at $XEN_LOG"
        exit 1
    fi

    if [[ ! -r "$XEN_LOG" ]]; then
        print_status "ERROR" "Cannot read $XEN_LOG (insufficient permissions)"
        exit 1
    fi

    print_status "INFO" "Found xen.log at $XEN_LOG"
}

###############################################################################
# FUNCTION: Parse VM lifecycle events from xen.log
###############################################################################
parse_vm_lifecycle_events() {
    local time_filter=""
    
    if [[ $HOURS_AGO -gt 0 ]]; then
        # Calculate timestamp for N hours ago
        local cutoff_time=$(date -d "$HOURS_AGO hours ago" '+%Y-%m-%d %H:%M:%S')
        time_filter="$cutoff_time"
        print_status "INFO" "Filtering events from last $HOURS_AGO hours"
    else
        print_status "INFO" "Retrieving all VM lifecycle events"
    fi

    # Extract VM creation, destruction, migration events
    echo "=== VM LIFECYCLE EVENTS ==="
    grep -E "Creating domain|Destroyed domain|Migrating domain|Suspending domain|Resuming domain" \
         "$XEN_LOG" 2>/dev/null | head -50 || echo "No VM lifecycle events found"

    echo ""
}

###############################################################################
# FUNCTION: Parse VM crash events from xen.log
###############################################################################
parse_vm_crash_events() {
    echo "=== VM CRASH EVENTS ==="
    grep -E "crash|FATAL|Watchdog timer fired|Guest OS failed to halt" \
         "$XEN_LOG" 2>/dev/null | head -50 || echo "No VM crash events found"

    echo ""
}

###############################################################################
# FUNCTION: Parse VM reboot events from xen.log
###############################################################################
parse_vm_reboot_events() {
    echo "=== VM REBOOT EVENTS ==="
    grep -E "Rebooting domain|ACPI shutdown request|Shutting down" \
         "$XEN_LOG" 2>/dev/null | head -50 || echo "No VM reboot events found"

    echo ""
}

###############################################################################
# FUNCTION: Dump and analyze xenstore for VM configurations
###############################################################################
analyze_xenstore() {
    echo "=== XENSTORE VM CONFIGURATIONS ==="
    
    if command -v xenstore-dump &> /dev/null; then
        xenstore-dump > "$XENSTORE_DUMP" 2>/dev/null || true
        
        # Extract VM name and UUID from xenstore
        grep -E "vm|domid|name" "$XENSTORE_DUMP" 2>/dev/null | head -50 || echo "No VM data in xenstore"
        
        rm -f "$XENSTORE_DUMP"
    else
        print_status "WARNING" "xenstore-dump command not found; skipping xenstore analysis"
    fi

    echo ""
}

###############################################################################
# FUNCTION: Extract audit summary statistics
###############################################################################
extract_audit_statistics() {
    echo "=== AUDIT STATISTICS (last 50 entries) ==="
    
    local total_entries=$(wc -l < "$XEN_LOG" 2>/dev/null || echo "0")
    local vm_events=$(grep -c -E "domain|vm" "$XEN_LOG" 2>/dev/null || echo "0")
    local error_events=$(grep -c -E "ERROR|FATAL|crash" "$XEN_LOG" 2>/dev/null || echo "0")

    echo "Total xen.log entries: $total_entries"
    echo "VM-related events: $vm_events"
    echo "Error/crash events: $error_events"
    echo ""

    # Show last 10 entries
    echo "=== LATEST LOG ENTRIES ==="
    tail -10 "$XEN_LOG" 2>/dev/null || echo "Cannot read latest entries"
    echo ""
}

###############################################################################
# FUNCTION: Validate audit integrity
###############################################################################
validate_audit_integrity() {
    echo "=== AUDIT INTEGRITY CHECK ==="
    
    # Check file permissions (should be readable, not world-writable)
    local perms=$(stat -c %a "$XEN_LOG" 2>/dev/null || echo "unknown")
    echo "xen.log permissions: $perms"
    
    if [[ "$perms" == *"2"* ]] || [[ "$perms" == *"7"* ]]; then
        print_status "ERROR" "xen.log has insecure permissions (world-writable)"
    else
        print_status "SUCCESS" "xen.log permissions are secure"
    fi

    # Check if xen.log is being actively written to
    if [[ -w "$XEN_LOG" ]]; then
        print_status "SUCCESS" "xen.log is actively being written to"
    else
        print_status "WARNING" "xen.log may not be actively logging"
    fi

    echo ""
}

###############################################################################
# MAIN EXECUTION
###############################################################################

echo "================================================================================"
echo "Xen/XCP-ng VM Audit Events Parser"
echo "================================================================================"
echo ""

check_xen_log

case "$EVENT_TYPE" in
    "vm_lifecycle")
        parse_vm_lifecycle_events
        ;;
    "vm_crash")
        parse_vm_crash_events
        ;;
    "vm_reboot")
        parse_vm_reboot_events
        ;;
    "all")
        parse_vm_lifecycle_events
        parse_vm_crash_events
        parse_vm_reboot_events
        ;;
    *)
        print_status "ERROR" "Unknown event type: $EVENT_TYPE"
        echo "Supported types: vm_lifecycle, vm_crash, vm_reboot, all"
        exit 1
        ;;
esac

analyze_xenstore
extract_audit_statistics
validate_audit_integrity

print_status "SUCCESS" "Audit events parsed successfully"
exit 0
