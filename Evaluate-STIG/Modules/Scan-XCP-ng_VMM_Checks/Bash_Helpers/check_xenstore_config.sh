#!/bin/bash
################################################################################
# check_xenstore_config.sh - XCP-ng Xenstore Configuration Validator
################################################################################
# Purpose: Validates critical xenstore settings for XCP-ng compliance
# 
# Usage: ./check_xenstore_config.sh [OPTIONS]
#   --vm UUID           Check specific VM (default: all VMs)
#   --check TYPE        Check specific setting type (auto-reboot|crash|numa|security)
#   --output FORMAT     Output format (text|json|csv)
#
# Description:
#   This script queries xenstore for VM and pool-level settings that impact
#   compliance. It verifies configurations such as:
#   - VM auto-reboot settings (should be disabled for controlled environments)
#   - Crash dump configuration (should be enabled for forensics)
#   - NUMA memory affinity (for resource isolation)
#   - Security policies and VM security parameters
################################################################################

set -o pipefail
umask 077

# Script directory and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/xenstore-compliance-check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CHECK_VM_UUID=""
CHECK_TYPE="all"
OUTPUT_FORMAT="text"
VERBOSE=0

################################################################################
# Helper Functions
################################################################################

print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        ERROR)
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        INFO)
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
    esac
    
    echo "[$status] $TIMESTAMP $message" >> "$LOG_FILE"
}

validate_xenstore_available() {
    if ! command -v xenstore-read &> /dev/null; then
        print_status ERROR "xenstore-read command not available. Are you on XCP-ng Dom0?"
        exit 1
    fi
}

get_vm_uuids() {
    # Get all VM UUIDs from xenstore
    if [ -n "$CHECK_VM_UUID" ]; then
        echo "$CHECK_VM_UUID"
    else
        xenstore-read /vm 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9a-f-]+$' || true
    fi
}

get_vm_name() {
    local vm_uuid="$1"
    xenstore-read "/vm/$vm_uuid/name" 2>/dev/null || echo "Unknown"
}

################################################################################
# Xenstore Configuration Checks
################################################################################

check_vm_auto_reboot() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    local auto_reboot=$(xenstore-read "/vm/$vm_uuid/auto-reboot" 2>/dev/null || echo "0")
    
    if [ "$auto_reboot" = "0" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|auto-reboot|disabled"
        return 0
    else
        echo "NON_COMPLIANT|$vm_uuid|$vm_name|auto-reboot|enabled"
        return 1
    fi
}

check_vm_crash_config() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check if VM has crash dump configuration
    local crash_action=$(xenstore-read "/vm/$vm_uuid/crash-action" 2>/dev/null || echo "unset")
    
    if [ "$crash_action" = "coredump" ] || [ "$crash_action" = "poweroff" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|crash-config|$crash_action"
        return 0
    else
        echo "NON_COMPLIANT|$vm_uuid|$vm_name|crash-config|$crash_action (should be coredump or poweroff)"
        return 1
    fi
}

check_vm_numa_affinity() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check NUMA node affinity
    local numa_setting=$(xenstore-read "/vm/$vm_uuid/NUMA-affinity-set" 2>/dev/null || echo "not-set")
    
    if [ "$numa_setting" != "not-set" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|numa-affinity|configured"
        return 0
    else
        echo "WARNING|$vm_uuid|$vm_name|numa-affinity|not-configured"
        return 1
    fi
}

check_vm_security_policy() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check for security label assignment (AppArmor, SELinux equivalent)
    local security_label=$(xenstore-read "/vm/$vm_uuid/security-label" 2>/dev/null || echo "none")
    
    if [ "$security_label" != "none" ] && [ -n "$security_label" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|security-label|$security_label"
        return 0
    else
        echo "WARNING|$vm_uuid|$vm_name|security-label|none assigned"
        return 1
    fi
}

check_pool_memory_overcommit() {
    local total_memory=$(xenstore-read "/memory-used" 2>/dev/null || echo "0")
    local available_memory=$(xenstore-read "/memory-available" 2>/dev/null || echo "0")
    
    if [ "$total_memory" -lt "$available_memory" ]; then
        echo "COMPLIANT|pool|memory|overcommit|$total_memory/$available_memory"
        return 0
    else
        echo "NON_COMPLIANT|pool|memory|overcommit|Memory overcommitted: $total_memory/$available_memory"
        return 1
    fi
}

check_pool_vlan_isolation() {
    # Verify VLANs are properly configured for network isolation
    local vlan_config=$(xenstore-read "/network" 2>/dev/null | grep -c "vlan" || echo "0")
    
    if [ "$vlan_config" -gt 0 ]; then
        echo "COMPLIANT|pool|network|vlan-isolation|$vlan_config VLANs configured"
        return 0
    else
        echo "WARNING|pool|network|vlan-isolation|No VLANs configured"
        return 1
    fi
}

################################################################################
# Output Formatters
################################################################################

format_text_output() {
    local check_result="$1"
    local status=$(echo "$check_result" | cut -d'|' -f1)
    local scope=$(echo "$check_result" | cut -d'|' -f2)
    local item=$(echo "$check_result" | cut -d'|' -f3)
    local check=$(echo "$check_result" | cut -d'|' -f4)
    local result=$(echo "$check_result" | cut -d'|' -f5-)
    
    printf "%-15s %-30s %-20s %-20s %s\n" "$status" "$scope" "$item" "$check" "$result"
}

format_json_output() {
    local check_result="$1"
    local status=$(echo "$check_result" | cut -d'|' -f1)
    local scope=$(echo "$check_result" | cut -d'|' -f2)
    local item=$(echo "$check_result" | cut -d'|' -f3)
    local check=$(echo "$check_result" | cut -d'|' -f4)
    local result=$(echo "$check_result" | cut -d'|' -f5-)
    
    cat <<EOF
{
  "status": "$status",
  "scope": "$scope",
  "item": "$item",
  "check": "$check",
  "result": "$result",
  "timestamp": "$TIMESTAMP"
}
EOF
}

format_csv_output() {
    local check_result="$1"
    echo "$check_result"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_status INFO "Starting Xenstore Configuration Check"
    
    validate_xenstore_available
    
    # Print header based on format
    case "$OUTPUT_FORMAT" in
        text)
            printf "%-15s %-30s %-20s %-20s %s\n" "STATUS" "SCOPE" "ITEM" "CHECK" "RESULT"
            printf "%s\n" "$(printf '=%.0s' {1..120})"
            ;;
        csv)
            echo "status,scope,item,check,result"
            ;;
    esac
    
    local compliant_count=0
    local non_compliant_count=0
    
    # Get VMs to check
    local vm_uuids=$(get_vm_uuids)
    
    if [ -z "$vm_uuids" ]; then
        print_status WARNING "No VMs found in xenstore"
    fi
    
    # Run VM-specific checks
    for vm_uuid in $vm_uuids; do
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "auto-reboot" ]; then
            local result=$(check_vm_auto_reboot "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
            [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "crash" ]; then
            local result=$(check_vm_crash_config "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
            [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "numa" ]; then
            local result=$(check_vm_numa_affinity "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "security" ]; then
            local result=$(check_vm_security_policy "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
        fi
    done
    
    # Run pool-level checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "memory" ]; then
        local result=$(check_pool_memory_overcommit)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
    fi
    
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "network" ]; then
        local result=$(check_pool_vlan_isolation)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
    fi
    
    print_status INFO "Xenstore Configuration Check Complete"
    print_status INFO "Compliant checks: $compliant_count"
    print_status INFO "Non-compliant checks: $non_compliant_count"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --vm)
            CHECK_VM_UUID="$2"
            shift 2
            ;;
        --check)
            CHECK_TYPE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

main
exit $?
