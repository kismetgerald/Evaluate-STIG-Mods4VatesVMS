#!/bin/bash
################################################################################
# query_guest_isolation.sh - XCP-ng Guest Isolation Validator
################################################################################
# Purpose: Verifies VM network and device isolation compliance
#
# Usage: ./query_guest_isolation.sh [OPTIONS]
#   --vm UUID           Check specific VM (default: all VMs)
#   --check TYPE        Check specific isolation type (network|device|vlan|sr-iov)
#   --output FORMAT     Output format (text|json|csv)
#
# Description:
#   This script validates that guest VMs are properly isolated:
#   - Network isolation via VLANs or dedicated networks
#   - Device isolation (no unauthorized passthrough)
#   - SR-IOV security policies
#   - VM-to-VM communication restrictions
################################################################################

set -o pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/guest-isolation-check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CHECK_VM_UUID=""
CHECK_TYPE="all"
OUTPUT_FORMAT="text"

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

validate_xe_available() {
    if ! command -v xe &> /dev/null; then
        print_status ERROR "xe command not available. Are you on XCP-ng Dom0?"
        exit 1
    fi
}

get_vm_uuids() {
    if [ -n "$CHECK_VM_UUID" ]; then
        echo "$CHECK_VM_UUID"
    else
        xe vm-list params=uuid --minimal 2>/dev/null | tr ',' '\n' | grep -v '^$' || true
    fi
}

get_vm_name() {
    local vm_uuid="$1"
    xe vm-list uuid="$vm_uuid" params=name-label --minimal 2>/dev/null || echo "Unknown"
}

################################################################################
# Network Isolation Checks
################################################################################

check_vm_network_isolation() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Get VM's network interfaces
    local vifs=$(xe vif-list vm-uuid="$vm_uuid" params=uuid --minimal 2>/dev/null | tr ',' '\n')
    
    if [ -z "$vifs" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|network-isolation|no-network-interfaces"
        return 0
    fi
    
    local vlan_count=0
    for vif in $vifs; do
        local network=$(xe vif-list uuid="$vif" params=network-uuid --minimal 2>/dev/null)
        local vlan_tag=$(xe network-list uuid="$network" params=other-config --minimal 2>/dev/null | grep -o "vlan=[0-9]*" || true)
        
        if [ -n "$vlan_tag" ]; then
            ((vlan_count++))
        fi
    done
    
    if [ "$vlan_count" -gt 0 ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|network-isolation|vlan-tagged ($vlan_count VLANs)"
        return 0
    else
        echo "WARNING|$vm_uuid|$vm_name|network-isolation|no-vlan-tagging (using native network)"
        return 1
    fi
}

check_vm_network_rate_limit() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check if rate limiting is configured
    local vifs=$(xe vif-list vm-uuid="$vm_uuid" params=uuid --minimal 2>/dev/null | tr ',' '\n')
    
    local rate_limited=0
    for vif in $vifs; do
        local rate=$(xe vif-list uuid="$vif" params=qos-algorithm-type --minimal 2>/dev/null || echo "none")
        if [ "$rate" != "none" ] && [ -n "$rate" ]; then
            ((rate_limited++))
        fi
    done
    
    if [ "$rate_limited" -gt 0 ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|network-rate-limiting|enabled ($rate_limited VIFs)"
        return 0
    else
        echo "WARNING|$vm_uuid|$vm_name|network-rate-limiting|not-configured"
        return 1
    fi
}

################################################################################
# Device Isolation Checks
################################################################################

check_vm_pci_passthrough() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check for PCI device passthrough
    local pci_devices=$(xe vm-list uuid="$vm_uuid" params=pci --minimal 2>/dev/null)
    
    if [ -z "$pci_devices" ] || [ "$pci_devices" = "" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|pci-passthrough|none-assigned"
        return 0
    else
        # PCI passthrough is configured - verify it's authorized
        echo "WARNING|$vm_uuid|$vm_name|pci-passthrough|devices-assigned ($pci_devices) - verify authorization"
        return 1
    fi
}

check_vm_sriov_config() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check for SR-IOV VF assignments
    local gpu_devices=$(xe vm-list uuid="$vm_uuid" params=gpu-group --minimal 2>/dev/null)
    
    if [ -z "$gpu_devices" ] || [ "$gpu_devices" = "" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|sr-iov|none-assigned"
        return 0
    else
        echo "WARNING|$vm_uuid|$vm_name|sr-iov|gpu-devices-assigned - verify security policies"
        return 1
    fi
}

check_vm_usb_passthrough() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check BIOS settings for USB passthrough
    local bios_custom=$(xe vm-list uuid="$vm_uuid" params=bios-strings --minimal 2>/dev/null)
    
    if echo "$bios_custom" | grep -qi "usb"; then
        echo "NON_COMPLIANT|$vm_uuid|$vm_name|usb-passthrough|enabled"
        return 1
    else
        echo "COMPLIANT|$vm_uuid|$vm_name|usb-passthrough|disabled"
        return 0
    fi
}

################################################################################
# Inter-VM Communication Checks
################################################################################

check_inter_vm_communication() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Check if VM has security policy restricting inter-VM communication
    local acl_policy=$(xe vm-list uuid="$vm_uuid" params=other-config --minimal 2>/dev/null | grep -o "security-acl=[^ \"]*" || true)
    
    if [ -n "$acl_policy" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|inter-vm-acl|policy-configured"
        return 0
    else
        echo "INFO|$vm_uuid|$vm_name|inter-vm-acl|no-policy (default allow)"
        return 0
    fi
}

################################################################################
# Memory Isolation Checks
################################################################################

check_memory_overcommit_isolation() {
    local vm_uuid="$1"
    local vm_name=$(get_vm_name "$vm_uuid")
    
    # Get VM memory configuration
    local mem_requested=$(xe vm-list uuid="$vm_uuid" params=memory-static-max --minimal 2>/dev/null)
    local mem_allocated=$(xe vm-list uuid="$vm_uuid" params=memory-dynamic-max --minimal 2>/dev/null)
    
    if [ "$mem_requested" = "$mem_allocated" ]; then
        echo "COMPLIANT|$vm_uuid|$vm_name|memory-isolation|no-overcommit"
        return 0
    else
        echo "INFO|$vm_uuid|$vm_name|memory-isolation|dynamic-allocation ($mem_allocated/$mem_requested)"
        return 0
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
    print_status INFO "Starting Guest Isolation Check"
    
    validate_xe_available
    
    # Print header
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
        print_status WARNING "No VMs found"
        return 0
    fi
    
    # Run checks for each VM
    for vm_uuid in $vm_uuids; do
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "network" ]; then
            local result=$(check_vm_network_isolation "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
            [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "network" ]; then
            local result=$(check_vm_network_rate_limit "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "device" ]; then
            local result=$(check_vm_pci_passthrough "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
            [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "sr-iov" ]; then
            local result=$(check_vm_sriov_config "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "device" ]; then
            local result=$(check_vm_usb_passthrough "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
            [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "network" ]; then
            local result=$(check_inter_vm_communication "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
        fi
        
        if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "memory" ]; then
            local result=$(check_memory_overcommit_isolation "$vm_uuid")
            case "$OUTPUT_FORMAT" in
                text) format_text_output "$result" ;;
                json) format_json_output "$result" ;;
                csv) format_csv_output "$result" ;;
            esac
        fi
    done
    
    print_status INFO "Guest Isolation Check Complete"
    print_status INFO "Compliant checks: $compliant_count"
    print_status INFO "Non-compliant checks: $non_compliant_count"
}

# Parse arguments
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
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

main
exit $?
