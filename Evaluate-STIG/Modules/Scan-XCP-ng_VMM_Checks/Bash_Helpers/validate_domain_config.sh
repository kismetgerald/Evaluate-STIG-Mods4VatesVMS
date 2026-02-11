#!/bin/bash
################################################################################
# validate_domain_config.sh - XCP-ng Domain Security Configuration Validator
################################################################################
# Purpose: Verifies Dom0 domain security, user permissions, and authentication
#
# Usage: ./validate_domain_config.sh [OPTIONS]
#   --check TYPE        Check specific aspect (auth|users|permissions|selinux|all)
#   --verbose           Enable verbose output
#   --output FORMAT     Output format (text|json|csv)
#
# Description:
#   This script validates:
#   - User account security policies
#   - File permission controls
#   - Authentication mechanisms
#   - SELinux/AppArmor enforcement (if present)
#   - Privilege escalation controls
################################################################################

set -o pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/domain-config-check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
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

check_root_access() {
    if [ "$EUID" -ne 0 ]; then
        print_status WARNING "Some checks require root privileges"
    fi
}

################################################################################
# User Account Checks
################################################################################

check_empty_password() {
    local users_with_empty=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow 2>/dev/null | wc -l)
    
    if [ "$users_with_empty" -eq 0 ]; then
        echo "COMPLIANT|system|users|empty-passwords|no empty passwords found"
        return 0
    else
        echo "NON_COMPLIANT|system|users|empty-passwords|$users_with_empty users have empty passwords"
        return 1
    fi
}

check_default_accounts_disabled() {
    local disabled_count=0
    local default_accounts=("bin" "daemon" "adm" "lp" "sync" "shutdown" "halt" "news" "uucp" "operator" "games")
    
    for account in "${default_accounts[@]}"; do
        local status=$(getent passwd "$account" 2>/dev/null | awk -F: '{print $7}')
        if [ -n "$status" ]; then
            if [ "$status" = "/usr/sbin/nologin" ] || [ "$status" = "/bin/false" ]; then
                ((disabled_count++))
            fi
        fi
    done
    
    if [ "$disabled_count" -ge 8 ]; then
        echo "COMPLIANT|system|users|default-accounts-disabled|$disabled_count/11 disabled"
        return 0
    else
        echo "WARNING|system|users|default-accounts-disabled|only $disabled_count/11 disabled"
        return 1
    fi
}

check_user_umask() {
    local root_umask=$(grep "^umask" /root/.bashrc 2>/dev/null)
    
    if echo "$root_umask" | grep -q "077\|0077"; then
        echo "COMPLIANT|system|users|root-umask|0077 configured"
        return 0
    else
        echo "NON_COMPLIANT|system|users|root-umask|not properly configured"
        return 1
    fi
}

check_password_policy() {
    local min_length=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    
    if [ -z "$min_length" ]; then
        min_length=$(grep "^minlen" /etc/pam.d/system-auth 2>/dev/null | grep -o "minlen=[0-9]*" | cut -d= -f2)
    fi
    
    if [ -n "$min_length" ] && [ "$min_length" -ge 14 ]; then
        echo "COMPLIANT|system|users|password-minlen|$min_length characters required"
        return 0
    else
        echo "WARNING|system|users|password-minlen|minimum length not enforced (current: ${min_length:-not set})"
        return 1
    fi
}

################################################################################
# File Permission Checks
################################################################################

check_critical_file_permissions() {
    local files=(
        "/etc/passwd:0644"
        "/etc/shadow:0640"
        "/etc/group:0644"
        "/etc/gshadow:0640"
        "/etc/ssh/sshd_config:0600"
        "/boot/grub/grub.cfg:0600"
    )
    
    local compliant=0
    for file_perm in "${files[@]}"; do
        local file="${file_perm%:*}"
        local expected_perm="${file_perm#*:}"
        
        if [ -f "$file" ]; then
            local actual_perm=$(stat -c '%a' "$file" 2>/dev/null)
            if [ "$actual_perm" = "$expected_perm" ]; then
                ((compliant++))
            fi
        fi
    done
    
    if [ "$compliant" -ge 4 ]; then
        echo "COMPLIANT|system|permissions|critical-files|$compliant/${#files[@]} compliant"
        return 0
    else
        echo "WARNING|system|permissions|critical-files|$compliant/${#files[@]} compliant"
        return 1
    fi
}

check_suid_binaries() {
    local suid_count=$(find /usr/bin /usr/sbin -perm -4000 2>/dev/null | wc -l)
    
    # Expected SUID binaries (varies by distro)
    local expected_max=20
    
    if [ "$suid_count" -le "$expected_max" ]; then
        echo "COMPLIANT|system|permissions|suid-binaries|$suid_count SUID binaries found"
        return 0
    else
        echo "WARNING|system|permissions|suid-binaries|$suid_count SUID binaries found (threshold: $expected_max)"
        return 1
    fi
}

check_world_writable() {
    local world_writable=$(find / -xdev -type f -perm -002 2>/dev/null | grep -v "/proc\|/sys\|/dev" | wc -l)
    
    if [ "$world_writable" -eq 0 ]; then
        echo "COMPLIANT|system|permissions|world-writable|no world-writable files"
        return 0
    else
        echo "NON_COMPLIANT|system|permissions|world-writable|$world_writable files found"
        return 1
    fi
}

################################################################################
# Authentication Checks
################################################################################

check_sudo_configuration() {
    if [ -f /etc/sudoers ]; then
        # Check if sudoers has audit logging configured
        local audit_log=$(grep -c "log_" /etc/sudoers 2>/dev/null || echo 0)
        
        if [ "$audit_log" -gt 0 ]; then
            echo "COMPLIANT|system|auth|sudo-logging|audit logging enabled"
            return 0
        else
            echo "WARNING|system|auth|sudo-logging|audit logging not configured"
            return 1
        fi
    else
        echo "INFO|system|auth|sudo-configuration|sudoers not found"
        return 0
    fi
}

check_ssh_root_login() {
    if [ -f /etc/ssh/sshd_config ]; then
        local permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
        
        if [ "$permit_root" = "no" ] || [ "$permit_root" = "without-password" ]; then
            echo "COMPLIANT|system|auth|ssh-root-login|disabled ($permit_root)"
            return 0
        else
            echo "NON_COMPLIANT|system|auth|ssh-root-login|enabled or misconfigured ($permit_root)"
            return 1
        fi
    else
        echo "ERROR|system|auth|ssh-config|sshd_config not found"
        return 1
    fi
}

check_ssh_protocol_version() {
    if [ -f /etc/ssh/sshd_config ]; then
        local protocol=$(grep "^Protocol" /etc/ssh/sshd_config | awk '{print $2}')
        
        if [ "$protocol" = "2" ] || [ -z "$protocol" ]; then
            echo "COMPLIANT|system|auth|ssh-protocol|2 (or default v2)"
            return 0
        else
            echo "NON_COMPLIANT|system|auth|ssh-protocol|$protocol (SSHv1 detected)"
            return 1
        fi
    else
        echo "ERROR|system|auth|ssh-config|sshd_config not found"
        return 1
    fi
}

check_password_aging() {
    local max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    
    if [ -n "$max_days" ] && [ "$max_days" -le 90 ]; then
        echo "COMPLIANT|system|auth|password-aging|$max_days days maximum"
        return 0
    else
        echo "WARNING|system|auth|password-aging|not properly configured (current: ${max_days:-not set})"
        return 1
    fi
}

################################################################################
# SELinux/AppArmor Checks
################################################################################

check_selinux_status() {
    if command -v getenforce &> /dev/null; then
        local selinux_status=$(getenforce 2>/dev/null)
        
        if [ "$selinux_status" = "Enforcing" ]; then
            echo "COMPLIANT|system|mac|selinux-status|Enforcing"
            return 0
        elif [ "$selinux_status" = "Permissive" ]; then
            echo "WARNING|system|mac|selinux-status|Permissive (not enforcing)"
            return 1
        else
            echo "INFO|system|mac|selinux-status|Disabled"
            return 0
        fi
    else
        echo "INFO|system|mac|selinux|not installed"
        return 0
    fi
}

check_apparmor_status() {
    if command -v aa-status &> /dev/null; then
        local apparmor_status=$(aa-status --enabled 2>&1)
        
        if [ $? -eq 0 ]; then
            echo "COMPLIANT|system|mac|apparmor-status|enabled"
            return 0
        else
            echo "WARNING|system|mac|apparmor-status|disabled or not loaded"
            return 1
        fi
    else
        echo "INFO|system|mac|apparmor|not installed"
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
    local category=$(echo "$check_result" | cut -d'|' -f3)
    local check=$(echo "$check_result" | cut -d'|' -f4)
    local result=$(echo "$check_result" | cut -d'|' -f5-)
    
    printf "%-15s %-10s %-15s %-25s %s\n" "$status" "$scope" "$category" "$check" "$result"
}

format_json_output() {
    local check_result="$1"
    local status=$(echo "$check_result" | cut -d'|' -f1)
    local scope=$(echo "$check_result" | cut -d'|' -f2)
    local category=$(echo "$check_result" | cut -d'|' -f3)
    local check=$(echo "$check_result" | cut -d'|' -f4)
    local result=$(echo "$check_result" | cut -d'|' -f5-)
    
    cat <<EOF
{
  "status": "$status",
  "scope": "$scope",
  "category": "$category",
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
    print_status INFO "Starting Domain Configuration Validation"
    
    check_root_access
    
    # Print header
    case "$OUTPUT_FORMAT" in
        text)
            printf "%-15s %-10s %-15s %-25s %s\n" "STATUS" "SCOPE" "CATEGORY" "CHECK" "RESULT"
            printf "%s\n" "$(printf '=%.0s' {1..100})"
            ;;
        csv)
            echo "status,scope,category,check,result"
            ;;
    esac
    
    local compliant_count=0
    local non_compliant_count=0
    
    # Run authentication checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "auth" ]; then
        local result=$(check_ssh_root_login)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_ssh_protocol_version)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_password_aging)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
    fi
    
    # Run user checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "users" ]; then
        local result=$(check_empty_password)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_default_accounts_disabled)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        
        result=$(check_user_umask)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
    fi
    
    # Run permission checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "permissions" ]; then
        local result=$(check_critical_file_permissions)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_suid_binaries)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
    fi
    
    # Run SELinux/AppArmor checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "selinux" ]; then
        local result=$(check_selinux_status)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        
        result=$(check_apparmor_status)
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
    fi
    
    print_status INFO "Domain Configuration Validation Complete"
    print_status INFO "Compliant checks: $compliant_count"
    print_status INFO "Non-compliant checks: $non_compliant_count"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
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
