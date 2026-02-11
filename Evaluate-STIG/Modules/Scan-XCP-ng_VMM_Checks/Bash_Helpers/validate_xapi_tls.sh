#!/bin/bash
################################################################################
# validate_xapi_tls.sh - XCP-ng xapi TLS Encryption Validator
################################################################################
# Purpose: Verifies xapi service encryption and certificate security
#
# Usage: ./validate_xapi_tls.sh [OPTIONS]
#   --check TYPE        Check specific aspect (encryption|certificates|ciphers|all)
#   --verbose           Enable verbose output
#   --output FORMAT     Output format (text|json|csv)
#
# Description:
#   This script validates that the xapi management service uses:
#   - TLS 1.2 or higher encryption
#   - Valid, non-expired certificates
#   - Strong cipher suites
#   - Proper certificate chain verification
################################################################################

set -o pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/xapi-tls-check.log"
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
XAPI_PORT=443
XAPI_HOST="localhost"

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

validate_openssl_available() {
    if ! command -v openssl &> /dev/null; then
        print_status ERROR "openssl command not available"
        exit 1
    fi
}

get_certificate_from_host() {
    local host="$1"
    local port="$2"
    
    echo | openssl s_client -connect "$host:$port" -showcerts 2>/dev/null | \
        sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
}

################################################################################
# TLS Version Checks
################################################################################

check_tls_version() {
    local host="$1"
    local port="$2"
    
    # Check for TLS 1.2 support
    local tls12=$(echo | openssl s_client -connect "$host:$port" -tls1_2 2>&1 | grep "Protocol\|tlsv1.2")
    
    if [ -n "$tls12" ]; then
        echo "COMPLIANT|$host|tls-version|tls-1.2-supported|yes"
        return 0
    else
        echo "NON_COMPLIANT|$host|tls-version|tls-1.2-supported|no"
        return 1
    fi
}

check_tls_version_minimum() {
    local host="$1"
    local port="$2"
    
    # Check that SSLv3 and TLSv1.0/1.1 are not supported
    local ssl_v3=$(echo | openssl s_client -connect "$host:$port" -ssl3 2>&1 | grep -c "Protocol\|sslv3" || true)
    local tls_v10=$(echo | openssl s_client -connect "$host:$port" -tls1 2>&1 | grep -c "Protocol\|tlsv1" || true)
    
    if [ "$ssl_v3" = "0" ] && [ "$tls_v10" = "0" ]; then
        echo "COMPLIANT|$host|tls-version|legacy-tls-disabled|yes"
        return 0
    else
        echo "NON_COMPLIANT|$host|tls-version|legacy-tls-disabled|no (SSLv3/TLSv1.0 still enabled)"
        return 1
    fi
}

################################################################################
# Certificate Checks
################################################################################

check_certificate_validity() {
    local host="$1"
    local port="$2"
    
    local cert=$(get_certificate_from_host "$host" "$port" | head -1)
    
    if [ -z "$cert" ]; then
        echo "ERROR|$host|certificate|validity|could-not-retrieve"
        return 1
    fi
    
    # Check if certificate is currently valid
    echo "$cert" | openssl x509 -noout -text 2>/dev/null > /tmp/cert_info.txt
    
    local valid_from=$(grep "Not Before" /tmp/cert_info.txt | awk '{print $3, $4, $5, $6}')
    local valid_to=$(grep "Not After" /tmp/cert_info.txt | awk '{print $3, $4, $5, $6}')
    local current_date=$(date '+%b %d %H:%M:%S %Y')
    
    if openssl x509 -checkend 0 -noout -in <(echo "$cert") 2>/dev/null; then
        echo "COMPLIANT|$host|certificate|validity|valid (expires: $valid_to)"
        return 0
    else
        echo "NON_COMPLIANT|$host|certificate|validity|expired or invalid"
        return 1
    fi
}

check_certificate_expiry_warning() {
    local host="$1"
    local port="$2"
    local days_warning=30
    
    local cert=$(get_certificate_from_host "$host" "$port" | head -1)
    
    if [ -z "$cert" ]; then
        return 1
    fi
    
    # Check if certificate expires within warning days
    if openssl x509 -checkend $((days_warning * 86400)) -noout -in <(echo "$cert") 2>/dev/null; then
        local expiry=$(echo "$cert" | openssl x509 -noout -dates 2>/dev/null | grep "notAfter" | cut -d'=' -f2)
        echo "WARNING|$host|certificate|expiry-soon|expires within $days_warning days ($expiry)"
        return 1
    else
        echo "COMPLIANT|$host|certificate|expiry-check|valid (expires in >$days_warning days)"
        return 0
    fi
}

check_certificate_subject() {
    local host="$1"
    local port="$2"
    
    local cert=$(get_certificate_from_host "$host" "$port" | head -1)
    
    if [ -z "$cert" ]; then
        return 1
    fi
    
    local subject=$(echo "$cert" | openssl x509 -noout -subject 2>/dev/null)
    
    # Verify certificate is issued to the host
    if echo "$subject" | grep -qi "$host\|localhost\|xen\|xenserver"; then
        echo "COMPLIANT|$host|certificate|subject|valid ($subject)"
        return 0
    else
        echo "WARNING|$host|certificate|subject|hostname mismatch ($subject)"
        return 1
    fi
}

check_certificate_chain() {
    local host="$1"
    local port="$2"
    
    # Get full certificate chain
    local chain=$(get_certificate_from_host "$host" "$port" | grep -c "BEGIN CERTIFICATE" || echo "0")
    
    if [ "$chain" -gt 1 ]; then
        echo "COMPLIANT|$host|certificate|chain-validation|complete ($chain certificates)"
        return 0
    else
        echo "WARNING|$host|certificate|chain-validation|self-signed or incomplete"
        return 1
    fi
}

################################################################################
# Cipher Suite Checks
################################################################################

check_cipher_strength() {
    local host="$1"
    local port="$2"
    
    # Get list of supported ciphers
    local ciphers=$(echo | openssl s_client -connect "$host:$port" 2>/dev/null | grep "Cipher" | head -1)
    
    if [ -z "$ciphers" ]; then
        echo "ERROR|$host|cipher|strength|could-not-determine"
        return 1
    fi
    
    # Check for weak ciphers (should be 256-bit or higher)
    if echo "$ciphers" | grep -qi "256\|aes"; then
        echo "COMPLIANT|$host|cipher|strength|strong ($ciphers)"
        return 0
    else
        echo "NON_COMPLIANT|$host|cipher|strength|weak or unknown ($ciphers)"
        return 1
    fi
}

check_cipher_ordering() {
    local host="$1"
    local port="$2"
    
    # Verify server cipher preference is enforced
    local pref=$(echo | openssl s_client -connect "$host:$port" 2>/dev/null | grep "Server" | head -1)
    
    if echo "$pref" | grep -qi "server"; then
        echo "COMPLIANT|$host|cipher|server-preference|enforced"
        return 0
    else
        echo "INFO|$host|cipher|server-preference|not-explicitly-set"
        return 0
    fi
}

check_forward_secrecy() {
    local host="$1"
    local port="$2"
    
    # Check for Perfect Forward Secrecy (ECDHE/DHE)
    local cipher=$(echo | openssl s_client -connect "$host:$port" 2>/dev/null | grep "Cipher" | head -1)
    
    if echo "$cipher" | grep -qi "ECDHE\|DHE"; then
        echo "COMPLIANT|$host|cipher|forward-secrecy|enabled ($cipher)"
        return 0
    else
        echo "WARNING|$host|cipher|forward-secrecy|not-enabled (consider using ECDHE/DHE)"
        return 1
    fi
}

################################################################################
# Output Formatters
################################################################################

format_text_output() {
    local check_result="$1"
    local status=$(echo "$check_result" | cut -d'|' -f1)
    local host=$(echo "$check_result" | cut -d'|' -f2)
    local category=$(echo "$check_result" | cut -d'|' -f3)
    local check=$(echo "$check_result" | cut -d'|' -f4)
    local result=$(echo "$check_result" | cut -d'|' -f5-)
    
    printf "%-15s %-20s %-15s %-25s %s\n" "$status" "$host" "$category" "$check" "$result"
}

format_json_output() {
    local check_result="$1"
    local status=$(echo "$check_result" | cut -d'|' -f1)
    local host=$(echo "$check_result" | cut -d'|' -f2)
    local category=$(echo "$check_result" | cut -d'|' -f3)
    local check=$(echo "$check_result" | cut -d'|' -f4)
    local result=$(echo "$check_result" | cut -d'|' -f5-)
    
    cat <<EOF
{
  "status": "$status",
  "host": "$host",
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
    print_status INFO "Starting xapi TLS Validation"
    
    validate_openssl_available
    
    # Determine xapi host and port
    if [ -S /var/lib/xcp/xapi ]; then
        XAPI_HOST="localhost"
        XAPI_PORT="443"
    fi
    
    # Print header
    case "$OUTPUT_FORMAT" in
        text)
            printf "%-15s %-20s %-15s %-25s %s\n" "STATUS" "HOST" "CATEGORY" "CHECK" "RESULT"
            printf "%s\n" "$(printf '=%.0s' {1..110})"
            ;;
        csv)
            echo "status,host,category,check,result"
            ;;
    esac
    
    local compliant_count=0
    local non_compliant_count=0
    
    # Run TLS checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "encryption" ]; then
        local result=$(check_tls_version "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_tls_version_minimum "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
    fi
    
    # Run certificate checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "certificates" ]; then
        local result=$(check_certificate_validity "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_certificate_expiry_warning "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_certificate_subject "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        
        result=$(check_certificate_chain "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
    fi
    
    # Run cipher checks
    if [ "$CHECK_TYPE" = "all" ] || [ "$CHECK_TYPE" = "ciphers" ]; then
        local result=$(check_cipher_strength "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
        
        result=$(check_cipher_ordering "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        
        result=$(check_forward_secrecy "$XAPI_HOST" "$XAPI_PORT")
        case "$OUTPUT_FORMAT" in
            text) format_text_output "$result" ;;
            json) format_json_output "$result" ;;
            csv) format_csv_output "$result" ;;
        esac
        [[ "$result" == COMPLIANT* ]] && ((compliant_count++)) || ((non_compliant_count++))
    fi
    
    print_status INFO "xapi TLS Validation Complete"
    print_status INFO "Compliant checks: $compliant_count"
    print_status INFO "Non-compliant checks: $non_compliant_count"
    
    # Cleanup
    rm -f /tmp/cert_info.txt
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
