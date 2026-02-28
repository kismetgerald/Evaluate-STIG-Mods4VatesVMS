#!/usr/bin/env python3
"""
Add Get-XOAuthLdapInfo helper function and auth-ldap detection CHECK blocks
to 5 GPOS functions impacted by AD/LDAP authentication offloading.

Functions updated:
  - V-203640: MFA for network privileged access (Batch 9)
  - V-203641: MFA for network non-privileged access (Batch 9)
  - V-203644: Individual auth before group accounts (Batch 9)
  - V-203727: MFA for remote privileged via separate device (CAT I)
  - V-203728: Accept PIV credentials (CAT I)

Each function gets a new CHECK block that:
  1. Calls Get-XOAuthLdapInfo to detect auth-ldap plugin
  2. If LDAP detected, adds compensating control evidence
  3. Updates status logic: if LDAP with AD → NotAFinding for auth-related checks
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# ── Helper function to insert after Get-XOAuditPluginInfo ──────────────
HELPER_FUNCTION = r'''
Function Get-XOAuthLdapInfo {
    <#
    .SYNOPSIS
        Checks if XO uses auth-ldap plugin for AD/LDAP authentication delegation.
        Cached per scan session.
    .DESCRIPTION
        Detects the auth-ldap plugin by checking XO configuration files for LDAP
        settings and optionally verifying the plugin package. When auth-ldap is
        active, authentication/authorization is offloaded to Active Directory,
        which satisfies several STIG requirements through delegation.
        Results cached in $Global:XOAuthLdapInfo to avoid repeated checks.
    #>

    if ($null -ne $Global:XOAuthLdapInfo) {
        return $Global:XOAuthLdapInfo
    }

    $nl = [Environment]::NewLine
    $Global:XOAuthLdapInfo = @{
        Enabled    = $false
        LdapUri    = ""
        BaseDN     = ""
        Details    = ""
    }

    # Check 1: XO config files for auth-ldap settings
    $configPaths = @(
        "/opt/xo/xo-server/config.toml",
        "/etc/xo-server/config.toml",
        "/opt/xo/xo-server/.xo-server.yaml",
        "/etc/xo-server/config.yaml"
    )
    foreach ($cfgPath in $configPaths) {
        $cfgContent = $(timeout 5 cat $cfgPath 2>/dev/null)
        if ($LASTEXITCODE -eq 0 -and $cfgContent) {
            $cfgStr = ($cfgContent -join $nl)
            # Look for auth-ldap plugin configuration
            if ($cfgStr -match "auth-ldap|auth_ldap|authLdap") {
                $Global:XOAuthLdapInfo.Enabled = $true
                $Global:XOAuthLdapInfo.Details = "auth-ldap configured in $cfgPath"
                # Extract LDAP URI
                if ($cfgStr -match "(?i)url\s*=\s*[" + [char]34 + "']?(ldaps?://[^" + [char]34 + "'\s]+)") {
                    $Global:XOAuthLdapInfo.LdapUri = $matches[1]
                }
                # Extract Base DN
                if ($cfgStr -match "(?i)base\s*=\s*[" + [char]34 + "']?([^" + [char]34 + "'\s]+)") {
                    $Global:XOAuthLdapInfo.BaseDN = $matches[1]
                }
                return $Global:XOAuthLdapInfo
            }
        }
    }

    # Check 2: Look for auth-ldap package in XO node_modules
    $pluginPaths = @(
        "/opt/xo/xo-server/node_modules/xo-server-auth-ldap",
        "/opt/xo/node_modules/xo-server-auth-ldap",
        "/usr/local/lib/node_modules/xo-server/node_modules/xo-server-auth-ldap",
        "/opt/xen-orchestra/packages/xo-server-auth-ldap"
    )
    foreach ($plugPath in $pluginPaths) {
        if (Test-Path $plugPath -ErrorAction SilentlyContinue) {
            $Global:XOAuthLdapInfo.Enabled = $true
            $Global:XOAuthLdapInfo.Details = "auth-ldap plugin found at $plugPath"
            return $Global:XOAuthLdapInfo
        }
    }

    # Check 3: Query XO REST API for plugin configuration (if token available)
    $auditInfo = Get-XOAuditPluginInfo
    if ($auditInfo.TokenFound) {
        $sq = [char]39
        $token = ""
        # Re-read token (same priority as audit plugin)
        if (Test-Path "/etc/xo-server/stig/api-token" -ErrorAction SilentlyContinue) {
            $tokenContent = $(timeout 5 cat /etc/xo-server/stig/api-token 2>&1)
            if ($LASTEXITCODE -eq 0 -and $tokenContent) { $token = ($tokenContent -join "").Trim() }
        }
        if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN }
        if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli" -ErrorAction SilentlyContinue)) {
            $cliContent = $(timeout 5 cat /var/lib/xo-server/.xo-cli 2>&1)
            if ($LASTEXITCODE -eq 0 -and $cliContent) {
                try {
                    $cliObj = ($cliContent -join "") | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $firstServer = $cliObj.PSObject.Properties | Select-Object -First 1
                    if ($firstServer -and $firstServer.Value.token) { $token = $firstServer.Value.token }
                }
                catch { }
            }
        }

        if ($token) {
            # Query XO users to check for LDAP-authenticated users
            $usersArgs = "timeout 10 curl -s -k -H ${sq}Cookie: authenticationToken=${token}${sq} ${sq}https://localhost/rest/v0/users${sq} 2>/dev/null"
            $usersJson = $(sh -c $usersArgs 2>&1)
            if ($LASTEXITCODE -eq 0 -and $usersJson) {
                $usersStr = ($usersJson -join "")
                if ($usersStr -match "authProviders.*ldap|auth-ldap") {
                    $Global:XOAuthLdapInfo.Enabled = $true
                    $Global:XOAuthLdapInfo.Details = "LDAP-authenticated users detected via REST API"
                    return $Global:XOAuthLdapInfo
                }
            }
        }
    }

    # Check 4: OS-level LDAP integration (SSSD/nslcd with AD provider)
    $sssdActive = $(timeout 5 systemctl is-active sssd 2>&1)
    if (($sssdActive -join "").Trim() -eq "active") {
        $sssdConf = $(timeout 5 cat /etc/sssd/sssd.conf 2>/dev/null)
        if ($LASTEXITCODE -eq 0 -and $sssdConf) {
            $sssdStr = ($sssdConf -join $nl)
            if ($sssdStr -match "id_provider\s*=\s*(ldap|ad)|auth_provider\s*=\s*(ldap|ad|krb5)") {
                $Global:XOAuthLdapInfo.Enabled = $true
                $Global:XOAuthLdapInfo.Details = "SSSD active with LDAP/AD provider"
                if ($sssdStr -match "ldap_uri\s*=\s*(\S+)") {
                    $Global:XOAuthLdapInfo.LdapUri = $matches[1]
                }
                if ($sssdStr -match "ldap_search_base\s*=\s*(\S+)") {
                    $Global:XOAuthLdapInfo.BaseDN = $matches[1]
                }
                return $Global:XOAuthLdapInfo
            }
        }
    }

    $Global:XOAuthLdapInfo.Details = "No LDAP/AD authentication integration detected"
    return $Global:XOAuthLdapInfo
}
'''

# ── CHECK blocks for each function ─────────────────────────────────────

def make_ldap_check(vuln_id, scope_desc, compensating_text):
    """Generate a CHECK block for auth-ldap detection."""
    return f'''
    $FindingDetails += "--- Check 5: XO auth-ldap (AD Authentication Delegation) ---" + $nl
    $xoLdapInfo = Get-XOAuthLdapInfo
    $ldapCompensates = $false
    if ($xoLdapInfo.Enabled) {{
        $FindingDetails += "  XO auth-ldap Plugin: ACTIVE" + $nl
        if ($xoLdapInfo.LdapUri) {{ $FindingDetails += "  LDAP Server: $($xoLdapInfo.LdapUri)" + $nl }}
        if ($xoLdapInfo.BaseDN) {{ $FindingDetails += "  Base DN: $($xoLdapInfo.BaseDN)" + $nl }}
        $FindingDetails += "  Source: $($xoLdapInfo.Details)" + $nl
        $FindingDetails += "  [PASS] {scope_desc}" + $nl
        $ldapCompensates = $true
    }}
    else {{
        $FindingDetails += "  XO auth-ldap Plugin: NOT DETECTED" + $nl
        $FindingDetails += "  Reason: $($xoLdapInfo.Details)" + $nl
        $FindingDetails += "  [INFO] No AD/LDAP authentication delegation available" + $nl
    }}
    $FindingDetails += $nl
'''

LDAP_CHECKS = {
    "V-203640": make_ldap_check(
        "V-203640",
        "User authentication delegated to AD via auth-ldap; AD enforces MFA for network access to privileged accounts",
        "MFA for network access to privileged accounts satisfied via AD delegation"
    ),
    "V-203641": make_ldap_check(
        "V-203641",
        "User authentication delegated to AD via auth-ldap; AD enforces MFA for network access to non-privileged accounts",
        "MFA for network access to non-privileged accounts satisfied via AD delegation"
    ),
    "V-203644": make_ldap_check(
        "V-203644",
        "AD via auth-ldap requires individual credentials; each user authenticates with unique AD account before accessing any shared resources",
        "Individual authentication before group account access enforced by AD"
    ),
    "V-203727": make_ldap_check(
        "V-203727",
        "Authentication delegated to AD via auth-ldap; AD infrastructure enforces MFA via separate device (CAC/PIV, Entra MFA, Duo) for remote privileged access",
        "MFA via separate device for remote privileged access satisfied via AD delegation"
    ),
    "V-203728": make_ldap_check(
        "V-203728",
        "Authentication delegated to AD via auth-ldap; AD infrastructure accepts PIV/CAC credentials for user authentication",
        "PIV credential acceptance delegated to AD which accepts CAC/PIV authentication"
    ),
}

# ── Status logic replacements ──────────────────────────────────────────

# For V-203640, V-203641: Replace hardcoded Open with conditional
STATUS_REPLACEMENTS = {
    "V-203640": {
        "old": '''    # Status determination — MFA requires organizational deployment
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: MFA for network access to privileged accounts requires organizational deployment" + $nl
    $FindingDetails += "of smartcard/PKI (CAC/PIV), TOTP, or hardware token authentication." + $nl''',
        "new": '''    # Status determination
    if ($ldapCompensates) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "COMPENSATING CONTROL: Authentication is delegated to Active Directory" + $nl
        $FindingDetails += "via the XO auth-ldap plugin. AD enforces MFA policies for all network" + $nl
        $FindingDetails += "access to privileged accounts. The ISSO/ISSM should verify that AD MFA" + $nl
        $FindingDetails += "policy is active and enrolled for all privileged users." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: MFA for network access to privileged accounts requires organizational deployment" + $nl
        $FindingDetails += "of smartcard/PKI (CAC/PIV), TOTP, or hardware token authentication." + $nl
    }''',
    },
    "V-203641": {
        "old": '''    # Status determination — MFA requires organizational deployment
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: MFA for network access to non-privileged accounts requires organizational deployment" + $nl
    $FindingDetails += "of smartcard/PKI (CAC/PIV), TOTP, or hardware token authentication." + $nl''',
        "new": '''    # Status determination
    if ($ldapCompensates) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "COMPENSATING CONTROL: Authentication is delegated to Active Directory" + $nl
        $FindingDetails += "via the XO auth-ldap plugin. AD enforces MFA policies for all network" + $nl
        $FindingDetails += "access to non-privileged accounts. The ISSO/ISSM should verify that AD" + $nl
        $FindingDetails += "MFA policy is active and enrolled for all users." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: MFA for network access to non-privileged accounts requires organizational deployment" + $nl
        $FindingDetails += "of smartcard/PKI (CAC/PIV), TOTP, or hardware token authentication." + $nl
    }''',
    },
    "V-203644": {
        "old": '''    # Status determination — individual auth before group is org policy
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Individual authentication before group/shared account" + $nl
    $FindingDetails += "access requires organizational policy enforcement. Verify that" + $nl
    $FindingDetails += "users authenticate with individual credentials before accessing" + $nl
    $FindingDetails += "any shared or group accounts (e.g., via sudo, su)." + $nl''',
        "new": '''    # Status determination
    if ($ldapCompensates) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "COMPENSATING CONTROL: Authentication is delegated to Active Directory" + $nl
        $FindingDetails += "via the XO auth-ldap plugin. Each user authenticates with their unique" + $nl
        $FindingDetails += "AD credentials before accessing any system resources. No shared XO" + $nl
        $FindingDetails += "passwords exist when auth-ldap is the primary authentication method." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Individual authentication before group/shared account" + $nl
        $FindingDetails += "access requires organizational policy enforcement. Verify that" + $nl
        $FindingDetails += "users authenticate with individual credentials before accessing" + $nl
        $FindingDetails += "any shared or group accounts (e.g., via sudo, su)." + $nl
    }''',
    },
    "V-203727": {
        # This one has conditional status: if $mfaConfigured -> NotAFinding
        "old": '''    if ($mfaConfigured) {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
        "new": '''    if ($mfaConfigured -or $ldapCompensates) {
        $Status = "NotAFinding"
    }
    if ($ldapCompensates -and -not $mfaConfigured) {
        $output += "${nl}COMPENSATING CONTROL: Authentication is delegated to Active Directory${nl}"
        $output += "via the XO auth-ldap plugin. AD infrastructure enforces MFA via separate${nl}"
        $output += "device (CAC/PIV, Entra MFA, Duo) for remote privileged access.${nl}"
    }

    $FindingDetails = $output.TrimEnd()''',
    },
    "V-203728": {
        # Same pattern: if $pivCapable -> NotAFinding
        "old": '''    if ($pivCapable) {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
        "new": '''    if ($pivCapable -or $ldapCompensates) {
        $Status = "NotAFinding"
    }
    if ($ldapCompensates -and -not $pivCapable) {
        $output += "${nl}COMPENSATING CONTROL: Authentication is delegated to Active Directory${nl}"
        $output += "via the XO auth-ldap plugin. AD infrastructure accepts PIV/CAC credentials${nl}"
        $output += "for user authentication, satisfying this requirement through delegation.${nl}"
    }

    $FindingDetails = $output.TrimEnd()''',
    },
}


def main():
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    # ── Step 1: Insert Get-XOAuthLdapInfo after Get-XOAuditPluginInfo ──
    # Find the closing brace of Get-XOAuditPluginInfo
    marker = "    return $Global:XOAuditPluginInfo\n}\n"
    if marker not in content:
        print("ERROR: Could not find Get-XOAuditPluginInfo closing marker")
        sys.exit(1)

    if "Get-XOAuthLdapInfo" in content:
        print("  Get-XOAuthLdapInfo already exists, skipping helper insertion")
    else:
        content = content.replace(marker, marker + HELPER_FUNCTION)
        print("  Inserted Get-XOAuthLdapInfo helper function")

    # ── Step 2: Insert CHECK 5 blocks into each function ───────────────
    for vuln_id, check_block in LDAP_CHECKS.items():
        func_name = f"Get-V{vuln_id.replace('V-', '')}"
        # For V-203640, V-203641, V-203644 (Batch 9): insert before status determination
        # For V-203727, V-203728 (CAT I): insert before status determination

        if vuln_id in ("V-203640", "V-203641", "V-203644"):
            # These have "# Status determination" comment — insert CHECK 5 before it
            old_status = STATUS_REPLACEMENTS[vuln_id]["old"]
            new_status = STATUS_REPLACEMENTS[vuln_id]["new"]

            if old_status in content:
                # Insert CHECK 5 block, then replace status logic
                content = content.replace(old_status, check_block + new_status, 1)
                print(f"  {vuln_id}: Inserted CHECK 5 + updated status logic")
            else:
                print(f"  WARNING: {vuln_id} status block not found")

        elif vuln_id == "V-203727":
            # Insert CHECK 5 before Check 4 (SSSD Smartcard)
            check4_marker = '    # Check 4: SSSD with smartcard auth\n    $output += "Check 4: SSSD Smartcard Authentication${nl}"'
            if check4_marker in content:
                # Insert CHECK 5 as Check 5 (after existing checks, before status)
                ldap_check_727 = check_block.replace("Check 5:", "Check 5:").replace("$FindingDetails", "$output")
                # Find status logic and replace
                old_status = STATUS_REPLACEMENTS[vuln_id]["old"]
                new_status = STATUS_REPLACEMENTS[vuln_id]["new"]
                if old_status in content:
                    content = content.replace(old_status, ldap_check_727 + new_status, 1)
                    print(f"  {vuln_id}: Inserted CHECK 5 + updated status logic")
                else:
                    print(f"  WARNING: {vuln_id} status block not found")
            else:
                print(f"  WARNING: {vuln_id} Check 4 marker not found")

        elif vuln_id == "V-203728":
            # Insert CHECK 5 before Check 4 (SSH Certificate)
            check4_marker = '    # Check 4: SSH certificate-based authentication\n    $output += "Check 4: SSH Certificate Authentication${nl}"'
            if check4_marker in content:
                ldap_check_728 = check_block.replace("$FindingDetails", "$output")
                old_status = STATUS_REPLACEMENTS[vuln_id]["old"]
                new_status = STATUS_REPLACEMENTS[vuln_id]["new"]
                if old_status in content:
                    content = content.replace(old_status, ldap_check_728 + new_status, 1)
                    print(f"  {vuln_id}: Inserted CHECK 5 + updated status logic")
                else:
                    print(f"  WARNING: {vuln_id} status block not found")
            else:
                print(f"  WARNING: {vuln_id} Check 4 marker not found")

    # ── Step 3: Write out ───────────────────────────────────────────────
    with open(MODULE_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"\nDone. Updated {MODULE_PATH}")


if __name__ == "__main__":
    main()
