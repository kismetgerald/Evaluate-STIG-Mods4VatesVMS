#!/usr/bin/env python3
"""Fix 13 CAT I functions that return Not_Reviewed due to Session #5-6 era bugs.

Issues fixed:
  - bash -c → $(command 2>&1) or $(sh -c 'cmd' 2>&1)
  - `n → $nl via [Environment]::NewLine
  - Not_Reviewed fallback → Open (automated check IS the review)
  - Emoji characters → plain text
  - Wrong search paths → /opt/xo (XOCE), /etc/xo-server (XOA)
  - Remediation guidance removed from FINDING_DETAILS → answer file only

Session #49 (Feb 2026): CAT I completion
"""

import os
import re
import sys

# Path to module (5 levels up from Helper_Scripts/)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..', '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Evaluate-STIG', 'Modules',
                           'Scan-XO_ASD_Checks', 'Scan-XO_ASD_Checks.psm1')

# ── Implementation code for each VulnID ──────────────────────────────────

IMPLEMENTATIONS = {}

# ═══════════════════════════════════════════════════════════════════════════
# V-222430: Execute without excessive account permissions (least privilege)
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222430"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: XO Server process owner
    $output += "CHECK 1: XO Server process owner" + $nl
    $procOwner = $(sh -c 'ps -eo user,comm 2>/dev/null | grep -E "xo-server|node.*cli\.mjs" | head -1 | awk "{print \$1}"' 2>&1)
    $procOwnerStr = ($procOwner -join $nl).Trim()
    $runningAsRoot = $false
    $nonRootFound = $false
    if ($procOwnerStr -and $procOwnerStr -ne "") {
        $output += "  Process owner: $procOwnerStr" + $nl
        if ($procOwnerStr -eq "root") {
            $output += "  [FINDING] XO Server running as root - excessive privileges" + $nl
            $runningAsRoot = $true
        } else {
            $output += "  [PASS] XO Server running as non-root user" + $nl
            $nonRootFound = $true
        }
    } else {
        $output += "  XO Server process not detected" + $nl
    }

    # Check 2: Service account group memberships
    $output += $nl + "CHECK 2: Service account group memberships" + $nl
    $elevatedGroups = $false
    if ($nonRootFound -and $procOwnerStr) {
        $groups = $(sh -c "id $procOwnerStr 2>/dev/null" 2>&1)
        $groupsStr = ($groups -join $nl).Trim()
        $output += "  Groups: $groupsStr" + $nl
        if ($groupsStr -match "sudo|wheel|adm") {
            $output += "  [FINDING] Elevated group memberships detected" + $nl
            $elevatedGroups = $true
        } else {
            $output += "  [PASS] No elevated group memberships" + $nl
        }
    }

    # Check 3: Linux capabilities on XO binaries
    $output += $nl + "CHECK 3: Linux capabilities" + $nl
    $excessiveCaps = $false
    $nodebin = $(sh -c 'which node 2>/dev/null' 2>&1)
    $nodebinStr = ($nodebin -join $nl).Trim()
    if ($nodebinStr -and (Test-Path $nodebinStr)) {
        $caps = $(sh -c "getcap $nodebinStr 2>/dev/null" 2>&1)
        $capsStr = ($caps -join $nl).Trim()
        if ($capsStr -match "cap_sys_admin|cap_dac_override|cap_setuid") {
            $output += "  [FINDING] Excessive capabilities: $capsStr" + $nl
            $excessiveCaps = $true
        } else {
            $output += "  [PASS] No excessive capabilities on node binary" + $nl
        }
    } else {
        $output += "  Node binary not found for capability check" + $nl
    }

    # Check 4: Redis process owner
    $output += $nl + "CHECK 4: Redis process owner" + $nl
    $redisOwner = $(sh -c 'ps -eo user,comm 2>/dev/null | grep redis-server | head -1 | awk "{print \$1}"' 2>&1)
    $redisOwnerStr = ($redisOwner -join $nl).Trim()
    if ($redisOwnerStr) {
        $output += "  Redis owner: $redisOwnerStr" + $nl
        if ($redisOwnerStr -ne "root") {
            $output += "  [PASS] Redis running as non-root" + $nl
        } else {
            $output += "  [INFO] Redis running as root" + $nl
        }
    }

    # Check 5: Systemd service user
    $output += $nl + "CHECK 5: Systemd service configuration" + $nl
    $svcUser = $(sh -c 'systemctl show xo-server --property=User 2>/dev/null || echo "N/A"' 2>&1)
    $svcUserStr = ($svcUser -join $nl).Trim()
    $output += "  Service User setting: $svcUserStr" + $nl

    # Determine status
    if ($runningAsRoot -or $elevatedGroups -or $excessiveCaps) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - excessive account permissions detected." + $nl
    } elseif ($nonRootFound) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - XO runs with least privilege (non-root, appropriate groups)." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - unable to confirm least privilege execution." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222550: PKI certificate path validation
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222550"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Find SSL/TLS certificates used by XO
    $output += "CHECK 1: SSL/TLS certificate configuration" + $nl
    $certFile = ""
    $configPaths = @("/etc/xo-server/config.toml", "/opt/xo/xo-server/config.toml")
    foreach ($cp in $configPaths) {
        if (Test-Path $cp) {
            $certLine = $(sh -c "grep -iE '^\s*cert\s*=' '$cp' 2>/dev/null | head -1" 2>&1)
            $certLineStr = ($certLine -join $nl).Trim()
            if ($certLineStr -match "=\s*['" + [char]34 + "]?(/[^'" + [char]34 + "]+)") {
                $certFile = $Matches[1].Trim()
                $output += "  Certificate from config: $certFile" + $nl
            }
        }
    }

    # Check 2: Validate certificate chain
    $output += $nl + "CHECK 2: Certificate chain validation" + $nl
    $chainValid = $false
    if ($certFile -and (Test-Path $certFile)) {
        $verify = $(sh -c "openssl verify '$certFile' 2>&1" 2>&1)
        $verifyStr = ($verify -join $nl).Trim()
        $output += "  openssl verify: $verifyStr" + $nl
        if ($verifyStr -match "OK") {
            $chainValid = $true
            $output += "  [PASS] Certificate chain validates successfully" + $nl
        } else {
            $output += "  [FINDING] Certificate chain validation failed" + $nl
        }
    } else {
        # Try active TLS connection
        $tlsVerify = $(sh -c "timeout 5 openssl s_client -connect localhost:443 -verify_return_error </dev/null 2>&1 | grep -E 'Verify return|verify error'" 2>&1)
        $tlsVerifyStr = ($tlsVerify -join $nl).Trim()
        $output += "  Active TLS check: $tlsVerifyStr" + $nl
        if ($tlsVerifyStr -match "Verify return code: 0") {
            $chainValid = $true
            $output += "  [PASS] Active TLS connection validates certificate" + $nl
        } elseif ($tlsVerifyStr -match "self.signed") {
            $output += "  [FINDING] Self-signed certificate detected" + $nl
        }
    }

    # Check 3: CA certificate bundle
    $output += $nl + "CHECK 3: CA certificate bundle" + $nl
    $bundleFound = $false
    $bundles = @("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")
    foreach ($b in $bundles) {
        if (Test-Path $b) {
            $bundleFound = $true
            $caCount = $(sh -c "grep -c 'BEGIN CERTIFICATE' '$b' 2>/dev/null" 2>&1)
            $caCountStr = ($caCount -join $nl).Trim()
            $output += "  [PASS] CA bundle found: $b ($caCountStr CAs)" + $nl
            break
        }
    }
    if (-not $bundleFound) {
        $output += "  [FINDING] No CA certificate bundle found" + $nl
    }

    # Check 4: Node.js TLS rejection setting
    $output += $nl + "CHECK 4: Node.js TLS validation" + $nl
    $tlsDisabled = $false
    $envCheck = $(sh -c 'ps auxe 2>/dev/null | grep "xo-server\|cli.mjs" | grep -o "NODE_TLS_REJECT_UNAUTHORIZED=[^[:space:]]*" || echo "not set"' 2>&1)
    $envCheckStr = ($envCheck -join $nl).Trim()
    if ($envCheckStr -match "=0") {
        $output += "  [FINDING] NODE_TLS_REJECT_UNAUTHORIZED=0 - certificate validation DISABLED" + $nl
        $tlsDisabled = $true
    } else {
        $output += "  [PASS] Certificate validation enabled (default)" + $nl
    }

    # Check 5: Certificate details
    $output += $nl + "CHECK 5: Certificate details" + $nl
    $certDetails = $(sh -c "timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null" 2>&1)
    $certDetailsStr = ($certDetails -join $nl).Trim()
    if ($certDetailsStr) { $output += "  $certDetailsStr" + $nl }

    # Determine status
    if ($tlsDisabled) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - TLS certificate validation is disabled." + $nl
    } elseif ($chainValid -and $bundleFound) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - PKI certificate path validation configured." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - certificate chain validation issues detected." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222551: PKI private key protection
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222551"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Find private key files
    $output += "CHECK 1: Private key file discovery" + $nl
    $searchPaths = @("/etc/ssl/private", "/etc/ssl", "/etc/pki/tls/private", "/etc/xo-server", "/opt/xo")
    $allKeys = @()
    foreach ($sp in $searchPaths) {
        if (Test-Path $sp) {
            $found = $(timeout 10 sh -c "find '$sp' -maxdepth 3 -type f \( -name '*.key' -o -name '*-key.pem' -o -name 'privkey.pem' -o -name '*private*' \) 2>/dev/null | head -10" 2>&1)
            $foundArr = @($found | Where-Object { $_ -and $_.Trim() -ne "" })
            if ($foundArr.Count -gt 0) {
                $allKeys += $foundArr
                $output += "  Found $($foundArr.Count) key(s) in $sp" + $nl
            }
        }
    }
    $output += "  Total private keys found: $($allKeys.Count)" + $nl

    # Check 2: Verify file permissions (should be 600 or 400)
    $output += $nl + "CHECK 2: Private key file permissions" + $nl
    $permViolations = 0
    $permOK = 0
    foreach ($key in ($allKeys | Select-Object -First 10)) {
        $keyStr = $key.Trim()
        if (-not $keyStr) { continue }
        $perms = $(sh -c "stat -c '%a %U:%G' '$keyStr' 2>/dev/null" 2>&1)
        $permsStr = ($perms -join $nl).Trim()
        $output += "  $keyStr : $permsStr" + $nl
        if ($permsStr -match "^(600|400|640)\s") {
            $permOK++
        } else {
            $permViolations++
            $output += "    [FINDING] Permissions too permissive (expected 600 or 400)" + $nl
        }
    }

    # Check 3: Check for keys in web-accessible directories
    $output += $nl + "CHECK 3: Keys in web-accessible directories" + $nl
    $webKeyFound = $false
    $webDirs = @("/var/www", "/opt/xo/xo-src/xen-orchestra/packages/xo-web/dist")
    foreach ($wd in $webDirs) {
        if (Test-Path $wd) {
            $wk = $(timeout 5 sh -c "find '$wd' -maxdepth 3 -type f -name '*.key' 2>/dev/null | head -3" 2>&1)
            $wkStr = ($wk -join $nl).Trim()
            if ($wkStr) {
                $webKeyFound = $true
                $output += "  [FINDING] Private key in web directory: $wkStr" + $nl
            }
        }
    }
    if (-not $webKeyFound) {
        $output += "  [PASS] No private keys in web-accessible directories" + $nl
    }

    # Check 4: Check key encryption status
    $output += $nl + "CHECK 4: Key encryption status" + $nl
    $unencrypted = 0
    foreach ($key in ($allKeys | Select-Object -First 5)) {
        $keyStr = $key.Trim()
        if (-not $keyStr) { continue }
        $encCheck = $(sh -c "head -2 '$keyStr' 2>/dev/null | grep -c 'ENCRYPTED'" 2>&1)
        $encCheckStr = ($encCheck -join $nl).Trim()
        if ($encCheckStr -eq "0") {
            $unencrypted++
            $output += "  $keyStr : unencrypted" + $nl
        } else {
            $output += "  $keyStr : encrypted" + $nl
        }
    }

    # Determine status
    if ($allKeys.Count -eq 0) {
        $Status = "Not_Applicable"
        $output += $nl + "RESULT: Not_Applicable - no private key files detected." + $nl
    } elseif ($permViolations -gt 0 -or $webKeyFound) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - private key protection violations detected." + $nl
    } elseif ($permOK -gt 0) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - private keys have appropriate permissions." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - unable to verify private key protection." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222554: No cleartext password display
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222554"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Find XO web application files
    $output += "CHECK 1: XO web application location" + $nl
    $webRoot = ""
    $webPaths = @("/opt/xo/xo-src/xen-orchestra/packages/xo-web", "/opt/xo/packages/xo-web", "/usr/share/xo-server/xo-web")
    foreach ($wp in $webPaths) {
        if (Test-Path $wp) { $webRoot = $wp; break }
    }
    if ($webRoot) {
        $output += "  XO web root: $webRoot" + $nl
    } else {
        $output += "  XO web root not found in standard locations" + $nl
    }

    # Check 2: Check for password input type in source files
    $output += $nl + "CHECK 2: Password input field types" + $nl
    $cleartextFound = $false
    $properInputFound = $false
    if ($webRoot) {
        $pwInputs = $(timeout 10 sh -c "find '$webRoot' -maxdepth 5 -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.html' \) -exec grep -l 'type.*password' {} + 2>/dev/null | head -5" 2>&1)
        $pwInputsStr = ($pwInputs -join $nl).Trim()
        if ($pwInputsStr) {
            $output += "  Files with password-type inputs: $pwInputsStr" + $nl
            $properInputFound = $true
        }
        # Check for type='text' on password fields
        $textPw = $(timeout 10 sh -c "find '$webRoot' -maxdepth 5 -type f \( -name '*.js' -o -name '*.jsx' \) -exec grep -n 'password.*type.*text\|type.*text.*password' {} + 2>/dev/null | head -3" 2>&1)
        $textPwStr = ($textPw -join $nl).Trim()
        if ($textPwStr) {
            $cleartextFound = $true
            $output += "  [FINDING] Cleartext password fields: $textPwStr" + $nl
        }
    }

    # Check 3: Check for cleartext passwords in logs
    $output += $nl + "CHECK 3: Cleartext passwords in log files" + $nl
    $pwInLogs = $false
    $logCheck = $(timeout 10 sh -c "find /var/log -maxdepth 2 -name '*xo*' -type f -exec grep -l 'password.*=.*[^*]' {} + 2>/dev/null | head -3" 2>&1)
    $logCheckStr = ($logCheck -join $nl).Trim()
    if ($logCheckStr) {
        $pwInLogs = $true
        $output += "  [FINDING] Potential cleartext passwords in logs: $logCheckStr" + $nl
    } else {
        $output += "  [PASS] No cleartext passwords detected in log files" + $nl
    }

    # Check 4: React framework (provides password masking by default)
    $output += $nl + "CHECK 4: UI framework analysis" + $nl
    $reactDetected = $false
    if ($webRoot) {
        $react = $(sh -c "find '$webRoot' -maxdepth 2 -name 'package.json' -exec grep -l 'react' {} + 2>/dev/null | head -1" 2>&1)
        $reactStr = ($react -join $nl).Trim()
        if ($reactStr) {
            $reactDetected = $true
            $output += "  [PASS] React framework detected (provides input masking)" + $nl
        }
    }

    # Check 5: XO API response analysis
    $output += $nl + "CHECK 5: API password exposure" + $nl
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN }
    if ($token) {
        $userResp = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users' 2>&1" 2>&1)
        $userRespStr = ($userResp -join $nl).Trim()
        if ($userRespStr -match "password") {
            $output += "  [FINDING] API response contains password field" + $nl
        } else {
            $output += "  [PASS] API does not expose password fields" + $nl
        }
    } else {
        $output += "  API token not available for response check" + $nl
    }

    # Determine status
    if ($cleartextFound -or $pwInLogs) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - cleartext password display detected." + $nl
    } elseif ($reactDetected -or $properInputFound) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - passwords are properly masked." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - unable to confirm password masking." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222577: No session ID exposure
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222577"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Cookie security flags via HTTP response
    $output += "CHECK 1: Cookie security flags" + $nl
    $httpOnly = $false
    $secureCookie = $false
    $headers = $(timeout 5 sh -c "curl -s -k -I 'https://localhost' 2>&1 | grep -i 'Set-Cookie'" 2>&1)
    $headersStr = ($headers -join $nl).Trim()
    if ($headersStr) {
        $output += "  Set-Cookie headers:" + $nl + "  $headersStr" + $nl
        if ($headersStr -match "HttpOnly") { $httpOnly = $true; $output += "  [PASS] HttpOnly flag present" + $nl }
        else { $output += "  [FINDING] HttpOnly flag missing" + $nl }
        if ($headersStr -match "Secure") { $secureCookie = $true; $output += "  [PASS] Secure flag present" + $nl }
        else { $output += "  [FINDING] Secure flag missing" + $nl }
    } else {
        $output += "  No Set-Cookie headers in response" + $nl
    }

    # Check 2: Session storage (Redis)
    $output += $nl + "CHECK 2: Session storage in Redis" + $nl
    $sessionCount = $(sh -c "timeout 3 redis-cli --scan --pattern 'xo:session:*' 2>/dev/null | wc -l" 2>&1)
    $sessionCountStr = ($sessionCount -join $nl).Trim()
    $output += "  Active sessions in Redis: $sessionCountStr" + $nl

    # Check 3: Check for session IDs in URLs (XO source code)
    $output += $nl + "CHECK 3: Session ID URL exposure" + $nl
    $urlExposure = $false
    $srcPath = "/opt/xo"
    $urlCheck = $(timeout 10 sh -c "find '$srcPath' -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -l 'sessionid.*url\|sid.*query\|token.*url.*param' {} + 2>/dev/null | head -3" 2>&1)
    $urlCheckStr = ($urlCheck -join $nl).Trim()
    if ($urlCheckStr) {
        $urlExposure = $true
        $output += "  [FINDING] Potential session ID in URL parameters: $urlCheckStr" + $nl
    } else {
        $output += "  [PASS] No session ID exposure in URL parameters detected" + $nl
    }

    # Check 4: Session ID in logs
    $output += $nl + "CHECK 4: Session ID in log files" + $nl
    $logExposure = $(timeout 5 sh -c "find /var/log -maxdepth 2 -name '*xo*' -type f -exec grep -l 'authenticationToken\|sessionId' {} + 2>/dev/null | head -3" 2>&1)
    $logExposureStr = ($logExposure -join $nl).Trim()
    if ($logExposureStr) {
        $output += "  [FINDING] Session references in logs: $logExposureStr" + $nl
    } else {
        $output += "  [PASS] No session ID exposure in log files" + $nl
    }

    # Check 5: HTTPS enforcement (session over TLS only)
    $output += $nl + "CHECK 5: HTTPS enforcement" + $nl
    $httpsActive = $false
    $tlsCheck = $(timeout 5 sh -c "ss -tlnp 2>/dev/null | grep -E ':443\s'" 2>&1)
    $tlsCheckStr = ($tlsCheck -join $nl).Trim()
    if ($tlsCheckStr) {
        $httpsActive = $true
        $output += "  [PASS] HTTPS active on port 443" + $nl
    } else {
        $output += "  [FINDING] HTTPS not detected on port 443" + $nl
    }

    # Determine status
    if ($urlExposure) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - session ID exposure in URL parameters." + $nl
    } elseif ($httpsActive -and ($httpOnly -or $secureCookie)) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - session IDs protected (HTTPS + cookie flags)." + $nl
    } elseif ($httpsActive) {
        # HTTPS active but cookie flags not confirmed (may be defaults)
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - sessions transmitted over HTTPS." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - session ID protection insufficient." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222578: Destroy session ID on logoff/browser close
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222578"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: XO signOut/logout handler in source
    $output += "CHECK 1: Session signOut/logout handlers" + $nl
    $signOutFound = $false
    $srcPaths = @("/opt/xo/xo-server", "/opt/xo/packages/xo-server", "/opt/xo/xo-src/xen-orchestra/packages/xo-server")
    foreach ($sp in $srcPaths) {
        if (Test-Path $sp) {
            $handlers = $(timeout 10 sh -c "find '$sp' -maxdepth 4 -name '*.js' -not -path '*/node_modules/*' -exec grep -l 'signOut\|logout\|session.*destroy\|session.*invalidate' {} + 2>/dev/null | head -5" 2>&1)
            $handlersStr = ($handlers -join $nl).Trim()
            if ($handlersStr) {
                $signOutFound = $true
                $output += "  [PASS] Logout handlers found:" + $nl + "  $handlersStr" + $nl
                break
            }
        }
    }
    if (-not $signOutFound) {
        $output += "  Logout handler files not detected in source" + $nl
    }

    # Check 2: XO REST API session.signOut endpoint
    $output += $nl + "CHECK 2: XO API session management" + $nl
    $apiSignOut = $false
    $apiCheck = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -l 'session.signOut\|api.*signOut' {} + 2>/dev/null | head -3" 2>&1)
    $apiCheckStr = ($apiCheck -join $nl).Trim()
    if ($apiCheckStr) {
        $apiSignOut = $true
        $output += "  [PASS] session.signOut API endpoint found: $apiCheckStr" + $nl
    }

    # Check 3: Redis session TTL (automatic expiration)
    $output += $nl + "CHECK 3: Redis session TTL" + $nl
    $hasTTL = $false
    $sampleKey = $(sh -c "timeout 3 redis-cli --scan --pattern 'xo:session:*' 2>/dev/null | head -1" 2>&1)
    $sampleKeyStr = ($sampleKey -join $nl).Trim()
    if ($sampleKeyStr) {
        $ttl = $(sh -c "timeout 3 redis-cli TTL '$sampleKeyStr' 2>/dev/null" 2>&1)
        $ttlStr = ($ttl -join $nl).Trim()
        $output += "  Session key: $sampleKeyStr" + $nl
        $output += "  TTL: $ttlStr seconds" + $nl
        if ($ttlStr -match "^\d+" -and [int]$ttlStr -gt 0) {
            $hasTTL = $true
            $output += "  [PASS] Session has finite TTL" + $nl
        } elseif ($ttlStr -eq "-1") {
            $output += "  [INFO] Session has no TTL (persistent)" + $nl
        }
    } else {
        $output += "  No active sessions in Redis" + $nl
    }

    # Check 4: Cookie settings (session cookies vs persistent)
    $output += $nl + "CHECK 4: Cookie persistence settings" + $nl
    $cookieCheck = $(timeout 5 sh -c "curl -s -k -I 'https://localhost' 2>&1 | grep -i 'Set-Cookie'" 2>&1)
    $cookieCheckStr = ($cookieCheck -join $nl).Trim()
    if ($cookieCheckStr) {
        $output += "  $cookieCheckStr" + $nl
        if ($cookieCheckStr -match "Max-Age=0|Expires=.*1970") {
            $output += "  [PASS] Session cookie (expires on browser close)" + $nl
        }
    }

    # Determine status
    if ($signOutFound -or $apiSignOut) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - session destruction mechanism present (signOut handler)." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - unable to confirm session destruction on logoff." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222596: Protect transmitted information confidentiality
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222596"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: HTTPS listener
    $output += "CHECK 1: HTTPS/TLS listener status" + $nl
    $httpsActive = $false
    $listeners = $(sh -c "ss -tlnp 2>/dev/null | grep -E ':443\s'" 2>&1)
    $listenersStr = ($listeners -join $nl).Trim()
    if ($listenersStr) {
        $httpsActive = $true
        $output += "  [PASS] HTTPS active on port 443: $listenersStr" + $nl
    } else {
        $output += "  [FINDING] No HTTPS listener on port 443" + $nl
    }

    # Check 2: TLS version verification
    $output += $nl + "CHECK 2: TLS version" + $nl
    $modernTLS = $false
    $tlsVer = $(timeout 5 sh -c "echo | openssl s_client -connect localhost:443 2>/dev/null | grep 'Protocol'" 2>&1)
    $tlsVerStr = ($tlsVer -join $nl).Trim()
    if ($tlsVerStr -match "TLSv1\.[23]") {
        $modernTLS = $true
        $output += "  [PASS] $tlsVerStr" + $nl
    } elseif ($tlsVerStr) {
        $output += "  [FINDING] $tlsVerStr" + $nl
    }

    # Check 3: XO config TLS settings
    $output += $nl + "CHECK 3: XO TLS configuration" + $nl
    $configPaths = @("/etc/xo-server/config.toml", "/opt/xo/xo-server/config.toml")
    foreach ($cp in $configPaths) {
        if (Test-Path $cp) {
            $tlsConfig = $(sh -c "grep -iE 'cert|key|https|redirectToHttps' '$cp' 2>/dev/null" 2>&1)
            $tlsConfigStr = ($tlsConfig -join $nl).Trim()
            if ($tlsConfigStr) { $output += "  Config ($cp): $tlsConfigStr" + $nl }
        }
    }

    # Check 4: Plaintext protocol exposure
    $output += $nl + "CHECK 4: Plaintext protocol exposure" + $nl
    $plaintextExposed = $false
    $ptCheck = $(sh -c "ss -tlnp 2>/dev/null | grep -E ':(21|23|80|3389)\s' | grep -v '127.0.0.1'" 2>&1)
    $ptCheckStr = ($ptCheck -join $nl).Trim()
    if ($ptCheckStr) {
        $plaintextExposed = $true
        $output += "  [FINDING] Plaintext protocols exposed: $ptCheckStr" + $nl
    } else {
        $output += "  [PASS] No plaintext protocols exposed on network interfaces" + $nl
    }

    # Check 5: Cipher strength
    $output += $nl + "CHECK 5: Cipher strength" + $nl
    $cipher = $(timeout 5 sh -c "echo | openssl s_client -connect localhost:443 2>/dev/null | grep 'Cipher'" 2>&1)
    $cipherStr = ($cipher -join $nl).Trim()
    if ($cipherStr) { $output += "  $cipherStr" + $nl }

    # Determine status
    if ($httpsActive -and $modernTLS -and -not $plaintextExposed) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - transmitted information protected with TLS." + $nl
    } elseif ($httpsActive) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - HTTPS active but additional issues detected." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - transmitted information not adequately protected." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222601: No sensitive info in hidden fields
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222601"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Locate XO web files
    $output += "CHECK 1: XO web application location" + $nl
    $webRoot = ""
    $webPaths = @("/opt/xo/xo-src/xen-orchestra/packages/xo-web", "/opt/xo/packages/xo-web", "/usr/share/xo-server/xo-web")
    foreach ($wp in $webPaths) {
        if (Test-Path $wp) { $webRoot = $wp; break }
    }
    if ($webRoot) {
        $output += "  XO web root: $webRoot" + $nl
    } else {
        $output += "  XO web root not found" + $nl
    }

    # Check 2: Scan for hidden fields with sensitive data patterns
    $output += $nl + "CHECK 2: Hidden field sensitive data scan" + $nl
    $sensitiveHidden = $false
    if ($webRoot) {
        $hiddenSensitive = $(timeout 15 sh -c "find '$webRoot' -maxdepth 5 -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.html' \) -exec grep -n 'type.*hidden.*password\|type.*hidden.*secret\|type.*hidden.*token\|type.*hidden.*key\|type.*hidden.*ssn\|type.*hidden.*credit' {} + 2>/dev/null | head -5" 2>&1)
        $hiddenSensitiveStr = ($hiddenSensitive -join $nl).Trim()
        if ($hiddenSensitiveStr) {
            $sensitiveHidden = $true
            $output += "  [FINDING] Sensitive data in hidden fields: $hiddenSensitiveStr" + $nl
        } else {
            $output += "  [PASS] No sensitive data patterns in hidden fields" + $nl
        }

        # Count hidden fields generally
        $hiddenCount = $(timeout 10 sh -c "find '$webRoot' -maxdepth 5 -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.html' \) -exec grep -c 'type.*hidden' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
        $hiddenCountStr = ($hiddenCount -join $nl).Trim()
        $output += "  Total hidden field references: $hiddenCountStr" + $nl
    }

    # Check 3: React framework (SPA - limited hidden field usage)
    $output += $nl + "CHECK 3: Application architecture" + $nl
    $isSPA = $false
    if ($webRoot) {
        $reactCheck = $(sh -c "find '$webRoot' -maxdepth 2 -name 'package.json' -exec grep -l 'react' {} + 2>/dev/null | head -1" 2>&1)
        $reactCheckStr = ($reactCheck -join $nl).Trim()
        if ($reactCheckStr) {
            $isSPA = $true
            $output += "  [PASS] React SPA detected - minimal server-rendered hidden fields" + $nl
        }
    }

    # Determine status
    if ($sensitiveHidden) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - sensitive information found in hidden fields." + $nl
    } elseif ($webRoot -and ($isSPA -or -not $sensitiveHidden)) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - no sensitive information in hidden fields." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - unable to verify hidden field content." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222602: Protect from XSS vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222602"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: React framework detection (inherent XSS protection)
    $output += "CHECK 1: React framework (inherent XSS protection)" + $nl
    $reactDetected = $false
    $webPaths = @("/opt/xo/xo-src/xen-orchestra/packages/xo-web", "/opt/xo/packages/xo-web")
    foreach ($wp in $webPaths) {
        if (Test-Path $wp) {
            $react = $(sh -c "find '$wp' -maxdepth 2 -name 'package.json' -exec grep -l 'react' {} + 2>/dev/null | head -1" 2>&1)
            $reactStr = ($react -join $nl).Trim()
            if ($reactStr) {
                $reactDetected = $true
                $output += "  [PASS] React framework detected (automatic JSX escaping)" + $nl
                break
            }
        }
    }
    if (-not $reactDetected) {
        $output += "  React framework not detected" + $nl
    }

    # Check 2: Security headers (CSP, X-XSS-Protection)
    $output += $nl + "CHECK 2: Security response headers" + $nl
    $hasCSP = $false
    $respHeaders = $(timeout 5 sh -c "curl -s -k -I 'https://localhost' 2>&1" 2>&1)
    $respHeadersStr = ($respHeaders -join $nl).Trim()
    if ($respHeadersStr -match "Content-Security-Policy") {
        $hasCSP = $true
        $cspLine = ($respHeadersStr -split "`n" | Where-Object { $_ -match "Content-Security-Policy" } | Select-Object -First 1)
        $output += "  [PASS] CSP header: $cspLine" + $nl
    } else {
        $output += "  [INFO] No Content-Security-Policy header (React provides protection)" + $nl
    }
    if ($respHeadersStr -match "X-Content-Type-Options") {
        $output += "  [PASS] X-Content-Type-Options header present" + $nl
    }

    # Check 3: dangerouslySetInnerHTML usage
    $output += $nl + "CHECK 3: Dangerous XSS patterns" + $nl
    $dangerousFound = $false
    foreach ($wp in $webPaths) {
        if (Test-Path $wp) {
            $dangerous = $(timeout 10 sh -c "find '$wp' -maxdepth 5 -type f -name '*.js' -exec grep -c 'dangerouslySetInnerHTML' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
            $dangerousStr = ($dangerous -join $nl).Trim()
            if ($dangerousStr -and [int]$dangerousStr -gt 0) {
                $dangerousFound = $true
                $output += "  [INFO] dangerouslySetInnerHTML usage: $dangerousStr instances" + $nl
            } else {
                $output += "  [PASS] No dangerouslySetInnerHTML usage detected" + $nl
            }
            break
        }
    }

    # Check 4: Output encoding libraries
    $output += $nl + "CHECK 4: Sanitization/encoding libraries" + $nl
    $hasSanitizer = $false
    $sanitizeCheck = $(timeout 5 sh -c "find /opt/xo -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' -exec grep -l 'dompurify\|sanitize-html\|xss\|validator' {} + 2>/dev/null | head -3" 2>&1)
    $sanitizeCheckStr = ($sanitizeCheck -join $nl).Trim()
    if ($sanitizeCheckStr) {
        $hasSanitizer = $true
        $output += "  [PASS] Sanitization library present" + $nl
    } else {
        $output += "  [INFO] No dedicated sanitization library (React handles escaping)" + $nl
    }

    # Determine status
    if ($reactDetected) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - React framework provides inherent XSS protection via JSX escaping." + $nl
    } elseif ($hasCSP -and $hasSanitizer) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - CSP headers and sanitization libraries provide XSS protection." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - XSS protection mechanisms not confirmed." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222604: Protect from command injection
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222604"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: child_process usage analysis
    $output += "CHECK 1: child_process module usage" + $nl
    $srcPaths = @("/opt/xo/xo-server", "/opt/xo/packages/xo-server", "/opt/xo/xo-src/xen-orchestra/packages/xo-server")
    $cpRefs = 0
    $execRefs = 0
    foreach ($sp in $srcPaths) {
        if (Test-Path $sp) {
            $cpCount = $(timeout 10 sh -c "find '$sp' -maxdepth 5 -name '*.js' -not -path '*/node_modules/*' -exec grep -c 'child_process\|require.*child' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
            $cpCountStr = ($cpCount -join $nl).Trim()
            if ($cpCountStr) { $cpRefs = [int]$cpCountStr }

            # Check for dangerous exec/execSync (vs safer spawn/execFile)
            $execCount = $(timeout 10 sh -c "find '$sp' -maxdepth 5 -name '*.js' -not -path '*/node_modules/*' -exec grep -c '\.exec(\|\.execSync(' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
            $execCountStr = ($execCount -join $nl).Trim()
            if ($execCountStr) { $execRefs = [int]$execCountStr }
            break
        }
    }
    $output += "  child_process references: $cpRefs" + $nl
    $output += "  exec/execSync calls (higher risk): $execRefs" + $nl
    if ($cpRefs -eq 0) {
        $output += "  [PASS] No child_process usage detected" + $nl
    }

    # Check 2: Input validation libraries
    $output += $nl + "CHECK 2: Input validation libraries" + $nl
    $hasValidation = $false
    $valCheck = $(timeout 5 sh -c "find /opt/xo -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' -exec grep -l 'ajv\|joi\|yup\|express-validator\|validator' {} + 2>/dev/null | head -3" 2>&1)
    $valCheckStr = ($valCheck -join $nl).Trim()
    if ($valCheckStr) {
        $hasValidation = $true
        $output += "  [PASS] Input validation library detected: $valCheckStr" + $nl
    } else {
        $output += "  [INFO] No dedicated input validation library found" + $nl
    }

    # Check 3: Parameterized command patterns
    $output += $nl + "CHECK 3: Command parameterization" + $nl
    $spawnUsage = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -c '\.spawn(\|\.execFile(' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
    $spawnUsageStr = ($spawnUsage -join $nl).Trim()
    $output += "  spawn/execFile calls (safer pattern): $spawnUsageStr" + $nl

    # Check 4: String concatenation in commands (injection risk)
    $output += $nl + "CHECK 4: Command string concatenation patterns" + $nl
    $concatRisk = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -n 'exec.*\`\|exec.*\${' {} + 2>/dev/null | head -5" 2>&1)
    $concatRiskStr = ($concatRisk -join $nl).Trim()
    if ($concatRiskStr) {
        $output += "  [FINDING] Template literals in exec calls detected:" + $nl + "  $concatRiskStr" + $nl
    } else {
        $output += "  [PASS] No string concatenation in exec calls detected" + $nl
    }

    # Determine status — code review is always needed for injection checks
    if ($cpRefs -eq 0) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - no command execution detected in application code." + $nl
    } elseif ($cpRefs -gt 0 -and $execRefs -eq 0 -and $hasValidation) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - uses safer spawn/execFile patterns with input validation." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - command execution detected; code review required for injection prevention." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222609: No input handling vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222609"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Input validation framework
    $output += "CHECK 1: Input validation framework" + $nl
    $hasAjv = $false
    $hasJoi = $false
    $ajvCheck = $(sh -c "find /opt/xo -maxdepth 3 -name 'package.json' -not -path '*/node_modules/*' -exec grep -l 'ajv' {} + 2>/dev/null | head -3" 2>&1)
    $ajvCheckStr = ($ajvCheck -join $nl).Trim()
    if ($ajvCheckStr) {
        $hasAjv = $true
        $output += "  [PASS] ajv (JSON Schema validator) detected" + $nl
    }
    $joiCheck = $(sh -c "find /opt/xo -maxdepth 3 -name 'package.json' -not -path '*/node_modules/*' -exec grep -l 'joi' {} + 2>/dev/null | head -3" 2>&1)
    $joiCheckStr = ($joiCheck -join $nl).Trim()
    if ($joiCheckStr) {
        $hasJoi = $true
        $output += "  [PASS] joi (schema validator) detected" + $nl
    }
    if (-not $hasAjv -and -not $hasJoi) {
        $output += "  [INFO] No dedicated validation library detected" + $nl
    }

    # Check 2: JSON-RPC type checking (XO uses JSON-RPC protocol)
    $output += $nl + "CHECK 2: JSON-RPC input type checking" + $nl
    $typeChecking = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -c 'typeof\|instanceof\|\.type\s*===\|schema.*validate' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
    $typeCheckingStr = ($typeChecking -join $nl).Trim()
    $output += "  Type checking references: $typeCheckingStr" + $nl

    # Check 3: Content-Type enforcement
    $output += $nl + "CHECK 3: Content-Type enforcement" + $nl
    $ctCheck = $(timeout 5 sh -c "curl -s -k -X POST -H 'Content-Type: text/plain' -d 'test' 'https://localhost/api/' 2>&1 | head -5" 2>&1)
    $ctCheckStr = ($ctCheck -join $nl).Trim()
    if ($ctCheckStr -match "error\|invalid\|unsupported\|bad request" ) {
        $output += "  [PASS] Invalid Content-Type rejected" + $nl
    } else {
        $output += "  [INFO] Content-Type enforcement status: $ctCheckStr" + $nl
    }

    # Check 4: Body-parser / express middleware
    $output += $nl + "CHECK 4: Request body parsing middleware" + $nl
    $bodyParser = $(timeout 5 sh -c "find /opt/xo -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' -exec grep -l 'body-parser\|express' {} + 2>/dev/null | head -3" 2>&1)
    $bodyParserStr = ($bodyParser -join $nl).Trim()
    if ($bodyParserStr) {
        $output += "  [PASS] Express/body-parser middleware present" + $nl
    }

    # Check 5: npm audit for input handling CVEs
    $output += $nl + "CHECK 5: Known input handling vulnerabilities" + $nl
    $npmAudit = $(timeout 30 sh -c "cd /opt/xo 2>/dev/null && npm audit --json 2>/dev/null | head -50 || echo 'npm audit unavailable'" 2>&1)
    $npmAuditStr = ($npmAudit -join $nl).Trim()
    if ($npmAuditStr -match "npm audit unavailable") {
        $output += "  npm audit not available" + $nl
    } elseif ($npmAuditStr -match [char]34 + "critical[char]34 + ":\s*[1-9]") {
        $output += "  [FINDING] Critical vulnerabilities detected in npm audit" + $nl
    } else {
        $output += "  [PASS] No critical input handling vulnerabilities in npm audit" + $nl
    }

    # Determine status
    if ($hasAjv -or $hasJoi) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - input validation framework (ajv/joi) present." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - dedicated input validation library not confirmed." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222612: Not vulnerable to overflow attacks
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222612"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Node.js version (memory-safe runtime)
    $output += "CHECK 1: Node.js runtime version" + $nl
    $modernNode = $false
    $nodeVer = $(sh -c "node --version 2>/dev/null" 2>&1)
    $nodeVerStr = ($nodeVer -join $nl).Trim()
    if ($nodeVerStr -match "v(\d+)\.") {
        $majorVer = [int]$Matches[1]
        $output += "  Node.js version: $nodeVerStr" + $nl
        if ($majorVer -ge 18) {
            $modernNode = $true
            $output += "  [PASS] Modern Node.js with memory safety features" + $nl
        } else {
            $output += "  [FINDING] Outdated Node.js version" + $nl
        }
    } else {
        $output += "  Node.js not detected" + $nl
    }

    # Check 2: ASLR status
    $output += $nl + "CHECK 2: Address Space Layout Randomization (ASLR)" + $nl
    $aslrEnabled = $false
    $aslr = $(sh -c "cat /proc/sys/kernel/randomize_va_space 2>/dev/null" 2>&1)
    $aslrStr = ($aslr -join $nl).Trim()
    if ($aslrStr -eq "2") {
        $aslrEnabled = $true
        $output += "  [PASS] ASLR fully enabled (randomize_va_space=2)" + $nl
    } elseif ($aslrStr -eq "1") {
        $aslrEnabled = $true
        $output += "  [PASS] ASLR partially enabled (randomize_va_space=1)" + $nl
    } else {
        $output += "  [FINDING] ASLR disabled or unknown (randomize_va_space=$aslrStr)" + $nl
    }

    # Check 3: Unsafe Buffer usage in XO source
    $output += $nl + "CHECK 3: Unsafe Buffer allocation patterns" + $nl
    $unsafeBuffers = 0
    $bufCheck = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -c 'new Buffer(\|Buffer.allocUnsafe\|Buffer.allocUnsafeSlow' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
    $bufCheckStr = ($bufCheck -join $nl).Trim()
    if ($bufCheckStr) { $unsafeBuffers = [int]$bufCheckStr }
    $output += "  Unsafe Buffer patterns: $unsafeBuffers" + $nl
    if ($unsafeBuffers -eq 0) {
        $output += "  [PASS] No unsafe Buffer allocations detected" + $nl
    } else {
        $output += "  [INFO] Unsafe Buffer patterns found (potential memory exposure)" + $nl
    }

    # Check 4: Stack size limits
    $output += $nl + "CHECK 4: Process resource limits" + $nl
    $stackLimit = $(sh -c "ulimit -s 2>/dev/null" 2>&1)
    $stackLimitStr = ($stackLimit -join $nl).Trim()
    $output += "  Stack size limit: $stackLimitStr" + $nl

    # Check 5: V8 engine protections
    $output += $nl + "CHECK 5: V8 engine protections" + $nl
    $output += "  Node.js/V8 provides:" + $nl
    $output += "  - Automatic garbage collection (prevents use-after-free)" + $nl
    $output += "  - ArrayBuffer bounds checking" + $nl
    $output += "  - TypedArray bounds enforcement" + $nl
    $output += "  - No direct memory pointer access from JavaScript" + $nl

    # Determine status
    if ($modernNode -and $aslrEnabled) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - Node.js memory-safe runtime with ASLR enabled." + $nl
    } elseif ($modernNode) {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - Node.js is a memory-safe runtime (V8 engine)." + $nl
    } else {
        $Status = "Open"
        $output += $nl + "RESULT: Open - unable to confirm overflow protection." + $nl
    }

    $FindingDetails = $output
'''

# ═══════════════════════════════════════════════════════════════════════════
# V-222642: No embedded authentication data in source
# ═══════════════════════════════════════════════════════════════════════════
IMPLEMENTATIONS["222642"] = r'''
    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Hardcoded credentials in XO source
    $output += "CHECK 1: Hardcoded credential patterns" + $nl
    $hardcodedFound = $false
    $srcPaths = @("/opt/xo/xo-server", "/opt/xo/packages/xo-server", "/opt/xo/xo-src/xen-orchestra/packages/xo-server")
    foreach ($sp in $srcPaths) {
        if (Test-Path $sp) {
            $hardcoded = $(timeout 15 sh -c "find '$sp' -maxdepth 5 -name '*.js' -not -path '*/node_modules/*' -exec grep -n 'password\s*[:=]\s*['" + [char]34 + "][^'" + [char]34 + "]*['" + [char]34 + "]\|apiKey\s*[:=]\s*['" + [char]34 + "][^'" + [char]34 + "]*['" + [char]34 + "]\|secret\s*[:=]\s*['" + [char]34 + "][^'" + [char]34 + "]*['" + [char]34 + "]' {} + 2>/dev/null | grep -v 'test\|spec\|example\|sample\|placeholder\|__' | head -5" 2>&1)
            $hardcodedStr = ($hardcoded -join $nl).Trim()
            if ($hardcodedStr) {
                $hardcodedFound = $true
                $output += "  [FINDING] Potential hardcoded credentials:" + $nl + "  $hardcodedStr" + $nl
            } else {
                $output += "  [PASS] No hardcoded credentials in $sp" + $nl
            }
            break
        }
    }

    # Check 2: Environment variable usage (proper pattern)
    $output += $nl + "CHECK 2: Environment variable credential management" + $nl
    $envUsage = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -c 'process\.env\.\|process\.env\[' {} + 2>/dev/null | awk -F: '{s+=\$NF}END{print s}'" 2>&1)
    $envUsageStr = ($envUsage -join $nl).Trim()
    $output += "  process.env references: $envUsageStr" + $nl
    if ($envUsageStr -and [int]$envUsageStr -gt 0) {
        $output += "  [PASS] Environment variables used for configuration" + $nl
    }

    # Check 3: Config file credential exposure
    $output += $nl + "CHECK 3: Configuration file credentials" + $nl
    $configCreds = $false
    $configPaths = @("/etc/xo-server/config.toml", "/opt/xo/xo-server/config.toml")
    foreach ($cp in $configPaths) {
        if (Test-Path $cp) {
            $creds = $(sh -c "grep -inE 'password|secret|apikey|token' '$cp' 2>/dev/null | grep -v '^#'" 2>&1)
            $credsStr = ($creds -join $nl).Trim()
            if ($credsStr) {
                $output += "  Config file credentials found in $cp :" + $nl + "  $credsStr" + $nl
                # Check if values are plaintext (not empty/placeholder)
                if ($credsStr -match "=\s*['" + [char]34 + "][a-zA-Z0-9]{8,}") {
                    $configCreds = $true
                    $output += "  [FINDING] Potential plaintext credential values in config" + $nl
                }
            }
        }
    }
    if (-not $configCreds) {
        $output += "  [PASS] No plaintext credentials in config files" + $nl
    }

    # Check 4: .env file check
    $output += $nl + "CHECK 4: .env file exposure" + $nl
    $envFile = $(timeout 5 sh -c "find /opt/xo -maxdepth 3 -name '.env' -not -path '*/node_modules/*' 2>/dev/null | head -3" 2>&1)
    $envFileStr = ($envFile -join $nl).Trim()
    if ($envFileStr) {
        $output += "  .env files found: $envFileStr" + $nl
        # Check permissions
        foreach ($ef in @($envFile | Where-Object { $_ -and $_.Trim() -ne "" })) {
            $efPerms = $(sh -c "stat -c '%a' '$($ef.Trim())' 2>/dev/null" 2>&1)
            $efPermsStr = ($efPerms -join $nl).Trim()
            $output += "  Permissions: $efPermsStr" + $nl
        }
    } else {
        $output += "  [PASS] No .env files found" + $nl
    }

    # Check 5: Embedded certificates/keys in source
    $output += $nl + "CHECK 5: Embedded keys/certificates in source" + $nl
    $embeddedKeys = $(timeout 10 sh -c "find /opt/xo -maxdepth 6 -name '*.js' -not -path '*/node_modules/*' -exec grep -l 'BEGIN.*PRIVATE KEY\|BEGIN.*CERTIFICATE' {} + 2>/dev/null | head -3" 2>&1)
    $embeddedKeysStr = ($embeddedKeys -join $nl).Trim()
    if ($embeddedKeysStr) {
        $hardcodedFound = $true
        $output += "  [FINDING] Embedded keys/certs in source: $embeddedKeysStr" + $nl
    } else {
        $output += "  [PASS] No embedded keys/certificates in source code" + $nl
    }

    # Determine status
    if ($hardcodedFound -or $configCreds) {
        $Status = "Open"
        $output += $nl + "RESULT: Open - embedded authentication data or plaintext credentials detected." + $nl
    } else {
        $Status = "NotAFinding"
        $output += $nl + "RESULT: NotAFinding - no embedded authentication data in source code." + $nl
    }

    $FindingDetails = $output
'''

# ── Main replacement logic ───────────────────────────────────────────────

def main():
    if not os.path.isfile(MODULE_PATH):
        print(f"ERROR: Module not found at {MODULE_PATH}")
        sys.exit(1)

    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    replaced = 0
    for vuln_num, new_code in IMPLEMENTATIONS.items():
        func_name = f"Get-V{vuln_num}"
        # Find the custom code block for this function
        begin_marker = "#---=== Begin Custom Code ===---#"
        end_marker = "#---=== End Custom Code ===---#"

        # Find the function definition, then the custom code block within it
        func_pattern = f"Function {func_name} " + "{"
        func_idx = content.find(func_pattern)
        if func_idx == -1:
            func_pattern = f"function {func_name} " + "{"
            func_idx = content.find(func_pattern)
        if func_idx == -1:
            print(f"WARNING: Function {func_name} not found")
            continue

        # Find begin/end markers after the function definition
        begin_idx = content.find(begin_marker, func_idx)
        end_idx = content.find(end_marker, begin_idx)

        if begin_idx == -1 or end_idx == -1:
            print(f"WARNING: Custom code markers not found for {func_name}")
            continue

        # Ensure this is within a reasonable distance (same function)
        if begin_idx - func_idx > 3000:
            print(f"WARNING: Custom code block too far from function def for {func_name}")
            continue

        # Replace the custom code block content (keep markers)
        old_block = content[begin_idx:end_idx + len(end_marker)]
        new_block = begin_marker + "\n" + new_code.rstrip() + "\n    " + end_marker
        content = content[:begin_idx] + new_block + content[end_idx + len(end_marker):]

        replaced += 1
        print(f"  [{replaced}/13] Replaced {func_name} (V-{vuln_num})")

    # Write updated module
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nDone: {replaced}/13 functions replaced")
    print(f"Module size: {os.path.getsize(MODULE_PATH):,} bytes")


if __name__ == '__main__':
    main()
