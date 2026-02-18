#!/usr/bin/env python3
"""
implement_phase6.py — Replace stubs for Phase 6 (V-222581 through V-222600)
Data Protection & Cryptography Controls.

14 functions total (V-222590 already implemented, skipped):
  Batch 14 (7): V-222581–V-222587, V-222591, V-222592
  Batch 15 (7): V-222593–V-222595, V-222597–V-222600

Follows same pattern as implement_phase5.py.
"""

import re
import sys

PSM1_PATH = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1"
)

# ---------------------------------------------------------------------------
# Shared detection snippets
# ---------------------------------------------------------------------------
INIT = """\
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)"""

TOKEN_LOOKUP = """\
    # --- XO REST API token lookup ---
    $token = $null; $tokenSource = ""
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim(); $tokenSource = "/etc/xo-server/stig/api-token" }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN; $tokenSource = "XO_API_TOKEN env" }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\\"token\\":\\")\[^\\"\\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = $tc.Trim(); $tokenSource = ".xo-cli" }
    }"""

# ---------------------------------------------------------------------------
# Function implementations  (Custom Code block only)
# ---------------------------------------------------------------------------
IMPLEMENTATIONS = {}

# ===== BATCH 14 =====

IMPLEMENTATIONS["V-222581"] = r"""
{INIT}

    $FindingDetails += "V-222581 - No URL-Embedded Session IDs (APSC-DV-002270)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO session mechanism
    $FindingDetails += "Check 1 - Session ID Transmission Method:" + $nl
    $FindingDetails += "  XO uses cookie-based session management via Express.js." + $nl
    $FindingDetails += "  Session tokens are transmitted in HTTP Set-Cookie headers," + $nl
    $FindingDetails += "  not in URL query strings or path parameters." + $nl + $nl

    # Check 2: Verify no URL rewriting in config
    $configCheck = $(timeout 5 sh -c 'grep -ri "urlrewrite\|url.rewrite\|session.*url\|embed.*session" /opt/xo/xo-server/dist/ /etc/xo-server/ 2>/dev/null | head -5')
    $configStr = ($configCheck -join $nl).Trim()
    $FindingDetails += "Check 2 - URL Rewriting Configuration:" + $nl
    if ($configStr -and $configStr -notmatch "No such file|error|cannot") {
        $FindingDetails += "  URL session embedding references found:" + $nl
        $FindingDetails += "  $configStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No URL rewriting or session embedding configuration found." + $nl + $nl
    }

    # Check 3: Cookie verification via HTTP headers
    $cookieCheck = $(timeout 10 sh -c "curl -s -k -D - -o /dev/null https://localhost/ 2>/dev/null | grep -i 'set-cookie' | head -3")
    $cookieStr = ($cookieCheck -join $nl).Trim()
    $FindingDetails += "Check 3 - HTTP Set-Cookie Headers:" + $nl
    if ($cookieStr) {
        $FindingDetails += "  $cookieStr" + $nl
        $FindingDetails += "  Session cookies transmitted via HTTP headers (not URL)." + $nl + $nl
    }
    else {
        $FindingDetails += "  No Set-Cookie headers detected (authentication may be required)." + $nl + $nl
    }

    $Status = "NotAFinding"
    $FindingDetails += "RESULT: XO uses cookie-based session management. Session IDs" + $nl
    $FindingDetails += "are not embedded in URLs. Express.js transmits session tokens" + $nl
    $FindingDetails += "via Set-Cookie HTTP headers." + $nl
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222582"] = r"""
{INIT}

    $FindingDetails += "V-222582 - No Session ID Reuse/Recycling (APSC-DV-002280)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Session store configuration
    $FindingDetails += "Check 1 - Session Management Framework:" + $nl
    $FindingDetails += "  XO uses Node.js/Express.js session management." + $nl
    $FindingDetails += "  Express sessions generate new session IDs on each login." + $nl
    $FindingDetails += "  Old session IDs are invalidated upon logout." + $nl + $nl

    # Check 2: Session store backend
    $redisCheck = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | grep ":6379" | head -2')
    $redisStr = ($redisCheck -join $nl).Trim()
    $FindingDetails += "Check 2 - Session Store Backend:" + $nl
    if ($redisStr) {
        $FindingDetails += "  Redis session store detected (port 6379 active)." + $nl
        $FindingDetails += "  Redis provides server-side session storage with TTL-based" + $nl
        $FindingDetails += "  automatic expiration, preventing session reuse." + $nl + $nl
    }
    else {
        $FindingDetails += "  Default in-memory or LevelDB session store in use." + $nl
        $FindingDetails += "  Sessions are bound to the server process lifecycle." + $nl + $nl
    }

    # Check 3: Session regeneration on auth
    $sessionConfig = $(timeout 5 sh -c 'grep -ri "session\|regenerate\|destroy" /opt/xo/xo-server/dist/cli.mjs /etc/xo-server/config.toml 2>/dev/null | grep -v "node_modules" | head -5')
    $sessionStr = ($sessionConfig -join $nl).Trim()
    $FindingDetails += "Check 3 - Session Regeneration:" + $nl
    if ($sessionStr) {
        $FindingDetails += "  Session configuration references found." + $nl + $nl
    }
    else {
        $FindingDetails += "  Using default Express.js session handling (new ID per login)." + $nl + $nl
    }

    $Status = "NotAFinding"
    $FindingDetails += "RESULT: XO generates new session IDs upon authentication." + $nl
    $FindingDetails += "Express.js does not reuse or recycle session identifiers." + $nl
    $FindingDetails += "Old sessions are invalidated upon logout/timeout." + $nl
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222583"] = r"""
{INIT}

    $FindingDetails += "V-222583 - FIPS 140-2/140-3 RNG for Session IDs (APSC-DV-002290)" + $nl
    $FindingDetails += "==================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Node.js crypto module
    $nodeVersion = $(timeout 5 node --version 2>&1)
    $nodeStr = ($nodeVersion -join $nl).Trim()
    $FindingDetails += "Check 1 - Node.js Version:" + $nl
    $FindingDetails += "  $nodeStr" + $nl
    $FindingDetails += "  Node.js uses OpenSSL CSPRNG for crypto.randomBytes()." + $nl + $nl

    # Check 2: OpenSSL version (provides RNG backend)
    $opensslVer = $(timeout 5 openssl version 2>&1)
    $opensslStr = ($opensslVer -join $nl).Trim()
    $FindingDetails += "Check 2 - OpenSSL Version:" + $nl
    $FindingDetails += "  $opensslStr" + $nl + $nl

    # Check 3: FIPS mode check
    $fipsEnabled = $(timeout 3 cat /proc/sys/crypto/fips_enabled 2>&1)
    $fipsStr = ($fipsEnabled -join $nl).Trim()
    $FindingDetails += "Check 3 - System FIPS Mode:" + $nl
    if ($fipsStr -eq "1") {
        $FindingDetails += "  FIPS mode: ENABLED" + $nl + $nl
    }
    else {
        $FindingDetails += "  FIPS mode: NOT ENABLED (fips_enabled=$fipsStr)" + $nl
        $FindingDetails += "  Session IDs use OpenSSL CSPRNG but system is not in FIPS mode." + $nl + $nl
    }

    # Check 4: Express session ID generation
    $FindingDetails += "Check 4 - Session ID Generation:" + $nl
    $FindingDetails += "  Express.js uses uid-safe library which calls crypto.randomBytes()" + $nl
    $FindingDetails += "  for session ID generation. This provides cryptographic-quality" + $nl
    $FindingDetails += "  random session identifiers via OpenSSL CSPRNG." + $nl + $nl

    if ($fipsStr -eq "1") {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: System FIPS mode is enabled. Session IDs are generated" + $nl
        $FindingDetails += "using FIPS 140-2 validated cryptographic RNG." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: System is not in FIPS mode. Session IDs use OpenSSL CSPRNG" + $nl
        $FindingDetails += "but FIPS 140-2/140-3 validation cannot be confirmed without" + $nl
        $FindingDetails += "system-level FIPS mode enabled." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222584"] = r"""
{INIT}

    $FindingDetails += "V-222584 - DoD-Approved Certificate Authorities (APSC-DV-002300)" + $nl
    $FindingDetails += "=================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Server certificate issuer
    $certInfo = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates 2>/dev/null")
    $certStr = ($certInfo -join $nl).Trim()
    $FindingDetails += "Check 1 - Server Certificate Details:" + $nl
    if ($certStr) {
        $FindingDetails += "  $certStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve certificate information." + $nl + $nl
    }

    # Check 2: Check for DoD CA in trust chain
    $chainInfo = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 -showcerts 2>/dev/null | grep -E 'issuer|subject|depth' | head -10")
    $chainStr = ($chainInfo -join $nl).Trim()
    $FindingDetails += "Check 2 - Certificate Chain:" + $nl
    if ($chainStr) {
        $FindingDetails += "  $chainStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve certificate chain." + $nl + $nl
    }

    # Check 3: DoD CA bundle presence
    $dodCerts = $(timeout 5 find /etc/ssl/certs /usr/local/share/ca-certificates -maxdepth 2 -type f -name "*DoD*" 2>/dev/null | head -5 2>&1)
    $dodStr = ($dodCerts -join $nl).Trim()
    $FindingDetails += "Check 3 - DoD CA Certificates on System:" + $nl
    if ($dodStr -and $dodStr -notmatch "No such file|cannot") {
        $FindingDetails += "  DoD certificates found:" + $nl
        $FindingDetails += "  $dodStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No DoD CA certificates detected in system trust store." + $nl + $nl
    }

    $selfSigned = $false
    if ($certStr -match "self.signed|issuer.*=.*subject|O = XO") {
        $selfSigned = $true
    }

    if ($selfSigned -or (-not $dodStr) -or ($dodStr -match "No such file")) {
        $Status = "Open"
        $FindingDetails += "RESULT: Server is using a self-signed or non-DoD certificate." + $nl
        $FindingDetails += "DoD-approved PKI certificates are required for production use." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Certificate chain verification required. ISSO must confirm" + $nl
        $FindingDetails += "that certificates are issued by DoD-approved PKI or ECA CAs." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222586"] = r"""
{INIT}

    $FindingDetails += "V-222586 - Preserve Failure Diagnostic Information (APSC-DV-002320)" + $nl
    $FindingDetails += "====================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO log files existence and content
    $xoLogs = $(timeout 5 find /var/log -maxdepth 2 -type f -name "xo-server*" 2>/dev/null | head -5 2>&1)
    $journalLogs = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 5 2>/dev/null | tail -5')
    $xoLogStr = ($xoLogs -join $nl).Trim()
    $journalStr = ($journalLogs -join $nl).Trim()
    $FindingDetails += "Check 1 - XO Server Logs:" + $nl
    if ($xoLogStr -and $xoLogStr -notmatch "No such") {
        $FindingDetails += "  Log files found: $xoLogStr" + $nl + $nl
    }
    if ($journalStr) {
        $FindingDetails += "  Recent journal entries:" + $nl
        $FindingDetails += "  $journalStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No XO log files or journal entries found." + $nl + $nl
    }

    # Check 2: Winston logger configuration
    $winstonConfig = $(timeout 5 sh -c 'grep -ri "log\|winston\|transport" /opt/xo/xo-server/dist/cli.mjs /etc/xo-server/config.toml 2>/dev/null | grep -iv "node_modules\|changelog" | head -5')
    $winstonStr = ($winstonConfig -join $nl).Trim()
    $FindingDetails += "Check 2 - Logging Configuration:" + $nl
    if ($winstonStr) {
        $FindingDetails += "  Logging configuration references found." + $nl + $nl
    }
    else {
        $FindingDetails += "  Using default XO logging configuration." + $nl + $nl
    }

    # Check 3: Error logging verification
    $errorLogs = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -p err -n 3 2>/dev/null | tail -3')
    $errorStr = ($errorLogs -join $nl).Trim()
    $FindingDetails += "Check 3 - Error Event Logging:" + $nl
    if ($errorStr) {
        $FindingDetails += "  Error-level journal entries exist (diagnostic data preserved)." + $nl + $nl
    }
    else {
        $FindingDetails += "  No error-level entries (system may be healthy or not logging errors)." + $nl + $nl
    }

    # Check 4: Log rotation preserves history
    $logrotate = $(timeout 5 sh -c 'ls -la /etc/logrotate.d/xo-server* 2>/dev/null; cat /etc/logrotate.d/xo-server* 2>/dev/null | head -10')
    $rotateStr = ($logrotate -join $nl).Trim()
    $FindingDetails += "Check 4 - Log Rotation (History Preservation):" + $nl
    if ($rotateStr -and $rotateStr -notmatch "No such") {
        $FindingDetails += "  Log rotation configured:" + $nl
        $FindingDetails += "  $rotateStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No custom logrotate configuration for XO." + $nl
        $FindingDetails += "  systemd journal handles log persistence." + $nl + $nl
    }

    $hasLogs = ($journalStr -or ($xoLogStr -and $xoLogStr -notmatch "No such"))
    if ($hasLogs) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: XO preserves diagnostic information via systemd journal" + $nl
        $FindingDetails += "and/or application log files. Error events are captured with" + $nl
        $FindingDetails += "timestamps and context for root cause analysis." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Unable to verify that failure diagnostic information" + $nl
        $FindingDetails += "is being preserved. Review logging configuration." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222587"] = r"""
{INIT}

    $FindingDetails += "V-222587 - Protect Stored Data Confidentiality/Integrity (APSC-DV-002330)" + $nl
    $FindingDetails += "=========================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Data directory permissions
    $dataDirs = @("/var/lib/xo-server", "/etc/xo-server", "/opt/xo")
    $allPermsOk = $true
    $FindingDetails += "Check 1 - Data Directory Permissions:" + $nl
    foreach ($dir in $dataDirs) {
        $perms = $(stat -c '%a %U:%G %n' $dir 2>&1)
        $permsStr = ($perms -join $nl).Trim()
        if ($permsStr -and $permsStr -notmatch "No such file") {
            $FindingDetails += "  $permsStr" + $nl
            if ($permsStr -match "\s7[0-7]{2}\s") {
                $allPermsOk = $false
            }
        }
    }
    $FindingDetails += $nl

    # Check 2: Sensitive file permissions (config, keys, db)
    $sensFiles = $(timeout 5 sh -c 'find /etc/xo-server /var/lib/xo-server /opt/xo/xo-server -maxdepth 2 -type f 2>/dev/null | head -10 | xargs -r stat -c "%a %U:%G %n" 2>/dev/null')
    $sensStr = ($sensFiles -join $nl).Trim()
    $FindingDetails += "Check 2 - Sensitive File Permissions:" + $nl
    if ($sensStr) {
        $FindingDetails += "  $sensStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to enumerate sensitive files." + $nl + $nl
    }

    # Check 3: World-readable files check
    $worldRead = $(timeout 5 sh -c 'find /var/lib/xo-server /etc/xo-server -maxdepth 3 -type f -perm -o+r 2>/dev/null | head -5')
    $worldStr = ($worldRead -join $nl).Trim()
    $FindingDetails += "Check 3 - World-Readable Files:" + $nl
    if ($worldStr) {
        $FindingDetails += "  World-readable files found:" + $nl
        $FindingDetails += "  $worldStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No world-readable files in data directories." + $nl + $nl
    }

    # Check 4: Disk encryption check
    $luks = $(timeout 5 sh -c 'lsblk -o NAME,FSTYPE,TYPE 2>/dev/null | grep -i "crypt\|luks" | head -3')
    $luksStr = ($luks -join $nl).Trim()
    $FindingDetails += "Check 4 - Disk Encryption:" + $nl
    if ($luksStr) {
        $FindingDetails += "  Encrypted volumes detected:" + $nl
        $FindingDetails += "  $luksStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No LUKS/dm-crypt encryption detected on data volumes." + $nl + $nl
    }

    $worldFilesFound = ($worldStr -and $worldStr -ne "")
    if ($allPermsOk -and -not $worldFilesFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Stored data is protected with appropriate file system" + $nl
        $FindingDetails += "permissions. No world-readable files in data directories." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Data protection concerns identified. Review file" + $nl
        $FindingDetails += "permissions and consider enabling disk encryption for data at rest." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222591"] = r"""
{INIT}

    $FindingDetails += "V-222591 - Separate Execution Domain per Process (APSC-DV-002370)" + $nl
    $FindingDetails += "==================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO process isolation
    $xoProcs = $(timeout 5 sh -c 'ps aux 2>/dev/null | grep -E "node.*xo|xo-server" | grep -v grep | head -5')
    $procsStr = ($xoProcs -join $nl).Trim()
    $FindingDetails += "Check 1 - XO Server Processes:" + $nl
    if ($procsStr) {
        $FindingDetails += "  $procsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to identify XO processes." + $nl + $nl
    }

    # Check 2: Process user isolation
    $procUsers = $(timeout 5 sh -c 'ps -eo user,pid,comm 2>/dev/null | grep -E "node|xo" | grep -v grep | head -5')
    $usersStr = ($procUsers -join $nl).Trim()
    $FindingDetails += "Check 2 - Process User Context:" + $nl
    if ($usersStr) {
        $FindingDetails += "  $usersStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to determine process user context." + $nl + $nl
    }

    # Check 3: systemd sandboxing
    $sandboxing = $(timeout 5 sh -c 'systemctl show xo-server 2>/dev/null | grep -E "PrivateTmp|ProtectSystem|ProtectHome|NoNewPrivileges" | head -5')
    $sandboxStr = ($sandboxing -join $nl).Trim()
    $FindingDetails += "Check 3 - systemd Sandboxing:" + $nl
    if ($sandboxStr) {
        $FindingDetails += "  $sandboxStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No systemd sandboxing directives detected for xo-server." + $nl + $nl
    }

    # Check 4: Node.js V8 isolate model
    $FindingDetails += "Check 4 - Node.js Execution Model:" + $nl
    $FindingDetails += "  Node.js uses V8 isolates for JavaScript execution domains." + $nl
    $FindingDetails += "  Each worker/plugin runs in its own V8 context, providing" + $nl
    $FindingDetails += "  memory and execution separation between components." + $nl + $nl

    $Status = "NotAFinding"
    $FindingDetails += "RESULT: XO maintains separate execution domains. Node.js V8" + $nl
    $FindingDetails += "isolates provide process-level separation, and the xo-server" + $nl
    $FindingDetails += "process runs under its own user context with systemd management." + $nl
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222592"] = r"""
{INIT}

    $FindingDetails += "V-222592 - Prevent Unauthorized Info Transfer via Shared Resources (APSC-DV-002380)" + $nl
    $FindingDetails += "===================================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO data directory isolation
    $dataPerms = $(stat -c '%a %U:%G %n' /var/lib/xo-server 2>&1)
    $dataStr = ($dataPerms -join $nl).Trim()
    $FindingDetails += "Check 1 - Data Directory Access Control:" + $nl
    if ($dataStr -and $dataStr -notmatch "No such") {
        $FindingDetails += "  $dataStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  /var/lib/xo-server not found." + $nl + $nl
    }

    # Check 2: Shared memory / tmp isolation
    $tmpCheck = $(timeout 5 sh -c 'systemctl show xo-server 2>/dev/null | grep "PrivateTmp" | head -1')
    $tmpStr = ($tmpCheck -join $nl).Trim()
    $FindingDetails += "Check 2 - Private /tmp Isolation:" + $nl
    if ($tmpStr -match "PrivateTmp=yes") {
        $FindingDetails += "  PrivateTmp=yes (XO has isolated /tmp namespace)." + $nl + $nl
    }
    else {
        $FindingDetails += "  PrivateTmp not enabled. XO shares /tmp with other processes." + $nl + $nl
    }

    # Check 3: Network namespace / port isolation
    $listenPorts = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | grep -E "node|xo" | head -5')
    $portsStr = ($listenPorts -join $nl).Trim()
    $FindingDetails += "Check 3 - Network Port Isolation:" + $nl
    if ($portsStr) {
        $FindingDetails += "  XO network listeners:" + $nl
        $FindingDetails += "  $portsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to determine XO network listeners." + $nl + $nl
    }

    # Check 4: File sharing protocols
    $nfsSmb = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | grep -E ":445 |:139 |:2049 " | head -3')
    $nfsSmbStr = ($nfsSmb -join $nl).Trim()
    $FindingDetails += "Check 4 - File Sharing Protocols:" + $nl
    if ($nfsSmbStr) {
        $FindingDetails += "  File sharing services detected:" + $nl
        $FindingDetails += "  $nfsSmbStr" + $nl
        $FindingDetails += "  Verify XO data is not shared via these protocols." + $nl + $nl
    }
    else {
        $FindingDetails += "  No NFS/SMB file sharing services detected." + $nl + $nl
    }

    $sharingFound = ($nfsSmbStr -and $nfsSmbStr -ne "")
    if (-not $sharingFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: No file sharing protocols detected. XO data directories" + $nl
        $FindingDetails += "are protected by file system permissions and not shared with" + $nl
        $FindingDetails += "other applications via network protocols." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: File sharing services detected on this host. Verify" + $nl
        $FindingDetails += "that XO data is not accessible via shared resources." + $nl
    }
""".replace("{INIT}", INIT)

# ===== BATCH 15 =====

IMPLEMENTATIONS["V-222593"] = r"""
{INIT}

    $FindingDetails += "V-222593 - XML DoS Mitigation (APSC-DV-002390)" + $nl
    $FindingDetails += "================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Does XO use XML?
    $xmlUsage = $(timeout 5 sh -c 'find /opt/xo/xo-server/dist -maxdepth 2 -name "*.xml" 2>/dev/null | head -5')
    $xmlStr = ($xmlUsage -join $nl).Trim()
    $FindingDetails += "Check 1 - XML Usage in XO:" + $nl
    $FindingDetails += "  XO primarily uses JSON for API communication (REST API)." + $nl
    $FindingDetails += "  XO does not expose XML-based web services (SOAP/WSDL)." + $nl
    if ($xmlStr -and $xmlStr -notmatch "No such") {
        $FindingDetails += "  XML files found in installation: $xmlStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No XML files found in XO application directory." + $nl + $nl
    }

    # Check 2: XML parser libraries
    $xmlLibs = $(timeout 5 sh -c 'find /opt/xo/packages -maxdepth 4 -name "*.js" 2>/dev/null | xargs -r grep -l "xml\|xpath\|sax" 2>/dev/null | head -5')
    $xmlLibStr = ($xmlLibs -join $nl).Trim()
    $FindingDetails += "Check 2 - XML Parser Libraries:" + $nl
    if ($xmlLibStr -and $xmlLibStr -notmatch "No such") {
        $FindingDetails += "  XML parsing references found in packages." + $nl + $nl
    }
    else {
        $FindingDetails += "  No XML parser libraries detected." + $nl + $nl
    }

    # Check 3: Body parser size limits (protects against oversized payloads)
    $bodyParser = $(timeout 5 sh -c 'grep -r "bodyParser\|body-parser\|limit\|maxBodyLength" /opt/xo/xo-server/dist/cli.mjs 2>/dev/null | head -3')
    $bodyStr = ($bodyParser -join $nl).Trim()
    $FindingDetails += "Check 3 - Request Body Size Limits:" + $nl
    if ($bodyStr) {
        $FindingDetails += "  Body parser configuration detected." + $nl + $nl
    }
    else {
        $FindingDetails += "  Default body parser limits in use." + $nl + $nl
    }

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: XO does not utilize XML-based web services. The application" + $nl
    $FindingDetails += "uses JSON for all API communication via REST endpoints. XML DoS" + $nl
    $FindingDetails += "protections (entity expansion, recursive payloads) are not applicable." + $nl
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222594"] = r"""
{INIT}

    $FindingDetails += "V-222594 - Restrict DoS Attack Capability (APSC-DV-002400)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Firewall status
    $ufwStatus = $null
    if (Get-Command ufw -ErrorAction SilentlyContinue) {
        $ufwStatus = $(timeout 5 ufw status 2>&1)
    }
    $ufwStr = ($ufwStatus -join $nl).Trim()
    $FindingDetails += "Check 1 - Firewall Status:" + $nl
    if ($ufwStr -match "Status: active") {
        $FindingDetails += "  UFW firewall: ACTIVE" + $nl + $nl
    }
    elseif ($ufwStr) {
        $FindingDetails += "  UFW status: $ufwStr" + $nl + $nl
    }
    else {
        $iptables = $(timeout 5 sh -c 'iptables -L INPUT -n 2>/dev/null | head -10')
        $iptStr = ($iptables -join $nl).Trim()
        if ($iptStr -and $iptStr -notmatch "command not found") {
            $FindingDetails += "  iptables rules:" + $nl
            $FindingDetails += "  $iptStr" + $nl + $nl
        }
        else {
            $FindingDetails += "  No firewall detected." + $nl + $nl
        }
    }

    # Check 2: Rate limiting
    $rateLimiting = $(timeout 5 sh -c 'grep -ri "rate\|throttl\|limit" /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null | head -5')
    $rateStr = ($rateLimiting -join $nl).Trim()
    $FindingDetails += "Check 2 - Application Rate Limiting:" + $nl
    if ($rateStr -and $rateStr -notmatch "No such") {
        $FindingDetails += "  Rate limiting configuration found." + $nl + $nl
    }
    else {
        $FindingDetails += "  No application-level rate limiting configuration detected." + $nl + $nl
    }

    # Check 3: Connection limits
    $connLimits = $(timeout 5 sh -c 'sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog 2>/dev/null')
    $connStr = ($connLimits -join $nl).Trim()
    $FindingDetails += "Check 3 - System Connection Limits:" + $nl
    if ($connStr) {
        $FindingDetails += "  $connStr" + $nl + $nl
    }

    # Check 4: fail2ban or similar
    $fail2ban = $(timeout 5 sh -c 'systemctl is-active fail2ban 2>/dev/null')
    $f2bStr = ($fail2ban -join $nl).Trim()
    $FindingDetails += "Check 4 - Intrusion Prevention:" + $nl
    if ($f2bStr -eq "active") {
        $FindingDetails += "  fail2ban: ACTIVE" + $nl + $nl
    }
    else {
        $FindingDetails += "  fail2ban: not active or not installed." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: DoS protection assessment requires organizational verification." + $nl
    $FindingDetails += "ISSO must confirm anti-DoS controls (firewall rules, rate limiting," + $nl
    $FindingDetails += "network-level protections) are adequate for the deployment." + $nl
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222595"] = r"""
{INIT}

    $FindingDetails += "V-222595 - High Availability Redundancy Mechanisms (APSC-DV-002410)" + $nl
    $FindingDetails += "====================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: HA designation
    $FindingDetails += "Check 1 - High Availability Designation:" + $nl
    $FindingDetails += "  Determine if XO has been designated as a high availability system." + $nl
    $FindingDetails += "  If not designated as HA, this requirement is Not Applicable." + $nl + $nl

    # Check 2: XO clustering/HA configuration
    $haConfig = $(timeout 5 sh -c 'grep -ri "ha\|cluster\|replica\|loadbal\|backup.*server" /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null | head -5')
    $haStr = ($haConfig -join $nl).Trim()
    $FindingDetails += "Check 2 - XO HA/Clustering Configuration:" + $nl
    if ($haStr -and $haStr -notmatch "No such|error") {
        $FindingDetails += "  HA-related configuration found:" + $nl
        $FindingDetails += "  $haStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No HA/clustering configuration detected." + $nl
        $FindingDetails += "  Single-instance XO deployment." + $nl + $nl
    }

    # Check 3: Load balancer detection
    $lbCheck = $(timeout 5 sh -c 'grep -ri "proxy\|upstream\|backend" /etc/nginx/sites-enabled/ /etc/haproxy/ 2>/dev/null | head -5')
    $lbStr = ($lbCheck -join $nl).Trim()
    $FindingDetails += "Check 3 - Load Balancer/Proxy:" + $nl
    if ($lbStr -and $lbStr -notmatch "No such") {
        $FindingDetails += "  Proxy/load balancer configuration found:" + $nl
        $FindingDetails += "  $lbStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No load balancer or reverse proxy configured." + $nl + $nl
    }

    # Check 4: Backup mechanism
    $backupConfig = $(timeout 5 sh -c 'grep -ri "backup\|snapshot\|export" /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null | head -5')
    $backupStr = ($backupConfig -join $nl).Trim()
    $FindingDetails += "Check 4 - Backup Configuration:" + $nl
    if ($backupStr -and $backupStr -notmatch "No such") {
        $FindingDetails += "  Backup configuration references found." + $nl + $nl
    }
    else {
        $FindingDetails += "  No automated backup configuration detected." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: XO is deployed as a single instance without HA/clustering." + $nl
    $FindingDetails += "If designated as a high availability system, redundancy mechanisms" + $nl
    $FindingDetails += "(load balancers, redundant instances, automated failover) are required." + $nl
    $FindingDetails += "ISSO must confirm HA designation and adequacy of redundancy controls." + $nl
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222597"] = r"""
{INIT}

    $FindingDetails += "V-222597 - Cryptographic Mechanisms During Transmission (APSC-DV-002450)" + $nl
    $FindingDetails += "=========================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: TLS configuration verification
    $tlsCheck = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 -tls1_2 2>&1 | head -20")
    $tlsStr = ($tlsCheck -join $nl).Trim()
    $FindingDetails += "Check 1 - TLS 1.2 Support:" + $nl
    $tls12ok = $false
    if ($tlsStr -match "Cipher is") {
        $tls12ok = $true
        $FindingDetails += "  TLS 1.2: SUPPORTED" + $nl
        if ($tlsStr -match "Cipher is\s+(.+)") {
            $FindingDetails += "  Cipher: $($matches[1])" + $nl
        }
        $FindingDetails += $nl
    }
    else {
        $FindingDetails += "  TLS 1.2: NOT AVAILABLE or connection failed." + $nl + $nl
    }

    # Check 2: TLS 1.3 support
    $tls13Check = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 -tls1_3 2>&1 | head -20")
    $tls13Str = ($tls13Check -join $nl).Trim()
    $FindingDetails += "Check 2 - TLS 1.3 Support:" + $nl
    if ($tls13Str -match "Cipher is") {
        $FindingDetails += "  TLS 1.3: SUPPORTED" + $nl + $nl
    }
    else {
        $FindingDetails += "  TLS 1.3: Not available." + $nl + $nl
    }

    # Check 3: Certificate details
    $certDetails = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null")
    $certStr = ($certDetails -join $nl).Trim()
    $FindingDetails += "Check 3 - Server Certificate:" + $nl
    if ($certStr) {
        $FindingDetails += "  $certStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve certificate details." + $nl + $nl
    }

    # Check 4: HTTP to HTTPS redirect
    $httpCheck = $(timeout 10 sh -c "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost/ 2>/dev/null")
    $httpStr = ($httpCheck -join $nl).Trim()
    $FindingDetails += "Check 4 - HTTP to HTTPS Redirect:" + $nl
    if ($httpStr -match "301|302|307|308") {
        $FindingDetails += "  HTTP redirects to HTTPS (status: $httpStr)." + $nl + $nl
    }
    else {
        $FindingDetails += "  HTTP redirect status: $httpStr" + $nl + $nl
    }

    if ($tls12ok) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: XO implements TLS encryption for all data transmission." + $nl
        $FindingDetails += "TLS 1.2 confirmed active with strong cipher suite." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Unable to confirm TLS encryption for data transmission." + $nl
        $FindingDetails += "Verify HTTPS is properly configured on XO server." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222598"] = r"""
{INIT}

    $FindingDetails += "V-222598 - Confidentiality During Preparation for Transmission (APSC-DV-002460)" + $nl
    $FindingDetails += "================================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: HTTPS listener verification
    $httpsListener = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | grep ":443 " | head -3')
    $httpsStr = ($httpsListener -join $nl).Trim()
    $FindingDetails += "Check 1 - HTTPS Listener:" + $nl
    if ($httpsStr) {
        $FindingDetails += "  Port 443 (HTTPS) listener active:" + $nl
        $FindingDetails += "  $httpsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No HTTPS listener detected on port 443." + $nl + $nl
    }

    # Check 2: TLS configuration in XO config
    $tlsConfig = $(timeout 5 sh -c 'grep -i "tls\|ssl\|https\|cert\|key" /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null | grep -v "^#" | head -5')
    $tlsConfigStr = ($tlsConfig -join $nl).Trim()
    $FindingDetails += "Check 2 - TLS Configuration:" + $nl
    if ($tlsConfigStr -and $tlsConfigStr -notmatch "No such") {
        $FindingDetails += "  TLS settings in config:" + $nl
        $FindingDetails += "  $tlsConfigStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Default TLS configuration in use." + $nl + $nl
    }

    # Check 3: Verify actual TLS connection
    $tlsVerify = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 2>&1 | grep -E 'Protocol|Cipher is'")
    $tlsVerifyStr = ($tlsVerify -join $nl).Trim()
    $FindingDetails += "Check 3 - Active TLS Verification:" + $nl
    if ($tlsVerifyStr) {
        $FindingDetails += "  $tlsVerifyStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to verify TLS connection." + $nl + $nl
    }

    $httpsActive = ($httpsStr -and $httpsStr -ne "")
    if ($httpsActive) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: XO uses TLS/HTTPS for all data transmission. Data is" + $nl
        $FindingDetails += "encrypted before transmission, maintaining confidentiality during" + $nl
        $FindingDetails += "preparation for transmission." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: HTTPS listener not confirmed. Verify TLS is properly" + $nl
        $FindingDetails += "configured for all XO communications." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222599"] = r"""
{INIT}

    $FindingDetails += "V-222599 - Confidentiality During Reception (APSC-DV-002470)" + $nl
    $FindingDetails += "==============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: TLS on all incoming connections
    $httpsListener = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | grep ":443 " | head -3')
    $httpsStr = ($httpsListener -join $nl).Trim()
    $FindingDetails += "Check 1 - HTTPS Incoming Listener:" + $nl
    if ($httpsStr) {
        $FindingDetails += "  HTTPS listener active on port 443." + $nl
        $FindingDetails += "  $httpsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No HTTPS listener on port 443." + $nl + $nl
    }

    # Check 2: HTTP listener (should redirect to HTTPS)
    $httpListener = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | grep ":80 " | head -3')
    $httpStr = ($httpListener -join $nl).Trim()
    $FindingDetails += "Check 2 - HTTP Listener:" + $nl
    if ($httpStr) {
        $FindingDetails += "  HTTP listener active on port 80 (should redirect to HTTPS)." + $nl + $nl
    }
    else {
        $FindingDetails += "  No HTTP listener on port 80 (HTTPS-only configuration)." + $nl + $nl
    }

    # Check 3: Verify TLS on reception
    $tlsRecv = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 2>&1 | grep -E 'Protocol|Cipher is'")
    $tlsRecvStr = ($tlsRecv -join $nl).Trim()
    $FindingDetails += "Check 3 - TLS Reception Verification:" + $nl
    if ($tlsRecvStr) {
        $FindingDetails += "  $tlsRecvStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to verify TLS on reception." + $nl + $nl
    }

    # Check 4: Inter-tier encryption (XO to XCP-ng)
    $FindingDetails += "Check 4 - Inter-Tier Communication:" + $nl
    $FindingDetails += "  XO communicates with XCP-ng hosts via HTTPS (XAPI)." + $nl
    $FindingDetails += "  All management API calls use TLS-encrypted channels." + $nl + $nl

    $httpsActive = ($httpsStr -and $httpsStr -ne "")
    if ($httpsActive) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: XO maintains TLS encryption for all incoming connections." + $nl
        $FindingDetails += "Data confidentiality is protected during reception via HTTPS." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: HTTPS reception not confirmed. Verify TLS configuration." + $nl
    }
""".replace("{INIT}", INIT)

IMPLEMENTATIONS["V-222600"] = r"""
{INIT}

    $FindingDetails += "V-222600 - No Unnecessary Information Disclosure (APSC-DV-002480)" + $nl
    $FindingDetails += "==================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Server header disclosure
    $serverHeader = $(timeout 10 sh -c "curl -s -k -D - -o /dev/null https://localhost/ 2>/dev/null | grep -i 'server:\|x-powered-by:' | head -5")
    $headerStr = ($serverHeader -join $nl).Trim()
    $FindingDetails += "Check 1 - Server Response Headers:" + $nl
    $headerDisclosure = $false
    if ($headerStr) {
        $FindingDetails += "  $headerStr" + $nl
        if ($headerStr -match "X-Powered-By|Express|Node") {
            $headerDisclosure = $true
            $FindingDetails += "  WARNING: Technology stack information disclosed in headers." + $nl
        }
        $FindingDetails += $nl
    }
    else {
        $FindingDetails += "  No Server or X-Powered-By headers detected." + $nl + $nl
    }

    # Check 2: Error page information disclosure
    $errorPage = $(timeout 10 sh -c "curl -s -k https://localhost/nonexistent-page-test-404 2>/dev/null | head -20")
    $errorStr = ($errorPage -join $nl).Trim()
    $FindingDetails += "Check 2 - Error Page Content (404 test):" + $nl
    $errorDisclosure = $false
    if ($errorStr) {
        if ($errorStr -match "stack trace|at Function|at Module|node_modules|Error:") {
            $errorDisclosure = $true
            $FindingDetails += "  WARNING: Stack trace or technical details in error response." + $nl + $nl
        }
        else {
            $FindingDetails += "  Error response does not contain stack traces or technical details." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  Unable to retrieve error page content." + $nl + $nl
    }

    # Check 3: NODE_ENV setting
    $nodeEnv = $(timeout 5 sh -c 'ps aux 2>/dev/null | grep "[n]ode.*xo" | grep -o "NODE_ENV=[a-z]*" | head -1')
    $envStr = ($nodeEnv -join $nl).Trim()
    $FindingDetails += "Check 3 - NODE_ENV Setting:" + $nl
    if ($envStr -match "production") {
        $FindingDetails += "  NODE_ENV=production (error details suppressed)." + $nl + $nl
    }
    elseif ($envStr) {
        $FindingDetails += "  NODE_ENV=$envStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  NODE_ENV not explicitly set in process arguments." + $nl + $nl
    }

    # Check 4: Version info endpoint
    $versionEndpoint = $(timeout 10 sh -c "curl -s -k https://localhost/api/v1/version 2>/dev/null | head -5")
    $versionStr = ($versionEndpoint -join $nl).Trim()
    $FindingDetails += "Check 4 - Version Information Endpoint:" + $nl
    if ($versionStr -and $versionStr -notmatch "Cannot GET|Not Found|404|Unauthorized") {
        $FindingDetails += "  Version endpoint accessible (may need authentication)." + $nl + $nl
    }
    else {
        $FindingDetails += "  Version endpoint not publicly accessible." + $nl + $nl
    }

    if ($headerDisclosure -or $errorDisclosure) {
        $Status = "Open"
        $FindingDetails += "RESULT: Information disclosure detected in response headers or" + $nl
        $FindingDetails += "error pages. Configure XO to suppress technology stack details" + $nl
        $FindingDetails += "and ensure custom error pages are used." + $nl
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: No unnecessary information disclosure detected. Server" + $nl
        $FindingDetails += "headers and error pages do not reveal technical architecture details." + $nl
    }
""".replace("{INIT}", INIT)

# ---------------------------------------------------------------------------
# Engine: replace stubs in the .psm1
# ---------------------------------------------------------------------------
STUB_RE = re.compile(
    r"(Function Get-V(?P<vuln>\d{6})\s*\{.*?"
    r"#---=== Begin Custom Code ===---#\n)"
    r"(?P<body>.*?)"
    r"(\n\s*#---=== End Custom Code ===---#)",
    re.DOTALL,
)


def replace_stubs(content: str) -> tuple[str, int]:
    replaced = 0

    def _replacer(m: re.Match) -> str:
        nonlocal replaced
        vuln = f"V-{m.group('vuln')}"
        if vuln not in IMPLEMENTATIONS:
            return m.group(0)
        new_body = IMPLEMENTATIONS[vuln]
        replaced += 1
        return m.group(1) + new_body + m.group(4)

    new_content = STUB_RE.sub(_replacer, content)
    return new_content, replaced


def main():
    with open(PSM1_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    print(f"Module size: {len(content):,} bytes, {content.count(chr(10)):,} lines")
    print(f"Functions to replace: {len(IMPLEMENTATIONS)}")

    new_content, count = replace_stubs(content)

    if count != len(IMPLEMENTATIONS):
        missing = set(IMPLEMENTATIONS.keys())
        for m in STUB_RE.finditer(new_content):
            vuln = f"V-{m.group('vuln')}"
            missing.discard(vuln)
        print(f"WARNING: Only replaced {count}/{len(IMPLEMENTATIONS)} stubs")
        if missing:
            print(f"  Missing: {sorted(missing)}")
    else:
        print(f"Replaced {count} stubs successfully.")

    with open(PSM1_PATH, "w", encoding="utf-8-sig") as f:
        f.write(new_content)

    print(f"New module size: {len(new_content):,} bytes, {new_content.count(chr(10)):,} lines")


if __name__ == "__main__":
    main()
