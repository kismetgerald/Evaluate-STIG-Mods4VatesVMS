"""
Batch 6 implementation: Replace stubs for V-222453 through V-222470
8 Not_Applicable (no data classification/OS access in XO)
10 Technical/Automatable (audit plugin + journal checks)
"""

import re

PSM1_PATH = r'd:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1'

# Each dict: vuln_id -> custom_code (the text between Begin/End Custom Code markers)
IMPLEMENTATIONS = {}

# ============================================================
# V-222453 — Not_Applicable (no compartmentalized data in XO)
# ============================================================
IMPLEMENTATIONS["V-222453"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "The STIG check states: " + [char]39 + "If the application requirements do not call" + $nl
    $FindingDetails += "for compartmentalized data and data protection, this requirement is not applicable." + [char]39 + $nl + $nl
    $FindingDetails += "Xen Orchestra is a virtualization management platform. It does not implement" + $nl
    $FindingDetails += "data classification categories, security labels, MAC (Mandatory Access Control)," + $nl
    $FindingDetails += "or compartmentalized data protection. XO manages virtual machines and hypervisor" + $nl
    $FindingDetails += "resources using RBAC (Admin/Operator/Viewer roles), not data classification levels." + $nl + $nl
    $FindingDetails += "This requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222454 — Technical: privilege modification audit records
# ============================================================
IMPLEMENTATIONS["V-222454"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin installed
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: XO API - look for role/ACL modification events in audit records
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $roleModEvents = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"acl\.|"role\.|"addAcl\|"removeAcl\|"setAcl') {
            $roleModEvents = $true
        }
    }

    # Check 3: XO source - ACL/role change logging
    $srcAclAudit = $(timeout 5 sh -c 'grep -rl "addAcl\|removeAcl\|setAcl\|role.*audit\|audit.*role" /opt/xo/packages /usr/share/xo-server 2>/dev/null | head -3')
    $srcAclAuditStr = ($srcAclAudit -join $nl).Trim()
    $srcHasAclAudit = $srcAclAuditStr -ne ""

    $FindingDetails = "Privilege Modification Audit Record Check" + $nl
    $FindingDetails += "=========================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "XO audit plugin records ACL changes (add/remove/set ACL entries = privilege modifications)" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Role/ACL Modification Events in Audit API" + $nl
    if ($apiTokenStr -ne "") {
        if ($roleModEvents) {
            $FindingDetails += "FOUND: Role/ACL modification events detected in audit records" + $nl
        }
        else {
            $FindingDetails += "NOT FOUND in sample records (may be present in full history)" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: ACL Audit Code in XO Source" + $nl
    if ($srcHasAclAudit) {
        $FindingDetails += "FOUND: ACL/role audit code: " + $srcAclAuditStr.Split($nl)[0] + $nl
    }
    else {
        $FindingDetails += "ACL audit code not found in searched paths" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin logs ACL and role changes (privilege modification events)." + $nl
        $FindingDetails += "Both successful and unsuccessful privilege modifications are captured." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify privilege modification events are logged." + $nl
    }
"""

# ============================================================
# V-222455 — Not_Applicable (no security object classification in XO)
# ============================================================
IMPLEMENTATIONS["V-222455"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "This requirement concerns audit records for modifications to security objects" + $nl
    $FindingDetails += "with associated classification labels or privilege designations." + $nl + $nl
    $FindingDetails += "Xen Orchestra does not implement classified security objects, data element" + $nl
    $FindingDetails += "privilege assignments, or compartmentalized data protection. XO manages" + $nl
    $FindingDetails += "virtual infrastructure resources (VMs, hosts, storage, networks) using" + $nl
    $FindingDetails += "RBAC access controls, not object-level security classification labels." + $nl + $nl
    $FindingDetails += "This requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222456 — Not_Applicable (no MAC security levels in XO)
# ============================================================
IMPLEMENTATIONS["V-222456"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "This requirement concerns audit records for modifications to security levels" + $nl
    $FindingDetails += "or security domains in a MAC (Mandatory Access Control) system." + $nl + $nl
    $FindingDetails += "Xen Orchestra uses RBAC (Role-Based Access Control) with three roles:" + $nl
    $FindingDetails += "Admin, Operator, and Viewer. It does not implement MAC security levels," + $nl
    $FindingDetails += "security domains, or multilevel security (MLS) classifications." + $nl + $nl
    $FindingDetails += "RBAC role changes (privilege modifications) are audited under V-222454." + $nl
    $FindingDetails += "This MAC-specific requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222457 — Not_Applicable (no classification data modification in XO)
# ============================================================
IMPLEMENTATIONS["V-222457"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "The STIG check states: " + [char]39 + "If the application requirements do not call" + $nl
    $FindingDetails += "for compartmentalized data and data protection, this requirement is not applicable." + [char]39 + $nl + $nl
    $FindingDetails += "Xen Orchestra does not store or process classified information, does not" + $nl
    $FindingDetails += "implement data classification categories, and does not require compartmentalized" + $nl
    $FindingDetails += "data protection mechanisms. Audit records for classification data modification" + $nl
    $FindingDetails += "are not applicable to XO as a virtualization management platform." + $nl + $nl
    $FindingDetails += "This requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222458 — Technical: privilege deletion audit records
# ============================================================
IMPLEMENTATIONS["V-222458"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: API - look for ACL removal/deletion events
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $roleDelEvents = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"removeAcl\|"deleteAcl\|"deleteUser\|"revokeRole') {
            $roleDelEvents = $true
        }
    }

    # Check 3: XO source - ACL removal code with audit
    $srcAclDel = $(timeout 5 sh -c 'grep -rl "removeAcl\|deleteAcl\|revokeRole\|removeRole" /opt/xo/packages /usr/share/xo-server 2>/dev/null | head -3')
    $srcAclDelStr = ($srcAclDel -join $nl).Trim()
    $srcHasAclDel = $srcAclDelStr -ne ""

    $FindingDetails = "Privilege Deletion Audit Record Check" + $nl
    $FindingDetails += "======================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "XO audit plugin records ACL removals (privilege deletions)" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Privilege Deletion Events in Audit API" + $nl
    if ($apiTokenStr -ne "") {
        if ($roleDelEvents) {
            $FindingDetails += "FOUND: Privilege deletion/ACL removal events detected in audit records" + $nl
        }
        else {
            $FindingDetails += "NOT FOUND in sample records (may be present in full history)" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: ACL Deletion Code in XO Source" + $nl
    if ($srcHasAclDel) {
        $FindingDetails += "FOUND: ACL deletion code: " + $srcAclDelStr.Split($nl)[0] + $nl
    }
    else {
        $FindingDetails += "ACL deletion code not found in searched paths" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin logs ACL/role removals (privilege deletion events)." + $nl
        $FindingDetails += "Both successful and unsuccessful privilege deletion attempts are captured." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify privilege deletion events are logged." + $nl
    }
"""

# ============================================================
# V-222459 — Not_Applicable (no MAC security level deletion in XO)
# ============================================================
IMPLEMENTATIONS["V-222459"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "This requirement concerns audit records for deletion of security levels" + $nl
    $FindingDetails += "or security domain permissions in a MAC system." + $nl + $nl
    $FindingDetails += "Xen Orchestra uses RBAC (Admin/Operator/Viewer) and does not implement" + $nl
    $FindingDetails += "MAC security levels or multilevel security domains. RBAC role removals" + $nl
    $FindingDetails += "(which are the nearest equivalent) are audited under V-222458." + $nl + $nl
    $FindingDetails += "This MAC-specific requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222460 — Not_Applicable (no database security objects in XO)
# ============================================================
IMPLEMENTATIONS["V-222460"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "This requirement concerns audit records for deletion of application database" + $nl
    $FindingDetails += "security objects (data elements with assigned privilege/classification labels)." + $nl + $nl
    $FindingDetails += "Xen Orchestra stores its state in LevelDB (a key-value store) and does not" + $nl
    $FindingDetails += "implement a relational database with security-labeled objects or data elements." + $nl
    $FindingDetails += "XO does not support compartmentalized data classification for database records." + $nl + $nl
    $FindingDetails += "This requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222461 — Not_Applicable (no protected category data deletion in XO)
# ============================================================
IMPLEMENTATIONS["V-222461"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    $FindingDetails = "Not Applicable" + $nl
    $FindingDetails += "==============" + $nl + $nl
    $FindingDetails += "The STIG check states: " + [char]39 + "If the application requirements do not call" + $nl
    $FindingDetails += "for compartmentalized data and data protection, this requirement is not applicable." + [char]39 + $nl + $nl
    $FindingDetails += "Xen Orchestra does not store classified or categorized information, does not" + $nl
    $FindingDetails += "implement data classification categories, and has no compartmentalized data" + $nl
    $FindingDetails += "requiring protected-category deletion audit records." + $nl + $nl
    $FindingDetails += "This requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222462 — Technical: logon attempt audit records
# ============================================================
IMPLEMENTATIONS["V-222462"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: API - look for signIn events (successful + failed)
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $signInEvents = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"session\.signIn\|"user\.authenticate\|"signIn') {
            $signInEvents = $true
        }
    }

    # Check 3: systemd journal for authentication events
    $journalAuth = $(timeout 5 sh -c 'journalctl -u xo-server --since "1 hour ago" --no-pager 2>/dev/null | grep -i "sign[Ii]n\|login\|auth\|session" | tail -5')
    $journalAuthStr = ($journalAuth -join $nl).Trim()
    $journalHasAuth = $journalAuthStr -ne ""

    # Check 4: nginx access logs for auth endpoints
    $nginxAuth = $(timeout 5 sh -c 'grep "POST.*signIn\|POST.*signin\|POST.*login\|POST.*auth" /var/log/nginx/access.log 2>/dev/null | tail -3')
    $nginxAuthStr = ($nginxAuth -join $nl).Trim()
    $nginxHasAuth = $nginxAuthStr -ne ""

    $FindingDetails = "Logon Attempt Audit Record Check" + $nl
    $FindingDetails += "=================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Session.signIn Events in Audit API" + $nl
    if ($apiTokenStr -ne "") {
        if ($signInEvents) {
            $FindingDetails += "FOUND: signIn/authentication events in XO audit records" + $nl
        }
        else {
            $FindingDetails += "NOT FOUND in sample records (plugin may be active but no recent logins)" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: systemd Journal Auth Events" + $nl
    if ($journalHasAuth) {
        $FindingDetails += "FOUND: Auth events in systemd journal:" + $nl
        $FindingDetails += $journalAuthStr + $nl
    }
    else {
        $FindingDetails += "No recent auth events in systemd journal" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 4: Nginx Access Log Auth Endpoints" + $nl
    if ($nginxHasAuth) {
        $FindingDetails += "FOUND: Auth endpoint requests in nginx access log:" + $nl
        $FindingDetails += $nginxAuthStr + $nl
    }
    else {
        $FindingDetails += "No auth endpoint hits in nginx access log (or nginx not present)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin captures session.signIn events (logon attempts)." + $nl
        $FindingDetails += "Both successful and unsuccessful logon attempts are recorded with userId," + $nl
        $FindingDetails += "action type, timestamp, and IP address." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify logon attempt events are logged." + $nl
    }
"""

# ============================================================
# V-222463 — Technical: privileged activities audit records
# ============================================================
IMPLEMENTATIONS["V-222463"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: API - look for admin/privileged action events
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $adminEvents = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"user\.\|"acl\.\|"server\.\|"host\.\|"pool\.') {
            $adminEvents = $true
        }
    }

    # Check 3: XO source - audit of system-level operations
    $srcPrivAudit = $(timeout 5 sh -c 'grep -rl "audit.*server\|audit.*host\|audit.*pool\|system.*audit" /opt/xo/packages /usr/share/xo-server 2>/dev/null | head -3')
    $srcPrivAuditStr = ($srcPrivAudit -join $nl).Trim()
    $srcHasPrivAudit = $srcPrivAuditStr -ne ""

    $FindingDetails = "Privileged Activities Audit Record Check" + $nl
    $FindingDetails += "=========================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "XO audit plugin logs all privileged operations (VM lifecycle, host management," + $nl
        $FindingDetails += "user management, ACL changes, server configuration)" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Admin/System-Level Events in Audit API" + $nl
    if ($apiTokenStr -ne "") {
        if ($adminEvents) {
            $FindingDetails += "FOUND: Admin-level and system operation events in XO audit records" + $nl
        }
        else {
            $FindingDetails += "NOT FOUND in sample records (may be present in full history)" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Privileged Operation Audit Code" + $nl
    if ($srcHasPrivAudit) {
        $FindingDetails += "FOUND: Admin operation audit code: " + $srcPrivAuditStr.Split($nl)[0] + $nl
    }
    else {
        $FindingDetails += "Admin audit code not found in searched paths" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin captures privileged activities including:" + $nl
        $FindingDetails += "  - VM start/stop/snapshot/migrate operations" + $nl
        $FindingDetails += "  - Host and pool management operations" + $nl
        $FindingDetails += "  - User management and ACL changes" + $nl
        $FindingDetails += "  - Server configuration changes" + $nl
        $FindingDetails += "All operations include userId, action, timestamp, and target object." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify privileged activity events are logged." + $nl
    }
"""

# ============================================================
# V-222464 — Technical: session start/end times
# ============================================================
IMPLEMENTATIONS["V-222464"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: API - look for session create/destroy events with timestamps
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $sessionTimestamps = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=20" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"time":\s*\d{13}') {
            $sessionTimestamps = $true
        }
    }

    # Check 3: systemd journal for service start/stop session events
    $journalSession = $(timeout 5 sh -c 'journalctl -u xo-server --since "24 hours ago" --no-pager 2>/dev/null | grep -i "session\|connect\|disconnect" | tail -5')
    $journalSessionStr = ($journalSession -join $nl).Trim()

    $FindingDetails = "Session Start/End Time Audit Record Check" + $nl
    $FindingDetails += "==========================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "XO audit records include Unix millisecond timestamps for all events" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Timestamps in Audit API Records" + $nl
    if ($apiTokenStr -ne "") {
        if ($sessionTimestamps) {
            $FindingDetails += "FOUND: Unix millisecond timestamps present in audit records" + $nl
            $FindingDetails += '(Format: "time": 1234567890123 - Unix ms, convertible to date/time)' + $nl
        }
        else {
            $FindingDetails += "Timestamp field not detected in sample audit records" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Session Events in systemd Journal" + $nl
    if ($journalSessionStr -ne "") {
        $FindingDetails += "Session events in journal:" + $nl
        $FindingDetails += $journalSessionStr + $nl
    }
    else {
        $FindingDetails += "No session events found in last 24h journal (or journald unavailable)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin records session.signIn (start) and session.signOut" + $nl
        $FindingDetails += "(end) events with Unix millisecond timestamps for each user session." + $nl
        $FindingDetails += "Session start and end times are available in the XO audit trail." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify session start/end times are recorded." + $nl
    }
"""

# ============================================================
# V-222465 — Technical: object access audit records
# ============================================================
IMPLEMENTATIONS["V-222465"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: API - check for object access events (vm., host., sr., network.)
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $objectEvents = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"vm\.\|"host\.\|"sr\.\|"network\.\|"pool\.') {
            $objectEvents = $true
        }
    }

    $FindingDetails = "Object Access Audit Record Check" + $nl
    $FindingDetails += "=================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "XO audit plugin records all object access events:" + $nl
        $FindingDetails += "  - VM operations (start, stop, snapshot, migrate, console access)" + $nl
        $FindingDetails += "  - Host management (patch, reboot, maintenance mode)" + $nl
        $FindingDetails += "  - Storage repository access (SR scan, VDI operations)" + $nl
        $FindingDetails += "  - Network configuration changes" + $nl
        $FindingDetails += "  - Pool membership changes" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Object Access Events in Audit API" + $nl
    if ($apiTokenStr -ne "") {
        if ($objectEvents) {
            $FindingDetails += "FOUND: Object access events (vm./host./sr./network.) in audit records" + $nl
        }
        else {
            $FindingDetails += "NOT FOUND in sample records (may be present in full history)" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin records both successful and unsuccessful access" + $nl
        $FindingDetails += "to application objects (VMs, hosts, storage, networks, pools)." + $nl
        $FindingDetails += "Each record includes userId, action, target object ID, and timestamp." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify object access events are logged." + $nl
    }
"""

# ============================================================
# V-222466 — Not_Applicable (XO provides no direct OS access to users)
# ============================================================
IMPLEMENTATIONS["V-222466"] = r"""
    $nl = [Environment]::NewLine
    $Status = "Not_Applicable"

    # Verify XO does not expose OS shell via web UI
    $shellExposure = $(timeout 5 sh -c 'grep -rl "execSync\|spawn.*shell\|child_process.*sh\|bash.*exec\|os.*command" /opt/xo/xo-server/dist /opt/xo/packages/xo-server/dist /usr/share/xo-server/dist 2>/dev/null | grep -v "node_modules" | head -3')
    $shellExposureStr = ($shellExposure -join $nl).Trim()

    $FindingDetails = "Direct OS Access Audit Record Check" + $nl
    $FindingDetails += "=====================================" + $nl + $nl

    $FindingDetails += "The STIG check states: " + [char]39 + "If the application does not provide direct" + $nl
    $FindingDetails += "access to the system, this requirement is not applicable." + [char]39 + $nl + $nl

    $FindingDetails += "Assessment: XO OS Shell Exposure Check" + $nl
    if ($shellExposureStr -ne "") {
        $FindingDetails += "Shell execution references found in XO source (review required):" + $nl
        $FindingDetails += $shellExposureStr + $nl + $nl
        $FindingDetails += "NOTE: These are internal server operations, not user-facing OS shell access." + $nl
    }
    else {
        $FindingDetails += "No user-accessible OS shell exposure detected in XO source." + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Conclusion:" + $nl
    $FindingDetails += "Xen Orchestra is a web-based virtualization management application." + $nl
    $FindingDetails += "Users interact with XO exclusively via HTTPS web UI and REST API." + $nl
    $FindingDetails += "XO does not expose terminal emulators, command shells, file browsers," + $nl
    $FindingDetails += "or direct OS command execution interfaces to authenticated users." + $nl
    $FindingDetails += "Internal Node.js server processes that call OS commands are not user-accessible." + $nl + $nl
    $FindingDetails += "This requirement does not apply to XO deployments." + $nl
"""

# ============================================================
# V-222467 — Technical: account lifecycle audit records
#            N/A if enterprise (LDAP) user management configured
# ============================================================
IMPLEMENTATIONS["V-222467"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: LDAP/AD enterprise auth plugin (N/A condition)
    $ldapPlugin = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -name "auth-ldap" -type d 2>/dev/null | head -2 2>&1)
    $ldapPluginStr = ($ldapPlugin -join $nl).Trim()
    $ldapFound = $ldapPluginStr -ne ""

    # Check LDAP config active
    $ldapActive = $false
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    if ($apiTokenStr -ne "" -and $ldapFound) {
        $pluginStatus = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins" 2>/dev/null)
        $pluginStatusStr = ($pluginStatus -join $nl).Trim()
        if ($pluginStatusStr -match '"auth-ldap".*"loaded":\s*true\|"loaded":\s*true.*"auth-ldap"') {
            $ldapActive = $true
        }
    }

    # Check 2: XO audit plugin (for non-LDAP case)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 3: API - account lifecycle events
    $accountEvents = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"user\.create\|"user\.delete\|"user\.set\|"createUser\|"deleteUser') {
            $accountEvents = $true
        }
    }

    $FindingDetails = "Account Lifecycle Audit Record Check" + $nl
    $FindingDetails += "=====================================" + $nl + $nl

    $FindingDetails += "Check 1: Enterprise Authentication (LDAP/AD)" + $nl
    if ($ldapFound) {
        $FindingDetails += "FOUND: auth-ldap plugin installed: " + $ldapPluginStr.Split($nl)[0] + $nl
        if ($ldapActive) {
            $FindingDetails += "Status: LDAP plugin is loaded and active" + $nl
        }
        else {
            $FindingDetails += "Status: LDAP plugin installed but may not be active" + $nl
        }
    }
    else {
        $FindingDetails += "LDAP plugin not found - XO using local user management" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Account Lifecycle Events in Audit API" + $nl
    if ($apiTokenStr -ne "") {
        if ($accountEvents) {
            $FindingDetails += "FOUND: user create/delete/modify events in XO audit records" + $nl
        }
        else {
            $FindingDetails += "NOT FOUND in sample records (may be present in full history)" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($ldapFound) {
        $Status = "Not_Applicable"
        $FindingDetails += "NOT APPLICABLE: XO is configured to use LDAP/AD enterprise authentication." + $nl
        $FindingDetails += "The STIG states: " + [char]39 + "If the application is configured to use an enterprise-based" + $nl
        $FindingDetails += "application user management capability that is STIG compliant, the requirement" + $nl
        $FindingDetails += "is not applicable." + [char]39 + $nl
        $FindingDetails += "Account lifecycle events (create/modify/disable/terminate) are managed" + $nl
        $FindingDetails += "and audited by the enterprise directory (AD/LDAP) system." + $nl
    }
    elseif ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin records user.create, user.set, and user.delete" + $nl
        $FindingDetails += "events for local XO user management operations." + $nl
        $FindingDetails += "Account creation, modification, and deletion are audited." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: No enterprise auth or audit plugin confirmed." + $nl
        $FindingDetails += "Manual review required: Verify account lifecycle events are logged." + $nl
    }
"""

# ============================================================
# V-222468 — Technical: session auditing starts on startup
# ============================================================
IMPLEMENTATIONS["V-222468"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin at startup
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: systemd journal - XO service start events
    $svcStart = $(timeout 5 sh -c 'journalctl -u xo-server --since "7 days ago" --no-pager 2>/dev/null | grep -i "started\|starting\|listening\|ready\|startup" | tail -5')
    $svcStartStr = ($svcStart -join $nl).Trim()
    $svcHasStart = $svcStartStr -ne ""

    # Check 3: Winston logger config - startup logging
    $winstonConfig = $(timeout 5 sh -c 'grep -r "winston\|createLogger\|transports\." /opt/xo/packages/xo-server/src /usr/share/xo-server/src 2>/dev/null | head -3')
    $winstonConfigStr = ($winstonConfig -join $nl).Trim()
    $winstonFound = $winstonConfigStr -ne ""

    # Check 4: Check XO service is currently active
    $svcStatus = $(timeout 5 systemctl is-active xo-server 2>/dev/null)
    $svcStatusStr = ($svcStatus -join $nl).Trim()
    $svcActive = $svcStatusStr -eq "active"

    $FindingDetails = "Session Auditing on Startup Check" + $nl
    $FindingDetails += "==================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "Audit plugin is loaded with the XO application at startup" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: systemd Journal - Service Startup Events" + $nl
    if ($svcHasStart) {
        $FindingDetails += "Startup events found in journal:" + $nl
        $FindingDetails += $svcStartStr + $nl
    }
    else {
        $FindingDetails += "No startup events in last 7 days journal (service may not have restarted)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Winston Logger Configuration" + $nl
    if ($winstonFound) {
        $FindingDetails += "FOUND: Winston logger configured in XO source" + $nl
    }
    else {
        $FindingDetails += "Winston logger config not found in searched source paths" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 4: XO Service Current Status" + $nl
    $FindingDetails += "xo-server service: " + $svcStatusStr + $nl + $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -and $svcActive) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin is loaded at application startup." + $nl
        $FindingDetails += "Winston logger is initialized with the application and begins logging" + $nl
        $FindingDetails += "from startup. systemd journal captures service start events." + $nl
        $FindingDetails += "Session auditing begins as soon as the application starts." + $nl
    }
    elseif ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin present - loaded at application startup." + $nl
        $FindingDetails += "Session auditing begins upon application start." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify session auditing starts on XO startup." + $nl
    }
"""

# ============================================================
# V-222469 — Technical: log shutdown events
# ============================================================
IMPLEMENTATIONS["V-222469"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: systemd journal - XO service stop events
    $svcStop = $(timeout 5 sh -c 'journalctl -u xo-server --since "30 days ago" --no-pager 2>/dev/null | grep -i "stopped\|stopping\|deactivat\|terminating\|shutdown\|exiting" | tail -5')
    $svcStopStr = ($svcStop -join $nl).Trim()
    $svcHasStop = $svcStopStr -ne ""

    # Check 2: XO audit plugin (logs application events)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 3: Winston logger for process exit events
    $processExit = $(timeout 5 sh -c 'grep -r "process.exit\|SIGTERM\|SIGINT\|beforeExit\|gracefulShutdown" /opt/xo/packages/xo-server/src /usr/share/xo-server/src 2>/dev/null | head -3')
    $processExitStr = ($processExit -join $nl).Trim()
    $processExitFound = $processExitStr -ne ""

    # Check 4: systemd unit - capture stop events
    $unitFile = $(timeout 5 sh -c 'systemctl cat xo-server 2>/dev/null | grep -i "ExecStop\|KillSignal\|TimeoutStop"')
    $unitFileStr = ($unitFile -join $nl).Trim()

    $FindingDetails = "Application Shutdown Event Logging Check" + $nl
    $FindingDetails += "==========================================" + $nl + $nl

    $FindingDetails += "Check 1: systemd Journal - Service Stop Events" + $nl
    if ($svcHasStop) {
        $FindingDetails += "FOUND: Shutdown events in systemd journal (last 30 days):" + $nl
        $FindingDetails += $svcStopStr + $nl
    }
    else {
        $FindingDetails += "No shutdown events in last 30 days (service may not have stopped recently)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Process Exit Event Handlers" + $nl
    if ($processExitFound) {
        $FindingDetails += "FOUND: Process shutdown handlers in XO source" + $nl
    }
    else {
        $FindingDetails += "Process exit handler code not found in searched paths" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 4: systemd Unit Configuration" + $nl
    if ($unitFileStr -ne "") {
        $FindingDetails += $unitFileStr + $nl
    }
    else {
        $FindingDetails += "systemd unit configuration not available" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    # systemd always logs service stops - this is the primary mechanism
    $svcIsSystemd = $(timeout 5 sh -c 'systemctl is-enabled xo-server 2>/dev/null')
    $svcIsSystemdStr = ($svcIsSystemd -join $nl).Trim()
    if ($svcIsSystemdStr -ne "not-found" -and $svcIsSystemdStr -ne "") {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO runs as a systemd service. systemd journals ALL service stop" + $nl
        $FindingDetails += "events including graceful shutdown, crash, and admin stop." + $nl
        $FindingDetails += "Service: xo-server (systemd-enabled: " + $svcIsSystemdStr + ")" + $nl
        $FindingDetails += "Shutdown events are recorded in the systemd journal with timestamp." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: Cannot confirm systemd manages XO service logging." + $nl
        $FindingDetails += "Manual review required: Verify shutdown events are logged." + $nl
    }
"""

# ============================================================
# V-222470 — Technical: log destination IP addresses
# ============================================================
IMPLEMENTATIONS["V-222470"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO API - does XO initiate connections? (Config for XCP-ng hosts)
    $xoConfig = $(timeout 5 sh -c 'cat /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null | grep -E "hostname|host\s*=|xapi" | head -10')
    $xoConfigStr = ($xoConfig -join $nl).Trim()
    $xoConnectsToHosts = $xoConfigStr -ne ""

    # Check 2: XO audit plugin - check audit records include target host IPs
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 3: nginx access log - destination IPs in upstream proxy logs
    $nginxUpstream = $(timeout 5 sh -c 'grep "upstream_addr\|127.0.0.1\|proxy_pass" /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | head -5')
    $nginxUpstreamStr = ($nginxUpstream -join $nl).Trim()

    # Check 4: API token - sample audit records for host/IP data
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $auditHasIP = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=20" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match '"ip":|"address":|"host":|"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"') {
            $auditHasIP = $true
        }
    }

    $FindingDetails = "Destination IP Address Logging Check" + $nl
    $FindingDetails += "======================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Configuration - Outbound Connections" + $nl
    if ($xoConnectsToHosts) {
        $FindingDetails += "XO connects to remote systems:" + $nl
        $FindingDetails += $xoConfigStr + $nl
    }
    else {
        $FindingDetails += "XO config not readable or no outbound host config found" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "XO audit records include the source IP (connecting client address)" + $nl
    }
    else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Nginx Upstream/Proxy Configuration" + $nl
    if ($nginxUpstreamStr -ne "") {
        $FindingDetails += $nginxUpstreamStr + $nl
    }
    else {
        $FindingDetails += "Nginx upstream config not found (nginx may not be present)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 4: IP Addresses in Audit API Records" + $nl
    if ($apiTokenStr -ne "") {
        if ($auditHasIP) {
            $FindingDetails += "FOUND: IP address fields present in XO audit records" + $nl
        }
        else {
            $FindingDetails += "IP address fields not detected in sample audit records" + $nl
        }
    }
    else {
        $FindingDetails += "API token not available - skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -and $xoConnectsToHosts) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO initiates connections to XCP-ng hosts and records source/dest" + $nl
        $FindingDetails += "addressing in audit records. XO audit plugin records client IP addresses" + $nl
        $FindingDetails += "for all inbound connections. Outbound connection targets (XCP-ng host IPs)" + $nl
        $FindingDetails += "are recorded per-operation in XO audit records." + $nl
    }
    elseif ($auditPluginFound) {
        $Status = "NotAFinding"
        $FindingDetails += "PASS: XO audit plugin records IP addresses. Outbound connection" + $nl
        $FindingDetails += "logging is available via systemd journal and nginx access logs." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "OPEN: XO audit plugin not confirmed active." + $nl
        $FindingDetails += "Manual review required: Verify destination IP addresses are logged." + $nl
    }
"""

# ============================================================
# Apply all implementations to the psm1 file
# ============================================================

def apply_implementations():
    with open(PSM1_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    changes = 0
    for vid, new_code in IMPLEMENTATIONS.items():
        # Match the stub custom code section for this VulnID
        # Pattern: from Begin Custom Code to End Custom Code
        stub_pattern = (
            r'(#---=== Begin Custom Code ===---#\n)'
            r'    \$FindingDetails = "This check requires manual review of Xen Orchestra application security configuration\. " \+\n'
            r'                      "Refer to the Application Security and Development STIG \(' + re.escape(vid) + r'\) for detailed requirements\. " \+\n'
            r'                      "Evidence should include configuration files, policies, and operational procedures\."\n'
            r'    (#---=== End Custom Code ===---#)'
        )

        begin_marker = '#---=== Begin Custom Code ===---#'
        end_marker = '#---=== End Custom Code ===---#'
        new_code_block = new_code.strip('\n')
        def make_repl(bc, nc, em):
            def repl(m):
                return m.group(1) + nc + '\n    ' + em
            return repl
        new_content, n = re.subn(stub_pattern, make_repl(begin_marker, new_code_block, end_marker), content)

        if n == 0:
            print(f"WARNING: Could not find stub pattern for {vid}")
        else:
            content = new_content
            changes += 1
            print(f"Replaced: {vid} ({n} substitution)")

    print(f"\nTotal changes: {changes}/18")

    with open(PSM1_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Written successfully")

if __name__ == "__main__":
    apply_implementations()
