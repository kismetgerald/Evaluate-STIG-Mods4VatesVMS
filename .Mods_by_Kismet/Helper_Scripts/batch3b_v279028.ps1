function Get-V279028 {
    <#
    .SYNOPSIS
        V-279028 - Uniquely identify source of information transfer

    .DESCRIPTION
        SRG-APP-000397-WSR-000076
        Severity: CAT II (Medium)

        The web server must uniquely identify the source of an information
        transfer for traceability and accountability.
    #>

    param(
        [Parameter(Mandatory=$true)]
        [String]$ScanType,
        [Parameter(Mandatory=$false)]
        [String]$AnswerFile,
        [Parameter(Mandatory=$false)]
        [String]$AnswerKey,
        [Parameter(Mandatory=$false)]
        [String]$Username,
        [Parameter(Mandatory=$false)]
        [String]$UserSID,
        [Parameter(Mandatory=$false)]
        [String]$Hostname,
        [Parameter(Mandatory=$false)]
        [String]$Instance,
        [Parameter(Mandatory=$false)]
        [String]$Database,
        [Parameter(Mandatory=$false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-279028"
    $RuleID = "SV-279028r1021166_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $output = @()
    $output += "=" * 80
    $output += "V-279028: Uniquely Identify Information Transfer Source"
    $output += "=" * 80
    $output += ""
    $output += "Requirement: Logs must uniquely identify source of information transfers"
    $output += "(source IP, username, session ID for traceability)"
    $output += ""

    # Check 1: Source IP logging
    $output += "Check 1: Source IP Address Logging"
    $output += "-" * 50
    $ipLoggingDetected = $false

    # Check Express.js access logs
    $expressLogs = bash -c "find /var/log/xo-server -name '*.log' 2>/dev/null | head -3" 2>&1
    if ($LASTEXITCODE -eq 0 -and $expressLogs) {
        $output += "[FOUND] XO server logs:"
        $output += $expressLogs
        # Check for IP addresses in recent logs
        $recentLog = ($expressLogs -split "`n")[0]
        if ($recentLog -and (Test-Path $recentLog)) {
            $ipSample = bash -c "grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' '$recentLog' 2>/dev/null | head -3" 2>&1
            if ($LASTEXITCODE -eq 0 -and $ipSample) {
                $output += "IP addresses detected in logs:"
                $output += $ipSample
                $ipLoggingDetected = $true
            }
        }
    }
    $output += ""

    # Check 2: User identity logging
    $output += "Check 2: User Identity Logging"
    $output += "-" * 50
    $userLoggingDetected = $false
    if ($expressLogs) {
        $recentLog = ($expressLogs -split "`n")[0]
        if ($recentLog -and (Test-Path $recentLog)) {
            $userSample = bash -c "grep -i 'user\|username\|email' '$recentLog' 2>/dev/null | head -3" 2>&1
            if ($LASTEXITCODE -eq 0 -and $userSample) {
                $output += "[FOUND] User identity in logs:"
                $output += $userSample
                $userLoggingDetected = $true
            } else {
                $output += "[INFO] No obvious user identity fields in recent logs"
            }
        }
    }
    $output += ""

    # Check 3: Session tracking
    $output += "Check 3: Session ID Tracking"
    $output += "-" * 50
    $sessionTrackingDetected = $false
    # Check for session IDs in logs
    if ($expressLogs) {
        $recentLog = ($expressLogs -split "`n")[0]
        if ($recentLog -and (Test-Path $recentLog)) {
            $sessionSample = bash -c "grep -i 'session\|sessionid\|sid' '$recentLog' 2>/dev/null | head -3" 2>&1
            if ($LASTEXITCODE -eq 0 -and $sessionSample) {
                $output += "[FOUND] Session tracking in logs:"
                $output += $sessionSample
                $sessionTrackingDetected = $true
            } else {
                $output += "[INFO] No obvious session IDs in recent logs"
            }
        }
    }
    $output += ""

    # Check 4: XO audit plugin (comprehensive event tracking)
    $output += "Check 4: XO Audit Plugin (Enhanced Event Tracking)"
    $output += "-" * 50
    $auditPlugin = bash -c "find /opt/xo/packages -name '*audit*' 2>/dev/null" 2>&1
    if ($LASTEXITCODE -eq 0 -and $auditPlugin) {
        $output += "[FOUND] XO audit plugin installed:"
        $output += $auditPlugin
        $output += "Audit plugin provides comprehensive source tracking (IP, user, action, resource)"
    } else {
        $output += "[INFO] XO audit plugin not detected (optional component)"
    }
    $output += ""

    # Check 5: Nginx reverse proxy logs (if present)
    $output += "Check 5: Reverse Proxy Logging (Optional)"
    $output += "-" * 50
    $nginxLogs = bash -c "ls -l /var/log/nginx/access.log 2>/dev/null" 2>&1
    if ($LASTEXITCODE -eq 0 -and $nginxLogs) {
        $output += "[FOUND] Nginx access logs (includes source IP):"
        $output += $nginxLogs
    } else {
        $output += "[INFO] No Nginx reverse proxy logs (direct XO access)"
    }
    $output += ""

    # Check 6: Systemd journal logging
    $output += "Check 6: Systemd Journal (System-Level Logging)"
    $output += "-" * 50
    $journalXO = bash -c "journalctl -u xo-server --since '5 minutes ago' --no-pager 2>/dev/null | head -5" 2>&1
    if ($LASTEXITCODE -eq 0 -and $journalXO) {
        $output += "[FOUND] Systemd journal captures XO events:"
        $output += $journalXO -split "`n" | Select-Object -First 3
    } else {
        $output += "[INFO] Limited systemd journal output for XO"
    }
    $output += ""

    # Assessment
    $output += "=" * 80
    $output += "MANUAL VERIFICATION REQUIRED"
    $output += "=" * 80
    $output += ""
    $Status = "Open"
    $output += "Status: Open - Requires ISSO/ISSM verification of source identification"
    $output += ""
    $output += "Automated checks detected:"
    if ($ipLoggingDetected) { $output += "  [YES] Source IP address logging" }
    else { $output += "  [UNKNOWN] Source IP address logging - manual verification required" }
    if ($userLoggingDetected) { $output += "  [YES] User identity logging" }
    else { $output += "  [UNKNOWN] User identity logging - manual verification required" }
    if ($sessionTrackingDetected) { $output += "  [YES] Session ID tracking" }
    else { $output += "  [UNKNOWN] Session ID tracking - manual verification required" }
    $output += ""
    $output += "Manual verification steps:"
    $output += "1. Review XO log files for source IP, username, session ID in each entry"
    $output += "2. Test information transfer (file upload/download, API call)"
    $output += "3. Verify log entry includes: timestamp, source IP, username, action, resource"
    $output += "4. Confirm logs enable tracing specific transaction to specific user/IP"
    $output += "5. Validate log retention allows historical source identification"
    $output += ""

    $FindingDetails = ($output | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $SiteName
            ResultHash   = ""
            ResultData   = $FindingDetails
            ESPath       = ""
            LogPath      = ""
            LogComponent = ""
            OSPlatform   = ""
        }
        If ($FindingDetails.Trim().Length -gt 0) {
            $GetCorpParams.ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
        }
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFKey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
    }
    return Send-CheckResult @SendCheckParams
}
