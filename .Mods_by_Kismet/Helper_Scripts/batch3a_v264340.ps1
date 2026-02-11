Function Get-V264340 {
    <#
    .DESCRIPTION
        Vuln ID    : V-264340
        STIG ID    : SRG-APP-000001-WSR-000001
        Rule ID    : SV-264340r508029_rule
        Rule Title : The web server must be configured to immediately alert security personnel of unauthorized changes to the audit log.
        DiscussMD5 : [To be populated by DISA]
        CheckMD5   : [To be populated by DISA]
        FixMD5     : [To be populated by DISA]
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$Hostname,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-264340"
    $RuleID = "SV-264340r508029_rule"
    $Status = "Open"  # Always Open - FIM + alerting implementation requires ISSO verification
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    # V-264340: Alert on Unauthorized Audit Log Changes
    # Organizational policy check - requires file integrity monitoring + alerting + ISSO verification
    # Always returns Open status

    $nl = [Environment]::NewLine
    $output = @()

    $output += "Vulnerability ID: ${VulnID}${nl}"
    $output += "Rule ID: ${RuleID}${nl}"
    $output += "CAT II / Medium - Unauthorized Audit Log Change Alerting${nl}"
    $output += "---[Organizational Policy Check]---${nl}${nl}"

    $output += "Requirement: Web server must immediately alert security personnel of unauthorized audit log changes.${nl}${nl}"

    # Check 1: Log file immutability/protection
    $output += "Check 1: Log File Immutability Protection${nl}"

    $logDirs = @("/var/log/xo-server", "/var/log/nginx", "/var/log/journal")
    $immutableFound = $false
    $appendOnlyFound = $false

    foreach ($logDir in $logDirs) {
        if ($(bash -c "test -d '$logDir' && echo 'exists' 2>&1") -eq "exists") {
            $output += "  Log Directory: $logDir${nl}"

            # Check for immutable/append-only attributes
            $attrs = $(bash -c "lsattr -d '$logDir' 2>&1 | head -1")

            if ($attrs -match "i") {
                $output += "    [FOUND] Immutable attribute set (prevents any modifications)${nl}"
                $immutableFound = $true
            }
            elseif ($attrs -match "a") {
                $output += "    [FOUND] Append-only attribute set (prevents deletion/modification)${nl}"
                $appendOnlyFound = $true
            }
            else {
                $output += "    [INFO] No immutable/append-only attributes detected${nl}"
            }

            # Check file permissions
            $dirPerms = $(bash -c "stat -c '%a %U:%G' '$logDir' 2>&1")
            $output += "    Permissions: $dirPerms${nl}"
        }
    }
    $output += ${nl}

    # Check 2: File Integrity Monitoring (FIM) tools
    $output += "Check 2: File Integrity Monitoring (FIM) Configuration${nl}"

    $fimFound = $false

    # Check for AIDE
    if ($(bash -c "test -f /etc/aide/aide.conf && echo 'exists' 2>&1") -eq "exists") {
        $output += "  [FOUND] AIDE configuration: /etc/aide/aide.conf${nl}"

        # Check if log directories are monitored
        $aideRules = $(bash -c "grep -E '^/var/log' /etc/aide/aide.conf 2>&1")
        if ($aideRules) {
            $output += "    Log monitoring rules:${nl}"
            $aideRules -split "`n" | ForEach-Object {
                if ($_.Trim()) { $output += "      $_${nl}" }
            }
            $fimFound = $true
        }
        else {
            $output += "    [WARN] No log directory monitoring rules found${nl}"
        }
    }

    # Check for Tripwire
    if ($(bash -c "test -d /etc/tripwire && echo 'exists' 2>&1") -eq "exists") {
        $output += "  [FOUND] Tripwire configuration: /etc/tripwire${nl}"

        $twConfig = $(bash -c "ls /etc/tripwire/*.pol 2>&1 | head -1")
        if ($twConfig) {
            $output += "    Policy file: $twConfig${nl}"
            $fimFound = $true
        }
    }

    # Check for OSSEC
    if ($(bash -c "test -f /etc/ossec-init.conf && echo 'exists' 2>&1") -eq "exists") {
        $output += "  [FOUND] OSSEC configuration${nl}"

        $ossecSyscheck = $(bash -c "grep -A5 '<syscheck>' /var/ossec/etc/ossec.conf 2>&1 | grep -E '<directories|<frequency'")
        if ($ossecSyscheck) {
            $output += "    Syscheck monitoring configured${nl}"
            $fimFound = $true
        }
    }

    if (-not $fimFound) {
        $output += "  [NOT FOUND] No FIM tools detected (AIDE/Tripwire/OSSEC)${nl}"
    }
    $output += ${nl}

    # Check 3: Auditd rules for log directories
    $output += "Check 3: Auditd Rules for Log Directory Monitoring${nl}"

    $auditdRulesFound = $false

    if ($(bash -c "test -d /etc/audit/rules.d && echo 'exists' 2>&1") -eq "exists") {
        $output += "  [FOUND] Auditd rules directory: /etc/audit/rules.d${nl}"

        # Check for watch rules on /var/log
        $logWatchRules = $(bash -c "grep -r -- '-w /var/log' /etc/audit/rules.d/ 2>&1")

        if ($logWatchRules) {
            $output += "    Log directory watch rules:${nl}"
            $logWatchRules -split "`n" | ForEach-Object {
                if ($_.Trim() -and $_ -notmatch "Binary file") {
                    $output += "      $_${nl}"
                }
            }
            $auditdRulesFound = $true
        }
        else {
            $output += "    [WARN] No log directory watch rules found${nl}"
        }
    }
    else {
        $output += "  [NOT FOUND] Auditd rules directory not present${nl}"
    }
    $output += ${nl}

    # Check 4: Alert configuration for unauthorized log modifications
    $output += "Check 4: Alert Configuration for Log Tampering${nl}"

    $alertingConfigured = $false

    # Check for FIM alert configuration
    if ($fimFound) {
        # Check AIDE email notifications
        if ($(bash -c "test -f /etc/aide/aide.conf && echo 'exists' 2>&1") -eq "exists") {
            $aideEmail = $(bash -c "grep -i 'mail\|email' /etc/aide/aide.conf 2>&1")
            if ($aideEmail) {
                $output += "  [FOUND] AIDE email configuration${nl}"
                $alertingConfigured = $true
            }
        }

        # Check OSSEC alerting
        if ($(bash -c "test -f /var/ossec/etc/ossec.conf && echo 'exists' 2>&1") -eq "exists") {
            $ossecAlerts = $(bash -c "grep -A5 '<email_notification>' /var/ossec/etc/ossec.conf 2>&1")
            if ($ossecAlerts) {
                $output += "  [FOUND] OSSEC email alerting configured${nl}"
                $alertingConfigured = $true
            }
        }
    }

    # Check for monitoring integration (SIEM, centralized logging)
    $syslogRemote = $(bash -c "grep -E '@@|@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>&1 | grep -v 'No such file'")
    if ($syslogRemote) {
        $output += "  [FOUND] Remote syslog configuration (centralized logging)${nl}"
        $syslogRemote -split "`n" | ForEach-Object {
            if ($_.Trim() -and $_ -notmatch "Binary file") {
                $output += "    $_${nl}"
            }
        }
    }

    if (-not $alertingConfigured) {
        $output += "  [MANUAL] Cannot automatically verify alerting configuration${nl}"
    }
    $output += ${nl}

    # Check 5: ISSO/SA notification mechanism
    $output += "Check 5: ISSO/SA Notification Mechanism${nl}"
    $output += "  [MANUAL] ISSO/SA notification requires organizational verification${nl}${nl}"

    $output += "  Required notification mechanisms:${nl}"
    $output += "  - Email alerts to security personnel${nl}"
    $output += "  - SIEM platform integration (Splunk, QRadar, ArcSight, etc.)${nl}"
    $output += "  - Centralized monitoring console alerts${nl}"
    $output += "  - Incident response ticketing system integration${nl}"
    $output += "  - 24/7 SOC notification for critical events${nl}${nl}"

    # Summary
    $output += "---[Manual Verification Required]---${nl}${nl}"

    $output += "STATUS: Open (Organizational Policy)${nl}${nl}"

    $output += "RATIONALE:${nl}"
    $output += "File integrity monitoring and real-time alerting for unauthorized audit log changes${nl}"
    $output += "requires organizational implementation and ISSO verification. While automated checks${nl}"
    $output += "can detect file protection mechanisms and FIM tool configurations, only manual review${nl}"
    $output += "can verify:${nl}${nl}"

    $output += "1. FIM tools are configured to monitor ALL audit log locations${nl}"
    $output += "2. Alert thresholds are properly calibrated to detect unauthorized changes${nl}"
    $output += "3. Alerting mechanisms reach designated security personnel (ISSO/SA)${nl}"
    $output += "4. Response procedures are documented and tested${nl}"
    $output += "5. Integration with organizational SIEM/monitoring infrastructure${nl}${nl}"

    $output += "DISCOVERY SUMMARY:${nl}"
    if ($immutableFound -or $appendOnlyFound) {
        $output += "- Log file protection: Configured (immutable/append-only attributes)${nl}"
    }
    else {
        $output += "- Log file protection: Not detected (no immutable attributes)${nl}"
    }

    if ($fimFound) {
        $output += "- File integrity monitoring: Configured (FIM tools detected)${nl}"
    }
    else {
        $output += "- File integrity monitoring: Not detected (no FIM tools found)${nl}"
    }

    if ($auditdRulesFound) {
        $output += "- Auditd log monitoring: Configured (watch rules detected)${nl}"
    }
    else {
        $output += "- Auditd log monitoring: Not detected (no watch rules)${nl}"
    }

    if ($alertingConfigured) {
        $output += "- Alert configuration: Found (email/SIEM integration)${nl}"
    }
    else {
        $output += "- Alert configuration: Manual verification required${nl}"
    }
    $output += ${nl}

    $FindingDetails = $output -join ""

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    } else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
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
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
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
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $SiteName
        HeadHash         = $ResultHash
    }

    return Send-CheckResult @SendCheckParams
}
