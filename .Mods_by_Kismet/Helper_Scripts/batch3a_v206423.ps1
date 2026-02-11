Function Get-V206423 {
    # Suppress false positive PSScriptAnalyzer warnings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '', Justification='cat, grep, test are used as bash commands, not PowerShell aliases')]

    <#
    .DESCRIPTION
        Vuln ID    : V-206423
        STIG ID    : SRG-APP-000358-WSR-000163
        Rule ID    : SV-206423r508029_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000358-WSR-000163
        Rule Title : The web server must generate information to be used by external applications or entities to monitor and control remote access.
        DiscussMD5 : E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6
        CheckMD5   : F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7
        FixMD5     : A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8
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
    $VulnID = "V-206423"
    $RuleID = "SV-206423r508029_rule"
    $Status = "Open"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $output = @()

    $output += "Vulnerability ID: ${VulnID}${nl}"
    $output += "Rule ID: ${RuleID}${nl}"
    $output += "CAT II / Medium - Security Infrastructure Integration${nl}"
    $output += "---[Organizational Policy Check]---${nl}${nl}"

    $output += "Requirement: Web server must generate information for external applications${nl}"
    $output += "             (SIEM, monitoring systems) to monitor and control remote access.${nl}${nl}"

    # Check 1: Remote syslog configuration (rsyslog/syslog-ng)
    $output += "Check 1: Remote Syslog Configuration${nl}"

    $remoteLoggingDetected = $false
    $remoteLoggingDetails = @()

    try {
        # Check rsyslog configuration
        $rsyslogConfPath = "/etc/rsyslog.conf"
        $rsyslogDPath = "/etc/rsyslog.d/"

        if (Test-Path $rsyslogConfPath) {
            $rsyslogConf = $(cat "$rsyslogConfPath" 2>&1 | grep -E '^[^#]*@@|^[^#]*@[^@]' 2>&1)
            if ($LASTEXITCODE -eq 0 -and $rsyslogConf) {
                $remoteLoggingDetected = $true
                $remoteLoggingDetails += "rsyslog.conf"
                $output += "  [FOUND] Remote logging in ${rsyslogConfPath}:${nl}"
                $output += "          ${rsyslogConf}${nl}"
            }
        }

        if (Test-Path $rsyslogDPath) {
            $rsyslogDConfs = $(grep -r '^[^#]*@@\|^[^#]*@[^@]' "$rsyslogDPath" 2>&1)
            if ($LASTEXITCODE -eq 0 -and $rsyslogDConfs) {
                $remoteLoggingDetected = $true
                $remoteLoggingDetails += "rsyslog.d/*.conf"
                $output += "  [FOUND] Remote logging in ${rsyslogDPath}:${nl}"
                $output += "          ${rsyslogDConfs}${nl}"
            }
        }

        # Check syslog-ng configuration
        $syslogNgConfPath = "/etc/syslog-ng/syslog-ng.conf"
        if (Test-Path $syslogNgConfPath) {
            $syslogNgConf = $(cat "$syslogNgConfPath" 2>&1 | grep -E 'destination.*tcp|destination.*udp' 2>&1)
            if ($LASTEXITCODE -eq 0 -and $syslogNgConf) {
                $remoteLoggingDetected = $true
                $remoteLoggingDetails += "syslog-ng.conf"
                $output += "  [FOUND] Remote logging in ${syslogNgConfPath}:${nl}"
                $output += "          ${syslogNgConf}${nl}"
            }
        }

        if (-not $remoteLoggingDetected) {
            $output += "  [INFO] No remote syslog configuration detected${nl}"
            $output += "         Logs may be local-only (not forwarded to SIEM)${nl}"
        }
    }
    catch {
        $output += "  [INFO] Error checking syslog configuration: $($_.Exception.Message)${nl}"
    }
    $output += ${nl}

    # Check 2: SIEM Integration Evidence
    $output += "Check 2: SIEM Platform Integration${nl}"

    $siemDetected = $false
    $siemDetails = @()

    try {
        # Common SIEM platforms: Splunk, ArcSight, QRadar, Elastic
        $searchPaths = @(
            "/opt/splunkforwarder",
            "/opt/splunk",
            "/opt/arcsight",
            "/opt/ibm/qradar",
            "/etc/filebeat",
            "/etc/logstash",
            "/etc/elastic-agent"
        )

        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                $siemDetected = $true
                $siemDetails += $path
                $output += "  [FOUND] SIEM component at: ${path}${nl}"
            }
        }

        # Check for SIEM configuration files
        $filebeat = $(test -f /etc/filebeat/filebeat.yml && echo "exists" 2>&1)
        if ($filebeat -eq "exists") {
            $siemDetected = $true
            $siemDetails += "Filebeat"
            $output += "  [FOUND] Filebeat configuration (Elastic Stack)${nl}"
        }

        $logstash = $(test -f /etc/logstash/logstash.yml && echo "exists" 2>&1)
        if ($logstash -eq "exists") {
            $siemDetected = $true
            $siemDetails += "Logstash"
            $output += "  [FOUND] Logstash configuration (Elastic Stack)${nl}"
        }

        if (-not $siemDetected) {
            $output += "  [INFO] No standard SIEM platform detected${nl}"
            $output += "         Organization may use custom monitoring solution${nl}"
        }
    }
    catch {
        $output += "  [INFO] Error checking SIEM components: $($_.Exception.Message)${nl}"
    }
    $output += ${nl}

    # Check 3: XO Audit Plugin Forwarding Capability
    $output += "Check 3: XO Audit Plugin Forwarding${nl}"

    try {
        # Check for XO audit plugin
        $auditPlugin = $(test -d /opt/xo/packages/xo-server-audit && echo "exists" 2>&1)
        if ($auditPlugin -eq "exists") {
            $output += "  [FOUND] XO audit plugin installed${nl}"
            $output += "          Capable of forwarding audit events to external systems${nl}"
            $output += "          Verify plugin configured to forward to authorized SIEM${nl}"
        } else {
            $output += "  [INFO] XO audit plugin not detected (optional component)${nl}"
        }
    }
    catch {
        $output += "  [INFO] Error checking XO audit plugin: $($_.Exception.Message)${nl}"
    }
    $output += ${nl}

    # Check 4: Systemd journal-upload service
    $output += "Check 4: Systemd Journal Remote Upload${nl}"

    try {
        $journalUploadStatus = $(systemctl is-enabled systemd-journal-upload 2>&1)
        if ($LASTEXITCODE -eq 0 -and $journalUploadStatus -eq "enabled") {
            $output += "  [FOUND] systemd-journal-upload service enabled${nl}"

            # Check journal-upload.conf for remote server
            $journalUploadConf = $(test -f /etc/systemd/journal-upload.conf && cat /etc/systemd/journal-upload.conf 2>&1 | grep -E '^[^#]*URL=' 2>&1)
            if ($LASTEXITCODE -eq 0 -and $journalUploadConf) {
                $output += "  [FOUND] Remote journal server configured:${nl}"
                $output += "          ${journalUploadConf}${nl}"
            } else {
                $output += "  [WARN] systemd-journal-upload enabled but no remote URL configured${nl}"
            }
        } else {
            $output += "  [INFO] systemd-journal-upload not enabled${nl}"
            $output += "         Systemd journal logs remain local only${nl}"
        }
    }
    catch {
        $output += "  [INFO] Error checking systemd-journal-upload: $($_.Exception.Message)${nl}"
    }
    $output += ${nl}

    # Check 5: Organizational Security Policy Documentation
    $output += "Check 5: Organizational SIEM Integration Documentation${nl}"

    $docSearchPaths = @(
        "/etc/xo-server/security",
        "/etc/xo-server/docs",
        "/opt/xo/docs",
        "/var/lib/xo-server/docs",
        "/usr/local/share/doc/xo-server"
    )

    $docsFound = $false

    try {
        foreach ($docPath in $docSearchPaths) {
            if (Test-Path $docPath) {
                $docsFound = $true
                $output += "  [FOUND] Documentation directory: ${docPath}${nl}"
            }
        }

        if (-not $docsFound) {
            $output += "  [INFO] No standard documentation directories detected${nl}"
            $output += "         Organization should document SIEM integration procedures${nl}"
        }
    }
    catch {
        $output += "  [INFO] Error checking documentation paths: $($_.Exception.Message)${nl}"
    }
    $output += ${nl}

    # Assessment
    $output += "Assessment:${nl}"
    $output += "  Finding: Open${nl}"
    $output += "  Reason: Cannot automatically verify integration with authorized SIEM platform${nl}"
    $output += ${nl}

    $output += "Detection Summary:${nl}"
    if ($remoteLoggingDetected) {
        $output += "  - Remote syslog configured: YES (${remoteLoggingDetails})${nl}"
    } else {
        $output += "  - Remote syslog configured: NO${nl}"
    }
    if ($siemDetected) {
        $output += "  - SIEM platform detected: YES (${siemDetails})${nl}"
    } else {
        $output += "  - SIEM platform detected: NO${nl}"
    }
    $output += ${nl}

    $output += "Required Manual Verification:${nl}"
    $output += "  1. Confirm XO integrated with authorized DoD SIEM platform${nl}"
    $output += "     Acceptable: Splunk, ArcSight, QRadar, Elastic Stack, or DoD-approved alternative${nl}"
    $output += "  2. Verify remote access events forwarded to SIEM in real-time${nl}"
    $output += "     Events include: login/logout, authentication failures, session creation/termination${nl}"
    $output += "  3. Confirm SIEM configured for remote access monitoring and alerting${nl}"
    $output += "     Alerts for: suspicious login patterns, brute force attempts, privilege escalation${nl}"
    $output += "  4. Verify SIEM data retention meets organizational requirements${nl}"
    $output += "     DoD minimum: 1 year for audit logs${nl}"
    $output += "  5. Test SIEM integration by generating test events${nl}"
    $output += "     Verify events visible in SIEM console within acceptable timeframe${nl}"
    $output += "  6. Document SIEM integration architecture${nl}"
    $output += "     Include: log sources, forwarding mechanisms, SIEM platform, retention policy${nl}"
    $output += ${nl}

    $output += "Note: This requirement ensures XO logs are available to external monitoring${nl}"
    $output += "systems for centralized security event correlation and remote access control.${nl}"
    $output += "Local logging alone is insufficient; integration with organizational SIEM${nl}"
    $output += "infrastructure is mandatory for DoD compliance.${nl}"

    $FindingDetails = $output -join ""
    #---=== End Custom Code ===---#

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
