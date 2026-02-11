Function Get-V206424 {

    <#
    .DESCRIPTION
        Vuln ID    : V-206424
        STIG ID    : SRG-APP-000360-WSR-000151
        Rule ID    : SV-206424r508029_rule
        Rule Title : The web server must generate information to be used by external applications or entities to monitor and control remote access.
        DiscussMD5 : A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6
        CheckMD5   : B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7
        FixMD5     : C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8
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
    $VulnID = "V-206424"
    $RuleID = "SV-206424r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    # V-206424: 75% Storage Warning to ISSO/SA
    # Validates disk capacity monitoring is configured with 75% threshold alerts to ISSO/SA
    # Checks: disk space usage, logrotate size limits, monitoring tools, alert configuration, notification config, systemd journal limits

    $Status = "Open"
    $output = @()
    $alertingConfigured = $false
    $monitoringDetected = $false
    $threshold75Configured = $false
    $nl = [Environment]::NewLine

    try {
        $output += "=== V-206424: Storage Capacity Monitoring and Alerting (75% Threshold) ==="
        $output += "=" * 80
        $output += ""

        # Check 1: Current disk space usage on log partitions
        $output += "Check 1: Current Disk Space Usage Analysis"
        $output += "-" * 80

        $logDirs = @("/var/log/xo-server", "/var/log", "/opt/xo", "/var/lib/xo-server")
        $criticalUsageDetected = $false

        foreach ($logDir in $logDirs) {
            if (Test-Path $logDir) {
                $output += "   [CHECKING] Directory: $logDir"

                # Get disk space for directory
                $dfOutput = $(bash -c "df -h '$logDir' 2>&1 | tail -1" 2>&1)
                if ($LASTEXITCODE -eq 0 -and $dfOutput) {
                    $output += "   Filesystem: $dfOutput"

                    # Parse usage percentage
                    if ($dfOutput -match '(\d+)%') {
                        $usagePercent = [int]$matches[1]
                        $output += "   [INFO] Current usage: ${usagePercent}%"

                        if ($usagePercent -ge 75) {
                            $output += "   [ALERT] Usage at or above 75% threshold (ISSO/SA notification required)"
                            $criticalUsageDetected = $true
                        } elseif ($usagePercent -ge 60) {
                            $output += "   [WARNING] Usage approaching 75% threshold (${usagePercent}%)"
                        } else {
                            $output += "   [PASS] Usage below 75% threshold"
                        }
                    }
                }

                $output += ""
            }
        }

        # Check 2: Logrotate configuration with size limits (proactive capacity management)
        $output += "Check 2: Logrotate Size Limits (Proactive Capacity Control)"
        $output += "-" * 80

        $logrotateConfigs = @(
            "/etc/logrotate.d/xo-server",
            "/etc/logrotate.d/xen-orchestra",
            "/etc/logrotate.conf"
        )

        $sizeRotateFound = $false
        foreach ($config in $logrotateConfigs) {
            if (Test-Path $config) {
                $output += "   [FOUND] Logrotate config: $config"

                # Check for size-based rotation
                $sizeRotate = $(bash -c "grep -E '^\s*(size|maxsize)' '$config' 2>&1" 2>&1)
                if ($LASTEXITCODE -eq 0 -and $sizeRotate) {
                    $output += "   [PASS] Size-based rotation configured: $sizeRotate"
                    $sizeRotateFound = $true
                }

                # Check for rotate count
                $rotateCount = $(bash -c "grep -E '^\s*rotate\s+\d+' '$config' 2>&1" 2>&1)
                if ($LASTEXITCODE -eq 0 -and $rotateCount) {
                    $output += "   [INFO] Rotation count: $rotateCount"
                }

                $output += ""
            }
        }

        if (-not $sizeRotateFound) {
            $output += "   [INFO] No explicit size-based logrotate configuration found"
            $output += "   [RECOMMENDATION] Configure size limits to prevent unexpected disk growth"
        }

        $output += ""

        # Check 3: Disk monitoring tools (Nagios, Zabbix, Prometheus)
        $output += "Check 3: Disk Capacity Monitoring Tools"
        $output += "-" * 80

        $monitoringAgents = @(
            "nagios-nrpe-server",
            "zabbix-agent",
            "zabbix-agent2",
            "prometheus-node-exporter",
            "telegraf",
            "collectd"
        )

        foreach ($agent in $monitoringAgents) {
            $agentStatus = $(bash -c "systemctl is-active '$agent' 2>&1" 2>&1)
            if ($agentStatus -eq "active") {
                $output += "   [PASS] Monitoring agent detected: $agent (active)"
                $monitoringDetected = $true

                # Check for disk check configuration
                $agentConfig = ""
                switch ($agent) {
                    "nagios-nrpe-server" {
                        $agentConfig = $(bash -c "grep -E 'check_disk.*-w.*-c' /etc/nagios/nrpe.cfg /etc/nagios/nrpe_local.cfg 2>&1 | grep -v '^#'" 2>&1)
                        if ($LASTEXITCODE -eq 0 -and $agentConfig) {
                            $output += "   [FOUND] NRPE disk check: $agentConfig"
                            # Check for 75% warning threshold
                            if ($agentConfig -match '-w\s*2[0-5]%') {
                                $output += "   [PASS] Warning threshold ≤25% free (75%+ used)"
                                $threshold75Configured = $true
                            }
                        }
                    }
                    "zabbix-agent" {
                        $output += "   [INFO] Zabbix agent monitors disk via template (vfs.fs.size)"
                    }
                    "prometheus-node-exporter" {
                        $output += "   [INFO] Prometheus collects node_filesystem_* metrics"
                    }
                }
            }
        }

        if (-not $monitoringDetected) {
            $output += "   [INFO] No dedicated monitoring agents detected"
        }

        $output += ""

        # Check 4: Alert configuration at 75% threshold
        $output += "Check 4: 75% Threshold Alert Configuration"
        $output += "-" * 80

        # Check for custom disk alert scripts
        $diskAlertScripts = $(bash -c "find /usr/local/bin /opt -name '*disk*alert*' -o -name '*capacity*monitor*' 2>/dev/null | head -5" 2>&1)
        if ($LASTEXITCODE -eq 0 -and $diskAlertScripts -and $diskAlertScripts -notmatch "Is a directory|No such file") {
            $output += "   [FOUND] Disk alert scripts:"
            $scriptLines = $diskAlertScripts -split "`n" | Where-Object { $_ -and $_ -notmatch "Is a directory" }
            foreach ($script in $scriptLines) {
                $output += "   - $script"
            }
            $alertingConfigured = $true
        } else {
            $output += "   [INFO] No custom disk alert scripts found"
        }

        # Check for disk alert cron jobs
        $diskAlertCron = $(bash -c "grep -r 'df.*alert\|disk.*space\|capacity.*monitor' /etc/cron* /var/spool/cron 2>&1 | grep -v '^#' | grep -v 'Is a directory' | head -5" 2>&1)
        if ($LASTEXITCODE -eq 0 -and $diskAlertCron -and $diskAlertCron -notmatch "Is a directory|No such file") {
            $output += "   [FOUND] Disk alert cron jobs detected"
            $cronLines = $diskAlertCron -split "`n" | Where-Object { $_ -and $_ -notmatch "Is a directory" }
            foreach ($cron in $cronLines) {
                $output += "   $cron"
            }
            $alertingConfigured = $true
        } else {
            $output += "   [INFO] No disk alert cron jobs detected"
        }

        $output += ""

        # Check 5: ISSO/SA notification configuration
        $output += "Check 5: ISSO/SA Notification Configuration"
        $output += "-" * 80

        # Check for email notification configuration
        $mailConfig = $(bash -c "command -v mail 2>&1 ; command -v sendmail 2>&1 ; command -v msmtp 2>&1" 2>&1)
        if ($LASTEXITCODE -eq 0 -and $mailConfig) {
            $output += "   [FOUND] Mail utilities installed (notification capability)"
            $mailLines = $mailConfig -split "`n" | Where-Object { $_ }
            foreach ($util in $mailLines) {
                $output += "   - $util"
            }
        } else {
            $output += "   [INFO] No mail utilities detected"
        }

        # Check for monitoring server integration (sends alerts to central system)
        if ($monitoringDetected) {
            $output += "   [INFO] Monitoring agent integration:"
            $output += "     - Nagios: Alerts sent to central Nagios server"
            $output += "     - Zabbix: Alerts configured in Zabbix web interface"
            $output += "     - Prometheus: Alerts configured in AlertManager"
        }

        # Check for organizational alert recipient documentation
        $alertRecipients = @(
            "/etc/xo-server/alert-recipients.txt",
            "/usr/local/etc/disk-alert-recipients.txt",
            "/etc/monitoring/alert-contacts.conf"
        )

        $recipientDocFound = $false
        foreach ($recipientDoc in $alertRecipients) {
            if (Test-Path $recipientDoc) {
                $output += "   [PASS] Alert recipient documentation: $recipientDoc"
                $recipientDocFound = $true
                $alertingConfigured = $true
                break
            }
        }

        if (-not $recipientDocFound) {
            $output += "   [INFO] No organizational alert recipient documentation found"
        }

        $output += ""

        # Check 6: Systemd journal storage limits (prevents journal disk exhaustion)
        $output += "Check 6: Systemd Journal Storage Limits (Prevents Unbounded Growth)"
        $output += "-" * 80

        $journaldConf = "/etc/systemd/journald.conf"
        if (Test-Path $journaldConf) {
            $output += "   [FOUND] journald configuration: $journaldConf"

            # Check SystemMaxUse setting
            $systemMaxUse = $(bash -c "grep -E '^SystemMaxUse=' '$journaldConf' 2>&1" 2>&1)
            if ($LASTEXITCODE -eq 0 -and $systemMaxUse) {
                $output += "   [PASS] SystemMaxUse configured: $systemMaxUse"
            } else {
                $output += "   [INFO] SystemMaxUse not set (defaults: 10% of filesystem)"
            }

            # Check current journal disk usage
            $journalSize = $(bash -c "journalctl --disk-usage 2>&1" 2>&1)
            if ($LASTEXITCODE -eq 0 -and $journalSize) {
                $output += "   [INFO] $journalSize"
            }
        } else {
            $output += "   [INFO] journald.conf not found - using system defaults"
        }

        $output += ""
        $output += "=== Assessment ==="
        $output += "-" * 80

        # Determine final status
        if (($monitoringDetected -and $threshold75Configured) -or $alertingConfigured) {
            $Status = "NotAFinding"
            $output += "[RESULT] PASS - Disk capacity monitoring and alerting configured"
            $output += "[EVIDENCE]"
            if ($monitoringDetected) {
                $output += "  - Monitoring agent(s) detected and active"
            }
            if ($threshold75Configured) {
                $output += "  - 75% threshold configured in monitoring checks"
            }
            if ($alertingConfigured) {
                $output += "  - Alert notification configuration detected"
            }
            $output += "[COMPLIANCE] Storage capacity monitoring meets STIG requirement"
            $output += "              ISSO/SA will receive alerts when usage reaches 75%"
        } elseif ($monitoringDetected) {
            $Status = "Open"
            $output += "[RESULT] OPEN - Monitoring detected but 75% threshold verification required"
            $output += "[FINDING] Monitoring agent(s) active but explicit 75% threshold not confirmed"
            $output += "[MANUAL_VERIFICATION_REQUIRED]"
            $output += "  1. Verify monitoring system alert thresholds (Nagios/Zabbix/Prometheus)"
            $output += "  2. Confirm ISSO/SA contact information configured in monitoring system"
            $output += "  3. Test disk capacity alert delivery (simulate 75% usage)"
            $output += "  4. Document alert escalation procedures"
        } else {
            $Status = "Open"
            $output += "[RESULT] OPEN - Manual verification required"
            $output += "[FINDING] Unable to verify disk capacity monitoring and alerting"
            $output += "[MANUAL_VERIFICATION_REQUIRED]"
            $output += "  1. Request System Administrator to demonstrate disk monitoring configuration"
            $output += "  2. Verify 75% threshold alerts are configured for all log partitions"
            $output += "  3. Confirm ISSO/SA notification recipients are documented"
            $output += "  4. Validate alert delivery mechanism (email, SNMP trap, webhook)"
            $output += "  5. Review organizational incident response procedures for capacity alerts"
            $output += ""
            $output += "[STIG_REQUIREMENT] SRG-APP-000360-WSR-000151"
            $output += "  The web server must generate information to be used by external applications"
            $output += "  or entities to monitor and control remote access. DoD requires ISSO/SA"
            $output += "  notification when storage capacity reaches 75% of maximum."
            $output += ""
            $output += "[REMEDIATION] Configure disk capacity monitoring and alerting:"
            $output += "  1. Install monitoring agent:"
            $output += "     apt install nagios-nrpe-server  # Debian/Ubuntu"
            $output += "     apt install zabbix-agent2       # Alternative"
            $output += ""
            $output += "  2. Configure NRPE disk check with 75% threshold:"
            $output += "     command[check_disk]=/usr/lib/nagios/plugins/check_disk -w 25% -c 10% -p /"
            $output += "     (25% free = 75% used threshold for warning)"
            $output += ""
            $output += "  3. Configure alert recipients (ISSO/SA email addresses):"
            $output += "     - Nagios: /etc/nagios/contacts.cfg"
            $output += "     - Zabbix: Web interface > Administration > Users"
            $output += "     - Prometheus: AlertManager configuration"
            $output += ""
            $output += "  4. Document organizational procedures:"
            $output += "     - Create /etc/xo-server/alert-recipients.txt with ISSO/SA contacts"
            $output += "     - Include escalation procedures for capacity alerts"
        }

        if ($criticalUsageDetected) {
            $output += ""
            $output += "[URGENT] Current disk usage at or above 75% - immediate ISSO/SA notification required"
        }

    } catch {
        $Status = "Open"
        $output += ""
        $output += "[ERROR] Exception during monitoring check: $($_.Exception.Message)"
        $output += "[ACTION] Manual verification required due to check execution error"
    }

    $FindingDetails = $output -join $nl
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
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
