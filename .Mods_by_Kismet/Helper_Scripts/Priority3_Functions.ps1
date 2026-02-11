# ============================================================================
# Priority 3: Process/Service Checks - V-206376
# ============================================================================

Function Get-V206376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206376
        STIG ID    : SRG-APP-000141-WSR-000082
        Rule ID    : SV-206376r508029_rule
        Rule Title : The web server must restrict inbound connections from nonsecure zones.
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206376"
    $RuleID = "SV-206376r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    # Check 1: Verify firewall restrictions for inbound connections
    $output = "Check 1: Firewall Configuration for Inbound Connections$nl"

    try {
        # Check if UFW is active (XO Appliance default)
        $ufwStatus = & ufw status 2>/dev/null
        if ($LASTEXITCODE -eq 0 -and $ufwStatus -match "Status: active") {
            $output += "   UFW Firewall: ACTIVE$nl"
            $output += "   UFW Status Output:$nl$ufwStatus$nl"

            # Check for restrictive default policies
            if ($ufwStatus -match "Default: deny \(incoming\)") {
                $output += "   Default Policy: DENY INCOMING (compliant)$nl"
            }
            else {
                $output += "   [WARN] Default Policy: ALLOW INCOMING (review required)$nl"
            }

            # Check for specific XO port allowances
            if ($ufwStatus -match "80/tcp|443/tcp") {
                $output += "   XO Web Ports: ALLOWED (80/tcp, 443/tcp)$nl"
            }
            else {
                $output += "   [INFO] XO Web Ports: Not explicitly allowed (may be covered by default policy)$nl"
            }
        }
        else {
            $output += "   UFW Firewall: NOT ACTIVE$nl"

            # Check iptables as fallback
            $iptablesRules = & iptables -L -n 2>/dev/null
            if ($LASTEXITCODE -eq 0) {
                $output += "   iptables Rules Detected:$nl$iptablesRules$nl"

                # Check for INPUT chain default policy
                if ($iptablesRules -match "Chain INPUT.*policy DROP" -or $iptablesRules -match "Chain INPUT.*policy REJECT") {
                    $output += "   iptables INPUT Policy: DROP/REJECT (restrictive)$nl"
                }
                else {
                    $output += "   [WARN] iptables INPUT Policy: ACCEPT (review required)$nl"
                }
            }
            else {
                $output += "   [WARN] No active firewall detected (UFW or iptables)$nl"
                $output += "   This is expected for XOCE (Community Edition) deployments$nl"
            }
        }
    }
    catch {
        $output += "   [ERROR] Failed to check firewall status: $($_.Exception.Message)$nl"
    }

    # Check 2: Verify XO server binding configuration
    $output += "$nl" + "Check 2: XO Server Network Binding$nl"

    try {
        # Check XO configuration for bind address
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $config = Get-Content $xoConfigPath -Raw
            if ($config -match "bind.*=.*127\.0\.0\.1|bind.*=.*localhost") {
                $output += "   XO Server Bind: LOCALHOST ONLY (secure)$nl"
            }
            elseif ($config -match "bind.*=.*0\.0\.0\.0") {
                $output += "   [WARN] XO Server Bind: ALL INTERFACES (review required)$nl"
            }
            else {
                $output += "   XO Server Bind: Not explicitly configured (check defaults)$nl"
            }
        }
        else {
            $output += "   XO Config File: Not found at $xoConfigPath$nl"
        }

        # Check nginx reverse proxy configuration
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $nginxContent = Get-Content $nginxConfig -Raw
            if ($nginxContent -match "listen.*127\.0\.0\.1|listen.*localhost") {
                $output += "   Nginx Listen: LOCALHOST ONLY (secure)$nl"
            }
            elseif ($nginxContent -match "listen.*80|listen.*443") {
                $output += "   Nginx Listen: EXTERNAL PORTS (expected for web server)$nl"
            }
            else {
                $output += "   Nginx Configuration: Non-standard binding$nl"
            }
        }
        else {
            $output += "   Nginx Config: Not found$nl"
        }
    }
    catch {
        $output += "   [ERROR] Failed to check XO binding: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Xen Orchestra web server should restrict inbound connections to authorized networks only.$nl"
    $output += "   Default XO configurations typically include firewall protection and localhost binding.$nl"
    $output += "   Manual review required to verify network restrictions meet organizational requirements.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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

# ============================================================================
# Priority 3: Process/Service Checks - V-206377
# ============================================================================

Function Get-V206377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206377
        STIG ID    : SRG-APP-000142-WSR-000014
        Rule ID    : SV-206377r508029_rule
        Rule Title : The web server must be configured to listen on a specific IP address and port.
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206377"
    $RuleID = "SV-206377r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Web Server Listening Configuration$nl"

    try {
        # Check nginx configuration for specific IP/port bindings
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration Found: $nginxConfig$nl"

            # Extract listen directives
            $listenMatches = [regex]::Matches($config, 'listen\s+([^;]+);')
            if ($listenMatches.Count -gt 0) {
                $output += "   Listen Directives Found:$nl"
                foreach ($match in $listenMatches) {
                    $listenDirective = $match.Groups[1].Value.Trim()
                    $output += "     - listen $listenDirective$nl"

                    # Check for specific IP binding (not 0.0.0.0 or *)
                    if ($listenDirective -match '^127\.0\.0\.1|^localhost|^::1|^\[::1\]') {
                        $output += "       [SECURE] Bound to localhost/loopback$nl"
                    }
                    elseif ($listenDirective -match '^0\.0\.0\.0|^:|^\*') {
                        $output += "       [WARN] Bound to all interfaces$nl"
                    }
                    elseif ($listenDirective -match '^\d+\.\d+\.\d+\.\d+') {
                        $output += "       [INFO] Bound to specific IP address$nl"
                    }
                    else {
                        $output += "       [INFO] Non-standard binding$nl"
                    }
                }
            }
            else {
                $output += "   [WARN] No listen directives found in nginx config$nl"
            }
        }
        else {
            $output += "   [WARN] Nginx configuration not found at expected location$nl"
        }

        # Check XO server configuration
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "$nl" + "XO Server Configuration:$nl"

            # Check for bind configuration in XO config
            if ($xoConfig -match 'bind\s*=\s*"([^"]+)"' -or $xoConfig -match "bind\s*=\s*'([^']+)'") {
                $bindAddress = $matches[1]
                $output += "   Bind Address: $bindAddress$nl"

                if ($bindAddress -eq "127.0.0.1" -or $bindAddress -eq "localhost") {
                    $output += "   [SECURE] XO server bound to localhost$nl"
                }
                elseif ($bindAddress -eq "0.0.0.0") {
                    $output += "   [WARN] XO server bound to all interfaces$nl"
                }
                else {
                    $output += "   [INFO] XO server bound to specific address$nl"
                }
            }
            else {
                $output += "   Bind Address: Not explicitly configured (check defaults)$nl"
            }

            if ($xoConfig -match 'port\s*=\s*(\d+)') {
                $port = $matches[1]
                $output += "   Port: $port$nl"
            }
            else {
                $output += "   Port: Not configured (default: 80)$nl"
            }
        }
        else {
            $output += "$nl" + "XO Server Config: Not found at $xoConfigPath$nl"
        }

        # Check actual listening ports
        $output += "$nl" + "Check 2: Active Network Listeners$nl"
        $netstat = & netstat -tlnp 2>/dev/null | Select-String -Pattern ":80 |:443 "
        if ($netstat) {
            $output += "   Active Web Ports:$nl$netstat$nl"
        }
        else {
            $output += "   No web ports (80/443) actively listening$nl"
        }

        # Check ss as alternative
        $ss = & ss -tlnp 2>/dev/null | Select-String -Pattern ":80 |:443 "
        if ($ss) {
            $output += "   SS Command Results:$nl$ss$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check listening configuration: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should be configured to listen on specific IP addresses and ports.$nl"
    $output += "   Default XO configurations typically bind to specific addresses for security.$nl"
    $output += "   Verify that only authorized IP addresses and ports are configured.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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