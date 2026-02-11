# ============================================================================
# Priority 3: Process/Service Checks - V-206393 to V-206395
# ============================================================================

Function Get-V206393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206393
        STIG ID    : SRG-APP-000141-WSR-000015
        Rule ID    : SV-206393r508029_rule
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
    $VulnID = "V-206393"
    $RuleID = "SV-206393r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Inbound Connection Restrictions$nl"

    try {
        # Check UFW firewall status and rules
        $output += "Firewall Status:$nl"
        try {
            $ufwStatus = & ufw status 2>/dev/null
            if ($LASTEXITCODE -eq 0) {
                $output += "   UFW Status: ACTIVE$nl"
                $output += "   UFW Rules:$nl$ufwStatus$nl"

                # Check for restrictive policies
                if ($ufwStatus -match 'Status:\s+active') {
                    $output += "   [GOOD] Firewall is active$nl"
                }

                # Check for default deny policies
                if ($ufwStatus -match 'Default:\s+deny\s+\(incoming\)') {
                    $output += "   [GOOD] Default deny incoming policy$nl"
                    $defaultDenyIncoming = $true
                }
                else {
                    $output += "   [WARN] Default policy allows incoming connections$nl"
                    $defaultDenyIncoming = $false
                }

                # Check for web server ports
                $webPortsOpen = $false
                if ($ufwStatus -match '80\s+ALLOW|443\s+ALLOW|:80\s+ALLOW|:443\s+ALLOW') {
                    $output += "   [INFO] Web ports (80/443) are open$nl"
                    $webPortsOpen = $true
                }

                # Check for unrestricted access
                if ($ufwStatus -match 'ALLOW\s+Anywhere|ALLOW\s+0\.0\.0\.0/0') {
                    $output += "   [WARN] Some rules allow unrestricted access$nl"
                }

            }
            else {
                $output += "   UFW Status: INACTIVE or NOT INSTALLED$nl"
            }
        }
        catch {
            $output += "   UFW Status: ERROR checking status$nl"
        }

        # Check iptables rules if UFW is not active
        if ($output -notmatch 'UFW Status: ACTIVE') {
            $output += "$nl" + "Checking iptables:$nl"
            try {
                $iptablesRules = & iptables -L -n 2>/dev/null
                if ($LASTEXITCODE -eq 0) {
                    $output += "   iptables Rules: FOUND$nl"

                    # Check INPUT chain policy
                    if ($iptablesRules -match 'Chain INPUT \(policy (\w+)\)') {
                        $inputPolicy = $matches[1]
                        $output += "   INPUT Chain Policy: $inputPolicy$nl"
                        if ($inputPolicy -eq 'DROP' -or $inputPolicy -eq 'REJECT') {
                            $output += "   [GOOD] Default INPUT policy is restrictive$nl"
                        }
                        else {
                            $output += "   [WARN] Default INPUT policy allows connections$nl"
                        }
                    }

                    # Check for web server rules
                    if ($iptablesRules -match 'dpt:80|dpt:443') {
                        $output += "   [INFO] Web server ports configured in iptables$nl"
                    }
                }
                else {
                    $output += "   iptables: NOT CONFIGURED$nl"
                }
            }
            catch {
                $output += "   iptables: ERROR checking rules$nl"
            }
        }

        # Check nginx configuration for access restrictions
        $output += "$nl" + "Check 2: Web Server Access Controls$nl"

        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Check for allow/deny directives
            $allowMatches = [regex]::Matches($config, 'allow\s+([^;]+);')
            $denyMatches = [regex]::Matches($config, 'deny\s+([^;]+);')

            if ($allowMatches.Count -gt 0 -or $denyMatches.Count -gt 0) {
                $output += "   Access control directives found:$nl"

                foreach ($match in $allowMatches) {
                    $allowRule = $match.Groups[1].Value.Trim()
                    $output += "     ALLOW: $allowRule$nl"
                }

                foreach ($match in $denyMatches) {
                    $denyRule = $match.Groups[1].Value.Trim()
                    $output += "     DENY: $denyRule$nl"
                }

                # Check for overly permissive rules
                if ($config -match 'allow\s+all;') {
                    $output += "   [WARN] 'allow all' rule found - may bypass restrictions$nl"
                }

                if ($config -match 'deny\s+all;') {
                    $output += "   [INFO] 'deny all' rule found$nl"
                }
            }
            else {
                $output += "   No access control directives found$nl"
            }

            # Check for IP restrictions
            if ($config -match 'geo\s+\$') {
                $output += "   [INFO] Geo-based access control configured$nl"
            }
        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check for network interface binding
        $output += "$nl" + "Check 3: Network Interface Binding$nl"

        try {
            $netstatOutput = & netstat -tlnp 2>/dev/null | Select-String 'nginx|xo-server'
            if ($netstatOutput) {
                $output += "   Listening services:$nl$netstatOutput$nl"

                # Check if services are bound to specific interfaces
                $boundToAll = $false
                $boundToLocal = $false

                foreach ($line in $netstatOutput) {
                    if ($line -match '0\.0\.0\.0:') {
                        $output += "   [WARN] Service bound to all interfaces (0.0.0.0)$nl"
                        $boundToAll = $true
                    }
                    elseif ($line -match '127\.0\.0\.1:') {
                        $output += "   [INFO] Service bound to localhost$nl"
                        $boundToLocal = $true
                    }
                }

                if (-not $boundToAll -and -not $boundToLocal) {
                    $output += "   [INFO] Services appear to be bound to specific interfaces$nl"
                }
            }
            else {
                $output += "   No nginx/xo-server services found listening$nl"
            }
        }
        catch {
            $output += "   [ERROR] Failed to check network bindings$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check inbound connection restrictions: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should restrict inbound connections from nonsecure zones.$nl"
    $output += "   This includes proper firewall configuration, access control lists,$nl"
    $output += "   and network interface binding to prevent unauthorized access.$nl"
    $output += "   Manual review required to verify connection restrictions meet$nl"
    $output += "   organizational security requirements.$nl"

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

Function Get-V206394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206394
        STIG ID    : SRG-APP-000142-WSR-000035
        Rule ID    : SV-206394r508029_rule
        Rule Title : The web server must be tuned to handle the operational requirements of the hosted application.
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
    $VulnID = "V-206394"
    $RuleID = "SV-206394r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Web Server Performance Tuning$nl"

    try {
        # Check nginx configuration for performance settings
        $nginxConfig = "/etc/nginx/nginx.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Main Configuration: FOUND$nl"

            # Check worker processes
            if ($config -match 'worker_processes\s+(\w+);') {
                $workerProcesses = $matches[1]
                $output += "   Worker Processes: $workerProcesses$nl"
                if ($workerProcesses -eq 'auto') {
                    $output += "   [GOOD] Worker processes set to auto$nl"
                }
                elseif ([int]::TryParse($workerProcesses, [ref]$null)) {
                    $output += "   [INFO] Worker processes set to: $workerProcesses$nl"
                }
            }
            else {
                $output += "   Worker Processes: NOT SPECIFIED$nl"
            }

            # Check worker connections
            if ($config -match 'worker_connections\s+(\d+);') {
                $workerConnections = $matches[1]
                $output += "   Worker Connections: $workerConnections$nl"
                if ([int]$workerConnections -ge 1024) {
                    $output += "   [GOOD] Adequate worker connections$nl"
                }
                else {
                    $output += "   [WARN] Low worker connections may limit performance$nl"
                }
            }
            else {
                $output += "   Worker Connections: NOT SPECIFIED$nl"
            }

            # Check client settings
            $clientSettings = @('client_max_body_size', 'client_body_timeout', 'client_header_timeout')
            foreach ($setting in $clientSettings) {
                if ($config -match "$setting\s+([^;]+);") {
                    $value = $matches[1]
                    $output += "   $setting : $value$nl"
                }
            }

            # Check buffer settings
            $bufferSettings = @('client_body_buffer_size', 'client_header_buffer_size', 'large_client_header_buffers')
            foreach ($setting in $bufferSettings) {
                if ($config -match "$setting\s+([^;]+);") {
                    $value = $matches[1]
                    $output += "   $setting : $value$nl"
                }
            }

            # Check timeout settings
            $timeoutSettings = @('keepalive_timeout', 'send_timeout', 'proxy_connect_timeout', 'proxy_send_timeout', 'proxy_read_timeout')
            foreach ($setting in $timeoutSettings) {
                if ($config -match "$setting\s+([^;]+);") {
                    $value = $matches[1]
                    $output += "   $setting : $value$nl"
                }
            }

        }
        else {
            $output += "   Nginx Main Configuration: NOT FOUND$nl"
        }

        # Check XO server configuration
        $output += "$nl" + "Check 2: XO Server Configuration$nl"

        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "   XO Configuration: FOUND$nl"

            # Check for performance-related settings
            $perfSettings = @('timeout', 'concurrency', 'pool_size', 'max_connections')
            $perfConfigured = $false
            foreach ($setting in $perfSettings) {
                if ($xoConfig -match "$setting\s*=") {
                    $output += "   Performance setting found: $setting$nl"
                    $perfConfigured = $true
                }
            }

            if (-not $perfConfigured) {
                $output += "   No explicit performance tuning settings found$nl"
            }
        }
        else {
            $output += "   XO Configuration: NOT FOUND$nl"
        }

        # Check system resource limits
        $output += "$nl" + "Check 3: System Resource Limits$nl"

        $limitsFile = "/etc/security/limits.conf"
        if (Test-Path $limitsFile) {
            $limits = Get-Content $limitsFile | Where-Object { $_ -notmatch '^#' -and $_ -notmatch '^\s*$' }
            $output += "   System Limits Configuration: FOUND$nl"

            # Check for nginx or web server limits
            $webLimits = $limits | Where-Object { $_ -match 'nginx|www-data|http' }
            if ($webLimits) {
                $output += "   Web server limits found:$nl"
                foreach ($limit in $webLimits) {
                    $output += "     $limit$nl"
                }
            }
            else {
                $output += "   No specific web server limits configured$nl"
            }
        }
        else {
            $output += "   System Limits Configuration: NOT FOUND$nl"
        }

        # Check systemd service limits
        $serviceFile = "/etc/systemd/system/xo-server.service"
        if (Test-Path $serviceFile) {
            $serviceConfig = Get-Content $serviceFile -Raw
            $output += "$nl" + "Service Limits:$nl"

            if ($serviceConfig -match 'LimitNOFILE|LimitNPROC|MemoryLimit') {
                $output += "   Resource limits configured in service$nl"
            }
            else {
                $output += "   No resource limits configured in service$nl"
            }
        }

        # Check current system performance
        $output += "$nl" + "Check 4: Current System Performance$nl"

        try {
            # Check available memory
            $memInfo = Get-Content /proc/meminfo 2>/dev/null | Where-Object { $_ -match 'MemTotal|MemAvailable' }
            if ($memInfo) {
                $output += "   Memory Information:$nl$memInfo$nl"
            }

            # Check CPU information
            $cpuInfo = Get-Content /proc/cpuinfo 2>/dev/null | Where-Object { $_ -match 'processor|cpu cores' } | Select-Object -First 4
            if ($cpuInfo) {
                $output += "   CPU Information:$nl$cpuInfo$nl"
            }

            # Check load average
            $loadAvg = Get-Content /proc/loadavg 2>/dev/null
            if ($loadAvg) {
                $output += "   System Load Average: $loadAvg$nl"
            }
        }
        catch {
            $output += "   [ERROR] Could not retrieve system performance information$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check performance tuning: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should be tuned to handle the operational requirements$nl"
    $output += "   of the hosted application. This includes proper worker processes,$nl"
    $output += "   connection limits, buffer sizes, timeouts, and system resource$nl"
    $output += "   allocation to ensure optimal performance and stability.$nl"
    $output += "   Manual review required to verify tuning meets application$nl"
    $output += "   performance requirements and security constraints.$nl"

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

Function Get-V206395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206395
        STIG ID    : SRG-APP-000143-WSR-000175
        Rule ID    : SV-206395r508029_rule
        Rule Title : The web server must protect the confidentiality of controlled information during transmission through the use of an approved TLS version.
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
    $VulnID = "V-206395"
    $RuleID = "SV-206395r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: TLS Version Configuration$nl"

    try {
        # Check nginx SSL/TLS configuration
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Check for ssl_protocols directive
            if ($config -match 'ssl_protocols\s+([^;]+);') {
                $protocols = $matches[1].Trim()
                $output += "   SSL Protocols configured: $protocols$nl"

                # Check for insecure protocols
                $insecureProtocols = @('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1')
                $secureProtocols = @('TLSv1.2', 'TLSv1.3')
                $hasInsecure = $false
                $hasSecure = $false

                foreach ($protocol in $insecureProtocols) {
                    if ($protocols -match $protocol) {
                        $output += "   [WARN] Insecure protocol enabled: $protocol$nl"
                        $hasInsecure = $true
                    }
                }

                foreach ($protocol in $secureProtocols) {
                    if ($protocols -match $protocol) {
                        $output += "   [GOOD] Secure protocol enabled: $protocol$nl"
                        $hasSecure = $true
                    }
                }

                if (-not $hasSecure) {
                    $output += "   [CRITICAL] No secure TLS protocols configured$nl"
                }

                if ($hasInsecure) {
                    $output += "   [WARN] Insecure protocols should be disabled$nl"
                }

            }
            else {
                $output += "   SSL Protocols: NOT SPECIFIED (using defaults)$nl"
                $output += "   [WARN] Default protocols may include insecure versions$nl"
            }

            # Check for ssl_ciphers directive
            if ($config -match 'ssl_ciphers\s+([^;]+);') {
                $ciphers = $matches[1].Trim()
                $output += "   SSL Ciphers configured: $ciphers$nl"

                # Check for weak ciphers
                $weakCiphers = @('RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL')
                $hasWeakCiphers = $false

                foreach ($cipher in $weakCiphers) {
                    if ($ciphers -match $cipher) {
                        $output += "   [WARN] Weak cipher found: $cipher$nl"
                        $hasWeakCiphers = $true
                    }
                }

                if (-not $hasWeakCiphers) {
                    $output += "   [GOOD] No obvious weak ciphers detected$nl"
                }
            }
            else {
                $output += "   SSL Ciphers: NOT SPECIFIED$nl"
            }

            # Check for ssl_prefer_server_ciphers
            if ($config -match 'ssl_prefer_server_ciphers\s+(on|off);') {
                $preferServer = $matches[1]
                $output += "   Prefer server ciphers: $preferServer$nl"
                if ($preferServer -eq 'on') {
                    $output += "   [GOOD] Server cipher preference enabled$nl"
                }
                else {
                    $output += "   [NOTE] Client cipher preference allowed$nl"
                }
            }
            else {
                $output += "   Prefer server ciphers: NOT SPECIFIED$nl"
            }

            # Check for HSTS header
            if ($config -match 'Strict-Transport-Security') {
                $output += "   [GOOD] HSTS header configured$nl"
            }
            else {
                $output += "   HSTS header: NOT CONFIGURED$nl"
            }

        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check Node.js/OpenSSL TLS configuration
        $output += "$nl" + "Check 2: Node.js TLS Configuration$nl"

        # Check NODE_TLS_REJECT_UNAUTHORIZED
        $nodeRejectUnauthorized = $env:NODE_TLS_REJECT_UNAUTHORIZED
        if ($nodeRejectUnauthorized -eq "0") {
            $output += "   [WARN] NODE_TLS_REJECT_UNAUTHORIZED = 0 (may allow insecure connections)$nl"
        }
        elseif ($nodeRejectUnauthorized -eq "1" -or -not $nodeRejectUnauthorized) {
            $output += "   NODE_TLS_REJECT_UNAUTHORIZED: SECURE (default)$nl"
        }

        # Check XO server configuration for TLS settings
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "$nl" + "XO Server TLS Configuration:$nl"

            # Look for TLS-related settings
            $tlsSettings = @('tls', 'ssl', 'secureProtocol', 'ciphers', 'rejectUnauthorized')
            $tlsConfigured = $false
            foreach ($setting in $tlsSettings) {
                if ($xoConfig -match "$setting\s*=") {
                    $output += "   TLS setting found: $setting$nl"
                    $tlsConfigured = $true
                }
            }

            if (-not $tlsConfigured) {
                $output += "   No explicit TLS configuration found in XO config$nl"
            }
        }
        else {
            $output += "   XO Config: NOT FOUND$nl"
        }

        # Check OpenSSL version and configuration
        $output += "$nl" + "Check 3: OpenSSL Version and Configuration$nl"

        try {
            $opensslVersion = & openssl version 2>/dev/null
            if ($LASTEXITCODE -eq 0) {
                $output += "   OpenSSL Version: $opensslVersion$nl"

                # Check if version supports TLS 1.2+
                if ($opensslVersion -match 'OpenSSL\s+([0-9]+)\.([0-9]+)') {
                    $major = [int]$matches[1]
                    $minor = [int]$matches[2]

                    if ($major -gt 1 -or ($major -eq 1 -and $minor -ge 0)) {
                        $output += "   [GOOD] OpenSSL version supports TLS 1.2+$nl"
                    }
                    else {
                        $output += "   [WARN] OpenSSL version may not support modern TLS$nl"
                    }
                }
            }
            else {
                $output += "   OpenSSL: NOT AVAILABLE$nl"
            }
        }
        catch {
            $output += "   [ERROR] Could not check OpenSSL version$nl"
        }

        # Check system crypto policies (RHEL/CentOS)
        $cryptoPolicyFile = "/etc/crypto-policies/config"
        if (Test-Path $cryptoPolicyFile) {
            $cryptoPolicy = Get-Content $cryptoPolicyFile -Raw
            $output += "$nl" + "System Crypto Policy: $cryptoPolicy$nl"

            if ($cryptoPolicy -match 'LEGACY|FIPS') {
                $output += "   [NOTE] Custom crypto policy configured$nl"
            }
            else {
                $output += "   [INFO] Default crypto policy$nl"
            }
        }

    }
    catch {
        $output += "   [ERROR] Failed to check TLS configuration: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server must protect the confidentiality of controlled information$nl"
    $output += "   during transmission through the use of an approved TLS version.$nl"
    $output += "   TLS 1.2 or higher should be used with secure cipher suites.$nl"
    $output += "   Insecure protocols (SSLv3, TLS 1.0, TLS 1.1) should be disabled.$nl"
    $output += "   Manual review required to verify TLS configuration meets$nl"
    $output += "   organizational security requirements and compliance standards.$nl"

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