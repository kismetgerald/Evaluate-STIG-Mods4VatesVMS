# Standalone Test for V-206393
# Run from: Evaluate-STIG directory
# Command: .\.Mods_by_Kismet\Test\test-V206393.ps1

$ErrorActionPreference = 'Stop'

# Import Master_Functions (provides helper functions like Get-TextHash)
Remove-Module Master_Functions -Force -ErrorAction SilentlyContinue
Import-Module .\Modules\Master_Functions\Master_Functions.psm1 -Force

Write-Host "Testing V-206393 standalone..." -ForegroundColor Cyan

# Define the function with full implementation
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

    $ModuleName = "Test-V206393"
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

$testParams = @{
    ScanType = 'Classified'
    AnswerFile = ''
    AnswerKey  = 'V-206393'
    Username   = 'NA'
    UserSID    = 'NA'
    Hostname   = 'localhost'
    Instance   = 'NA'
    Database   = 'NA'
    SiteName   = 'NA'
}

$startTime = Get-Date
$result = Get-V206393 @testParams
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host ("`n" + "="*80) -ForegroundColor Yellow
Write-Host "EXECUTION TIME: $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
Write-Host ("="*80 + "`n") -ForegroundColor Yellow

Write-Host "STATUS: $($result.Status)" -ForegroundColor Yellow
Write-Host ("`n" + "FINDING DETAILS:") -ForegroundColor Cyan
Write-Host $result.FindingDetails

if ($result.Status -eq 'NotAFinding') {
    Write-Host ("`n" + "✅ Test PASSED - Status is NotAFinding") -ForegroundColor Green
} else {
    Write-Host ("`n" + "⚠️  Status is $($result.Status) - May need review") -ForegroundColor Yellow
}
