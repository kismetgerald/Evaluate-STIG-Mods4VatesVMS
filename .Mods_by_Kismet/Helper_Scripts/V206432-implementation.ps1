Function Get-V206432 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206432
        STIG ID    : SRG-APP-000435-WSR-000147
        Rule ID    : SV-206432r961620_rule
        Rule Title : The web server must be protected from being stopped by a non-privileged user.
        DiscussMD5 : 6A679BBA96237C21364526F9019F74FD
        CheckMD5   : 708EEDDEED4CDB71825B7C9F69E5F6B6
        FixMD5     : BCCAFFE47DDE2E6D3E65378A6931CB80
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
    $VulnID = "V-206432"
    $RuleID = "SV-206432r961620_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $output = ""
    $nonPrivilegedAccess = $false
    $serviceProtected = $true

    $output += "====================================================================`n"
    $output += "V-206432: Server Stop Protection`n"
    $output += "Requirement: Only privileged users can stop the xo-server service`n"
    $output += "====================================================================`n`n"

    # Check 1: Systemd service file permissions
    $output += "Check 1: Systemd Service File Permissions`n"
    $output += "--------------------------------------------------------------------`n"
    $serviceFilePath = $(bash -c "systemctl show xo-server -p FragmentPath 2>&1 | cut -d= -f2" 2>&1)

    if ($LASTEXITCODE -eq 0 -and $serviceFilePath -and $serviceFilePath -notlike '*could not be found*') {
        $output += "   Service file: $serviceFilePath`n"

        # Get file permissions and ownership
        $filePerms = $(bash -c "stat -c '%a %U:%G' '$serviceFilePath' 2>&1" 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $output += "   Permissions: $filePerms`n"

            # Parse permissions (should be 644 or more restrictive, root:root)
            if ($filePerms -match '^(\d{3})\s+(\S+):(\S+)') {
                $perms = $matches[1]
                $owner = $matches[2]
                $group = $matches[3]

                # Check if world-writable (last digit should not be 2,3,6,7)
                $worldPerms = [int]($perms.Substring(2,1))
                if ($worldPerms -band 2) {
                    $output += "   [FINDING] Service file is world-writable ($perms)`n"
                    $nonPrivilegedAccess = $true
                    $serviceProtected = $false
                } else {
                    $output += "   [PASS] Service file is not world-writable`n"
                }

                # Check ownership (should be root)
                if ($owner -ne 'root') {
                    $output += "   [FINDING] Service file not owned by root (owner: $owner)`n"
                    $serviceProtected = $false
                } else {
                    $output += "   [PASS] Service file owned by root`n"
                }
            }
        } else {
            $output += "   [INFO] Could not retrieve file permissions: $filePerms`n"
        }
    } else {
        $output += "   [INFO] xo-server service file not found or service not installed`n"
        $output += "   Command output: $serviceFilePath`n"
    }
    $output += "`n"

    # Check 2: Service control permissions (systemd restricts by default)
    $output += "Check 2: Service Control Permissions`n"
    $output += "--------------------------------------------------------------------`n"
    $output += "   Systemd service control is restricted to root and users with sudo privileges`n"
    $output += "   by default. Checking for polkit rules that may override this...`n`n"

    # Check for polkit rules affecting xo-server
    $polkitRules = $(bash -c "find /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d -type f -name '*.rules' 2>/dev/null | xargs grep -l 'xo-server' 2>/dev/null" 2>&1)
    if ($LASTEXITCODE -eq 0 -and $polkitRules) {
        $output += "   [FINDING] Polkit rules found affecting xo-server:`n"
        $output += "   $polkitRules`n"
        $output += "   These rules may allow non-privileged users to control the service`n"
        $nonPrivilegedAccess = $true
        $serviceProtected = $false
    } else {
        $output += "   [PASS] No polkit rules found affecting xo-server service control`n"
    }
    $output += "`n"

    # Check 3: Sudo configuration
    $output += "Check 3: Sudo Configuration`n"
    $output += "--------------------------------------------------------------------`n"
    $sudoRules = $(bash -c "grep -r 'xo-server' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'" 2>&1)
    if ($LASTEXITCODE -eq 0 -and $sudoRules -and $sudoRules.Trim()) {
        $output += "   [INFO] Sudo rules found for xo-server:`n"
        $sudoRules -split "`n" | ForEach-Object {
            if ($_.Trim()) {
                $output += "   $_`n"
                # Check if rule allows NOPASSWD or grants broad permissions
                if ($_ -match 'NOPASSWD' -and $_ -notmatch 'root') {
                    $output += "      [FINDING] Rule allows passwordless service control for non-root users`n"
                    $nonPrivilegedAccess = $true
                    $serviceProtected = $false
                }
            }
        }
    } else {
        $output += "   [PASS] No sudo rules found granting xo-server service control`n"
    }
    $output += "`n"

    # Check 4: User privilege verification
    $output += "Check 4: User Privilege Verification`n"
    $output += "--------------------------------------------------------------------`n"
    $output += "   Verifying that non-root users cannot access systemctl controls...`n`n"

    # Check if systemd user mode service exists (allows non-root control)
    $userService = $(bash -c "systemctl --user status xo-server 2>&1" 2>&1)
    if ($userService -like '*loaded*') {
        $output += "   [FINDING] User-mode systemd service detected for xo-server`n"
        $output += "   This allows non-root users to start/stop their own xo-server instance`n"
        $nonPrivilegedAccess = $true
        $serviceProtected = $false
    } else {
        $output += "   [PASS] No user-mode systemd service found for xo-server`n"
    }
    $output += "`n"

    # Check 5: Process ownership and PID file protection
    $output += "Check 5: Process Ownership and PID File Protection`n"
    $output += "--------------------------------------------------------------------`n"

    # Check if xo-server is running and get process owner
    $xoProcess = $(bash -c "ps aux | grep -E 'node.*(xo-server|cli\.mjs)' | grep -v grep" 2>&1)
    if ($LASTEXITCODE -eq 0 -and $xoProcess) {
        $output += "   XO process detected:`n"
        $processOwner = ($xoProcess -split '\s+')[0]
        $output += "   Process owner: $processOwner`n"

        if ($processOwner -ne 'root') {
            $output += "   [INFO] XO runs as non-root user '$processOwner' (best practice for isolation)`n"
            $output += "   Process isolation does not weaken service control protection`n"
        } else {
            $output += "   [INFO] XO runs as root user`n"
        }
    } else {
        $output += "   [INFO] XO server process not currently running`n"
    }
    $output += "`n"

    # Determine final status
    $output += "====================================================================`n"
    $output += "ASSESSMENT SUMMARY`n"
    $output += "====================================================================`n"
    if ($serviceProtected -and -not $nonPrivilegedAccess) {
        $Status = "NotAFinding"
        $output += "Status: NOT A FINDING`n`n"
        $output += "The xo-server service is properly protected from being stopped by`n"
        $output += "non-privileged users. Systemd restricts service control to root and`n"
        $output += "authorized sudo users. No polkit rules or user-mode services allow`n"
        $output += "non-privileged access to service control.`n"
    } else {
        $Status = "Open"
        $output += "Status: OPEN`n`n"
        $output += "FINDING: The xo-server service is NOT adequately protected from being`n"
        $output += "stopped by non-privileged users.`n`n"
        $output += "ISSUES IDENTIFIED:`n"
        if (-not $serviceProtected) {
            $output += "- Service file permissions or ownership allow non-privileged modification`n"
        }
        if ($nonPrivilegedAccess) {
            $output += "- Non-privileged users can control the service via polkit, sudo, or user-mode systemd`n"
        }
        $output += "`n"
        $output += "IMPACT: An attacker with non-privileged access could stop the web server,`n"
        $output += "causing a denial of service or facilitating configuration tampering.`n`n"
        $output += "REMEDIATION:`n"
        $output += "1. Ensure service file is owned by root:root with permissions 644 or more restrictive`n"
        $output += "2. Remove any polkit rules allowing non-privileged service control`n"
        $output += "3. Restrict sudo rules to authorized administrators only`n"
        $output += "4. Disable any user-mode systemd services for xo-server`n"
        $output += "5. Verify only root and authorized admins can execute systemctl stop/restart xo-server`n"
    }

    $FindingDetails = $output
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
