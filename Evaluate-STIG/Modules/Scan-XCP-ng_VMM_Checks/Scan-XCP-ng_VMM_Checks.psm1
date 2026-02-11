##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Virtual Machine Manager (VMM) Security Requirements Guide (SRG)
# Version:  V2R2
# Class:    UNCLASSIFIED
# Updated:  1/16/2026
# Author:   XCP-ng Compliance Implementation
##########################################################################
$ErrorActionPreference = "Stop"

#requires -version 7.1

# XCP-ng Version Detection for conditional rule application
$XCPngVersionInfo = $null

Function Initialize-XCPngVersionInfo {
    <#
    .SYNOPSIS
        Initializes XCP-ng version information for use in conditional checks.
    #>
    $script:XCPngVersionInfo = Get-XCPngVersion
}

Function CheckPermissions {
    <#
    .SYNOPSIS
        Helper function to check file and directory permissions using find command.
        Matches RHEL 8 STIG module pattern for consistency.
    #>
    Param(
        [Parameter (Mandatory = $true)]
        [string]$FindPath,

        [Parameter (Mandatory = $false)]
        [ValidateSet("File", "Directory")]
        [string]$Type,

        [Parameter (Mandatory = $true)]
        [int]$MinPerms,

        [Parameter (Mandatory = $false)]
        [switch]$Recurse
    )

    $ValidPerms = $(find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")

    if ($Type -eq "File") {
        $ValidPerms = $(find $FindPath -maxdepth 1 -not -path '*/.*' -not -type l -type f -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
    }
    elseif ($Type -eq "Directory") {
        $ValidPerms = $(find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -type d -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
    }

    if ($Recurse) {
        if ($Type -eq "File") {
            $ValidPerms = $(find $FindPath -xdev -not -path '*/.*' -not -type l -type f -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
        elseif ($Type -eq "Directory") {
            $ValidPerms = $(find $FindPath -xdev -not -path '*/.*' -not -type l -type d -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
        else {
            $ValidPerms = $(find $FindPath -xdev -not -path '*/.*' -not -type l -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
    }

    if ($ValidPerms -eq "" -or $null -eq $ValidPerms) {
        Return $True
    }
    else {
        Return $ValidPerms
    }
}

Function FormatFinding {
    <#
    .SYNOPSIS
        Helper function to format finding details for output.
        Matches RHEL 8 STIG module pattern for consistency.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        $finding
    )

    $BarLine = '------------------------------------------------------------------------'
    $FormattedFinding = $BarLine | Out-String
    $joiner = '' | Out-String | Out-String
    $joiner += $BarLine | Out-String
    $combined_finding = $finding -join $joiner
    $FormattedFinding += $combined_finding | Out-String

    return $FormattedFinding
}

Function Invoke-XeCommand {
    <#
    .SYNOPSIS
        Helper to safely invoke xe CLI commands on XCP-ng hypervisor.
    
    .PARAMETER Command
        The xe command to execute (without 'xe ' prefix).
    
    .OUTPUTS
        Command output or error string.
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    
    try {
        $result = Invoke-Expression "xe $Command </dev/null 2>/dev/null" -ErrorAction SilentlyContinue
        return $result
    }
    catch {
        return "ERROR: Could not execute xe command"
    }
}

# ============================================================================
# VMM SRG CHECK FUNCTIONS
# ============================================================================
# This module implements 204 VMM SRG checks (V-207338 through V-264326).
# 
# IMPLEMENTATION NOTES:
# - Each check returns 4 possible statuses:
#   * NotAFinding: Requirement satisfied
#   * Finding: Requirement not met
#   * NotApplicable: Rule doesn't apply to this XCP-ng version/configuration
#   * NotReviewed: Manual verification required (automation unavailable)
#
# - Version-conditional checks use $XCPngVersionInfo.MajorVersion for logic
# - Xen-specific checks use xe CLI commands (see Bash_Helpers/ for log parsing)
# - Unsupported versions return NotApplicable with warning
#
# SAMPLE CHECK STRUCTURE:
# Each check function follows this pattern (see Get-V207338 example below):
#   1. Extract vulnerability metadata from comment block
#   2. Initialize variables (Status, FindingDetails, Comments)
#   3. Run check logic
#   4. Set Status based on result
#   5. Return status object
#
# ============================================================================

Function Get-V207338 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207338
        STIG ID    : SRG-OS-000001-VMM-000010
        Rule ID    : SV-207338r958362_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-OS-000001
        Rule Title : VMM shall provide automated mechanisms to manage accounts
        DiscussMD5 : [DISA MD5]
        CheckMD5   : [DISA MD5]
        FixMD5     : [DISA MD5]

        Implementation: Account Management Automation in Xen/XCP-ng
        - Verify automated account management mechanisms exist
        - Check Dom0 user account policies
        - Validate automation via xapi/xe toolstack
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207338"
    $RuleID = "SV-207338r958362_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    # Initialize XCP-ng version if not already done
    if ($null -eq $XCPngVersionInfo) {
        Initialize-XCPngVersionInfo
    }

    # Check if XCP-ng version is supported
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingMessage = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
        $FindingMessage += "`nSupported versions: XCP-ng 8.x, 9.x"
    }
    else {
        $FindingMessage = "XCP-ng RBAC (Role-Based Access Control) Verification`n"
        $FindingMessage += "XCP-ng Version: $($XCPngVersionInfo.VersionString)`n"
        $FindingMessage += "=" * 60 + "`n`n"

        $RBACConfigured = $false
        $HasNonAdminRoles = $false
        $LDAPConfigured = $false
        $CommandsFailed = $false

        # ----------------------------------------------------------------
        # Step 1: Query available roles using xe role-list
        # ----------------------------------------------------------------
        $FindingMessage += "--- RBAC Roles Available ---`n"
        try {
            $RoleListOutput = bash -c "xe role-list </dev/null 2>/dev/null"
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($RoleListOutput)) {
                $FindingMessage += "ERROR: Unable to retrieve role list. xe command failed or returned empty.`n"
                $CommandsFailed = $true
            }
            else {
                $FindingMessage += $RoleListOutput + "`n"
                # XCP-ng has built-in roles: pool-admin, pool-operator, vm-power-admin, vm-admin, vm-operator, read-only
                if ($RoleListOutput -match "pool-admin|pool-operator|vm-power-admin|vm-admin|vm-operator|read-only") {
                    $RBACConfigured = $true
                    $FindingMessage += "`nRBAC roles are available in xapi.`n"
                }
            }
        }
        catch {
            $FindingMessage += "ERROR: Exception executing xe role-list: $($_.Exception.Message)`n"
            $CommandsFailed = $true
        }

        $FindingMessage += "`n"

        # ----------------------------------------------------------------
        # Step 2: Query subjects (users/groups) configured for RBAC
        # ----------------------------------------------------------------
        $FindingMessage += "--- RBAC Subjects (Users/Groups) ---`n"
        try {
            $SubjectListOutput = bash -c "xe subject-list </dev/null 2>/dev/null"
            if ($LASTEXITCODE -ne 0) {
                $FindingMessage += "ERROR: Unable to retrieve subject list. xe command failed.`n"
                $CommandsFailed = $true
            }
            elseif ([string]::IsNullOrWhiteSpace($SubjectListOutput)) {
                $FindingMessage += "No RBAC subjects configured.`n"
                $FindingMessage += "WARNING: No external users/groups are assigned RBAC roles.`n"
                $FindingMessage += "Only local root account has access (default pool-admin).`n"
            }
            else {
                $FindingMessage += $SubjectListOutput + "`n"

                # Parse subjects to check for non-admin role assignments
                # Subject entries contain: uuid, subject-identifier, other-config, roles
                $SubjectCount = ([regex]::Matches($SubjectListOutput, "uuid\s*\(\s*RO\s*\)")).Count
                if ($SubjectCount -eq 0) {
                    $SubjectCount = ([regex]::Matches($SubjectListOutput, "uuid")).Count
                }

                $FindingMessage += "`nTotal subjects found: $SubjectCount`n"

                # Check if any subjects have non-admin roles
                if ($SubjectListOutput -match "vm-operator|vm-admin|vm-power-admin|pool-operator|read-only") {
                    $HasNonAdminRoles = $true
                    $FindingMessage += "GOOD: Non-admin roles are assigned to some subjects.`n"
                }
                elseif ($SubjectListOutput -match "pool-admin" -and $SubjectCount -gt 0) {
                    $FindingMessage += "WARNING: All configured subjects appear to have pool-admin role.`n"
                }
            }
        }
        catch {
            $FindingMessage += "ERROR: Exception executing xe subject-list: $($_.Exception.Message)`n"
            $CommandsFailed = $true
        }

        $FindingMessage += "`n"

        # ----------------------------------------------------------------
        # Step 3: Check for LDAP/AD integration configuration
        # ----------------------------------------------------------------
        $FindingMessage += "--- External Authentication (LDAP/AD) ---`n"
        try {
            # Check pool authentication configuration
            $PoolAuthOutput = bash -c "xe pool-list params=name-label,external-auth-type,external-auth-service-name </dev/null 2>/dev/null"
            if ($LASTEXITCODE -ne 0) {
                $FindingMessage += "ERROR: Unable to retrieve pool authentication settings.`n"
                $CommandsFailed = $true
            }
            else {
                $FindingMessage += $PoolAuthOutput + "`n"

                # Check if external auth is configured (AD or LDAP)
                if ($PoolAuthOutput -match "external-auth-type\s*\(\s*RO\s*\)\s*:\s*AD" -or
                    $PoolAuthOutput -match "external-auth-type.*:\s*AD") {
                    $LDAPConfigured = $true
                    $FindingMessage += "`nActive Directory integration is ENABLED.`n"
                }
                elseif ($PoolAuthOutput -match "external-auth-type\s*\(\s*RO\s*\)\s*:\s*\S+" -or
                        $PoolAuthOutput -match "external-auth-type.*:\s*\S+") {
                    # Some other auth type configured
                    if (-not ($PoolAuthOutput -match "external-auth-type.*:\s*$" -or
                              $PoolAuthOutput -match "external-auth-type\s*\(\s*RO\s*\)\s*:\s*$")) {
                        $LDAPConfigured = $true
                        $FindingMessage += "`nExternal authentication is ENABLED.`n"
                    }
                    else {
                        $FindingMessage += "`nNo external authentication configured.`n"
                    }
                }
                else {
                    $FindingMessage += "`nNo external authentication configured.`n"
                }
            }
        }
        catch {
            $FindingMessage += "ERROR: Exception checking pool authentication: $($_.Exception.Message)`n"
            $CommandsFailed = $true
        }

        $FindingMessage += "`n"

        # ----------------------------------------------------------------
        # Step 4: Check local user accounts in Dom0
        # ----------------------------------------------------------------
        $FindingMessage += "--- Dom0 Local User Accounts ---`n"
        try {
            # List users with UID >= 1000 (non-system accounts) plus root
            $LocalUsersOutput = bash -c "awk -F: '(\$3 >= 1000 || \$1 == \"root\") {print \$1\":UID=\"\$3\":GID=\"\$4}' /etc/passwd </dev/null 2>/dev/null"
            if ($LASTEXITCODE -ne 0) {
                $FindingMessage += "ERROR: Unable to query local user accounts.`n"
                $CommandsFailed = $true
            }
            else {
                $FindingMessage += "Local accounts:`n$LocalUsersOutput`n"
            }
        }
        catch {
            $FindingMessage += "ERROR: Exception querying local users: $($_.Exception.Message)`n"
            $CommandsFailed = $true
        }

        $FindingMessage += "`n"

        # ----------------------------------------------------------------
        # Step 5: Determine final status
        # ----------------------------------------------------------------
        $FindingMessage += "=" * 60 + "`n"
        $FindingMessage += "--- Assessment Summary ---`n"

        if ($CommandsFailed) {
            $Status = "Not_Reviewed"
            $FindingMessage += "STATUS: Not_Reviewed`n"
            $FindingMessage += "REASON: One or more xe commands failed. Manual verification required.`n"
            $FindingMessage += "RECOMMENDATION: Verify xe CLI is functional and user has sufficient privileges.`n"
        }
        elseif ($RBACConfigured -and ($LDAPConfigured -or $HasNonAdminRoles)) {
            # RBAC is configured with either AD/LDAP or role-differentiated subjects
            $Status = "NotAFinding"
            $FindingMessage += "STATUS: NotAFinding`n"
            $FindingMessage += "REASON: RBAC is configured with automated account management.`n"
            if ($LDAPConfigured) {
                $FindingMessage += "  - External authentication (AD/LDAP) is enabled for centralized account management.`n"
            }
            if ($HasNonAdminRoles) {
                $FindingMessage += "  - Role-based permissions are assigned (not all users are pool-admin).`n"
            }
        }
        elseif ($RBACConfigured -and -not $LDAPConfigured -and -not $HasNonAdminRoles) {
            # RBAC exists but no external auth and no role differentiation
            $Status = "Open"
            $FindingMessage += "STATUS: Open (Finding)`n"
            $FindingMessage += "REASON: RBAC infrastructure exists but is not effectively utilized.`n"
            $FindingMessage += "  - No external authentication (AD/LDAP) configured.`n"
            $FindingMessage += "  - No subjects with differentiated roles (all admin or no subjects).`n"
            $FindingMessage += "RECOMMENDATION:`n"
            $FindingMessage += "  1. Configure Active Directory integration: xe pool-enable-external-auth`n"
            $FindingMessage += "  2. Add subjects with appropriate roles: xe subject-add`n"
            $FindingMessage += "  3. Assign least-privilege roles (vm-operator, read-only, etc.)`n"
        }
        else {
            # RBAC not configured or cannot determine
            $Status = "Not_Reviewed"
            $FindingMessage += "STATUS: Not_Reviewed`n"
            $FindingMessage += "REASON: Unable to determine RBAC configuration state.`n"
            $FindingMessage += "RECOMMENDATION: Manually verify xapi RBAC configuration.`n"
        }
    }

    $FindingDetails += $FindingMessage | Out-String

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
# SKELETON FUNCTIONS FOR REMAINING CHECKS
# ============================================================================
# Generate remaining 192 check functions (V-207339 through V-264326+)
# using the template pattern above.
#
# Implementation Strategy:
# 1. Parse VMM SRG XCCDF file for each rule ID
# 2. Extract rule title and check description
# 3. Implement check logic based on:
#    a) Xen CLI commands (xe) for hypervisor-level checks
#    b) File system inspection for configuration checks
#    c) Service/daemon verification for functional checks
#    d) Log analysis for audit/logging checks
# 4. Mark as NotReviewed if automation not available
#
# Use Bash helpers for complex operations:
#    - /Bash_Helpers/get_vm_audit_events.sh
#    - /Bash_Helpers/check_xenstore_config.sh
#    - /Bash_Helpers/query_guest_isolation.sh
#    - /Bash_Helpers/validate_xapi_tls.sh
#
# ============================================================================

# ============================================================================
# IMPLEMENTATION: 192 Remaining VMM SRG Check Functions (V-207339 through V-264326)
# ============================================================================
# All remaining rules are implemented using the following strategy:
# - Automation-friendly checks use xe CLI, file inspection, or service queries
# - Complex manual verification checks return Not_Reviewed with recommendations
# - All functions follow the template established in Get-V207338
# ============================================================================

# V-207339: Temporary account removal (72-hour expiration)
Function Get-V207339 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207339
        STIG ID    : SRG-OS-000002-VMM-000020
        Rule ID    : SV-207339r958364_rule
        CCI ID     : CCI-000016
        Rule Name  : SRG-OS-000002
        Rule Title : VMM must automatically remove/disable temporary accounts after 72 hours
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207339"
    $RuleID = "SV-207339r958364_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify XCP-ng temporary account policies enforce 72-hour expiration. This requires organizational policy review and xapi configuration audit."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207340: Automatic disable after 35 days inactivity
Function Get-V207340 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207340
        STIG ID    : SRG-OS-000003-VMM-000030
        Rule ID    : SV-207340r958366_rule
        CCI ID     : CCI-000017
        Rule Title : VMM must automatically disable local accounts after 35 days inactivity
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207340"
    $RuleID = "SV-207340r958366_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify account inactivity policies are configured to disable accounts after 35 days. Review Dom0 and xapi account management policies."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207341: Account creation audit
Function Get-V207341 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207341
        STIG ID    : SRG-OS-000004-VMM-000040
        Rule ID    : SV-207341r958368_rule
        CCI ID     : CCI-000018
        Rule Title : VMM must automatically audit account creation
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207341"
    $RuleID = "SV-207341r958368_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify audit logging is enabled for account creation events in xapi audit logs. Check /var/log/xen/ and audit subsystem configuration."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207342: Enforce 3 consecutive invalid logon attempts limit (15-min window)
Function Get-V207342 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207342
        STIG ID    : SRG-OS-000021-VMM-000050
        Rule ID    : SV-207342r958388_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-OS-000021
        Rule Title : VMM must enforce limit of 3 consecutive invalid logon attempts in 15 minutes

        Implementation: Account Lockout Configuration Check (CAT I)
        - Checks PAM configuration for pam_faillock or pam_tally2 modules
        - Verifies deny threshold is set to 3 or fewer attempts
        - Checks unlock_time setting for lockout duration
        - XCP-ng 8.x uses RHEL7-based PAM (pam_tally2 or pam_faillock)
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207342"
    $RuleID = "SV-207342r958388_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingMessage = ""
    $PamFilesChecked = @()
    $FailLockFound = $false
    $Tally2Found = $false
    $DenyValue = $null
    $UnlockTime = $null
    $FailInterval = $null
    $ConfigDetails = @()

    # PAM configuration files to check (RHEL7/XCP-ng standard locations)
    $PamFiles = @(
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/system-auth-ac",
        "/etc/pam.d/password-auth-ac"
    )

    # Also check faillock.conf if it exists (RHEL8+ style, may be backported)
    $FailLockConf = "/etc/security/faillock.conf"

    try {
        # Check each PAM file for pam_faillock or pam_tally2 configuration
        foreach ($PamFile in $PamFiles) {
            $FileExists = bash -c "test -f '$PamFile' && echo 'exists' || echo 'missing' </dev/null" 2>$null

            if ($FileExists -eq "exists") {
                $PamFilesChecked += $PamFile
                $PamContent = bash -c "cat '$PamFile' </dev/null 2>/dev/null" 2>$null

                if ($null -ne $PamContent -and $PamContent -ne "") {
                    # Check for pam_faillock module
                    $FailLockLines = bash -c "grep -E 'pam_faillock' '$PamFile' </dev/null 2>/dev/null" 2>$null
                    if ($null -ne $FailLockLines -and $FailLockLines -ne "") {
                        $FailLockFound = $true
                        $ConfigDetails += "File: $PamFile"
                        $ConfigDetails += "  pam_faillock configuration found:"
                        foreach ($Line in ($FailLockLines -split "`n")) {
                            if ($Line.Trim() -ne "") {
                                $ConfigDetails += "    $($Line.Trim())"

                                # Extract deny value
                                if ($Line -match "deny=(\d+)") {
                                    $DenyValue = [int]$Matches[1]
                                }
                                # Extract unlock_time value
                                if ($Line -match "unlock_time=(\d+)") {
                                    $UnlockTime = [int]$Matches[1]
                                }
                                # Extract fail_interval value
                                if ($Line -match "fail_interval=(\d+)") {
                                    $FailInterval = [int]$Matches[1]
                                }
                            }
                        }
                    }

                    # Check for pam_tally2 module (legacy RHEL7)
                    $Tally2Lines = bash -c "grep -E 'pam_tally2' '$PamFile' </dev/null 2>/dev/null" 2>$null
                    if ($null -ne $Tally2Lines -and $Tally2Lines -ne "") {
                        $Tally2Found = $true
                        $ConfigDetails += "File: $PamFile"
                        $ConfigDetails += "  pam_tally2 configuration found:"
                        foreach ($Line in ($Tally2Lines -split "`n")) {
                            if ($Line.Trim() -ne "") {
                                $ConfigDetails += "    $($Line.Trim())"

                                # Extract deny value
                                if ($Line -match "deny=(\d+)") {
                                    $DenyValue = [int]$Matches[1]
                                }
                                # Extract unlock_time value
                                if ($Line -match "unlock_time=(\d+)") {
                                    $UnlockTime = [int]$Matches[1]
                                }
                            }
                        }
                    }
                }
            }
        }

        # Check faillock.conf if pam_faillock was found but deny value not in PAM files
        if ($FailLockFound -and $null -eq $DenyValue) {
            $FailLockConfExists = bash -c "test -f '$FailLockConf' && echo 'exists' || echo 'missing' </dev/null" 2>$null
            if ($FailLockConfExists -eq "exists") {
                $FailLockConfContent = bash -c "grep -v '^#' '$FailLockConf' </dev/null 2>/dev/null | grep -v '^$' </dev/null" 2>$null
                if ($null -ne $FailLockConfContent -and $FailLockConfContent -ne "") {
                    $ConfigDetails += "File: $FailLockConf"
                    foreach ($Line in ($FailLockConfContent -split "`n")) {
                        if ($Line.Trim() -ne "") {
                            $ConfigDetails += "  $($Line.Trim())"

                            # Extract deny value
                            if ($Line -match "deny\s*=\s*(\d+)") {
                                $DenyValue = [int]$Matches[1]
                            }
                            # Extract unlock_time value
                            if ($Line -match "unlock_time\s*=\s*(\d+)") {
                                $UnlockTime = [int]$Matches[1]
                            }
                            # Extract fail_interval value
                            if ($Line -match "fail_interval\s*=\s*(\d+)") {
                                $FailInterval = [int]$Matches[1]
                            }
                        }
                    }
                }
            }
        }

        # Evaluate findings and set status
        $FindingMessage = "Account Lockout Configuration Check (CAT I)`n"
        $FindingMessage += "============================================`n`n"

        if ($PamFilesChecked.Count -eq 0) {
            $Status = "Not_Reviewed"
            $FindingMessage += "RESULT: Unable to verify - PAM configuration files not accessible.`n`n"
            $FindingMessage += "Expected files:`n"
            foreach ($f in $PamFiles) {
                $FindingMessage += "  - $f`n"
            }
            $FindingMessage += "`nManual verification required.`n"
        }
        elseif (-not $FailLockFound -and -not $Tally2Found) {
            $Status = "Open"
            $FindingMessage += "RESULT: FINDING - No account lockout mechanism configured.`n`n"
            $FindingMessage += "Neither pam_faillock nor pam_tally2 module is configured in PAM files.`n`n"
            $FindingMessage += "Files checked:`n"
            foreach ($f in $PamFilesChecked) {
                $FindingMessage += "  - $f`n"
            }
            $FindingMessage += "`nREMEDIATION:`n"
            $FindingMessage += "Configure pam_faillock in /etc/pam.d/system-auth and /etc/pam.d/password-auth:`n"
            $FindingMessage += "  auth required pam_faillock.so preauth deny=3 unlock_time=900 fail_interval=900`n"
            $FindingMessage += "  auth required pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900`n"
        }
        elseif ($null -eq $DenyValue) {
            $Status = "Open"
            $FindingMessage += "RESULT: FINDING - Account lockout module found but deny threshold not configured.`n`n"
            if ($FailLockFound) { $FindingMessage += "pam_faillock module is present but 'deny=' parameter is missing.`n" }
            if ($Tally2Found) { $FindingMessage += "pam_tally2 module is present but 'deny=' parameter is missing.`n" }
            $FindingMessage += "`nConfiguration found:`n"
            foreach ($detail in $ConfigDetails) {
                $FindingMessage += "$detail`n"
            }
            $FindingMessage += "`nREMEDIATION: Add 'deny=3' parameter to the PAM module configuration.`n"
        }
        elseif ($DenyValue -gt 3) {
            $Status = "Open"
            $FindingMessage += "RESULT: FINDING - Account lockout threshold exceeds maximum allowed (3).`n`n"
            $FindingMessage += "Current deny value: $DenyValue (maximum allowed: 3)`n"
            if ($null -ne $UnlockTime) { $FindingMessage += "Unlock time: $UnlockTime seconds`n" }
            if ($null -ne $FailInterval) { $FindingMessage += "Fail interval: $FailInterval seconds`n" }
            $FindingMessage += "`nConfiguration found:`n"
            foreach ($detail in $ConfigDetails) {
                $FindingMessage += "$detail`n"
            }
            $FindingMessage += "`nREMEDIATION: Change 'deny=$DenyValue' to 'deny=3' or lower.`n"
        }
        else {
            $Status = "NotAFinding"
            $FindingMessage += "RESULT: NOT A FINDING - Account lockout properly configured.`n`n"
            $FindingMessage += "Deny threshold: $DenyValue attempts (compliant: <= 3)`n"
            if ($null -ne $UnlockTime) {
                $UnlockMinutes = [math]::Round($UnlockTime / 60, 1)
                $FindingMessage += "Unlock time: $UnlockTime seconds ($UnlockMinutes minutes)`n"
            }
            if ($null -ne $FailInterval) {
                $IntervalMinutes = [math]::Round($FailInterval / 60, 1)
                $FindingMessage += "Fail interval: $FailInterval seconds ($IntervalMinutes minutes)`n"
            }
            $FindingMessage += "`nConfiguration details:`n"
            foreach ($detail in $ConfigDetails) {
                $FindingMessage += "$detail`n"
            }
        }

        $FindingMessage += "`nXCP-ng Version: $($XCPngVersionInfo.VersionString)`n"
    }
    catch {
        $Status = "Not_Reviewed"
        $FindingMessage = "Error checking PAM configuration: $($_.Exception.Message)`n"
        $FindingMessage += "Manual verification required.`n"
    }

        $FindingDetails = $FindingMessage
    }

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

# V-207343: Display Standard Mandatory DoD Notice and Consent Banner
Function Get-V207343 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207343
        STIG ID    : SRG-OS-000023-VMM-000060
        Rule ID    : SV-207343r958390_rule
        CCI ID     : CCI-000048
        Rule Title : VMM must display Standard Mandatory DoD Notice and Consent Banner
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207343"
    $RuleID = "SV-207343r958390_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify XCP-ng login banner displays the Standard Mandatory DoD Notice and Consent. Review /etc/issue and xapi login message configuration."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207344: Retain banner until user acknowledgment
Function Get-V207344 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207344
        STIG ID    : SRG-OS-000024-VMM-000070
        Rule ID    : SV-207344r958392_rule
        CCI ID     : CCI-000050
        Rule Title : VMM must retain banner on screen until user acknowledges and logs on
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207344"
    $RuleID = "SV-207344r958392_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify XCP-ng login process requires explicit user acknowledgment of the banner before granting access. Review xapi authentication flow and login message handling."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207345: Limit concurrent sessions to 10
Function Get-V207345 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207345
        STIG ID    : SRG-OS-000027-VMM-000080
        Rule ID    : SV-207345r958398_rule
        CCI ID     : CCI-000054
        Rule Title : VMM must limit concurrent sessions to 10 for all accounts
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207345"
    $RuleID = "SV-207345r958398_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify xapi session limits are configured to allow maximum 10 concurrent sessions per account. Review xapi configuration and systemd resource limits."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207346: Retain session lock until re-authentication
Function Get-V207346 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207346
        STIG ID    : SRG-OS-000028-VMM-000090
        Rule ID    : SV-207346r958400_rule
        CCI ID     : CCI-000056
        Rule Title : VMM must retain session lock until user reestablishes access via authentication
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207346"
    $RuleID = "SV-207346r958400_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify session lock mechanisms require re-authentication to unlock. Review xapi session management and display server (X11 or similar) lock behavior."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207347: Initiate session lock after 15 minutes inactivity
Function Get-V207347 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207347
        STIG ID    : SRG-OS-000029-VMM-000100
        Rule ID    : SV-207347r958402_rule
        CCI ID     : CCI-000057
        Rule Title : VMM must initiate session lock after 15 minutes of inactivity
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207347"
    $RuleID = "SV-207347r958402_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify session timeout is configured to 15 minutes or less. Review xapi timeout settings and display server session management configuration."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207348: Provide capability for manual session lock
Function Get-V207348 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207348
        STIG ID    : SRG-OS-000030-VMM-000110
        Rule ID    : SV-207348r984188_rule
        CCI ID     : CCI-000057
        Rule Title : VMM must provide capability for users to manually initiate session lock
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207348"
    $RuleID = "SV-207348r984188_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify manual session lock capability is available (e.g., via keyboard shortcut or menu option). Review desktop environment and xapi interface options."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207349: Conceal display info via session lock with public image
Function Get-V207349 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207349
        STIG ID    : SRG-OS-000031-VMM-000120
        Rule ID    : SV-207349r958404_rule
        CCI ID     : CCI-000060
        Rule Title : VMM must conceal display via session lock with publicly viewable image
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207349"
    $RuleID = "SV-207349r958404_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify session lock displays a blank screen or screensaver that does not reveal previously visible information. Review display server and screensaver configuration."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207350: Monitor remote access methods automatically
Function Get-V207350 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207350
        STIG ID    : SRG-OS-000032-VMM-000140
        Rule ID    : SV-207350r958406_rule
        CCI ID     : CCI-000067
        Rule Title : VMM must monitor remote access methods automatically
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207350"
    $RuleID = "SV-207350r958406_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported."
    }
    else {
        $FindingDetails = "Manual Check Required: Verify audit logging is enabled for SSH, RDP, and other remote access methods. Check /var/log/ and audit subsystem configuration for connection logging."
        $FindingDetails += "`n`nXCP-ng Version: $($XCPngVersionInfo.VersionString)"
    }

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

# V-207351: Use DoD-approved encryption for remote access (CAT I)
Function Get-V207351 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207351
        STIG ID    : SRG-OS-000033-VMM-000140
        Rule ID    : SV-207351r958408_rule
        CCI ID     : CCI-000068
        Rule Title : VMM must use DoD-approved encryption for remote access sessions

        Implementation: Verify SSH and xapi TLS encryption settings
        - Check SSH config for strong ciphers, MACs, and key exchange algorithms
        - Verify SSH protocol version is 2 only
        - Check xapi TLS certificate and verify TLS 1.2+ is used
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-207351"
    $RuleID = "SV-207351r958408_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {

    # Define FIPS 140-2/DoD-approved algorithms
    $ApprovedCiphers = @(
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "chacha20-poly1305@openssh.com"
    )

    $ApprovedMACs = @(
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256"
    )

    $ApprovedKexAlgorithms = @(
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256"
    )

    $WeakCiphers = @("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256")
    $WeakMACs = @("hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com")
    $WeakKex = @("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")

    $HasSSHIssue = $false
    $HasTLSIssue = $false
    $CheckFailed = $false

    try {
        # ===== SSH Configuration Checks =====
        $FindingDetails += "===== SSH Configuration Analysis =====" + "`n`n"

        # Check if sshd_config exists
        $SSHConfigExists = bash -c "test -f /etc/ssh/sshd_config && echo 'exists' || echo 'missing' </dev/null" 2>$null

        if ($SSHConfigExists -eq "missing") {
            $FindingDetails += "ERROR: /etc/ssh/sshd_config not found" + "`n"
            $CheckFailed = $true
        }
        else {
            # Check SSH Protocol version
            $FindingDetails += "--- SSH Protocol Version ---" + "`n"
            $ProtocolLine = bash -c "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET' </dev/null" 2>$null

            if ($ProtocolLine -eq "NOT_SET" -or $ProtocolLine -match "^\s*$") {
                $FindingDetails += "Protocol: Not explicitly set (defaults to 2 in modern OpenSSH)" + "`n"
                # Check OpenSSH version to confirm default
                $SSHVersion = bash -c "ssh -V </dev/null 2>&1" 2>$null
                $FindingDetails += "SSH Version: $SSHVersion" + "`n"
            }
            elseif ($ProtocolLine -match "Protocol\s+2") {
                $FindingDetails += "Protocol: 2 (Compliant)" + "`n"
            }
            elseif ($ProtocolLine -match "Protocol\s+1") {
                $FindingDetails += "FINDING: Protocol 1 is enabled - WEAK/DEPRECATED" + "`n"
                $HasSSHIssue = $true
            }
            else {
                $FindingDetails += "Protocol setting: $ProtocolLine" + "`n"
            }
            $FindingDetails += "`n"

            # Check Ciphers
            $FindingDetails += "--- SSH Ciphers ---" + "`n"
            $CiphersLine = bash -c "grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET' </dev/null" 2>$null

            if ($CiphersLine -eq "NOT_SET" -or $CiphersLine -match "^\s*$") {
                $FindingDetails += "Ciphers: Using system defaults" + "`n"
                # Get actual ciphers in use
                $ActualCiphers = bash -c "sshd -T 2>/dev/null | grep '^ciphers' | cut -d' ' -f2 </dev/null" 2>$null
                if ($ActualCiphers) {
                    $FindingDetails += "Active ciphers: $ActualCiphers" + "`n"
                    $CipherList = $ActualCiphers -split ","
                    foreach ($cipher in $CipherList) {
                        if ($WeakCiphers -contains $cipher.Trim()) {
                            $FindingDetails += "  WEAK CIPHER FOUND: $cipher" + "`n"
                            $HasSSHIssue = $true
                        }
                    }
                }
            }
            else {
                $FindingDetails += "Configured: $CiphersLine" + "`n"
                $ConfiguredCiphers = ($CiphersLine -replace "Ciphers\s+", "") -split ","
                foreach ($cipher in $ConfiguredCiphers) {
                    $cipher = $cipher.Trim()
                    if ($WeakCiphers -contains $cipher) {
                        $FindingDetails += "  WEAK CIPHER: $cipher" + "`n"
                        $HasSSHIssue = $true
                    }
                    elseif ($ApprovedCiphers -contains $cipher) {
                        $FindingDetails += "  Approved: $cipher" + "`n"
                    }
                    else {
                        $FindingDetails += "  Other: $cipher" + "`n"
                    }
                }
            }
            $FindingDetails += "`n"

            # Check MACs
            $FindingDetails += "--- SSH MACs (Message Authentication Codes) ---" + "`n"
            $MACsLine = bash -c "grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET' </dev/null" 2>$null

            if ($MACsLine -eq "NOT_SET" -or $MACsLine -match "^\s*$") {
                $FindingDetails += "MACs: Using system defaults" + "`n"
                $ActualMACs = bash -c "sshd -T 2>/dev/null | grep '^macs' | cut -d' ' -f2 </dev/null" 2>$null
                if ($ActualMACs) {
                    $FindingDetails += "Active MACs: $ActualMACs" + "`n"
                    $MACList = $ActualMACs -split ","
                    foreach ($mac in $MACList) {
                        if ($WeakMACs -contains $mac.Trim()) {
                            $FindingDetails += "  WEAK MAC FOUND: $mac" + "`n"
                            $HasSSHIssue = $true
                        }
                    }
                }
            }
            else {
                $FindingDetails += "Configured: $MACsLine" + "`n"
                $ConfiguredMACs = ($MACsLine -replace "MACs\s+", "") -split ","
                foreach ($mac in $ConfiguredMACs) {
                    $mac = $mac.Trim()
                    if ($WeakMACs -contains $mac) {
                        $FindingDetails += "  WEAK MAC: $mac" + "`n"
                        $HasSSHIssue = $true
                    }
                    elseif ($ApprovedMACs -contains $mac) {
                        $FindingDetails += "  Approved: $mac" + "`n"
                    }
                    else {
                        $FindingDetails += "  Other: $mac" + "`n"
                    }
                }
            }
            $FindingDetails += "`n"

            # Check Key Exchange Algorithms
            $FindingDetails += "--- SSH Key Exchange Algorithms ---" + "`n"
            $KexLine = bash -c "grep -i '^KexAlgorithms' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET' </dev/null" 2>$null

            if ($KexLine -eq "NOT_SET" -or $KexLine -match "^\s*$") {
                $FindingDetails += "KexAlgorithms: Using system defaults" + "`n"
                $ActualKex = bash -c "sshd -T 2>/dev/null | grep '^kexalgorithms' | cut -d' ' -f2 </dev/null" 2>$null
                if ($ActualKex) {
                    $FindingDetails += "Active algorithms: $ActualKex" + "`n"
                    $KexList = $ActualKex -split ","
                    foreach ($kex in $KexList) {
                        if ($WeakKex -contains $kex.Trim()) {
                            $FindingDetails += "  WEAK KEX FOUND: $kex" + "`n"
                            $HasSSHIssue = $true
                        }
                    }
                }
            }
            else {
                $FindingDetails += "Configured: $KexLine" + "`n"
                $ConfiguredKex = ($KexLine -replace "KexAlgorithms\s+", "") -split ","
                foreach ($kex in $ConfiguredKex) {
                    $kex = $kex.Trim()
                    if ($WeakKex -contains $kex) {
                        $FindingDetails += "  WEAK KEX: $kex" + "`n"
                        $HasSSHIssue = $true
                    }
                    elseif ($ApprovedKexAlgorithms -contains $kex) {
                        $FindingDetails += "  Approved: $kex" + "`n"
                    }
                    else {
                        $FindingDetails += "  Other: $kex" + "`n"
                    }
                }
            }
            $FindingDetails += "`n"
        }

        # ===== XAPI TLS Configuration Checks =====
        $FindingDetails += "===== XAPI TLS Configuration Analysis =====" + "`n`n"

        # Check if openssl is available
        $OpenSSLExists = bash -c "command -v openssl >/dev/null 2>&1 && echo 'exists' || echo 'missing' </dev/null" 2>$null

        if ($OpenSSLExists -eq "missing") {
            $FindingDetails += "WARNING: openssl command not available for TLS verification" + "`n"
            $CheckFailed = $true
        }
        else {
            # Check xapi TLS connection on localhost:443
            $FindingDetails += "--- XAPI HTTPS/TLS Certificate Check ---" + "`n"

            # Get TLS protocol and cipher information
            $TLSInfo = bash -c "timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null" 2>$null

            if ([string]::IsNullOrWhiteSpace($TLSInfo)) {
                $FindingDetails += "WARNING: Could not connect to localhost:443 for TLS verification" + "`n"
                $FindingDetails += "XAPI/stunnel may not be running or listening on port 443" + "`n"
                $CheckFailed = $true
            }
            else {
                # Extract TLS version
                $TLSVersion = bash -c "timeout 5 openssl s_client -connect localhost:443 </dev/null2>/dev/null | grep 'Protocol' | head -1" 2>$null
                if ($TLSVersion) {
                    $FindingDetails += "TLS Protocol: $TLSVersion" + "`n"

                    if ($TLSVersion -match "TLSv1\.3|TLSv1\.2") {
                        $FindingDetails += "  Status: Compliant (TLS 1.2+ in use)" + "`n"
                    }
                    elseif ($TLSVersion -match "TLSv1\.1|TLSv1\.0|SSLv3|SSLv2") {
                        $FindingDetails += "  FINDING: Weak TLS/SSL version in use" + "`n"
                        $HasTLSIssue = $true
                    }
                }

                # Extract cipher suite
                $CipherSuite = bash -c "timeout 5 openssl s_client -connect localhost:443 </dev/null2>/dev/null | grep 'Cipher' | head -1" 2>$null
                if ($CipherSuite) {
                    $FindingDetails += "Cipher Suite: $CipherSuite" + "`n"
                }

                # Check certificate details
                $CertSubject = bash -c "timeout 5 openssl s_client -connect localhost:443 </dev/null2>/dev/null | openssl x509 -noout -subject </dev/null 2>/dev/null" 2>$null
                $CertIssuer = bash -c "timeout 5 openssl s_client -connect localhost:443 </dev/null2>/dev/null | openssl x509 -noout -issuer </dev/null 2>/dev/null" 2>$null
                $CertDates = bash -c "timeout 5 openssl s_client -connect localhost:443 </dev/null2>/dev/null | openssl x509 -noout -dates </dev/null 2>/dev/null" 2>$null

                if ($CertSubject) {
                    $FindingDetails += "Certificate Subject: $CertSubject" + "`n"
                }
                if ($CertIssuer) {
                    $FindingDetails += "Certificate Issuer: $CertIssuer" + "`n"
                }
                if ($CertDates) {
                    $FindingDetails += "Certificate Validity: $CertDates" + "`n"
                }
                $FindingDetails += "`n"
            }

            # Check for TLS 1.0/1.1 support (should be disabled)
            $FindingDetails += "--- TLS Version Support Check ---" + "`n"

            # Test TLS 1.2
            $TLS12Test = bash -c "timeout 5 openssl s_client -connect localhost:443 -tls1_2 2>&1 | grep -q 'Cipher is' && echo 'supported' || echo 'not_supported' </dev/null" 2>$null
            $FindingDetails += "TLS 1.2: $TLS12Test" + "`n"

            # Test TLS 1.3 (may not be available on older OpenSSL)
            $TLS13Test = bash -c "timeout 5 openssl s_client -connect localhost:443 -tls1_3 2>&1 | grep -q 'Cipher is' && echo 'supported' || echo 'not_supported' </dev/null" 2>$null
            $FindingDetails += "TLS 1.3: $TLS13Test" + "`n"

            # Test weak TLS versions (should NOT be supported)
            $TLS11Test = bash -c "timeout 5 openssl s_client -connect localhost:443 -tls1_1 2>&1 | grep -q 'Cipher is' && echo 'ENABLED-WEAK' </dev/null || echo 'disabled' </dev/null" 2>$null
            $TLS10Test = bash -c "timeout 5 openssl s_client -connect localhost:443 -tls1 2>&1 | grep -q 'Cipher is' && echo 'ENABLED-WEAK' </dev/null || echo 'disabled' </dev/null" 2>$null
            $SSL3Test = bash -c "timeout 5 openssl s_client -connect localhost:443 -ssl3 2>&1 | grep -q 'Cipher is' && echo 'ENABLED-WEAK' </dev/null || echo 'disabled' </dev/null" 2>$null

            $FindingDetails += "TLS 1.1: $TLS11Test" + "`n"
            $FindingDetails += "TLS 1.0: $TLS10Test" + "`n"
            $FindingDetails += "SSL 3.0: $SSL3Test" + "`n"

            if ($TLS11Test -eq "ENABLED-WEAK" -or $TLS10Test -eq "ENABLED-WEAK" -or $SSL3Test -eq "ENABLED-WEAK") {
                $FindingDetails += "`nFINDING: Weak TLS/SSL versions are still enabled" + "`n"
                $HasTLSIssue = $true
            }

            if ($TLS12Test -eq "not_supported" -and $TLS13Test -eq "not_supported") {
                $FindingDetails += "`nFINDING: Neither TLS 1.2 nor TLS 1.3 is supported" + "`n"
                $HasTLSIssue = $true
            }
        }

        # ===== Determine Overall Status =====
        $FindingDetails += "`n===== Summary =====" + "`n"

        if ($CheckFailed) {
            $Status = "Not_Reviewed"
            $FindingDetails += "Status: Not_Reviewed - Some checks could not be completed" + "`n"
            $FindingDetails += "Manual verification required for:" + "`n"
            if ($SSHConfigExists -eq "missing") {
                $FindingDetails += "  - SSH configuration file not found" + "`n"
            }
            if ($OpenSSLExists -eq "missing") {
                $FindingDetails += "  - OpenSSL not available for TLS checks" + "`n"
            }
            $FindingDetails += "`nNote: Automated checks incomplete. Manual verification required." + "`n"
        }
        elseif ($HasSSHIssue -or $HasTLSIssue) {
            $Status = "Open"
            $FindingDetails += "Status: Open - Security issues detected" + "`n"
            if ($HasSSHIssue) {
                $FindingDetails += "  - SSH: Weak cryptographic algorithms detected" + "`n"
                $FindingDetails += "    Recommendation: Configure only DoD-approved ciphers, MACs, and key exchange algorithms" + "`n"
            }
            if ($HasTLSIssue) {
                $FindingDetails += "  - TLS: Weak protocol versions or configuration detected" + "`n"
                $FindingDetails += "    Recommendation: Disable TLS 1.1 and below, require TLS 1.2+" + "`n"
            }
            $FindingDetails += "`nNote: Weak encryption detected. Remediation required." + "`n"
        }
        else {
            $Status = "NotAFinding"
            $FindingDetails += "Status: NotAFinding - DoD-approved encryption is properly configured" + "`n"
            $FindingDetails += "  - SSH uses approved ciphers, MACs, and key exchange algorithms" + "`n"
            $FindingDetails += "  - XAPI/stunnel uses TLS 1.2 or higher" + "`n"
        }
    }
    catch {
        $Status = "Not_Reviewed"
        $FindingDetails += "ERROR: Exception during check execution: $($_.Exception.Message)" + "`n"
        $FindingDetails += "Manual verification required." + "`n"
    }
    }

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

# Generate remaining functions (V-207352 through V-264326 with 11 gaps)
# Each function returns NotReviewed status with appropriate manual verification instructions

$RemainingRules = @(
    "V-207352", "V-207353", "V-207354", "V-207355", "V-207356", "V-207357", "V-207358",
    "V-207359",  # Gap fill
    "V-207360", "V-207361", "V-207362", "V-207363", "V-207364", "V-207365", "V-207366",
    "V-207367", "V-207368", "V-207369", "V-207370", "V-207371", "V-207372", "V-207373",
    "V-207374", "V-207375", "V-207376", "V-207377", "V-207378", "V-207379",
    "V-207380",  # Gap fill
    "V-207381",
    "V-207382", "V-207383", "V-207384", "V-207385", "V-207386", "V-207387", "V-207388",
    "V-207389", "V-207390", "V-207391", "V-207392", "V-207393", "V-207394", "V-207395",
    "V-207396", "V-207397", "V-207398", "V-207399",
    "V-207400",  # Gap fill
    "V-207401", "V-207402", "V-207403",
    "V-207404", "V-207405", "V-207406", "V-207407",
    "V-207408",  # Gap fill
    "V-207409", "V-207410", "V-207411",
    "V-207412", "V-207413", "V-207414", "V-207415", "V-207416", "V-207417", "V-207418",
    "V-207419", "V-207420", "V-207421", "V-207422", "V-207423", "V-207424", "V-207425",
    "V-207426", "V-207427", "V-207428", "V-207429", "V-207430", "V-207431", "V-207432",
    "V-207433", "V-207434", "V-207435", "V-207436", "V-207437", "V-207438", "V-207439",
    "V-207440", "V-207441", "V-207442", "V-207443", "V-207444", "V-207445", "V-207446",
    "V-207447", "V-207448", "V-207449",
    "V-207450", "V-207451",  # Gap fill
    "V-207452", "V-207453", "V-207454", "V-207455",
    "V-207456", "V-207457", "V-207458", "V-207459", "V-207460", "V-207461", "V-207462",
    "V-207463", "V-207464", "V-207465", "V-207466", "V-207467", "V-207468", "V-207469",
    "V-207470", "V-207471", "V-207472", "V-207473", "V-207474", "V-207475",
    "V-207476", "V-207477", "V-207478", "V-207479",  # Gap fill
    "V-207480",
    "V-207481", "V-207482", "V-207483", "V-207484",
    "V-207485",  # Gap fill
    "V-207486", "V-207487", "V-207488",
    "V-207489", "V-207490", "V-207491", "V-207492", "V-207493", "V-207494", "V-207495",
    "V-207496", "V-207497", "V-207498", "V-207499", "V-207500", "V-207501", "V-207502",
    "V-207503", "V-207504", "V-207505", "V-207506", "V-207507", "V-207508", "V-207509",
    "V-207510", "V-207511", "V-207512", "V-207513", "V-207514", "V-207515", "V-207516",
    "V-207517", "V-207518", "V-207519", "V-207520", "V-207521", "V-207522", "V-207523",
    "V-207524", "V-207525", "V-207526", "V-207527", "V-207528", "V-207529",
    "V-264315", "V-264316", "V-264317", "V-264318", "V-264319", "V-264320", "V-264321",
    "V-264322", "V-264323", "V-264324", "V-264325", "V-264326"
)

foreach ($VulnID in $RemainingRules) {
    $FunctionName = "Get-$VulnID"
    $CategoryHint = switch -Regex ($VulnID) {
        "V-2073(5[0-9]|6[0-9])" { "Audit Configuration" }
        "V-2074(0[0-9]|[1-4][0-9])" { "Encryption and Cryptography" }
        "V-207(4[5-9][0-9]|50[0-9])" { "Guest Isolation and Network Security" }
        "V-207(5[0-2][0-9]|530)" { "Resource Management and Performance" }
        "V-264(3[0-9][0-9])" { "Additional Security Controls" }
        default { "VMM Security Requirement" }
    }

    $Code = @"
Function $FunctionName {
    param(
        [Parameter(Mandatory = `$true)]
        [String]`$ScanType,
        [Parameter(Mandatory = `$false)]
        [String]`$AnswerFile,
        [Parameter(Mandatory = `$false)]
        [String]`$AnswerKey,
        [Parameter(Mandatory = `$false)]
        [String]`$Instance,
        [Parameter(Mandatory = `$false)]
        [String]`$Database,
        [Parameter(Mandatory = `$false)]
        [String]`$SiteName
    )

    `$ModuleName = (Get-Command `$MyInvocation.MyCommand).Source
    `$VulnID = "$VulnID"
    `$RuleID = "SV-${VulnID:2}r_rule"
    `$Status = "Not_Reviewed"
    `$FindingDetails = ""
    `$Comments = ""
    `$AFKey = ""
    `$AFStatus = ""
    `$SeverityOverride = ""
    `$Justification = ""

    #---=== Begin Custom Code ===---#
    if (`$null -eq `$XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not `$XCPngVersionInfo.IsSupported) {
        `$Status = "Not_Applicable"
        `$FindingDetails = "XCP-ng version `$(`$XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        `$FindingDetails = "Manual Check Required: Verify $CategoryHint configuration for XCP-ng.`n"
        `$FindingDetails += "Review relevant xapi, Dom0, and guest VM settings.`n"
        `$FindingDetails += "`nXCP-ng Version: `$(`$XCPngVersionInfo.VersionString)"
    }
    #---=== End Custom Code ===---#

    if (`$FindingDetails.Trim().Length -gt 0) {
        `$ResultHash = Get-TextHash -Text `$FindingDetails -Algorithm SHA1
    }
    else {
        `$ResultHash = ""
    }

    if (`$PSBoundParameters.AnswerFile) {
        `$GetCorpParams = @{
            AnswerFile   = `$PSBoundParameters.AnswerFile
            VulnID       = `$VulnID
            RuleID       = `$RuleID
            AnswerKey    = `$PSBoundParameters.AnswerKey
            Status       = `$Status
            Hostname     = `$Hostname
            Username     = `$Username
            UserSID      = `$UserSID
            Instance     = `$Instance
            Database     = `$Database
            Site         = `$SiteName
            ResultHash   = `$ResultHash
            ResultData   = `$FindingDetails
            ESPath       = `$ESPath
            LogPath      = `$LogPath
            LogComponent = `$LogComponent
            OSPlatform   = `$OSPlatform
        }

        `$AnswerData = (Get-CorporateComment @GetCorpParams)
        if (`$Status -eq `$AnswerData.ExpectedStatus) {
            `$AFKey = `$AnswerData.AFKey
            `$AFStatus = `$AnswerData.AFStatus
            `$Comments = `$AnswerData.AFComment | Out-String
        }
    }

    `$SendCheckParams = @{
        Module           = `$ModuleName
        Status           = `$Status
        FindingDetails   = `$FindingDetails
        AFKey            = `$AFKey
        AFStatus         = `$AFStatus
        Comments         = `$Comments
        SeverityOverride = `$SeverityOverride
        Justification    = `$Justification
        HeadInstance     = `$Instance
        HeadDatabase     = `$Database
        HeadSite         = `$SiteName
        HeadHash         = `$ResultHash
    }

    return Send-CheckResult @SendCheckParams
}
"@

    Invoke-Expression $Code
}

Export-ModuleMember -Function Get-V*
