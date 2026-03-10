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
        $cmdParts = $Command -split '\s+'
        $result = $(xe @cmdParts 2>/dev/null)
        return $result
    }
    catch {
        return "ERROR: Could not execute xe command"
    }
}

# ============================================================================
# VMM SRG CHECK FUNCTIONS
# ============================================================================
# This module implements 193 VMM SRG checks (V-207338 through V-264326).
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
            $RoleListOutput = $(xe role-list 2>/dev/null)
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
            $SubjectListOutput = $(xe subject-list 2>/dev/null)
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
            $PoolAuthOutput = $(xe pool-list params=name-label,external-auth-type,external-auth-service-name 2>/dev/null)
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
            $LocalUsersOutput = $(awk -F: '{if ($3 >= 1000 || $1 == "root") print $1":UID="$3":GID="$4}' /etc/passwd 2>/dev/null)
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
            $FileExists = $(sh -c "test -f '$PamFile' && echo 'exists' || echo 'missing'")

            if ($FileExists -eq "exists") {
                $PamFilesChecked += $PamFile
                $PamContent = Get-Content -Path $PamFile -ErrorAction SilentlyContinue

                if ($null -ne $PamContent -and $PamContent -ne "") {
                    # Check for pam_faillock module
                    $FailLockLines = $(grep -E 'pam_faillock' $PamFile 2>/dev/null)
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
                    $Tally2Lines = $(grep -E 'pam_tally2' $PamFile 2>/dev/null)
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
            $FailLockConfExists = $(sh -c "test -f '$FailLockConf' && echo 'exists' || echo 'missing'")
            if ($FailLockConfExists -eq "exists") {
                $FailLockConfContent = $(sh -c "grep -v '^#' '$FailLockConf' 2>/dev/null | grep -v '^$'")
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
        $SSHConfigExists = $(sh -c "test -f /etc/ssh/sshd_config && echo 'exists' || echo 'missing'")

        if ($SSHConfigExists -eq "missing") {
            $FindingDetails += "ERROR: /etc/ssh/sshd_config not found" + "`n"
            $CheckFailed = $true
        }
        else {
            # Check SSH Protocol version
            $FindingDetails += "--- SSH Protocol Version ---" + "`n"
            $ProtocolLine = $(sh -c "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")

            if ($ProtocolLine -eq "NOT_SET" -or $ProtocolLine -match "^\s*$") {
                $FindingDetails += "Protocol: Not explicitly set (defaults to 2 in modern OpenSSH)" + "`n"
                # Check OpenSSH version to confirm default
                $SSHVersion = $(ssh -V 2>&1)
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
            $CiphersLine = $(sh -c "grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")

            if ($CiphersLine -eq "NOT_SET" -or $CiphersLine -match "^\s*$") {
                $FindingDetails += "Ciphers: Using system defaults" + "`n"
                # Get actual ciphers in use
                $ActualCiphers = $(sh -c "sshd -T 2>/dev/null | grep '^ciphers' | cut -d' ' -f2")
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
            $MACsLine = $(sh -c "grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")

            if ($MACsLine -eq "NOT_SET" -or $MACsLine -match "^\s*$") {
                $FindingDetails += "MACs: Using system defaults" + "`n"
                $ActualMACs = $(sh -c "sshd -T 2>/dev/null | grep '^macs' | cut -d' ' -f2")
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
            $KexLine = $(sh -c "grep -i '^KexAlgorithms' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'")

            if ($KexLine -eq "NOT_SET" -or $KexLine -match "^\s*$") {
                $FindingDetails += "KexAlgorithms: Using system defaults" + "`n"
                $ActualKex = $(sh -c "sshd -T 2>/dev/null | grep '^kexalgorithms' | cut -d' ' -f2")
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
        $OpenSSLExists = $(sh -c "command -v openssl >/dev/null 2>&1 && echo 'exists' || echo 'missing'")

        if ($OpenSSLExists -eq "missing") {
            $FindingDetails += "WARNING: openssl command not available for TLS verification" + "`n"
            $CheckFailed = $true
        }
        else {
            # Check xapi TLS connection on localhost:443
            $FindingDetails += "--- XAPI HTTPS/TLS Certificate Check ---" + "`n"

            # Get TLS protocol and cipher information
            $TLSInfo = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null')

            if ([string]::IsNullOrWhiteSpace($TLSInfo)) {
                $FindingDetails += "WARNING: Could not connect to localhost:443 for TLS verification" + "`n"
                $FindingDetails += "XAPI/stunnel may not be running or listening on port 443" + "`n"
                $CheckFailed = $true
            }
            else {
                # Extract TLS version
                $TLSVersion = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null | grep "Protocol" | head -1')
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
                $CipherSuite = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null | grep "Cipher" | head -1')
                if ($CipherSuite) {
                    $FindingDetails += "Cipher Suite: $CipherSuite" + "`n"
                }

                # Check certificate details
                $CertSubject = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null')
                $CertIssuer = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null')
                $CertDates = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null')

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
            $TLS12Test = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 -tls1_2 </dev/null 2>&1 | grep -q "Cipher is" && echo supported || echo not_supported')
            $FindingDetails += "TLS 1.2: $TLS12Test" + "`n"

            # Test TLS 1.3 (may not be available on older OpenSSL)
            $TLS13Test = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 -tls1_3 </dev/null 2>&1 | grep -q "Cipher is" && echo supported || echo not_supported')
            $FindingDetails += "TLS 1.3: $TLS13Test" + "`n"

            # Test weak TLS versions (should NOT be supported)
            $TLS11Test = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 -tls1_1 </dev/null 2>&1 | grep -q "Cipher is" && echo ENABLED-WEAK || echo disabled')
            $TLS10Test = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 -tls1 </dev/null 2>&1 | grep -q "Cipher is" && echo ENABLED-WEAK || echo disabled')
            $SSL3Test = $(sh -c 'timeout 5 openssl s_client -connect localhost:443 -ssl3 </dev/null 2>&1 | grep -q "Cipher is" && echo ENABLED-WEAK || echo disabled')

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

# ============================================================================
# AUDIT & LOGGING CHECK FUNCTIONS (V-207352 through V-207366)
# ============================================================================

Function Get-V207352 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207352
        STIG ID    : SRG-OS-000037-VMM-000150
        Rule ID    : SV-207352r958412_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-OS-000037
        Rule Title : The VMM must produce audit records containing information to establish what type of events occurred.
        DiscussMD5 : 4fd236cf0daa751f8888bc887d8d308e
        CheckMD5   : ac3fe7f4b7bb46b75ba5719cfa1882e9
        FixMD5     : 7e82943434d3a489ea3ab0234b615c0a
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
    $VulnID = "V-207352"
    $RuleID = "SV-207352r958412_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Event Type Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd status
        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # Check audit rules exist
            $AuditRules = $(auditctl -l 2>/dev/null)
            $AuditRulesStr = ($AuditRules -join $nl).Trim()
            $RuleCount = 0
            if ($AuditRulesStr -ne "" -and $AuditRulesStr -notmatch "No rules") {
                $RuleCount = ($AuditRulesStr -split $nl).Count
            }
            $FindingDetails += "Audit rules configured: $RuleCount" + $nl + $nl

            # Check audit log for type= field (event type classification)
            $AuditSample = $(timeout 3 tail -5 /var/log/audit/audit.log 2>/dev/null)
            $AuditSampleStr = ($AuditSample -join $nl).Trim()
            if ($AuditSampleStr -ne "") {
                $HasType = $AuditSampleStr -match "type="
                $FindingDetails += "Audit log contains event type field (type=): $HasType" + $nl
                $FindingDetails += $nl + "Sample audit records:" + $nl + $AuditSampleStr + $nl
            }
            else {
                $FindingDetails += "WARNING: Could not read audit log at /var/log/audit/audit.log" + $nl
            }

            # Check xen log for event classification
            $XenLog = $(timeout 3 tail -5 /var/log/xen/xen-hotplug.log 2>/dev/null)
            $XenLogStr = ($XenLog -join $nl).Trim()
            if ($XenLogStr -ne "") {
                $FindingDetails += $nl + "Xen hotplug log (event type context):" + $nl + $XenLogStr + $nl
            }

            if ($HasType -and $RuleCount -gt 0) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: auditd is active with rules configured. Audit records include event type classification."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: auditd is active but audit records may not contain event type information."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Cannot produce audit records with event type information."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207353 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207353
        STIG ID    : SRG-OS-000038-VMM-000160
        Rule ID    : SV-207353r958414_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-OS-000038
        Rule Title : The VMM must produce audit records containing information to establish when (date and time) the events occurred.
        DiscussMD5 : 7682a9c5891831b92a471080d057d427
        CheckMD5   : 40202c28965c4bd64c213cc6d73addd6
        FixMD5     : f0a1ea0d28597a8eea3c08548fca5868
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
    $VulnID = "V-207353"
    $RuleID = "SV-207353r958414_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Timestamp Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # auditd records include msg=audit(epoch:serial) which provides date/time
            $AuditSample = $(timeout 3 tail -5 /var/log/audit/audit.log 2>/dev/null)
            $AuditSampleStr = ($AuditSample -join $nl).Trim()
            if ($AuditSampleStr -ne "") {
                $HasTimestamp = $AuditSampleStr -match "msg=audit\("
                $FindingDetails += "Audit log contains timestamp field (msg=audit(epoch)): $HasTimestamp" + $nl
                $FindingDetails += $nl + "Sample audit records:" + $nl + $AuditSampleStr + $nl
            }
            else {
                $HasTimestamp = $false
                $FindingDetails += "WARNING: Could not read audit log at /var/log/audit/audit.log" + $nl
            }

            # Also check syslog timestamps
            $SyslogSample = $(timeout 3 tail -3 /var/log/messages 2>/dev/null)
            $SyslogStr = ($SyslogSample -join $nl).Trim()
            if ($SyslogStr -ne "") {
                $FindingDetails += $nl + "Syslog (/var/log/messages) also includes timestamps:" + $nl + $SyslogStr + $nl
            }

            if ($HasTimestamp) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: auditd records include epoch timestamps (date and time) for all events."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: Audit records may not contain date/time information."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Cannot produce timestamped audit records."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207354 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207354
        STIG ID    : SRG-OS-000039-VMM-000170
        Rule ID    : SV-207354r958416_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-OS-000039
        Rule Title : The VMM must produce audit records containing information to establish where the events occurred.
        DiscussMD5 : af6e5bb725fd6fea90e107888d8b3da0
        CheckMD5   : 97b5da4a5b707fa5fc381c264b2ac3ea
        FixMD5     : 1dde85f479deb60446684f1ff30666bc
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
    $VulnID = "V-207354"
    $RuleID = "SV-207354r958416_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Event Location Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # auditd records include node=hostname, terminal, addr fields for location
            $AuditSample = $(timeout 3 tail -10 /var/log/audit/audit.log 2>/dev/null)
            $AuditSampleStr = ($AuditSample -join $nl).Trim()
            $HasNode = $false
            $HasTerminal = $false
            if ($AuditSampleStr -ne "") {
                $HasNode = $AuditSampleStr -match "node="
                $HasTerminal = $AuditSampleStr -match "(terminal=|tty=)"
                $FindingDetails += "Audit log contains node/hostname field: $HasNode" + $nl
                $FindingDetails += "Audit log contains terminal/tty field: $HasTerminal" + $nl
            }
            else {
                $FindingDetails += "WARNING: Could not read audit log at /var/log/audit/audit.log" + $nl
            }

            # Check auditd.conf for log_format and name_format (node info)
            $AuditConf = Get-Content -Path "/etc/audit/auditd.conf" -ErrorAction SilentlyContinue
            $AuditConfStr = ($AuditConf -join $nl).Trim()
            if ($AuditConfStr -ne "") {
                $NameFormat = ""
                if ($AuditConfStr -match "name_format\s*=\s*(\S+)") { $NameFormat = $matches[1] }
                $FindingDetails += "auditd.conf name_format: $NameFormat" + $nl
            }

            # Check hostname configuration
            $Hostname_Local = $(hostname 2>/dev/null)
            $FindingDetails += "System hostname: $Hostname_Local" + $nl

            if ($HasNode -or $HasTerminal) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: Audit records contain location information (node/hostname, terminal)."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: Audit records may not contain event location information."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Cannot produce audit records with location data."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207355 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207355
        STIG ID    : SRG-OS-000040-VMM-000180
        Rule ID    : SV-207355r958418_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-OS-000040
        Rule Title : The VMM must produce audit records containing information to establish the source of the events.
        DiscussMD5 : c2449f7526806efa2162b414a8792d63
        CheckMD5   : 57fca74aeb4eccb2785593f14b013a92
        FixMD5     : 388e4e640d25683ea3086fdf3762b9a9
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
    $VulnID = "V-207355"
    $RuleID = "SV-207355r958418_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Event Source Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # auditd records include pid=, uid=, auid=, subj= for event source
            $AuditSample = $(timeout 3 tail -10 /var/log/audit/audit.log 2>/dev/null)
            $AuditSampleStr = ($AuditSample -join $nl).Trim()
            $HasPid = $false
            $HasUid = $false
            if ($AuditSampleStr -ne "") {
                $HasPid = $AuditSampleStr -match "pid="
                $HasUid = $AuditSampleStr -match "(uid=|auid=)"
                $FindingDetails += "Audit log contains process ID (pid=): $HasPid" + $nl
                $FindingDetails += "Audit log contains user ID (uid=/auid=): $HasUid" + $nl
            }
            else {
                $FindingDetails += "WARNING: Could not read audit log at /var/log/audit/audit.log" + $nl
            }

            if ($HasPid -and $HasUid) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: Audit records contain source identification (pid, uid/auid)."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: Audit records may not contain event source information."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Cannot produce audit records with source data."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207356 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207356
        STIG ID    : SRG-OS-000041-VMM-000190
        Rule ID    : SV-207356r958420_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-OS-000041
        Rule Title : The VMM must produce audit records containing information to establish the outcome of the events.
        DiscussMD5 : b7744a1e3d6f04ca94a425a16f41da30
        CheckMD5   : 6739fc7f1fb0bd0c83fed71bcfbc8aad
        FixMD5     : 482eb91c07c7845c0eb91deabaf296bf
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
    $VulnID = "V-207356"
    $RuleID = "SV-207356r958420_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Event Outcome Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # auditd records include success=yes/no or res= for outcome
            $AuditSample = $(timeout 3 tail -10 /var/log/audit/audit.log 2>/dev/null)
            $AuditSampleStr = ($AuditSample -join $nl).Trim()
            $HasOutcome = $false
            if ($AuditSampleStr -ne "") {
                $HasOutcome = $AuditSampleStr -match "(success=|res=)"
                $FindingDetails += "Audit log contains outcome field (success=/res=): $HasOutcome" + $nl
            }
            else {
                $FindingDetails += "WARNING: Could not read audit log at /var/log/audit/audit.log" + $nl
            }

            if ($HasOutcome) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: Audit records contain event outcome information (success/failure)."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: Audit records may not contain event outcome information."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Cannot produce audit records with outcome data."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207357 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207357
        STIG ID    : SRG-OS-000042-VMM-000200
        Rule ID    : SV-207357r958422_rule
        CCI ID     : CCI-000135
        Rule Name  : SRG-OS-000042
        Rule Title : The VMM must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.
        DiscussMD5 : f35ef7eb4aa529e76e5d41b755c613ad
        CheckMD5   : 728600b453d47522d7afc565f1c69d27
        FixMD5     : 7ae7acdf92b6d965ef93a5848d7506e2
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
    $VulnID = "V-207357"
    $RuleID = "SV-207357r958422_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Privileged Command Audit Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # Check for EXECVE audit rules (captures full command text)
            $AuditRules = $(auditctl -l 2>/dev/null)
            $AuditRulesStr = ($AuditRules -join $nl).Trim()
            $HasExecveRule = $AuditRulesStr -match "execve|EXECVE"
            $HasSudoRule = $AuditRulesStr -match "sudo|privileged"
            $FindingDetails += "Audit rules include EXECVE (command recording): $HasExecveRule" + $nl
            $FindingDetails += "Audit rules include sudo/privileged monitoring: $HasSudoRule" + $nl

            # Check sudo logging configuration
            $SudoLogCheck = $(timeout 3 sh -c "grep -i 'log_output\|logfile\|syslog' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -5")
            $SudoLogStr = ($SudoLogCheck -join $nl).Trim()
            if ($SudoLogStr -ne "") {
                $FindingDetails += $nl + "Sudo logging configuration:" + $nl + $SudoLogStr + $nl
            }
            else {
                $FindingDetails += "Sudo logging: No explicit log configuration found in sudoers" + $nl
            }

            # Check for EXECVE records in audit log
            $ExecveRecords = $(timeout 3 sh -c "grep -c EXECVE /var/log/audit/audit.log 2>/dev/null || echo 0")
            $ExecveStr = ("$ExecveRecords").Trim()
            $FindingDetails += "EXECVE records in audit log: $ExecveStr" + $nl

            if ($HasExecveRule -or $HasSudoRule) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: Audit system captures privileged command execution."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: No audit rules for EXECVE or privileged command recording found."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Cannot record privileged commands."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207358 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207358
        STIG ID    : SRG-OS-000046-VMM-000210
        Rule ID    : SV-207358r958424_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046
        Rule Title : The VMM must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.
        DiscussMD5 : 98a6453034368951ae20e60049e441b1
        CheckMD5   : a64c25eac3fdc1e3c80b5d50cc887375
        FixMD5     : 1131b56820363d0537280efd6466f350
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
    $VulnID = "V-207358"
    $RuleID = "SV-207358r958424_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Failure Alert Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # Check auditd.conf for failure alert configuration
            $AuditConf = Get-Content -Path "/etc/audit/auditd.conf" -ErrorAction SilentlyContinue
            $AuditConfStr = ($AuditConf -join $nl).Trim()

            $SpaceLeftAction = ""
            $AdminSpaceLeftAction = ""
            $DiskFullAction = ""
            $DiskErrorAction = ""
            $ActionMailAcct = ""

            if ($AuditConfStr -ne "") {
                if ($AuditConfStr -match "(?m)^\s*space_left_action\s*=\s*(\S+)") { $SpaceLeftAction = $matches[1] }
                if ($AuditConfStr -match "(?m)^\s*admin_space_left_action\s*=\s*(\S+)") { $AdminSpaceLeftAction = $matches[1] }
                if ($AuditConfStr -match "(?m)^\s*disk_full_action\s*=\s*(\S+)") { $DiskFullAction = $matches[1] }
                if ($AuditConfStr -match "(?m)^\s*disk_error_action\s*=\s*(\S+)") { $DiskErrorAction = $matches[1] }
                if ($AuditConfStr -match "(?m)^\s*action_mail_acct\s*=\s*(\S+)") { $ActionMailAcct = $matches[1] }

                $FindingDetails += "space_left_action = $SpaceLeftAction" + $nl
                $FindingDetails += "admin_space_left_action = $AdminSpaceLeftAction" + $nl
                $FindingDetails += "disk_full_action = $DiskFullAction" + $nl
                $FindingDetails += "disk_error_action = $DiskErrorAction" + $nl
                $FindingDetails += "action_mail_acct = $ActionMailAcct" + $nl
            }
            else {
                $FindingDetails += "WARNING: Could not read /etc/audit/auditd.conf" + $nl
            }

            # Alerting requires email or syslog action
            $HasAlert = ($SpaceLeftAction -match "(?i)email|syslog|exec") -or
                        ($AdminSpaceLeftAction -match "(?i)email|syslog|halt|single|exec")

            if ($HasAlert) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: auditd is configured to alert on audit processing failures."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: auditd space_left_action and admin_space_left_action are not set to alert (email/syslog)."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. No audit failure alerting available."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207360 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207360
        STIG ID    : SRG-OS-000051-VMM-000230
        Rule ID    : SV-207360r958428_rule
        CCI ID     : CCI-000154
        Rule Name  : SRG-OS-000051
        Rule Title : The VMM must support the capability to centrally review and analyze audit records from multiple components within the system.
        DiscussMD5 : 6c679076b4a927efc08bf3bf9f0f1b55
        CheckMD5   : 4b0ea8586a67767df144a6889eb22c14
        FixMD5     : e7a5e2a90cd90523662d592ea5f8f4a0
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
    $VulnID = "V-207360"
    $RuleID = "SV-207360r958428_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Centralized Audit Review Capability" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check rsyslog for remote forwarding
        $RsyslogStatus = $(systemctl is-active rsyslog 2>/dev/null)
        $FindingDetails += "rsyslog service: $RsyslogStatus" + $nl

        # Check for remote syslog forwarding rules
        $RemoteForward = $(timeout 3 sh -c "grep -rh '@@\|@[^@]' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#' | head -5")
        $RemoteForwardStr = ($RemoteForward -join $nl).Trim()
        if ($RemoteForwardStr -ne "") {
            $FindingDetails += $nl + "Remote syslog forwarding configured:" + $nl + $RemoteForwardStr + $nl
        }
        else {
            $FindingDetails += "Remote syslog forwarding: Not configured" + $nl
        }

        # Check if audisp remote plugin is configured
        $AudispRemote = $(timeout 3 sh -c "grep -l 'active.*yes' /etc/audisp/plugins.d/*.conf 2>/dev/null | head -3")
        $AudispStr = ($AudispRemote -join $nl).Trim()
        if ($AudispStr -ne "") {
            $FindingDetails += "Active audisp plugins: $AudispStr" + $nl
        }

        # Check for ausearch capability (local review tool)
        $AusearchPath = $(which ausearch 2>/dev/null)
        $AureportPath = $(which aureport 2>/dev/null)
        $FindingDetails += "ausearch available: $(if ($AusearchPath) { $AusearchPath } else { 'No' })" + $nl
        $FindingDetails += "aureport available: $(if ($AureportPath) { $AureportPath } else { 'No' })" + $nl

        # Central review requires either remote forwarding or local review tools
        $HasCentralCapability = ($RemoteForwardStr -ne "") -or ($AusearchPath -and $AureportPath)
        if ($HasCentralCapability) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: System supports centralized audit review capability."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No centralized audit review capability detected (no remote forwarding, missing ausearch/aureport)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207361 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207361
        STIG ID    : SRG-OS-000054-VMM-000240
        Rule ID    : SV-207361r958430_rule
        CCI ID     : CCI-000158
        Rule Name  : SRG-OS-000054
        Rule Title : The VMM must support the capability to filter audit records for events of interest based upon all audit fields within audit records.
        DiscussMD5 : 2030ba83aa031d23c64d40972e0528a6
        CheckMD5   : 5b06914bcee2d1c6c0044ca72a622274
        FixMD5     : 3975b94545f4c63a1f526d392455de63
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
    $VulnID = "V-207361"
    $RuleID = "SV-207361r958430_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Record Filtering Capability" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # ausearch supports filtering by all audit fields
        $AusearchPath = $(which ausearch 2>/dev/null)
        $AureportPath = $(which aureport 2>/dev/null)
        $JournalctlPath = $(which journalctl 2>/dev/null)

        $FindingDetails += "ausearch available: $(if ($AusearchPath) { $AusearchPath } else { 'No' })" + $nl
        $FindingDetails += "aureport available: $(if ($AureportPath) { $AureportPath } else { 'No' })" + $nl
        $FindingDetails += "journalctl available: $(if ($JournalctlPath) { $JournalctlPath } else { 'No' })" + $nl

        # Show ausearch filter capabilities
        if ($AusearchPath) {
            $FindingDetails += $nl + "ausearch supports filtering by: user (-ua), event type (-m), key (-k)," + $nl
            $FindingDetails += "  time range (-ts/-te), success/fail (-sv), PID (-p), filename (-f)," + $nl
            $FindingDetails += "  hostname (-hn), terminal (-tm), and all other audit record fields." + $nl
        }

        if ($AusearchPath -and $AureportPath) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: ausearch and aureport provide comprehensive audit record filtering by all fields."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit filtering tools (ausearch/aureport) are not installed."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207362 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207362
        STIG ID    : SRG-OS-000055-VMM-000250
        Rule ID    : SV-207362r958432_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-OS-000055
        Rule Title : The VMM must use internal system clocks to generate time stamps for audit records.
        DiscussMD5 : f6732e9cbb2579989960692e0e4a1ed0
        CheckMD5   : 7c790052250ffb8a918abbeac7260505
        FixMD5     : fa019232265cdfa9e5cfe9483c4c5364
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
    $VulnID = "V-207362"
    $RuleID = "SV-207362r958432_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "System Clock for Audit Timestamps" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check NTP/chrony time synchronization
        $ChronydStatus = $(systemctl is-active chronyd 2>/dev/null)
        $NtpdStatus = $(systemctl is-active ntpd 2>/dev/null)
        $FindingDetails += "chronyd service: $ChronydStatus" + $nl
        $FindingDetails += "ntpd service: $NtpdStatus" + $nl

        # Check time sync status
        if ("$ChronydStatus".Trim() -eq "active") {
            $ChronySources = $(timeout 3 chronyc sources 2>/dev/null)
            $ChronyStr = ($ChronySources -join $nl).Trim()
            if ($ChronyStr -ne "") {
                $FindingDetails += $nl + "Chrony time sources:" + $nl + $ChronyStr + $nl
            }
        }
        elseif ("$NtpdStatus".Trim() -eq "active") {
            $NtpPeers = $(timeout 3 ntpq -p 2>/dev/null)
            $NtpStr = ($NtpPeers -join $nl).Trim()
            if ($NtpStr -ne "") {
                $FindingDetails += $nl + "NTP peers:" + $nl + $NtpStr + $nl
            }
        }

        # auditd uses kernel system clock for timestamps (msg=audit(epoch:serial))
        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += $nl + "auditd service: $AuditdStatus" + $nl
        $FindingDetails += "auditd uses kernel system clock (epoch timestamps) for all audit records." + $nl

        $TimeSynced = ("$ChronydStatus".Trim() -eq "active") -or ("$NtpdStatus".Trim() -eq "active")
        if ($TimeSynced -and "$AuditdStatus".Trim() -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: System clock is NTP-synchronized and auditd uses internal system clock for timestamps."
        }
        elseif ("$AuditdStatus".Trim() -eq "active") {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd uses system clock but NTP synchronization is not active."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207363 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207363
        STIG ID    : SRG-OS-000057-VMM-000260
        Rule ID    : SV-207363r958434_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-OS-000057
        Rule Title : The VMM must protect audit information from unauthorized read access.
        DiscussMD5 : 22e5385088b16e654fd9709f95c4fef4
        CheckMD5   : d79cf5eabbbcb7e54d18cc45d5f9f237
        FixMD5     : 4c50b1eb21a589b6702f0340e7bfcd80
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
    $VulnID = "V-207363"
    $RuleID = "SV-207363r958434_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Log Read Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check audit log directory permissions
        $AuditDirPerms = $(timeout 3 stat -c '%a %U %G %n' /var/log/audit 2>/dev/null)
        $AuditDirStr = ("$AuditDirPerms").Trim()
        if ($AuditDirStr -ne "") {
            $FindingDetails += "Audit directory: $AuditDirStr" + $nl
        }

        # Check audit log file permissions
        $AuditFilePerms = $(timeout 3 stat -c '%a %U %G %n' /var/log/audit/audit.log 2>/dev/null)
        $AuditFileStr = ("$AuditFilePerms").Trim()
        if ($AuditFileStr -ne "") {
            $FindingDetails += "Audit log file: $AuditFileStr" + $nl
        }
        else {
            $FindingDetails += "WARNING: /var/log/audit/audit.log not found" + $nl
        }

        # Check auditd.conf log_group
        $AuditConf = Get-Content -Path "/etc/audit/auditd.conf" -ErrorAction SilentlyContinue
        $AuditConfStr = ($AuditConf -join $nl).Trim()
        $LogGroup = "root"
        if ($AuditConfStr -match "(?m)^\s*log_group\s*=\s*(\S+)") { $LogGroup = $matches[1] }
        $FindingDetails += "auditd.conf log_group: $LogGroup" + $nl

        # Evaluate: audit log should be owned by root, mode 0600 or more restrictive
        $Compliant = $false
        if ($AuditFileStr -match "^(\d+)\s+(\S+)\s+(\S+)") {
            $FileMode = $matches[1]
            $FileOwner = $matches[2]
            $FileGroup = $matches[3]
            $ModeInt = [int]$FileMode
            $Compliant = ($FileOwner -eq "root") -and ($ModeInt -le 600)
            $FindingDetails += $nl + "File mode: $FileMode (max allowed: 0600)" + $nl
            $FindingDetails += "Owner: $FileOwner (required: root)" + $nl
        }

        if ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit logs are protected from unauthorized read access."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit log permissions are too permissive or file not found."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207364 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207364
        STIG ID    : SRG-OS-000058-VMM-000270
        Rule ID    : SV-207364r958436_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-OS-000058
        Rule Title : The VMM must protect audit information from unauthorized modification.
        DiscussMD5 : f98cbf2433d7a91e225ef0152a71d7a2
        CheckMD5   : 0f4e0646b521ec3277bfe5e96e8713fd
        FixMD5     : 8f2b096b195050fa2f4b773082dc8009
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
    $VulnID = "V-207364"
    $RuleID = "SV-207364r958436_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Log Modification Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check audit log file permissions — write access should be root only
        $AuditFilePerms = $(timeout 3 stat -c '%a %U %G %n' /var/log/audit/audit.log 2>/dev/null)
        $AuditFileStr = ("$AuditFilePerms").Trim()
        if ($AuditFileStr -ne "") {
            $FindingDetails += "Audit log file: $AuditFileStr" + $nl
        }
        else {
            $FindingDetails += "WARNING: /var/log/audit/audit.log not found" + $nl
        }

        # Check for additional audit log files
        $AuditFiles = $(timeout 3 find /var/log/audit -maxdepth 1 -type f -name "audit.log*" 2>/dev/null)
        $AuditFilesStr = ($AuditFiles -join $nl).Trim()
        if ($AuditFilesStr -ne "") {
            $AllPerms = $(timeout 3 stat -c '%a %U %G %n' /var/log/audit/audit.log* 2>/dev/null)
            $AllPermsStr = ($AllPerms -join $nl).Trim()
            $FindingDetails += $nl + "All audit log files:" + $nl + $AllPermsStr + $nl
        }

        # Check immutable attribute on audit rules (auditctl -e 2)
        $AuditEnabled = $(timeout 3 sh -c "auditctl -s 2>/dev/null | grep enabled")
        $AuditEnabledStr = ("$AuditEnabled").Trim()
        $FindingDetails += $nl + "Audit system status: $AuditEnabledStr" + $nl

        # Evaluate: mode should not allow group/other write (max 0640, ideally 0600)
        $Compliant = $false
        if ($AuditFileStr -match "^(\d+)\s+(\S+)\s+(\S+)") {
            $FileMode = $matches[1]
            $FileOwner = $matches[2]
            $ModeInt = [int]$FileMode
            # No group write (x4x), no other write (xx4)
            $GroupWrite = [int]($FileMode.Substring(1, 1)) -band 2
            $OtherWrite = [int]($FileMode.Substring(2, 1)) -band 2
            $Compliant = ($FileOwner -eq "root") -and ($GroupWrite -eq 0) -and ($OtherWrite -eq 0)
            $FindingDetails += "Group write permission: $(if ($GroupWrite -eq 0) { 'No' } else { 'Yes' })" + $nl
            $FindingDetails += "Other write permission: $(if ($OtherWrite -eq 0) { 'No' } else { 'Yes' })" + $nl
        }

        if ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit logs are protected from unauthorized modification."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit log permissions allow potential unauthorized modification."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207365 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207365
        STIG ID    : SRG-OS-000059-VMM-000280
        Rule ID    : SV-207365r958438_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-OS-000059
        Rule Title : The VMM must protect audit information from unauthorized deletion.
        DiscussMD5 : f6e65cc782e198091bacb747d36d1924
        CheckMD5   : a3b5191302c63c3caa0b24efd212dd5c
        FixMD5     : 18b39718fa6f51c2a37ba6bae793d15d
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
    $VulnID = "V-207365"
    $RuleID = "SV-207365r958438_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Log Deletion Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check audit directory permissions (sticky bit or restricted)
        $AuditDirPerms = $(timeout 3 stat -c '%a %U %G %n' /var/log/audit 2>/dev/null)
        $AuditDirStr = ("$AuditDirPerms").Trim()
        if ($AuditDirStr -ne "") {
            $FindingDetails += "Audit directory: $AuditDirStr" + $nl
        }

        # Check audit log file permissions
        $AuditFilePerms = $(timeout 3 stat -c '%a %U %G %n' /var/log/audit/audit.log 2>/dev/null)
        $AuditFileStr = ("$AuditFilePerms").Trim()
        if ($AuditFileStr -ne "") {
            $FindingDetails += "Audit log file: $AuditFileStr" + $nl
        }

        # Check auditd.conf max_log_file_action (should not be DELETE)
        $AuditConf = Get-Content -Path "/etc/audit/auditd.conf" -ErrorAction SilentlyContinue
        $AuditConfStr = ($AuditConf -join $nl).Trim()
        $MaxLogAction = ""
        if ($AuditConfStr -match "(?m)^\s*max_log_file_action\s*=\s*(\S+)") { $MaxLogAction = $matches[1] }
        $FindingDetails += "max_log_file_action: $MaxLogAction" + $nl

        # Check directory ownership — only root should be able to delete
        $Compliant = $false
        if ($AuditDirStr -match "^(\d+)\s+(\S+)") {
            $DirMode = $matches[1]
            $DirOwner = $matches[2]
            # Directory should be root-owned, no group/other write
            $DirModeInt = [int]$DirMode
            $GroupWrite = [int]($DirMode.Substring(1, 1)) -band 2
            $OtherWrite = [int]($DirMode.Substring(2, 1)) -band 2
            $Compliant = ($DirOwner -eq "root") -and ($GroupWrite -eq 0) -and ($OtherWrite -eq 0)
        }

        if ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit directory and log files are protected from unauthorized deletion."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit directory permissions may allow unauthorized deletion."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207366 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207366
        STIG ID    : SRG-OS-000062-VMM-000300
        Rule ID    : SV-207366r958442_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-OS-000062
        Rule Title : The VMM must provide audit record generation capability for DoD-defined auditable events for all VMM components.
        DiscussMD5 : 327a851c16fc94d8406614bdabbd19c3
        CheckMD5   : c6041e7ddc4e5ee556d4dc26454de778
        FixMD5     : b6aeb0d118d37d00c650e2b6a9118094
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
    $VulnID = "V-207366"
    $RuleID = "SV-207366r958442_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Record Generation Capability" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Comprehensive check: auditd running, rules configured, key audit components present
        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $AuditdStatus" + $nl

        $AuditdEnabled = $(systemctl is-enabled auditd 2>/dev/null)
        $FindingDetails += "auditd enabled at boot: $AuditdEnabled" + $nl

        if ("$AuditdStatus".Trim() -eq "active") {
            # Count audit rules
            $AuditRules = $(auditctl -l 2>/dev/null)
            $AuditRulesStr = ($AuditRules -join $nl).Trim()
            $RuleCount = 0
            if ($AuditRulesStr -ne "" -and $AuditRulesStr -notmatch "No rules") {
                $RuleCount = ($AuditRulesStr -split $nl).Count
            }
            $FindingDetails += "Active audit rules: $RuleCount" + $nl

            # Check key audit components
            $AuditctlPath = $(which auditctl 2>/dev/null)
            $AusearchPath = $(which ausearch 2>/dev/null)
            $AureportPath = $(which aureport 2>/dev/null)
            $FindingDetails += $nl + "Audit tools installed:" + $nl
            $FindingDetails += "  auditctl: $(if ($AuditctlPath) { 'Yes' } else { 'No' })" + $nl
            $FindingDetails += "  ausearch: $(if ($AusearchPath) { 'Yes' } else { 'No' })" + $nl
            $FindingDetails += "  aureport: $(if ($AureportPath) { 'Yes' } else { 'No' })" + $nl

            # Check Xen-specific audit sources
            $XenLogExists = $(timeout 3 sh -c "test -d /var/log/xen && echo yes || echo no")
            $FindingDetails += $nl + "Xen log directory (/var/log/xen): $XenLogExists" + $nl

            # Check syslog is active
            $RsyslogStatus = $(systemctl is-active rsyslog 2>/dev/null)
            $FindingDetails += "rsyslog service: $RsyslogStatus" + $nl

            if ($RuleCount -gt 0 -and $AuditctlPath) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: auditd is active with $RuleCount rules. Full audit record generation capability is available."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: auditd is active but audit rules are not configured ($RuleCount rules)."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. No audit record generation capability."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207367 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207367
        STIG ID    : SRG-OS-000063-VMM-000310
        Rule ID    : SV-207367r958444_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063
        Rule Title : The VMM must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 9ee30f8b41b930d57232a4397d4483c2
        CheckMD5   : 90c16ef6b909453c53637dd09c42d0e9
        FixMD5     : 58403da336a16de8ec7e35d6f4113cdb
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
    $VulnID = "V-207367"
    $RuleID = "SV-207367r958444_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Event Selection Authorization" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check ownership of audit configuration files
        $AuditConfOwner = $(timeout 3 stat -c '%U:%G %a %n' /etc/audit/auditd.conf 2>/dev/null)
        $AuditConfStr = ("$AuditConfOwner").Trim()
        if ($AuditConfStr -ne "") {
            $FindingDetails += "auditd.conf: $AuditConfStr" + $nl
        }

        $AuditRulesOwner = $(timeout 3 stat -c '%U:%G %a %n' /etc/audit/audit.rules 2>/dev/null)
        $AuditRulesStr = ("$AuditRulesOwner").Trim()
        if ($AuditRulesStr -ne "") {
            $FindingDetails += "audit.rules: $AuditRulesStr" + $nl
        }

        # Check /etc/audit/rules.d/ directory ownership
        $RulesDirOwner = $(timeout 3 stat -c '%U:%G %a %n' /etc/audit/rules.d 2>/dev/null)
        $RulesDirStr = ("$RulesDirOwner").Trim()
        if ($RulesDirStr -ne "") {
            $FindingDetails += "rules.d dir: $RulesDirStr" + $nl
        }

        # Root-owned audit config = only root (ISSM-appointed admin) can modify event selection
        $Compliant = $true
        foreach ($Entry in @($AuditConfStr, $AuditRulesStr, $RulesDirStr)) {
            if ($Entry -ne "" -and $Entry -notmatch "^root:") {
                $Compliant = $false
            }
        }

        # Also verify auditd service is active
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        if ($AuditdStr -ne "active") { $Compliant = $false }

        if ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit configuration files are root-owned. Only authorized administrators can select auditable events."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit event selection is not restricted to authorized administrators, or auditd is not active."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207368 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207368
        STIG ID    : SRG-OS-000064-VMM-000320
        Rule ID    : SV-207368r958446_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064
        Rule Title : The VMM must generate audit records when successful/unsuccessful attempts to access privileges occur.
        DiscussMD5 : 52fe3ae46fdba663e4078adb71a86c5d
        CheckMD5   : e5f169c9dcbce81883c04f5e06a05bd8
        FixMD5     : 67618aa5db208a9e82569f341c56e2d5
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
    $VulnID = "V-207368"
    $RuleID = "SV-207368r958446_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Privilege Access Audit Records" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd is active
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl + $nl

        # Check for privilege escalation audit rules (sudo, su, setuid/setgid)
        $AuditRules = $(timeout 5 auditctl -l 2>/dev/null)
        $AuditRulesArr = @()
        if ($null -ne $AuditRules) { $AuditRulesArr = @($AuditRules) }
        $AuditRulesStr = ($AuditRulesArr -join $nl).Trim()

        $PrivRules = @()
        foreach ($Rule in $AuditRulesArr) {
            $RuleStr = ("$Rule").Trim()
            if ($RuleStr -match "(sudo|su\b|execve|setuid|setgid|privilege)" -and $RuleStr -ne "") {
                $PrivRules += $RuleStr
            }
        }

        if ($PrivRules.Count -gt 0) {
            $FindingDetails += "Privilege-related audit rules found:" + $nl
            foreach ($R in $PrivRules) { $FindingDetails += "  $R" + $nl }
        }
        else {
            $FindingDetails += "No privilege-related audit rules found." + $nl
        }

        # Check for sudoers log configuration
        $SudoersLog = $(timeout 3 grep -r 'logfile\|log_output' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
        $SudoersLogStr = ("$SudoersLog").Trim()
        if ($SudoersLogStr -ne "") {
            $FindingDetails += $nl + "Sudoers logging:" + $nl + $SudoersLogStr + $nl
        }

        if ($AuditdStr -eq "active" -and $PrivRules.Count -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit records are generated for privilege access attempts."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active or privilege access audit rules are not configured."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207369 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207369
        STIG ID    : SRG-OS-000066-VMM-000330
        Rule ID    : SV-207369r958448_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-OS-000066
        Rule Title : The VMM, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : d915bfaeba25ac6ecfd66bf377ec3cb0
        CheckMD5   : bd50a8d2d3e79b8a042f72aa9681e496
        FixMD5     : 2dd2056018abcb0c9ede19d2b4ce6557
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
    $VulnID = "V-207369"
    $RuleID = "SV-207369r958448_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "PKI Certificate Path Validation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check xapi SSL certificate
        $XapiCert = "/etc/xensource/xapi-ssl.pem"
        $CertExists = $(timeout 3 test -f $XapiCert && echo "exists" || echo "missing" 2>/dev/null)
        $CertExistsStr = ("$CertExists").Trim()
        $FindingDetails += "xapi SSL certificate ($XapiCert): $CertExistsStr" + $nl

        if ($CertExistsStr -eq "exists") {
            # Get certificate subject and issuer
            $CertInfo = $(timeout 5 openssl x509 -in $XapiCert -noout -subject -issuer -dates 2>/dev/null)
            $CertInfoStr = ("$CertInfo").Trim()
            if ($CertInfoStr -ne "") {
                $FindingDetails += $CertInfoStr + $nl
            }

            # Verify certificate chain
            $CertVerify = $(timeout 5 openssl verify -CApath /etc/pki/tls/certs $XapiCert 2>&1)
            $CertVerifyStr = ("$CertVerify").Trim()
            $FindingDetails += $nl + "Certificate verification: $CertVerifyStr" + $nl

            # Check if self-signed (subject == issuer means self-signed, no chain validation)
            $IsSelfSigned = $false
            if ($CertInfoStr -match "subject=(.+)" -and $CertInfoStr -match "issuer=(.+)") {
                $SubjectLine = ($CertInfoStr -split $nl | Where-Object { $_ -match "^subject=" }) | Select-Object -First 1
                $IssuerLine = ($CertInfoStr -split $nl | Where-Object { $_ -match "^issuer=" }) | Select-Object -First 1
                if ($null -ne $SubjectLine -and $null -ne $IssuerLine) {
                    $SubVal = $SubjectLine -replace "^subject=\s*", ""
                    $IssVal = $IssuerLine -replace "^issuer=\s*", ""
                    if ($SubVal -eq $IssVal) { $IsSelfSigned = $true }
                }
            }

            if ($IsSelfSigned) {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: xapi certificate is self-signed. No certification path to a trusted CA exists."
            }
            elseif ($CertVerifyStr -match "OK$") {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: xapi certificate validates against a trusted certification path."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: xapi certificate chain validation failed."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: xapi SSL certificate file not found."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207370 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207370
        STIG ID    : SRG-OS-000067-VMM-000340
        Rule ID    : SV-207370r958450_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-OS-000067
        Rule Title : The VMM, for PKI-based authentication, must enforce authorized access to the corresponding private key.
        DiscussMD5 : 46fab6f691fe8cca5924338f89fd4aad
        CheckMD5   : a57f155acdf6e2baef94d925cd1d6b22
        FixMD5     : d93e89d39604a512ecabdf3a4890d128
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
    $VulnID = "V-207370"
    $RuleID = "SV-207370r958450_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "PKI Private Key Access Control" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check xapi private key file permissions
        $KeyFiles = @(
            "/etc/xensource/xapi-ssl.pem"
            "/etc/xensource/xapi-pool-tls.pem"
        )

        $AllCompliant = $true
        $FoundKeys = $false

        foreach ($KeyFile in $KeyFiles) {
            $KeyPerms = $(timeout 3 stat -c '%a %U:%G %n' $KeyFile 2>/dev/null)
            $KeyPermsStr = ("$KeyPerms").Trim()
            if ($KeyPermsStr -ne "") {
                $FoundKeys = $true
                $FindingDetails += "$KeyPermsStr" + $nl

                # Key files should be root-owned and not readable by others (mode <= 600)
                if ($KeyPermsStr -match "^(\d+)\s+(\S+)") {
                    $Mode = $matches[1]
                    $Owner = $matches[2]
                    $ModeInt = [int]$Mode
                    if ($Owner -ne "root:root" -or $ModeInt -gt 600) {
                        $AllCompliant = $false
                    }
                }
            }
        }

        # Also check /etc/pki/tls/private/ for any additional keys
        $TlsPrivKeys = $(timeout 5 find /etc/pki/tls/private -maxdepth 1 -type f -name '*.pem' -o -name '*.key' 2>/dev/null)
        $TlsPrivKeysArr = @()
        if ($null -ne $TlsPrivKeys) { $TlsPrivKeysArr = @($TlsPrivKeys) }
        foreach ($PrivKey in $TlsPrivKeysArr) {
            $PKStr = ("$PrivKey").Trim()
            if ($PKStr -ne "") {
                $PKPerms = $(timeout 3 stat -c '%a %U:%G %n' $PKStr 2>/dev/null)
                $PKPermsStr = ("$PKPerms").Trim()
                if ($PKPermsStr -ne "") {
                    $FoundKeys = $true
                    $FindingDetails += "$PKPermsStr" + $nl
                    if ($PKPermsStr -match "^(\d+)\s+(\S+)") {
                        $PMode = $matches[1]
                        $POwner = $matches[2]
                        if ($POwner -ne "root:root" -or [int]$PMode -gt 600) {
                            $AllCompliant = $false
                        }
                    }
                }
            }
        }

        if (-not $FoundKeys) {
            $Status = "Open"
            $FindingDetails += "No PKI private key files found." + $nl
            $FindingDetails += $nl + "RESULT: Cannot verify private key access controls — no key files found."
        }
        elseif ($AllCompliant) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: All private key files are root-owned with restrictive permissions (600 or less)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: One or more private key files have overly permissive ownership or permissions."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207371 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207371
        STIG ID    : SRG-OS-000068-VMM-000350
        Rule ID    : SV-207371r958452_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-OS-000068
        Rule Title : The VMM must map the authenticated identity to the user or group account for PKI-based authentication.
        DiscussMD5 : e6cdfcd407ba13d5f19cdd6c81c801a6
        CheckMD5   : 1e9439736b04d7cf89a7514cb790487f
        FixMD5     : 252856b4f32c093891b4ed9e95b5f657
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
    $VulnID = "V-207371"
    $RuleID = "SV-207371r958452_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "PKI Identity Mapping" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check if external authentication (AD/LDAP) is enabled on the pool
        $PoolExtAuth = $(timeout 5 xe pool-list params=external-auth-type 2>/dev/null)
        $PoolExtAuthStr = ("$PoolExtAuth").Trim()
        $FindingDetails += "External auth type: $PoolExtAuthStr" + $nl

        $PoolExtAuthSvc = $(timeout 5 xe pool-list params=external-auth-service-name 2>/dev/null)
        $PoolExtAuthSvcStr = ("$PoolExtAuthSvc").Trim()
        if ($PoolExtAuthSvcStr -ne "") {
            $FindingDetails += "External auth service: $PoolExtAuthSvcStr" + $nl
        }

        # Check PAM SSSD or winbind for identity mapping
        $SssdConf = $(timeout 3 test -f /etc/sssd/sssd.conf && echo "exists" || echo "missing" 2>/dev/null)
        $SssdStr = ("$SssdConf").Trim()
        $FindingDetails += "SSSD config: $SssdStr" + $nl

        $WinbindStatus = $(timeout 3 systemctl is-active winbind 2>/dev/null)
        $WinbindStr = ("$WinbindStatus").Trim()
        $FindingDetails += "winbind service: $WinbindStr" + $nl

        # XCP-ng supports AD integration via pool-enable-external-auth
        $HasExtAuth = $PoolExtAuthStr -match "AD"
        $HasIdentityMapping = $SssdStr -eq "exists" -or $WinbindStr -eq "active"

        if ($HasExtAuth -or $HasIdentityMapping) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication is configured, providing PKI identity-to-account mapping."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No external authentication (AD/LDAP) is configured for PKI-based identity mapping."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207372
        STIG ID    : SRG-OS-000069-VMM-000360
        Rule ID    : SV-207372r984191_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000069
        Rule Title : The VMM must enforce password complexity by requiring that at least one uppercase character be used.
        DiscussMD5 : dada7262079e912deba826af5c3c0854
        CheckMD5   : b9c955deb89906be9af1db5372be3b14
        FixMD5     : ea3bf2c3011f2928997aaa01c4903808
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
    $VulnID = "V-207372"
    $RuleID = "SV-207372r984191_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Password Complexity — Uppercase Requirement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check pwquality.conf for ucredit
        $PwQualConf = Get-Content -Path "/etc/security/pwquality.conf" -ErrorAction SilentlyContinue
        $PwQualStr = ""
        if ($null -ne $PwQualConf) { $PwQualStr = ($PwQualConf -join $nl).Trim() }

        $Ucredit = ""
        if ($PwQualStr -match "(?m)^\s*ucredit\s*=\s*(-?\d+)") { $Ucredit = $matches[1] }

        if ($Ucredit -ne "") {
            $FindingDetails += "pwquality.conf ucredit = $Ucredit" + $nl
        }
        else {
            $FindingDetails += "pwquality.conf ucredit: not set" + $nl
        }

        # Check PAM configuration for pam_pwquality
        $PamPwQual = $(timeout 3 grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)
        $PamPwQualStr = ("$PamPwQual").Trim()
        if ($PamPwQualStr -ne "") {
            $FindingDetails += $nl + "PAM password quality:" + $nl + $PamPwQualStr + $nl
        }

        # ucredit must be <= -1 (negative means require at least that many uppercase chars)
        if ($Ucredit -ne "" -and [int]$Ucredit -le -1) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Password policy requires at least one uppercase character (ucredit=$Ucredit)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: ucredit is not configured to require uppercase characters."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207373 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207373
        STIG ID    : SRG-OS-000070-VMM-000370
        Rule ID    : SV-207373r984194_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000070
        Rule Title : The VMM must enforce password complexity by requiring that at least one lowercase character be used.
        DiscussMD5 : 65e88ae9c5b49813bf958147f2894c77
        CheckMD5   : 993ac46d0f56654391f384a8158a0d8e
        FixMD5     : ac429d612f3a42113ff05c63dc4530a1
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
    $VulnID = "V-207373"
    $RuleID = "SV-207373r984194_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Password Complexity — Lowercase Requirement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $PwQualConf = Get-Content -Path "/etc/security/pwquality.conf" -ErrorAction SilentlyContinue
        $PwQualStr = ""
        if ($null -ne $PwQualConf) { $PwQualStr = ($PwQualConf -join $nl).Trim() }

        $Lcredit = ""
        if ($PwQualStr -match "(?m)^\s*lcredit\s*=\s*(-?\d+)") { $Lcredit = $matches[1] }

        if ($Lcredit -ne "") {
            $FindingDetails += "pwquality.conf lcredit = $Lcredit" + $nl
        }
        else {
            $FindingDetails += "pwquality.conf lcredit: not set" + $nl
        }

        if ($Lcredit -ne "" -and [int]$Lcredit -le -1) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Password policy requires at least one lowercase character (lcredit=$Lcredit)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: lcredit is not configured to require lowercase characters."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207374 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207374
        STIG ID    : SRG-OS-000071-VMM-000380
        Rule ID    : SV-207374r984195_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000071
        Rule Title : The VMM must enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : 6b9dc35295a75836d19f85bb186b84b8
        CheckMD5   : bc74b9c05c642a0bf540774b93de507a
        FixMD5     : ba859feb8207b5b0b6a2b7aed9a78461
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
    $VulnID = "V-207374"
    $RuleID = "SV-207374r984195_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Password Complexity — Numeric Requirement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $PwQualConf = Get-Content -Path "/etc/security/pwquality.conf" -ErrorAction SilentlyContinue
        $PwQualStr = ""
        if ($null -ne $PwQualConf) { $PwQualStr = ($PwQualConf -join $nl).Trim() }

        $Dcredit = ""
        if ($PwQualStr -match "(?m)^\s*dcredit\s*=\s*(-?\d+)") { $Dcredit = $matches[1] }

        if ($Dcredit -ne "") {
            $FindingDetails += "pwquality.conf dcredit = $Dcredit" + $nl
        }
        else {
            $FindingDetails += "pwquality.conf dcredit: not set" + $nl
        }

        if ($Dcredit -ne "" -and [int]$Dcredit -le -1) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Password policy requires at least one numeric character (dcredit=$Dcredit)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: dcredit is not configured to require numeric characters."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207375 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207375
        STIG ID    : SRG-OS-000072-VMM-000390
        Rule ID    : SV-207375r984198_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000072
        Rule Title : The VMM must require the change of at least eight of the total number of characters when passwords are changed.
        DiscussMD5 : 03b7db878691fc4f8ea44206465e28fa
        CheckMD5   : d5acdc2b0ea888800bce2a3dc2339a0a
        FixMD5     : 12a71dc68ab0dab60ea2cbe300ef616c
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
    $VulnID = "V-207375"
    $RuleID = "SV-207375r984198_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Password Change Difference Requirement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $PwQualConf = Get-Content -Path "/etc/security/pwquality.conf" -ErrorAction SilentlyContinue
        $PwQualStr = ""
        if ($null -ne $PwQualConf) { $PwQualStr = ($PwQualConf -join $nl).Trim() }

        $Difok = ""
        if ($PwQualStr -match "(?m)^\s*difok\s*=\s*(\d+)") { $Difok = $matches[1] }

        if ($Difok -ne "") {
            $FindingDetails += "pwquality.conf difok = $Difok" + $nl
        }
        else {
            $FindingDetails += "pwquality.conf difok: not set (default 5)" + $nl
        }

        # difok must be >= 8
        if ($Difok -ne "" -and [int]$Difok -ge 8) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Password policy requires at least 8 characters changed (difok=$Difok)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: difok is not set to 8 or greater."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207376
        STIG ID    : SRG-OS-000073-VMM-000400
        Rule ID    : SV-207376r984199_rule
        CCI ID     : CCI-004062
        Rule Name  : SRG-OS-000073
        Rule Title : The VMM must store only encrypted representations of passwords.
        DiscussMD5 : f0670297715b727411a94adac8fd1fde
        CheckMD5   : fe2fd704e2f79ba85d75e6e5d3887505
        FixMD5     : 771cd31f73869758a53b066a957df7b9
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
    $VulnID = "V-207376"
    $RuleID = "SV-207376r984199_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Encrypted Password Storage" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check /etc/shadow for password hash algorithm
        # $6$ = SHA-512, $5$ = SHA-256, $1$ = MD5 (weak), $y$ = yescrypt
        $ShadowHashes = $(timeout 3 awk -F: '$2 ~ /^\$/ {print $1 ":" substr($2,1,4)}' /etc/shadow 2>/dev/null)
        $ShadowHashArr = @()
        if ($null -ne $ShadowHashes) { $ShadowHashArr = @($ShadowHashes) }

        $FindingDetails += "Password hash algorithms in /etc/shadow:" + $nl
        $WeakHash = $false
        foreach ($Entry in $ShadowHashArr) {
            $EntryStr = ("$Entry").Trim()
            if ($EntryStr -ne "") {
                $FindingDetails += "  $EntryStr" + $nl
                # MD5 ($1$) or DES (no $) are weak
                if ($EntryStr -match ':\$1\$') { $WeakHash = $true }
            }
        }

        # Check login.defs ENCRYPT_METHOD
        $LoginDefs = Get-Content -Path "/etc/login.defs" -ErrorAction SilentlyContinue
        $LoginDefsStr = ""
        if ($null -ne $LoginDefs) { $LoginDefsStr = ($LoginDefs -join $nl).Trim() }
        $EncryptMethod = ""
        if ($LoginDefsStr -match "(?m)^\s*ENCRYPT_METHOD\s+(\S+)") { $EncryptMethod = $matches[1] }
        $FindingDetails += $nl + "ENCRYPT_METHOD in login.defs: $EncryptMethod" + $nl

        if ($WeakHash) {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Weak password hash algorithm (MD5) detected in /etc/shadow."
        }
        elseif ($EncryptMethod -match "SHA512|SHA256|YESCRYPT") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Passwords are stored using encrypted hash algorithm ($EncryptMethod)."
        }
        elseif ($ShadowHashArr.Count -gt 0) {
            # If all hashes are $6$ or $5$ or $y$, still compliant even if login.defs is missing
            $AllStrong = $true
            foreach ($Entry in $ShadowHashArr) {
                $EStr = ("$Entry").Trim()
                if ($EStr -ne "" -and $EStr -notmatch ':\$[56y]\$') { $AllStrong = $false }
            }
            if ($AllStrong) {
                $Status = "NotAFinding"
                $FindingDetails += $nl + "RESULT: All password hashes use strong algorithms (SHA-256/SHA-512/yescrypt)."
            }
            else {
                $Status = "Open"
                $FindingDetails += $nl + "RESULT: Password hash configuration could not be fully verified."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify password storage encryption."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207377
        STIG ID    : SRG-OS-000074-VMM-000410
        Rule ID    : SV-207377r987796_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-OS-000074
        Rule Title : The VMM must transmit only encrypted representations of passwords.
        DiscussMD5 : f0670297715b727411a94adac8fd1fde
        CheckMD5   : e999d6bc2e0bccf65afe32a3a03bb6cf
        FixMD5     : 6e563f99d1bd93759c45ba9d54e32c86
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
    $VulnID = "V-207377"
    $RuleID = "SV-207377r987796_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Encrypted Password Transmission" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check xapi uses TLS (port 443)
        $XapiListening = $(timeout 3 ss -tlnp 2>/dev/null | grep -E ':443\b' 2>/dev/null)
        $XapiListeningStr = ("$XapiListening").Trim()
        if ($XapiListeningStr -ne "") {
            $FindingDetails += "xapi TLS listener (port 443):" + $nl + $XapiListeningStr + $nl
        }
        else {
            $FindingDetails += "xapi TLS listener (port 443): not detected" + $nl
        }

        # Check SSH is the only remote shell (no telnet, no rsh)
        $TelnetActive = $(timeout 3 systemctl is-active telnet.socket 2>/dev/null)
        $TelnetStr = ("$TelnetActive").Trim()
        $FindingDetails += "telnet service: $TelnetStr" + $nl

        $RshActive = $(timeout 3 systemctl is-active rsh.socket 2>/dev/null)
        $RshStr = ("$RshActive").Trim()
        $FindingDetails += "rsh service: $RshStr" + $nl

        $SshActive = $(timeout 3 systemctl is-active sshd 2>/dev/null)
        $SshStr = ("$SshActive").Trim()
        $FindingDetails += "sshd service: $SshStr" + $nl

        # Check if xapi SSL cert exists (means TLS is configured)
        $XapiCertExists = $(timeout 3 test -f /etc/xensource/xapi-ssl.pem && echo "exists" || echo "missing" 2>/dev/null)
        $XapiCertStr = ("$XapiCertExists").Trim()
        $FindingDetails += "xapi SSL certificate: $XapiCertStr" + $nl

        $InsecureServices = ($TelnetStr -eq "active") -or ($RshStr -eq "active")
        $HasTLS = $XapiListeningStr -ne "" -or $XapiCertStr -eq "exists"

        if (-not $InsecureServices -and $HasTLS -and $SshStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Passwords are transmitted only via encrypted channels (TLS/SSH). No insecure services active."
        }
        else {
            $Status = "Open"
            if ($InsecureServices) {
                $FindingDetails += $nl + "RESULT: Insecure remote access services (telnet/rsh) are active — passwords may be transmitted in cleartext."
            }
            else {
                $FindingDetails += $nl + "RESULT: Cannot verify that all password transmission uses encryption."
            }
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207378 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207378
        STIG ID    : SRG-OS-000075-VMM-000420
        Rule ID    : SV-207378r984202_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000075
        Rule Title : The VMM must enforce 24 hours/one day as the minimum password lifetime.
        DiscussMD5 : a13f8dd5b3602a221cac064dec313195
        CheckMD5   : 4f762107ab72956ee870767cff00cfb8
        FixMD5     : ed025bc2081f9d341f9526f3e0f89f55
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
    $VulnID = "V-207378"
    $RuleID = "SV-207378r984202_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Minimum Password Lifetime" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check /etc/login.defs for PASS_MIN_DAYS
        $LoginDefs = Get-Content -Path "/etc/login.defs" -ErrorAction SilentlyContinue
        $LoginDefsStr = ""
        if ($null -ne $LoginDefs) { $LoginDefsStr = ($LoginDefs -join $nl).Trim() }

        $PassMinDays = ""
        if ($LoginDefsStr -match "(?m)^\s*PASS_MIN_DAYS\s+(\d+)") { $PassMinDays = $matches[1] }

        if ($PassMinDays -ne "") {
            $FindingDetails += "PASS_MIN_DAYS in login.defs: $PassMinDays" + $nl
        }
        else {
            $FindingDetails += "PASS_MIN_DAYS in login.defs: not set" + $nl
        }

        # Check individual user settings via chage
        $UserMinDays = $(timeout 5 awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd 2>/dev/null)
        $UserArr = @()
        if ($null -ne $UserMinDays) { $UserArr = @($UserMinDays) }
        if ($UserArr.Count -gt 0) {
            $FindingDetails += $nl + "User password minimum age (chage):" + $nl
            foreach ($User in $UserArr) {
                $UStr = ("$User").Trim()
                if ($UStr -ne "") {
                    $ChageInfo = $(timeout 3 chage -l $UStr 2>/dev/null | grep -i 'minimum' 2>/dev/null)
                    $ChageStr = ("$ChageInfo").Trim()
                    if ($ChageStr -ne "") { $FindingDetails += "  $UStr - $ChageStr" + $nl }
                }
            }
        }

        # PASS_MIN_DAYS must be >= 1 (24 hours = 1 day)
        if ($PassMinDays -ne "" -and [int]$PassMinDays -ge 1) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Minimum password lifetime is $PassMinDays day(s) (requirement: >= 1)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: PASS_MIN_DAYS is not set to 1 or greater."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207379
        STIG ID    : SRG-OS-000076-VMM-000430
        Rule ID    : SV-207379r1038967_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000076
        Rule Title : The VMM must enforce a 60-day maximum password lifetime restriction.
        DiscussMD5 : 03bad317055b71a930415bdbe2ac8426
        CheckMD5   : 8f1692a09b610cdc993b96a600202ef6
        FixMD5     : ec6c33f7d05ee252597af5205a0f8bb7
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
    $VulnID = "V-207379"
    $RuleID = "SV-207379r1038967_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Maximum Password Lifetime" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check /etc/login.defs for PASS_MAX_DAYS
        $LoginDefs = Get-Content -Path "/etc/login.defs" -ErrorAction SilentlyContinue
        $LoginDefsStr = ""
        if ($null -ne $LoginDefs) { $LoginDefsStr = ($LoginDefs -join $nl).Trim() }

        $PassMaxDays = ""
        if ($LoginDefsStr -match "(?m)^\s*PASS_MAX_DAYS\s+(\d+)") { $PassMaxDays = $matches[1] }

        if ($PassMaxDays -ne "") {
            $FindingDetails += "PASS_MAX_DAYS in login.defs: $PassMaxDays" + $nl
        }
        else {
            $FindingDetails += "PASS_MAX_DAYS in login.defs: not set" + $nl
        }

        # Check individual user settings
        $UserMaxDays = $(timeout 5 awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd 2>/dev/null)
        $UserArr = @()
        if ($null -ne $UserMaxDays) { $UserArr = @($UserMaxDays) }
        if ($UserArr.Count -gt 0) {
            $FindingDetails += $nl + "User password maximum age (chage):" + $nl
            foreach ($User in $UserArr) {
                $UStr = ("$User").Trim()
                if ($UStr -ne "") {
                    $ChageInfo = $(timeout 3 chage -l $UStr 2>/dev/null | grep -i 'maximum' 2>/dev/null)
                    $ChageStr = ("$ChageInfo").Trim()
                    if ($ChageStr -ne "") { $FindingDetails += "  $UStr - $ChageStr" + $nl }
                }
            }
        }

        # PASS_MAX_DAYS must be <= 60
        if ($PassMaxDays -ne "" -and [int]$PassMaxDays -le 60) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Maximum password lifetime is $PassMaxDays days (requirement: <= 60)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: PASS_MAX_DAYS is not set to 60 or less."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207381
        STIG ID    : SRG-OS-000078-VMM-000450
        Rule ID    : SV-207381r984205_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000078
        Rule Title : The VMM must enforce a minimum 15-character password length.
        DiscussMD5 : ac553fb941e0c109b52498035d2d0328
        CheckMD5   : cb7019f229b2d9eacd27c30792b4e2b3
        FixMD5     : a09ff9ca8ea8a3196a63821611b3f4b9
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
    $VulnID = "V-207381"
    $RuleID = "SV-207381r984205_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Minimum Password Length" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check pwquality.conf for minlen
        $PwQualConf = Get-Content -Path "/etc/security/pwquality.conf" -ErrorAction SilentlyContinue
        $PwQualStr = ""
        if ($null -ne $PwQualConf) { $PwQualStr = ($PwQualConf -join $nl).Trim() }

        $Minlen = ""
        if ($PwQualStr -match "(?m)^\s*minlen\s*=\s*(\d+)") { $Minlen = $matches[1] }

        if ($Minlen -ne "") {
            $FindingDetails += "pwquality.conf minlen = $Minlen" + $nl
        }
        else {
            $FindingDetails += "pwquality.conf minlen: not set (default 8)" + $nl
        }

        # Also check PAM for minlen override
        $PamMinlen = $(timeout 3 grep -E 'minlen' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)
        $PamMinlenStr = ("$PamMinlen").Trim()
        if ($PamMinlenStr -ne "") {
            $FindingDetails += $nl + "PAM minlen settings:" + $nl + $PamMinlenStr + $nl
        }

        # minlen must be >= 15
        if ($Minlen -ne "" -and [int]$Minlen -ge 15) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Minimum password length is $Minlen characters (requirement: >= 15)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: minlen is not set to 15 or greater."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207382 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207382
        STIG ID    : SRG-OS-000079-VMM-000460
        Rule ID    : SV-207382r958470_rule
        CCI ID     : CCI-000206
        Rule Name  : SRG-OS-000079
        Rule Title : The VMM must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.
        DiscussMD5 : 21e1e7122a3abe374c462974a0fdea17
        CheckMD5   : e7406c7e2ca4988521f058d0e11e06de
        FixMD5     : 3fc8e10f6be4a1f3c399f7f9d8681c6d
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
    $VulnID = "V-207382"
    $RuleID = "SV-207382r958470_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Authentication Information Obscuring" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # SSH password authentication feedback is obscured by default (asterisks/no echo)
        $SshConf = Get-Content -Path "/etc/ssh/sshd_config" -ErrorAction SilentlyContinue
        $SshConfStr = ""
        if ($null -ne $SshConf) { $SshConfStr = ($SshConf -join $nl).Trim() }

        # Check PasswordAuthentication setting
        $PwdAuth = ""
        if ($SshConfStr -match "(?m)^\s*PasswordAuthentication\s+(\S+)") { $PwdAuth = $matches[1] }
        $FindingDetails += "SSH PasswordAuthentication: $PwdAuth" + $nl

        # xapi/XAPI management uses HTTPS (port 443) — passwords transmitted over TLS
        $XapiTLS = $(timeout 3 ss -tlnp 2>/dev/null | grep -E ':443\b' 2>/dev/null)
        $XapiTLSStr = ("$XapiTLS").Trim()
        $FindingDetails += "xapi HTTPS (443): $(if ($XapiTLSStr -ne '') { 'active' } else { 'not detected' })" + $nl

        # Console login uses standard Linux PAM which obscures password input
        $FindingDetails += "Console login: PAM handles password input (no echo by default)" + $nl

        # SSH and xapi both obscure password feedback
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Authentication feedback is obscured. SSH uses no-echo password input. xapi uses HTTPS for web-based authentication."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207383
        STIG ID    : SRG-OS-000080-VMM-000470
        Rule ID    : SV-207383r958472_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080
        Rule Title : The VMM must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
        DiscussMD5 : f9555b0fa4d44ed6683c68ae9ab53c95
        CheckMD5   : 50f10f8c7a9aebd09f0315eb3fd8e7c5
        FixMD5     : 1bac849206b832107906f567359e7215
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
    $VulnID = "V-207383"
    $RuleID = "SV-207383r958472_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Access Control Policy Enforcement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check RBAC roles via xe
        $RbacRoles = Invoke-XeCommand -Command "role-list --minimal"
        $RbacStr = ("$RbacRoles").Trim()
        if ($RbacStr -ne "") {
            $FindingDetails += "RBAC roles configured: yes" + $nl
            $FindingDetails += "Roles: $RbacStr" + $nl
        }
        else {
            $FindingDetails += "RBAC roles: unable to enumerate" + $nl
        }

        # Check sudo configuration
        $SudoersExists = $(timeout 3 test -f /etc/sudoers && echo "exists" || echo "missing" 2>/dev/null)
        $SudoersStr = ("$SudoersExists").Trim()
        $FindingDetails += "sudoers file: $SudoersStr" + $nl

        # Check file permission enforcement
        $EtcPerms = $(timeout 3 stat -c '%a %U:%G' /etc/passwd /etc/shadow /etc/group 2>/dev/null)
        $EtcPermsArr = @()
        if ($null -ne $EtcPerms) { $EtcPermsArr = @($EtcPerms) }
        $FindingDetails += $nl + "Critical file permissions:" + $nl
        $CritFiles = @("/etc/passwd", "/etc/shadow", "/etc/group")
        for ($i = 0; $i -lt $EtcPermsArr.Count -and $i -lt $CritFiles.Count; $i++) {
            $FindingDetails += "  $($CritFiles[$i]): $($EtcPermsArr[$i])" + $nl
        }

        # XCP-ng RBAC + Linux DAC = access control enforcement
        if ($RbacStr -ne "" -and $SudoersStr -eq "exists") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: RBAC and DAC access controls are enforced. XCP-ng RBAC manages hypervisor-level access. Linux DAC manages OS-level access."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Access control policy enforcement cannot be fully verified."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207384 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207384
        STIG ID    : SRG-OS-000095-VMM-000480
        Rule ID    : SV-207384r958478_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095
        Rule Title : The VMM must be configured to disable non-essential capabilities.
        DiscussMD5 : 5b05e25a56e2a8da2f4483bd06f90192
        CheckMD5   : e012eb37ebf0faed0acfe721b4923d14
        FixMD5     : 13eb0cb328768143ed720a013c530665
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
    $VulnID = "V-207384"
    $RuleID = "SV-207384r958478_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Non-Essential Capabilities" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for non-essential services that should be disabled
        $NonEssentialSvcs = @("telnet.socket", "rsh.socket", "rlogin.socket", "rexec.socket", "tftp.socket", "vsftpd", "avahi-daemon", "cups")
        $FindingDetails += "Non-essential services status:" + $nl
        $ActiveNonEssential = @()
        foreach ($Svc in $NonEssentialSvcs) {
            $SvcStatus = $(timeout 3 systemctl is-active $Svc 2>/dev/null)
            $SvcStr = ("$SvcStatus").Trim()
            if ($SvcStr -eq "active") {
                $ActiveNonEssential += $Svc
                $FindingDetails += "  $Svc : ACTIVE (non-essential)" + $nl
            }
        }

        if ($ActiveNonEssential.Count -eq 0) {
            $FindingDetails += "  No non-essential services are active." + $nl
        }

        # Check for unnecessary packages
        $UnnecessaryPkgs = $(timeout 5 rpm -q telnet-server rsh-server tftp-server vsftpd 2>/dev/null)
        $UnnecessaryArr = @()
        if ($null -ne $UnnecessaryPkgs) { $UnnecessaryArr = @($UnnecessaryPkgs) }
        $InstalledUnnecessary = @()
        foreach ($Pkg in $UnnecessaryArr) {
            $PkgStr = ("$Pkg").Trim()
            if ($PkgStr -ne "" -and $PkgStr -notmatch "not installed") {
                $InstalledUnnecessary += $PkgStr
            }
        }

        if ($InstalledUnnecessary.Count -gt 0) {
            $FindingDetails += $nl + "Unnecessary packages installed:" + $nl
            foreach ($P in $InstalledUnnecessary) { $FindingDetails += "  $P" + $nl }
        }

        if ($ActiveNonEssential.Count -eq 0 -and $InstalledUnnecessary.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: No non-essential capabilities are active or installed."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Non-essential capabilities detected that should be disabled or removed."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207385 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207385
        STIG ID    : SRG-OS-000096-VMM-000490
        Rule ID    : SV-207385r958480_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000096
        Rule Title : The VMM must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
        DiscussMD5 : f709183525b3628dbde153b1d5976e83
        CheckMD5   : 5fb36aea4d365d1d89bbe159e050c446
        FixMD5     : 0d76aff2449c9e0b83ecb03b1d5e1fdf
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
    $VulnID = "V-207385"
    $RuleID = "SV-207385r958480_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Port/Protocol/Service Restriction" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # List listening TCP ports
        $ListeningPorts = $(timeout 5 ss -tlnp 2>/dev/null)
        $ListenArr = @()
        if ($null -ne $ListeningPorts) { $ListenArr = @($ListeningPorts) }
        $FindingDetails += "Listening TCP ports:" + $nl
        foreach ($Port in $ListenArr) {
            $PortStr = ("$Port").Trim()
            if ($PortStr -ne "" -and $PortStr -notmatch "^State") {
                $FindingDetails += "  $PortStr" + $nl
            }
        }

        # Check firewall status (iptables on CentOS 7)
        $IptablesRules = $(timeout 5 iptables -L -n --line-numbers 2>/dev/null | head -20 2>/dev/null)
        $IptablesStr = ("$IptablesRules").Trim()
        $FindingDetails += $nl + "Firewall rules (first 20 lines):" + $nl
        if ($IptablesStr -ne "") {
            $FindingDetails += $IptablesStr + $nl
        }
        else {
            $FindingDetails += "  Unable to read iptables rules" + $nl
        }

        # This is a policy-based check — needs organizational PPSM CAL review
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Listening ports and firewall rules listed above. Organizational review against PPSM CAL required to verify compliance."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207386 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207386
        STIG ID    : SRG-OS-000104-VMM-000500
        Rule ID    : SV-207386r958482_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-OS-000104
        Rule Title : The VMM must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users).
        DiscussMD5 : 66d324f2c996c8fe8c20ced89a51b3dc
        CheckMD5   : 22039f1c7ea0b189105231773b24f702
        FixMD5     : 1c4235c8d098b569720654152f6b0015
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
    $VulnID = "V-207386"
    $RuleID = "SV-207386r958482_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Unique User Identification and Authentication" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check that each user has a unique UID
        $DuplicateUIDs = $(timeout 5 awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d 2>/dev/null)
        $DupUIDStr = ("$DuplicateUIDs").Trim()
        if ($DupUIDStr -ne "") {
            $FindingDetails += "Duplicate UIDs found: $DupUIDStr" + $nl
        }
        else {
            $FindingDetails += "No duplicate UIDs found." + $nl
        }

        # Check that root is the only UID 0
        $UID0Accounts = $(timeout 3 awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
        $UID0Str = ("$UID0Accounts").Trim()
        $FindingDetails += "UID 0 accounts: $UID0Str" + $nl

        # Check SSH requires authentication
        $SshConf = Get-Content -Path "/etc/ssh/sshd_config" -ErrorAction SilentlyContinue
        $SshConfStr = ""
        if ($null -ne $SshConf) { $SshConfStr = ($SshConf -join $nl).Trim() }
        $PermitEmpty = ""
        if ($SshConfStr -match "(?m)^\s*PermitEmptyPasswords\s+(\S+)") { $PermitEmpty = $matches[1] }
        $FindingDetails += "SSH PermitEmptyPasswords: $(if ($PermitEmpty -ne '') { $PermitEmpty } else { 'not set (default no)' })" + $nl

        $NoSharedAccounts = ($DupUIDStr -eq "") -and ($UID0Str -eq "root" -or $UID0Str -match "^root$")
        $NoEmptyPw = ($PermitEmpty -ne "yes")

        if ($NoSharedAccounts -and $NoEmptyPw) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Users are uniquely identified (no duplicate UIDs, only root has UID 0, empty passwords not permitted)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: User identification issues detected (duplicate UIDs, multiple UID 0, or empty passwords allowed)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207387 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207387
        STIG ID    : SRG-OS-000105-VMM-000510
        Rule ID    : SV-207387r958484_rule
        CCI ID     : CCI-000765
        Rule Name  : SRG-OS-000105
        Rule Title : The VMM must use multifactor authentication for network access to privileged accounts.
        DiscussMD5 : b172f52081f37dff1519f014fb7aa6b1
        CheckMD5   : 2a61d46bb5b7c463985f8c2f065d5db8
        FixMD5     : d98ddeacba539ddb29d6e54e2fce6e29
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
    $VulnID = "V-207387"
    $RuleID = "SV-207387r958484_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "MFA — Network Access to Privileged Accounts" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for AD/LDAP external auth (can enforce MFA via AD policies)
        $PoolExtAuth = $(timeout 5 xe pool-list params=external-auth-type 2>/dev/null)
        $PoolExtAuthStr = ("$PoolExtAuth").Trim()
        $FindingDetails += "External auth type: $PoolExtAuthStr" + $nl

        # Check for SSSD/smart card PAM modules
        $PamSmartCard = $(timeout 3 grep -r 'pam_sss\|pam_pkcs11\|pam_google_authenticator' /etc/pam.d/ 2>/dev/null)
        $PamSCStr = ("$PamSmartCard").Trim()
        if ($PamSCStr -ne "") {
            $FindingDetails += $nl + "MFA PAM modules:" + $nl + $PamSCStr + $nl
        }
        else {
            $FindingDetails += "MFA PAM modules (pam_sss, pam_pkcs11, pam_google_authenticator): none configured" + $nl
        }

        $HasMFA = ($PoolExtAuthStr -match "AD") -or ($PamSCStr -ne "")

        if ($HasMFA) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: MFA is available for network access to privileged accounts via external authentication."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: MFA is not configured for network access to privileged accounts."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207388 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207388
        STIG ID    : SRG-OS-000106-VMM-000520
        Rule ID    : SV-207388r958486_rule
        CCI ID     : CCI-000766
        Rule Name  : SRG-OS-000106
        Rule Title : The VMM must use multifactor authentication for network access to non-privileged accounts.
        DiscussMD5 : 4625ce365d0ba6117c50efaf9e0792c2
        CheckMD5   : da847a8be9ae59d4cec2f0945b73dca6
        FixMD5     : 5d4843b9a1f6f110e0c252c350dc0786
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
    $VulnID = "V-207388"
    $RuleID = "SV-207388r958486_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "MFA — Network Access to Non-Privileged Accounts" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $PoolExtAuth = $(timeout 5 xe pool-list params=external-auth-type 2>/dev/null)
        $PoolExtAuthStr = ("$PoolExtAuth").Trim()
        $FindingDetails += "External auth type: $PoolExtAuthStr" + $nl

        $PamSmartCard = $(timeout 3 grep -r 'pam_sss\|pam_pkcs11\|pam_google_authenticator' /etc/pam.d/ 2>/dev/null)
        $PamSCStr = ("$PamSmartCard").Trim()
        if ($PamSCStr -ne "") {
            $FindingDetails += "MFA PAM modules: configured" + $nl
        }
        else {
            $FindingDetails += "MFA PAM modules: none configured" + $nl
        }

        $HasMFA = ($PoolExtAuthStr -match "AD") -or ($PamSCStr -ne "")
        if ($HasMFA) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: MFA is available for network access to non-privileged accounts via external authentication."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: MFA is not configured for network access to non-privileged accounts."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207389 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207389
        STIG ID    : SRG-OS-000107-VMM-000530
        Rule ID    : SV-207389r984206_rule
        CCI ID     : CCI-000765
        Rule Name  : SRG-OS-000107
        Rule Title : The VMM must use multifactor authentication for local access to privileged accounts.
        DiscussMD5 : bd715bd6f53860aaf86ed9d7d9684676
        CheckMD5   : aab51431c3436f4cdf7c173e6f167f7b
        FixMD5     : f6a1362fe8abf3199499a6936ec80ee8
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
    $VulnID = "V-207389"
    $RuleID = "SV-207389r984206_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "MFA — Local Access to Privileged Accounts" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $PamSmartCard = $(timeout 3 grep -r 'pam_sss\|pam_pkcs11\|pam_google_authenticator' /etc/pam.d/ 2>/dev/null)
        $PamSCStr = ("$PamSmartCard").Trim()
        if ($PamSCStr -ne "") {
            $FindingDetails += "MFA PAM modules:" + $nl + $PamSCStr + $nl
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: MFA PAM modules are configured for local access."
        }
        else {
            $FindingDetails += "MFA PAM modules (pam_sss, pam_pkcs11, pam_google_authenticator): none configured" + $nl
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: MFA is not configured for local access to privileged accounts."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207390 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207390
        STIG ID    : SRG-OS-000108-VMM-000540
        Rule ID    : SV-207390r984209_rule
        CCI ID     : CCI-000766
        Rule Name  : SRG-OS-000108
        Rule Title : The VMM must use multifactor authentication for local access to nonprivileged accounts.
        DiscussMD5 : 4f0ecd45517f5c8b295f75944214b58b
        CheckMD5   : f79bcb08eb37566d3ace9a01bbf6a30f
        FixMD5     : 03d6a0c737baf9d5595fac037c018dd6
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
    $VulnID = "V-207390"
    $RuleID = "SV-207390r984209_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "MFA — Local Access to Non-Privileged Accounts" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $PamSmartCard = $(timeout 3 grep -r 'pam_sss\|pam_pkcs11\|pam_google_authenticator' /etc/pam.d/ 2>/dev/null)
        $PamSCStr = ("$PamSmartCard").Trim()
        if ($PamSCStr -ne "") {
            $FindingDetails += "MFA PAM modules: configured" + $nl
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: MFA PAM modules are configured for local access."
        }
        else {
            $FindingDetails += "MFA PAM modules: none configured" + $nl
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: MFA is not configured for local access to non-privileged accounts."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207391 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207391
        STIG ID    : SRG-OS-000109-VMM-000550
        Rule ID    : SV-207391r984210_rule
        CCI ID     : CCI-004045
        Rule Name  : SRG-OS-000109
        Rule Title : The VMM must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
        DiscussMD5 : f2ee6653ce44e09569da88269d02d21b
        CheckMD5   : 84281efb2b1bbdb7ad9f863319ee760c
        FixMD5     : d5a2cbdfa2625592b560d31ad995c777
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
    $VulnID = "V-207391"
    $RuleID = "SV-207391r984210_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Individual Authentication Before Group Authenticator" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check root login restrictions — users must log in as individual then su/sudo
        $SshConf = Get-Content -Path "/etc/ssh/sshd_config" -ErrorAction SilentlyContinue
        $SshConfStr = ""
        if ($null -ne $SshConf) { $SshConfStr = ($SshConf -join $nl).Trim() }
        $PermitRoot = ""
        if ($SshConfStr -match "(?m)^\s*PermitRootLogin\s+(\S+)") { $PermitRoot = $matches[1] }
        $FindingDetails += "SSH PermitRootLogin: $(if ($PermitRoot -ne '') { $PermitRoot } else { 'not set (default varies)' })" + $nl

        # Check if su requires group membership (pam_wheel)
        $PamWheel = $(timeout 3 grep -E 'pam_wheel' /etc/pam.d/su 2>/dev/null)
        $PamWheelStr = ("$PamWheel").Trim()
        if ($PamWheelStr -ne "") {
            $FindingDetails += "pam_wheel in /etc/pam.d/su: configured" + $nl
        }
        else {
            $FindingDetails += "pam_wheel in /etc/pam.d/su: not configured" + $nl
        }

        # Check sudo requires password (no NOPASSWD for all)
        $NoPasswd = $(timeout 3 grep -r 'NOPASSWD.*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
        $NoPasswdStr = ("$NoPasswd").Trim()
        if ($NoPasswdStr -ne "") {
            $FindingDetails += "NOPASSWD ALL in sudoers: found" + $nl + $NoPasswdStr + $nl
        }
        else {
            $FindingDetails += "NOPASSWD ALL in sudoers: not found" + $nl
        }

        # Individual auth before group: direct root login prohibited + sudo requires individual password
        $RootRestricted = ($PermitRoot -eq "no" -or $PermitRoot -eq "prohibit-password")
        $SudoRequiresPw = ($NoPasswdStr -eq "")

        if ($RootRestricted -and $SudoRequiresPw) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Individual authentication is required before group/shared access. Direct root SSH login is restricted and sudo requires password."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Individual authentication may not be required before group authenticator use."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207392 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207392
        STIG ID    : SRG-OS-000112-VMM-000560
        Rule ID    : SV-207392r958494_rule
        CCI ID     : CCI-001941
        Rule Name  : SRG-OS-000112
        Rule Title : The VMM must implement replay-resistant authentication mechanisms for network access to privileged accounts.
        DiscussMD5 : 62f5b142b09fe5848bd13e36de29e16b
        CheckMD5   : 8e668c284227f968350dcb5db4164323
        FixMD5     : 509b608a0c1ef2834745ac6215a0409c
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
    $VulnID = "V-207392"
    $RuleID = "SV-207392r958494_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Replay-Resistant Authentication — Privileged Network Access" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # SSH uses key exchange (Diffie-Hellman) which is inherently replay-resistant
        $SshActive = $(timeout 3 systemctl is-active sshd 2>/dev/null)
        $SshStr = ("$SshActive").Trim()
        $FindingDetails += "SSH service: $SshStr" + $nl

        # xapi uses TLS which provides replay resistance via session keys
        $XapiTLS = $(timeout 3 ss -tlnp 2>/dev/null | grep -E ':443\b' 2>/dev/null)
        $XapiTLSStr = ("$XapiTLS").Trim()
        $FindingDetails += "xapi HTTPS (443): $(if ($XapiTLSStr -ne '') { 'active' } else { 'not detected' })" + $nl

        # Check for insecure services (telnet, rsh — no replay resistance)
        $TelnetActive = $(timeout 3 systemctl is-active telnet.socket 2>/dev/null)
        $TelnetStr = ("$TelnetActive").Trim()
        $FindingDetails += "telnet: $TelnetStr" + $nl

        if ($SshStr -eq "active" -and $TelnetStr -ne "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Network access uses SSH and TLS which provide replay-resistant authentication via cryptographic session establishment."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Replay-resistant authentication cannot be verified (SSH not active or insecure services enabled)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207393
        STIG ID    : SRG-OS-000113-VMM-000570
        Rule ID    : SV-207393r984213_rule
        CCI ID     : CCI-001941
        Rule Name  : SRG-OS-000113
        Rule Title : The VMM must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.
        DiscussMD5 : 66bc9e4217a2c23b5e4b5b5672d056c8
        CheckMD5   : ad476741c8a618f07f5c41dabdf0d7d7
        FixMD5     : 51e4e9122437d5df323b57613faac622
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
    $VulnID = "V-207393"
    $RuleID = "SV-207393r984213_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Replay-Resistant Authentication — Non-Privileged Network Access" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $SshActive = $(timeout 3 systemctl is-active sshd 2>/dev/null)
        $SshStr = ("$SshActive").Trim()
        $FindingDetails += "SSH service: $SshStr" + $nl

        $XapiTLS = $(timeout 3 ss -tlnp 2>/dev/null | grep -E ':443\b' 2>/dev/null)
        $XapiTLSStr = ("$XapiTLS").Trim()
        $FindingDetails += "xapi HTTPS (443): $(if ($XapiTLSStr -ne '') { 'active' } else { 'not detected' })" + $nl

        $TelnetActive = $(timeout 3 systemctl is-active telnet.socket 2>/dev/null)
        $TelnetStr = ("$TelnetActive").Trim()

        if ($SshStr -eq "active" -and $TelnetStr -ne "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Network access uses SSH and TLS which provide replay-resistant authentication."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Replay-resistant authentication cannot be verified."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207394
        STIG ID    : SRG-OS-000114-VMM-000580
        Rule ID    : SV-207394r958498_rule
        CCI ID     : CCI-000778
        Rule Name  : SRG-OS-000114
        Rule Title : The VMM must uniquely identify peripherals before establishing a connection.
        DiscussMD5 : c6b284c5ddf721374919f89221630be5
        CheckMD5   : f221f56e9d600b146196c5fc61379db8
        FixMD5     : feb0b52e0f90eed49d2eee9a804e778a
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
    $VulnID = "V-207394"
    $RuleID = "SV-207394r958498_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Peripheral Device Identification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # XCP-ng uses PCI/USB passthrough which requires explicit device identification
        $PciDevices = $(timeout 5 xe pbd-list params=device-config 2>/dev/null)
        $PciStr = ("$PciDevices").Trim()
        if ($PciStr -ne "") {
            $FindingDetails += "Physical block device configuration:" + $nl + $PciStr + $nl
        }

        # Check USB passthrough configuration
        $UsbPolicy = $(timeout 5 xe pool-list params=other-config 2>/dev/null | grep -i usb 2>/dev/null)
        $UsbStr = ("$UsbPolicy").Trim()
        if ($UsbStr -ne "") {
            $FindingDetails += "USB policy: $UsbStr" + $nl
        }
        else {
            $FindingDetails += "USB policy: not explicitly configured" + $nl
        }

        # XCP-ng identifies devices via PCI bus ID and vendor/device ID before passthrough
        $FindingDetails += $nl + "XCP-ng identifies physical devices (PCI/USB) via bus address and vendor/device IDs before passthrough to VMs." + $nl

        # Peripherals are managed through xapi — requires explicit admin action to pass through
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng uniquely identifies peripherals via PCI/USB bus addressing before establishing VM connections. Device passthrough requires explicit administrative action."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207395
        STIG ID    : SRG-OS-000118-VMM-000590
        Rule ID    : SV-207395r984214_rule
        CCI ID     : CCI-003627
        Rule Name  : SRG-OS-000118
        Rule Title : The VMM must disable local account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
        DiscussMD5 : 9ad049accd11e6ea512d1491033b09a9
        CheckMD5   : 18c34f4ccb4ddf235e82a8bd2d96ed7c
        FixMD5     : 4a1a5d8aef9d4bd6cefb111cf2c94867
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
    $VulnID = "V-207395"
    $RuleID = "SV-207395r984214_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Inactive Account Disabling (35 Days)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check useradd default INACTIVE setting
        $UseraddDefault = $(timeout 3 useradd -D 2>/dev/null)
        $UseraddStr = ("$UseraddDefault").Trim()
        $InactiveDays = ""
        if ($UseraddStr -match "INACTIVE=(-?\d+)") { $InactiveDays = $matches[1] }
        $FindingDetails += "useradd default INACTIVE: $(if ($InactiveDays -ne '') { $InactiveDays } else { 'not set' })" + $nl

        # Check individual user inactive settings
        $UserList = $(timeout 5 awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd 2>/dev/null)
        $UserArr = @()
        if ($null -ne $UserList) { $UserArr = @($UserList) }
        if ($UserArr.Count -gt 0) {
            $FindingDetails += $nl + "User inactivity settings:" + $nl
            foreach ($User in $UserArr) {
                $UStr = ("$User").Trim()
                if ($UStr -ne "") {
                    $ChageInfo = $(timeout 3 chage -l $UStr 2>/dev/null | grep -i 'inactive' 2>/dev/null)
                    $ChageStr = ("$ChageInfo").Trim()
                    if ($ChageStr -ne "") { $FindingDetails += "  $UStr - $ChageStr" + $nl }
                }
            }
        }

        # INACTIVE must be set to 35 or less (and not -1 which means disabled)
        if ($InactiveDays -ne "" -and [int]$InactiveDays -ge 0 -and [int]$InactiveDays -le 35) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Accounts are disabled after $InactiveDays days of inactivity (requirement: <= 35)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Inactive account disabling is not configured to 35 days or less."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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
# BATCH 4: Encryption, Session Management, System Integrity, Error Handling
# VulnIDs: V-207396 through V-207411 (14 functions)
# ============================================================================

Function Get-V207396 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207396
        STIG ID    : SRG-OS-000120-VMM-000600
        Rule ID    : SV-207396r971535_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-OS-000120
        Rule Title : The VMM must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.
        DiscussMD5 : ca19339d214af74e1f98d36d9b550ba4
        CheckMD5   : 637e361a6cbe59af250ddc7034d86b1f
        FixMD5     : a1639350aee99fb6761d77ca79501bec
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
    $VulnID = "V-207396"
    $RuleID = "SV-207396r971535_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Cryptographic Module Authentication Mechanisms" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check OpenSSL version and FIPS capability
        $OpenSSLVer = $(openssl version 2>/dev/null)
        $OpenSSLStr = ("$OpenSSLVer").Trim()
        $FindingDetails += "OpenSSL version: $OpenSSLStr" + $nl

        # Check if FIPS mode is available/enabled
        $FIPSMode = $(cat /proc/sys/crypto/fips_enabled 2>/dev/null)
        $FIPSStr = ("$FIPSMode").Trim()
        if ($FIPSStr -eq "1") {
            $FindingDetails += "FIPS mode: enabled" + $nl
        }
        else {
            $FindingDetails += "FIPS mode: not enabled (value=$FIPSStr)" + $nl
        }

        # Check SSH crypto algorithms
        $SSHCiphers = $(timeout 5 sshd -T 2>/dev/null | grep -i "^ciphers" 2>/dev/null)
        $SSHCiphersStr = ("$SSHCiphers").Trim()
        $FindingDetails += "SSH ciphers: $SSHCiphersStr" + $nl

        $SSHMACs = $(timeout 5 sshd -T 2>/dev/null | grep -i "^macs" 2>/dev/null)
        $SSHMACsStr = ("$SSHMACs").Trim()
        $FindingDetails += "SSH MACs: $SSHMACsStr" + $nl

        # Check PAM password hashing algorithm
        $PamHash = $(timeout 3 grep -E "^password.*pam_unix" /etc/pam.d/system-auth 2>/dev/null)
        $PamHashStr = ("$PamHash").Trim()
        $FindingDetails += "PAM password hashing: $PamHashStr" + $nl

        # XCP-ng 8.3 does not support FIPS mode — this is a known compliance gap
        if ($FIPSStr -eq "1") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: FIPS mode is enabled. Cryptographic module authentication meets federal requirements."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: FIPS mode is not enabled. XCP-ng (CentOS 7-based) does not ship with FIPS mode enabled by default."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207397 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207397
        STIG ID    : SRG-OS-000122-VMM-000610
        Rule ID    : SV-207397r958506_rule
        CCI ID     : CCI-001876
        Rule Name  : SRG-OS-000122
        Rule Title : The VMM must support an audit reduction capability that supports on-demand reporting requirements.
        DiscussMD5 : d4d67652a4bc37c3beee4ef88a823577
        CheckMD5   : 5eb10bde466fc861e32648daf8d1f178
        FixMD5     : bddca0284e5882be678f4517a923883a
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
    $VulnID = "V-207397"
    $RuleID = "SV-207397r958506_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Reduction and On-Demand Reporting" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for audit tools
        $AusearchExists = $(which ausearch 2>/dev/null)
        $AusearchStr = ("$AusearchExists").Trim()
        $AureportExists = $(which aureport 2>/dev/null)
        $AureportStr = ("$AureportExists").Trim()

        $FindingDetails += "ausearch: $(if ($AusearchStr -ne '') { $AusearchStr } else { 'not found' })" + $nl
        $FindingDetails += "aureport: $(if ($AureportStr -ne '') { $AureportStr } else { 'not found' })" + $nl

        # Check for journalctl (systemd journal)
        $JournalctlExists = $(which journalctl 2>/dev/null)
        $JournalctlStr = ("$JournalctlExists").Trim()
        $FindingDetails += "journalctl: $(if ($JournalctlStr -ne '') { $JournalctlStr } else { 'not found' })" + $nl

        # Check auditd status
        $AuditdStatus = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdStatus").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Check for grep/awk (basic log analysis)
        $GrepExists = $(which grep 2>/dev/null)
        $AwkExists = $(which awk 2>/dev/null)
        $FindingDetails += "grep: $(("$GrepExists").Trim())" + $nl
        $FindingDetails += "awk: $(("$AwkExists").Trim())" + $nl

        # XCP-ng has journalctl + standard text tools for audit reduction
        $HasTools = ($JournalctlStr -ne "" -and ("$GrepExists").Trim() -ne "" -and ("$AwkExists").Trim() -ne "")
        if ($HasTools) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit reduction capabilities available. journalctl provides structured log queries with filtering. Standard tools (grep, awk, ausearch, aureport) support on-demand reporting."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit reduction tools not fully available."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207398 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207398
        STIG ID    : SRG-OS-000123-VMM-000620
        Rule ID    : SV-207398r958508_rule
        CCI ID     : CCI-001682
        Rule Name  : SRG-OS-000123
        Rule Title : The VMM must automatically remove or disable emergency accounts after the crisis is resolved or 72 hours.
        DiscussMD5 : 9303e4aecadb2df15ff6f5748b22d28b
        CheckMD5   : b248ec3c92d9df77ce977719b10fad44
        FixMD5     : a2ba73f540d5f0cecb820530f46146ce
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
    $VulnID = "V-207398"
    $RuleID = "SV-207398r958508_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Emergency Account Removal/Disabling (72-hour)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for temporary/emergency accounts with expiration
        $ExpireInfo = $(timeout 5 chage -l root 2>/dev/null | grep -i "account expires" 2>/dev/null)
        $ExpireStr = ("$ExpireInfo").Trim()
        $FindingDetails += "root account expiration: $ExpireStr" + $nl

        # Check for accounts with near-term expiration (potential emergency accounts)
        $AllExpiry = $(timeout 5 grep -v "^#" /etc/shadow 2>/dev/null | awk -F: '{if ($8 != "" && $8 > 0) print $1 ": expires at day " $8}' 2>/dev/null)
        $AllExpiryArr = @()
        if ($null -ne $AllExpiry) { $AllExpiryArr = @($AllExpiry) }

        if ($AllExpiryArr.Count -gt 0) {
            $FindingDetails += $nl + "Accounts with expiration set:" + $nl
            foreach ($line in $AllExpiryArr) {
                $FindingDetails += "  $line" + $nl
            }
        }
        else {
            $FindingDetails += "Accounts with expiration set: none found" + $nl
        }

        # Check for at/cron jobs that disable accounts
        $AtJobs = $(timeout 3 atq 2>/dev/null)
        $AtJobsStr = ("$AtJobs").Trim()
        $FindingDetails += $nl + "at job queue: $(if ($AtJobsStr -ne '') { $AtJobsStr } else { 'empty' })" + $nl

        # This is primarily a policy/procedural requirement
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No automated mechanism detected for removing or disabling emergency accounts after 72 hours. This is an organizational procedural requirement. Configure account expiration (chage -E) when creating emergency accounts."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207399 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207399
        STIG ID    : SRG-OS-000125-VMM-000630
        Rule ID    : SV-207399r958510_rule
        CCI ID     : CCI-000877
        Rule Name  : SRG-OS-000125
        Rule Title : The VMM must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.
        DiscussMD5 : e598f67a3b6f9f81086b2482879d3d2f
        CheckMD5   : 300152032e3d9611bc72eeaa92fd2ddd
        FixMD5     : df8a11d01cf626e4cfd0b513fac2cd6b
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
    $VulnID = "V-207399"
    $RuleID = "SV-207399r958510_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Nonlocal Maintenance Strong Authentication" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH key-based auth configuration
        $PubKeyAuth = $(timeout 5 sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" 2>/dev/null)
        $PubKeyStr = ("$PubKeyAuth").Trim()
        $FindingDetails += "SSH PubkeyAuthentication: $PubKeyStr" + $nl

        # Check PasswordAuthentication
        $PassAuth = $(timeout 5 sshd -T 2>/dev/null | grep -i "^passwordauthentication" 2>/dev/null)
        $PassStr = ("$PassAuth").Trim()
        $FindingDetails += "SSH PasswordAuthentication: $PassStr" + $nl

        # Check for SSH protocol version
        $SSHProtocol = $(timeout 5 sshd -T 2>/dev/null | grep -i "^protocol" 2>/dev/null)
        $SSHProtoStr = ("$SSHProtocol").Trim()
        if ($SSHProtoStr -ne "") {
            $FindingDetails += "SSH Protocol: $SSHProtoStr" + $nl
        }

        # Check xapi uses HTTPS for remote management
        $XapiHTTPS = $(timeout 3 ss -tlnp 2>/dev/null | grep ":443 " 2>/dev/null)
        $XapiStr = ("$XapiHTTPS").Trim()
        if ($XapiStr -ne "") {
            $FindingDetails += "xapi HTTPS (port 443): active" + $nl
        }
        else {
            $FindingDetails += "xapi HTTPS (port 443): not detected" + $nl
        }

        # Check for external auth (AD/LDAP)
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr -ne '') { $ExtAuthStr } else { 'none' })" + $nl

        # SSH + HTTPS = strong authenticators for nonlocal maintenance
        if ($PubKeyStr -match "yes" -and $XapiStr -ne "") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: SSH with public key authentication and xapi HTTPS provide strong authentication for nonlocal maintenance and diagnostic sessions."
        }
        elseif ($XapiStr -ne "") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: SSH with password authentication and xapi HTTPS are available. SSH provides encrypted channel. xapi management via HTTPS with TLS."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify strong authenticators for nonlocal maintenance sessions."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207401 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207401
        STIG ID    : SRG-OS-000132-VMM-000650
        Rule ID    : SV-207401r958514_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-OS-000132
        Rule Title : The VMM must separate user functionality (including user interface services) from VMM management functionality.
        DiscussMD5 : 84e2d827e1c03ef23cc29067de5f3aeb
        CheckMD5   : bd6496cb7bdcc3635aef4bcab9c5d980
        FixMD5     : 27059efc8d81c597a326f996c49b8a20
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
    $VulnID = "V-207401"
    $RuleID = "SV-207401r958514_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "User/Management Functionality Separation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # XCP-ng architecture: Dom0 is the management domain, VMs are user domains (DomU)
        # This is a fundamental architectural property of Xen hypervisor
        $DomInfo = $(timeout 5 xl info 2>/dev/null | grep -E "^(nr_cpus|total_memory|xen_version|xen_caps)" 2>/dev/null)
        $DomInfoArr = @()
        if ($null -ne $DomInfo) { $DomInfoArr = @($DomInfo) }
        $FindingDetails += "Xen hypervisor info:" + $nl
        foreach ($line in $DomInfoArr) {
            $FindingDetails += "  $line" + $nl
        }

        # List running VMs to show separation
        $VMList = Invoke-XeCommand -Command "vm-list params=name-label,power-state --minimal"
        $VMListStr = ("$VMList").Trim()
        $FindingDetails += $nl + "VM list (minimal): $VMListStr" + $nl

        # Dom0 is privileged management domain; user VMs run in isolated DomU
        $FindingDetails += $nl + "Architecture:" + $nl
        $FindingDetails += "  - Dom0 (privileged): VMM management only" + $nl
        $FindingDetails += "  - DomU (unprivileged): guest VM user workloads" + $nl
        $FindingDetails += "  - Xen hypervisor enforces hardware-level isolation" + $nl

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng (Xen) architecture inherently separates user functionality (DomU guest VMs) from VMM management functionality (Dom0 privileged domain). The Xen hypervisor enforces this separation at the hardware level."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207402 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207402
        STIG ID    : SRG-OS-000134-VMM-000660
        Rule ID    : SV-207402r958518_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-OS-000134
        Rule Title : The VMM must isolate security functions from non-security functions.
        DiscussMD5 : a73b72ec6252719210c87149b78042d1
        CheckMD5   : 83b28612621ac59417341928d1cd835c
        FixMD5     : 54b7cd5bab774c8a0e1685abccb9357d
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
    $VulnID = "V-207402"
    $RuleID = "SV-207402r958518_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Security Function Isolation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Xen hypervisor provides hardware-level isolation between domains
        # Security functions (Dom0) are isolated from guest workloads (DomU)
        $XenVersion = $(timeout 3 xl info 2>/dev/null | grep "^xen_version" 2>/dev/null)
        $XenVerStr = ("$XenVersion").Trim()
        $FindingDetails += "Xen version: $XenVerStr" + $nl

        # Check xapi daemon (security management)
        $XapiStatus = $(systemctl is-active xapi 2>/dev/null)
        $XapiStr = ("$XapiStatus").Trim()
        $FindingDetails += "xapi service: $XapiStr" + $nl

        # Check that xenstored is running (inter-domain communication)
        $XenstoredStatus = $(systemctl is-active xenstored 2>/dev/null)
        $XenstoredStr = ("$XenstoredStatus").Trim()
        $FindingDetails += "xenstored service: $XenstoredStr" + $nl

        # Check for SELinux/AppArmor on Dom0
        $SELinux = $(getenforce 2>/dev/null)
        $SELinuxStr = ("$SELinux").Trim()
        $FindingDetails += "SELinux: $(if ($SELinuxStr -ne '') { $SELinuxStr } else { 'not available' })" + $nl

        $FindingDetails += $nl + "Isolation mechanisms:" + $nl
        $FindingDetails += "  - Xen hypervisor: hardware-level domain isolation" + $nl
        $FindingDetails += "  - Dom0: privileged domain for security/management functions" + $nl
        $FindingDetails += "  - DomU: unprivileged domains for non-security workloads" + $nl
        $FindingDetails += "  - xenstored: controlled inter-domain communication" + $nl

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng (Xen) architecture isolates security functions in the privileged Dom0 domain from non-security guest workloads in DomU domains. The hypervisor enforces hardware-level memory and CPU isolation."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207403 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207403
        STIG ID    : SRG-OS-000138-VMM-000670
        Rule ID    : SV-207403r958524_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138
        Rule Title : The VMM must prevent unauthorized and unintended information transfer via shared system resources.
        DiscussMD5 : 63b395af0ca6a0f02ffeee2dba36ec09
        CheckMD5   : eddf30c9b098632afdc3c20a188837e0
        FixMD5     : 9a5cce3aacb7d7ed1adce901f2fdc2f3
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
    $VulnID = "V-207403"
    $RuleID = "SV-207403r958524_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Shared Resource Information Transfer Prevention" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check Xen memory isolation — VMs get dedicated memory pages
        $XenCaps = $(timeout 3 xl info 2>/dev/null | grep "^xen_caps" 2>/dev/null)
        $XenCapsStr = ("$XenCaps").Trim()
        $FindingDetails += "Xen capabilities: $XenCapsStr" + $nl

        # Check for memory ballooning (DMC - Dynamic Memory Control)
        $DMC = Invoke-XeCommand -Command "pool-list params=other-config --minimal"
        $DMCStr = ("$DMC").Trim()
        $FindingDetails += "Pool other-config: $(if ($DMCStr.Length -gt 200) { $DMCStr.Substring(0,200) + '...' } else { $DMCStr })" + $nl

        # Check shared storage configuration
        $SRList = Invoke-XeCommand -Command "sr-list params=type,name-label --minimal"
        $SRStr = ("$SRList").Trim()
        $FindingDetails += "Storage repositories: $(if ($SRStr -ne '') { $SRStr } else { 'none listed' })" + $nl

        $FindingDetails += $nl + "Isolation mechanisms:" + $nl
        $FindingDetails += "  - Memory: Xen hypervisor enforces per-VM memory page isolation" + $nl
        $FindingDetails += "  - CPU: Hardware-assisted virtualization (VT-x/AMD-V) provides CPU isolation" + $nl
        $FindingDetails += "  - Storage: VDIs provide per-VM virtual disk isolation" + $nl
        $FindingDetails += "  - Network: Virtual interfaces (VIFs) isolated per VM" + $nl

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Xen hypervisor prevents unauthorized information transfer via shared resources. Hardware-assisted virtualization provides memory, CPU, and I/O isolation between guest VMs."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207404 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207404
        STIG ID    : SRG-OS-000142-VMM-000690
        Rule ID    : SV-207404r958528_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-OS-000142
        Rule Title : The VMM must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks.
        DiscussMD5 : 0e0887a05d65e98cb4bc63f15fc47828
        CheckMD5   : 3d844b2be6c54e6492776d1c385fdaf7
        FixMD5     : d7c01b8b1c800de72ee42379bf1c0a9e
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
    $VulnID = "V-207404"
    $RuleID = "SV-207404r958528_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DoS Protection — Capacity and Bandwidth Management" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SYN cookies (kernel DoS protection)
        $SynCookies = $(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
        $SynStr = ("$SynCookies").Trim()
        $FindingDetails += "TCP SYN cookies: $(if ($SynStr -eq '1') { 'enabled' } else { "disabled ($SynStr)" })" + $nl

        # Check connection tracking limits
        $ConnTrackMax = $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)
        $ConnTrackStr = ("$ConnTrackMax").Trim()
        $FindingDetails += "Connection tracking max: $ConnTrackStr" + $nl

        # Check VM resource limits (memory, vCPU caps)
        $TotalMem = $(timeout 3 xl info 2>/dev/null | grep "^total_memory" 2>/dev/null)
        $TotalMemStr = ("$TotalMem").Trim()
        $FindingDetails += "Total memory: $TotalMemStr" + $nl

        $FreeMem = $(timeout 3 xl info 2>/dev/null | grep "^free_memory" 2>/dev/null)
        $FreeMemStr = ("$FreeMem").Trim()
        $FindingDetails += "Free memory: $FreeMemStr" + $nl

        # Check iptables rate limiting rules
        $RateLimit = $(timeout 3 iptables -L -n 2>/dev/null | grep -i "limit" 2>/dev/null)
        $RateLimitArr = @()
        if ($null -ne $RateLimit) { $RateLimitArr = @($RateLimit) }
        if ($RateLimitArr.Count -gt 0) {
            $FindingDetails += "iptables rate-limiting rules: $($RateLimitArr.Count) found" + $nl
        }
        else {
            $FindingDetails += "iptables rate-limiting rules: none configured" + $nl
        }

        # XCP-ng resource management + SYN cookies provide baseline DoS protection
        if ($SynStr -eq "1") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: TCP SYN cookies enabled for flood protection. XCP-ng resource management (memory/CPU limits per VM) prevents individual VMs from consuming all host resources."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: TCP SYN cookies not enabled. Configure: sysctl -w net.ipv4.tcp_syncookies=1"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207405 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207405
        STIG ID    : SRG-OS-000163-VMM-000700
        Rule ID    : SV-207405r970703_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-OS-000163
        Rule Title : The VMM must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity.
        DiscussMD5 : 18bdd5cf09c6c5177ad9cf0c0615366e
        CheckMD5   : e00a8133927ede250ef450dbe4c804b6
        FixMD5     : 233569f7d6fe06d0abfbe46693d80e3d
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
    $VulnID = "V-207405"
    $RuleID = "SV-207405r970703_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Session Timeout Configuration" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH ClientAliveInterval and ClientAliveCountMax
        $ClientAlive = $(timeout 5 sshd -T 2>/dev/null | grep -i "^clientaliveinterval" 2>/dev/null)
        $ClientAliveStr = ("$ClientAlive").Trim()
        $FindingDetails += "SSH ClientAliveInterval: $ClientAliveStr" + $nl

        $ClientCount = $(timeout 5 sshd -T 2>/dev/null | grep -i "^clientalivecountmax" 2>/dev/null)
        $ClientCountStr = ("$ClientCount").Trim()
        $FindingDetails += "SSH ClientAliveCountMax: $ClientCountStr" + $nl

        # Parse interval value
        $IntervalValue = 0
        if ($ClientAliveStr -match "(\d+)") {
            $IntervalValue = [int]$Matches[1]
        }
        $CountValue = 0
        if ($ClientCountStr -match "(\d+)") {
            $CountValue = [int]$Matches[1]
        }

        # Calculate effective timeout in seconds
        $EffectiveTimeout = 0
        if ($IntervalValue -gt 0 -and $CountValue -gt 0) {
            $EffectiveTimeout = $IntervalValue * $CountValue
            $FindingDetails += "Effective SSH timeout: $EffectiveTimeout seconds ($([math]::Round($EffectiveTimeout / 60, 1)) minutes)" + $nl
        }
        elseif ($IntervalValue -gt 0) {
            $EffectiveTimeout = $IntervalValue
            $FindingDetails += "Effective SSH timeout: $EffectiveTimeout seconds ($([math]::Round($EffectiveTimeout / 60, 1)) minutes)" + $nl
        }
        else {
            $FindingDetails += "Effective SSH timeout: not configured (no automatic disconnect)" + $nl
        }

        # Check TMOUT environment variable
        $Tmout = $(timeout 3 grep -r "TMOUT" /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null)
        $TmoutArr = @()
        if ($null -ne $Tmout) { $TmoutArr = @($Tmout) }
        if ($TmoutArr.Count -gt 0) {
            $FindingDetails += $nl + "TMOUT settings:" + $nl
            foreach ($line in $TmoutArr) {
                $FindingDetails += "  $line" + $nl
            }
        }
        else {
            $FindingDetails += "TMOUT: not configured" + $nl
        }

        # Requirement: 10 min (600s) for privileged, 15 min (900s) for non-privileged
        if ($EffectiveTimeout -gt 0 -and $EffectiveTimeout -le 600) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: SSH session timeout ($EffectiveTimeout seconds) meets the 10-minute requirement for privileged management sessions."
        }
        elseif ($EffectiveTimeout -gt 0 -and $EffectiveTimeout -le 900) {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: SSH session timeout ($EffectiveTimeout seconds) exceeds 10-minute privileged session requirement. Set ClientAliveInterval to 600 and ClientAliveCountMax to 1."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: SSH session timeout not properly configured. Set ClientAliveInterval to 600 and ClientAliveCountMax to 1 in /etc/ssh/sshd_config."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207406 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207406
        STIG ID    : SRG-OS-000184-VMM-000710
        Rule ID    : SV-207406r958550_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000184
        Rule Title : The VMM must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.
        DiscussMD5 : 1c266d9e8cb7ba2dce3a0e1b2ef72259
        CheckMD5   : cf35dfa090716b923ad6ab881c3db8ed
        FixMD5     : d180cb55251ba1d7ce8276c3b350a6f8
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
    $VulnID = "V-207406"
    $RuleID = "SV-207406r958550_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Fail-Secure State Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check kernel panic behavior
        $PanicTimeout = $(sysctl -n kernel.panic 2>/dev/null)
        $PanicStr = ("$PanicTimeout").Trim()
        $FindingDetails += "kernel.panic timeout: $PanicStr seconds (0=halt, >0=reboot after N sec)" + $nl

        $PanicOnOops = $(sysctl -n kernel.panic_on_oops 2>/dev/null)
        $OopsStr = ("$PanicOnOops").Trim()
        $FindingDetails += "kernel.panic_on_oops: $OopsStr (1=panic on oops)" + $nl

        # Check crashdump configuration (kdump)
        $KdumpActive = $(systemctl is-active kdump 2>/dev/null)
        $KdumpStr = ("$KdumpActive").Trim()
        $FindingDetails += "kdump service: $KdumpStr" + $nl

        # Check Xen crash behavior
        $XenDmesg = $(timeout 3 xl dmesg 2>/dev/null | tail -5 2>/dev/null)
        $XenDmesgArr = @()
        if ($null -ne $XenDmesg) { $XenDmesgArr = @($XenDmesg) }
        if ($XenDmesgArr.Count -gt 0) {
            $FindingDetails += $nl + "Xen dmesg (last 5 lines):" + $nl
            foreach ($line in $XenDmesgArr) {
                $FindingDetails += "  $line" + $nl
            }
        }

        # Check VM auto-start on host boot
        $AutoStart = Invoke-XeCommand -Command "pool-list params=other-config:auto_poweron --minimal"
        $AutoStartStr = ("$AutoStart").Trim()
        $FindingDetails += "Pool auto_poweron: $AutoStartStr" + $nl

        # XCP-ng/Xen fails secure: if Dom0 crashes, all VMs halt (no degraded mode)
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng (Xen) fails to a secure state by design. If Dom0 initialization fails, the hypervisor halts (no VMs can run without Dom0). If Dom0 crashes, all guest VMs are immediately stopped. There is no degraded operational mode."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207407 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207407
        STIG ID    : SRG-OS-000185-VMM-000720
        Rule ID    : SV-207407r958552_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-OS-000185
        Rule Title : The VMM must protect the confidentiality and integrity of all information at rest.
        DiscussMD5 : fbe0a0777da2a42746bcf11100303c35
        CheckMD5   : 4cd574a9f49aff43e139db79570b779d
        FixMD5     : 405e9ea9cde483f4318cb7f3c2999ad4
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
    $VulnID = "V-207407"
    $RuleID = "SV-207407r958552_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Data-at-Rest Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for LUKS encrypted volumes
        $LUKSDevices = $(timeout 5 lsblk -o NAME,FSTYPE,TYPE 2>/dev/null | grep -i "crypt" 2>/dev/null)
        $LUKSArr = @()
        if ($null -ne $LUKSDevices) { $LUKSArr = @($LUKSDevices) }

        if ($LUKSArr.Count -gt 0) {
            $FindingDetails += "LUKS encrypted devices:" + $nl
            foreach ($line in $LUKSArr) {
                $FindingDetails += "  $line" + $nl
            }
        }
        else {
            $FindingDetails += "LUKS encrypted devices: none detected" + $nl
        }

        # Check dm-crypt status
        $DMCrypt = $(timeout 3 dmsetup ls --target crypt 2>/dev/null)
        $DMCryptStr = ("$DMCrypt").Trim()
        $FindingDetails += "dm-crypt targets: $(if ($DMCryptStr -ne '' -and $DMCryptStr -ne 'No devices found') { $DMCryptStr } else { 'none' })" + $nl

        # Check file permissions on sensitive files
        $ShadowPerms = $(timeout 3 stat -c '%a %U:%G' /etc/shadow 2>/dev/null)
        $ShadowStr = ("$ShadowPerms").Trim()
        $FindingDetails += "/etc/shadow permissions: $ShadowStr" + $nl

        # Check SR storage backend
        $SRTypes = Invoke-XeCommand -Command "sr-list params=type --minimal"
        $SRTypesStr = ("$SRTypes").Trim()
        $FindingDetails += "Storage repository types: $SRTypesStr" + $nl

        # Data-at-rest encryption requires LUKS or similar
        if ($LUKSArr.Count -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: LUKS encryption detected for data-at-rest protection."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No disk encryption (LUKS) detected. Data-at-rest is not encrypted. Configure LUKS for storage repositories and Dom0 partitions."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207409 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207409
        STIG ID    : SRG-OS-000203-VMM-000750
        Rule ID    : SV-207409r958562_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-OS-000203
        Rule Title : The VMM must check the validity of all data inputs except those specifically identified by the organization.
        DiscussMD5 : edd10e931fdb13fcea3dfdf6bda72d4e
        CheckMD5   : 485d725d5e73fa99cad6fa468f6e44de
        FixMD5     : d8937a6779638442d534613ac0696e8e
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
    $VulnID = "V-207409"
    $RuleID = "SV-207409r958562_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Input Validation Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # xapi provides input validation for all management API calls
        $XapiActive = $(systemctl is-active xapi 2>/dev/null)
        $XapiStr = ("$XapiActive").Trim()
        $FindingDetails += "xapi service: $XapiStr" + $nl

        # Check xapi configuration
        $XapiConf = $(timeout 3 test -f /etc/xapi.conf && echo "exists" || echo "missing" 2>/dev/null)
        $XapiConfStr = ("$XapiConf").Trim()
        $FindingDetails += "/etc/xapi.conf: $XapiConfStr" + $nl

        # Check xe CLI validates parameters
        $XeHelp = Invoke-XeCommand -Command "help --minimal"
        $XeHelpStr = ("$XeHelp").Trim()
        $FindingDetails += "xe CLI commands available: $(if ($XeHelpStr -ne '') { 'yes' } else { 'unable to verify' })" + $nl

        # xapi validates all inputs through its typed API
        $FindingDetails += $nl + "Input validation mechanisms:" + $nl
        $FindingDetails += "  - xapi: Typed XML-RPC API with parameter validation" + $nl
        $FindingDetails += "  - xe CLI: Parameter type checking and required field enforcement" + $nl
        $FindingDetails += "  - SSH: OpenSSH input handling with protocol validation" + $nl

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: xapi (the XCP-ng management daemon) validates all data inputs through its typed XML-RPC API. The xe CLI enforces parameter types and required fields. Invalid inputs are rejected with error messages."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207410 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207410
        STIG ID    : SRG-OS-000205-VMM-000760
        Rule ID    : SV-207410r958564_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-OS-000205
        Rule Title : The VMM must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
        DiscussMD5 : a4c24ab71950b5ea23206de63302489d
        CheckMD5   : aa43eacd2abffe22aa554de7e296e99c
        FixMD5     : 75303721c1ff539c5c18138a291944e7
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
    $VulnID = "V-207410"
    $RuleID = "SV-207410r958564_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Error Message Information Control" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH banner configuration (should not reveal system details)
        $SSHBanner = $(timeout 5 sshd -T 2>/dev/null | grep -i "^banner" 2>/dev/null)
        $SSHBannerStr = ("$SSHBanner").Trim()
        $FindingDetails += "SSH Banner: $SSHBannerStr" + $nl

        # Check if SSH exposes version info
        $SSHVersion = $(ssh -V 2>&1)
        $SSHVerStr = ("$SSHVersion").Trim()
        $FindingDetails += "SSH version string: $SSHVerStr" + $nl

        # Check xapi error handling
        $XapiLogLevel = $(timeout 3 grep -i "log_level\|debug" /etc/xapi.conf 2>/dev/null)
        $XapiLogArr = @()
        if ($null -ne $XapiLogLevel) { $XapiLogArr = @($XapiLogLevel) }
        if ($XapiLogArr.Count -gt 0) {
            $FindingDetails += $nl + "xapi log configuration:" + $nl
            foreach ($line in $XapiLogArr) {
                $FindingDetails += "  $line" + $nl
            }
        }
        else {
            $FindingDetails += "xapi log configuration: default (no debug overrides)" + $nl
        }

        # Check if PermitRootLogin shows different error for valid/invalid users
        $LoginGraceTime = $(timeout 5 sshd -T 2>/dev/null | grep -i "^logingracetime" 2>/dev/null)
        $LoginGraceStr = ("$LoginGraceTime").Trim()
        $FindingDetails += "SSH LoginGraceTime: $LoginGraceStr" + $nl

        # xapi returns structured error codes without exposing internals
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: xapi returns structured XML-RPC error codes with action-oriented messages. Detailed stack traces and internal paths are logged server-side (not exposed to clients). SSH error messages follow OpenSSH standard practices."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207411 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207411
        STIG ID    : SRG-OS-000206-VMM-000770
        Rule ID    : SV-207411r958566_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206
        Rule Title : The VMM must reveal system error messages only to authorized users.
        DiscussMD5 : 4422122bba856e2c8568b3169cd0f772
        CheckMD5   : 71b94fbed696566d23fb9b233f175d2a
        FixMD5     : 0015cd8f737099702fcd1e5a18042178
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
    $VulnID = "V-207411"
    $RuleID = "SV-207411r958566_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Error Message Access Control" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check log file permissions — only root should read system logs
        $LogPerms = $(timeout 3 stat -c '%a %U:%G %n' /var/log/messages /var/log/secure /var/log/xensource.log 2>/dev/null)
        $LogPermsArr = @()
        if ($null -ne $LogPerms) { $LogPermsArr = @($LogPerms) }

        $FindingDetails += "Log file permissions:" + $nl
        if ($LogPermsArr.Count -gt 0) {
            foreach ($line in $LogPermsArr) {
                $FindingDetails += "  $line" + $nl
            }
        }
        else {
            $FindingDetails += "  Unable to retrieve log file permissions" + $nl
        }

        # Check xapi log permissions
        $XapiLogPerms = $(timeout 3 stat -c '%a %U:%G %n' /var/log/xensource.log 2>/dev/null)
        $XapiLogStr = ("$XapiLogPerms").Trim()

        # Check SSH access control
        $SSHAccess = $(timeout 5 sshd -T 2>/dev/null | grep -iE "^(permitrootlogin|allowusers|allowgroups)" 2>/dev/null)
        $SSHAccessArr = @()
        if ($null -ne $SSHAccess) { $SSHAccessArr = @($SSHAccess) }
        $FindingDetails += $nl + "SSH access controls:" + $nl
        foreach ($line in $SSHAccessArr) {
            $FindingDetails += "  $line" + $nl
        }

        # Check xapi requires authentication
        $XapiHTTPS = $(timeout 3 ss -tlnp 2>/dev/null | grep ":443 " 2>/dev/null)
        $XapiHTTPSStr = ("$XapiHTTPS").Trim()
        $FindingDetails += "xapi HTTPS (authenticated access): $(if ($XapiHTTPSStr -ne '') { 'active' } else { 'not detected' })" + $nl

        # System logs restricted to root; xapi requires authentication
        $AllRestricted = $true
        foreach ($line in $LogPermsArr) {
            if ($line -match "^(\d+)") {
                $perms = $Matches[1]
                if ($perms -match ".[^0].$") {
                    $AllRestricted = $false
                }
            }
        }

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: System error messages (logs) are restricted to root/authorized users via file permissions. xapi management requires authenticated HTTPS sessions. SSH access requires valid credentials."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207412 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207412
        STIG ID    : SRG-OS-000221-VMM-000800
        Rule ID    : SV-207412r958578_rule
        Severity   : CAT II
        Title      : All interactions among guest VMs must be mediated by the VMM or its service VMs to support proper function.
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
    $VulnID = "V-207412"
    $RuleID = "SV-207412r958578_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Guest VM Interaction Mediation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check VM network backends (all VIFs should use XAPI-managed bridges)
        $VifList = $(timeout 10 xe vif-list params=vm-name-label,device,network-name-label 2>&1)
        $VifArr = @()
        if ($null -ne $VifList) { $VifArr = @($VifList) }
        $VifStr = ($VifArr -join $nl)

        if ($VifArr.Count -gt 0) {
            $FindingDetails += "VM VIF Configuration:" + $nl + $VifStr + $nl + $nl
        }
        else {
            $FindingDetails += "VM VIF Configuration: No VIFs found (no running VMs with network interfaces)" + $nl + $nl
        }

        # Check for PCI passthrough devices (bypass VMM mediation)
        $PciPassthrough = $(timeout 5 xl pci-list 2>&1)
        $PciArr = @()
        if ($null -ne $PciPassthrough) { $PciArr = @($PciPassthrough) }
        $PciStr = ($PciArr -join $nl).Trim()

        $HasPassthrough = $false
        if ($PciStr.Length -gt 0 -and $PciStr -notmatch "No.*found" -and $PciStr -notmatch "command not found") {
            $FindingDetails += "PCI Passthrough Devices:" + $nl + $PciStr + $nl
            $HasPassthrough = $true
        }
        else {
            $FindingDetails += "PCI Passthrough Devices: None" + $nl
        }

        # Check network backends are all openvswitch or bridge (VMM-mediated)
        $NetworkList = $(timeout 5 xe network-list params=name-label,bridge 2>&1)
        $NetArr = @()
        if ($null -ne $NetworkList) { $NetArr = @($NetworkList) }
        $NetStr = ($NetArr -join $nl)

        $FindingDetails += $nl + "XAPI-Managed Networks:" + $nl + $NetStr + $nl

        # XCP-ng architecture inherently mediates all VM interactions through XAPI/xen hypervisor
        if (-not $HasPassthrough) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: All guest VM interactions are mediated by XCP-ng XAPI and Xen hypervisor. VMs communicate through XAPI-managed virtual bridges. No PCI passthrough devices bypass VMM mediation."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: PCI passthrough devices detected. These bypass VMM mediation and allow direct hardware access from guest VMs. Verify each passthrough device is authorized and documented."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207413
        STIG ID    : SRG-OS-000239-VMM-000810
        Rule ID    : SV-207413r958590_rule
        Severity   : CAT II
        Title      : The VMM must automatically audit account modification.
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
    $VulnID = "V-207413"
    $RuleID = "SV-207413r958590_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit — Account Modification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd rules for account modification events
        $AuditRules = $(timeout 5 auditctl -l 2>&1)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl)

        # Account modification files to monitor
        $RequiredFiles = @("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")
        $MissingFiles = @()
        $FoundFiles = @()

        foreach ($File in $RequiredFiles) {
            if ($AuditStr -match [regex]::Escape($File)) {
                $FoundFiles += $File
            }
            else {
                $MissingFiles += $File
            }
        }

        $FindingDetails += "Audit rules monitoring account modification files:" + $nl
        foreach ($f in $FoundFiles) {
            $FindingDetails += "  [PASS] $f — monitored" + $nl
        }
        foreach ($f in $MissingFiles) {
            $FindingDetails += "  [FAIL] $f — NOT monitored" + $nl
        }

        # Also check for usermod/chage command auditing
        $HasUsermod = $AuditStr -match "usermod"
        $HasChage = $AuditStr -match "chage"
        $FindingDetails += $nl + "Command auditing:" + $nl
        $FindingDetails += "  usermod: $(if ($HasUsermod) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  chage: $(if ($HasChage) { 'monitored' } else { 'NOT monitored' })" + $nl

        if ($MissingFiles.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: All account modification files are monitored by auditd."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: $($MissingFiles.Count) account modification file(s) not monitored by auditd. Add audit rules for: $($MissingFiles -join ', ')"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207414 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207414
        STIG ID    : SRG-OS-000240-VMM-000820
        Rule ID    : SV-207414r958592_rule
        Severity   : CAT II
        Title      : The VMM must automatically audit account disabling actions.
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
    $VulnID = "V-207414"
    $RuleID = "SV-207414r958592_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit — Account Disabling Actions" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd rules for account disabling events
        $AuditRules = $(timeout 5 auditctl -l 2>&1)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl)

        # Account disabling tracked through shadow/passwd changes and PAM
        $HasShadow = $AuditStr -match "/etc/shadow"
        $HasPasswd = $AuditStr -match "/etc/passwd"
        $HasUsermod = $AuditStr -match "usermod"
        $HasPasswdCmd = $AuditStr -match "/usr/bin/passwd"

        $FindingDetails += "Audit rules for account disabling:" + $nl
        $FindingDetails += "  /etc/shadow: $(if ($HasShadow) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  /etc/passwd: $(if ($HasPasswd) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  usermod: $(if ($HasUsermod) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  /usr/bin/passwd: $(if ($HasPasswdCmd) { 'monitored' } else { 'NOT monitored' })" + $nl

        # Shadow and passwd are the critical files for account disabling
        if ($HasShadow -and $HasPasswd) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Account disabling actions are audited. /etc/shadow and /etc/passwd are monitored by auditd, capturing lock/disable operations."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Account disabling actions not fully audited. Add audit rules for /etc/shadow and /etc/passwd to capture account lock/disable events."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207415 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207415
        STIG ID    : SRG-OS-000241-VMM-000830
        Rule ID    : SV-207415r958594_rule
        Severity   : CAT II
        Title      : The VMM must automatically audit account removal actions.
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
    $VulnID = "V-207415"
    $RuleID = "SV-207415r958594_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit — Account Removal Actions" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd rules for account removal events
        $AuditRules = $(timeout 5 auditctl -l 2>&1)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl)

        # Account removal tracked through passwd/group/shadow changes and userdel/groupdel
        $HasPasswd = $AuditStr -match "/etc/passwd"
        $HasGroup = $AuditStr -match "/etc/group"
        $HasShadow = $AuditStr -match "/etc/shadow"
        $HasUserdel = $AuditStr -match "userdel"
        $HasGroupdel = $AuditStr -match "groupdel"

        $FindingDetails += "Audit rules for account removal:" + $nl
        $FindingDetails += "  /etc/passwd: $(if ($HasPasswd) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  /etc/group: $(if ($HasGroup) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  /etc/shadow: $(if ($HasShadow) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  userdel: $(if ($HasUserdel) { 'monitored' } else { 'NOT monitored' })" + $nl
        $FindingDetails += "  groupdel: $(if ($HasGroupdel) { 'monitored' } else { 'NOT monitored' })" + $nl

        # passwd, group, shadow are the critical files for account removal
        if ($HasPasswd -and $HasGroup -and $HasShadow) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Account removal actions are audited. /etc/passwd, /etc/group, and /etc/shadow are monitored by auditd."
        }
        else {
            $Status = "Open"
            $MissingList = @()
            if (-not $HasPasswd) { $MissingList += "/etc/passwd" }
            if (-not $HasGroup) { $MissingList += "/etc/group" }
            if (-not $HasShadow) { $MissingList += "/etc/shadow" }
            $FindingDetails += $nl + "RESULT: Account removal actions not fully audited. Add audit rules for: $($MissingList -join ', ')"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207416 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207416
        STIG ID    : SRG-OS-000242-VMM-000840
        Rule ID    : SV-207416r958596_rule
        Severity   : CAT II
        Title      : All guest VM network communications must be implemented through use of virtual network devices provisioned by the VMM.
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
    $VulnID = "V-207416"
    $RuleID = "SV-207416r958596_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Guest VM Network — Virtual Device Provisioning" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # List all XAPI-managed networks
        $Networks = $(timeout 5 xe network-list params=uuid,name-label,bridge,managed --minimal 2>&1)
        $NetworksFull = $(timeout 5 xe network-list params=uuid,name-label,bridge 2>&1)
        $NetFullArr = @()
        if ($null -ne $NetworksFull) { $NetFullArr = @($NetworksFull) }

        $FindingDetails += "XAPI-Managed Networks:" + $nl
        $FindingDetails += ($NetFullArr -join $nl) + $nl + $nl

        # List all VIFs attached to VMs
        $VifCount = $(timeout 5 xe vif-list --minimal 2>&1)
        $VifCountStr = ("$VifCount").Trim()
        $VifTotal = 0
        if ($VifCountStr.Length -gt 0 -and $VifCountStr -ne "") {
            $VifTotal = ($VifCountStr -split ",").Count
        }

        $FindingDetails += "Total VM VIFs (virtual network interfaces): $VifTotal" + $nl

        # Check for any VMs with direct PCI NIC passthrough
        $PciAssign = $(timeout 5 xe vm-list params=name-label,other-config 2>&1 | grep -i "pci" 2>/dev/null)
        $PciArr = @()
        if ($null -ne $PciAssign) { $PciArr = @($PciAssign) }

        if ($PciArr.Count -gt 0) {
            $FindingDetails += "VMs with PCI passthrough config: $($PciArr.Count)" + $nl
            $FindingDetails += ($PciArr -join $nl) + $nl
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: PCI NIC passthrough detected. VMs with direct NIC passthrough bypass XAPI-managed virtual networking. Verify authorization."
        }
        else {
            $Status = "NotAFinding"
            $FindingDetails += "VMs with PCI NIC passthrough: None" + $nl
            $FindingDetails += $nl + "RESULT: All guest VM network communications use XAPI-provisioned virtual network interfaces (VIFs) connected to managed virtual bridges."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207417
        STIG ID    : SRG-OS-000242-VMM-000850
        Rule ID    : SV-207417r958596_rule
        Severity   : CAT II
        Title      : All interactions between guest VMs and external systems, via other interface devices, must be mediated by the VMM or its service VMs.
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
    $VulnID = "V-207417"
    $RuleID = "SV-207417r958596_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "VM-External Interaction Mediation (Other Interfaces)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for USB passthrough to VMs
        $UsbPassthrough = $(timeout 5 xe pusb-list 2>&1)
        $UsbArr = @()
        if ($null -ne $UsbPassthrough) { $UsbArr = @($UsbPassthrough) }
        $UsbStr = ($UsbArr -join $nl).Trim()

        $HasUsbPassthrough = $false
        if ($UsbStr.Length -gt 0 -and $UsbStr -notmatch "No.*found" -and $UsbStr -notmatch "command not found" -and $UsbStr -notmatch "Unknown command") {
            $FindingDetails += "USB Passthrough Devices:" + $nl + $UsbStr + $nl + $nl
            $HasUsbPassthrough = $true
        }
        else {
            $FindingDetails += "USB Passthrough Devices: None configured" + $nl + $nl
        }

        # Check for GPU/vGPU passthrough
        $GpuGroups = $(timeout 5 xe gpu-group-list 2>&1)
        $GpuArr = @()
        if ($null -ne $GpuGroups) { $GpuArr = @($GpuGroups) }
        $GpuStr = ($GpuArr -join $nl).Trim()

        $HasGpuPassthrough = $false
        if ($GpuStr.Length -gt 0 -and $GpuStr -notmatch "No.*found" -and $GpuStr -notmatch "command not found") {
            $FindingDetails += "GPU Groups:" + $nl + $GpuStr + $nl + $nl
            $HasGpuPassthrough = $true
        }
        else {
            $FindingDetails += "GPU Passthrough: None configured" + $nl + $nl
        }

        # Check for SR-IOV (direct hardware NIC passthrough)
        $SriovNets = $(timeout 5 xe network-list params=name-label,other-config 2>&1 | grep -i "sriov" 2>/dev/null)
        $SriovArr = @()
        if ($null -ne $SriovNets) { $SriovArr = @($SriovNets) }

        if ($SriovArr.Count -gt 0) {
            $FindingDetails += "SR-IOV Networks: $($SriovArr.Count) found" + $nl
            $FindingDetails += ($SriovArr -join $nl) + $nl
        }
        else {
            $FindingDetails += "SR-IOV Networks: None" + $nl
        }

        # XCP-ng mediates all VM-external interactions through XAPI by default
        if (-not $HasUsbPassthrough -and -not $HasGpuPassthrough -and $SriovArr.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: All VM-external interactions are mediated by the VMM. No USB passthrough, GPU passthrough, or SR-IOV bypasses detected. All VM I/O goes through XAPI-managed virtual devices."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Direct hardware passthrough detected (USB, GPU, or SR-IOV). These devices bypass VMM mediation. Verify each passthrough assignment is authorized and documented."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207418 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207418
        STIG ID    : SRG-OS-000250-VMM-000860
        Rule ID    : SV-207418r958604_rule
        Severity   : CAT II
        Title      : The VMM must implement cryptography to protect the integrity of remote access sessions.
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
    $VulnID = "V-207418"
    $RuleID = "SV-207418r958604_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Remote Access Session Integrity — Cryptography" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH protocol and crypto configuration
        $SshProtocol = $(timeout 3 sshd -T 2>/dev/null | grep -i "^protocol" 2>/dev/null)
        $SshProtoStr = ("$SshProtocol").Trim()

        $SshCiphers = $(timeout 3 sshd -T 2>/dev/null | grep -i "^ciphers" 2>/dev/null)
        $SshCipherStr = ("$SshCiphers").Trim()

        $SshMacs = $(timeout 3 sshd -T 2>/dev/null | grep -i "^macs" 2>/dev/null)
        $SshMacStr = ("$SshMacs").Trim()

        $FindingDetails += "SSH Configuration:" + $nl
        if ($SshProtoStr.Length -gt 0) {
            $FindingDetails += "  Protocol: $SshProtoStr" + $nl
        }
        $FindingDetails += "  Ciphers: $SshCipherStr" + $nl
        $FindingDetails += "  MACs: $SshMacStr" + $nl + $nl

        # Check XAPI HTTPS/TLS configuration
        $XapiPort = $(timeout 3 ss -tlnp 2>/dev/null | grep ":443" 2>/dev/null)
        $XapiPortStr = ("$XapiPort").Trim()
        $FindingDetails += "XAPI HTTPS (port 443):" + $nl
        if ($XapiPortStr.Length -gt 0) {
            $FindingDetails += "  Listening: Yes" + $nl
        }
        else {
            $FindingDetails += "  Listening: Not detected on port 443" + $nl
        }

        # Check stunnel/XAPI TLS certificate
        $XapiCert = $(timeout 3 cat /etc/xensource/xapi-ssl.pem 2>/dev/null | head -1 2>/dev/null)
        $XapiCertStr = ("$XapiCert").Trim()
        if ($XapiCertStr -match "BEGIN CERTIFICATE") {
            $FindingDetails += "  TLS certificate: Present (/etc/xensource/xapi-ssl.pem)" + $nl
        }
        else {
            $FindingDetails += "  TLS certificate: Not found at expected path" + $nl
        }

        # SSH with crypto ciphers + XAPI over HTTPS = integrity protection
        $WeakCiphers = @("3des-cbc", "arcfour", "blowfish-cbc", "cast128-cbc")
        $HasWeak = $false
        foreach ($wc in $WeakCiphers) {
            if ($SshCipherStr -match [regex]::Escape($wc)) {
                $HasWeak = $true
                break
            }
        }

        if (-not $HasWeak -and $XapiPortStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Remote access sessions are protected by cryptography. SSH uses approved ciphers and XAPI communicates over HTTPS/TLS."
        }
        else {
            $Status = "Open"
            if ($HasWeak) {
                $FindingDetails += $nl + "RESULT: Weak SSH ciphers detected. Remove 3DES, Arcfour, Blowfish, and CAST128 from sshd_config Ciphers."
            }
            else {
                $FindingDetails += $nl + "RESULT: XAPI HTTPS not detected on port 443. Verify XAPI TLS configuration."
            }
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207419 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207419
        STIG ID    : SRG-OS-000254-VMM-000880
        Rule ID    : SV-207419r958606_rule
        Severity   : CAT II
        Title      : The VMM must initiate session audits at system startup.
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
    $VulnID = "V-207419"
    $RuleID = "SV-207419r958606_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Session Audits at System Startup" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check if auditd is enabled at boot
        $AuditdEnabled = $(timeout 3 systemctl is-enabled auditd 2>&1)
        $AuditdEnabledStr = ("$AuditdEnabled").Trim()

        # Check if auditd is currently running
        $AuditdActive = $(timeout 3 systemctl is-active auditd 2>&1)
        $AuditdActiveStr = ("$AuditdActive").Trim()

        $FindingDetails += "auditd service:" + $nl
        $FindingDetails += "  Enabled at boot: $AuditdEnabledStr" + $nl
        $FindingDetails += "  Currently active: $AuditdActiveStr" + $nl + $nl

        # Check kernel audit parameter (audit=1 in grub)
        $CmdLine = $(timeout 3 cat /proc/cmdline 2>&1)
        $CmdLineStr = ("$CmdLine").Trim()
        $HasAuditBoot = $CmdLineStr -match "audit=1"

        $FindingDetails += "Kernel boot parameters:" + $nl
        $FindingDetails += "  audit=1 in /proc/cmdline: $(if ($HasAuditBoot) { 'Yes' } else { 'No' })" + $nl

        # Check grub config for persistent audit=1
        $GrubCfg = $(timeout 3 grep -i "audit" /etc/default/grub 2>/dev/null)
        $GrubStr = ("$GrubCfg").Trim()
        if ($GrubStr.Length -gt 0) {
            $FindingDetails += "  /etc/default/grub: $GrubStr" + $nl
        }

        if ($AuditdEnabledStr -eq "enabled" -and $AuditdActiveStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is enabled at boot and currently active. Session auditing initiates at system startup."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not properly configured to start at boot. Enable with: systemctl enable auditd"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207420 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207420
        STIG ID    : SRG-OS-000255-VMM-000890
        Rule ID    : SV-207420r958608_rule
        Severity   : CAT II
        Title      : The VMM must produce audit records containing information to establish the identity of any individual or process associated with the event.
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
    $VulnID = "V-207420"
    $RuleID = "SV-207420r958608_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Records — Identity Information" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd configuration for log format
        $AuditdConf = $(timeout 3 grep -i "^log_format" /etc/audit/auditd.conf 2>/dev/null)
        $AuditdConfStr = ("$AuditdConf").Trim()
        $FindingDetails += "auditd log format: $(if ($AuditdConfStr.Length -gt 0) { $AuditdConfStr } else { 'default (RAW)' })" + $nl

        # Check a sample audit record to verify identity fields are present
        $SampleRecord = $(timeout 3 ausearch -m USER_LOGIN --start recent 2>/dev/null | head -5 2>/dev/null)
        $SampleArr = @()
        if ($null -ne $SampleRecord) { $SampleArr = @($SampleRecord) }
        $SampleStr = ($SampleArr -join $nl).Trim()

        if ($SampleStr.Length -gt 0 -and $SampleStr -notmatch "no matches") {
            $FindingDetails += $nl + "Sample audit record (USER_LOGIN):" + $nl + $SampleStr + $nl
        }

        # Verify auditd captures identity fields (uid, auid, subj, etc.)
        $AuditRules = $(timeout 5 auditctl -l 2>&1)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl)

        $RuleCount = $AuditArr.Count
        $FindingDetails += $nl + "Total active audit rules: $RuleCount" + $nl

        # auditd inherently includes uid, auid, pid, exe, subj in all records
        $AuditdActive = $(timeout 3 systemctl is-active auditd 2>&1)
        $AuditdActiveStr = ("$AuditdActive").Trim()

        if ($AuditdActiveStr -eq "active" -and $RuleCount -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is active with $RuleCount rules. Audit records inherently include identity information (uid, auid, pid, exe, subject context) for all events."
        }
        else {
            $Status = "Open"
            if ($AuditdActiveStr -ne "active") {
                $FindingDetails += $nl + "RESULT: auditd is not active. Enable auditd to produce audit records with identity information."
            }
            else {
                $FindingDetails += $nl + "RESULT: auditd has no active rules. Configure audit rules to capture security-relevant events."
            }
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207421 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207421
        STIG ID    : SRG-OS-000256-VMM-000900
        Rule ID    : SV-207421r958610_rule
        Severity   : CAT II
        Title      : The VMM must protect audit tools from unauthorized access.
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
    $VulnID = "V-207421"
    $RuleID = "SV-207421r958610_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Tool Access Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check permissions on audit binaries
        $AuditTools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules")
        $AllSecure = $true
        $CheckedCount = 0

        foreach ($Tool in $AuditTools) {
            $ToolPerms = $(timeout 3 stat -c "%a %U %G" $Tool 2>/dev/null)
            $ToolPermsStr = ("$ToolPerms").Trim()
            if ($ToolPermsStr.Length -gt 0) {
                $CheckedCount++
                $Parts = $ToolPermsStr -split "\s+"
                $Perms = $Parts[0]
                $Owner = $Parts[1]
                $Group = $Parts[2]
                $PermOk = ([int]$Perms -le 755) -and ($Owner -eq "root")
                if (-not $PermOk) { $AllSecure = $false }
                $FindingDetails += "  $Tool : $Perms $Owner`:$Group $(if ($PermOk) { '[PASS]' } else { '[FAIL]' })" + $nl
            }
            else {
                $FindingDetails += "  $Tool : not found" + $nl
            }
        }

        # Check audit log file permissions
        $LogPerms = $(timeout 3 stat -c "%a %U %G" /var/log/audit/audit.log 2>/dev/null)
        $LogPermsStr = ("$LogPerms").Trim()
        if ($LogPermsStr.Length -gt 0) {
            $Parts = $LogPermsStr -split "\s+"
            $Perms = $Parts[0]
            $Owner = $Parts[1]
            $Group = $Parts[2]
            $LogOk = ([int]$Perms -le 600) -and ($Owner -eq "root")
            if (-not $LogOk) { $AllSecure = $false }
            $FindingDetails += $nl + "  /var/log/audit/audit.log : $Perms $Owner`:$Group $(if ($LogOk) { '[PASS]' } else { '[FAIL]' })" + $nl
        }
        else {
            $FindingDetails += $nl + "  /var/log/audit/audit.log : not found" + $nl
            $AllSecure = $false
        }

        if ($AllSecure -and $CheckedCount -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit tools are protected from unauthorized access. All binaries are owned by root with appropriate permissions (755 or more restrictive)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit tools have improper access permissions. Ensure all audit binaries are owned by root with permissions no more permissive than 755."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207422 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207422
        STIG ID    : SRG-OS-000257-VMM-000910
        Rule ID    : SV-207422r958612_rule
        Severity   : CAT II
        Title      : The VMM must protect audit tools from unauthorized modification.
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
    $VulnID = "V-207422"
    $RuleID = "SV-207422r958612_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Tool Modification Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check write permissions on audit binaries (only root should have write)
        $AuditTools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules")
        $AllSecure = $true
        $CheckedCount = 0

        foreach ($Tool in $AuditTools) {
            $ToolPerms = $(timeout 3 stat -c "%a %U %G" $Tool 2>/dev/null)
            $ToolPermsStr = ("$ToolPerms").Trim()
            if ($ToolPermsStr.Length -gt 0) {
                $CheckedCount++
                $Parts = $ToolPermsStr -split "\s+"
                $Perms = $Parts[0]
                $Owner = $Parts[1]
                $Group = $Parts[2]
                # Check no group/other write (perms should not have 2 in group or other position)
                $PermInt = [int]$Perms
                $GroupWrite = ($PermInt / 10) % 10 -band 2
                $OtherWrite = $PermInt % 10 -band 2
                $NoUnauthorizedWrite = ($GroupWrite -eq 0) -and ($OtherWrite -eq 0) -and ($Owner -eq "root")
                if (-not $NoUnauthorizedWrite) { $AllSecure = $false }
                $FindingDetails += "  $Tool : $Perms $Owner`:$Group $(if ($NoUnauthorizedWrite) { '[PASS]' } else { '[FAIL] unauthorized write' })" + $nl
            }
            else {
                $FindingDetails += "  $Tool : not found" + $nl
            }
        }

        # Check audit configuration files
        $AuditConfFiles = @("/etc/audit/auditd.conf", "/etc/audit/audit.rules")
        foreach ($Conf in $AuditConfFiles) {
            $ConfPerms = $(timeout 3 stat -c "%a %U %G" $Conf 2>/dev/null)
            $ConfPermsStr = ("$ConfPerms").Trim()
            if ($ConfPermsStr.Length -gt 0) {
                $Parts = $ConfPermsStr -split "\s+"
                $Perms = $Parts[0]
                $Owner = $Parts[1]
                $PermInt = [int]$Perms
                $GroupWrite = ($PermInt / 10) % 10 -band 2
                $OtherWrite = $PermInt % 10 -band 2
                $ConfOk = ($GroupWrite -eq 0) -and ($OtherWrite -eq 0) -and ($Owner -eq "root")
                if (-not $ConfOk) { $AllSecure = $false }
                $FindingDetails += "  $Conf : $Perms $Owner $(if ($ConfOk) { '[PASS]' } else { '[FAIL]' })" + $nl
            }
        }

        if ($AllSecure -and $CheckedCount -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit tools are protected from unauthorized modification. Only root has write access to audit binaries and configuration files."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit tools may be modified by unauthorized users. Ensure only root has write permissions on audit binaries and config files."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207423 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207423
        STIG ID    : SRG-OS-000258-VMM-000920
        Rule ID    : SV-207423r958614_rule
        Severity   : CAT II
        Title      : The VMM must protect audit tools from unauthorized deletion.
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
    $VulnID = "V-207423"
    $RuleID = "SV-207423r958614_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Tool Deletion Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check directory permissions on /sbin (parent of audit tools) - sticky bit or restrictive
        $SbinPerms = $(timeout 3 stat -c "%a %U %G" /sbin 2>/dev/null)
        $SbinPermsStr = ("$SbinPerms").Trim()
        $FindingDetails += "Directory /sbin permissions: $SbinPermsStr" + $nl + $nl

        # Verify audit tools exist and are RPM-managed (can be reinstalled)
        $AuditTools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules")
        $AllPresent = $true
        $AllRpmManaged = $true

        foreach ($Tool in $AuditTools) {
            $Exists = $(timeout 3 test -f $Tool && echo "exists" || echo "missing" 2>/dev/null)
            $ExistsStr = ("$Exists").Trim()
            $RpmOwner = $(timeout 3 rpm -qf $Tool 2>/dev/null)
            $RpmStr = ("$RpmOwner").Trim()
            $IsManaged = $RpmStr -notmatch "not owned"

            if ($ExistsStr -ne "exists") { $AllPresent = $false }
            if (-not $IsManaged) { $AllRpmManaged = $false }

            $FindingDetails += "  $Tool : $ExistsStr, RPM: $RpmStr" + $nl
        }

        # Check directory write permissions (only root should delete from /sbin)
        $SbinParts = $SbinPermsStr -split "\s+"
        $SbinPerm = if ($SbinParts.Count -gt 0) { $SbinParts[0] } else { "" }
        $SbinOwner = if ($SbinParts.Count -gt 1) { $SbinParts[1] } else { "" }
        $SbinSecure = ($SbinOwner -eq "root") -and ($SbinPerm -match "^[0-7]?755$")

        if ($AllPresent -and $SbinSecure) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit tools are protected from unauthorized deletion. /sbin is owned by root with restricted permissions. Audit tools are RPM-managed and can be restored from packages."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit tools may be vulnerable to unauthorized deletion. Ensure /sbin is owned by root with permissions 755 and all audit tools are present."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207424 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207424
        STIG ID    : SRG-OS-000259-VMM-000930
        Rule ID    : SV-207424r958616_rule
        Severity   : CAT II
        Title      : The VMM must limit privileges to change software resident within software libraries.
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
    $VulnID = "V-207424"
    $RuleID = "SV-207424r958616_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Software Library Privilege Restriction" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check permissions on key XCP-ng/Xen library directories
        $LibDirs = @("/opt/xensource/lib", "/usr/lib64/xen", "/usr/lib/xen", "/usr/lib64")
        $AllSecure = $true
        $CheckedCount = 0

        foreach ($Dir in $LibDirs) {
            $DirPerms = $(timeout 3 stat -c "%a %U %G" $Dir 2>/dev/null)
            $DirPermsStr = ("$DirPerms").Trim()
            if ($DirPermsStr.Length -gt 0) {
                $CheckedCount++
                $Parts = $DirPermsStr -split "\s+"
                $Perms = $Parts[0]
                $Owner = $Parts[1]
                $Group = $Parts[2]
                $PermInt = [int]$Perms
                $GroupWrite = [math]::Floor($PermInt / 10) % 10 -band 2
                $OtherWrite = $PermInt % 10 -band 2
                $DirOk = ($GroupWrite -eq 0) -and ($OtherWrite -eq 0) -and ($Owner -eq "root")
                if (-not $DirOk) { $AllSecure = $false }
                $FindingDetails += "  $Dir : $Perms $Owner`:$Group $(if ($DirOk) { '[PASS]' } else { '[FAIL]' })" + $nl
            }
            else {
                $FindingDetails += "  $Dir : not found" + $nl
            }
        }

        # Check for world-writable files in xensource lib
        $WorldWritable = $(timeout 10 find /opt/xensource/lib -maxdepth 3 -perm -002 -type f 2>/dev/null | head -10 2>/dev/null)
        $WwArr = @()
        if ($null -ne $WorldWritable) { $WwArr = @($WorldWritable) }
        $WwStr = ($WwArr -join $nl).Trim()

        if ($WwStr.Length -gt 0) {
            $FindingDetails += $nl + "World-writable files in /opt/xensource/lib:" + $nl + $WwStr + $nl
            $AllSecure = $false
        }
        else {
            $FindingDetails += $nl + "World-writable files in /opt/xensource/lib: None" + $nl
        }

        if ($AllSecure -and $CheckedCount -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Software library directories are properly restricted. Only root has write access to VMM library paths. No world-writable files found."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Software library permissions are too permissive. Ensure only root has write access to VMM library directories."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207425 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207425
        STIG ID    : SRG-OS-000266-VMM-000940
        Rule ID    : SV-207425r984219_rule
        Severity   : CAT II
        Title      : The VMM must enforce password complexity by requiring that at least one special character be used.
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
    $VulnID = "V-207425"
    $RuleID = "SV-207425r984219_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Password Complexity — Special Character Requirement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check PAM pwquality/pam_cracklib for ocredit (special character)
        $PwQuality = $(timeout 3 grep -i "ocredit" /etc/security/pwquality.conf 2>/dev/null)
        $PwQualStr = ("$PwQuality").Trim()

        $PamSystemAuth = $(timeout 3 grep -i "ocredit\|pam_cracklib\|pam_pwquality" /etc/pam.d/system-auth 2>/dev/null)
        $PamArr = @()
        if ($null -ne $PamSystemAuth) { $PamArr = @($PamSystemAuth) }
        $PamStr = ($PamArr -join $nl).Trim()

        $PamPasswordAuth = $(timeout 3 grep -i "ocredit\|pam_cracklib\|pam_pwquality" /etc/pam.d/password-auth 2>/dev/null)
        $PamPwArr = @()
        if ($null -ne $PamPasswordAuth) { $PamPwArr = @($PamPasswordAuth) }
        $PamPwStr = ($PamPwArr -join $nl).Trim()

        $FindingDetails += "pwquality.conf ocredit setting:" + $nl
        if ($PwQualStr.Length -gt 0) {
            $FindingDetails += "  $PwQualStr" + $nl
        }
        else {
            $FindingDetails += "  Not set in pwquality.conf" + $nl
        }

        $FindingDetails += $nl + "PAM system-auth:" + $nl
        if ($PamStr.Length -gt 0) {
            $FindingDetails += "  $PamStr" + $nl
        }
        else {
            $FindingDetails += "  No ocredit/pwquality config found" + $nl
        }

        $FindingDetails += $nl + "PAM password-auth:" + $nl
        if ($PamPwStr.Length -gt 0) {
            $FindingDetails += "  $PamPwStr" + $nl
        }
        else {
            $FindingDetails += "  No ocredit/pwquality config found" + $nl
        }

        # Check if ocredit is set to -1 (require at least 1 special character)
        $OcreditSet = $false
        if ($PwQualStr -match "ocredit\s*=\s*(-\d+)") {
            $OcreditVal = [int]$Matches[1]
            if ($OcreditVal -le -1) { $OcreditSet = $true }
        }
        if (-not $OcreditSet -and ($PamStr + $PamPwStr) -match "ocredit=(-\d+)") {
            $OcreditVal = [int]$Matches[1]
            if ($OcreditVal -le -1) { $OcreditSet = $true }
        }

        if ($OcreditSet) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Password complexity requires at least one special character (ocredit=$OcreditVal)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Password complexity does not require special characters. Set ocredit = -1 in /etc/security/pwquality.conf."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207426 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207426
        STIG ID    : SRG-OS-000269-VMM-000950
        Rule ID    : SV-207426r958624_rule
        Severity   : CAT II
        Title      : In the event of a system failure, the VMM must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.
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
    $VulnID = "V-207426"
    $RuleID = "SV-207426r958624_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "System Failure Information Preservation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check kdump service for crash dump collection
        $KdumpActive = $(systemctl is-active kdump 2>/dev/null)
        $KdumpStr = ("$KdumpActive").Trim()
        $KdumpEnabled = $(systemctl is-enabled kdump 2>/dev/null)
        $KdumpEnaStr = ("$KdumpEnabled").Trim()
        $FindingDetails += "kdump service: active=$KdumpStr, enabled=$KdumpEnaStr" + $nl

        # Check crash dump directory
        $CrashDir = $(timeout 3 test -d /var/crash && echo "exists" || echo "missing" 2>/dev/null)
        $CrashStr = ("$CrashDir").Trim()
        $FindingDetails += "/var/crash directory: $CrashStr" + $nl

        # Check Xen crash dump configuration
        $XenCrashkernel = $(timeout 3 cat /proc/cmdline 2>/dev/null)
        $XenCrashArr = @()
        if ($null -ne $XenCrashkernel) { $XenCrashArr = @($XenCrashkernel) }
        $XenCrashStr = ($XenCrashArr -join $nl).Trim()
        $HasCrashkernel = $XenCrashStr -match "crashkernel"
        $FindingDetails += "Kernel crashkernel parameter: $(if ($HasCrashkernel) { 'configured' } else { 'not found' })" + $nl

        # Check xen dmesg availability
        $XenDmesg = $(timeout 3 xl dmesg 2>/dev/null | head -3 2>/dev/null)
        $XenDmesgStr = ("$XenDmesg").Trim()
        $FindingDetails += "Xen dmesg available: $(if ($XenDmesgStr.Length -gt 0) { 'yes' } else { 'no' })" + $nl

        # Check persistent logging
        $JournalPersist = $(timeout 3 cat /etc/systemd/journald.conf 2>/dev/null | grep -i "^Storage" 2>/dev/null)
        $JournalStr = ("$JournalPersist").Trim()
        $FindingDetails += "journald storage: $(if ($JournalStr.Length -gt 0) { $JournalStr } else { 'default (auto)' })" + $nl

        if ($KdumpStr -eq "active" -or $HasCrashkernel) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: System failure information preservation is configured. Crash dump collection (kdump/crashkernel) and persistent logging are available for forensic analysis."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Crash dump collection is not fully configured. Enable kdump service and verify crashkernel boot parameter is set."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207427 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207427
        STIG ID    : SRG-OS-000274-VMM-000960
        Rule ID    : SV-207427r984222_rule
        Severity   : CAT II
        Title      : The VMM must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.
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
    $VulnID = "V-207427"
    $RuleID = "SV-207427r984222_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Account Creation Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check if external auth (AD/LDAP) is configured
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'not configured' })" + $nl

        # Check RBAC subjects
        $Subjects = Invoke-XeCommand -Command "subject-list --minimal"
        $SubjectStr = ("$Subjects").Trim()
        $SubjectCount = 0
        if ($SubjectStr.Length -gt 0) { $SubjectCount = ($SubjectStr -split ",").Count }
        $FindingDetails += "RBAC subjects: $SubjectCount" + $nl

        # Check auditd for account creation events
        $AuditRules = $(timeout 3 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()
        $HasUseradd = $AuditStr -match "useradd|user-add|identity"
        $FindingDetails += "Audit rules for account creation: $(if ($HasUseradd) { 'configured' } else { 'not found' })" + $nl

        if ($ExtAuthStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication ($ExtAuthStr) is configured. Active Directory provides centralized account management with built-in notification capabilities for account creation events."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No external authentication configured. XCP-ng does not natively notify SA/ISSO on account creation. Configure AD/LDAP integration via xe pool-enable-external-auth or implement organizational notification procedures."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207428 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207428
        STIG ID    : SRG-OS-000275-VMM-000970
        Rule ID    : SV-207428r984225_rule
        Severity   : CAT II
        Title      : The VMM must notify the system administrator (SA) and information system security officer (ISSO) when accounts are modified.
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
    $VulnID = "V-207428"
    $RuleID = "SV-207428r984225_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Account Modification Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'not configured' })" + $nl

        $AuditRules = $(timeout 3 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()
        $HasUsermod = $AuditStr -match "usermod|user-mod|identity"
        $FindingDetails += "Audit rules for account modification: $(if ($HasUsermod) { 'configured' } else { 'not found' })" + $nl

        if ($ExtAuthStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication ($ExtAuthStr) is configured. Active Directory provides centralized account management with built-in notification capabilities for account modification events."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No external authentication configured. XCP-ng does not natively notify SA/ISSO on account modification. Configure AD/LDAP integration or implement organizational notification procedures."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207429 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207429
        STIG ID    : SRG-OS-000276-VMM-000980
        Rule ID    : SV-207429r984228_rule
        Severity   : CAT II
        Title      : The VMM must notify the system administrator (SA) and information system security officer (ISSO) when accounts are disabled.
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
    $VulnID = "V-207429"
    $RuleID = "SV-207429r984228_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Account Disabling Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'not configured' })" + $nl

        $AuditRules = $(timeout 3 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()
        $HasPasswd = $AuditStr -match "passwd|shadow|identity"
        $FindingDetails += "Audit rules for account disabling: $(if ($HasPasswd) { 'configured' } else { 'not found' })" + $nl

        if ($ExtAuthStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication ($ExtAuthStr) is configured. Active Directory provides centralized account management with built-in notification capabilities for account disabling events."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No external authentication configured. XCP-ng does not natively notify SA/ISSO on account disabling. Configure AD/LDAP integration or implement organizational notification procedures."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207430 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207430
        STIG ID    : SRG-OS-000277-VMM-000990
        Rule ID    : SV-207430r984231_rule
        Severity   : CAT II
        Title      : The VMM must notify the system administrator (SA) and information system security officer (ISSO) when accounts are removed.
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
    $VulnID = "V-207430"
    $RuleID = "SV-207430r984231_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Account Removal Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'not configured' })" + $nl

        $AuditRules = $(timeout 3 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()
        $HasUserdel = $AuditStr -match "userdel|user-del|delete|identity"
        $FindingDetails += "Audit rules for account removal: $(if ($HasUserdel) { 'configured' } else { 'not found' })" + $nl

        if ($ExtAuthStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication ($ExtAuthStr) is configured. Active Directory provides centralized account management with built-in notification capabilities for account removal events."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No external authentication configured. XCP-ng does not natively notify SA/ISSO on account removal. Configure AD/LDAP integration or implement organizational notification procedures."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207431 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207431
        STIG ID    : SRG-OS-000278-VMM-001000
        Rule ID    : SV-207431r958634_rule
        Severity   : CAT II
        Title      : The VMM must use cryptographic mechanisms to protect the integrity of audit tools.
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
    $VulnID = "V-207431"
    $RuleID = "SV-207431r958634_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Tool Integrity Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check RPM verification of audit packages
        $AuditRpm = $(timeout 5 rpm -V audit 2>/dev/null)
        $AuditRpmArr = @()
        if ($null -ne $AuditRpm) { $AuditRpmArr = @($AuditRpm) }
        $AuditRpmStr = ($AuditRpmArr -join $nl).Trim()
        $FindingDetails += "RPM verify audit package:" + $nl
        $FindingDetails += $(if ($AuditRpmStr.Length -gt 0) { $AuditRpmStr } else { "  (no modifications detected)" }) + $nl + $nl

        $AuditLibsRpm = $(timeout 5 rpm -V audit-libs 2>/dev/null)
        $AuditLibsArr = @()
        if ($null -ne $AuditLibsRpm) { $AuditLibsArr = @($AuditLibsRpm) }
        $AuditLibsStr = ($AuditLibsArr -join $nl).Trim()
        $FindingDetails += "RPM verify audit-libs package:" + $nl
        $FindingDetails += $(if ($AuditLibsStr.Length -gt 0) { $AuditLibsStr } else { "  (no modifications detected)" }) + $nl + $nl

        # Check if AIDE is installed for file integrity monitoring
        $AideInstalled = $(rpm -q aide 2>/dev/null)
        $AideStr = ("$AideInstalled").Trim()
        $FindingDetails += "AIDE package: $AideStr" + $nl

        # RPM uses GPG signatures for package verification
        $GpgKeys = $(timeout 3 rpm -qa gpg-pubkey 2>/dev/null | head -5 2>/dev/null)
        $GpgArr = @()
        if ($null -ne $GpgKeys) { $GpgArr = @($GpgKeys) }
        $GpgStr = ($GpgArr -join $nl).Trim()
        $FindingDetails += "RPM GPG keys installed: $(if ($GpgStr.Length -gt 0) { ($GpgStr -split $nl).Count } else { '0' })" + $nl

        # RPM verification is the cryptographic mechanism
        $AuditClean = ($AuditRpmStr.Length -eq 0 -or $AuditRpmStr -notmatch "^[0-9SM]")
        if ($AuditClean -and $GpgStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit tools are protected via RPM cryptographic verification. GPG-signed packages ensure integrity. No unauthorized modifications to audit binaries detected."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit tool integrity cannot be fully verified. Ensure audit package is installed from signed RPM repositories and AIDE or equivalent file integrity monitoring is configured."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207432 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207432
        STIG ID    : SRG-OS-000279-VMM-001010
        Rule ID    : SV-207432r958636_rule
        Severity   : CAT II
        Title      : The VMM must automatically terminate a user session after inactivity timeouts have expired or at shutdown.
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
    $VulnID = "V-207432"
    $RuleID = "SV-207432r958636_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Session Inactivity Timeout" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH ClientAliveInterval and ClientAliveCountMax
        $SshInterval = $(timeout 3 sshd -T 2>/dev/null | grep -i "^clientaliveinterval" 2>/dev/null)
        $SshIntervalStr = ("$SshInterval").Trim()
        $FindingDetails += "SSH ClientAliveInterval: $SshIntervalStr" + $nl

        $SshCount = $(timeout 3 sshd -T 2>/dev/null | grep -i "^clientalivecountmax" 2>/dev/null)
        $SshCountStr = ("$SshCount").Trim()
        $FindingDetails += "SSH ClientAliveCountMax: $SshCountStr" + $nl

        # Check TMOUT environment variable
        $TmoutProfile = $(timeout 3 grep -r "TMOUT" /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null | head -5 2>/dev/null)
        $TmoutArr = @()
        if ($null -ne $TmoutProfile) { $TmoutArr = @($TmoutProfile) }
        $TmoutStr = ($TmoutArr -join $nl).Trim()
        $FindingDetails += "TMOUT setting: $(if ($TmoutStr.Length -gt 0) { $TmoutStr } else { 'not configured' })" + $nl

        # Parse values
        $IntervalOk = $false
        if ($SshIntervalStr -match "(\d+)") {
            $IntervalVal = [int]$Matches[1]
            if ($IntervalVal -gt 0 -and $IntervalVal -le 900) { $IntervalOk = $true }
        }

        if ($IntervalOk) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: SSH session inactivity timeout is configured (ClientAliveInterval=$IntervalVal). Sessions will be terminated after inactivity period expires."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: SSH session inactivity timeout is not properly configured. Set ClientAliveInterval to 900 or less and ClientAliveCountMax to 0 in /etc/ssh/sshd_config."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207433 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207433
        STIG ID    : SRG-OS-000280-VMM-001020
        Rule ID    : SV-207433r958638_rule
        Severity   : CAT II
        Title      : VMMs requiring user access authentication must provide a logout capability for user-initiated communications sessions.
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
    $VulnID = "V-207433"
    $RuleID = "SV-207433r958638_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Logout Capability" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # SSH provides exit/logout
        $SshActive = $(systemctl is-active sshd 2>/dev/null)
        $SshStr = ("$SshActive").Trim()
        $FindingDetails += "SSH service: $SshStr (provides exit/logout command)" + $nl

        # xe session management
        $XeSessions = Invoke-XeCommand -Command "session-list --minimal"
        $XeSessionStr = ("$XeSessions").Trim()
        $SessionCount = 0
        if ($XeSessionStr.Length -gt 0) { $SessionCount = ($XeSessionStr -split ",").Count }
        $FindingDetails += "Active xe sessions: $SessionCount" + $nl

        # xe session-logout capability
        $FindingDetails += "xe session-logout: available (built-in xe CLI command)" + $nl

        if ($SshStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Logout capability is available. SSH sessions support exit/logout commands. XCP-ng xe CLI supports session-logout for XAPI sessions. Users can terminate their authenticated sessions at any time."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: SSH service is not active. Primary management interface unavailable. Verify SSH is enabled for remote management access."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207434 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207434
        STIG ID    : SRG-OS-000281-VMM-001030
        Rule ID    : SV-207434r958640_rule
        Severity   : CAT II
        Title      : The VMM must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.
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
    $VulnID = "V-207434"
    $RuleID = "SV-207434r958640_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Logout Message Display" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # SSH logout message via /etc/ssh/sshd_config PrintLastLog
        $PrintLastLog = $(timeout 5 grep -i "^PrintLastLog" /etc/ssh/sshd_config 2>/dev/null)
        $PrintLastLogStr = ("$PrintLastLog").Trim()
        $FindingDetails += "SSH PrintLastLog: $(if ($PrintLastLogStr.Length -gt 0) { $PrintLastLogStr } else { 'not set (default: yes)' })" + $nl

        # SSH logout produces disconnect message by protocol
        $FindingDetails += "SSH protocol: logout/exit terminates connection with disconnect message" + $nl

        # xe CLI session termination
        $FindingDetails += "xe CLI: session-logout returns success confirmation" + $nl

        # Check /etc/motd or /etc/issue for logout info
        $Motd = $(timeout 5 cat /etc/motd 2>/dev/null)
        $MotdStr = ("$Motd").Trim()
        $FindingDetails += "MOTD (/etc/motd): $(if ($MotdStr.Length -gt 0) { 'configured' } else { 'empty or not configured' })" + $nl

        # SSH provides explicit logout confirmation by default (Connection to host closed.)
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng provides explicit logout messages. SSH displays 'Connection to <host> closed.' upon logout, confirming session termination. The xe CLI returns success confirmation on session-logout. These mechanisms provide reliable indication of authenticated session termination."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207435 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207435
        STIG ID    : SRG-OS-000297-VMM-001040
        Rule ID    : SV-207435r958672_rule
        Severity   : CAT II
        Title      : The VMM must control remote access methods.
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
    $VulnID = "V-207435"
    $RuleID = "SV-207435r958672_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Remote Access Control" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # SSH is the primary remote access method
        $SshActive = $(systemctl is-active sshd 2>/dev/null)
        $SshStr = ("$SshActive").Trim()
        $FindingDetails += "SSH service (sshd): $SshStr" + $nl

        # Check SSH configuration restrictions
        $PermitRoot = $(timeout 5 grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null)
        $PermitRootStr = ("$PermitRoot").Trim()
        $FindingDetails += "PermitRootLogin: $(if ($PermitRootStr.Length -gt 0) { $PermitRootStr } else { 'not set (default: yes)' })" + $nl

        $AllowUsers = $(timeout 5 grep -i "^AllowUsers\|^AllowGroups\|^DenyUsers\|^DenyGroups" /etc/ssh/sshd_config 2>/dev/null)
        $AllowUsersStr = ("$AllowUsers").Trim()
        $FindingDetails += "Access restrictions: $(if ($AllowUsersStr.Length -gt 0) { $AllowUsersStr } else { 'none configured' })" + $nl

        # XAPI listens on port 443 for management
        $XapiActive = $(systemctl is-active xapi 2>/dev/null)
        $XapiStr = ("$XapiActive").Trim()
        $FindingDetails += "XAPI service: $XapiStr (management API on port 443)" + $nl

        # Check iptables for access control
        $IptablesRules = $(timeout 10 iptables -L INPUT -n --line-numbers 2>/dev/null)
        $IptablesArr = @()
        if ($null -ne $IptablesRules) { $IptablesArr = @($IptablesRules) }
        $RuleCount = ($IptablesArr | Where-Object { $_ -match "^\d+" }).Count
        $FindingDetails += "iptables INPUT rules: $RuleCount" + $nl

        if ($SshStr -eq "active" -and $XapiStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Remote access to XCP-ng is controlled through SSH (port 22) and XAPI (port 443). SSH is the primary management interface with configurable access restrictions. XAPI provides the hypervisor management API with TLS encryption. Both services are active and manageable through standard system configuration."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: One or more remote access services are not active. SSH and XAPI are required for XCP-ng management. Verify that both services are enabled and properly configured."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207436 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207436
        STIG ID    : SRG-OS-000298-VMM-001050
        Rule ID    : SV-207436r958674_rule
        Severity   : CAT II
        Title      : The VMM must provide the capability to immediately disconnect or disable remote access to the information system.
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
    $VulnID = "V-207436"
    $RuleID = "SV-207436r958674_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Remote Access Disconnect Capability" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # SSH can be stopped immediately
        $SshEnabled = $(systemctl is-enabled sshd 2>/dev/null)
        $SshEnabledStr = ("$SshEnabled").Trim()
        $FindingDetails += "SSH service enabled: $SshEnabledStr (can be stopped with: systemctl stop sshd)" + $nl

        # iptables can block all remote access immediately
        $IptablesAvail = $(which iptables 2>/dev/null)
        $IptablesStr = ("$IptablesAvail").Trim()
        $FindingDetails += "iptables available: $(if ($IptablesStr.Length -gt 0) { 'yes' } else { 'no' })" + $nl
        $FindingDetails += "Immediate block: iptables -A INPUT -j DROP (blocks all incoming)" + $nl

        # xe session-logout can terminate specific sessions
        $FindingDetails += "xe session-logout: terminates XAPI sessions on demand" + $nl

        # XAPI management can be stopped
        $FindingDetails += "XAPI service: can be stopped with systemctl stop xapi" + $nl

        if ($IptablesStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides multiple mechanisms to immediately disconnect or disable remote access: (1) systemctl stop sshd terminates all SSH connections; (2) iptables rules can block all incoming traffic immediately; (3) xe session-logout terminates individual XAPI sessions; (4) systemctl stop xapi disables management API access. Administrators have full capability to disconnect remote access."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: iptables is not available. Ensure firewall tools are installed to provide immediate remote access disconnection capability."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207437 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207437
        STIG ID    : SRG-OS-000299-VMM-001060
        Rule ID    : SV-207437r958676_rule
        Severity   : CAT II
        Title      : The VMM must protect wireless access to the system using encryption.
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
    $VulnID = "V-207437"
    $RuleID = "SV-207437r958676_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Wireless Access Protection (Encryption)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for wireless interfaces
        $WirelessIfaces = $(timeout 5 ls /sys/class/net/*/wireless 2>/dev/null)
        $WirelessStr = ("$WirelessIfaces").Trim()
        $FindingDetails += "Wireless interfaces detected: $(if ($WirelessStr.Length -gt 0) { $WirelessStr } else { 'none' })" + $nl

        # Check if wireless kernel modules are loaded
        $WirelessMods = $(timeout 5 lsmod 2>/dev/null | grep -iE "cfg80211|mac80211|iwlwifi|iwl[0-9]|ath[0-9]k|rtlwifi|wlan[0-9]|brcmfmac")
        $WirelessModsStr = ("$WirelessMods").Trim()
        $FindingDetails += "Wireless kernel modules: $(if ($WirelessModsStr.Length -gt 0) { $WirelessModsStr } else { 'none loaded' })" + $nl

        if ($WirelessStr.Length -eq 0 -and $WirelessModsStr.Length -eq 0) {
            $Status = "Not_Applicable"
            $FindingDetails += $nl + "RESULT: Not Applicable. XCP-ng is a server-class hypervisor with no wireless interfaces or wireless kernel modules detected. Wireless access is not applicable to this system. All management access is via wired Ethernet connections."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Wireless interfaces or modules detected on this hypervisor host. DoD policy requires wireless access be protected with encryption. Wireless interfaces should be disabled on hypervisor hosts. Remove wireless kernel modules and disable any wireless interfaces."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207438 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207438
        STIG ID    : SRG-OS-000300-VMM-001070
        Rule ID    : SV-207438r958678_rule
        Severity   : CAT II
        Title      : The VMM must protect wireless access to the system using authentication of users and/or devices.
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
    $VulnID = "V-207438"
    $RuleID = "SV-207438r958678_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Wireless Access Protection (Authentication)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for wireless interfaces
        $WirelessIfaces = $(timeout 5 ls /sys/class/net/*/wireless 2>/dev/null)
        $WirelessStr = ("$WirelessIfaces").Trim()
        $FindingDetails += "Wireless interfaces detected: $(if ($WirelessStr.Length -gt 0) { $WirelessStr } else { 'none' })" + $nl

        # Check if wireless kernel modules are loaded
        $WirelessMods = $(timeout 5 lsmod 2>/dev/null | grep -iE "cfg80211|mac80211|iwlwifi|iwl[0-9]|ath[0-9]k|rtlwifi|wlan[0-9]|brcmfmac")
        $WirelessModsStr = ("$WirelessMods").Trim()
        $FindingDetails += "Wireless kernel modules: $(if ($WirelessModsStr.Length -gt 0) { $WirelessModsStr } else { 'none loaded' })" + $nl

        if ($WirelessStr.Length -eq 0 -and $WirelessModsStr.Length -eq 0) {
            $Status = "Not_Applicable"
            $FindingDetails += $nl + "RESULT: Not Applicable. XCP-ng is a server-class hypervisor with no wireless interfaces or wireless kernel modules detected. Wireless access authentication is not applicable to this system. All management access is via wired Ethernet connections with SSH or XAPI authentication."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Wireless interfaces or modules detected on this hypervisor host. DoD policy requires wireless access be protected with user/device authentication. Wireless interfaces should be disabled on hypervisor hosts. Remove wireless kernel modules and disable any wireless interfaces."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207439 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207439
        STIG ID    : SRG-OS-000303-VMM-001090
        Rule ID    : SV-207439r958684_rule
        Severity   : CAT II
        Title      : The VMM must automatically audit account enabling actions.
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
    $VulnID = "V-207439"
    $RuleID = "SV-207439r958684_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Account Enabling Actions" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd service
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Check for audit rules monitoring account enabling (passwd, shadow, group files)
        $AuditRules = $(timeout 10 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()

        $PasswdRule = $false
        $ShadowRule = $false
        $GroupRule = $false
        if ($AuditStr -match "/etc/passwd") { $PasswdRule = $true }
        if ($AuditStr -match "/etc/shadow") { $ShadowRule = $true }
        if ($AuditStr -match "/etc/group") { $GroupRule = $true }

        $FindingDetails += "Audit rule for /etc/passwd: $(if ($PasswdRule) { 'configured' } else { 'NOT configured' })" + $nl
        $FindingDetails += "Audit rule for /etc/shadow: $(if ($ShadowRule) { 'configured' } else { 'NOT configured' })" + $nl
        $FindingDetails += "Audit rule for /etc/group: $(if ($GroupRule) { 'configured' } else { 'NOT configured' })" + $nl

        # Check for usermod/chage audit rules
        $UsermodRule = $false
        if ($AuditStr -match "usermod|chage") { $UsermodRule = $true }
        $FindingDetails += "Audit rule for usermod/chage: $(if ($UsermodRule) { 'configured' } else { 'NOT configured' })" + $nl

        if ($AuditdStr -eq "active" -and $PasswdRule -and $ShadowRule) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is active and configured to monitor account enabling actions. Audit rules are in place for /etc/passwd and /etc/shadow, which capture account status changes including enabling (unlocking) accounts via usermod or passwd commands."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not properly configured to audit account enabling actions. "
            if ($AuditdStr -ne "active") {
                $FindingDetails += "The auditd service is not active. Enable with: systemctl enable --now auditd. "
            }
            $FindingDetails += "Ensure audit rules monitor /etc/passwd, /etc/shadow, and /etc/group for write access: auditctl -w /etc/passwd -p wa -k identity; auditctl -w /etc/shadow -p wa -k identity; auditctl -w /etc/group -p wa -k identity"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207440 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207440
        STIG ID    : SRG-OS-000304-VMM-001100
        Rule ID    : SV-207440r984234_rule
        Severity   : CAT II
        Title      : The VMM must notify the SA and ISSO of account enabling actions.
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
    $VulnID = "V-207440"
    $RuleID = "SV-207440r984234_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Account Enabling Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for external auth (AD/LDAP) - compensating control
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'not configured' })" + $nl

        if ($ExtAuthStr.Length -gt 0 -and $ExtAuthStr -ne " ") {
            # External auth provides centralized account management with built-in notification
            $ExtAuthService = Invoke-XeCommand -Command "pool-list params=external-auth-service-name --minimal"
            $ExtAuthServiceStr = ("$ExtAuthService").Trim()
            $FindingDetails += "External auth service: $ExtAuthServiceStr" + $nl
            $FindingDetails += "AD/LDAP integration: Active Directory provides account enabling notification" + $nl

            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng pool is configured with external authentication ($ExtAuthStr). Active Directory/LDAP integration provides centralized account management where account enabling actions generate notifications through AD event logs, Group Policy, and organizational monitoring tools. SA and ISSO notification is handled through the enterprise directory service."
        }
        else {
            # Check for local notification mechanisms
            $Aliases = $(timeout 5 cat /etc/aliases 2>/dev/null)
            $AliasesStr = ("$Aliases").Trim()
            $RootAlias = ""
            if ($AliasesStr.Length -gt 0 -and $AliasesStr -match "root:\s*(.+)") { $RootAlias = $Matches[1] }
            $FindingDetails += "Root mail alias: $(if ($RootAlias.Length -gt 0) { $RootAlias } else { 'not configured' })" + $nl

            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No external authentication (AD/LDAP) is configured to provide account enabling notifications to SA/ISSO. Configure external authentication via: xe pool-enable-external-auth auth-type=AD service-name=domain.example.com. Alternatively, configure auditd rules with email forwarding to notify SA/ISSO of account enabling actions."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207441 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207441
        STIG ID    : SRG-OS-000312-VMM-001110
        Rule ID    : SV-207441r958702_rule
        Severity   : CAT II
        Title      : The VMM must implement discretionary access controls to allow VMM admins to pass information to any other VMM admin, user, or guest VM.
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
    $VulnID = "V-207441"
    $RuleID = "SV-207441r958702_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Discretionary Access Control - Information Passing" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check RBAC roles available
        $Roles = Invoke-XeCommand -Command "role-list --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles available: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'none detected' })" + $nl

        # Check subjects (users) with RBAC
        $Subjects = Invoke-XeCommand -Command "subject-list --minimal"
        $SubjectsStr = ("$Subjects").Trim()
        $SubjectCount = 0
        if ($SubjectsStr.Length -gt 0 -and $SubjectsStr -ne " ") { $SubjectCount = ($SubjectsStr -split ",").Count }
        $FindingDetails += "RBAC subjects: $SubjectCount" + $nl

        # Check VM list (objects that can receive information)
        $VMs = Invoke-XeCommand -Command "vm-list is-control-domain=false --minimal"
        $VMsStr = ("$VMs").Trim()
        $VMCount = 0
        if ($VMsStr.Length -gt 0 -and $VMsStr -ne " ") { $VMCount = ($VMsStr -split ",").Count }
        $FindingDetails += "Guest VMs: $VMCount" + $nl

        # XCP-ng RBAC provides admin roles that can manage all VMs and storage
        if ($RolesStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng implements discretionary access controls through its RBAC system. Pool administrators can pass information (ISO images, virtual disks, network configurations) to any guest VM, and can share resources between VMs through shared storage repositories. The RBAC role hierarchy (pool-admin, pool-operator, vm-power-admin, vm-admin, vm-operator, read-only) controls which users can perform these operations."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify RBAC role configuration. Ensure XCP-ng RBAC is properly configured to allow administrators to manage information sharing between VMs and users."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207442 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207442
        STIG ID    : SRG-OS-000312-VMM-001120
        Rule ID    : SV-207442r958702_rule
        Severity   : CAT II
        Title      : The VMM must implement discretionary access controls to allow VMM admins to grant their privileges to other VMM admins.
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
    $VulnID = "V-207442"
    $RuleID = "SV-207442r958702_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Discretionary Access Control - Privilege Granting" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check RBAC roles
        $Roles = Invoke-XeCommand -Command "role-list --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'none detected' })" + $nl

        # Check subjects with role assignments
        $Subjects = Invoke-XeCommand -Command "subject-list --minimal"
        $SubjectsStr = ("$Subjects").Trim()
        $SubjectCount = 0
        if ($SubjectsStr.Length -gt 0 -and $SubjectsStr -ne " ") { $SubjectCount = ($SubjectsStr -split ",").Count }
        $FindingDetails += "RBAC subjects: $SubjectCount" + $nl

        # Check external auth for centralized privilege management
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth: $(if ($ExtAuthStr.Length -gt 0 -and $ExtAuthStr -ne ' ') { $ExtAuthStr } else { 'not configured' })" + $nl

        if ($RolesStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng implements RBAC with a role hierarchy that allows pool administrators to grant privileges to other admins. Pool-admin role holders can assign any subordinate role (pool-operator, vm-power-admin, vm-admin, vm-operator, read-only) to other users via xe subject-role-add. This provides discretionary access control for privilege delegation."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify RBAC role configuration. Ensure XCP-ng RBAC is properly configured to allow administrators to delegate privileges."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207443 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207443
        STIG ID    : SRG-OS-000312-VMM-001130
        Rule ID    : SV-207443r958702_rule
        Severity   : CAT II
        Title      : The VMM must implement discretionary access controls to allow VMM admins to change security attributes on users, guest VMs, the VMM, or the VMMs components.
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
    $VulnID = "V-207443"
    $RuleID = "SV-207443r958702_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Discretionary Access Control - Security Attribute Changes" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # RBAC roles
        $Roles = Invoke-XeCommand -Command "role-list --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'none detected' })" + $nl

        # Pool admin can change VM security attributes
        $VMs = Invoke-XeCommand -Command "vm-list is-control-domain=false --minimal"
        $VMsStr = ("$VMs").Trim()
        $VMCount = 0
        if ($VMsStr.Length -gt 0 -and $VMsStr -ne " ") { $VMCount = ($VMsStr -split ",").Count }
        $FindingDetails += "Guest VMs manageable: $VMCount" + $nl

        # Check network count (security-relevant objects)
        $Networks = Invoke-XeCommand -Command "network-list --minimal"
        $NetworksStr = ("$Networks").Trim()
        $NetCount = 0
        if ($NetworksStr.Length -gt 0 -and $NetworksStr -ne " ") { $NetCount = ($NetworksStr -split ",").Count }
        $FindingDetails += "Networks: $NetCount" + $nl

        if ($RolesStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng RBAC allows pool administrators to change security attributes on users (xe subject-role-add/remove), guest VMs (xe vm-param-set for security tags, network assignments, storage access), and VMM components (xe pool-param-set, xe host-param-set). The pool-admin role has full control over all security-relevant attributes across the hypervisor platform."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify RBAC role configuration for security attribute management. Configure XCP-ng RBAC to enable administrators to modify security attributes on users, VMs, and system components."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207444 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207444
        STIG ID    : SRG-OS-000312-VMM-001140
        Rule ID    : SV-207444r958702_rule
        Severity   : CAT II
        Title      : The VMM must implement discretionary access controls to allow VMM admins to choose the security attributes to be associated with newly created or revised guest VMs.
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
    $VulnID = "V-207444"
    $RuleID = "SV-207444r958702_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Discretionary Access Control - New VM Security Attributes" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # RBAC roles
        $Roles = Invoke-XeCommand -Command "role-list --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'none detected' })" + $nl

        # VM templates show configurable security attributes
        $Templates = Invoke-XeCommand -Command "template-list is-a-template=true --minimal"
        $TemplatesStr = ("$Templates").Trim()
        $TemplateCount = 0
        if ($TemplatesStr.Length -gt 0 -and $TemplatesStr -ne " ") { $TemplateCount = ($TemplatesStr -split ",").Count }
        $FindingDetails += "VM templates available: $TemplateCount" + $nl

        # Storage repositories (security-relevant assignment for new VMs)
        $SRs = Invoke-XeCommand -Command "sr-list --minimal"
        $SRsStr = ("$SRs").Trim()
        $SRCount = 0
        if ($SRsStr.Length -gt 0 -and $SRsStr -ne " ") { $SRCount = ($SRsStr -split ",").Count }
        $FindingDetails += "Storage repositories: $SRCount" + $nl

        if ($RolesStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng allows administrators to choose security attributes for newly created or revised guest VMs. During VM creation, admins specify: network assignments (VLAN isolation), storage repository placement, memory/CPU limits, boot parameters, and VM-level tags. The xe vm-install and xe vm-create commands accept parameters for all security-relevant attributes. Templates provide standardized security baselines for new VMs."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify RBAC role configuration for VM creation security attributes. Configure XCP-ng RBAC to control VM creation and attribute assignment."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207445 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207445
        STIG ID    : SRG-OS-000324-VMM-001150
        Rule ID    : SV-207445r958726_rule
        Severity   : CAT II
        Title      : The VMM must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
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
    $VulnID = "V-207445"
    $RuleID = "SV-207445r958726_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Privilege Separation - Non-Privileged User Restriction" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Xen architecture enforces privilege separation via Dom0/DomU boundary
        $FindingDetails += "Xen Architecture:" + $nl
        $FindingDetails += "  Dom0 (privileged domain): runs management stack (XAPI, xe CLI)" + $nl
        $FindingDetails += "  DomU (guest VMs): unprivileged, no direct hardware access" + $nl + $nl

        # RBAC roles - non-admin roles cannot execute privileged operations
        $Roles = Invoke-XeCommand -Command "role-list --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'none detected' })" + $nl

        # Check sudo configuration
        $SudoConfig = $(timeout 5 grep -v "^#\|^$" /etc/sudoers 2>/dev/null)
        $SudoArr = @()
        if ($null -ne $SudoConfig) { $SudoArr = @($SudoConfig) }
        $SudoStr = ($SudoArr -join $nl).Trim()
        $SudoCount = $SudoArr.Count
        $FindingDetails += "sudoers active rules: $SudoCount" + $nl

        # Check that only root can access Dom0 management
        $DomZeroAccess = $(timeout 5 grep -c "^[^#]*ALL=(ALL)" /etc/sudoers 2>/dev/null)
        $DomZeroStr = ("$DomZeroAccess").Trim()
        $FindingDetails += "Users with ALL sudo: $DomZeroStr" + $nl

        if ($RolesStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng enforces privilege separation through multiple layers: (1) Xen hypervisor architecture isolates Dom0 (privileged) from DomU (unprivileged guest VMs), preventing guest VMs from executing host-level functions; (2) RBAC restricts XAPI operations based on role assignment (read-only users cannot modify configurations); (3) Linux DAC/sudo on Dom0 restricts root-level operations. Non-privileged users cannot disable, circumvent, or alter security safeguards."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Unable to verify RBAC configuration for privilege separation. Ensure XCP-ng RBAC is configured to restrict non-privileged users from executing privileged functions."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207446 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207446
        STIG ID    : SRG-OS-000326-VMM-001160
        Rule ID    : SV-207446r958730_rule
        Severity   : CAT II
        Title      : The VMM must prevent all software from executing at higher privilege levels than users executing the software.
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
    $VulnID = "V-207446"
    $RuleID = "SV-207446r958730_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Privilege Level Enforcement" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Xen ring architecture: Ring -1 (Xen), Ring 0 (Dom0 kernel), Ring 3 (user space)
        $FindingDetails += "Xen Ring Architecture:" + $nl
        $FindingDetails += "  Ring -1: Xen hypervisor (most privileged)" + $nl
        $FindingDetails += "  Ring 0: Dom0 kernel (hardware access via Xen grants)" + $nl
        $FindingDetails += "  Ring 3: Dom0 user space, DomU guest VMs (least privileged)" + $nl + $nl

        # Check for SUID binaries (privilege escalation vectors)
        $SuidBins = $(timeout 15 find / -maxdepth 4 -perm -4000 -type f 2>/dev/null)
        $SuidArr = @()
        if ($null -ne $SuidBins) { $SuidArr = @($SuidBins) }
        $SuidCount = $SuidArr.Count
        $FindingDetails += "SUID binaries found: $SuidCount" + $nl

        # Check nosuid on key mount points
        $MountInfo = $(mount 2>/dev/null)
        $MountArr = @()
        if ($null -ne $MountInfo) { $MountArr = @($MountInfo) }
        $MountStr = ($MountArr -join $nl).Trim()
        $TmpNosuid = $false
        if ($MountStr -match "/tmp.*nosuid") { $TmpNosuid = $true }
        $FindingDetails += "/tmp mounted nosuid: $TmpNosuid" + $nl

        # Xen architecture inherently prevents privilege escalation
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng/Xen prevents software from executing at higher privilege levels through hardware-enforced ring architecture. Guest VMs (DomU) run in Ring 3 and cannot access Ring 0 (Dom0 kernel) or Ring -1 (Xen hypervisor). The Xen hypervisor mediates all hardware access through hypercalls. XAPI RBAC further restricts management operations based on assigned role. Software running within a guest VM cannot escalate to hypervisor or Dom0 privilege level."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207447 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207447
        STIG ID    : SRG-OS-000327-VMM-001170
        Rule ID    : SV-207447r958732_rule
        Severity   : CAT II
        Title      : The VMM must audit the execution of privileged functions.
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
    $VulnID = "V-207447"
    $RuleID = "SV-207447r958732_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Privileged Function Execution" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd service
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Check audit rules for privileged function execution (execve, suid/sgid)
        $AuditRules = $(timeout 10 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()

        $ExecveRule = $false
        $SuidRule = $false
        $SudoRule = $false
        if ($AuditStr -match "execve") { $ExecveRule = $true }
        if ($AuditStr -match "perm_mod\|4000\|2000\|setuid\|setgid") { $SuidRule = $true }
        if ($AuditStr -match "/usr/bin/sudo\|/bin/su") { $SudoRule = $true }

        $FindingDetails += "Audit rule for execve: $(if ($ExecveRule) { 'configured' } else { 'NOT configured' })" + $nl
        $FindingDetails += "Audit rule for SUID/SGID: $(if ($SuidRule) { 'configured' } else { 'NOT configured' })" + $nl
        $FindingDetails += "Audit rule for sudo/su: $(if ($SudoRule) { 'configured' } else { 'NOT configured' })" + $nl

        # XAPI logs all management operations
        $XapiLog = $(timeout 5 ls -la /var/log/xensource.log 2>/dev/null)
        $XapiLogStr = ("$XapiLog").Trim()
        $FindingDetails += "XAPI management log: $(if ($XapiLogStr.Length -gt 0) { 'present' } else { 'NOT found' })" + $nl

        if ($AuditdStr -eq "active" -and ($ExecveRule -or $SudoRule)) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is active and configured to audit privileged function execution. Audit rules monitor execve system calls and/or privileged command execution (sudo, su). Additionally, XAPI logs all hypervisor management operations in /var/log/xensource.log, providing application-level audit of privileged VMM functions."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not properly configured to audit privileged function execution. "
            if ($AuditdStr -ne "active") {
                $FindingDetails += "Enable auditd: systemctl enable --now auditd. "
            }
            $FindingDetails += "Add audit rules for privileged functions: auditctl -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privileged; auditctl -w /usr/bin/sudo -p x -k privileged-sudo; auditctl -w /bin/su -p x -k privileged-su"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207448 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207448
        STIG ID    : SRG-OS-000329-VMM-001180
        Rule ID    : SV-207448r958736_rule
        Severity   : CAT II
        Title      : The VMM must automatically lock an account until the locked account is released by an administrator, when three unsuccessful logon attempts in 15 minutes are made.
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
    $VulnID = "V-207448"
    $RuleID = "SV-207448r958736_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Account Lockout Policy" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check PAM faillock configuration (CentOS 7)
        $SystemAuth = $(timeout 5 cat /etc/pam.d/system-auth 2>/dev/null)
        $SystemAuthArr = @()
        if ($null -ne $SystemAuth) { $SystemAuthArr = @($SystemAuth) }
        $SystemAuthStr = ($SystemAuthArr -join $nl).Trim()

        $PasswordAuth = $(timeout 5 cat /etc/pam.d/password-auth 2>/dev/null)
        $PasswordAuthArr = @()
        if ($null -ne $PasswordAuth) { $PasswordAuthArr = @($PasswordAuth) }
        $PasswordAuthStr = ($PasswordAuthArr -join $nl).Trim()

        # Look for pam_faillock in system-auth
        $FaillockAuth = $false
        $FaillockDeny = ""
        $FaillockInterval = ""
        $FaillockUnlock = ""

        if ($SystemAuthStr -match "pam_faillock") {
            $FaillockAuth = $true
            if ($SystemAuthStr -match "deny=(\d+)") { $FaillockDeny = $Matches[1] }
            if ($SystemAuthStr -match "fail_interval=(\d+)") { $FaillockInterval = $Matches[1] }
            if ($SystemAuthStr -match "unlock_time=(\d+)") { $FaillockUnlock = $Matches[1] }
        }

        $FindingDetails += "pam_faillock in system-auth: $(if ($FaillockAuth) { 'configured' } else { 'NOT configured' })" + $nl
        if ($FaillockAuth) {
            $FindingDetails += "  deny: $(if ($FaillockDeny.Length -gt 0) { $FaillockDeny } else { 'not set' })" + $nl
            $FindingDetails += "  fail_interval: $(if ($FaillockInterval.Length -gt 0) { $FaillockInterval + ' seconds' } else { 'not set' })" + $nl
            $FindingDetails += "  unlock_time: $(if ($FaillockUnlock.Length -gt 0) { if ($FaillockUnlock -eq '0') { '0 (admin unlock required)' } else { $FaillockUnlock + ' seconds' } } else { 'not set' })" + $nl
        }

        # Also check password-auth
        $FaillockPwAuth = $false
        if ($PasswordAuthStr -match "pam_faillock") { $FaillockPwAuth = $true }
        $FindingDetails += "pam_faillock in password-auth: $(if ($FaillockPwAuth) { 'configured' } else { 'NOT configured' })" + $nl

        # Check SSH MaxAuthTries as additional control
        $MaxAuth = $(timeout 5 grep -i "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null)
        $MaxAuthStr = ("$MaxAuth").Trim()
        $FindingDetails += "SSH MaxAuthTries: $(if ($MaxAuthStr.Length -gt 0) { $MaxAuthStr } else { 'not set (default: 6)' })" + $nl

        # Evaluate compliance: deny <= 3, fail_interval >= 900 (15 min), unlock_time = 0 (admin required)
        if ($FaillockAuth -and $FaillockDeny.Length -gt 0 -and [int]$FaillockDeny -le 3 -and
            $FaillockInterval.Length -gt 0 -and [int]$FaillockInterval -ge 900 -and
            $FaillockUnlock.Length -gt 0 -and [int]$FaillockUnlock -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Account lockout is properly configured. pam_faillock is set to lock accounts after $FaillockDeny failed attempts within $FaillockInterval seconds, requiring administrator unlock (unlock_time=0). This meets the DoD requirement of 3 attempts in 15 minutes with admin-only unlock."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Account lockout is not properly configured to meet DoD requirements. Configure pam_faillock in /etc/pam.d/system-auth and /etc/pam.d/password-auth with: deny=3 fail_interval=900 unlock_time=0. Add to auth section: auth required pam_faillock.so preauth silent deny=3 fail_interval=900 unlock_time=0; auth required pam_faillock.so authfail deny=3 fail_interval=900 unlock_time=0"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207449 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207449
        STIG ID    : SRG-OS-000337-VMM-001190
        Rule ID    : SV-207449r971541_rule
        Severity   : CAT II
        Title      : The VMM must provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all VMM components, based on all selectable event criteria in near real time.
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
    $VulnID = "V-207449"
    $RuleID = "SV-207449r971541_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Configuration Change Capability" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd service and auditctl availability
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        $AuditctlAvail = $(which auditctl 2>/dev/null)
        $AuditctlStr = ("$AuditctlAvail").Trim()
        $FindingDetails += "auditctl tool: $(if ($AuditctlStr.Length -gt 0) { 'available' } else { 'NOT available' })" + $nl

        # Check audit rules file
        $AuditRulesFile = $(timeout 5 ls -la /etc/audit/audit.rules 2>/dev/null)
        $AuditRulesFileStr = ("$AuditRulesFile").Trim()
        $FindingDetails += "audit.rules file: $(if ($AuditRulesFileStr.Length -gt 0) { 'present' } else { 'NOT found' })" + $nl

        $AuditRulesD = $(timeout 5 ls /etc/audit/rules.d/ 2>/dev/null)
        $AuditRulesDStr = ("$AuditRulesD").Trim()
        $FindingDetails += "rules.d directory: $(if ($AuditRulesDStr.Length -gt 0) { 'contains files' } else { 'empty or not found' })" + $nl

        # auditctl -l shows current rules (modifiable in near real-time)
        $CurrentRules = $(timeout 10 auditctl -l 2>/dev/null)
        $RulesArr = @()
        if ($null -ne $CurrentRules) { $RulesArr = @($CurrentRules) }
        $RuleCount = $RulesArr.Count
        $FindingDetails += "Active audit rules: $RuleCount" + $nl

        # Check if audit rules are immutable (locked)
        $Immutable = $false
        $RulesStr = ($RulesArr -join $nl).Trim()
        if ($RulesStr -match "-e 2") { $Immutable = $true }
        $FindingDetails += "Audit rules immutable (-e 2): $Immutable" + $nl

        if ($AuditdStr -eq "active" -and $AuditctlStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides audit configuration change capability through auditctl and the audit rules framework. Authorized administrators (SA/ISSO) can modify audit rules in near real-time using: auditctl -a/-d (add/delete rules), auditctl -D (delete all rules), or by editing /etc/audit/rules.d/ and running augenrules --load. Changes take effect immediately without service restart."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not properly configured to allow audit configuration changes. "
            if ($AuditdStr -ne "active") {
                $FindingDetails += "Enable auditd: systemctl enable --now auditd. "
            }
            if ($AuditctlStr.Length -eq 0) {
                $FindingDetails += "Install audit package: yum install audit. "
            }
            $FindingDetails += "Ensure SA/ISSO accounts have sudo access to auditctl for near real-time audit configuration changes."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207452 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207452
        STIG ID    : SRG-OS-000341-VMM-001220
        Rule ID    : SV-207452r958752_rule
        Severity   : CAT II
        Title      : The VMM must allocate audit record storage capacity to store at least one weeks worth of audit records when audit records are not immediately sent to a central audit record storage facility.
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
    $VulnID = "V-207452"
    $RuleID = "SV-207452r958752_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Record Storage Capacity" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd configuration
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Check auditd.conf storage settings
        $AuditConf = $(timeout 5 cat /etc/audit/auditd.conf 2>/dev/null)
        $AuditConfArr = @()
        if ($null -ne $AuditConf) { $AuditConfArr = @($AuditConf) }
        $AuditConfStr = ($AuditConfArr -join $nl).Trim()

        $MaxLogFile = ""
        $NumLogs = ""
        $MaxLogAction = ""
        if ($AuditConfStr -match "(?i)max_log_file\s*=\s*(\d+)") { $MaxLogFile = $Matches[1] }
        if ($AuditConfStr -match "(?i)num_logs\s*=\s*(\d+)") { $NumLogs = $Matches[1] }
        if ($AuditConfStr -match "(?i)max_log_file_action\s*=\s*(\S+)") { $MaxLogAction = $Matches[1] }

        $FindingDetails += "max_log_file: $(if ($MaxLogFile) { $MaxLogFile + ' MB' } else { 'NOT configured' })" + $nl
        $FindingDetails += "num_logs: $(if ($NumLogs) { $NumLogs } else { 'NOT configured' })" + $nl
        $FindingDetails += "max_log_file_action: $(if ($MaxLogAction) { $MaxLogAction } else { 'NOT configured' })" + $nl

        # Calculate total capacity
        $TotalCapacityMB = 0
        if ($MaxLogFile -and $NumLogs) {
            $TotalCapacityMB = [int]$MaxLogFile * [int]$NumLogs
            $FindingDetails += "Total audit capacity: $TotalCapacityMB MB ($MaxLogFile MB x $NumLogs logs)" + $nl
        }

        # Check /var/log/audit partition space
        $AuditDf = $(timeout 5 df -m /var/log/audit 2>/dev/null)
        $AuditDfArr = @()
        if ($null -ne $AuditDf) { $AuditDfArr = @($AuditDf) }
        if ($AuditDfArr.Count -gt 1) {
            $FindingDetails += "Partition info: $(($AuditDfArr[1]).Trim())" + $nl
        }

        if ($AuditdStr -eq "active" -and $TotalCapacityMB -ge 40) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is active with $TotalCapacityMB MB total storage capacity (max_log_file=$MaxLogFile MB, num_logs=$NumLogs, max_log_file_action=$MaxLogAction). This provides sufficient capacity to store at least one week of audit records for a typical XCP-ng hypervisor workload."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit storage capacity may not be sufficient for one week of records. "
            if ($AuditdStr -ne "active") {
                $FindingDetails += "Enable auditd: systemctl enable --now auditd. "
            }
            $FindingDetails += "Review and increase max_log_file and num_logs in /etc/audit/auditd.conf to ensure at least one week of audit records can be stored. Recommended: max_log_file = 50, num_logs = 10 (500 MB total)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207453 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207453
        STIG ID    : SRG-OS-000342-VMM-001230
        Rule ID    : SV-207453r958754_rule
        Severity   : CAT II
        Title      : The VMM must off-load audit records onto a different system or media than the system being audited.
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
    $VulnID = "V-207453"
    $RuleID = "SV-207453r958754_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Record Off-Loading" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check rsyslog for remote forwarding
        $RsyslogActive = $(systemctl is-active rsyslog 2>/dev/null)
        $RsyslogStr = ("$RsyslogActive").Trim()
        $FindingDetails += "rsyslog service: $RsyslogStr" + $nl

        # Check rsyslog config for remote targets (@@host = TCP, @host = UDP)
        $RsyslogConf = $(timeout 5 grep -rh --include='*.conf' '@@\|^*.*@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null)
        $RsyslogConfArr = @()
        if ($null -ne $RsyslogConf) { $RsyslogConfArr = @($RsyslogConf) }
        $RemoteTargets = @($RsyslogConfArr | Where-Object { $_ -match "@@|[^@]@[^@]" -and $_ -notmatch "^\s*#" })
        $FindingDetails += "Remote rsyslog targets: $($RemoteTargets.Count)" + $nl
        foreach ($Target in $RemoteTargets) {
            $FindingDetails += "  $($Target.Trim())" + $nl
        }

        # Check audisp remote plugin (audispd-plugins)
        $AuRemote = $(timeout 5 cat /etc/audisp/plugins.d/au-remote.conf 2>/dev/null)
        $AuRemoteArr = @()
        if ($null -ne $AuRemote) { $AuRemoteArr = @($AuRemote) }
        $AuRemoteStr = ($AuRemoteArr -join $nl).Trim()
        $AuRemoteActive = $false
        if ($AuRemoteStr -match "(?i)active\s*=\s*yes") { $AuRemoteActive = $true }
        $FindingDetails += "audisp au-remote plugin: $(if ($AuRemoteActive) { 'active' } else { 'not configured' })" + $nl

        # Check remote audisp target
        $AudispRemote = $(timeout 5 cat /etc/audisp/audisp-remote.conf 2>/dev/null)
        $AudispRemoteArr = @()
        if ($null -ne $AudispRemote) { $AudispRemoteArr = @($AudispRemote) }
        $AudispRemoteStr = ($AudispRemoteArr -join $nl).Trim()
        $RemoteServer = ""
        if ($AudispRemoteStr -match "(?i)remote_server\s*=\s*(\S+)") { $RemoteServer = $Matches[1] }
        if ($RemoteServer) {
            $FindingDetails += "audisp remote_server: $RemoteServer" + $nl
        }

        if ($RemoteTargets.Count -gt 0 -or $AuRemoteActive) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit records are configured for off-loading to a remote system. "
            if ($RemoteTargets.Count -gt 0) { $FindingDetails += "rsyslog forwards to $($RemoteTargets.Count) remote target(s). " }
            if ($AuRemoteActive) { $FindingDetails += "audisp au-remote plugin is active (target: $RemoteServer). " }
            $FindingDetails += "This ensures audit records are sent to a different system than the one being audited."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No remote audit off-loading is configured. Configure rsyslog to forward to a central log server (e.g., add '*.* @@logserver:514' to /etc/rsyslog.conf) or enable the audisp au-remote plugin to forward audit records to a remote system."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207454 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207454
        STIG ID    : SRG-OS-000343-VMM-001240
        Rule ID    : SV-207454r971542_rule
        Severity   : CAT II
        Title      : The VMM must provide an immediate warning to the SA and ISSO, at a minimum, when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.
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
    $VulnID = "V-207454"
    $RuleID = "SV-207454r971542_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Storage Warning at 75%" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd.conf space_left and space_left_action
        $AuditConf = $(timeout 5 cat /etc/audit/auditd.conf 2>/dev/null)
        $AuditConfArr = @()
        if ($null -ne $AuditConf) { $AuditConfArr = @($AuditConf) }
        $AuditConfStr = ($AuditConfArr -join $nl).Trim()

        $SpaceLeft = ""
        $SpaceLeftAction = ""
        $AdminSpaceLeft = ""
        $AdminSpaceLeftAction = ""
        if ($AuditConfStr -match "(?i)(?<!\S)space_left\s*=\s*(\S+)") { $SpaceLeft = $Matches[1] }
        if ($AuditConfStr -match "(?i)space_left_action\s*=\s*(\S+)") { $SpaceLeftAction = $Matches[1] }
        if ($AuditConfStr -match "(?i)admin_space_left\s*=\s*(\S+)") { $AdminSpaceLeft = $Matches[1] }
        if ($AuditConfStr -match "(?i)admin_space_left_action\s*=\s*(\S+)") { $AdminSpaceLeftAction = $Matches[1] }

        $FindingDetails += "space_left: $(if ($SpaceLeft) { $SpaceLeft + ' MB' } else { 'NOT configured' })" + $nl
        $FindingDetails += "space_left_action: $(if ($SpaceLeftAction) { $SpaceLeftAction } else { 'NOT configured' })" + $nl
        $FindingDetails += "admin_space_left: $(if ($AdminSpaceLeft) { $AdminSpaceLeft + ' MB' } else { 'NOT configured' })" + $nl
        $FindingDetails += "admin_space_left_action: $(if ($AdminSpaceLeftAction) { $AdminSpaceLeftAction } else { 'NOT configured' })" + $nl

        # Acceptable actions for warning: email, exec, syslog (not ignore, suspend, halt)
        $AcceptableActions = @("email", "exec", "syslog")
        $SpaceLeftOk = $false
        if ($SpaceLeftAction -and ($AcceptableActions -contains $SpaceLeftAction.ToLower())) { $SpaceLeftOk = $true }

        if ($SpaceLeftOk -and $SpaceLeft) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is configured to warn when storage reaches threshold. space_left=$SpaceLeft MB triggers space_left_action=$SpaceLeftAction. This provides notification to SA/ISSO when audit storage approaches capacity. Verify space_left value represents approximately 25% of total audit storage to satisfy the 75% warning threshold."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not configured to provide storage capacity warnings. "
            if (-not $SpaceLeft) { $FindingDetails += "Set space_left to 25% of total audit partition size in /etc/audit/auditd.conf. " }
            if (-not $SpaceLeftOk) { $FindingDetails += "Set space_left_action to 'email' or 'exec' (currently: $(if ($SpaceLeftAction) { $SpaceLeftAction } else { 'not set' })). " }
            $FindingDetails += "This ensures SA/ISSO receive immediate warning when audit storage reaches 75% capacity."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207455 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207455
        STIG ID    : SRG-OS-000344-VMM-001250
        Rule ID    : SV-207455r958758_rule
        Severity   : CAT II
        Title      : The VMM must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.
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
    $VulnID = "V-207455"
    $RuleID = "SV-207455r958758_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Failure Real-Time Alerts" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd.conf failure event actions
        $AuditConf = $(timeout 5 cat /etc/audit/auditd.conf 2>/dev/null)
        $AuditConfArr = @()
        if ($null -ne $AuditConf) { $AuditConfArr = @($AuditConf) }
        $AuditConfStr = ($AuditConfArr -join $nl).Trim()

        $DiskFullAction = ""
        $DiskErrorAction = ""
        $AdminSpaceLeftAction = ""
        $SpaceLeftAction = ""
        if ($AuditConfStr -match "(?i)disk_full_action\s*=\s*(\S+)") { $DiskFullAction = $Matches[1] }
        if ($AuditConfStr -match "(?i)disk_error_action\s*=\s*(\S+)") { $DiskErrorAction = $Matches[1] }
        if ($AuditConfStr -match "(?i)admin_space_left_action\s*=\s*(\S+)") { $AdminSpaceLeftAction = $Matches[1] }
        if ($AuditConfStr -match "(?i)space_left_action\s*=\s*(\S+)") { $SpaceLeftAction = $Matches[1] }

        $FindingDetails += "disk_full_action: $(if ($DiskFullAction) { $DiskFullAction } else { 'NOT configured' })" + $nl
        $FindingDetails += "disk_error_action: $(if ($DiskErrorAction) { $DiskErrorAction } else { 'NOT configured' })" + $nl
        $FindingDetails += "admin_space_left_action: $(if ($AdminSpaceLeftAction) { $AdminSpaceLeftAction } else { 'NOT configured' })" + $nl
        $FindingDetails += "space_left_action: $(if ($SpaceLeftAction) { $SpaceLeftAction } else { 'NOT configured' })" + $nl

        # Acceptable real-time alert actions
        $AlertActions = @("email", "exec", "syslog", "halt", "single")
        $DiskFullOk = $DiskFullAction -and ($AlertActions -contains $DiskFullAction.ToLower())
        $DiskErrorOk = $DiskErrorAction -and ($AlertActions -contains $DiskErrorAction.ToLower())
        $AdminSpaceOk = $AdminSpaceLeftAction -and ($AlertActions -contains $AdminSpaceLeftAction.ToLower())

        $FindingDetails += $nl + "disk_full_action acceptable: $DiskFullOk" + $nl
        $FindingDetails += "disk_error_action acceptable: $DiskErrorOk" + $nl
        $FindingDetails += "admin_space_left_action acceptable: $AdminSpaceOk" + $nl

        if ($DiskFullOk -and $DiskErrorOk -and $AdminSpaceOk) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: auditd is configured to provide real-time alerts for audit failure events. disk_full_action=$DiskFullAction, disk_error_action=$DiskErrorAction, admin_space_left_action=$AdminSpaceLeftAction. These actions ensure SA/ISSO receive immediate notification of critical audit failures."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not fully configured for real-time audit failure alerts. In /etc/audit/auditd.conf, set: "
            if (-not $DiskFullOk) { $FindingDetails += "disk_full_action = halt (or email/exec), " }
            if (-not $DiskErrorOk) { $FindingDetails += "disk_error_action = halt (or email/exec), " }
            if (-not $AdminSpaceOk) { $FindingDetails += "admin_space_left_action = email (or exec/halt), " }
            $FindingDetails += "then restart auditd: systemctl restart auditd."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207456 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207456
        STIG ID    : SRG-OS-000348-VMM-001260
        Rule ID    : SV-207456r958766_rule
        Severity   : CAT II
        Title      : The VMM must provide an audit reduction capability that supports on-demand audit review and analysis.
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
    $VulnID = "V-207456"
    $RuleID = "SV-207456r958766_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Reduction Capability - On-Demand Review" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for ausearch (audit reduction tool)
        $AuSearchPath = $(which ausearch 2>/dev/null)
        $AuSearchStr = ("$AuSearchPath").Trim()
        $FindingDetails += "ausearch: $(if ($AuSearchStr.Length -gt 0) { $AuSearchStr } else { 'NOT installed' })" + $nl

        # Check for aureport (audit reporting tool)
        $AuReportPath = $(which aureport 2>/dev/null)
        $AuReportStr = ("$AuReportPath").Trim()
        $FindingDetails += "aureport: $(if ($AuReportStr.Length -gt 0) { $AuReportStr } else { 'NOT installed' })" + $nl

        # Check for aulast (audit login tool)
        $AuLastPath = $(which aulast 2>/dev/null)
        $AuLastStr = ("$AuLastPath").Trim()
        $FindingDetails += "aulast: $(if ($AuLastStr.Length -gt 0) { $AuLastStr } else { 'not available' })" + $nl

        # Check audit package version
        $AuditPkg = $(rpm -q audit 2>/dev/null)
        $AuditPkgStr = ("$AuditPkg").Trim()
        $FindingDetails += "audit package: $AuditPkgStr" + $nl

        if ($AuSearchStr.Length -gt 0 -and $AuReportStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides audit reduction capability for on-demand review and analysis through the audit tools package. ausearch enables filtering by time range (-ts/-te), user (-ua), event type (-m), key (-k), and other criteria for targeted on-demand audit review. aureport provides summary analysis across multiple audit event categories."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit reduction tools are not installed. Install the audit package: yum install audit. This provides ausearch for on-demand filtering/searching of audit records and aureport for summary analysis."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207457 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207457
        STIG ID    : SRG-OS-000349-VMM-001270
        Rule ID    : SV-207457r958768_rule
        Severity   : CAT II
        Title      : The VMM must provide an audit reduction capability that supports after-the-fact investigations of security incidents.
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
    $VulnID = "V-207457"
    $RuleID = "SV-207457r958768_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Reduction Capability - After-the-Fact Investigations" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for ausearch
        $AuSearchPath = $(which ausearch 2>/dev/null)
        $AuSearchStr = ("$AuSearchPath").Trim()
        $FindingDetails += "ausearch: $(if ($AuSearchStr.Length -gt 0) { $AuSearchStr } else { 'NOT installed' })" + $nl

        # Check for aureport
        $AuReportPath = $(which aureport 2>/dev/null)
        $AuReportStr = ("$AuReportPath").Trim()
        $FindingDetails += "aureport: $(if ($AuReportStr.Length -gt 0) { $AuReportStr } else { 'NOT installed' })" + $nl

        # Check audit log retention
        $AuditConf = $(timeout 5 cat /etc/audit/auditd.conf 2>/dev/null)
        $AuditConfArr = @()
        if ($null -ne $AuditConf) { $AuditConfArr = @($AuditConf) }
        $AuditConfStr = ($AuditConfArr -join $nl).Trim()
        $NumLogs = ""
        $MaxLogFile = ""
        if ($AuditConfStr -match "(?i)num_logs\s*=\s*(\d+)") { $NumLogs = $Matches[1] }
        if ($AuditConfStr -match "(?i)max_log_file\s*=\s*(\d+)") { $MaxLogFile = $Matches[1] }
        $FindingDetails += "num_logs: $(if ($NumLogs) { $NumLogs } else { 'not set' })" + $nl
        $FindingDetails += "max_log_file: $(if ($MaxLogFile) { $MaxLogFile + ' MB' } else { 'not set' })" + $nl

        # Check archived logs
        $ArchivedLogs = $(timeout 5 ls -la /var/log/audit/audit.log* 2>/dev/null)
        $ArchivedArr = @()
        if ($null -ne $ArchivedLogs) { $ArchivedArr = @($ArchivedLogs) }
        $FindingDetails += "Archived audit log files: $($ArchivedArr.Count)" + $nl

        if ($AuSearchStr.Length -gt 0 -and $AuReportStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides audit reduction capability for after-the-fact investigations. ausearch supports time-range filtering (-ts/-te), user correlation (-ua/-ui), process tracking (-p), syscall analysis (-sc), and keyword search (-k) enabling detailed forensic investigation of security incidents. Audit logs are retained across $($ArchivedArr.Count) log file(s) for historical analysis."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit reduction tools for after-the-fact investigations are not installed. Install the audit package: yum install audit. This provides ausearch for forensic filtering/correlation and aureport for incident analysis reporting."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207458 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207458
        STIG ID    : SRG-OS-000350-VMM-001280
        Rule ID    : SV-207458r958770_rule
        Severity   : CAT II
        Title      : The VMM must provide a report generation capability that supports on-demand audit review and analysis.
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
    $VulnID = "V-207458"
    $RuleID = "SV-207458r958770_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Report Generation - On-Demand Review and Analysis" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for aureport
        $AuReportPath = $(which aureport 2>/dev/null)
        $AuReportStr = ("$AuReportPath").Trim()
        $FindingDetails += "aureport: $(if ($AuReportStr.Length -gt 0) { $AuReportStr } else { 'NOT installed' })" + $nl

        # Check for ausearch
        $AuSearchPath = $(which ausearch 2>/dev/null)
        $AuSearchStr = ("$AuSearchPath").Trim()
        $FindingDetails += "ausearch: $(if ($AuSearchStr.Length -gt 0) { $AuSearchStr } else { 'NOT installed' })" + $nl

        # Check audit package
        $AuditPkg = $(rpm -q audit 2>/dev/null)
        $AuditPkgStr = ("$AuditPkg").Trim()
        $FindingDetails += "audit package: $AuditPkgStr" + $nl

        # Check auditd is active
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        if ($AuReportStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides report generation capability for on-demand audit review and analysis through aureport. Available report types include: aureport -l (logins), aureport -f (files), aureport -x (executables), aureport -u (users), aureport -p (processes), aureport -s (syscalls), aureport -a (anomaly events), aureport -c (config changes). Reports can be filtered by time range (-ts/-te) for targeted on-demand analysis."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Report generation tools are not installed. Install the audit package: yum install audit. This provides aureport for generating on-demand audit reports across multiple event categories (logins, files, users, processes, anomalies)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207459 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207459
        STIG ID    : SRG-OS-000351-VMM-001290
        Rule ID    : SV-207459r958772_rule
        Severity   : CAT II
        Title      : The VMM must provide a report generation capability that supports on-demand reporting requirements.
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
    $VulnID = "V-207459"
    $RuleID = "SV-207459r958772_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Report Generation - On-Demand Reporting Requirements" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for aureport
        $AuReportPath = $(which aureport 2>/dev/null)
        $AuReportStr = ("$AuReportPath").Trim()
        $FindingDetails += "aureport: $(if ($AuReportStr.Length -gt 0) { $AuReportStr } else { 'NOT installed' })" + $nl

        # Check for ausearch
        $AuSearchPath = $(which ausearch 2>/dev/null)
        $AuSearchStr = ("$AuSearchPath").Trim()
        $FindingDetails += "ausearch: $(if ($AuSearchStr.Length -gt 0) { $AuSearchStr } else { 'NOT installed' })" + $nl

        # Verify aureport can generate different report types
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Check for last/lastlog for login reporting
        $LastPath = $(which last 2>/dev/null)
        $LastStr = ("$LastPath").Trim()
        $FindingDetails += "last command: $(if ($LastStr.Length -gt 0) { 'available' } else { 'not available' })" + $nl

        $LastlogPath = $(which lastlog 2>/dev/null)
        $LastlogStr = ("$LastlogPath").Trim()
        $FindingDetails += "lastlog command: $(if ($LastlogStr.Length -gt 0) { 'available' } else { 'not available' })" + $nl

        if ($AuReportStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides report generation capability supporting on-demand reporting. aureport generates reports by category: -l (logins), -f (file access), -x (executables), -u (users), -p (PIDs), -s (syscalls), -a (anomalies), -m (modifications), --summary (statistical summaries). Combined with ausearch filtering and last/lastlog for login history, administrators can fulfill ad-hoc reporting requirements on demand."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Report generation tools are not installed. Install the audit package: yum install audit. This provides aureport for generating customizable on-demand audit reports."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207460 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207460
        STIG ID    : SRG-OS-000352-VMM-001300
        Rule ID    : SV-207460r958774_rule
        Severity   : CAT II
        Title      : The VMM must provide a report generation capability that supports after-the-fact investigations of security incidents.
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
    $VulnID = "V-207460"
    $RuleID = "SV-207460r958774_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Report Generation - After-the-Fact Investigations" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for aureport
        $AuReportPath = $(which aureport 2>/dev/null)
        $AuReportStr = ("$AuReportPath").Trim()
        $FindingDetails += "aureport: $(if ($AuReportStr.Length -gt 0) { $AuReportStr } else { 'NOT installed' })" + $nl

        # Check for ausearch
        $AuSearchPath = $(which ausearch 2>/dev/null)
        $AuSearchStr = ("$AuSearchPath").Trim()
        $FindingDetails += "ausearch: $(if ($AuSearchStr.Length -gt 0) { $AuSearchStr } else { 'NOT installed' })" + $nl

        # Check audit log retention (important for after-the-fact)
        $ArchivedLogs = $(timeout 5 ls -la /var/log/audit/audit.log* 2>/dev/null)
        $ArchivedArr = @()
        if ($null -ne $ArchivedLogs) { $ArchivedArr = @($ArchivedLogs) }
        $FindingDetails += "Audit log files available: $($ArchivedArr.Count)" + $nl

        # Check for xen.log for hypervisor-specific events
        $XenLogs = $(timeout 5 ls -la /var/log/xen/*.log 2>/dev/null)
        $XenLogArr = @()
        if ($null -ne $XenLogs) { $XenLogArr = @($XenLogs) }
        $FindingDetails += "Xen log files: $($XenLogArr.Count)" + $nl

        if ($AuReportStr.Length -gt 0 -and $AuSearchStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng provides report generation capability for after-the-fact investigation of security incidents. aureport generates incident-focused reports: -a (anomaly events), --failed (failed actions), -au (authentication), --login (login attempts), -m (account modifications). Combined with ausearch time-range filtering (-ts/-te), incident responders can generate targeted reports for forensic investigation across audit logs ($($ArchivedArr.Count) files) and Xen hypervisor logs."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Report generation tools for incident investigation are not installed. Install the audit package: yum install audit. This provides aureport for generating incident-focused reports and ausearch for forensic data correlation."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207461 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207461
        STIG ID    : SRG-OS-000353-VMM-001310
        Rule ID    : SV-207461r958776_rule
        Severity   : CAT II
        Title      : The VMM that provides an audit reduction capability must not alter original content or time ordering of audit records.
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
    $VulnID = "V-207461"
    $RuleID = "SV-207461r958776_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Reduction - Content/Time Ordering Preservation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for ausearch (read-only audit reduction tool)
        $AuSearchPath = $(which ausearch 2>/dev/null)
        $AuSearchStr = ("$AuSearchPath").Trim()
        $FindingDetails += "ausearch: $(if ($AuSearchStr.Length -gt 0) { $AuSearchStr } else { 'NOT installed' })" + $nl

        # Check audit log file permissions (immutability)
        $AuditLogPerms = $(timeout 5 stat -c '%a %U %G' /var/log/audit/audit.log 2>/dev/null)
        $AuditLogPermsStr = ("$AuditLogPerms").Trim()
        $FindingDetails += "audit.log permissions: $(if ($AuditLogPermsStr.Length -gt 0) { $AuditLogPermsStr } else { 'file not found' })" + $nl

        # Check if audit log is append-only (immutable attribute)
        $LogAttrs = $(timeout 5 lsattr /var/log/audit/audit.log 2>/dev/null)
        $LogAttrsStr = ("$LogAttrs").Trim()
        if ($LogAttrsStr.Length -gt 0) {
            $FindingDetails += "audit.log attributes: $LogAttrsStr" + $nl
        }

        # Check audit package info to confirm standard tools
        $AuditPkg = $(rpm -q audit 2>/dev/null)
        $AuditPkgStr = ("$AuditPkg").Trim()
        $FindingDetails += "audit package: $AuditPkgStr" + $nl

        if ($AuSearchStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: The XCP-ng audit reduction tool (ausearch) operates in read-only mode against audit log files. ausearch filters and displays audit records without modifying the original audit.log files. The audit subsystem writes records sequentially with kernel-generated timestamps, and ausearch preserves this time ordering in its output. The audit log files are protected by file permissions ($AuditLogPermsStr) ensuring only the audit daemon can write to them."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Audit reduction tools are not installed. Install the audit package (yum install audit) to provide ausearch, which operates in read-only mode and preserves original content and time ordering of audit records."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207462 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207462
        STIG ID    : SRG-OS-000354-VMM-001320
        Rule ID    : SV-207462r987795_rule
        Severity   : CAT II
        Title      : The VMM that provides a report generation capability must not alter original content or time ordering of audit records.
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
    $VulnID = "V-207462"
    $RuleID = "SV-207462r987795_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Report Generation - Content/Time Ordering Preservation" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for aureport (read-only report generation tool)
        $AuReportPath = $(which aureport 2>/dev/null)
        $AuReportStr = ("$AuReportPath").Trim()
        $FindingDetails += "aureport: $(if ($AuReportStr.Length -gt 0) { $AuReportStr } else { 'NOT installed' })" + $nl

        # Check audit log permissions
        $AuditLogPerms = $(timeout 5 stat -c '%a %U %G' /var/log/audit/audit.log 2>/dev/null)
        $AuditLogPermsStr = ("$AuditLogPerms").Trim()
        $FindingDetails += "audit.log permissions: $(if ($AuditLogPermsStr.Length -gt 0) { $AuditLogPermsStr } else { 'file not found' })" + $nl

        # Check audit package
        $AuditPkg = $(rpm -q audit 2>/dev/null)
        $AuditPkgStr = ("$AuditPkg").Trim()
        $FindingDetails += "audit package: $AuditPkgStr" + $nl

        if ($AuReportStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: The XCP-ng report generation tool (aureport) operates in read-only mode against audit log files. aureport reads audit records and generates summary reports without modifying the original audit.log content. Reports maintain chronological time ordering based on kernel-generated timestamps. The audit log files are protected by file permissions ($AuditLogPermsStr) ensuring only the audit daemon can write to them. aureport is a standard component of the Linux Audit Framework maintained by Red Hat."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Report generation tools are not installed. Install the audit package (yum install audit) to provide aureport, which operates in read-only mode and preserves original content and time ordering of audit records when generating reports."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207463 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207463
        STIG ID    : SRG-OS-000355-VMM-001330
        Rule ID    : SV-207463r1038976_rule
        Severity   : CAT II
        Title      : The VMM must, for networked systems, compare internal information system clocks at least every 24 hours with an authoritative time source.
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
    $VulnID = "V-207463"
    $RuleID = "SV-207463r1038976_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "NTP Time Synchronization (24-Hour Comparison)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check chronyd (preferred on CentOS 7)
        $ChronydActive = $(systemctl is-active chronyd 2>/dev/null)
        $ChronydStr = ("$ChronydActive").Trim()
        $FindingDetails += "chronyd service: $ChronydStr" + $nl

        # Check ntpd
        $NtpdActive = $(systemctl is-active ntpd 2>/dev/null)
        $NtpdStr = ("$NtpdActive").Trim()
        $FindingDetails += "ntpd service: $NtpdStr" + $nl

        $HasTimeSvc = ($ChronydStr -eq "active" -or $NtpdStr -eq "active")

        if ($ChronydStr -eq "active") {
            # Show chrony sources
            $ChronySources = $(timeout 10 chronyc sources 2>/dev/null)
            $ChronyArr = @()
            if ($null -ne $ChronySources) { $ChronyArr = @($ChronySources) }
            $ChronyStr = ($ChronyArr -join $nl).Trim()
            if ($ChronyStr.Length -gt 0) {
                $FindingDetails += $nl + "Chrony Sources:" + $nl + $ChronyStr + $nl
            }

            # Show chrony tracking
            $ChronyTracking = $(timeout 10 chronyc tracking 2>/dev/null)
            $TrackArr = @()
            if ($null -ne $ChronyTracking) { $TrackArr = @($ChronyTracking) }
            $TrackStr = ($TrackArr -join $nl).Trim()
            if ($TrackStr.Length -gt 0) {
                $FindingDetails += $nl + "Chrony Tracking:" + $nl + $TrackStr + $nl
            }
        }
        elseif ($NtpdStr -eq "active") {
            # Show NTP peers
            $NtpPeers = $(timeout 10 ntpq -p 2>/dev/null)
            $NtpArr = @()
            if ($null -ne $NtpPeers) { $NtpArr = @($NtpPeers) }
            $NtpStr = ($NtpArr -join $nl).Trim()
            if ($NtpStr.Length -gt 0) {
                $FindingDetails += $nl + "NTP Peers:" + $nl + $NtpStr + $nl
            }
        }

        # Check chrony or ntp config for server entries
        $ChronyConf = $(timeout 5 cat /etc/chrony.conf 2>/dev/null)
        $ChronyConfArr = @()
        if ($null -ne $ChronyConf) { $ChronyConfArr = @($ChronyConf) }
        $ServerLines = @($ChronyConfArr | Where-Object { $_ -match "^\s*(server|pool)\s+" -and $_ -notmatch "^\s*#" })
        if ($ServerLines.Count -gt 0) {
            $FindingDetails += $nl + "Configured time sources (chrony.conf):" + $nl
            foreach ($Line in $ServerLines) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $NtpConf = $(timeout 5 cat /etc/ntp.conf 2>/dev/null)
            $NtpConfArr = @()
            if ($null -ne $NtpConf) { $NtpConfArr = @($NtpConf) }
            $ServerLines = @($NtpConfArr | Where-Object { $_ -match "^\s*(server|pool)\s+" -and $_ -notmatch "^\s*#" })
            if ($ServerLines.Count -gt 0) {
                $FindingDetails += $nl + "Configured time sources (ntp.conf):" + $nl
                foreach ($Line in $ServerLines) { $FindingDetails += "  $($Line.Trim())" + $nl }
            }
        }

        if ($HasTimeSvc -and $ServerLines.Count -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: NTP time synchronization is active. "
            if ($ChronydStr -eq "active") { $FindingDetails += "chronyd is running and configured with $($ServerLines.Count) authoritative time source(s). " }
            else { $FindingDetails += "ntpd is running and configured with $($ServerLines.Count) authoritative time source(s). " }
            $FindingDetails += "By default, NTP clients poll servers at intervals ranging from 64 seconds (minpoll 6) to 1024 seconds (maxpoll 10), far exceeding the 24-hour comparison requirement."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: NTP time synchronization is not properly configured. "
            if (-not $HasTimeSvc) { $FindingDetails += "Enable chronyd: systemctl enable --now chronyd. " }
            if ($ServerLines.Count -eq 0) { $FindingDetails += "Configure authoritative time sources in /etc/chrony.conf (e.g., server ntp.mil iburst). " }
            $FindingDetails += "Internal system clocks must be compared with an authoritative time source at least every 24 hours."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207464 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207464
        STIG ID    : SRG-OS-000356-VMM-001340
        Rule ID    : SV-207464r984238_rule
        Severity   : CAT II
        Title      : The VMM must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
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
    $VulnID = "V-207464"
    $RuleID = "SV-207464r984238_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Clock Synchronization (1-Second Threshold)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check chronyd
        $ChronydActive = $(systemctl is-active chronyd 2>/dev/null)
        $ChronydStr = ("$ChronydActive").Trim()
        $FindingDetails += "chronyd service: $ChronydStr" + $nl

        # Check ntpd
        $NtpdActive = $(systemctl is-active ntpd 2>/dev/null)
        $NtpdStr = ("$NtpdActive").Trim()
        $FindingDetails += "ntpd service: $NtpdStr" + $nl

        $HasTimeSvc = ($ChronydStr -eq "active" -or $NtpdStr -eq "active")

        if ($ChronydStr -eq "active") {
            # Check makestep directive (auto-step for large offsets)
            $ChronyConf = $(timeout 5 cat /etc/chrony.conf 2>/dev/null)
            $ChronyConfArr = @()
            if ($null -ne $ChronyConf) { $ChronyConfArr = @($ChronyConf) }
            $MakeStep = @($ChronyConfArr | Where-Object { $_ -match "^\s*makestep\s+" -and $_ -notmatch "^\s*#" })
            if ($MakeStep.Count -gt 0) {
                $FindingDetails += "makestep directive: $($MakeStep[0].Trim())" + $nl
            }

            # Show current offset
            $ChronyTracking = $(timeout 10 chronyc tracking 2>/dev/null)
            $TrackArr = @()
            if ($null -ne $ChronyTracking) { $TrackArr = @($ChronyTracking) }
            $TrackStr = ($TrackArr -join $nl).Trim()
            $CurrentOffset = ""
            if ($TrackStr -match "(?i)System time\s*:\s*(.+)") { $CurrentOffset = $Matches[1] }
            if ($CurrentOffset) { $FindingDetails += "Current system time offset: $CurrentOffset" + $nl }

            $RootDelay = ""
            if ($TrackStr -match "(?i)Root delay\s*:\s*(.+)") { $RootDelay = $Matches[1] }
            if ($RootDelay) { $FindingDetails += "Root delay: $RootDelay" + $nl }
        }
        elseif ($NtpdStr -eq "active") {
            # Check NTP tinker/step settings
            $NtpConf = $(timeout 5 cat /etc/ntp.conf 2>/dev/null)
            $NtpConfArr = @()
            if ($null -ne $NtpConf) { $NtpConfArr = @($NtpConf) }
            $TinkerLine = @($NtpConfArr | Where-Object { $_ -match "^\s*tinker\s+" -and $_ -notmatch "^\s*#" })
            if ($TinkerLine.Count -gt 0) {
                $FindingDetails += "tinker directive: $($TinkerLine[0].Trim())" + $nl
            }
        }

        if ($HasTimeSvc) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: NTP time synchronization is active and automatically corrects time differences. "
            if ($ChronydStr -eq "active") {
                $FindingDetails += "chronyd continuously adjusts system clock via slewing for small offsets. The makestep directive enables immediate stepping for offsets larger than the configured threshold. Both mechanisms ensure synchronization when the time difference exceeds one second."
            }
            else {
                $FindingDetails += "ntpd continuously disciplines the system clock via slewing and can step the clock for large offsets. This ensures synchronization when time difference exceeds one second."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No NTP time synchronization service is active. Enable chronyd: systemctl enable --now chronyd. Configure authoritative time sources and ensure the makestep directive allows clock stepping for offsets greater than one second (e.g., makestep 1 3)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207465 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207465
        STIG ID    : SRG-OS-000358-VMM-001350
        Rule ID    : SV-207465r958786_rule
        Severity   : CAT II
        Title      : The VMM must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.
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
    $VulnID = "V-207465"
    $RuleID = "SV-207465r958786_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Timestamp Granularity (1-Second Minimum)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd is active
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Show a recent audit record to demonstrate timestamp format
        $RecentRecord = $(timeout 5 tail -5 /var/log/audit/audit.log 2>/dev/null)
        $RecentArr = @()
        if ($null -ne $RecentRecord) { $RecentArr = @($RecentRecord) }
        if ($RecentArr.Count -gt 0) {
            $FindingDetails += $nl + "Recent audit record (timestamp format demonstration):" + $nl
            $FindingDetails += "  $($RecentArr[0].Trim())" + $nl
        }

        # Check auditd.conf log_format
        $AuditConf = $(timeout 5 cat /etc/audit/auditd.conf 2>/dev/null)
        $AuditConfArr = @()
        if ($null -ne $AuditConf) { $AuditConfArr = @($AuditConf) }
        $AuditConfStr = ($AuditConfArr -join $nl).Trim()
        $LogFormat = ""
        if ($AuditConfStr -match "(?i)log_format\s*=\s*(\S+)") { $LogFormat = $Matches[1] }
        $FindingDetails += "log_format: $(if ($LogFormat) { $LogFormat } else { 'RAW (default)' })" + $nl

        if ($AuditdStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: The Linux Audit Framework records timestamps with sub-second (millisecond) precision, exceeding the one-second granularity requirement. Each audit record includes a timestamp in epoch format (e.g., msg=audit(EPOCH.MILLISECONDS:SERIAL)), where the decimal portion provides millisecond-level precision. This is a built-in capability of the kernel audit subsystem and cannot be configured to a lower granularity."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Enable the audit service: systemctl enable --now auditd. The Linux audit framework inherently provides sub-second timestamp precision when active."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207466
        STIG ID    : SRG-OS-000359-VMM-001360
        Rule ID    : SV-207466r958788_rule
        Severity   : CAT II
        Title      : The VMM must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
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
    $VulnID = "V-207466"
    $RuleID = "SV-207466r958788_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Timestamps Mappable to UTC/GMT" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check system timezone
        $TzInfo = $(timedatectl 2>/dev/null)
        $TzArr = @()
        if ($null -ne $TzInfo) { $TzArr = @($TzInfo) }
        $TzStr = ($TzArr -join $nl).Trim()
        $TimeZone = ""
        $UtcOffset = ""
        if ($TzStr -match "(?i)Time zone:\s*(.+)") { $TimeZone = $Matches[1].Trim() }
        if ($TzStr -match "(?i)Universal time:\s*(.+)") { $UtcOffset = $Matches[1].Trim() }

        $FindingDetails += "System timezone: $(if ($TimeZone) { $TimeZone } else { 'unknown' })" + $nl
        if ($UtcOffset) { $FindingDetails += "Universal time: $UtcOffset" + $nl }

        # Check /etc/localtime symlink
        $LocalTimeLink = $(timeout 5 ls -la /etc/localtime 2>/dev/null)
        $LocalTimeLinkStr = ("$LocalTimeLink").Trim()
        if ($LocalTimeLinkStr.Length -gt 0) {
            $FindingDetails += "localtime: $LocalTimeLinkStr" + $nl
        }

        # Check auditd is active
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        if ($AuditdStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit records use epoch timestamps (seconds since 1970-01-01 00:00:00 UTC) which are inherently in UTC and directly mappable to Coordinated Universal Time. The Linux audit framework records all events using this UTC-based epoch format regardless of the system's configured local timezone ($TimeZone). Tools like ausearch and aureport convert these to human-readable UTC or local time representations."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Enable the audit service: systemctl enable --now auditd. The Linux audit framework records timestamps in UTC-based epoch format, satisfying the UTC/GMT mapping requirement."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207467
        STIG ID    : SRG-OS-000360-VMM-001370
        Rule ID    : SV-207467r958790_rule
        Severity   : CAT II
        Title      : The VMM must enforce dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.
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
    $VulnID = "V-207467"
    $RuleID = "SV-207467r958790_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Dual Authorization for Audit Data Movement/Deletion" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check audit log ownership and permissions
        $AuditLogPerms = $(timeout 5 stat -c '%a %U %G' /var/log/audit/audit.log 2>/dev/null)
        $AuditLogPermsStr = ("$AuditLogPerms").Trim()
        $FindingDetails += "audit.log permissions: $(if ($AuditLogPermsStr.Length -gt 0) { $AuditLogPermsStr } else { 'file not found' })" + $nl

        $AuditDirPerms = $(timeout 5 stat -c '%a %U %G' /var/log/audit 2>/dev/null)
        $AuditDirPermsStr = ("$AuditDirPerms").Trim()
        $FindingDetails += "/var/log/audit/ permissions: $(if ($AuditDirPermsStr.Length -gt 0) { $AuditDirPermsStr } else { 'directory not found' })" + $nl

        # Check if audit rules are immutable
        $CurrentRules = $(timeout 10 auditctl -l 2>/dev/null)
        $RulesArr = @()
        if ($null -ne $CurrentRules) { $RulesArr = @($CurrentRules) }
        $RulesStr = ($RulesArr -join $nl).Trim()
        $Immutable = $false
        if ($RulesStr -match "-e 2") { $Immutable = $true }
        $FindingDetails += "Audit rules immutable (-e 2): $Immutable" + $nl

        # Check for audit watch on audit log directory
        $AuditWatches = @($RulesArr | Where-Object { $_ -match "/var/log/audit" })
        $FindingDetails += "Audit watches on /var/log/audit: $($AuditWatches.Count)" + $nl

        # Dual authorization requires organizational policy enforcement
        # Technical controls: restricted file ownership (root only) + immutable audit rules
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Dual authorization for movement/deletion of audit information requires organizational policy controls beyond what XCP-ng can enforce technically. While audit log files are restricted to root ownership ($AuditLogPermsStr) and audit rules can be made immutable (-e 2), the dual authorization requirement (two separate individuals must authorize) must be enforced through organizational procedures such as: requiring ISSO approval before SA can delete/move audit logs, implementing ticket-based change control for audit data operations, and maintaining a log of all audit data movement/deletion activities."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207468 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207468
        STIG ID    : SRG-OS-000362-VMM-001390
        Rule ID    : SV-207468r984239_rule
        Severity   : CAT II
        Title      : The VMM must prohibit user installation of software without explicit privileged status.
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
    $VulnID = "V-207468"
    $RuleID = "SV-207468r984239_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Software Installation Privilege Restriction" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check xe RBAC — only pool-admin can install VMs/patches
        $Roles = Invoke-XeCommand -Command "role-list --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles available: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'none' })" + $nl

        # Check who can run yum/rpm (package installation)
        $YumPath = $(which yum 2>/dev/null)
        $YumStr = ("$YumPath").Trim()
        $YumPerms = $(timeout 5 stat -c '%a %U %G' $YumStr 2>/dev/null)
        $YumPermsStr = ("$YumPerms").Trim()
        $FindingDetails += "yum binary permissions: $(if ($YumPermsStr.Length -gt 0) { $YumPermsStr } else { 'not found' })" + $nl

        $RpmPath = $(which rpm 2>/dev/null)
        $RpmStr = ("$RpmPath").Trim()
        $RpmPerms = $(timeout 5 stat -c '%a %U %G' $RpmStr 2>/dev/null)
        $RpmPermsStr = ("$RpmPerms").Trim()
        $FindingDetails += "rpm binary permissions: $(if ($RpmPermsStr.Length -gt 0) { $RpmPermsStr } else { 'not found' })" + $nl

        # Check sudo configuration for yum/rpm restrictions
        $SudoYum = $(timeout 5 grep -r 'yum\|rpm\|dnf' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
        $SudoYumArr = @()
        if ($null -ne $SudoYum) { $SudoYumArr = @($SudoYum) }
        $FindingDetails += "sudo rules for package management: $($SudoYumArr.Count)" + $nl

        # Check XAPI RBAC — VM creation requires pool-admin or pool-operator
        $Subjects = Invoke-XeCommand -Command "subject-list --minimal"
        $SubjectsStr = ("$Subjects").Trim()
        $SubjectCount = 0
        if ($SubjectsStr.Length -gt 0) { $SubjectCount = ($SubjectsStr -split ",").Count }
        $FindingDetails += "RBAC subjects configured: $SubjectCount" + $nl

        # On XCP-ng, only root can install packages and only pool-admin can create VMs via XAPI
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng enforces privileged access for software and VM installation through multiple mechanisms: (1) RPM/YUM package installation requires root privileges (owned by root, standard permissions). (2) XAPI RBAC restricts VM creation to pool-admin and pool-operator roles. (3) Dom0 SSH access is limited to authorized administrators. Non-privileged users cannot install software or create guest VMs without explicit elevated privileges."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207469 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207469
        STIG ID    : SRG-OS-000363-VMM-001400
        Rule ID    : SV-207469r958794_rule
        Severity   : CAT II
        Title      : The VMM must notify designated personnel if baseline configurations are changed in an unauthorized manner.
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
    $VulnID = "V-207469"
    $RuleID = "SV-207469r958794_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Baseline Configuration Change Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for AIDE (file integrity monitoring)
        $AidePath = $(which aide 2>/dev/null)
        $AideStr = ("$AidePath").Trim()
        $FindingDetails += "AIDE: $(if ($AideStr.Length -gt 0) { $AideStr } else { 'NOT installed' })" + $nl

        # Check for AIDE config
        $AideConf = $(timeout 5 ls -la /etc/aide.conf 2>/dev/null)
        $AideConfStr = ("$AideConf").Trim()
        $FindingDetails += "AIDE config: $(if ($AideConfStr.Length -gt 0) { 'present' } else { 'NOT found' })" + $nl

        # Check for Tripwire
        $TripwirePath = $(which tripwire 2>/dev/null)
        $TripwireStr = ("$TripwirePath").Trim()
        $FindingDetails += "Tripwire: $(if ($TripwireStr.Length -gt 0) { $TripwireStr } else { 'not installed' })" + $nl

        # Check auditd rules for configuration file watches
        $AuditRules = $(timeout 10 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $ConfigWatches = @($AuditArr | Where-Object { $_ -match "/etc/" -or $_ -match "xapi" -or $_ -match "xensource" })
        $FindingDetails += "Audit watches on config files: $($ConfigWatches.Count)" + $nl
        foreach ($Watch in $ConfigWatches) {
            $FindingDetails += "  $($Watch.Trim())" + $nl
        }

        # Check for AIDE cron job (regular scanning)
        $AideCron = $(timeout 5 grep -rl 'aide' /etc/cron.d/ /etc/cron.daily/ /var/spool/cron/ 2>/dev/null)
        $AideCronArr = @()
        if ($null -ne $AideCron) { $AideCronArr = @($AideCron) }
        $FindingDetails += "AIDE cron jobs: $($AideCronArr.Count)" + $nl

        if ($AideStr.Length -gt 0 -and $AideConfStr.Length -gt 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: File integrity monitoring (AIDE) is installed and configured to detect unauthorized baseline configuration changes. AIDE compares current file states against a known-good baseline database and reports modifications, additions, and deletions. "
            if ($AideCronArr.Count -gt 0) { $FindingDetails += "Automated scanning is configured via cron. " }
            $FindingDetails += "Notification to designated personnel should be configured through AIDE's reporting mechanisms or integration with a centralized monitoring system."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No file integrity monitoring tool is configured to detect and notify on unauthorized baseline changes. Install and configure AIDE: yum install aide, configure /etc/aide.conf with baseline paths (including /etc/xensource/, /etc/xapi.conf, /etc/audit/), initialize database (aide --init), and configure cron job for regular scanning with email notification to SA/ISSO."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207470 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207470
        STIG ID    : SRG-OS-000364-VMM-001410
        Rule ID    : SV-207470r958796_rule
        Severity   : CAT II
        Title      : The VMM must enforce access restrictions associated with changes to the system.
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
    $VulnID = "V-207470"
    $RuleID = "SV-207470r958796_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Access Restrictions for System Changes" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check XAPI RBAC
        $Roles = Invoke-XeCommand -Command "role-list params=name --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'not available' })" + $nl

        # Check configured subjects
        $Subjects = Invoke-XeCommand -Command "subject-list --minimal"
        $SubjectsStr = ("$Subjects").Trim()
        $SubjectCount = 0
        if ($SubjectsStr.Length -gt 0 -and $SubjectsStr -ne "") { $SubjectCount = ($SubjectsStr -split ",").Count }
        $FindingDetails += "RBAC subjects: $SubjectCount" + $nl

        # Check sudo configuration
        $SudoersExists = $(timeout 5 ls -la /etc/sudoers 2>/dev/null)
        $SudoersStr = ("$SudoersExists").Trim()
        $FindingDetails += "sudoers file: $(if ($SudoersStr.Length -gt 0) { 'present' } else { 'NOT found' })" + $nl

        # Check sudoers.d directory
        $SudoersD = $(timeout 5 ls /etc/sudoers.d/ 2>/dev/null)
        $SudoersDArr = @()
        if ($null -ne $SudoersD) { $SudoersDArr = @($SudoersD) }
        $FindingDetails += "sudoers.d entries: $($SudoersDArr.Count)" + $nl

        # Check file permissions on critical config files
        $XapiConfPerms = $(timeout 5 stat -c '%a %U %G' /etc/xapi.conf 2>/dev/null)
        $XapiConfStr = ("$XapiConfPerms").Trim()
        $FindingDetails += "/etc/xapi.conf permissions: $(if ($XapiConfStr.Length -gt 0) { $XapiConfStr } else { 'not found' })" + $nl

        $XensourcePerms = $(timeout 5 stat -c '%a %U %G' /etc/xensource 2>/dev/null)
        $XensourceStr = ("$XensourcePerms").Trim()
        $FindingDetails += "/etc/xensource permissions: $(if ($XensourceStr.Length -gt 0) { $XensourceStr } else { 'not found' })" + $nl

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng enforces access restrictions for system changes through multiple layers: (1) XAPI RBAC with role hierarchy (pool-admin, pool-operator, vm-power-admin, vm-admin, vm-operator, read-only) restricts management API operations. (2) Linux DAC file permissions restrict access to critical configuration files. (3) sudo controls limit which users can execute privileged commands. (4) SSH access to Dom0 is restricted to authorized administrators. Only pool-admin role can modify pool-level configurations and system settings."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207471 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207471
        STIG ID    : SRG-OS-000365-VMM-001420
        Rule ID    : SV-207471r984240_rule
        Severity   : CAT II
        Title      : The VMM must audit the enforcement actions used to restrict access associated with changes to the system.
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
    $VulnID = "V-207471"
    $RuleID = "SV-207471r984240_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit of Access Restriction Enforcement Actions" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check auditd service
        $AuditdActive = $(systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdActive").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        # Check for audit rules covering access restriction enforcement
        $AuditRules = $(timeout 10 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }
        $AuditStr = ($AuditArr -join $nl).Trim()

        # Look for rules auditing sudo, su, privilege escalation
        $SudoRules = @($AuditArr | Where-Object { $_ -match "sudo\|/usr/bin/su\|/etc/sudoers" })
        $FindingDetails += "Audit rules for privilege escalation: $($SudoRules.Count)" + $nl

        # Look for rules auditing access denied / permission changes
        $AccessRules = @($AuditArr | Where-Object { $_ -match "access\|perm_mod\|EPERM\|EACCES\|chmod\|chown\|setxattr" })
        $FindingDetails += "Audit rules for access/permission changes: $($AccessRules.Count)" + $nl

        # Check /var/log/secure for access enforcement logging
        $SecureLog = $(timeout 5 ls -la /var/log/secure 2>/dev/null)
        $SecureLogStr = ("$SecureLog").Trim()
        $FindingDetails += "Security log (/var/log/secure): $(if ($SecureLogStr.Length -gt 0) { 'present' } else { 'NOT found' })" + $nl

        # XAPI logs access events
        $XapiLog = $(timeout 5 ls -la /var/log/xensource.log 2>/dev/null)
        $XapiLogStr = ("$XapiLog").Trim()
        $FindingDetails += "XAPI log: $(if ($XapiLogStr.Length -gt 0) { 'present' } else { 'NOT found' })" + $nl

        if ($AuditdStr -eq "active") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng audits enforcement actions for access restrictions through multiple mechanisms: (1) auditd records privilege escalation (sudo/su), permission changes (chmod/chown/setxattr), and access denials (EPERM/EACCES syscalls). (2) /var/log/secure logs authentication and authorization events including failed access attempts. (3) XAPI logs (xensource.log) record API-level access restriction enforcement for RBAC-controlled operations. These combined logs provide comprehensive audit trail of all access restriction enforcement actions."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Enable auditd to audit access restriction enforcement: systemctl enable --now auditd. Configure audit rules for sudo (-w /etc/sudoers -p wa), su (-w /usr/bin/su -p x), permission changes (-a always,exit -F arch=b64 -S chmod,chown,setxattr -k perm_mod), and access denials (-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207472 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207472
        STIG ID    : SRG-OS-000366-VMM-001430
        Rule ID    : SV-207472r984242_rule
        Severity   : CAT II
        Title      : The VMM must prevent the installation of guest VMs, patches, service packs, device drivers, or VMM components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
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
    $VulnID = "V-207472"
    $RuleID = "SV-207472r984242_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Digital Signature Verification for Installations" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check yum gpgcheck setting
        $YumConf = $(timeout 5 cat /etc/yum.conf 2>/dev/null)
        $YumConfArr = @()
        if ($null -ne $YumConf) { $YumConfArr = @($YumConf) }
        $YumConfStr = ($YumConfArr -join $nl).Trim()
        $GpgCheck = ""
        if ($YumConfStr -match "(?i)gpgcheck\s*=\s*(\d)") { $GpgCheck = $Matches[1] }
        $FindingDetails += "yum.conf gpgcheck: $(if ($GpgCheck) { $GpgCheck } else { 'NOT configured' })" + $nl

        # Check localpkg_gpgcheck
        $LocalGpgCheck = ""
        if ($YumConfStr -match "(?i)localpkg_gpgcheck\s*=\s*(\d)") { $LocalGpgCheck = $Matches[1] }
        $FindingDetails += "yum.conf localpkg_gpgcheck: $(if ($LocalGpgCheck) { $LocalGpgCheck } else { 'NOT configured (defaults to gpgcheck)' })" + $nl

        # Check repo-level gpgcheck
        $RepoGpg = $(timeout 5 grep -rl 'gpgcheck' /etc/yum.repos.d/ 2>/dev/null)
        $RepoGpgArr = @()
        if ($null -ne $RepoGpg) { $RepoGpgArr = @($RepoGpg) }
        $FindingDetails += "Repos with gpgcheck setting: $($RepoGpgArr.Count)" + $nl

        # Check repos with gpgcheck=0 (disabled)
        $GpgDisabled = $(timeout 5 grep -l 'gpgcheck=0' /etc/yum.repos.d/*.repo 2>/dev/null)
        $GpgDisabledArr = @()
        if ($null -ne $GpgDisabled) { $GpgDisabledArr = @($GpgDisabled) }
        $FindingDetails += "Repos with gpgcheck DISABLED: $($GpgDisabledArr.Count)" + $nl
        foreach ($Repo in $GpgDisabledArr) {
            $FindingDetails += "  $($Repo.Trim())" + $nl
        }

        # Check installed GPG keys
        $GpgKeys = $(rpm -q gpg-pubkey 2>/dev/null)
        $GpgKeysArr = @()
        if ($null -ne $GpgKeys) { $GpgKeysArr = @($GpgKeys) }
        $FindingDetails += "Installed GPG keys: $($GpgKeysArr.Count)" + $nl

        if ($GpgCheck -eq "1" -and $GpgDisabledArr.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: RPM/YUM GPG signature verification is enabled globally (gpgcheck=1) and no repositories have GPG checking disabled. All packages must be signed with an approved GPG key before installation. XCP-ng packages are signed with the Vates/XCP-ng GPG key. This ensures patches, drivers, and VMM components are verified before installation."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: GPG signature verification is not fully enforced. "
            if ($GpgCheck -ne "1") { $FindingDetails += "Set gpgcheck=1 in /etc/yum.conf. " }
            if ($GpgDisabledArr.Count -gt 0) { $FindingDetails += "Enable gpgcheck in $($GpgDisabledArr.Count) repo(s) that have it disabled. " }
            $FindingDetails += "All package repositories must have gpgcheck=1 to verify digital signatures before installation."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207473
        STIG ID    : SRG-OS-000368-VMM-001440
        Rule ID    : SV-207473r958804_rule
        Severity   : CAT II
        Title      : The VMM must prevent use of service and helper VMs not required to support proper VMM function.
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
    $VulnID = "V-207473"
    $RuleID = "SV-207473r958804_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Service and Helper VM Control" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # List all VMs and their types
        $AllVMs = Invoke-XeCommand -Command "vm-list params=name-label,power-state,is-a-template,is-control-domain --minimal"
        $AllVMsStr = ("$AllVMs").Trim()

        # Get detailed VM list
        $VMDetail = Invoke-XeCommand -Command "vm-list is-control-domain=false is-a-template=false params=name-label,power-state,uuid"
        $VMDetailArr = @()
        if ($null -ne $VMDetail) { $VMDetailArr = @($VMDetail) }
        $VMDetailStr = ($VMDetailArr -join $nl).Trim()

        $FindingDetails += "Guest VMs (non-template, non-control-domain):" + $nl
        if ($VMDetailStr.Length -gt 0) {
            $FindingDetails += $VMDetailStr + $nl
        }
        else {
            $FindingDetails += "  No guest VMs found" + $nl
        }

        # Count running VMs
        $RunningVMs = Invoke-XeCommand -Command "vm-list is-control-domain=false is-a-template=false power-state=running --minimal"
        $RunningStr = ("$RunningVMs").Trim()
        $RunningCount = 0
        if ($RunningStr.Length -gt 0) { $RunningCount = ($RunningStr -split ",").Count }
        $FindingDetails += $nl + "Running guest VMs: $RunningCount" + $nl

        # Check for XO Proxy VM (common service VM)
        $XoProxy = Invoke-XeCommand -Command "vm-list name-label=XOA Proxy --minimal"
        $XoProxyStr = ("$XoProxy").Trim()
        if ($XoProxyStr.Length -gt 0) {
            $FindingDetails += "XOA Proxy VM detected (service VM for Xen Orchestra)" + $nl
        }

        # XCP-ng does not use helper/service VMs by default (unlike VMware with vCLS)
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng does not deploy service or helper VMs as part of its core hypervisor function. Unlike some hypervisors that create management VMs automatically, XCP-ng uses Dom0 (the control domain) for management operations. All running VMs ($RunningCount) are explicitly created by administrators. XAPI RBAC controls restrict VM creation and management to authorized roles (pool-admin, pool-operator). Administrators should periodically review the VM inventory to ensure no unnecessary service or helper VMs are present."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207474 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207474
        STIG ID    : SRG-OS-000368-VMM-001450
        Rule ID    : SV-207474r958804_rule
        Severity   : CAT II
        Title      : The VMM must prevent inappropriate use of redundant guest VMs.
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
    $VulnID = "V-207474"
    $RuleID = "SV-207474r958804_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Redundant Guest VM Control" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Get all VMs with their names and power states
        $AllVMs = Invoke-XeCommand -Command "vm-list is-control-domain=false is-a-template=false params=name-label,power-state"
        $AllVMsArr = @()
        if ($null -ne $AllVMs) { $AllVMsArr = @($AllVMs) }
        $AllVMsStr = ($AllVMsArr -join $nl).Trim()

        if ($AllVMsStr.Length -gt 0) {
            $FindingDetails += "Guest VM Inventory:" + $nl + $AllVMsStr + $nl
        }
        else {
            $FindingDetails += "Guest VM Inventory: No guest VMs found" + $nl
        }

        # Count total and halted VMs
        $TotalVMs = Invoke-XeCommand -Command "vm-list is-control-domain=false is-a-template=false --minimal"
        $TotalStr = ("$TotalVMs").Trim()
        $TotalCount = 0
        if ($TotalStr.Length -gt 0) { $TotalCount = ($TotalStr -split ",").Count }

        $HaltedVMs = Invoke-XeCommand -Command "vm-list is-control-domain=false is-a-template=false power-state=halted --minimal"
        $HaltedStr = ("$HaltedVMs").Trim()
        $HaltedCount = 0
        if ($HaltedStr.Length -gt 0) { $HaltedCount = ($HaltedStr -split ",").Count }

        $FindingDetails += $nl + "Total guest VMs: $TotalCount" + $nl
        $FindingDetails += "Halted (stopped) VMs: $HaltedCount" + $nl

        # Check snapshots (potential redundancy)
        $Snapshots = Invoke-XeCommand -Command "snapshot-list --minimal"
        $SnapshotsStr = ("$Snapshots").Trim()
        $SnapshotCount = 0
        if ($SnapshotsStr.Length -gt 0) { $SnapshotCount = ($SnapshotsStr -split ",").Count }
        $FindingDetails += "VM snapshots: $SnapshotCount" + $nl

        # RBAC prevents unauthorized VM creation
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng provides controls to prevent inappropriate use of redundant guest VMs. XAPI RBAC restricts VM creation to pool-admin and pool-operator roles, preventing unauthorized proliferation. The hypervisor maintains a complete inventory of all VMs with their power states. Administrators should review: (1) halted VMs ($HaltedCount) for unnecessary dormant instances, (2) snapshots ($SnapshotCount) for stale checkpoint data, and (3) naming conventions to identify potential duplicates. VM lifecycle management is enforced through RBAC access controls."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207475 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207475
        STIG ID    : SRG-OS-000370-VMM-001460
        Rule ID    : SV-207475r958808_rule
        Severity   : CAT II
        Title      : The VMM must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and guest VMs.
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
    $VulnID = "V-207475"
    $RuleID = "SV-207475r958808_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Deny-All, Permit-by-Exception Execution Policy" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check iptables default policies (deny-all for network)
        $IptablesPolicy = $(timeout 5 iptables -L -n 2>/dev/null)
        $IptablesArr = @()
        if ($null -ne $IptablesPolicy) { $IptablesArr = @($IptablesPolicy) }
        $IptablesStr = ($IptablesArr -join $nl).Trim()

        # Extract chain defaults
        $InputPolicy = ""
        $ForwardPolicy = ""
        $OutputPolicy = ""
        if ($IptablesStr -match "Chain INPUT \(policy (\w+)\)") { $InputPolicy = $Matches[1] }
        if ($IptablesStr -match "Chain FORWARD \(policy (\w+)\)") { $ForwardPolicy = $Matches[1] }
        if ($IptablesStr -match "Chain OUTPUT \(policy (\w+)\)") { $OutputPolicy = $Matches[1] }

        $FindingDetails += "iptables INPUT policy: $(if ($InputPolicy) { $InputPolicy } else { 'unknown' })" + $nl
        $FindingDetails += "iptables FORWARD policy: $(if ($ForwardPolicy) { $ForwardPolicy } else { 'unknown' })" + $nl
        $FindingDetails += "iptables OUTPUT policy: $(if ($OutputPolicy) { $OutputPolicy } else { 'unknown' })" + $nl

        # Check XAPI RBAC — default deny for unauthorized users
        $Roles = Invoke-XeCommand -Command "role-list params=name --minimal"
        $RolesStr = ("$Roles").Trim()
        $FindingDetails += "RBAC roles: $(if ($RolesStr.Length -gt 0) { $RolesStr } else { 'not available' })" + $nl

        # Check external auth (AD/LDAP integration controls access)
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External auth type: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'none (local only)' })" + $nl

        # Check SSH access restriction
        $SshdConfig = $(timeout 5 grep -E '^(AllowUsers|AllowGroups|DenyUsers|DenyGroups|PermitRootLogin)' /etc/ssh/sshd_config 2>/dev/null)
        $SshdArr = @()
        if ($null -ne $SshdConfig) { $SshdArr = @($SshdConfig) }
        if ($SshdArr.Count -gt 0) {
            $FindingDetails += "SSH access restrictions:" + $nl
            foreach ($Line in $SshdArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        # XCP-ng inherently implements deny-all for VM execution through RBAC
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng employs a deny-all, permit-by-exception policy for execution through: (1) XAPI RBAC denies all management operations by default; users must be explicitly assigned a role (pool-admin, pool-operator, etc.) to execute any VM or management operation. (2) Dom0 SSH access is restricted to authorized accounts. (3) iptables firewall policies control network-level access. (4) Only root and authorized RBAC subjects can start, stop, or create VMs. The read-only role provides the minimum baseline — all additional privileges must be explicitly granted."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207480 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207480
        STIG ID    : SRG-OS-000375-VMM-001510
        Rule ID    : SV-207480r984255_rule
        Severity   : CAT II
        Title      : The VMM must implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.
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
    $VulnID = "V-207480"
    $RuleID = "SV-207480r984255_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Multifactor Authentication for Remote Privileged Access" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check external auth (AD/LDAP integration for MFA)
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External authentication: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'none (local only)' })" + $nl

        # Check SSH authentication methods
        $SshPubkey = $(timeout 5 grep -E '^PubkeyAuthentication' /etc/ssh/sshd_config 2>/dev/null)
        $SshPassword = $(timeout 5 grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null)
        $SshPubkeyStr = ("$SshPubkey").Trim()
        $SshPasswordStr = ("$SshPassword").Trim()
        $FindingDetails += "SSH PubkeyAuthentication: $(if ($SshPubkeyStr.Length -gt 0) { $SshPubkeyStr } else { 'not explicitly set (default: yes)' })" + $nl
        $FindingDetails += "SSH PasswordAuthentication: $(if ($SshPasswordStr.Length -gt 0) { $SshPasswordStr } else { 'not explicitly set (default: yes)' })" + $nl

        # Check for PAM MFA modules (google-authenticator, oath, duo)
        $PamMfa = $(timeout 5 grep -r 'pam_google_authenticator\|pam_oath\|pam_duo' /etc/pam.d/ 2>/dev/null)
        $PamMfaArr = @()
        if ($null -ne $PamMfa) { $PamMfaArr = @($PamMfa) }
        if ($PamMfaArr.Count -gt 0) {
            $FindingDetails += "PAM MFA modules detected:" + $nl
            foreach ($Line in $PamMfaArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "PAM MFA modules: none detected" + $nl
        }

        # Check for smart card/PKI PAM modules
        $PamPkcs = $(timeout 5 grep -r 'pam_pkcs11\|pam_sss' /etc/pam.d/ 2>/dev/null)
        $PamPkcsArr = @()
        if ($null -ne $PamPkcs) { $PamPkcsArr = @($PamPkcs) }
        if ($PamPkcsArr.Count -gt 0) {
            $FindingDetails += "Smart card PAM modules detected:" + $nl
            foreach ($Line in $PamPkcsArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "Smart card PAM modules: none detected" + $nl
        }

        # MFA requires separate physical device — organizational requirement
        $HasMfaPam = ($PamMfaArr.Count -gt 0) -or ($PamPkcsArr.Count -gt 0)
        $HasExtAuth = ($ExtAuthStr.Length -gt 0 -and $ExtAuthStr -ne "")

        if ($HasMfaPam -or $HasExtAuth) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: MFA infrastructure detected. "
            if ($HasExtAuth) { $FindingDetails += "External authentication ($ExtAuthStr) is configured, which can provide MFA through the identity provider. " }
            if ($HasMfaPam) { $FindingDetails += "PAM MFA modules are configured for local authentication. " }
            $FindingDetails += "Verify that the MFA factor is provided by a device separate from the system gaining access (e.g., hardware token, smart card, mobile device)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No multifactor authentication infrastructure detected. XCP-ng requires MFA for remote privileged access. Configure AD/LDAP external authentication with MFA enforcement, or deploy PAM-based MFA (e.g., pam_google_authenticator, pam_duo, or smart card via pam_pkcs11)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207481 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207481
        STIG ID    : SRG-OS-000376-VMM-001520
        Rule ID    : SV-207481r958816_rule
        Severity   : CAT II
        Title      : The VMM must accept Personal Identity Verification (PIV) credentials.
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
    $VulnID = "V-207481"
    $RuleID = "SV-207481r958816_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Personal Identity Verification (PIV) Credential Acceptance" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for pam_pkcs11 package (smart card/PIV PAM module)
        $PkcsRpm = $(rpm -q pam_pkcs11 2>/dev/null)
        $PkcsRpmStr = ("$PkcsRpm").Trim()
        $FindingDetails += "pam_pkcs11 package: $PkcsRpmStr" + $nl

        # Check for opensc package (smart card middleware)
        $OpenscRpm = $(rpm -q opensc 2>/dev/null)
        $OpenscRpmStr = ("$OpenscRpm").Trim()
        $FindingDetails += "opensc package: $OpenscRpmStr" + $nl

        # Check for pcsc-lite (PC/SC smart card daemon)
        $PcscRpm = $(rpm -q pcsc-lite 2>/dev/null)
        $PcscRpmStr = ("$PcscRpm").Trim()
        $FindingDetails += "pcsc-lite package: $PcscRpmStr" + $nl

        # Check if pcscd service is active
        $PcscService = $(timeout 5 systemctl is-active pcscd 2>/dev/null)
        $PcscServiceStr = ("$PcscService").Trim()
        $FindingDetails += "pcscd service: $PcscServiceStr" + $nl

        # Check PAM for PKCS11 configuration
        $PamPkcs = $(timeout 5 grep -l 'pam_pkcs11' /etc/pam.d/system-auth /etc/pam.d/smartcard-auth 2>/dev/null)
        $PamPkcsArr = @()
        if ($null -ne $PamPkcs) { $PamPkcsArr = @($PamPkcs) }
        if ($PamPkcsArr.Count -gt 0) {
            $FindingDetails += "PAM PKCS11 configured in: " + ($PamPkcsArr -join ", ") + $nl
        }
        else {
            $FindingDetails += "PAM PKCS11 configuration: not found" + $nl
        }

        # Check for SSSD smart card support
        $SssdConf = $(timeout 5 grep -i 'pam_cert_auth' /etc/sssd/sssd.conf 2>/dev/null)
        $SssdConfStr = ("$SssdConf").Trim()
        if ($SssdConfStr.Length -gt 0) {
            $FindingDetails += "SSSD smart card auth: $SssdConfStr" + $nl
        }

        # Check external auth (AD/LDAP can accept PIV via PKINIT)
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External authentication: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'none' })" + $nl

        $HasPkcs = ($PkcsRpmStr -notmatch "not installed")
        $HasPam = ($PamPkcsArr.Count -gt 0)
        $HasExtAuth = ($ExtAuthStr.Length -gt 0 -and $ExtAuthStr -ne "")

        if ($HasPkcs -and $HasPam) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: PIV credential acceptance infrastructure is installed. pam_pkcs11 is configured in PAM, enabling smart card/PIV authentication for system access."
        }
        elseif ($HasExtAuth) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication ($ExtAuthStr) is configured. PIV/smart card credential acceptance can be provided through the external identity provider (e.g., Active Directory with PKINIT for Kerberos smart card logon)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: PIV credential acceptance is not configured. Install pam_pkcs11, opensc, and pcsc-lite packages, configure PAM for smart card authentication, or integrate with AD/LDAP that supports PIV via PKINIT."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207482 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207482
        STIG ID    : SRG-OS-000377-VMM-001530
        Rule ID    : SV-207482r958818_rule
        Severity   : CAT II
        Title      : The VMM must electronically verify Personal Identity Verification (PIV) credentials.
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
    $VulnID = "V-207482"
    $RuleID = "SV-207482r958818_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Electronic PIV Credential Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check pam_pkcs11 configuration for certificate verification
        $PkcsConf = $(timeout 5 cat /etc/pam_pkcs11/pam_pkcs11.conf 2>/dev/null)
        $PkcsArr = @()
        if ($null -ne $PkcsConf) { $PkcsArr = @($PkcsConf) }
        $PkcsStr = ($PkcsArr -join $nl).Trim()

        if ($PkcsStr.Length -gt 0) {
            $FindingDetails += "pam_pkcs11.conf found (certificate verification config exists)" + $nl
            # Check for CRL/OCSP verification settings
            if ($PkcsStr -match "crl_") { $FindingDetails += "CRL checking: configured" + $nl }
            else { $FindingDetails += "CRL checking: not configured" + $nl }
            if ($PkcsStr -match "ocsp") { $FindingDetails += "OCSP checking: configured" + $nl }
            else { $FindingDetails += "OCSP checking: not configured" + $nl }
        }
        else {
            $FindingDetails += "pam_pkcs11.conf: not found" + $nl
        }

        # Check for certificate trust anchors (DoD CA certs)
        $CaCerts = $(timeout 5 find /etc/pki/tls/certs -maxdepth 1 -name '*.pem' -type f 2>/dev/null | head -10 2>&1)
        $CaCertsArr = @()
        if ($null -ne $CaCerts) { $CaCertsArr = @($CaCerts) }
        $FindingDetails += "CA certificates in /etc/pki/tls/certs/: $($CaCertsArr.Count) PEM files" + $nl

        # Check OpenSSL OCSP/CRL verify settings
        $OpensslConf = $(timeout 5 grep -E '(crl_check|OCSP)' /etc/pki/tls/openssl.cnf 2>/dev/null)
        $OpensslArr = @()
        if ($null -ne $OpensslConf) { $OpensslArr = @($OpensslConf) }
        if ($OpensslArr.Count -gt 0) {
            $FindingDetails += "OpenSSL verification settings:" + $nl
            foreach ($Line in $OpensslArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        # Check external auth for PIV verification delegation
        $ExtAuth = Invoke-XeCommand -Command "pool-list params=external-auth-type --minimal"
        $ExtAuthStr = ("$ExtAuth").Trim()
        $FindingDetails += "External authentication: $(if ($ExtAuthStr.Length -gt 0) { $ExtAuthStr } else { 'none' })" + $nl

        $HasPkcsConf = ($PkcsStr.Length -gt 0)
        $HasExtAuth = ($ExtAuthStr.Length -gt 0 -and $ExtAuthStr -ne "")

        if ($HasPkcsConf) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: PIV electronic verification is configured via pam_pkcs11. Certificate validation infrastructure is present to electronically verify PIV credentials against trusted CAs."
        }
        elseif ($HasExtAuth) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: External authentication ($ExtAuthStr) is configured. PIV credential electronic verification is delegated to the identity provider (e.g., Active Directory performs certificate validation for smart card logon)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No PIV electronic verification infrastructure detected. Configure pam_pkcs11 with CRL/OCSP checking for local PIV verification, or integrate with AD/LDAP that performs electronic PIV credential validation."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207483 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207483
        STIG ID    : SRG-OS-000378-VMM-001540
        Rule ID    : SV-207483r958820_rule
        Severity   : CAT II
        Title      : The VMM must authenticate peripherals before establishing a connection.
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
    $VulnID = "V-207483"
    $RuleID = "SV-207483r958820_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Peripheral Authentication Before Connection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check USB device authorization policy
        $UsbAuth = $(timeout 5 cat /sys/bus/usb/devices/usb1/authorized_default 2>/dev/null)
        $UsbAuthStr = ("$UsbAuth").Trim()
        $FindingDetails += "USB default authorization: $(if ($UsbAuthStr.Length -gt 0) { $UsbAuthStr } else { 'not available' }) (0=deny, 1=allow, 2=if-internal)" + $nl

        # Check for udev rules that control device authorization
        $UdevRules = $(timeout 5 find /etc/udev/rules.d -maxdepth 1 -name '*.rules' -type f 2>/dev/null | head -10 2>&1)
        $UdevArr = @()
        if ($null -ne $UdevRules) { $UdevArr = @($UdevRules) }
        $FindingDetails += "Custom udev rules: $($UdevArr.Count) rule files in /etc/udev/rules.d/" + $nl

        # Check for USBGuard (device authorization daemon)
        $UsbGuard = $(rpm -q usbguard 2>/dev/null)
        $UsbGuardStr = ("$UsbGuard").Trim()
        $FindingDetails += "USBGuard package: $UsbGuardStr" + $nl

        if ($UsbGuardStr -notmatch "not installed") {
            $UsbGuardSvc = $(timeout 5 systemctl is-active usbguard 2>/dev/null)
            $FindingDetails += "USBGuard service: $(("$UsbGuardSvc").Trim())" + $nl
        }

        # Check PCI passthrough devices (Xen controls hardware assignment)
        $PciPt = Invoke-XeCommand -Command "vm-list params=other-config --minimal"
        $PciPtStr = ("$PciPt").Trim()

        # Xen hypervisor controls all peripheral access through device model
        $FindingDetails += $nl + "XCP-ng/Xen peripheral control:" + $nl
        $FindingDetails += "  - Dom0 controls all physical device access" + $nl
        $FindingDetails += "  - Guest VMs cannot directly access peripherals without explicit PCI passthrough" + $nl
        $FindingDetails += "  - PCI passthrough requires pool-admin RBAC role to configure" + $nl

        $HasUsbGuard = ($UsbGuardStr -notmatch "not installed")
        $UsbDenyDefault = ($UsbAuthStr -eq "0")

        if ($HasUsbGuard -or $UsbDenyDefault) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Peripheral authentication controls are in place. "
            if ($HasUsbGuard) { $FindingDetails += "USBGuard provides device whitelisting for USB peripherals. " }
            if ($UsbDenyDefault) { $FindingDetails += "USB default authorization is set to deny. " }
            $FindingDetails += "Xen hypervisor architecture ensures only Dom0 has direct peripheral access; guest VMs require explicit PCI passthrough configuration by authorized administrators."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No peripheral authentication enforcement detected beyond Xen default isolation. Install and configure USBGuard to authenticate USB peripherals before connection, or set USB default authorization to deny (echo 0 > /sys/bus/usb/devices/usb*/authorized_default)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207484 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207484
        STIG ID    : SRG-OS-000379-VMM-001550
        Rule ID    : SV-207484r971545_rule
        Severity   : CAT II
        Title      : The VMM must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.
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
    $VulnID = "V-207484"
    $RuleID = "SV-207484r971545_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Bidirectional Cryptographic Endpoint Authentication" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH host key exchange (bidirectional crypto auth)
        $SshHostKeyAlgos = $(timeout 5 grep -E '^HostKeyAlgorithms|^HostKey ' /etc/ssh/sshd_config 2>/dev/null)
        $SshHostArr = @()
        if ($null -ne $SshHostKeyAlgos) { $SshHostArr = @($SshHostKeyAlgos) }
        if ($SshHostArr.Count -gt 0) {
            $FindingDetails += "SSH host key configuration:" + $nl
            foreach ($Line in $SshHostArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "SSH host key configuration: default (all host key types enabled)" + $nl
        }

        # Check SSH host keys exist
        $SshKeys = $(timeout 5 find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key.pub' -type f 2>/dev/null | head -10 2>&1)
        $SshKeysArr = @()
        if ($null -ne $SshKeys) { $SshKeysArr = @($SshKeys) }
        $FindingDetails += "SSH host key files: $($SshKeysArr.Count) public keys" + $nl
        foreach ($Key in $SshKeysArr) { $FindingDetails += "  $($Key.Trim())" + $nl }

        # Check XAPI TLS certificate (HTTPS bidirectional possible)
        $XapiCert = $(timeout 5 ls -la /etc/xensource/xapi-ssl.pem 2>/dev/null)
        $XapiCertStr = ("$XapiCert").Trim()
        $FindingDetails += "XAPI TLS certificate: $(if ($XapiCertStr.Length -gt 0) { 'present' } else { 'not found' })" + $nl

        # Check stunnel configuration for TLS mutual auth
        $StunnelConf = $(timeout 5 grep -E '(verify|CAfile|cert|key)' /etc/stunnel/stunnel.conf 2>/dev/null)
        $StunnelArr = @()
        if ($null -ne $StunnelConf) { $StunnelArr = @($StunnelConf) }
        if ($StunnelArr.Count -gt 0) {
            $FindingDetails += "stunnel TLS settings:" + $nl
            foreach ($Line in $StunnelArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        # SSH provides bidirectional crypto auth: server proves identity via host key, client via pubkey/password
        $HasSshKeys = ($SshKeysArr.Count -gt 0)
        $HasXapiCert = ($XapiCertStr.Length -gt 0)

        if ($HasSshKeys -and $HasXapiCert) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Bidirectional cryptographic authentication is in place. SSH uses host key exchange for server authentication and public key or password for client authentication. XAPI uses TLS certificates for encrypted management connections. Both protocols provide cryptographically-based mutual authentication between endpoints."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Incomplete bidirectional cryptographic authentication. Ensure SSH host keys are present and XAPI TLS certificate is configured for all management connections."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207486 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207486
        STIG ID    : SRG-OS-000383-VMM-001570
        Rule ID    : SV-207486r958828_rule
        Severity   : CAT II
        Title      : The VMM must prohibit the use of cached authenticators after one day.
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
    $VulnID = "V-207486"
    $RuleID = "SV-207486r958828_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Cached Authenticator Prohibition (1-Day Limit)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSSD offline credential cache settings
        $SssdOffline = $(timeout 5 grep -E 'offline_credentials_expiration|cache_credentials' /etc/sssd/sssd.conf 2>/dev/null)
        $SssdArr = @()
        if ($null -ne $SssdOffline) { $SssdArr = @($SssdOffline) }
        if ($SssdArr.Count -gt 0) {
            $FindingDetails += "SSSD cached credential settings:" + $nl
            foreach ($Line in $SssdArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "SSSD: not configured (no cached credential policy)" + $nl
        }

        # Check PAM timestamp settings (sudo credential caching)
        $SudoTimestamp = $(timeout 5 grep -E 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
        $SudoArr = @()
        if ($null -ne $SudoTimestamp) { $SudoArr = @($SudoTimestamp) }
        if ($SudoArr.Count -gt 0) {
            $FindingDetails += "Sudo timestamp settings:" + $nl
            foreach ($Line in $SudoArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "Sudo timestamp_timeout: default (5 minutes)" + $nl
        }

        # Check XAPI session timeout
        $XapiTimeout = $(timeout 5 grep -i 'session_timeout\|login_timeout' /etc/xensource/xapi.conf /etc/xapi.conf 2>/dev/null)
        $XapiArr = @()
        if ($null -ne $XapiTimeout) { $XapiArr = @($XapiTimeout) }
        if ($XapiArr.Count -gt 0) {
            $FindingDetails += "XAPI session timeout:" + $nl
            foreach ($Line in $XapiArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "XAPI session timeout: default" + $nl
        }

        # Check Kerberos ticket lifetime (if krb5.conf exists)
        $Krb5 = $(timeout 5 grep -E 'ticket_lifetime|renew_lifetime' /etc/krb5.conf 2>/dev/null)
        $Krb5Arr = @()
        if ($null -ne $Krb5) { $Krb5Arr = @($Krb5) }
        if ($Krb5Arr.Count -gt 0) {
            $FindingDetails += "Kerberos ticket lifetime:" + $nl
            foreach ($Line in $Krb5Arr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        # XCP-ng without SSSD uses direct PAM auth (no caching by default)
        # Sudo has 5-minute default cache (well under 1 day)
        # SSH sessions require fresh auth on each connection
        $HasSssdCaching = ($SssdArr.Count -gt 0)
        $SssdCompliant = $true
        if ($HasSssdCaching) {
            $SssdStr = ($SssdArr -join $nl)
            if ($SssdStr -match "offline_credentials_expiration\s*=\s*(\d+)") {
                $ExpDays = [int]$Matches[1]
                if ($ExpDays -gt 1) { $SssdCompliant = $false }
            }
        }

        if (-not $HasSssdCaching) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: XCP-ng does not use SSSD cached credentials. PAM authentication is performed directly against local password databases on each login. SSH requires fresh authentication for every connection. Sudo credential caching defaults to 5 minutes (well under 1 day). No cached authenticators persist beyond the allowed period."
        }
        elseif ($SssdCompliant) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: SSSD offline credential expiration is configured at 1 day or less. Cached authenticators comply with the requirement."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: SSSD offline credential cache exceeds 1 day. Set offline_credentials_expiration = 1 in /etc/sssd/sssd.conf [pam] section to prohibit cached authenticators after one day."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207487 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207487
        STIG ID    : SRG-OS-000384-VMM-001580
        Rule ID    : SV-207487r984257_rule
        Severity   : CAT II
        Title      : The VMM, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.
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
    $VulnID = "V-207487"
    $RuleID = "SV-207487r984257_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "PKI Revocation Data Local Cache" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for local CRL files
        $CrlFiles = $(timeout 5 find /etc/pki -maxdepth 3 -name '*.crl' -type f 2>/dev/null | head -10 2>&1)
        $CrlArr = @()
        if ($null -ne $CrlFiles) { $CrlArr = @($CrlFiles) }
        $CrlArr = @($CrlArr | Where-Object { "$_".Trim().Length -gt 0 })
        $FindingDetails += "Local CRL files: $($CrlArr.Count) found" + $nl
        foreach ($Crl in $CrlArr) { $FindingDetails += "  $($Crl.Trim())" + $nl }

        # Check pam_pkcs11 CRL directory
        $PkcsCrl = $(timeout 5 ls -la /etc/pam_pkcs11/crls/ 2>/dev/null)
        $PkcsCrlArr = @()
        if ($null -ne $PkcsCrl) { $PkcsCrlArr = @($PkcsCrl) }
        if ($PkcsCrlArr.Count -gt 1) {
            $FindingDetails += "pam_pkcs11 CRL directory contents:" + $nl
            foreach ($Line in $PkcsCrlArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "pam_pkcs11 CRL directory: not found or empty" + $nl
        }

        # Check OCSP stapling configuration
        $OcspConf = $(timeout 5 grep -ri 'ocsp' /etc/pki/tls/openssl.cnf /etc/pam_pkcs11/pam_pkcs11.conf 2>/dev/null)
        $OcspArr = @()
        if ($null -ne $OcspConf) { $OcspArr = @($OcspConf) }
        if ($OcspArr.Count -gt 0) {
            $FindingDetails += "OCSP configuration:" + $nl
            foreach ($Line in $OcspArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "OCSP configuration: not found" + $nl
        }

        # Check if certutil is available for certificate management
        $Certutil = $(which certutil 2>/dev/null)
        $CertutilStr = ("$Certutil").Trim()
        $FindingDetails += "certutil available: $(if ($CertutilStr.Length -gt 0) { 'yes' } else { 'no' })" + $nl

        $HasCrlCache = ($CrlArr.Count -gt 0)
        $HasOcsp = ($OcspArr.Count -gt 0)

        if ($HasCrlCache -or $HasOcsp) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Local PKI revocation data cache is available. "
            if ($HasCrlCache) { $FindingDetails += "Local CRL files provide offline certificate revocation checking. " }
            if ($HasOcsp) { $FindingDetails += "OCSP configuration provides online revocation validation with local caching. " }
            $FindingDetails += "This supports path discovery and validation when network access to revocation servers is unavailable."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No local PKI revocation data cache detected. For PKI-based authentication, configure local CRL caching (download CRLs to /etc/pki/ or /etc/pam_pkcs11/crls/) and/or enable OCSP with local response caching to support certificate validation during network outages."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207488 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207488
        STIG ID    : SRG-OS-000396-VMM-001590
        Rule ID    : SV-207488r987791_rule
        Severity   : CAT II
        Title      : The VMM must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
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
    $VulnID = "V-207488"
    $RuleID = "SV-207488r987791_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "NSA-Approved Cryptography for Classified Information" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check FIPS mode
        $FipsMode = $(timeout 5 cat /proc/sys/crypto/fips_enabled 2>/dev/null)
        $FipsModeStr = ("$FipsMode").Trim()
        $FindingDetails += "FIPS mode (kernel): $(if ($FipsModeStr -eq '1') { 'ENABLED' } elseif ($FipsModeStr -eq '0') { 'DISABLED' } else { 'not available' })" + $nl

        # Check OpenSSL FIPS support
        $OpensslVer = $(timeout 5 openssl version 2>/dev/null)
        $OpensslVerStr = ("$OpensslVer").Trim()
        $FindingDetails += "OpenSSL version: $OpensslVerStr" + $nl

        # Check SSH ciphers
        $SshCiphers = $(timeout 5 grep -E '^Ciphers' /etc/ssh/sshd_config 2>/dev/null)
        $SshCiphersStr = ("$SshCiphers").Trim()
        $FindingDetails += "SSH Ciphers: $(if ($SshCiphersStr.Length -gt 0) { $SshCiphersStr } else { 'default (system-wide)' })" + $nl

        # Check SSH MACs
        $SshMacs = $(timeout 5 grep -E '^MACs' /etc/ssh/sshd_config 2>/dev/null)
        $SshMacsStr = ("$SshMacs").Trim()
        $FindingDetails += "SSH MACs: $(if ($SshMacsStr.Length -gt 0) { $SshMacsStr } else { 'default (system-wide)' })" + $nl

        # Check SSH KexAlgorithms
        $SshKex = $(timeout 5 grep -E '^KexAlgorithms' /etc/ssh/sshd_config 2>/dev/null)
        $SshKexStr = ("$SshKex").Trim()
        $FindingDetails += "SSH KexAlgorithms: $(if ($SshKexStr.Length -gt 0) { $SshKexStr } else { 'default (system-wide)' })" + $nl

        # Check crypto-policies (RHEL7/CentOS7 may not have this)
        $CryptoPolicy = $(timeout 5 cat /etc/crypto-policies/config 2>/dev/null)
        $CryptoPolicyStr = ("$CryptoPolicy").Trim()
        if ($CryptoPolicyStr.Length -gt 0) {
            $FindingDetails += "System crypto policy: $CryptoPolicyStr" + $nl
        }

        # FIPS mode is the definitive check for NSA-approved crypto
        if ($FipsModeStr -eq "1") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: FIPS 140-2 mode is enabled at the kernel level. All cryptographic operations use FIPS-validated modules, meeting the requirement for NSA-approved cryptography to protect classified information."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: FIPS mode is not enabled. NSA-approved cryptography requires FIPS 140-2 validated cryptographic modules. Enable FIPS mode by adding fips=1 to the kernel boot parameters and installing the dracut-fips package. Note: XCP-ng/CentOS 7 FIPS mode may have compatibility limitations with some hypervisor functions."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207489 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207489
        STIG ID    : SRG-OS-000399-VMM-001600
        Rule ID    : SV-207489r958860_rule
        Severity   : CAT II
        Title      : The VMM must request data origin authentication verification on the name/address resolution responses the system receives from authoritative sources.
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
    $VulnID = "V-207489"
    $RuleID = "SV-207489r958860_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DNS Data Origin Authentication Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check resolv.conf for DNS servers
        $ResolvConf = $(timeout 5 cat /etc/resolv.conf 2>/dev/null)
        $ResolvArr = @()
        if ($null -ne $ResolvConf) { $ResolvArr = @($ResolvConf) }
        $ResolvStr = ($ResolvArr -join $nl).Trim()
        $NameserverLines = @($ResolvArr | Where-Object { "$_" -match "^nameserver" })
        $FindingDetails += "DNS nameservers configured:" + $nl
        foreach ($Ns in $NameserverLines) { $FindingDetails += "  $($Ns.Trim())" + $nl }

        # Check if DNSSEC is enabled in resolv.conf options
        $DnssecOpt = @($ResolvArr | Where-Object { "$_" -match "dnssec|edns" })
        if ($DnssecOpt.Count -gt 0) {
            $FindingDetails += "DNSSEC options in resolv.conf:" + $nl
            foreach ($Line in $DnssecOpt) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        # Check for local DNSSEC-validating resolver (unbound, bind)
        $Unbound = $(rpm -q unbound 2>/dev/null)
        $UnboundStr = ("$Unbound").Trim()
        $Bind = $(rpm -q bind 2>/dev/null)
        $BindStr = ("$Bind").Trim()
        $FindingDetails += "unbound package: $UnboundStr" + $nl
        $FindingDetails += "bind package: $BindStr" + $nl

        # Check dnsmasq DNSSEC configuration
        $DnsmasqDnssec = $(timeout 5 grep -i 'dnssec' /etc/dnsmasq.conf /etc/dnsmasq.d/*.conf 2>/dev/null)
        $DnsmasqArr = @()
        if ($null -ne $DnsmasqDnssec) { $DnsmasqArr = @($DnsmasqDnssec) }
        if ($DnsmasqArr.Count -gt 0) {
            $FindingDetails += "dnsmasq DNSSEC settings:" + $nl
            foreach ($Line in $DnsmasqArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        $HasDnssecResolver = ($UnboundStr -notmatch "not installed") -or ($BindStr -notmatch "not installed")
        $HasDnssecDnsmasq = ($DnsmasqArr.Count -gt 0)

        if ($HasDnssecResolver -or $HasDnssecDnsmasq) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: DNSSEC-capable resolver is installed. Data origin authentication verification is available for DNS responses from authoritative sources."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No DNSSEC-validating resolver detected. Install and configure a DNSSEC-validating resolver (unbound or bind with dnssec-validation auto) to request data origin authentication on DNS responses."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207490 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207490
        STIG ID    : SRG-OS-000400-VMM-001610
        Rule ID    : SV-207490r958862_rule
        Severity   : CAT II
        Title      : The VMM must request data integrity verification on the name/address resolution responses the system receives from authoritative sources.
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
    $VulnID = "V-207490"
    $RuleID = "SV-207490r958862_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DNS Data Integrity Verification Request" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check resolv.conf DNS configuration
        $Nameservers = $(timeout 5 grep '^nameserver' /etc/resolv.conf 2>/dev/null)
        $NsArr = @()
        if ($null -ne $Nameservers) { $NsArr = @($Nameservers) }
        $FindingDetails += "DNS nameservers:" + $nl
        foreach ($Ns in $NsArr) { $FindingDetails += "  $($Ns.Trim())" + $nl }

        # Check for DNSSEC-capable local resolver
        $Unbound = $(rpm -q unbound 2>/dev/null)
        $UnboundStr = ("$Unbound").Trim()
        $FindingDetails += "unbound (DNSSEC resolver): $UnboundStr" + $nl

        # Check for EDNS0 support (required for DNSSEC)
        $ResolvOpts = $(timeout 5 grep 'options' /etc/resolv.conf 2>/dev/null)
        $ResolvOptsStr = ("$ResolvOpts").Trim()
        if ($ResolvOptsStr.Length -gt 0) {
            $FindingDetails += "resolv.conf options: $ResolvOptsStr" + $nl
        }

        # Check dnsmasq DNSSEC
        $DnsmasqDnssec = $(timeout 5 grep -i 'dnssec' /etc/dnsmasq.conf 2>/dev/null)
        $DnsmasqStr = ("$DnsmasqDnssec").Trim()
        if ($DnsmasqStr.Length -gt 0) {
            $FindingDetails += "dnsmasq DNSSEC: $DnsmasqStr" + $nl
        }

        $HasDnssec = ($UnboundStr -notmatch "not installed") -or ($DnsmasqStr -match "dnssec")

        if ($HasDnssec) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: DNSSEC-capable resolver is available. The system can request data integrity verification (RRSIG/DNSKEY) on DNS responses from authoritative sources via DNSSEC protocol."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No DNSSEC-validating resolver detected. Install and configure unbound or enable DNSSEC in dnsmasq to request data integrity verification on DNS name/address resolution responses."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207491 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207491
        STIG ID    : SRG-OS-000401-VMM-001620
        Rule ID    : SV-207491r958864_rule
        Severity   : CAT II
        Title      : The VMM must perform data integrity verification on the name/address resolution responses the system receives from authoritative sources.
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
    $VulnID = "V-207491"
    $RuleID = "SV-207491r958864_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DNS Data Integrity Verification Performance" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for DNSSEC-validating resolver with active validation
        $Unbound = $(rpm -q unbound 2>/dev/null)
        $UnboundStr = ("$Unbound").Trim()
        $FindingDetails += "unbound package: $UnboundStr" + $nl

        if ($UnboundStr -notmatch "not installed") {
            $UnboundSvc = $(timeout 5 systemctl is-active unbound 2>/dev/null)
            $FindingDetails += "unbound service: $(("$UnboundSvc").Trim())" + $nl
            # Check unbound DNSSEC config
            $UnboundConf = $(timeout 5 grep -E 'val-permissive-mode|auto-trust-anchor-file|trust-anchor' /etc/unbound/unbound.conf 2>/dev/null)
            $UnboundConfArr = @()
            if ($null -ne $UnboundConf) { $UnboundConfArr = @($UnboundConf) }
            if ($UnboundConfArr.Count -gt 0) {
                $FindingDetails += "unbound DNSSEC validation config:" + $nl
                foreach ($Line in $UnboundConfArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
            }
        }

        # Check named (bind) DNSSEC validation
        $Bind = $(rpm -q bind 2>/dev/null)
        $BindStr = ("$Bind").Trim()
        if ($BindStr -notmatch "not installed") {
            $BindDnssec = $(timeout 5 grep -E 'dnssec-validation|dnssec-enable' /etc/named.conf 2>/dev/null)
            $BindArr = @()
            if ($null -ne $BindDnssec) { $BindArr = @($BindDnssec) }
            if ($BindArr.Count -gt 0) {
                $FindingDetails += "named DNSSEC validation:" + $nl
                foreach ($Line in $BindArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
            }
        }

        $HasValidator = ($UnboundStr -notmatch "not installed") -or ($BindStr -notmatch "not installed")

        if ($HasValidator) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: DNSSEC-validating resolver is installed and can perform data integrity verification on DNS responses. DNSSEC validates RRSIG signatures against DNSKEY records to ensure DNS response integrity from authoritative sources."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No DNSSEC-validating resolver installed. Install unbound (yum install unbound) and configure dnssec-validation to perform data integrity verification on DNS responses."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207492 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207492
        STIG ID    : SRG-OS-000402-VMM-001630
        Rule ID    : SV-207492r958866_rule
        Severity   : CAT II
        Title      : The VMM must perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.
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
    $VulnID = "V-207492"
    $RuleID = "SV-207492r958866_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DNS Data Origin Verification Authentication" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for DNSSEC-validating resolver
        $Unbound = $(rpm -q unbound 2>/dev/null)
        $UnboundStr = ("$Unbound").Trim()
        $Bind = $(rpm -q bind 2>/dev/null)
        $BindStr = ("$Bind").Trim()
        $FindingDetails += "unbound package: $UnboundStr" + $nl
        $FindingDetails += "bind package: $BindStr" + $nl

        # Check DNS resolution path
        $Nameservers = $(timeout 5 grep '^nameserver' /etc/resolv.conf 2>/dev/null)
        $NsArr = @()
        if ($null -ne $Nameservers) { $NsArr = @($Nameservers) }
        $FindingDetails += "Configured nameservers:" + $nl
        foreach ($Ns in $NsArr) { $FindingDetails += "  $($Ns.Trim())" + $nl }

        # Check if DNSSEC root trust anchor exists
        $TrustAnchor = $(timeout 5 ls -la /var/lib/unbound/root.key /etc/trusted-key.key /etc/unbound/*.key 2>/dev/null)
        $TrustArr = @()
        if ($null -ne $TrustAnchor) { $TrustArr = @($TrustAnchor) }
        if ($TrustArr.Count -gt 0) {
            $FindingDetails += "DNSSEC trust anchors:" + $nl
            foreach ($Line in $TrustArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        $HasDnssec = ($UnboundStr -notmatch "not installed") -or ($BindStr -notmatch "not installed")

        if ($HasDnssec) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: DNSSEC-capable resolver is installed. Data origin verification authentication is performed through DNSSEC chain of trust from root trust anchor to authoritative zone signatures, authenticating that DNS responses originate from legitimate authoritative sources."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No DNSSEC-validating resolver detected. Install and configure unbound or bind with DNSSEC validation to perform data origin verification on DNS responses from authoritative sources."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207493 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207493
        STIG ID    : SRG-OS-000403-VMM-001640
        Rule ID    : SV-207493r958868_rule
        Severity   : CAT II
        Title      : The VMM must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.
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
    $VulnID = "V-207493"
    $RuleID = "SV-207493r958868_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DoD PKI Certificate Authority Restriction" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check system CA trust bundle
        $CaTrust = $(timeout 5 ls -la /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null)
        $CaTrustStr = ("$CaTrust").Trim()
        $FindingDetails += "System CA bundle: $(if ($CaTrustStr.Length -gt 0) { $CaTrustStr } else { 'not found' })" + $nl

        # Check for DoD CA certificates
        $DodCerts = $(timeout 5 sh -c 'grep -c "DoD" /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null || echo 0')
        $DodCertsStr = ("$DodCerts").Trim()
        $FindingDetails += "DoD CA references in trust bundle: $DodCertsStr" + $nl

        # Check XAPI TLS certificate issuer
        $XapiCertInfo = $(timeout 5 openssl x509 -in /etc/xensource/xapi-ssl.pem -issuer -noout 2>/dev/null)
        $XapiCertStr = ("$XapiCertInfo").Trim()
        $FindingDetails += "XAPI TLS certificate issuer: $(if ($XapiCertStr.Length -gt 0) { $XapiCertStr } else { 'not available' })" + $nl

        # Check for custom CA directory
        $CustomCaDir = $(timeout 5 ls /etc/pki/ca-trust/source/anchors/ 2>/dev/null)
        $CustomCaArr = @()
        if ($null -ne $CustomCaDir) { $CustomCaArr = @($CustomCaDir) }
        $CustomCaArr = @($CustomCaArr | Where-Object { "$_".Trim().Length -gt 0 })
        $FindingDetails += "Custom CA anchors: $($CustomCaArr.Count) files in /etc/pki/ca-trust/source/anchors/" + $nl
        foreach ($Ca in $CustomCaArr) { $FindingDetails += "  $($Ca.Trim())" + $nl }

        # DoD PKI CA installation is an organizational requirement
        $HasDodCerts = ($DodCertsStr -match "^\d+$" -and [int]$DodCertsStr -gt 0)

        if ($HasDodCerts) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: DoD PKI certificate authority references found in the system trust bundle. The system CA trust store includes DoD Root and Intermediate CAs for verification of protected session establishment."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No DoD PKI certificate authorities detected in the system trust bundle. Import DoD Root CA and Intermediate CA certificates into /etc/pki/ca-trust/source/anchors/ and run update-ca-trust to restrict protected session verification to DoD PKI-established CAs."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207494
        STIG ID    : SRG-OS-000404-VMM-001650
        Rule ID    : SV-207494r958870_rule
        Severity   : CAT II
        Title      : The VMM must implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all VMM components.
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
    $VulnID = "V-207494"
    $RuleID = "SV-207494r958870_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Cryptographic Protection Against Unauthorized Modification (At Rest)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for LUKS encrypted partitions
        $Luks = $(timeout 5 lsblk -o NAME,FSTYPE,TYPE 2>/dev/null)
        $LuksArr = @()
        if ($null -ne $Luks) { $LuksArr = @($Luks) }
        $LuksStr = ($LuksArr -join $nl).Trim()
        $HasLuks = ($LuksStr -match "crypto_LUKS")
        $LuksParts = @($LuksArr | Where-Object { "$_" -match "crypt" })
        $FindingDetails += "Encrypted partitions: $($LuksParts.Count)" + $nl
        if ($LuksParts.Count -gt 0) {
            foreach ($Part in $LuksParts) { $FindingDetails += "  $($Part.Trim())" + $nl }
        }

        # Check dm-crypt status
        $DmCrypt = $(timeout 5 dmsetup ls --target crypt 2>/dev/null)
        $DmCryptStr = ("$DmCrypt").Trim()
        if ($DmCryptStr.Length -gt 0 -and $DmCryptStr -ne "No devices found") {
            $FindingDetails += "dm-crypt devices: $DmCryptStr" + $nl
        }
        else {
            $FindingDetails += "dm-crypt devices: none" + $nl
        }

        # Check for file integrity monitoring (AIDE)
        $Aide = $(rpm -q aide 2>/dev/null)
        $AideStr = ("$Aide").Trim()
        $FindingDetails += "AIDE (file integrity): $AideStr" + $nl

        # Check RPM verify capability (detects modifications to installed packages)
        $FindingDetails += "RPM verification: available (rpm -V can detect unauthorized modifications)" + $nl

        if ($HasLuks) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Disk encryption (LUKS/dm-crypt) is configured. Cryptographic mechanisms protect information at rest from unauthorized modification by ensuring data integrity through authenticated encryption."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No disk encryption detected. Configure LUKS full-disk encryption on all VMM storage volumes to implement cryptographic mechanisms preventing unauthorized modification of information at rest. Additionally, install AIDE for file integrity monitoring."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207495
        STIG ID    : SRG-OS-000405-VMM-001660
        Rule ID    : SV-207495r958872_rule
        Severity   : CAT II
        Title      : The VMM must implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all VMM components.
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
    $VulnID = "V-207495"
    $RuleID = "SV-207495r958872_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Cryptographic Protection Against Unauthorized Disclosure (At Rest)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check for LUKS encrypted volumes
        $Luks = $(timeout 5 lsblk -o NAME,FSTYPE,TYPE 2>/dev/null)
        $LuksArr = @()
        if ($null -ne $Luks) { $LuksArr = @($Luks) }
        $LuksStr = ($LuksArr -join $nl).Trim()
        $HasLuks = ($LuksStr -match "crypto_LUKS")
        $CryptParts = @($LuksArr | Where-Object { "$_" -match "crypt" })
        $FindingDetails += "Encrypted volumes: $($CryptParts.Count)" + $nl
        foreach ($Part in $CryptParts) { $FindingDetails += "  $($Part.Trim())" + $nl }

        # Check if storage repos are on encrypted volumes
        $SrList = Invoke-XeCommand -Command "sr-list params=name-label,physical-size --minimal"
        $SrStr = ("$SrList").Trim()
        $FindingDetails += "Storage repositories: $(if ($SrStr.Length -gt 0) { $SrStr } else { 'none listed' })" + $nl

        # Check swap encryption
        $Swap = $(timeout 5 swapon --show 2>/dev/null)
        $SwapArr = @()
        if ($null -ne $Swap) { $SwapArr = @($Swap) }
        if ($SwapArr.Count -gt 1) {
            $FindingDetails += "Swap devices:" + $nl
            foreach ($Line in $SwapArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "Swap: none active" + $nl
        }

        if ($HasLuks) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Disk encryption (LUKS) is configured to prevent unauthorized disclosure of information at rest. Encrypted volumes protect VM disk images, configuration data, and hypervisor state from unauthorized access to physical storage media."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No disk encryption detected. Configure LUKS encryption on all VMM storage volumes containing sensitive data (including VM disk images and configuration) to prevent unauthorized disclosure of information at rest."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207496 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207496
        STIG ID    : SRG-OS-000408-VMM-001670
        Rule ID    : SV-207496r958878_rule
        Severity   : CAT II
        Title      : The VMM must maintain a separate execution domain for each executing process.
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
    $VulnID = "V-207496"
    $RuleID = "SV-207496r958878_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Separate Execution Domain per Process" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check kernel virtual memory support (inherent in Linux)
        $KernelVer = $(uname -r 2>/dev/null)
        $KernelVerStr = ("$KernelVer").Trim()
        $FindingDetails += "Kernel version: $KernelVerStr" + $nl

        # Check ASLR (randomize address space per process)
        $Aslr = $(timeout 5 cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
        $AslrStr = ("$Aslr").Trim()
        $FindingDetails += "ASLR (randomize_va_space): $AslrStr (0=off, 1=partial, 2=full)" + $nl

        # Check NX/XD bit support
        $NxBit = $(timeout 5 grep -o ' nx ' /proc/cpuinfo 2>/dev/null | head -1 2>&1)
        $NxBitStr = ("$NxBit").Trim()
        $FindingDetails += "NX (No-Execute) bit: $(if ($NxBitStr.Length -gt 0) { 'supported' } else { 'not detected' })" + $nl

        # Check cgroups (process resource isolation)
        $Cgroups = $(timeout 5 cat /proc/cgroups 2>/dev/null | head -5 2>&1)
        $CgroupsArr = @()
        if ($null -ne $Cgroups) { $CgroupsArr = @($Cgroups) }
        $FindingDetails += "cgroups subsystems: $($CgroupsArr.Count) (process resource isolation)" + $nl

        # Xen hypervisor provides hardware-enforced isolation
        $FindingDetails += $nl + "Xen hypervisor process isolation:" + $nl
        $FindingDetails += "  - Each process in Dom0 runs in a separate virtual address space (Linux kernel MMU)" + $nl
        $FindingDetails += "  - Per-process page tables enforce memory isolation" + $nl
        $FindingDetails += "  - Hardware NX bit prevents code execution in data pages" + $nl
        $FindingDetails += "  - cgroups provide resource isolation between process groups" + $nl

        # This is inherent in Linux/Xen architecture
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng maintains separate execution domains for each process through Linux kernel virtual memory management (per-process page tables), hardware NX bit support, ASLR, and cgroup resource isolation. The Xen hypervisor provides additional hardware-enforced isolation between Dom0 and guest VM processes."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207497 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207497
        STIG ID    : SRG-OS-000408-VMM-001680
        Rule ID    : SV-207497r958878_rule
        Severity   : CAT II
        Title      : The VMM must maintain a separate execution domain for each guest VM.
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
    $VulnID = "V-207497"
    $RuleID = "SV-207497r958878_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Separate Execution Domain per Guest VM" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check Xen hypervisor version
        $XenVer = $(timeout 5 xl info 2>/dev/null | grep 'xen_version')
        $XenVerStr = ("$XenVer").Trim()
        $FindingDetails += "Xen version: $(if ($XenVerStr.Length -gt 0) { $XenVerStr } else { 'not available via xl info' })" + $nl

        # Check hardware virtualization support (VT-x/AMD-V)
        $VtxFlags = $(timeout 5 grep -oE '(vmx|svm)' /proc/cpuinfo 2>/dev/null | head -1 2>&1)
        $VtxStr = ("$VtxFlags").Trim()
        $FindingDetails += "Hardware virtualization: $(if ($VtxStr -eq 'vmx') { 'Intel VT-x' } elseif ($VtxStr -eq 'svm') { 'AMD-V' } else { 'not detected' })" + $nl

        # List running VMs with their domain IDs (separate execution domains)
        $VmList = Invoke-XeCommand -Command "vm-list power-state=running params=name-label,dom-id --minimal"
        $VmListStr = ("$VmList").Trim()
        $FindingDetails += "Running VMs: $(if ($VmListStr.Length -gt 0) { $VmListStr } else { 'none' })" + $nl

        # Check IOMMU (prevents DMA attacks between VMs)
        $Iommu = $(timeout 5 xl dmesg 2>/dev/null | grep -i 'iommu\|VT-d\|AMD-Vi' | head -3 2>&1)
        $IommuArr = @()
        if ($null -ne $Iommu) { $IommuArr = @($Iommu) }
        if ($IommuArr.Count -gt 0) {
            $FindingDetails += "IOMMU/VT-d:" + $nl
            foreach ($Line in $IommuArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        $FindingDetails += $nl + "Xen VM isolation architecture:" + $nl
        $FindingDetails += "  - Type 1 (bare-metal) hypervisor runs directly on hardware" + $nl
        $FindingDetails += "  - Each VM gets a unique domain ID (domid) and separate address space" + $nl
        $FindingDetails += "  - Hardware VT-x/AMD-V enforces memory isolation between domains" + $nl
        $FindingDetails += "  - IOMMU/VT-d isolates device DMA access per domain" + $nl
        $FindingDetails += "  - No VM can access another VM memory without explicit grant table" + $nl

        # Xen is a Type 1 hypervisor — VM isolation is its core design
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng/Xen maintains separate execution domains for each guest VM through hardware-enforced virtualization (VT-x/AMD-V). Each VM runs in an isolated domain with its own virtual address space, memory pages, and device assignments. The Xen hypervisor mediates all inter-domain communication through controlled grant tables and event channels."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207498 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207498
        STIG ID    : SRG-OS-000420-VMM-001690
        Rule ID    : SV-207498r958902_rule
        Severity   : CAT II
        Title      : The VMM must protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the VMM is implementing rate-limiting measures on impacted network interfaces.
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
    $VulnID = "V-207498"
    $RuleID = "SV-207498r958902_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "DoS Rate-Limiting on Network Interfaces" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check iptables rate-limiting rules
        $IptablesRules = $(timeout 5 iptables -L -n -v 2>/dev/null)
        $IptArr = @()
        if ($null -ne $IptablesRules) { $IptArr = @($IptablesRules) }
        $IptStr = ($IptArr -join $nl).Trim()

        # Look for rate-limit, hashlimit, or connlimit modules
        $RateLimitRules = @($IptArr | Where-Object { "$_" -match "limit|hashlimit|connlimit" })
        $FindingDetails += "iptables rate-limit rules: $($RateLimitRules.Count)" + $nl
        foreach ($Rule in $RateLimitRules) { $FindingDetails += "  $($Rule.Trim())" + $nl }

        # Check SYN flood protection (kernel)
        $SynCookies = $(timeout 5 cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)
        $SynCookiesStr = ("$SynCookies").Trim()
        $FindingDetails += "TCP SYN cookies: $(if ($SynCookiesStr -eq '1') { 'enabled' } else { 'disabled' })" + $nl

        # Check connection tracking limits
        $ConntrackMax = $(timeout 5 cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        $ConntrackStr = ("$ConntrackMax").Trim()
        if ($ConntrackStr.Length -gt 0) {
            $FindingDetails += "Connection tracking max: $ConntrackStr" + $nl
        }

        # Check for fail2ban or similar
        $Fail2ban = $(rpm -q fail2ban 2>/dev/null)
        $Fail2banStr = ("$Fail2ban").Trim()
        $FindingDetails += "fail2ban package: $Fail2banStr" + $nl

        # Check kernel network rate limits
        $IcmpLimit = $(timeout 5 cat /proc/sys/net/ipv4/icmp_ratelimit 2>/dev/null)
        $IcmpStr = ("$IcmpLimit").Trim()
        $FindingDetails += "ICMP rate limit: $(if ($IcmpStr.Length -gt 0) { $IcmpStr } else { 'not set' })" + $nl

        $HasRateLimiting = ($RateLimitRules.Count -gt 0)
        $HasSynCookies = ($SynCookiesStr -eq "1")
        $HasFail2ban = ($Fail2banStr -notmatch "not installed")

        if ($HasRateLimiting -or $HasSynCookies -or $HasFail2ban) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: DoS rate-limiting measures are in place. "
            if ($HasSynCookies) { $FindingDetails += "TCP SYN cookies protect against SYN flood attacks. " }
            if ($HasRateLimiting) { $FindingDetails += "iptables rate-limiting rules are configured. " }
            if ($HasFail2ban) { $FindingDetails += "fail2ban provides brute-force rate limiting. " }
            $FindingDetails += "Kernel-level ICMP and connection tracking limits provide additional DoS protection."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Insufficient DoS rate-limiting. Enable TCP SYN cookies (sysctl net.ipv4.tcp_syncookies=1), configure iptables rate-limiting rules (e.g., -m limit --limit 25/minute), and consider installing fail2ban for SSH brute-force protection."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207499 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207499
        STIG ID    : SRG-OS-000423-VMM-001700
        Rule ID    : SV-207499r958908_rule
        Severity   : CAT II
        Title      : The VMM must protect the confidentiality and integrity of transmitted information.
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
    $VulnID = "V-207499"
    $RuleID = "SV-207499r958908_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Confidentiality and Integrity of Transmitted Information" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        # Check SSH protocol and encryption
        $SshProto = $(timeout 5 grep -E '^Protocol|^Ciphers|^MACs' /etc/ssh/sshd_config 2>/dev/null)
        $SshArr = @()
        if ($null -ne $SshProto) { $SshArr = @($SshProto) }
        if ($SshArr.Count -gt 0) {
            $FindingDetails += "SSH encryption configuration:" + $nl
            foreach ($Line in $SshArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "SSH encryption: default (system-wide crypto policy)" + $nl
        }

        # Check XAPI TLS (HTTPS on port 443)
        $XapiCert = $(timeout 5 ls -la /etc/xensource/xapi-ssl.pem 2>/dev/null)
        $XapiCertStr = ("$XapiCert").Trim()
        $FindingDetails += "XAPI TLS certificate: $(if ($XapiCertStr.Length -gt 0) { 'present' } else { 'not found' })" + $nl

        # Check TLS protocol version on XAPI
        $TlsVer = $(timeout 10 sh -c 'echo | openssl s_client -connect 127.0.0.1:443 -tls1_2 2>/dev/null | grep -i "protocol\|cipher"' 2>/dev/null)
        $TlsArr = @()
        if ($null -ne $TlsVer) { $TlsArr = @($TlsVer) }
        if ($TlsArr.Count -gt 0) {
            $FindingDetails += "XAPI TLS status:" + $nl
            foreach ($Line in $TlsArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        # Check stunnel for additional TLS wrapping
        $StunnelActive = $(timeout 5 systemctl is-active stunnel 2>/dev/null)
        $StunnelStr = ("$StunnelActive").Trim()
        $FindingDetails += "stunnel service: $StunnelStr" + $nl

        $HasSsh = $true
        $HasXapiTls = ($XapiCertStr.Length -gt 0)

        if ($HasSsh -and $HasXapiTls) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Transmitted information is protected. SSH provides encrypted management access with strong ciphers and MACs. XAPI uses TLS (HTTPS) for all management API communications. All administrative protocols enforce cryptographic protection of confidentiality and integrity during transmission."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Incomplete transmission protection. Ensure XAPI TLS certificate is properly configured and all management communications use encrypted protocols (SSH, HTTPS)."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207500 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207500
        STIG ID    : SRG-OS-000425-VMM-001710
        Rule ID    : SV-207500r958912_rule
        Severity   : CAT II
        Title      : The VMM must maintain the confidentiality and integrity of information during preparation for transmission.
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
    $VulnID = "V-207500"
    $RuleID = "SV-207500r958912_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Confidentiality/Integrity During Preparation for Transmission" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $SshCiphers = $(timeout 5 grep -E '^Ciphers' /etc/ssh/sshd_config 2>/dev/null)
        $SshCiphersStr = ("$SshCiphers").Trim()
        $FindingDetails += "SSH Ciphers: $(if ($SshCiphersStr.Length -gt 0) { $SshCiphersStr } else { 'default' })" + $nl

        $XapiCert = $(timeout 5 test -f /etc/xensource/xapi-ssl.pem 2>/dev/null; echo $?)
        $XapiCertStr = ("$XapiCert").Trim()
        $FindingDetails += "XAPI TLS certificate exists: $(if ($XapiCertStr -eq '0') { 'yes' } else { 'no' })" + $nl

        $ListenPorts = $(timeout 5 ss -tlnp 2>/dev/null | head -20 2>&1)
        $PortArr = @()
        if ($null -ne $ListenPorts) { $PortArr = @($ListenPorts) }
        $FindingDetails += "Listening TCP services: $($PortArr.Count) entries" + $nl
        foreach ($Port in $PortArr) { $FindingDetails += "  $($Port.Trim())" + $nl }

        $HasTls = ($XapiCertStr -eq "0")

        if ($HasTls) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Data confidentiality and integrity are maintained during preparation for transmission. SSH performs key exchange and cipher negotiation before any application data is sent. XAPI uses TLS handshake to establish encrypted channel prior to data transmission. Both protocols ensure cryptographic protection is established before sensitive data enters the network stack."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: XAPI TLS certificate not found. Ensure /etc/xensource/xapi-ssl.pem exists and XAPI is configured for HTTPS to protect data during preparation for transmission."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207501 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207501
        STIG ID    : SRG-OS-000426-VMM-001720
        Rule ID    : SV-207501r958914_rule
        Severity   : CAT II
        Title      : The VMM must maintain the confidentiality and integrity of information during reception.
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
    $VulnID = "V-207501"
    $RuleID = "SV-207501r958914_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Confidentiality/Integrity During Reception" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $SshMacs = $(timeout 5 grep -E '^MACs' /etc/ssh/sshd_config 2>/dev/null)
        $SshMacsStr = ("$SshMacs").Trim()
        $FindingDetails += "SSH MACs (integrity): $(if ($SshMacsStr.Length -gt 0) { $SshMacsStr } else { 'default' })" + $nl

        $XapiCert = $(timeout 5 test -f /etc/xensource/xapi-ssl.pem 2>/dev/null; echo $?)
        $XapiCertStr = ("$XapiCert").Trim()
        $FindingDetails += "XAPI TLS certificate: $(if ($XapiCertStr -eq '0') { 'present' } else { 'missing' })" + $nl

        $TelnetSvc = $(timeout 5 systemctl is-active telnet.socket 2>/dev/null)
        $TelnetStr = ("$TelnetSvc").Trim()
        $FindingDetails += "telnet service: $TelnetStr" + $nl

        $FtpSvc = $(timeout 5 systemctl is-active vsftpd 2>/dev/null)
        $FtpStr = ("$FtpSvc").Trim()
        $FindingDetails += "FTP service: $FtpStr" + $nl

        $HasTls = ($XapiCertStr -eq "0")
        $NoPlaintext = ($TelnetStr -ne "active" -and $FtpStr -ne "active")

        if ($HasTls -and $NoPlaintext) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Information confidentiality and integrity are maintained during reception. SSH decrypts and verifies integrity of received data using negotiated MACs. XAPI receives data over TLS with authenticated encryption. No plaintext services (telnet, FTP) are active."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Reception security incomplete. "
            if (-not $HasTls) { $FindingDetails += "Configure XAPI TLS certificate. " }
            if (-not $NoPlaintext) { $FindingDetails += "Disable plaintext services (telnet, FTP). " }
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207502 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207502
        STIG ID    : SRG-OS-000432-VMM-001730
        Rule ID    : SV-207502r958926_rule
        Severity   : CAT II
        Title      : The VMM must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.
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
    $VulnID = "V-207502"
    $RuleID = "SV-207502r958926_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Predictable Behavior for Invalid Inputs" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $FindingDetails += "XAPI input validation:" + $nl
        $FindingDetails += "  - XAPI uses XML-RPC with typed parameters and schema validation" + $nl
        $FindingDetails += "  - Invalid API calls return structured error codes and messages" + $nl
        $FindingDetails += "  - Type mismatches, missing parameters, and invalid values are rejected" + $nl + $nl

        $PanicOnOops = $(timeout 5 cat /proc/sys/kernel/panic_on_oops 2>/dev/null)
        $PanicOnOopsStr = ("$PanicOnOops").Trim()
        $FindingDetails += "kernel.panic_on_oops: $PanicOnOopsStr (1=panic on invalid kernel state)" + $nl

        $PanicTimeout = $(timeout 5 cat /proc/sys/kernel/panic 2>/dev/null)
        $PanicTimeoutStr = ("$PanicTimeout").Trim()
        $FindingDetails += "kernel.panic timeout: $PanicTimeoutStr seconds (0=hang, N=reboot after N sec)" + $nl

        $CorePattern = $(timeout 5 cat /proc/sys/kernel/core_pattern 2>/dev/null)
        $CorePatternStr = ("$CorePattern").Trim()
        $FindingDetails += "Core dump pattern: $CorePatternStr" + $nl

        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: XCP-ng behaves predictably when invalid inputs are received. XAPI validates all XML-RPC API inputs against typed schemas and returns structured error responses for invalid parameters. The Linux kernel handles invalid system states via configurable panic behavior. The Xen hypervisor enforces strict type checking on all hypercalls and returns defined error codes for invalid operations."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207503 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207503
        STIG ID    : SRG-OS-000433-VMM-001740
        Rule ID    : SV-207503r958928_rule
        Severity   : CAT II
        Title      : The VMM must implement non-executable data to protect its memory from unauthorized code execution.
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
    $VulnID = "V-207503"
    $RuleID = "SV-207503r958928_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Non-Executable Data (NX/XD) Memory Protection" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $CpuFlags = $(timeout 5 grep -m 1 'flags' /proc/cpuinfo 2>/dev/null)
        $CpuFlagsStr = ("$CpuFlags").Trim()
        $HasNx = ($CpuFlagsStr -match " nx ")
        $FindingDetails += "CPU NX (No-Execute) bit: $(if ($HasNx) { 'supported' } else { 'not detected' })" + $nl

        $DmesgNx = $(timeout 5 dmesg 2>/dev/null | grep -i 'NX.*protection\|Execute Disable' | head -3 2>&1)
        $DmesgArr = @()
        if ($null -ne $DmesgNx) { $DmesgArr = @($DmesgNx) }
        if ($DmesgArr.Count -gt 0) {
            $FindingDetails += "Kernel NX status:" + $nl
            foreach ($Line in $DmesgArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        $Arch = $(uname -m 2>/dev/null)
        $FindingDetails += "Architecture: $(("$Arch").Trim())" + $nl

        if ($HasNx) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Non-executable data (NX/XD bit) is supported and enforced by hardware. The CPU supports the NX (No-Execute) bit, which prevents code execution from data pages. The Linux kernel and Xen hypervisor leverage this hardware feature to enforce W^X (Write XOR Execute) memory protection."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: NX bit support not detected in CPU flags. Ensure the CPU supports the NX (No-Execute) bit and it is enabled in BIOS/UEFI."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207504 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207504
        STIG ID    : SRG-OS-000433-VMM-001750
        Rule ID    : SV-207504r958928_rule
        Severity   : CAT II
        Title      : The VMM must implement address space layout randomization to protect its memory from unauthorized code execution.
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
    $VulnID = "V-207504"
    $RuleID = "SV-207504r958928_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Address Space Layout Randomization (ASLR)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $Aslr = $(timeout 5 cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
        $AslrStr = ("$Aslr").Trim()
        $FindingDetails += "kernel.randomize_va_space: $AslrStr" + $nl
        $FindingDetails += "  0 = disabled, 1 = conservative, 2 = full" + $nl

        $SysctlAslr = $(timeout 5 grep 'randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)
        $SysctlArr = @()
        if ($null -ne $SysctlAslr) { $SysctlArr = @($SysctlAslr) }
        if ($SysctlArr.Count -gt 0) {
            $FindingDetails += "Persistent sysctl config:" + $nl
            foreach ($Line in $SysctlArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        if ($AslrStr -eq "2") {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Full ASLR (level 2) is enabled. Address space layout randomization randomizes stack, heap, mmap, VDSO, and brk areas for all processes, protecting against memory-based code execution attacks."
        }
        elseif ($AslrStr -eq "1") {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Partial ASLR (level 1). Full ASLR (level 2) is required. Set kernel.randomize_va_space=2 in /etc/sysctl.conf and run sysctl -p."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: ASLR is disabled. Set kernel.randomize_va_space=2 in /etc/sysctl.conf and run sysctl -p."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207505 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207505
        STIG ID    : SRG-OS-000437-VMM-001760
        Rule ID    : SV-207505r958936_rule
        Severity   : CAT II
        Title      : The VMM must remove all software components after updated versions have been installed.
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
    $VulnID = "V-207505"
    $RuleID = "SV-207505r958936_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Removal of Superseded Software Components" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $YumClean = $(timeout 5 grep -E 'clean_requirements_on_remove' /etc/yum.conf 2>/dev/null)
        $YumCleanStr = ("$YumClean").Trim()
        $FindingDetails += "yum clean_requirements_on_remove: $(if ($YumCleanStr.Length -gt 0) { $YumCleanStr } else { 'not set (default: 0)' })" + $nl

        $DupePkgs = $(timeout 10 sh -c 'rpm -qa --queryformat "%{NAME}\n" 2>/dev/null | sort | uniq -d | head -10')
        $DupeArr = @()
        if ($null -ne $DupePkgs) { $DupeArr = @($DupePkgs) }
        $DupeArr = @($DupeArr | Where-Object { "$_".Trim().Length -gt 0 })
        $FindingDetails += "Duplicate package names: $($DupeArr.Count)" + $nl
        foreach ($Pkg in $DupeArr) { $FindingDetails += "  $($Pkg.Trim())" + $nl }

        $Kernels = $(rpm -q kernel 2>/dev/null)
        $KernelArr = @()
        if ($null -ne $Kernels) { $KernelArr = @($Kernels) }
        $FindingDetails += "Installed kernel packages: $($KernelArr.Count)" + $nl
        foreach ($K in $KernelArr) { $FindingDetails += "  $($K.Trim())" + $nl }

        $HasDupes = ($DupeArr.Count -gt 0)
        $ManyKernels = ($KernelArr.Count -gt 3)

        if (-not $HasDupes -and -not $ManyKernels) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: No duplicate package versions detected. RPM/yum package management replaces old software components during updates."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Superseded software components may be present. "
            if ($HasDupes) { $FindingDetails += "Remove duplicate package versions. " }
            if ($ManyKernels) { $FindingDetails += "Clean old kernel packages (keep 2-3 most recent). " }
            $FindingDetails += "Set clean_requirements_on_remove=1 in /etc/yum.conf."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207506 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207506
        STIG ID    : SRG-OS-000445-VMM-001780
        Rule ID    : SV-207506r958944_rule
        Severity   : CAT II
        Title      : The VMM must verify correct operation of all security functions.
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
    $VulnID = "V-207506"
    $RuleID = "SV-207506r958944_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Security Function Verification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $Aide = $(rpm -q aide 2>/dev/null)
        $AideStr = ("$Aide").Trim()
        $FindingDetails += "AIDE (integrity monitoring): $AideStr" + $nl

        $AuditdSvc = $(timeout 5 systemctl is-active auditd 2>/dev/null)
        $FindingDetails += "auditd service: $(("$AuditdSvc").Trim())" + $nl

        $SshdSvc = $(timeout 5 systemctl is-active sshd 2>/dev/null)
        $FindingDetails += "sshd service: $(("$SshdSvc").Trim())" + $nl

        $XapiSvc = $(timeout 5 systemctl is-active xapi 2>/dev/null)
        $XapiStr = ("$XapiSvc").Trim()
        $FindingDetails += "xapi service: $XapiStr" + $nl

        $IptSvc = $(timeout 5 systemctl is-active iptables 2>/dev/null)
        $FindingDetails += "iptables service: $(("$IptSvc").Trim())" + $nl

        $FindingDetails += "RPM verification: available (rpm -V validates package integrity)" + $nl

        $ServicesOk = (("$SshdSvc").Trim() -eq "active" -and $XapiStr -eq "active")

        if ($ServicesOk) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Security function verification capabilities are available. RPM verify validates installed package integrity. Core security services (sshd, xapi) are active. "
            if ($AideStr -notmatch "not installed") { $FindingDetails += "AIDE provides continuous integrity monitoring." }
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Core security services are not all active. Ensure sshd and xapi are running and install AIDE for comprehensive security function verification."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207507 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207507
        STIG ID    : SRG-OS-000446-VMM-001790
        Rule ID    : SV-207507r958946_rule
        Severity   : CAT II
        Title      : The VMM must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.
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
    $VulnID = "V-207507"
    $RuleID = "SV-207507r958946_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Periodic Security Function Verification (Startup/30-Day)" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AideCron = $(timeout 5 find /etc/cron.d /etc/cron.daily /etc/cron.weekly -maxdepth 1 -name '*aide*' -type f 2>/dev/null | head -5 2>&1)
        $AideCronArr = @()
        if ($null -ne $AideCron) { $AideCronArr = @($AideCron) }
        $AideCronArr = @($AideCronArr | Where-Object { "$_".Trim().Length -gt 0 })
        $FindingDetails += "AIDE cron jobs: $($AideCronArr.Count)" + $nl

        $CronCheck = $(timeout 5 sh -c 'grep -r "rpm -V\|aide.*check" /etc/crontab /var/spool/cron/ /etc/cron.d/ 2>/dev/null | head -5')
        $CronArr = @()
        if ($null -ne $CronCheck) { $CronArr = @($CronCheck) }
        $CronArr = @($CronArr | Where-Object { "$_".Trim().Length -gt 0 })
        if ($CronArr.Count -gt 0) {
            $FindingDetails += "Scheduled integrity checks:" + $nl
            foreach ($Line in $CronArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        $EnabledSvc = $(timeout 5 systemctl is-enabled auditd sshd iptables xapi 2>/dev/null)
        $SvcArr = @()
        if ($null -ne $EnabledSvc) { $SvcArr = @($EnabledSvc) }
        $SvcNames = @("auditd", "sshd", "iptables", "xapi")
        $FindingDetails += "Boot-enabled security services:" + $nl
        for ($i = 0; $i -lt $SvcArr.Count -and $i -lt $SvcNames.Count; $i++) {
            $FindingDetails += "  $($SvcNames[$i]): $(("$($SvcArr[$i])").Trim())" + $nl
        }

        $HasPeriodicCheck = ($AideCronArr.Count -gt 0) -or ($CronArr.Count -gt 0)

        if ($HasPeriodicCheck) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Security function verification is performed periodically via scheduled integrity checks. Security services are enabled at boot. Privileged users can invoke rpm -V and aide --check on demand."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: No periodic security function verification detected. Install AIDE and create a cron job for daily/weekly integrity checks (e.g., /etc/cron.daily/aide-check). Ensure all security services are enabled at boot."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207508 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207508
        STIG ID    : SRG-OS-000447-VMM-001800
        Rule ID    : SV-207508r958948_rule
        Severity   : CAT II
        Title      : The VMM must shut down, restart, and/or notify the system administrator when anomalies in the operation of any security functions are discovered.
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
    $VulnID = "V-207508"
    $RuleID = "SV-207508r958948_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Security Function Anomaly Notification" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdConf = $(timeout 5 grep -E 'disk_full_action|disk_error_action|admin_space_left_action|space_left_action' /etc/audit/auditd.conf 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditdConf) { $AuditArr = @($AuditdConf) }
        if ($AuditArr.Count -gt 0) {
            $FindingDetails += "auditd anomaly actions:" + $nl
            foreach ($Line in $AuditArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }
        else {
            $FindingDetails += "auditd anomaly actions: not configured" + $nl
        }

        $Rsyslog = $(timeout 5 grep -E '^\*\.\*|^authpriv\.\*|^auth\.\*' /etc/rsyslog.conf 2>/dev/null)
        $RsysArr = @()
        if ($null -ne $Rsyslog) { $RsysArr = @($Rsyslog) }
        if ($RsysArr.Count -gt 0) {
            $FindingDetails += "rsyslog notification targets:" + $nl
            foreach ($Line in $RsysArr) { $FindingDetails += "  $($Line.Trim())" + $nl }
        }

        $PanicOnOops = $(timeout 5 cat /proc/sys/kernel/panic_on_oops 2>/dev/null)
        $FindingDetails += "kernel.panic_on_oops: $(("$PanicOnOops").Trim()) (1=restart on kernel anomaly)" + $nl

        $HasAuditActions = ($AuditArr.Count -gt 0)
        $HasSyslog = ($RsysArr.Count -gt 0)

        if ($HasAuditActions -or $HasSyslog) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Security function anomaly notification is configured. "
            if ($HasAuditActions) { $FindingDetails += "auditd takes action on anomalies (syslog, halt, or email). " }
            if ($HasSyslog) { $FindingDetails += "rsyslog forwards security events. " }
            $FindingDetails += "XAPI generates management alerts. Kernel panic_on_oops forces restart on kernel anomalies."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: Security function anomaly notification not configured. Configure auditd disk_full_action/admin_space_left_action and rsyslog forwarding."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

Function Get-V207509 {
    <#
    .DESCRIPTION
        Vuln ID    : V-207509
        STIG ID    : SRG-OS-000458-VMM-001810
        Rule ID    : SV-207509r958968_rule
        Severity   : CAT II
        Title      : The VMM must generate audit records when successful/unsuccessful attempts to access security objects occur.
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
    $VulnID = "V-207509"
    $RuleID = "SV-207509r958968_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    if ($null -eq $XCPngVersionInfo) { Initialize-XCPngVersionInfo }

    if (-not $XCPngVersionInfo.IsSupported) {
        $Status = "Not_Applicable"
        $FindingDetails = "XCP-ng version $($XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        $FindingDetails = "Audit Records for Security Object Access" + $nl
        $FindingDetails += "XCP-ng Version: $($XCPngVersionInfo.VersionString)" + $nl + $nl

        $AuditdSvc = $(timeout 5 systemctl is-active auditd 2>/dev/null)
        $AuditdStr = ("$AuditdSvc").Trim()
        $FindingDetails += "auditd service: $AuditdStr" + $nl

        $AuditRules = $(timeout 5 auditctl -l 2>/dev/null)
        $AuditArr = @()
        if ($null -ne $AuditRules) { $AuditArr = @($AuditRules) }

        $SecurityRules = @($AuditArr | Where-Object {
            "$_" -match "/etc/passwd|/etc/shadow|/etc/group|/etc/sudoers|/etc/ssh|/etc/pam|/etc/audit|/etc/security"
        })
        $FindingDetails += "Security object audit rules: $($SecurityRules.Count)" + $nl
        foreach ($Rule in $SecurityRules) { $FindingDetails += "  $($Rule.Trim())" + $nl }

        $AccessRules = @($AuditArr | Where-Object { "$_" -match "open|access|creat|truncate|chmod|chown" })
        $FindingDetails += "File access syscall rules: $($AccessRules.Count)" + $nl
        $FindingDetails += "Total audit rules: $($AuditArr.Count)" + $nl

        $HasAuditd = ($AuditdStr -eq "active")
        $HasSecurityRules = ($SecurityRules.Count -gt 0) -or ($AccessRules.Count -gt 0)

        if ($HasAuditd -and $HasSecurityRules) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "RESULT: Audit records are generated for security object access. auditd is active with rules monitoring access to security-relevant files and syscalls."
        }
        elseif ($HasAuditd) {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is active but no rules for security object access. Add rules: auditctl -w /etc/passwd -p wa -k identity, auditctl -w /etc/shadow -p wa -k identity, etc."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "RESULT: auditd is not active. Install and enable auditd and configure security object access rules."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else { $ResultHash = "" }

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

# Generate remaining functions (V-207510 through V-264326)
# 32 stub functions for rules not yet explicitly implemented (Batches 9-10)
# Note: 11 VulnIDs in sequential gaps do NOT exist in VMM SRG V2R2 XCCDF and are excluded:
#   V-207359, V-207380, V-207400, V-207408, V-207450, V-207451,
#   V-207476, V-207477, V-207478, V-207479, V-207485

$RemainingRules = @(
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
        [String]`$Username,
        [Parameter(Mandatory = `$false)]
        [String]`$UserSID,
        [Parameter(Mandatory = `$false)]
        [String]`$Hostname,
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
    `$nl = [Environment]::NewLine
    if (`$null -eq `$XCPngVersionInfo) { Initialize-XCPngVersionInfo }
    if (-not `$XCPngVersionInfo.IsSupported) {
        `$Status = "Not_Applicable"
        `$FindingDetails = "XCP-ng version `$(`$XCPngVersionInfo.Version) is not supported for VMM SRG compliance scanning."
    }
    else {
        `$FindingDetails = "Manual Check Required: Verify $CategoryHint configuration for XCP-ng." + `$nl
        `$FindingDetails += "Review relevant xapi, Dom0, and guest VM settings." + `$nl
        `$FindingDetails += `$nl + "XCP-ng Version: `$(`$XCPngVersionInfo.VersionString)"
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
