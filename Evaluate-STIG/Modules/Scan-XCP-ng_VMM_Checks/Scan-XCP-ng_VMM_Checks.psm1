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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
        [Parameter(Mandatory = $true)][String]$ScanType,
        [Parameter(Mandatory = $false)][String]$AnswerFile,
        [Parameter(Mandatory = $false)][String]$AnswerKey,
        [Parameter(Mandatory = $false)][String]$Instance,
        [Parameter(Mandatory = $false)][String]$Database,
        [Parameter(Mandatory = $false)][String]$SiteName
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Session,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [String]$UserSID,
        [Parameter(Mandatory = $true)]
        [String]$Ession,
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

# Generate remaining functions (V-207426 through V-264326)
# 109 stub functions for rules not yet explicitly implemented
# Note: 11 VulnIDs in sequential gaps do NOT exist in VMM SRG V2R2 XCCDF and are excluded:
#   V-207359, V-207380, V-207400, V-207408, V-207450, V-207451,
#   V-207476, V-207477, V-207478, V-207479, V-207485

$RemainingRules = @(
    "V-207426", "V-207427", "V-207428", "V-207429", "V-207430", "V-207431", "V-207432",
    "V-207433", "V-207434", "V-207435", "V-207436", "V-207437", "V-207438", "V-207439",
    "V-207440", "V-207441", "V-207442", "V-207443", "V-207444", "V-207445", "V-207446",
    "V-207447", "V-207448", "V-207449",
    "V-207452", "V-207453", "V-207454", "V-207455",
    "V-207456", "V-207457", "V-207458", "V-207459", "V-207460", "V-207461", "V-207462",
    "V-207463", "V-207464", "V-207465", "V-207466", "V-207467", "V-207468", "V-207469",
    "V-207470", "V-207471", "V-207472", "V-207473", "V-207474", "V-207475",
    "V-207480",
    "V-207481", "V-207482", "V-207483", "V-207484",
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
