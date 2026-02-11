# Minimal helper module for manual-only STIG entries
$ErrorActionPreference = 'Stop'

function New-ManualResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [string]$StigId,

        [Parameter(Mandatory)]
        [string]$GroupId,

        [Parameter()]
        [string]$Reason = 'Manual review required; no automated check implemented.'
    )

    [pscustomobject]@{
        Status           = 'Not_Reviewed'
        FindingDetails   = "${Reason}`nRuleId: ${RuleId}`nGroupId: ${GroupId}`nSTIGID: ${StigId}"
        Comments         = ''
        AFKey            = ''
        AFStatus         = ''
        SeverityOverride = ''
        Justification    = ''
        ErrorData        = $null
    }
}

Export-ModuleMember -Function New-ManualResult
