#!/usr/bin/env python3
"""Fix Batch 11 functions missing param blocks and variable initialization.

The integration script's regex ate the section between the description #> closing
and the custom code marker, resulting in #>#---=== Begin Custom Code ===---#
which eliminated the param block, $ModuleName, $VulnID, etc.

This script restores the missing sections for all 10 Batch 11 functions.
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

FUNCTIONS = {
    "V-203649": {"RuleID": "SV-203649r971535_rule", "InitStatus": "Open"},
    "V-203657": {"RuleID": "SV-203657r958524_rule", "InitStatus": "Open"},
    "V-203658": {"RuleID": "SV-203658r958528_rule", "InitStatus": "Open"},
    "V-203659": {"RuleID": "SV-203659r970703_rule", "InitStatus": "Open"},
    "V-203660": {"RuleID": "SV-203660r958550_rule", "InitStatus": "Open"},
    "V-203661": {"RuleID": "SV-203661r958552_rule", "InitStatus": "Open"},
    "V-203663": {"RuleID": "SV-203663r958564_rule", "InitStatus": "Open"},
    "V-203664": {"RuleID": "SV-203664r958566_rule", "InitStatus": "Open"},
    "V-203683": {"RuleID": "SV-203683r958636_rule", "InitStatus": "Open"},
    "V-203684": {"RuleID": "SV-203684r958638_rule", "InitStatus": "Open"},
}

PARAM_TEMPLATE = '''    #>

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
    $VulnID = "{vuln_id}"
    $RuleID = "{rule_id}"
    $Status = "{init_status}"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#'''


def main():
    with open(MODULE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    fixes = 0
    for vuln_id, info in FUNCTIONS.items():
        # Look for the broken pattern: #>#---=== Begin Custom Code ===---#
        broken = "#>#---=== Begin Custom Code ===---#"

        # We need to find this pattern specifically within the function for this VulnID
        # Search for the VulnID in the description, then find the broken marker after it
        vuln_pattern = f'Vuln ID    : {vuln_id}'
        vuln_pos = content.find(vuln_pattern)
        if vuln_pos == -1:
            print(f"WARNING: {vuln_id} not found in module")
            continue

        # Find the broken marker after this VulnID
        broken_pos = content.find(broken, vuln_pos)
        if broken_pos == -1:
            print(f"SKIP: {vuln_id} — no broken marker found (already fixed?)")
            continue

        # Make sure this broken marker belongs to this function (not a later one)
        next_func_pos = content.find("Function Get-V", vuln_pos + 20)
        if next_func_pos != -1 and broken_pos > next_func_pos:
            print(f"SKIP: {vuln_id} — broken marker is in a different function")
            continue

        # Build the replacement
        replacement = PARAM_TEMPLATE.format(
            vuln_id=vuln_id,
            rule_id=info["RuleID"],
            init_status=info["InitStatus"]
        )

        # Replace the broken marker with the full param block
        content = content[:broken_pos] + replacement + content[broken_pos + len(broken):]
        fixes += 1
        print(f"OK: {vuln_id} — restored param block and variable initialization")

    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nFixed {fixes}/10 functions")

    # Validate parse
    return 0


if __name__ == "__main__":
    sys.exit(main())
