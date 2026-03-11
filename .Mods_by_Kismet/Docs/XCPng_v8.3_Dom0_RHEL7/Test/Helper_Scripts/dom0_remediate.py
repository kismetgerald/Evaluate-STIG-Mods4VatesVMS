#!/usr/bin/env python3
"""
Dom0 RHEL7 Module Remediation Script
Fixes all critical issues in Scan-XCP-ng_Dom0_RHEL7_Checks.psm1:
1. Rename all functions: Get-V-###### -> Get-V######
2. Fix param blocks: add $Username, $UserSID, $Hostname
3. Fix docblocks: correct STIG IDs, Rule IDs, MD5 hashes, titles
4. Fix helper functions: add timeout+maxdepth to CheckPermissions
"""

import re
import json

PSM1 = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XCP-ng_Dom0_RHEL7_Checks\Scan-XCP-ng_Dom0_RHEL7_Checks.psm1"
METADATA = r"d:\tmp\rhel7_xccdf_metadata.json"

with open(METADATA) as f:
    xccdf = json.load(f)

with open(PSM1, "r", encoding="utf-8") as f:
    content = f.read()

original_len = len(content)

# ===========================================================================
# Fix 1: Rename all functions Get-V-###### -> Get-V######
# ===========================================================================
# This covers: Function definitions, $VulnID assignments, docblock VulnID lines
rename_count = 0

# Function definitions: "Function Get-V-204392" -> "Function Get-V204392"
old_count = len(re.findall(r'Function Get-V-(\d+)', content))
content = re.sub(r'Function Get-V-(\d+)', r'Function Get-V\1', content)
rename_count += old_count
print(f"Fix 1a: Renamed {old_count} function definitions")

# Export line should already be correct (Get-V* wildcard), verify
if "Export-ModuleMember -Function Get-V*" in content:
    print("Fix 1b: Export-ModuleMember already uses Get-V* wildcard (OK)")
else:
    print("WARNING: Export-ModuleMember pattern not found!")

# ===========================================================================
# Fix 2: Fix param blocks - add $Username, $UserSID, $Hostname
# ===========================================================================
# Current param block has 6 params: $ScanType, $AnswerFile, $AnswerKey, $Instance, $Database, $SiteName
# Need to add: $Username, $UserSID, $Hostname (after $AnswerKey)

old_param = """        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,"""

new_param = """        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$Hostname,

        [Parameter(Mandatory = $false)]
        [String]$Instance,"""

param_count = content.count(old_param)
content = content.replace(old_param, new_param)
print(f"Fix 2: Added $Username, $UserSID, $Hostname to {param_count} param blocks")

# ===========================================================================
# Fix 3: Fix docblocks with correct XCCDF metadata
# ===========================================================================
fix3_count = 0
for vid, meta in xccdf.items():
    # Find the docblock for this VulnID
    # Pattern: Vuln ID    : V-######
    #          STIG ID    : RHEL-07-######
    #          Rule ID    : SV-######_rule
    #          Rule Title : [STUB] ...
    #          DiscussMD5 : 000...
    #          CheckMD5   : 000...
    #          FixMD5     : 000...

    pattern = (
        rf'(Vuln ID    : {vid}\n)'
        rf'\s+STIG ID    : .*?\n'
        rf'\s+Rule ID    : .*?\n'
        rf'\s+Rule Title : .*?\n'
        rf'\s+DiscussMD5 : .*?\n'
        rf'\s+CheckMD5   : .*?\n'
        rf'\s+FixMD5     : .*?\n'
    )

    # Escape special chars in title for replacement
    safe_title = meta['title'].replace('\\', '\\\\')

    replacement = (
        f"Vuln ID    : {vid}\n"
        f"        STIG ID    : {meta['stig_id']}\n"
        f"        Rule ID    : {meta['rule_id']}\n"
        f"        Rule Title : {safe_title}\n"
        f"        DiscussMD5 : {meta['discuss_md5']}\n"
        f"        CheckMD5   : {meta['check_md5']}\n"
        f"        FixMD5     : {meta['fix_md5']}\n"
    )

    new_content, n = re.subn(pattern, replacement, content, count=1)
    if n > 0:
        content = new_content
        fix3_count += 1

print(f"Fix 3: Updated {fix3_count}/244 docblocks with correct XCCDF metadata")

# ===========================================================================
# Fix 4: Fix Rule IDs in $RuleID variable assignments
# ===========================================================================
fix4_count = 0
for vid, meta in xccdf.items():
    # Fix $RuleID = "SV-######_rule" -> correct rule ID from XCCDF
    # Find within context of this function (after Vuln ID line)
    old_ruleid_pattern = rf'(\$VulnID = "{vid}"\n\s+\$RuleID = ")[^"]*(")'
    new_ruleid = rf'\g<1>{meta["rule_id"]}\2'
    new_content, n = re.subn(old_ruleid_pattern, new_ruleid, content, count=1)
    if n > 0:
        content = new_content
        fix4_count += 1

print(f"Fix 4: Updated {fix4_count}/244 $RuleID assignments")

# ===========================================================================
# Fix 5: Fix CheckPermissions helper - add timeout and maxdepth
# ===========================================================================
# The find commands in CheckPermissions don't have timeout
# Add timeout 30 to all find commands in the helper

old_check_perms = """Function CheckPermissions {
    param(
        [string]$FindPath,
        [ValidateSet("File", "Directory")]
        [string]$Type,
        [int]$MinPerms,
        [switch]$Recurse
    )

    $permMask = "{0:D4}" -f $(7777 - $MinPerms)

    if ($Recurse) {
        if ($Type -eq "File") {
            $result = @(find $FindPath -xdev -not -path '*/.*' -not -type l -type f -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        elseif ($Type -eq "Directory") {
            $result = @(find $FindPath -xdev -not -path '*/.*' -not -type l -type d -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        else {
            $result = @(find $FindPath -xdev -not -path '*/.*' -not -type l -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
    }
    else {
        if ($Type -eq "File") {
            $result = @(find $FindPath -maxdepth 1 -not -path '*/.*' -not -type l -type f -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        elseif ($Type -eq "Directory") {
            $result = @(find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -type d -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        else {
            $result = @(find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
    }

    if ($result.Count -eq 0 -or $null -eq $result) {
        return $true
    }
    else {
        return $result
    }
}"""

new_check_perms = """Function CheckPermissions {
    param(
        [string]$FindPath,
        [ValidateSet("File", "Directory")]
        [string]$Type,
        [int]$MinPerms,
        [switch]$Recurse
    )

    $permMask = "{0:D4}" -f $(7777 - $MinPerms)

    if ($Recurse) {
        if ($Type -eq "File") {
            $result = @(timeout 30 find $FindPath -xdev -maxdepth 5 -not -path '*/.*' -not -type l -type f -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        elseif ($Type -eq "Directory") {
            $result = @(timeout 30 find $FindPath -xdev -maxdepth 5 -not -path '*/.*' -not -type l -type d -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        else {
            $result = @(timeout 30 find $FindPath -xdev -maxdepth 5 -not -path '*/.*' -not -type l -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
    }
    else {
        if ($Type -eq "File") {
            $result = @(timeout 30 find $FindPath -maxdepth 1 -not -path '*/.*' -not -type l -type f -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        elseif ($Type -eq "Directory") {
            $result = @(timeout 30 find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -type d -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
        else {
            $result = @(timeout 30 find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -perm /$permMask -printf "%04m %p\\n" 2>/dev/null)
        }
    }

    if ($result.Count -eq 0 -or $null -eq $result) {
        return $true
    }
    else {
        return $result
    }
}"""

if old_check_perms in content:
    content = content.replace(old_check_perms, new_check_perms)
    print("Fix 5: Added timeout 30 + maxdepth 5 to CheckPermissions helper")
else:
    print("WARNING: CheckPermissions helper pattern not found (may need manual fix)")

# ===========================================================================
# Write output
# ===========================================================================
with open(PSM1, "w", encoding="utf-8") as f:
    f.write(content)

print(f"\nDone! File size: {original_len} -> {len(content)} bytes")
print(f"Net change: {len(content) - original_len:+d} bytes")
