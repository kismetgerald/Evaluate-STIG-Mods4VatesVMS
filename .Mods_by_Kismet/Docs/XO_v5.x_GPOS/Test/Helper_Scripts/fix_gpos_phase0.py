#!/usr/bin/env python3
"""
Phase 0 Remediation Script for Scan-XO_GPOS_Debian12_Checks
Fixes:
  1. Function naming: Get-V-###### -> Get-V######  (remove hyphen after V)
  2. Missing params: Add $Username, $UserSID, $Hostname to all stub param blocks
  3. Missing StigType in GetCorpParams
  4. Regenerate PSD1 manifest with correct function names
"""

import re
import os

PROJECT = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode"
PSM1 = os.path.join(PROJECT, "Evaluate-STIG", "Modules", "Scan-XO_GPOS_Debian12_Checks", "Scan-XO_GPOS_Debian12_Checks.psm1")
PSD1 = os.path.join(PROJECT, "Evaluate-STIG", "Modules", "Scan-XO_GPOS_Debian12_Checks", "Scan-XO_GPOS_Debian12_Checks.psd1")

# --- Fix PSM1 ---
print("Reading PSM1...")
with open(PSM1, 'r', encoding='utf-8') as f:
    content = f.read()

original_len = len(content)

# 1. Fix function naming: Get-V-###### -> Get-V######
# Match "Function Get-V-" followed by digits
rename_count = len(re.findall(r'Function Get-V-(\d+)', content))
content = re.sub(r'Function Get-V-(\d+)', r'Function Get-V\1', content)
print(f"  1. Renamed {rename_count} function declarations (Get-V-###### -> Get-V######)")

# 2. Add missing params ($Username, $UserSID, $Hostname)
# The current param blocks have: ScanType, AnswerFile, AnswerKey, Instance, Database, SiteName
# Need to insert: $Username, $UserSID, $Hostname BEFORE $Instance
# Pattern: after [String]$AnswerKey, insert the 3 missing params before [String]$Instance

MISSING_PARAMS = """
        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$Hostname,
"""

# Find the pattern: AnswerKey declaration followed by Instance declaration
# We need to insert between them
param_pattern = r'(\[String\]\$AnswerKey,\s*\n)(\s*\[Parameter\(Mandatory = \$false\)\]\s*\n\s*\[String\]\$Instance)'
param_count = len(re.findall(param_pattern, content))
content = re.sub(param_pattern, r'\1' + MISSING_PARAMS + r'\2', content)
print(f"  2. Added missing params ($Username, $UserSID, $Hostname) to {param_count} functions")

# 3. Add StigType to GetCorpParams where missing
# Pattern: OSPlatform line without StigType following it
# Current: OSPlatform   = $OSPlatform
# Need to add: StigType     = $StigType
stigtype_pattern = r'(OSPlatform\s*=\s*\$OSPlatform)\s*\n(\s*\})'
stigtype_count = len(re.findall(stigtype_pattern, content))
content = re.sub(stigtype_pattern, r'\1\n            StigType     = $StigType\n\2', content)
print(f"  3. Added StigType to {stigtype_count} GetCorpParams blocks")

# Write updated PSM1
with open(PSM1, 'w', encoding='utf-8') as f:
    f.write(content)

new_len = len(content)
print(f"  PSM1 updated: {original_len} -> {new_len} chars ({new_len - original_len:+d})")

# Verify function count
func_names = re.findall(r'Function Get-V(\d+)', content)
print(f"  Functions found: {len(func_names)}")

# Check for any remaining hyphenated functions
remaining_hyphens = re.findall(r'Function Get-V-(\d+)', content)
if remaining_hyphens:
    print(f"  WARNING: {len(remaining_hyphens)} hyphenated functions remaining!")
else:
    print(f"  OK: No hyphenated function names remaining")

# --- Regenerate PSD1 ---
print("\nRegenerating PSD1...")

# Extract all check function names (not helpers)
check_funcs = sorted(func_names, key=lambda x: int(x))
# Format as Get-V######
func_exports = [f"'Get-V{num}'" for num in check_funcs]

# Build PSD1 content
psd1_content = """@{
    RootModule = 'Scan-XO_GPOS_Debian12_Checks.psm1'
    ModuleVersion = '1.0.0'
    GUID = '6f9d4c2e-7a5b-4e3f-8c1a-9b2d5e3a1f6c'
    Author = 'Kismet Agbasi'
    CompanyName = 'Evaluate-STIG Contributors'
    Description = 'PowerShell STIG compliance checking module for Debian 12 General Purpose Operating System (GPOS) SRG V3R2'
    PowerShellVersion = '7.1'

    # Functions to export - 198 GPOS SRG check functions + helpers
    FunctionsToExport = @(
"""

# Add functions in groups of 5
for i in range(0, len(func_exports), 5):
    chunk = func_exports[i:i+5]
    psd1_content += "        " + ", ".join(chunk)
    if i + 5 < len(func_exports):
        psd1_content += ","
    psd1_content += "\n"

psd1_content += """    )
}
"""

with open(PSD1, 'w', encoding='utf-8') as f:
    f.write(psd1_content)

print(f"  PSD1 regenerated with {len(func_exports)} function exports")
print(f"  VulnID range: V-{check_funcs[0]} to V-{check_funcs[-1]}")

print("\nPhase 0 remediation complete!")
print(f"  - {rename_count} functions renamed")
print(f"  - {param_count} param blocks updated")
print(f"  - {stigtype_count} GetCorpParams blocks updated")
print(f"  - PSD1 regenerated with {len(func_exports)} correct exports")
