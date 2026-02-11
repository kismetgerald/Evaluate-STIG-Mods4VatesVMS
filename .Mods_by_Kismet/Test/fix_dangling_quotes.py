#!/usr/bin/env python3
"""
Fix dangling double-quotes introduced by the previous backtick-n replacement.
Pattern: $varname" + $nl  ->  $varname + $nl
"""
import re

psm1_path = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules"
    r"\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
)

with open(psm1_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Target ranges (1-indexed, inclusive)
target_ranges = [(21374, 21735), (35232, 35483)]
changes = 0

for i in range(len(lines)):
    in_range = any(start <= i+1 <= end for start, end in target_ranges)
    if not in_range:
        continue

    line = lines[i]
    orig = line

    # Fix: $varname" + $nl -> $varname + $nl
    # This removes the dangling closing quote before " + $nl"
    # Pattern: a PowerShell variable ($word) followed by " + $nl
    line = re.sub(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)"( \+ \$nl)', r'\1\2', line)

    # Also fix any remaining "`n" that's mid-string followed by just $nl (no + before it)
    # This shouldn't exist but just in case

    if line != orig:
        lines[i] = line
        changes += 1
        print(f"Line {i+1}: {line.rstrip()}")

print(f"\nTotal changes: {changes}")

with open(psm1_path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("Verifying module loads...")
import subprocess
result = subprocess.run(
    ['pwsh', '-Command',
     r"Import-Module '.\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1' -Force -ErrorAction Stop; (Get-Command -Module Scan-XO_WebSRG_Checks).Count"],
    cwd=r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode",
    capture_output=True, text=True
)
if result.returncode == 0:
    print(f"Module loads OK: {result.stdout.strip()} functions")
else:
    print(f"Module load FAILED:")
    print(result.stderr[:500])
