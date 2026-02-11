#!/usr/bin/env python3
"""
Comprehensive quote fix for V-206430 and V-264354 custom code.

Logic: Count " after ' += ' in each assignment line.
  - EVEN count -> correct, skip
  - count == 1 -> unclosed string, add closing " before ' + $nl'
  - count >= 3 (odd) -> extra " added by mistake, remove it:
      If '$nl" + $nl' at end: remove the trailing '" + $nl' (double-nl case)
      Else: remove the single " before ' + $nl'
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
target_ranges = [(21348, 21754), (35184, 35503)]
changes = 0

for i in range(len(lines)):
    in_range = any(start <= i+1 <= end for start, end in target_ranges)
    if not in_range:
        continue

    line = lines[i]
    orig = line

    # Only process lines with $FindingDetails += or $output += assignments
    m = re.match(r'(\s*(?:\$FindingDetails|\$output)\s*\+=\s*)"(.*?)(\r?\n)$', line, re.DOTALL)
    if not m:
        continue

    # Get the full content after += (includes everything to end of line)
    after_assign_start = line.index(' += "') + len(' += ')
    content_after_assign = line[after_assign_start:].rstrip('\r\n')

    # Count " in content_after_assign
    quote_count = content_after_assign.count('"')

    if quote_count % 2 == 0:
        # Even -> correct, skip
        continue

    # ODD count -> needs fixing
    stripped = line.rstrip('\r\n')

    if quote_count == 1:
        # Unclosed string: add " before ' + $nl'
        new_line = re.sub(r'( \+ \$nl\s*)$', r'"\1', stripped) + '\n'
        if new_line != orig.rstrip('\r\n') + '\n':
            lines[i] = new_line
            changes += 1
            print(f"FIXED(add): Line {i+1}: {new_line.rstrip()}")

    else:
        # count >= 3 (odd): remove the extra "
        # Case A: ...$nl" + $nl at end -> remove trailing " + $nl
        if re.search(r'\$nl" \+ \$nl\s*$', stripped):
            new_line = re.sub(r'" \+ \$nl(\s*)$', r'\1', stripped) + '\n'
            if new_line != orig.rstrip('\r\n') + '\n':
                lines[i] = new_line
                changes += 1
                print(f"FIXED(rm-dbl): Line {i+1}: {new_line.rstrip()}")
        # Case B: something" + $nl at end -> remove just the "
        elif re.search(r'"( \+ \$nl\s*)$', stripped):
            new_line = re.sub(r'"( \+ \$nl\s*)$', r'\1', stripped) + '\n'
            if new_line != orig.rstrip('\r\n') + '\n':
                lines[i] = new_line
                changes += 1
                print(f"FIXED(rm-quot): Line {i+1}: {new_line.rstrip()}")

print(f"\nTotal changes: {changes}")

with open(psm1_path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("\nVerifying module loads...")
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
    print(f"Module load FAILED: {result.stderr[:800]}")
