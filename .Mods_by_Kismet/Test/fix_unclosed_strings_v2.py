#!/usr/bin/env python3
"""
Fix unclosed strings: add closing double-quote before ' + $nl' at end of lines
where a += string assignment is missing its closing quote.

Pattern:
  BROKEN:  $FindingDetails += "text $var + $nl
  FIXED:   $FindingDetails += "text $var" + $nl

Detection: lines where $FindingDetails or $output starts an assignment with "
and the character immediately before ' + $nl' is NOT a closing quote.
"""
import re

psm1_path = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules"
    r"\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
)

with open(psm1_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Target ranges (1-indexed, inclusive) - the 5 functions being fixed
target_ranges = [(21348, 21754), (26511, 27057), (34507, 35183), (35184, 35503), (35508, 35986)]
changes = 0

for i in range(len(lines)):
    in_range = any(start <= i+1 <= end for start, end in target_ranges)
    if not in_range:
        continue

    line = lines[i]
    orig = line

    # Match:  $FindingDetails += "...content... + $nl
    # Where the string opened by " is NOT closed (no closing " before ' + $nl')
    # Pattern: assignment start " then content then ' + $nl' at end
    # Key: the content DOES NOT end with " before ' + $nl'
    m = re.search(
        r'(\s*(?:\$FindingDetails|\$output)\s*\+=\s*)"(.*[^"])( \+ \$nl\s*)$',
        line
    )
    if m:
        # Count unescaped " in content to determine if string is open
        content = m.group(2)
        # In PowerShell strings: "" is escaped quote, ` is escape char
        # Count standalone quotes (not part of "")
        quote_count = content.count('"')

        # If even number of quotes in content, string is already closed with one of them
        # If content ends with a variable ($word) and quote_count is even,
        # that means there's a balanced embedded string but outer string is unclosed
        # Simple approach: if content does NOT end with ", string is unclosed

        # Verify content doesn't end with "
        if not content.endswith('"'):
            # Add closing " before ' + $nl'
            suffix = m.group(3)
            new_line = line.rstrip('\n').rstrip('\r')
            # Replace the trailing ' + $nl...' with '" + $nl...'
            new_line = re.sub(
                r'( \+ \$nl\s*)$',
                r'"\1',
                new_line
            ) + '\n'
            if new_line != orig:
                lines[i] = new_line
                changes += 1
                print(f"Line {i+1}: {new_line.rstrip()}")

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
    print(f"Module load FAILED: {result.stderr[:500]}")
