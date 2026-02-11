#!/usr/bin/env python3
"""Fix remaining unsafe backtick-n patterns in V-206430 and V-264354."""
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
backtick_n = chr(96) + 'n'  # the actual backtick-n character sequence

for i in range(len(lines)):
    in_range = any(start <= i+1 <= end for start, end in target_ranges)
    if not in_range:
        continue
    line = lines[i]
    if backtick_n not in line:
        continue
    if '-split' in line:
        continue  # -split usage is safe, skip
    if '-join' in line:
        continue  # -join usage is safe, skip

    orig = line

    # Pattern A: "text`n$varname" + $nl
    # -> "text" + $nl + $varname + $nl
    # Regex: finds backtick-n before a $variable at end of quoted string
    # The group captures: everything before `n, the $varname, the rest of the line
    line = re.sub(
        r'(`n)(\$[a-zA-Z_][a-zA-Z0-9_]*)(")',
        r'" + $nl + \2\3',
        line
    )

    # Pattern B: "text`n" + $nl
    # -> "text" + $nl  (the + $nl already provides the newline, remove the embedded one)
    # This pattern: backtick-n right before closing quote, followed by + $nl
    line = re.sub(
        r'`n" \+ \$nl',
        '" + $nl',
        line
    )

    # Pattern C: "text`n" (just backtick-n at end, no + $nl after)
    # -> "text" + $nl
    line = re.sub(
        r'`n"(\s*)$',
        r'" + $nl\1',
        line
    )

    if line != orig:
        lines[i] = line
        changes += 1
        print(f"Line {i+1}: {line.rstrip()}")

with open(psm1_path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f"\nTotal changes: {changes}")

# Verify no unsafe backtick-n remain
print("\nVerifying remaining backtick-n in target ranges...")
with open(psm1_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i in range(len(lines)):
    in_range = any(start <= i+1 <= end for start, end in target_ranges)
    if not in_range:
        continue
    line = lines[i]
    if backtick_n in line and '-split' not in line and '-join' not in line:
        print(f"  REMAINING: Line {i+1}: {line.rstrip()}")

print("Done.")
