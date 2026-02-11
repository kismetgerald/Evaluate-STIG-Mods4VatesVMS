#!/usr/bin/env python3
"""
Restore closing double-quotes that were incorrectly removed by fix_dangling_quotes.py.
Problem: lines like  $FindingDetails += "text $var + $nl  are unclosed strings.
Fix:                  $FindingDetails += "text $var" + $nl

Only fix lines where the string is unclosed (odd number of unescaped double-quotes
that appear in a += assignment string context).
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

    # Check for unclosed string assignment pattern:
    # $FindingDetails += "...stuff... + $nl
    # or $output += "...stuff... + $nl
    # where the string is unclosed (no matching closing " before + $nl)

    # Pattern: += "...variable... + $nl  (where string is not closed)
    # We detect unclosed string by looking for:
    # - starts with += "  (assignment opening a string)
    # - ends with + $nl (after some content)
    # - has ONLY ONE double-quote (the opening one) in the relevant section

    # Find the += " part
    m = re.search(r'(\s*(?:\$FindingDetails|\$output)\s*\+=\s*)"(.*)( \+ \$nl\s*)$', line)
    if m:
        prefix = m.group(1)  # the += " part
        content = m.group(2)  # content between opening " and end
        suffix = m.group(3)  # " + $nl" part

        # Count unescaped double-quotes in content
        # (PS doesn't have \" escaping inside double-quoted strings, uses `" or "")
        quote_count = content.count('"')

        # If even number of quotes in content, the string is CLOSED (content has paired quotes)
        # If odd number, the string might be unclosed or has an issue
        # But the simpler check: if content ends with a variable ($word),
        # the string was NOT closed by fix_dangling_quotes.py

        # Check if content ends with a PowerShell variable (indicating missing closing quote)
        if re.search(r'\$[a-zA-Z_][a-zA-Z0-9_]*$', content):
            # String is unclosed - add back the closing "
            lines[i] = line.rstrip('\n').rstrip('\r')
            lines[i] = re.sub(
                r'(" \+ \$nl\s*)$',
                r'"\1',
                lines[i].rstrip() + '\n'
            )
            if lines[i] != orig:
                changes += 1
                print(f"Line {i+1}: {lines[i].rstrip()}")

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
