#!/usr/bin/env python3
"""
Fix Rule 1 (backtick-n) and Rule 4 (bash -c) violations in 5 WebSRG functions.
Also fixes V-264357's join with backtick-n, and adds missing Send-CheckResult params.

Functions to fix:
  V-206430 (lines ~21348-21754) - backtick-n + bash -c + missing Head* params
  V-264339 (lines ~26500-27055) - bash -c + missing Head* params
  V-264354 (lines ~35181-35500) - backtick-n + bash -c
  V-264357 (lines ~34504-35180) - bash -c + join backtick-n + missing Head* params
  V-279028 (lines ~35501-35978) - bash -c + missing Head* params
"""

import re

psm1_path = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules"
    r"\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
)

print(f"Reading {psm1_path}")
with open(psm1_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
changes = []

def fix_bash_c(line, lineno):
    """Replace bash -c with sh -c (fixes Rule 4 hang)."""
    orig = line
    line = line.replace('bash -c "', 'sh -c "')
    line = line.replace("bash -c '", "sh -c '")
    if line != orig:
        changes.append(f"  Line {lineno+1}: bash -c → sh -c")
    return line

def fix_backtick_n(line, lineno):
    """
    Fix backtick-n patterns in string literals (Rule 1).
    Converts to use $nl variable instead.
    Assumes $nl = [Environment]::NewLine is defined in the function.
    """
    orig = line

    # Pattern 1: + "`n`n" → + $nl + $nl
    line = re.sub(r'\+\s*"`n`n"', '+ $nl + $nl', line)
    # Pattern 2: + "`n" → + $nl
    line = re.sub(r'\+\s*"`n"', '+ $nl', line)
    # Pattern 3: text`n" at end of a quoted string (before closing quote) -> text" + $nl
    #   e.g.,: "   some text`n"   -> "   some text" + $nl
    #   Handle: "text`n"  ->  "text" + $nl
    line = re.sub(r'`n"(\s*$)', r'" + $nl\g<1>', line)
    # Pattern 4: text`n`n" at end → text" + $nl + $nl
    # (After pattern 3 already handles the last `n, so handle "`n`n" sequences)
    # Actually patterns 1+2 should handle the + form, and pattern 3 handles embedded

    # Pattern 5: text`n$var or text`n  followed by more string
    # e.g.: "text`n$var`n" → "text" + $nl + $var + $nl
    # This is complex - handle the common case: `n$ inside a string
    # Replace `n before a $ with closing quote + $nl +
    # BUT only inside string literals - this is risky, so let's leave for manual fix
    # and just handle the simple end-of-string cases

    if line != orig:
        changes.append(f"  Line {lineno+1}: backtick-n fixed")
    return line

def add_nl_if_missing(lines, custom_code_start_lineno):
    """
    Check if $nl = [Environment]::NewLine is already in the first 5 lines of custom code.
    If not, add it after the custom code begin marker.
    Returns (lines, was_added)
    """
    # Check lines in the next 10 lines after custom code start
    for i in range(custom_code_start_lineno, min(custom_code_start_lineno + 10, len(lines))):
        if '$nl = [Environment]::NewLine' in lines[i]:
            return lines, False
    # Add it
    insert_at = custom_code_start_lineno + 1
    lines.insert(insert_at, '    $nl = [Environment]::NewLine\n')
    changes.append(f"  Line {insert_at+1}: Added $nl = [Environment]::NewLine")
    return lines, True

def fix_send_check_result(lines, function_end_lineno):
    """
    Add HeadInstance, HeadDatabase, HeadSite, HeadHash to Send-CheckResult if missing.
    Searches backwards from function end for the $SendCheckParams block.
    """
    # Find the Justification = $Justification line (last standard param before Head* ones)
    for i in range(function_end_lineno, max(0, function_end_lineno - 30), -1):
        if 'Justification    = $Justification' in lines[i]:
            # Check if HeadInstance is already there
            check_range = lines[i:min(i+10, len(lines))]
            if any('HeadInstance' in l for l in check_range):
                return lines  # Already has it
            # Insert the missing parameters after Justification
            indent = '        '
            new_params = (
                f'{indent}HeadInstance     = $Instance\n'
                f'{indent}HeadDatabase     = $Database\n'
                f'{indent}HeadSite         = $SiteName\n'
                f'{indent}HeadHash         = $ResultHash\n'
            )
            lines.insert(i + 1, new_params)
            changes.append(f"  Line {i+2}: Added HeadInstance/Database/Site/Hash to Send-CheckResult")
            return lines
    return lines

# ============================================================
# Find function boundaries by searching for VulnID markers
# ============================================================

def find_function_lines(lines, vuln_id):
    """Find the start of Function Get-VXXXXXX and the end (closing }) for a given VulnID."""
    start = None
    for i, line in enumerate(lines):
        # Function start: e.g. 'Function Get-V206430 {'
        if f'Function Get-V{vuln_id.replace("V-", "")}' in line:
            start = i
            break
    if start is None:
        return None, None

    # Find end: look for 'Function Get-V' after this start, end is just before it
    # or look for the closing } at function level
    for i in range(start + 1, len(lines)):
        if lines[i].strip().startswith('Function Get-V') and i > start + 10:
            return start, i - 1
    # If no next function found, end at Export-ModuleMember
    for i in range(start + 1, len(lines)):
        if 'Export-ModuleMember' in lines[i]:
            return start, i - 1
    return start, len(lines) - 1

def find_custom_code_start(lines, func_start, func_end):
    """Find the line with Begin Custom Code marker."""
    for i in range(func_start, func_end):
        if 'Begin Custom Code' in lines[i] or '# Custom code starts here' in lines[i]:
            return i
    # Fallback: look for $nl = or first $output = or $FindingDetails =
    for i in range(func_start, func_end):
        if '$FindingDetails = "' in lines[i] or '$output = @()' in lines[i] or '$output = "' in lines[i]:
            return i - 1
    return func_start + 30  # rough estimate

def find_custom_code_end(lines, func_start, func_end):
    """Find the line with End Custom Code marker."""
    for i in range(func_end, func_start, -1):
        if 'End Custom Code' in lines[i]:
            return i
    return func_end - 20  # rough estimate

# ============================================================
# Process each function
# ============================================================

functions_to_fix = {
    'V-206430': {'fix_backtick_n': True,  'fix_join_backtick_n': False},
    'V-264339': {'fix_backtick_n': False, 'fix_join_backtick_n': False},
    'V-264354': {'fix_backtick_n': True,  'fix_join_backtick_n': False},
    'V-264357': {'fix_backtick_n': False, 'fix_join_backtick_n': True},
    'V-279028': {'fix_backtick_n': False, 'fix_join_backtick_n': False},
}

for vuln_id, opts in functions_to_fix.items():
    print(f"\nProcessing {vuln_id}...")
    func_start, func_end = find_function_lines(lines, vuln_id)
    if func_start is None:
        print(f"  ERROR: Could not find function for {vuln_id}")
        continue

    print(f"  Function: lines {func_start+1} to {func_end+1}")

    cc_start = find_custom_code_start(lines, func_start, func_end)
    cc_end = find_custom_code_end(lines, func_start, func_end)
    print(f"  Custom code: lines {cc_start+1} to {cc_end+1}")

    # Apply fixes to custom code region
    for i in range(cc_start, cc_end + 1):
        lines[i] = fix_bash_c(lines[i], i)
        if opts['fix_backtick_n']:
            lines[i] = fix_backtick_n(lines[i], i)

    # Fix the join with backtick-n (V-264357 line with $output -join "`n")
    if opts['fix_join_backtick_n']:
        for i in range(cc_start, cc_end + 1):
            if '$output -join' in lines[i] and '"`n"' in lines[i]:
                orig = lines[i]
                lines[i] = lines[i].replace('-join "`n"', '-join $nl')
                if lines[i] != orig:
                    changes.append(f"  Line {i+1}: Fixed -join backtick-n → $nl")

    # Ensure $nl is defined if function uses backtick-n fixes or join fix
    if opts['fix_backtick_n'] or opts['fix_join_backtick_n']:
        lines, was_added = add_nl_if_missing(lines, cc_start)
        if was_added:
            # Recalculate func_end since we inserted a line
            func_end += 1
            cc_end += 1

    # Fix Send-CheckResult (add missing Head* params)
    # Search for the SendCheckParams block near function end
    lines = fix_send_check_result(lines, func_end)

print(f"\n\nAll changes made ({len(changes)} total):")
for c in changes:
    print(c.encode('ascii', errors='replace').decode('ascii'))

# Write back
with open(psm1_path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f"\nWrote {len(lines)} lines back to {psm1_path}")
print("\nDone! Please verify the module loads correctly.")
