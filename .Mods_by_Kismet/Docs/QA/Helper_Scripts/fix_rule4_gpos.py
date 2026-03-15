#!/usr/bin/env python3
r"""Fix Rule 4 violations in GPOS Debian12 module -- Phase 2C QA Remediation

Removes sh -c wrappers from ~187 commands.
Also fixes the 2 variable-based sh -c calls (lines 273, 307) by inlining curl directly.
"""

import re
import sys
from pathlib import Path

MODULE_FILE = (Path(__file__).resolve().parents[3] /
               "Evaluate-STIG" / "Modules" /
               "Scan-XO_GPOS_Debian12_Checks" /
               "Scan-XO_GPOS_Debian12_Checks.psm1")


def fix_variable_shc_calls(text):
    """Fix the 2 sh -c calls that use a variable: $(sh -c $recordArgs 2>&1) and $(sh -c $detailArgs 2>&1).

    These build a command string and use sh -c to execute it. Convert to direct curl calls.
    """
    count = 0

    # Fix line ~272-273: $recordArgs + $(sh -c $recordArgs 2>&1)
    # Replace the $recordArgs assignment and sh -c call with direct curl
    old_record = (
        '    $recordArgs = "timeout 10 curl -s -k -H ${sq}Cookie: authenticationToken=${token}${sq} '
        '${sq}https://localhost/rest/v0/plugins/audit/records?limit=10${sq} 2>/dev/null"\n'
        '    $recordsJson = $(sh -c $recordArgs 2>&1)'
    )
    new_record = (
        '    $recordsJson = $(timeout 10 curl -s -k -H "Cookie: authenticationToken=${token}" '
        '"https://localhost/rest/v0/plugins/audit/records?limit=10" 2>/dev/null)'
    )
    if old_record in text:
        text = text.replace(old_record, new_record)
        count += 1

    # Fix line ~306-307: $detailArgs + $(sh -c $detailArgs 2>&1)
    old_detail = (
        '    $detailArgs = "timeout 10 curl -s -k -H ${sq}Cookie: authenticationToken=${token}${sq} '
        '${sq}https://localhost/rest/v0/plugins/audit/records/${encodedId}${sq} 2>/dev/null"\n'
        '        $detailJson = $(sh -c $detailArgs 2>&1)'
    )
    new_detail = (
        '        $detailJson = $(timeout 10 curl -s -k -H "Cookie: authenticationToken=${token}" '
        '"https://localhost/rest/v0/plugins/audit/records/${encodedId}" 2>/dev/null)'
    )
    if old_detail in text:
        text = text.replace(old_detail, new_detail)
        count += 1

    return text, count


def unwrap_sh_c(text):
    """Remove all remaining sh -c wrappers."""
    count = 0
    lines = text.split('\n')
    new_lines = []

    for i, line in enumerate(lines):
        if 'sh -c' not in line:
            new_lines.append(line)
            continue

        # Skip comments
        stripped = line.lstrip()
        if stripped.startswith('#') or stripped.startswith('<!--'):
            new_lines.append(line)
            continue

        original_line = line

        # Pattern A: $(timeout N sh -c "..." 2>&1)
        m = re.search(r'\$\((timeout \d+ )?sh -c "(.*?)"( 2>&1| 2>/dev/null)?\)', line)
        if m:
            timeout_prefix = m.group(1) or ""
            inner = m.group(2)
            redirect = m.group(3) or ""
            # Remove PS dollar escapes
            inner = inner.replace("\\$", "$")
            inner = re.sub(r'\s*</dev/null', '', inner)
            if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                redirect = " 2>&1"
            replacement = f"$({timeout_prefix}{inner}{redirect})"
            line = line[:m.start()] + replacement + line[m.end():]
            count += 1
            new_lines.append(line)
            continue

        # Pattern B: $(timeout N sh -c '...' 2>&1)
        m = re.search(r"\$\((timeout \d+ )?sh -c '(.*?)'( 2>&1| 2>/dev/null)?\)", line)
        if m:
            timeout_prefix = m.group(1) or ""
            inner = m.group(2)
            redirect = m.group(3) or ""
            has_dev_null_stdin = '</dev/null' in inner
            inner = re.sub(r'\s*</dev/null', '', inner)
            if has_dev_null_stdin and 'openssl s_client' in inner:
                prefix_str = f"echo '' | {timeout_prefix}"
            else:
                prefix_str = timeout_prefix
            if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                redirect = " 2>&1"
            replacement = f"$({prefix_str}{inner}{redirect})"
            line = line[:m.start()] + replacement + line[m.end():]
            count += 1
            new_lines.append(line)
            continue

        # Pattern C: $(sh -c $variable 2>&1) - should be handled by fix_variable_shc_calls
        # If still present, warn
        if re.search(r'\$\(sh -c \$\w+', line):
            print(f"  WARNING: Variable sh -c at line {i+1}: {line.strip()[:120]}")
            new_lines.append(line)
            continue

        # If we get here, unhandled
        print(f"  WARNING: Unhandled sh -c at line {i+1}: {line.strip()[:120]}")
        new_lines.append(line)

    return '\n'.join(new_lines), count


def main():
    if not MODULE_FILE.exists():
        print(f"ERROR: Module file not found: {MODULE_FILE}")
        sys.exit(1)

    print(f"Reading: {MODULE_FILE}")
    original = MODULE_FILE.read_text(encoding='utf-8')

    # Step 1: Fix variable-based sh -c calls
    text, var_count = fix_variable_shc_calls(original)
    print(f"Step 1: Fixed {var_count} variable-based sh -c calls")

    # Step 2: Unwrap remaining sh -c
    text, unwrap_count = unwrap_sh_c(text)
    print(f"Step 2: Unwrapped {unwrap_count} sh -c wrappers")

    # Verify
    remaining = [(i+1, line) for i, line in enumerate(text.split('\n'))
                 if 'sh -c' in line and not line.lstrip().startswith('#')]
    print(f"Remaining sh -c (non-comment): {len(remaining)}")
    for lineno, line in remaining[:10]:
        print(f"  Line {lineno}: {line.strip()[:120]}")

    # Also count comment references
    comment_shc = [(i+1, line) for i, line in enumerate(text.split('\n'))
                   if 'sh -c' in line and line.lstrip().startswith('#')]
    if comment_shc:
        print(f"sh -c in comments (OK): {len(comment_shc)}")

    total = var_count + unwrap_count
    print(f"\nTotal fixes: {total}")

    if text != original:
        MODULE_FILE.write_text(text, encoding='utf-8')
        print(f"Wrote: {MODULE_FILE}")
    else:
        print("No changes needed.")


if __name__ == "__main__":
    main()
