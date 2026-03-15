#!/usr/bin/env python3
"""Fix Rule 4 violations in Dom0 RHEL7 module -- Phase 2A QA Remediation

Removes sh -c wrappers from 20 commands.
Patterns:
1. $(timeout N sh -c 'awk -F: ''pattern'' /etc/passwd' 2>&1)
   -> $(timeout N awk -F: 'pattern' /etc/passwd 2>&1)
2. $(timeout N sh -c "awk -F: '\$field' /etc/passwd")
   -> $(timeout N awk -F: '$field' /etc/passwd 2>&1)
3. $(timeout N sh -c 'cmd1 | cmd2 | cmd3')
   -> $(timeout N cmd1 | cmd2 | cmd3)
4. $(timeout N sh -c 'grep ...' 2>&1)
   -> $(timeout N grep ... 2>&1)
"""

import re
import sys
from pathlib import Path

MODULE_FILE = (Path(__file__).resolve().parents[3] /
               "Evaluate-STIG" / "Modules" /
               "Scan-XCP-ng_Dom0_RHEL7_Checks" /
               "Scan-XCP-ng_Dom0_RHEL7_Checks.psm1")


def fix_rule4(text):
    """Remove all sh -c wrappers."""
    count = 0

    # Pattern 1: $(timeout N sh -c 'awk -F: ''pattern'' /etc/file' 2>&1)
    # The doubled single quotes '' inside shell single-quoted string = literal '
    # Transform: remove sh -c, un-double the single quotes
    def fix_awk_single_quoted(match):
        nonlocal count
        count += 1
        prefix = match.group(1)       # e.g., "$(timeout 5 "
        awk_body = match.group(2)     # e.g., "awk -F: ''pattern'' /etc/passwd"
        suffix = match.group(3)       # e.g., " 2>&1)" or ")"

        # Un-double the single quotes: '' -> ' (shell escaping -> PowerShell literal)
        awk_body = awk_body.replace("''", "'")
        return prefix + awk_body + suffix

    # Match: $(timeout N sh -c 'awk...anything with doubled quotes.../etc/something' optional_redirect)
    text = re.sub(
        r"(\$\(timeout \d+ )sh -c '(awk -F: ''.+?'' /etc/\w+)'( 2>&1\)|\))",
        fix_awk_single_quoted,
        text
    )

    # Pattern 2: $(timeout N sh -c "awk -F: '\$field...' /etc/file")
    # Double-quoted with escaped dollar signs
    def fix_awk_double_quoted(match):
        nonlocal count
        count += 1
        prefix = match.group(1)
        inner = match.group(2)
        # Remove escaped dollars: \$ -> $ (no longer needs escaping outside double quotes)
        inner = inner.replace("\\$", "$")
        # Ensure 2>&1 at end
        if "2>&1" not in inner and "2>/dev/null" not in inner:
            inner = inner.rstrip() + " 2>&1"
        return prefix + inner + ")"

    text = re.sub(
        r'(\$\(timeout \d+ )sh -c "(awk -F: .+?)"(\))',
        fix_awk_double_quoted,
        text
    )

    # Pattern 3: $(timeout N sh -c 'rpm/grep piped commands')
    # Piped commands inside sh -c single quotes
    def fix_piped_single_quoted(match):
        nonlocal count
        count += 1
        prefix = match.group(1)
        inner = match.group(2)
        # No quote transformation needed for these (no awk doubled quotes)
        return prefix + inner + ")"

    text = re.sub(
        r"(\$\(timeout \d+ )sh -c '((?:rpm|grep) .+?)'(\))",
        fix_piped_single_quoted,
        text
    )

    return text, count


def verify(text):
    """Verify no sh -c remains."""
    remaining = [(i+1, line) for i, line in enumerate(text.split('\n'))
                 if 'sh -c' in line]
    return remaining


def main():
    if not MODULE_FILE.exists():
        print(f"ERROR: Module file not found: {MODULE_FILE}")
        sys.exit(1)

    print(f"Reading: {MODULE_FILE}")
    original = MODULE_FILE.read_text(encoding='utf-8')

    text, count = fix_rule4(original)
    print(f"Fixed {count} sh -c wrappers")

    remaining = verify(text)
    print(f"Remaining sh -c: {len(remaining)}")
    for lineno, line in remaining:
        print(f"  Line {lineno}: {line.strip()[:100]}")

    if text != original:
        MODULE_FILE.write_text(text, encoding='utf-8')
        print(f"\nWrote: {MODULE_FILE}")
    else:
        print("\nNo changes needed.")


if __name__ == "__main__":
    main()
