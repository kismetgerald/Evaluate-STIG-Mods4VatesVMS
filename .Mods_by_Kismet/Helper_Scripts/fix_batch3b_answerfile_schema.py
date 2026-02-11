#!/usr/bin/env python3
"""
Fix schema validation errors in Batch 3b answer file entries.

The entries are missing the required <ValidationCode> element that must
come before <ValidTrueStatus> according to the XSD schema.

Schema-required order:
1. ValidationCode (REQUIRED)
2. ValidTrueStatus
3. ValidTrueComment
4. ValidFalseStatus (optional)
5. ValidFalseComment (optional)

Usage:
    python fix_batch3b_answerfile_schema.py
"""

import os
import re
import shutil
from datetime import datetime

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
ANSWERFILE_PATH = os.path.join(PROJECT_ROOT, 'AnswerFiles', 'XO_v5.x_WebSRG_AnswerFile.xml')

# Batch 3b Vuln IDs
VULN_IDS = ['V-264346', 'V-264347', 'V-264357', 'V-264354', 'V-279028']


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def fix_validation_code(content):
    """
    Add <ValidationCode>None</ValidationCode> before every <ValidTrueStatus>
    that doesn't already have a ValidationCode before it.

    This fixes the schema validation error where ValidationCode is required
    but missing from answer entries.
    """
    fixes_applied = 0

    # Pattern: Find <ValidTrueStatus> that is NOT preceded by <ValidationCode>
    # We need to match the indentation and add ValidationCode at the same level

    # Split content into lines for processing
    lines = content.split('\n')
    new_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check if this line contains <ValidTrueStatus>
        if '<ValidTrueStatus>' in line:
            # Check if the previous non-empty line contains <ValidationCode>
            # Look backwards to find the last non-empty line
            prev_idx = i - 1
            while prev_idx >= 0 and lines[prev_idx].strip() == '':
                prev_idx -= 1

            prev_line = lines[prev_idx] if prev_idx >= 0 else ''

            # If previous line doesn't have ValidationCode, we need to add it
            if '<ValidationCode>' not in prev_line:
                # Extract indentation from current line
                indent = len(line) - len(line.lstrip())
                indent_str = ' ' * indent

                # Add ValidationCode line before ValidTrueStatus
                validation_line = f"{indent_str}<ValidationCode>None</ValidationCode>"
                new_lines.append(validation_line)
                fixes_applied += 1

        new_lines.append(line)
        i += 1

    return '\n'.join(new_lines), fixes_applied


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Fix Answer File Schema Validation")
    print("=" * 80)
    print()

    # Read answer file
    print(f"Reading answer file: {os.path.basename(ANSWERFILE_PATH)}")
    with open(ANSWERFILE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    original_size = len(content)
    original_lines = content.count('\n') + 1
    print(f"  Original: {original_lines:,} lines, {original_size:,} chars")
    print()

    # Create backup
    backup_path = create_backup(ANSWERFILE_PATH)
    print()

    # Fix ValidationCode elements
    print("Adding missing <ValidationCode> elements...")
    fixed_content, fixes_applied = fix_validation_code(content)

    print(f"  [OK] Added {fixes_applied} ValidationCode elements")
    print()

    # Write updated answer file
    with open(ANSWERFILE_PATH, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    new_size = len(fixed_content)
    new_lines = fixed_content.count('\n') + 1

    print("Answer file updated:")
    print(f"  New size: {new_lines:,} lines ({new_lines - original_lines:+,})")
    print(f"  Chars: {new_size:,} ({new_size - original_size:+,})")
    print()

    # Validate XML structure
    print("Validating XML structure...")
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(fixed_content)
        print("[OK] XML is well-formed")
    except ET.ParseError as e:
        print(f"[ERROR] XML validation failed: {e}")
        return 1

    print()
    print("=" * 80)
    print("[OK] Batch 3b answer file schema fix complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run schema validation via Evaluate-STIG_GUI.ps1")
    print("  2. Verify all 12 errors are resolved (lines 7281-7603)")
    print("  3. User runs Test115 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
