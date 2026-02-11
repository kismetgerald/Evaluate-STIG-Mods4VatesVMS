#!/usr/bin/env python3
"""
Add missing ValidFalseStatus and ValidFalseComment elements to answer file.

The XSD schema requires ALL Answer elements to have:
1. ValidationCode
2. ValidTrueStatus
3. ValidTrueComment
4. ValidFalseStatus (REQUIRED)
5. ValidFalseComment (REQUIRED)

Our Batch 3b entries are missing ValidFalseStatus and ValidFalseComment.

Usage:
    python fix_batch3b_answerfile_complete.py
"""

import os
import re
import shutil
from datetime import datetime

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
ANSWERFILE_PATH = os.path.join(PROJECT_ROOT, 'AnswerFiles', 'XO_v5.x_WebSRG_AnswerFile.xml')


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def add_valid_false_elements(content):
    """
    Add ValidFalseStatus and ValidFalseComment after ValidTrueComment
    where they are missing.

    Strategy: Find </ValidTrueComment> tags that are NOT followed by
    <ValidFalseStatus>, and insert both ValidFalseStatus and ValidFalseComment.
    """
    fixes_applied = 0

    # Split content into lines for processing
    lines = content.split('\n')
    new_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        # Check if this line closes ValidTrueComment
        if '</ValidTrueComment>' in line:
            # Look ahead to see if ValidFalseStatus follows
            next_idx = i + 1
            while next_idx < len(lines) and lines[next_idx].strip() == '':
                next_idx += 1

            next_line = lines[next_idx] if next_idx < len(lines) else ''

            # If next non-empty line doesn't have ValidFalseStatus, add it
            if '<ValidFalseStatus>' not in next_line:
                # Extract indentation from current line
                indent = len(line) - len(line.lstrip())
                indent_str = ' ' * indent

                # Add ValidFalseStatus and ValidFalseComment
                new_lines.append(f"{indent_str}<ValidFalseStatus>NotAFinding</ValidFalseStatus>")
                new_lines.append(f"{indent_str}<ValidFalseComment>This Answer Index should not normally be used. The automated check should properly determine the system status. If the status is incorrect, manual verification may be required to confirm the system configuration meets DoD requirements.</ValidFalseComment>")
                fixes_applied += 1

        i += 1

    return '\n'.join(new_lines), fixes_applied


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Add Missing ValidFalseStatus/Comment")
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

    # Add ValidFalseStatus/Comment elements
    print("Adding missing ValidFalseStatus and ValidFalseComment elements...")
    fixed_content, fixes_applied = add_valid_false_elements(content)

    print(f"  [OK] Added {fixes_applied} sets of ValidFalse elements")
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
    print("[OK] Batch 3b answer file completion successful!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run schema validation via Evaluate-STIG_GUI.ps1")
    print("  2. Verify all 12 errors are resolved")
    print("  3. User runs Test115 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
