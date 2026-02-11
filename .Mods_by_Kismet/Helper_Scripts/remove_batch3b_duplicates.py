#!/usr/bin/env python3
"""
Remove duplicate Batch 3b stub entries from answer file.

The integration script added full implementations but stub entries remain.
This script removes the FIRST occurrence (stub) and keeps the SECOND (full).

Usage:
    python remove_batch3b_duplicates.py
"""

import os
import re
import shutil
from datetime import datetime

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
ANSWERFILE_PATH = os.path.join(PROJECT_ROOT, 'AnswerFiles', 'XO_v5.x_WebSRG_AnswerFile.xml')

# Vuln IDs to process (remove first occurrence of each)
VULN_IDS = ['V-264346', 'V-264347', 'V-264357', 'V-264354', 'V-279028']


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def find_vuln_entry(content, vuln_id, start_pos=0):
    """
    Find a complete <Vuln ID="...">...</Vuln> entry.
    Returns tuple: (start_pos, end_pos, entry_text) or (None, None, None) if not found.
    """
    # Find opening tag
    pattern = rf'<Vuln ID="{re.escape(vuln_id)}">'
    match = re.search(pattern, content[start_pos:])

    if not match:
        return None, None, None

    actual_start = start_pos + match.start()

    # Find closing tag (from actual_start forward)
    closing_pattern = r'</Vuln>'
    closing_match = re.search(closing_pattern, content[actual_start:])

    if not closing_match:
        raise ValueError(f"No closing </Vuln> found for {vuln_id}")

    actual_end = actual_start + closing_match.end()
    entry_text = content[actual_start:actual_end]

    return actual_start, actual_end, entry_text


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Remove Duplicate Stub Entries")
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

    # Process each Vuln ID
    print("Removing first occurrence (stub) of each Vuln ID:")
    chars_removed = 0
    lines_removed = 0

    for vuln_id in VULN_IDS:
        # Find first occurrence
        start, end, entry = find_vuln_entry(content, vuln_id)

        if start is None:
            print(f"  [WARNING] {vuln_id} not found")
            continue

        entry_lines = entry.count('\n') + 1
        entry_chars = len(entry)

        # Remove from content
        content = content[:start] + content[end:]

        chars_removed += entry_chars
        lines_removed += entry_lines

        print(f"  [OK] Removed {vuln_id} - {entry_lines} lines, {entry_chars} chars")

    print()

    # Write updated answer file
    with open(ANSWERFILE_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    new_size = len(content)
    new_lines = content.count('\n') + 1

    print("Answer file updated:")
    print(f"  New size: {new_lines:,} lines ({new_lines - original_lines:+,})")
    print(f"  Removed: {lines_removed} lines, {chars_removed} chars")
    print()

    # Verify no duplicates remain
    print("Verifying no duplicates remain:")
    for vuln_id in VULN_IDS:
        # Count occurrences
        pattern = rf'<Vuln ID="{re.escape(vuln_id)}">'
        occurrences = len(re.findall(pattern, content))

        if occurrences == 1:
            print(f"  [OK] {vuln_id}: 1 occurrence")
        else:
            print(f"  [ERROR] {vuln_id}: {occurrences} occurrences (expected 1)")

    print()
    print("=" * 80)
    print("[OK] Batch 3b duplicate removal complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. User runs Test115 for framework validation")
    print("  2. Verify COMMENTS fields populated in CKL file")

    return 0


if __name__ == '__main__':
    exit(main())
