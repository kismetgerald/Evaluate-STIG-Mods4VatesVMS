#!/usr/bin/env python3
"""
Fix ExpectedStatus values in answer file entries.

Changes ExpectedStatus="NR" to proper values ("Open" or "NotAFinding")
for 10 functions that are missing COMMENTS due to status mismatch.

Usage:
    python fix_answer_file_expectedstatus.py
"""

import os
import re
from datetime import datetime
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
ANSWER_FILE_PATH = os.path.join(PROJECT_ROOT, 'AnswerFiles', 'XO_v5.x_WebSRG_AnswerFile.xml')

# Actual status values from Test116 CKL
STATUS_CORRECTIONS = {
    'V-206425': 'Open',
    'V-206426': 'NotAFinding',
    'V-206433': 'Open',
    'V-206445': 'Open',
    'V-264341': 'NotAFinding',
    'V-264343': 'Open',
    'V-264344': 'Open',
    'V-264356': 'Open',
    'V-264358': 'NotAFinding',
    'V-264359': 'Open',
}


def create_backup(filepath):
    """Create timestamped backup."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def fix_expected_status(content):
    """Fix ExpectedStatus values for the 10 functions."""
    fixes_applied = 0

    for vuln_id, correct_status in STATUS_CORRECTIONS.items():
        # Pattern: Find the Vuln block and its first Answer element with ExpectedStatus="NR"
        # We need to be careful to only change the first occurrence within each Vuln block

        # Find the entire Vuln block
        vuln_pattern = rf'(<Vuln ID="{vuln_id}">.*?</Vuln>)'
        vuln_match = re.search(vuln_pattern, content, re.DOTALL)

        if not vuln_match:
            print(f"  [WARNING] {vuln_id} not found in answer file")
            continue

        vuln_block = vuln_match.group(1)
        original_block = vuln_block

        # Within this block, replace ExpectedStatus="NR" with correct status
        # Only replace if it's currently "NR"
        updated_block = re.sub(
            r'ExpectedStatus="NR"',
            f'ExpectedStatus="{correct_status}"',
            vuln_block
        )

        if updated_block != original_block:
            content = content.replace(original_block, updated_block)
            fixes_applied += 1
            print(f"  [OK] {vuln_id}: NR -> {correct_status}")

    return content, fixes_applied


def main():
    print("=" * 80)
    print("Fix Answer File ExpectedStatus Values")
    print("=" * 80)
    print()

    # Read answer file
    print(f"Reading answer file: {os.path.basename(ANSWER_FILE_PATH)}")
    with open(ANSWER_FILE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    # Create backup
    backup_path = create_backup(ANSWER_FILE_PATH)
    print()

    # Fix ExpectedStatus values
    print("Fixing ExpectedStatus values...")
    fixed_content, fixes_applied = fix_expected_status(content)

    print()
    print(f"Total fixes applied: {fixes_applied}/10")
    print()

    # Write fixed content
    with open(ANSWER_FILE_PATH, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print("=" * 80)
    print("[OK] Answer file ExpectedStatus values fixed!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run Test117 to verify COMMENTS now populate correctly")
    print("  2. Check CKL file to confirm all 10 functions have COMMENTS")

    return 0


if __name__ == '__main__':
    exit(main())
