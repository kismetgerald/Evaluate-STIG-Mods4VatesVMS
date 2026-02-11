#!/usr/bin/env python3
"""
Fix MD5 hash lengths in XO WebSRG module.

Some functions have MD5 hashes with garbage text appended (63 chars instead of 32).
This script truncates all MD5 hashes to exactly 32 characters.

Usage:
    python fix_md5_hash_length.py
"""

import os
import re
from datetime import datetime
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Modules', 'Scan-XO_WebSRG_Checks', 'Scan-XO_WebSRG_Checks.psm1')


def create_backup(filepath):
    """Create timestamped backup."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def fix_md5_lengths(content):
    """Truncate MD5 hash values to exactly 32 characters."""
    fixes_applied = 0

    # Pattern: MD5 field followed by 32+ hex chars
    # Matches: "DiscussMD5 : 45f15e...T5U6V7..." or "CheckMD5   : bba8a...U6V7W8..."
    pattern = r'(DiscussMD5|CheckMD5|FixMD5)(\s*:\s*)([a-f0-9]{32})[a-zA-Z0-9]+'

    def truncate_hash(match):
        nonlocal fixes_applied
        field_name = match.group(1)
        separator = match.group(2)
        valid_hash = match.group(3)  # First 32 chars only

        fixes_applied += 1
        return f"{field_name}{separator}{valid_hash}"

    new_content = re.sub(pattern, truncate_hash, content)

    return new_content, fixes_applied


def main():
    print("=" * 80)
    print("Fix MD5 Hash Lengths in XO WebSRG Module")
    print("=" * 80)
    print()

    # Read module
    print(f"Reading module: {os.path.basename(MODULE_PATH)}")
    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Fix MD5 lengths
    print("Truncating MD5 hashes to 32 characters...")
    fixed_content, fixes_applied = fix_md5_lengths(content)

    print(f"  [OK] Fixed {fixes_applied} MD5 hash fields")
    print()

    # Write fixed content
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print("=" * 80)
    print("[OK] MD5 hash lengths fixed!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run validate_function_metadata.py to verify all hashes are 32 chars")
    print("  2. Test module loading: Import-Module ... -Force")

    return 0


if __name__ == '__main__':
    exit(main())
