#!/usr/bin/env python3
"""
Fix the remaining 12 functions with malformed STIG ID and missing Rule ID.

These functions have PSScriptAnalyzer attributes and malformed metadata blocks
where STIG ID value is on a separate line and Rule ID is missing.

Usage:
    python fix_remaining_12.py
"""

import os
import re
from datetime import datetime
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Modules', 'Scan-XO_WebSRG_Checks', 'Scan-XO_WebSRG_Checks.psm1')

# Correct values from XCCDF
CORRECTIONS = {
    'V-264337': {'stig_id': 'SRG-APP-000700-WSR-000100', 'rule_id': 'SV-264337r984356_rule'},
    'V-264339': {'stig_id': 'SRG-APP-000745-WSR-000120', 'rule_id': 'SV-264339r984362_rule'},
    'V-264349': {'stig_id': 'SRG-APP-000850-WSR-000230', 'rule_id': 'SV-264349r984392_rule'},
    'V-264353': {'stig_id': 'SRG-APP-000870-WSR-000270', 'rule_id': 'SV-264353r984404_rule'},
    'V-264355': {'stig_id': 'SRG-APP-000880-WSR-000290', 'rule_id': 'SV-264355r984410_rule'},
    'V-264356': {'stig_id': 'SRG-APP-000910-WSR-000300', 'rule_id': 'SV-264356r984413_rule'},
    'V-264361': {'stig_id': 'SRG-APP-000219-WSR-000191', 'rule_id': 'SV-264361r1067566_rule'},
    'V-264362': {'stig_id': 'SRG-APP-000439-WSR-000192', 'rule_id': 'SV-264362r984431_rule'},
    'V-264363': {'stig_id': 'SRG-APP-000439-WSR-000193', 'rule_id': 'SV-264363r984434_rule'},
    'V-264364': {'stig_id': 'SRG-APP-000251-WSR-000194', 'rule_id': 'SV-264364r984437_rule'},
    'V-264365': {'stig_id': 'SRG-APP-000251-WSR-000195', 'rule_id': 'SV-264365r984440_rule'},
    'V-264366': {'stig_id': 'SRG-APP-000439-WSR-000196', 'rule_id': 'SV-264366r984443_rule'},
}


def create_backup(filepath):
    """Create timestamped backup."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def fix_malformed_metadata(content):
    """Fix malformed metadata blocks for the 12 functions."""
    fixes_applied = 0

    for vuln_id, correct in CORRECTIONS.items():
        vuln_num = vuln_id.replace('V-', '')

        # Pattern to find the malformed metadata block
        # Matches: "STIG ID    : \n        SRG-APP-xxx"
        pattern = rf'(Vuln ID\s*:\s*{re.escape(vuln_id)}\s*\n\s*STIG ID\s*:\s*\n\s*)({re.escape(correct["stig_id"])})'

        # Replacement: "Vuln ID    : V-xxxxx\n        STIG ID    : SRG-APP-xxx\n        Rule ID    : SV-xxxxx"
        def replacer(match):
            indent = '        '  # 8 spaces
            return f'Vuln ID    : {vuln_id}\n{indent}STIG ID    : {correct["stig_id"]}\n{indent}Rule ID    : {correct["rule_id"]}\n{indent}'

        new_content = re.sub(pattern, replacer, content)

        if new_content != content:
            fixes_applied += 1
            content = new_content
            print(f"  [OK] Fixed {vuln_id}")

    return content, fixes_applied


def main():
    print("=" * 80)
    print("Fix Remaining 12 Functions with Malformed Metadata")
    print("=" * 80)
    print()

    # Read module
    print(f"Reading module: {os.path.basename(MODULE_PATH)}")
    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Fix malformed metadata
    print("Fixing malformed metadata blocks...")
    fixed_content, fixes_applied = fix_malformed_metadata(content)

    print()
    print(f"Total fixes applied: {fixes_applied}/12")
    print()

    # Write fixed content
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print("=" * 80)
    print("[OK] Malformed metadata fixed!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run validate_function_metadata.py to verify all 126 functions")
    print("  2. Test module loading: Import-Module ... -Force")

    return 0


if __name__ == '__main__':
    exit(main())
