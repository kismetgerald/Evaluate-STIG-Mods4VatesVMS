#!/usr/bin/env python3
"""
Rebuild metadata blocks for 37 functions with non-standard or missing metadata.

This script completely replaces the <#...#> comment block for functions that:
1. Have non-standard metadata structure
2. Are missing required fields
3. Have non-hex placeholder MD5 values

Usage:
    python rebuild_metadata_for_37.py
"""

import os
import re
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import shutil

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Modules', 'Scan-XO_WebSRG_Checks', 'Scan-XO_WebSRG_Checks.psm1')
XCCDF_PATH = os.path.join(PROJECT_ROOT, 'StigContent', 'U_Web_Server_SRG_V4R4_Manual-xccdf.xml')

# 37 problem Vuln IDs that need metadata rebuild
PROBLEM_VULNS = [
    'V-206378', 'V-206415', 'V-206416', 'V-206417', 'V-206418',
    'V-264337', 'V-264338', 'V-264339', 'V-264340', 'V-264341',
    'V-264342', 'V-264343', 'V-264344', 'V-264345', 'V-264346',
    'V-264347', 'V-264348', 'V-264349', 'V-264350', 'V-264351',
    'V-264352', 'V-264353', 'V-264354', 'V-264355', 'V-264356',
    'V-264357', 'V-264358', 'V-264359', 'V-264360', 'V-264361',
    'V-264362', 'V-264363', 'V-264364', 'V-264365', 'V-264366',
    'V-279028', 'V-279029'
]


def calculate_md5(text):
    """Calculate MD5 hash of text."""
    if not text:
        return "00000000000000000000000000000000"
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def parse_xccdf(xccdf_path):
    """Parse XCCDF and extract metadata."""
    print(f"Parsing XCCDF: {os.path.basename(xccdf_path)}")

    tree = ET.parse(xccdf_path)
    root = tree.getroot()

    ns = {
        'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
        'dc': 'http://purl.org/dc/elements/1.1/',
        'xhtml': 'http://www.w3.org/1999/xhtml'
    }

    metadata = {}

    for group in root.findall('.//xccdf:Group', ns):
        group_id = group.get('id')
        if not group_id or not group_id.startswith('V-'):
            continue

        vuln_id = group_id
        rule = group.find('.//xccdf:Rule', ns)
        if rule is None:
            continue

        rule_id = rule.get('id', '')
        title_elem = rule.find('xccdf:title', ns)
        rule_title = title_elem.text if title_elem is not None else ''

        # Extract STIG ID from version element (SRG-APP-xxx format)
        version_elem = rule.find('xccdf:version', ns)
        stig_id = version_elem.text if version_elem is not None else ''

        description_elem = rule.find('xccdf:description', ns)
        description = description_elem.text if description_elem is not None else ''

        check_elem = rule.find('.//xccdf:check-content', ns)
        check_content = check_elem.text if check_elem is not None else ''

        fixtext_elem = rule.find('.//xccdf:fixtext', ns)
        fix_content = fixtext_elem.text if fixtext_elem is not None else ''

        metadata[vuln_id] = {
            'vuln_id': vuln_id,
            'stig_id': stig_id,
            'rule_id': rule_id,
            'rule_title': rule_title,
            'discuss_md5': calculate_md5(description),
            'check_md5': calculate_md5(check_content),
            'fix_md5': calculate_md5(fix_content)
        }

    print(f"  Found metadata for {len(metadata)} Vuln IDs")
    return metadata


def create_backup(filepath):
    """Create timestamped backup."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def rebuild_metadata_blocks(module_path, xccdf_meta):
    """Rebuild metadata blocks for problem functions."""
    print(f"\nRebuilding metadata blocks: {os.path.basename(module_path)}")

    with open(module_path, 'r', encoding='utf-8') as f:
        content = f.read()

    rebuilds = 0

    # Pattern: Find entire function including metadata block
    # Capture: function declaration, metadata block, rest of function
    pattern = r'([Ff]unction\s+(Get-V\d+)\s*\{)\s*<#.*?#>'

    def rebuild_block(match):
        nonlocal rebuilds

        func_decl = match.group(1)  # "Function Get-V206378 {"
        func_name = match.group(2)   # "Get-V206378"

        # Extract Vuln ID
        vuln_match = re.search(r'Get-V(\d+)', func_name)
        if not vuln_match:
            return match.group(0)

        vuln_id = f"V-{vuln_match.group(1)}"

        # Only process problem functions
        if vuln_id not in PROBLEM_VULNS:
            return match.group(0)

        # Get correct metadata from XCCDF
        if vuln_id not in xccdf_meta:
            print(f"  [WARNING] {vuln_id} not found in XCCDF")
            return match.group(0)

        meta = xccdf_meta[vuln_id]

        # Build standard metadata block
        new_block = f"""{func_decl}
    <#
    .DESCRIPTION
        Vuln ID    : {meta['vuln_id']}
        STIG ID    : {meta['stig_id']}
        Rule ID    : {meta['rule_id']}
        Rule Title : {meta['rule_title']}
        DiscussMD5 : {meta['discuss_md5']}
        CheckMD5   : {meta['check_md5']}
        FixMD5     : {meta['fix_md5']}
    #>"""

        rebuilds += 1
        return new_block

    # Apply rebuilds
    corrected_content = re.sub(pattern, rebuild_block, content, flags=re.DOTALL)

    print(f"  [OK] Rebuilt {rebuilds} function metadata blocks")

    return corrected_content


def main():
    print("=" * 80)
    print("XO WebSRG Metadata Rebuild (37 Functions)")
    print("=" * 80)
    print()

    # Parse XCCDF
    xccdf_meta = parse_xccdf(XCCDF_PATH)
    print()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Rebuild metadata blocks
    corrected_content = rebuild_metadata_blocks(MODULE_PATH, xccdf_meta)

    # Write corrected module
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(corrected_content)

    print()
    print("=" * 80)
    print("[OK] Metadata rebuild complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run validate_function_metadata.py to verify all 126 functions")
    print("  2. Test module loading: Import-Module ... -Force")
    print("  3. Run Test115 or Test116 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
