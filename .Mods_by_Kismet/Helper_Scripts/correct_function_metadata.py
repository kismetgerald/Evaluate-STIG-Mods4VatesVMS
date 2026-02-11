#!/usr/bin/env python3
"""
Correct function metadata in XO WebSRG module based on XCCDF validation.

Updates STIG ID, Rule ID, Rule Title, and MD5 hashes for all 126 functions
to match the authoritative XCCDF file.

Usage:
    python correct_function_metadata.py
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


def calculate_md5(text):
    """Calculate MD5 hash of text."""
    if not text:
        return "00000000000000000000000000000000"
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def parse_xccdf(xccdf_path):
    """
    Parse XCCDF file and extract metadata for each Vuln ID.

    Returns: dict mapping Vuln ID to metadata dict
    """
    print(f"Parsing XCCDF: {os.path.basename(xccdf_path)}")

    tree = ET.parse(xccdf_path)
    root = tree.getroot()

    # Define namespaces (XCCDF 1.1 for Web Server SRG V4R4)
    ns = {
        'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
        'dc': 'http://purl.org/dc/elements/1.1/',
        'xhtml': 'http://www.w3.org/1999/xhtml'
    }

    metadata = {}

    # Find all Group elements (each contains a Vuln ID)
    for group in root.findall('.//xccdf:Group', ns):
        group_id = group.get('id')

        # Extract Vuln ID (e.g., "V-206350")
        if not group_id or not group_id.startswith('V-'):
            continue

        vuln_id = group_id

        # Find the Rule element within this Group
        rule = group.find('.//xccdf:Rule', ns)
        if rule is None:
            continue

        rule_id = rule.get('id', '')
        rule_severity = rule.get('severity', '')

        # Extract Rule Title
        title_elem = rule.find('xccdf:title', ns)
        rule_title = title_elem.text if title_elem is not None else ''

        # Extract STIG ID from version element (SRG-APP-xxx format)
        version_elem = rule.find('xccdf:version', ns)
        stig_id = version_elem.text if version_elem is not None else ''

        # Extract description, check, and fix content for MD5 calculation
        description_elem = rule.find('xccdf:description', ns)
        description = description_elem.text if description_elem is not None else ''

        check_elem = rule.find('.//xccdf:check-content', ns)
        check_content = check_elem.text if check_elem is not None else ''

        fixtext_elem = rule.find('.//xccdf:fixtext', ns)
        fix_content = fixtext_elem.text if fixtext_elem is not None else ''

        # Calculate MD5 hashes
        discuss_md5 = calculate_md5(description)
        check_md5 = calculate_md5(check_content)
        fix_md5 = calculate_md5(fix_content)

        metadata[vuln_id] = {
            'vuln_id': vuln_id,
            'stig_id': stig_id,
            'rule_id': rule_id,
            'rule_title': rule_title,
            'severity': rule_severity,
            'discuss_md5': discuss_md5,
            'check_md5': check_md5,
            'fix_md5': fix_md5
        }

    print(f"  Found metadata for {len(metadata)} Vuln IDs")
    return metadata


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def correct_function_metadata(module_path, xccdf_meta):
    """
    Correct function metadata in module file.

    Updates STIG ID, Rule ID, Rule Title, and MD5 hashes for each function.
    """
    print(f"\nCorrecting function metadata: {os.path.basename(module_path)}")

    with open(module_path, 'r', encoding='utf-8') as f:
        content = f.read()

    corrections_made = 0

    # Pattern to find function declarations and their metadata blocks
    # Allow for optional PSScriptAnalyzer attributes between { and <#
    pattern = r'([Ff]unction\s+(Get-V\d+)\s*\{[^<]*?<#)(.*?)(#>)'

    def replace_metadata(match):
        nonlocal corrections_made

        function_declaration = match.group(1)  # "Function Get-V206350 {\n    <#"
        function_name = match.group(2)          # "Get-V206350"
        metadata_block = match.group(3)         # Everything between <# and #>
        closing = match.group(4)                # "#>"

        # Extract Vuln ID from function name
        vuln_match = re.search(r'Get-V(\d+)', function_name)
        if not vuln_match:
            return match.group(0)  # No change

        vuln_id = f"V-{vuln_match.group(1)}"

        # Get correct metadata from XCCDF
        if vuln_id not in xccdf_meta:
            print(f"  [WARNING] {vuln_id} not found in XCCDF")
            return match.group(0)  # No change

        correct = xccdf_meta[vuln_id]

        # Update STIG ID
        metadata_block = re.sub(
            r'(STIG ID\s*:\s*)([^\r\n]+)',
            lambda m: m.group(1) + correct["stig_id"],
            metadata_block
        )

        # Update Rule ID
        metadata_block = re.sub(
            r'(Rule ID\s*:\s*)([^\r\n]+)',
            lambda m: m.group(1) + correct["rule_id"],
            metadata_block
        )

        # Update Rule Title
        metadata_block = re.sub(
            r'(Rule Title\s*:\s*)([^\r\n]+)',
            lambda m: m.group(1) + correct["rule_title"],
            metadata_block
        )

        # Update DiscussMD5
        metadata_block = re.sub(
            r'(DiscussMD5\s*:\s*)([a-fA-F0-9]+)',
            lambda m: m.group(1) + correct["discuss_md5"],
            metadata_block,
            flags=re.IGNORECASE
        )

        # Update CheckMD5
        metadata_block = re.sub(
            r'(CheckMD5\s*:\s*)([a-fA-F0-9]+)',
            lambda m: m.group(1) + correct["check_md5"],
            metadata_block,
            flags=re.IGNORECASE
        )

        # Update FixMD5
        metadata_block = re.sub(
            r'(FixMD5\s*:\s*)([a-fA-F0-9]+)',
            lambda m: m.group(1) + correct["fix_md5"],
            metadata_block,
            flags=re.IGNORECASE
        )

        corrections_made += 1

        return function_declaration + metadata_block + closing

    # Apply corrections
    corrected_content = re.sub(pattern, replace_metadata, content, flags=re.DOTALL)

    print(f"  [OK] Corrected {corrections_made} functions")

    return corrected_content


def main():
    print("=" * 80)
    print("XO WebSRG Function Metadata Correction")
    print("=" * 80)
    print()

    # Parse XCCDF
    xccdf_meta = parse_xccdf(XCCDF_PATH)
    print()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Correct function metadata
    corrected_content = correct_function_metadata(MODULE_PATH, xccdf_meta)

    # Write corrected module
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(corrected_content)

    print()
    print("=" * 80)
    print("[OK] Module metadata correction complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run validate_function_metadata.py to verify corrections")
    print("  2. Test module loading: Import-Module ... -Force")
    print("  3. Run Test115 or Test116 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
