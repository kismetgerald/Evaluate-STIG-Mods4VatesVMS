#!/usr/bin/env python3
"""
Validate and report discrepancies in XO WebSRG function metadata.

Compares function header metadata against the authoritative XCCDF file:
- Vuln ID
- STIG ID
- Rule ID
- Rule Title
- DiscussMD5, CheckMD5, FixMD5 hashes

Generates a report of all discrepancies for review.

Usage:
    python validate_function_metadata.py
"""

import os
import re
import hashlib
import xml.etree.ElementTree as ET
from collections import defaultdict

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

        # Extract Vuln ID (e.g., "V-206350" from "V-206350")
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


def extract_function_metadata(module_path):
    """
    Extract metadata from all function headers in the module.

    Returns: dict mapping Vuln ID to metadata dict
    """
    print(f"Extracting function metadata: {os.path.basename(module_path)}")

    with open(module_path, 'r', encoding='utf-8') as f:
        content = f.read()

    metadata = {}

    # Pattern to find function declarations and their metadata
    # Allow for optional PSScriptAnalyzer attributes between { and <#
    pattern = r'[Ff]unction\s+(Get-V\d+)\s*\{[^<]*?<#(.*?)#>'

    for match in re.finditer(pattern, content, re.DOTALL):
        function_name = match.group(1)
        header_block = match.group(2)

        # Extract Vuln ID from function name (Get-V264346 -> V-264346)
        vuln_match = re.search(r'Get-V(\d+)', function_name)
        if not vuln_match:
            continue
        vuln_id = f"V-{vuln_match.group(1)}"

        # Extract metadata fields (use [ \t]* for horizontal whitespace only, [^\r\n]* for values)
        vuln_id_line = re.search(r'Vuln ID\s*:[ \t]*([^\r\n]*)', header_block)
        stig_id_line = re.search(r'STIG ID\s*:[ \t]*([^\r\n]*)', header_block)
        rule_id_line = re.search(r'Rule ID\s*:[ \t]*([^\r\n]*)', header_block)
        rule_title_line = re.search(r'Rule Title\s*:[ \t]*([^\r\n]*)', header_block)
        discuss_md5_line = re.search(r'DiscussMD5\s*:\s*([a-f0-9]+)', header_block, re.IGNORECASE)
        check_md5_line = re.search(r'CheckMD5\s*:\s*([a-f0-9]+)', header_block, re.IGNORECASE)
        fix_md5_line = re.search(r'FixMD5\s*:\s*([a-f0-9]+)', header_block, re.IGNORECASE)

        metadata[vuln_id] = {
            'function_name': function_name,
            'vuln_id': vuln_id_line.group(1).strip() if vuln_id_line else '',
            'stig_id': stig_id_line.group(1).strip() if stig_id_line else '',
            'rule_id': rule_id_line.group(1).strip() if rule_id_line else '',
            'rule_title': rule_title_line.group(1) if rule_title_line else '',  # Don't strip - preserve trailing spaces
            'discuss_md5': discuss_md5_line.group(1).strip() if discuss_md5_line else '00000000000000000000000000000000',
            'check_md5': check_md5_line.group(1).strip() if check_md5_line else '00000000000000000000000000000000',
            'fix_md5': fix_md5_line.group(1).strip() if fix_md5_line else '00000000000000000000000000000000'
        }

    print(f"  Found metadata for {len(metadata)} functions")
    return metadata


def compare_metadata(xccdf_meta, func_meta):
    """
    Compare XCCDF metadata against function metadata.

    Returns: list of discrepancy dicts
    """
    print("\nComparing metadata...")

    discrepancies = []
    all_vuln_ids = set(xccdf_meta.keys()) | set(func_meta.keys())

    for vuln_id in sorted(all_vuln_ids):
        xccdf = xccdf_meta.get(vuln_id, {})
        func = func_meta.get(vuln_id, {})

        issues = []

        # Check if Vuln ID exists in both
        if not xccdf:
            issues.append(f"Not found in XCCDF")
        if not func:
            issues.append(f"Not found in module")

        if xccdf and func:
            # Compare each field
            if xccdf.get('stig_id', '') != func.get('stig_id', ''):
                issues.append(f"STIG ID: '{func.get('stig_id')}' != '{xccdf.get('stig_id')}'")
            if xccdf.get('rule_id', '') != func.get('rule_id', ''):
                issues.append(f"Rule ID: '{func.get('rule_id')}' != '{xccdf.get('rule_id')}'")
            if xccdf.get('rule_title', '') != func.get('rule_title', ''):
                issues.append(f"Rule Title mismatch")
            if xccdf.get('discuss_md5', '') != func.get('discuss_md5', ''):
                issues.append(f"DiscussMD5: '{func.get('discuss_md5')}' != '{xccdf.get('discuss_md5')}'")
            if xccdf.get('check_md5', '') != func.get('check_md5', ''):
                issues.append(f"CheckMD5: '{func.get('check_md5')}' != '{xccdf.get('check_md5')}'")
            if xccdf.get('fix_md5', '') != func.get('fix_md5', ''):
                issues.append(f"FixMD5: '{func.get('fix_md5')}' != '{xccdf.get('fix_md5')}'")

        if issues:
            discrepancies.append({
                'vuln_id': vuln_id,
                'function_name': func.get('function_name', 'N/A'),
                'issues': issues,
                'xccdf': xccdf,
                'func': func
            })

    return discrepancies


def generate_report(discrepancies, output_path):
    """Generate detailed report of metadata discrepancies."""
    print(f"\nGenerating report: {os.path.basename(output_path)}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# XO WebSRG Function Metadata Validation Report\n\n")
        f.write(f"**Total Functions Checked:** {len(discrepancies) if discrepancies else 0}\n")
        f.write(f"**Functions with Issues:** {len(discrepancies)}\n\n")

        if not discrepancies:
            f.write("✅ All function metadata matches XCCDF!\n")
            return

        f.write("---\n\n")
        f.write("## Discrepancies by Vuln ID\n\n")

        for disc in discrepancies:
            vuln_id = disc['vuln_id']
            func_name = disc['function_name']
            issues = disc['issues']

            f.write(f"### {vuln_id} ({func_name})\n\n")

            for issue in issues:
                f.write(f"- ❌ {issue}\n")

            f.write("\n")

            # Show correct values from XCCDF
            if disc['xccdf']:
                f.write("**Correct Values (from XCCDF):**\n")
                xccdf = disc['xccdf']
                f.write(f"- STIG ID: `{xccdf.get('stig_id', 'N/A')}`\n")
                f.write(f"- Rule ID: `{xccdf.get('rule_id', 'N/A')}`\n")
                f.write(f"- Rule Title: `{xccdf.get('rule_title', 'N/A')}`\n")
                f.write(f"- DiscussMD5: `{xccdf.get('discuss_md5', 'N/A')}`\n")
                f.write(f"- CheckMD5: `{xccdf.get('check_md5', 'N/A')}`\n")
                f.write(f"- FixMD5: `{xccdf.get('fix_md5', 'N/A')}`\n")

            f.write("\n")

            # Show current values from module
            if disc['func']:
                f.write("**Current Values (in module):**\n")
                func = disc['func']
                f.write(f"- STIG ID: `{func.get('stig_id', 'N/A')}`\n")
                f.write(f"- Rule ID: `{func.get('rule_id', 'N/A')}`\n")
                f.write(f"- Rule Title: `{func.get('rule_title', 'N/A')}`\n")
                f.write(f"- DiscussMD5: `{func.get('discuss_md5', 'N/A')}`\n")
                f.write(f"- CheckMD5: `{func.get('check_md5', 'N/A')}`\n")
                f.write(f"- FixMD5: `{func.get('fix_md5', 'N/A')}`\n")

            f.write("\n---\n\n")

    print(f"  Report written: {len(discrepancies)} discrepancies found")


def main():
    print("=" * 80)
    print("XO WebSRG Function Metadata Validation")
    print("=" * 80)
    print()

    # Parse XCCDF
    xccdf_meta = parse_xccdf(XCCDF_PATH)
    print()

    # Extract function metadata
    func_meta = extract_function_metadata(MODULE_PATH)
    print()

    # Compare
    discrepancies = compare_metadata(xccdf_meta, func_meta)

    # Generate report
    report_path = os.path.join(SCRIPT_DIR, '..', 'Docs', 'METADATA_VALIDATION_REPORT.md')
    generate_report(discrepancies, report_path)

    print()
    print("=" * 80)
    print("Validation Complete")
    print("=" * 80)
    print()
    print(f"Report: {report_path}")
    print(f"Functions with issues: {len(discrepancies)}")

    if discrepancies:
        print("\nNext steps:")
        print("  1. Review METADATA_VALIDATION_REPORT.md")
        print("  2. Run correction script to fix discrepancies")
        print("  3. Re-validate after corrections")
    else:
        print("\n✅ All function metadata is correct!")

    return 0


if __name__ == '__main__':
    exit(main())
