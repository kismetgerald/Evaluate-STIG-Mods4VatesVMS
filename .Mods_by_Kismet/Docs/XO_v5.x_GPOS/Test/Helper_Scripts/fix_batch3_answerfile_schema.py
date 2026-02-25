#!/usr/bin/env python3
"""Fix Batch 3 answer file entries to include required schema elements.

The Batch 3 entries are missing:
1. <ValidationCode></ValidationCode> before <ValidTrueStatus>
2. <ValidFalseStatus> and <ValidFalseComment> after </ValidTrueComment>
3. Optional attributes (Hostname, Instance, Database, Site, ResultHash) on <Answer>
"""

import re
import sys
import xml.etree.ElementTree as ET

ANSWER_FILE = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Batch 3 VulnIDs that need fixing
BATCH3_VULNS = [
    "V-203625", "V-203626", "V-203627", "V-203628",
    "V-203631", "V-203632", "V-203634",
    "V-203676", "V-203778", "V-263653",
]


def fix_answer_file():
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    fixes = 0

    for vuln_id in BATCH3_VULNS:
        # Find the Vuln block
        vuln_pattern = rf'(<Vuln ID="{re.escape(vuln_id)}">)(.*?)(</Vuln>)'
        match = re.search(vuln_pattern, content, re.DOTALL)

        if not match:
            print(f"WARNING: Could not find {vuln_id}")
            continue

        vuln_block = match.group(0)

        # Fix 1: Add missing attributes to <Answer> tags
        # Change: <Answer Index="N" ExpectedStatus="X">
        # To:     <Answer Index="N" ExpectedStatus="X" Hostname="" Instance="" Database="" Site="" ResultHash="">
        fixed_block = re.sub(
            r'<Answer Index="(\d+)" ExpectedStatus="([^"]+)">',
            r'<Answer Index="\1" ExpectedStatus="\2" Hostname="" Instance="" Database="" Site="" ResultHash="">',
            vuln_block
        )

        # Fix 2: Add <ValidationCode> before <ValidTrueStatus>
        fixed_block = re.sub(
            r'(        )<ValidTrueStatus>',
            r'\1<ValidationCode></ValidationCode>\n\1<ValidTrueStatus>',
            fixed_block
        )

        # Fix 3: Add <ValidFalseStatus> and <ValidFalseComment> before </Answer>
        fixed_block = re.sub(
            r'(</ValidTrueComment>)\s*\n(\s*)(</Answer>)',
            r'\1\n\2<ValidFalseStatus>NR</ValidFalseStatus>\n\2<ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>\n\2\3',
            fixed_block
        )

        if fixed_block != vuln_block:
            content = content.replace(vuln_block, fixed_block)
            fixes += 1
            print(f"Fixed {vuln_id}")
        else:
            print(f"No changes needed for {vuln_id}")

    with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nApplied fixes to {fixes} Vuln entries")

    # Validate XML
    try:
        tree = ET.parse(ANSWER_FILE)
        root = tree.getroot()
        vuln_count = len(root.findall('.//Vuln'))
        print(f"XML Validation: PASSED ({vuln_count} Vuln entries)")
    except ET.ParseError as e:
        print(f"XML Validation: FAILED - {e}")
        sys.exit(1)


if __name__ == '__main__':
    fix_answer_file()
