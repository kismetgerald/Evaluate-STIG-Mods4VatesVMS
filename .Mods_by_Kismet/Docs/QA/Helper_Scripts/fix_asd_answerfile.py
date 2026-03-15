#!/usr/bin/env python3
"""Fix ASD Answer File -- Phase 1B QA Remediation

Fixes:
1. Add missing 5 attributes to all Answer elements that lack them
2. Remove Index 3 entries from 23 VulnIDs
3. Fix V-222413-416, V-222421: consolidate 3-index -> 2-index (NF/Open)
4. Add missing Index 2 entries for 42 VulnIDs
"""

import re
import sys
from pathlib import Path

ANSWER_FILE = Path(__file__).resolve().parents[3] / "Evaluate-STIG" / "AnswerFiles" / "XO_v5.x_ASD_AnswerFile.xml"

# The 5 VulnIDs with 3-index Open/NA/NF pattern -> consolidate to NF(Idx1)/Open(Idx2)
CONSOLIDATE_3INDEX = {"V-222413", "V-222414", "V-222415", "V-222416", "V-222421"}

# Index 3 VulnIDs with Not_Applicable (just remove Index 3, keep Index 1+2)
REMOVE_INDEX3_NA = {
    "V-222467", "V-222475", "V-222535", "V-222551", "V-222595",
    "V-222644", "V-222646", "V-222648", "V-222649", "V-222650",
    "V-222652", "V-222653", "V-222654", "V-222655", "V-222657",
    "V-222664", "V-222673", "V-265634"
}

# Index 2 templates
INDEX2_OPEN = """      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode />
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>
The automated scan determined this system does not meet the requirement. Review FINDING_DETAILS for specific technical evidence. Implement corrective actions per the STIG Check_Content guidance, then re-scan to verify compliance.
        </ValidTrueComment>
        <ValidFalseStatus />
        <ValidFalseComment />
      </Answer>"""

INDEX2_NF = """      <Answer Index="2" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode />
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>
The automated scan determined this system meets the requirement. The technical evidence in FINDING_DETAILS confirms compliance with the STIG check criteria.
        </ValidTrueComment>
        <ValidFalseStatus />
        <ValidFalseComment />
      </Answer>"""

INDEX2_OPEN_FOR_NA = """      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode />
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>
The automated scan determined this requirement is applicable and the system does not meet it. Review FINDING_DETAILS for specific technical evidence and implement corrective actions per the STIG Check_Content guidance.
        </ValidTrueComment>
        <ValidFalseStatus />
        <ValidFalseComment />
      </Answer>"""


def fix_missing_attributes(text):
    """Add missing attributes to Answer elements that lack them."""
    count = 0

    def add_attrs(match):
        nonlocal count
        tag = match.group(0)
        # Check if all 5 attributes are present
        has_all = all(attr in tag for attr in
                      ['Hostname="', 'Instance="', 'Database="', 'Site="', 'ResultHash="'])
        if has_all:
            return tag

        count += 1
        # Extract existing attributes
        index_match = re.search(r'Index="([^"]*)"', tag)
        status_match = re.search(r'ExpectedStatus="([^"]*)"', tag)
        hostname_match = re.search(r'Hostname="([^"]*)"', tag)
        instance_match = re.search(r'Instance="([^"]*)"', tag)
        database_match = re.search(r'Database="([^"]*)"', tag)
        site_match = re.search(r'Site="([^"]*)"', tag)
        hash_match = re.search(r'ResultHash="([^"]*)"', tag)

        idx = index_match.group(1) if index_match else ""
        status = status_match.group(1) if status_match else ""
        hostname = hostname_match.group(1) if hostname_match else ""
        instance = instance_match.group(1) if instance_match else ""
        database = database_match.group(1) if database_match else ""
        site = site_match.group(1) if site_match else ""
        rhash = hash_match.group(1) if hash_match else ""

        return (f'<Answer Index="{idx}" ExpectedStatus="{status}" '
                f'Hostname="{hostname}" Instance="{instance}" '
                f'Database="{database}" Site="{site}" ResultHash="{rhash}">')

    text = re.sub(r'<Answer\s+[^>]*>', add_attrs, text)
    return text, count


def remove_index3(text):
    """Remove Index 3 entries from all VulnIDs that have them."""
    all_idx3_vulns = CONSOLIDATE_3INDEX | REMOVE_INDEX3_NA
    removed = 0

    for vuln_id in all_idx3_vulns:
        vuln_pattern = rf'(<Vuln ID="{vuln_id}">)(.*?)(</AnswerKey>)'

        def do_remove(match):
            nonlocal removed
            before = match.group(1)
            content = match.group(2)
            closing = match.group(3)
            # Count before removing
            idx3_count = len(re.findall(r'<Answer\s+Index="3"', content))
            if idx3_count > 0:
                removed += idx3_count
                content = re.sub(
                    r'\s*<Answer\s+Index="3"[^>]*>.*?</Answer>',
                    '',
                    content,
                    flags=re.DOTALL
                )
            return before + content + closing

        text = re.sub(vuln_pattern, do_remove, text, flags=re.DOTALL)

    return text, removed


def fix_consolidate_vulns(text):
    """Fix V-222413-416, V-222421: change Index 1 from Open to NotAFinding, Index 2 from NA to Open."""
    fixed = 0

    for vuln_id in CONSOLIDATE_3INDEX:
        vuln_pattern = rf'(<Vuln ID="{vuln_id}">)(.*?)(</Vuln>)'

        def do_fix(match):
            nonlocal fixed
            before = match.group(1)
            content = match.group(2)
            closing = match.group(3)

            # Fix Index 1: Open -> NotAFinding
            content = re.sub(
                r'(<Answer Index="1"[^>]*ExpectedStatus=")Open(")',
                r'\1NotAFinding\2',
                content
            )
            content = re.sub(
                r'(<Answer Index="1".*?<ValidTrueStatus>)Open(</ValidTrueStatus>)',
                r'\1NotAFinding\2',
                content,
                flags=re.DOTALL
            )

            # Fix Index 2: Not_Applicable -> Open
            content = re.sub(
                r'(<Answer Index="2"[^>]*ExpectedStatus=")Not_Applicable(")',
                r'\1Open\2',
                content
            )
            content = re.sub(
                r'(<Answer Index="2".*?<ValidTrueStatus>)Not_Applicable(</ValidTrueStatus>)',
                r'\1Open\2',
                content,
                flags=re.DOTALL
            )

            fixed += 1
            return before + content + closing

        text = re.sub(vuln_pattern, do_fix, text, flags=re.DOTALL)

    return text, fixed


def add_missing_index2(text):
    """Add Index 2 entries for VulnIDs that only have Index 1."""
    added = 0

    # Find all Vuln blocks
    vuln_pattern = r'(<Vuln ID="(V-\d+)">)(.*?)(</AnswerKey>\s*</Vuln>)'

    def maybe_add_idx2(match):
        nonlocal added
        vuln_open = match.group(1)
        vuln_id = match.group(2)
        content = match.group(3)
        closing = match.group(4)

        # Count Answer entries
        answer_count = len(re.findall(r'<Answer\s+Index=', content))
        if answer_count >= 2:
            return match.group(0)

        if answer_count == 1:
            # Determine Index 1 status
            idx1_status_match = re.search(r'<Answer\s+Index="1"[^>]*ExpectedStatus="([^"]*)"', content)
            if not idx1_status_match:
                return match.group(0)

            idx1_status = idx1_status_match.group(1)

            # Determine Index 2 (opposite)
            if idx1_status in ("NotAFinding",):
                idx2 = INDEX2_OPEN
            elif idx1_status in ("Open",):
                idx2 = INDEX2_NF
            elif idx1_status in ("Not_Applicable",):
                idx2 = INDEX2_OPEN_FOR_NA
            elif idx1_status in ("Not_Reviewed",):
                # Not_Reviewed single entries get Index 2 = Open
                idx2 = INDEX2_OPEN
            else:
                return match.group(0)

            added += 1
            # Insert before </AnswerKey>
            return vuln_open + content + idx2 + "\n    " + closing

        return match.group(0)

    text = re.sub(vuln_pattern, maybe_add_idx2, text, flags=re.DOTALL)
    return text, added


def verify(text):
    """Verify all VulnIDs have exactly 2 Answer entries and proper attributes."""
    vuln_blocks = re.findall(r'<Vuln ID="(V-\d+)">(.*?)</Vuln>', text, re.DOTALL)

    single = []
    triple = []
    missing_attrs = []

    for vid, block in vuln_blocks:
        idx_count = len(re.findall(r'<Answer\s+Index=', block))
        if idx_count == 1:
            single.append(vid)
        elif idx_count >= 3:
            triple.append(vid)

        # Check attributes
        for answer_match in re.finditer(r'<Answer\s+([^>]*)>', block):
            attrs = answer_match.group(1)
            for attr in ['Hostname="', 'Instance="', 'Database="', 'Site="', 'ResultHash="']:
                if attr not in attrs:
                    missing_attrs.append(vid)
                    break

    return vuln_blocks, single, triple, missing_attrs


def main():
    if not ANSWER_FILE.exists():
        print(f"ERROR: Answer file not found: {ANSWER_FILE}")
        sys.exit(1)

    print(f"Reading: {ANSWER_FILE}")
    original = ANSWER_FILE.read_text(encoding='utf-8')
    text = original

    # Step 1: Fix missing attributes
    text, attr_count = fix_missing_attributes(text)
    print(f"Step 1: Added missing attributes to {attr_count} Answer elements")

    # Step 2: Fix V-222413-416, V-222421 (consolidate statuses before removing Index 3)
    text, consol_count = fix_consolidate_vulns(text)
    print(f"Step 2: Consolidated {consol_count} VulnIDs (Open/NA/NF -> NF/Open)")

    # Step 3: Remove all Index 3 entries
    text, removed = remove_index3(text)
    print(f"Step 3: Removed {removed} Index 3 entries")

    # Step 4: Add missing Index 2 entries
    text, added = add_missing_index2(text)
    print(f"Step 4: Added Index 2 to {added} VulnIDs")

    # Verify
    vuln_blocks, single, triple, missing_attrs = verify(text)
    print(f"\nVerification:")
    print(f"  Total VulnIDs: {len(vuln_blocks)}")
    print(f"  VulnIDs with 1 Answer: {len(single)} {single[:10] if single else ''}")
    print(f"  VulnIDs with 3+ Answers: {len(triple)} {triple[:10] if triple else ''}")
    print(f"  VulnIDs with missing attrs: {len(missing_attrs)} {missing_attrs[:10] if missing_attrs else ''}")

    # Write
    if text != original:
        ANSWER_FILE.write_text(text, encoding='utf-8')
        print(f"\nWrote: {ANSWER_FILE}")
        print(f"  Original size: {len(original):,} chars")
        print(f"  New size: {len(text):,} chars")
    else:
        print("\nNo changes needed.")


if __name__ == "__main__":
    main()
