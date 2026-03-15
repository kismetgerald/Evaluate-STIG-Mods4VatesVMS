#!/usr/bin/env python3
"""Fix WebSRG Answer File — Phase 1A QA Remediation

Fixes:
1. Normalize ExpectedStatus: NF→NotAFinding, O→Open, NA→Not_Applicable
2. Normalize ValidTrueStatus/ValidFalseStatus to match
3. Add missing Index 2 entries for 11 VulnIDs
4. Remove extra Index 3 entries from V-206389, V-264357
5. Fix V-264357 Index 1 from Not_Reviewed to NotAFinding
6. Fix empty ValidTrueStatus/ValidFalseStatus in V-206352, V-206353, V-264360, V-264361
"""

import re
import sys
import os
import copy
from pathlib import Path

ANSWER_FILE = Path(__file__).resolve().parents[3] / "Evaluate-STIG" / "AnswerFiles" / "XO_v5.x_WebSRG_AnswerFile.xml"

# VulnIDs missing Index 2, with their Index 1 ExpectedStatus (after normalization)
MISSING_INDEX2 = {
    "V-206351": "NotAFinding",   # Idx1=NF → needs Idx2=Open
    "V-206352": "NotAFinding",   # Idx1=NF → needs Idx2=Open (also fix empty statuses)
    "V-206353": "NotAFinding",   # Idx1=NF → needs Idx2=Open (also fix empty statuses)
    "V-206390": "Open",          # Idx1=O → needs Idx2=NotAFinding (reversed pattern)
    "V-206399": "NotAFinding",   # Idx1=NF → needs Idx2=Open
    "V-206431": "Open",          # Idx1=O → needs Idx2=NotAFinding (reversed pattern)
    "V-206434": "NotAFinding",   # Idx1=NF → needs Idx2=Open
    "V-264348": "Open",          # Idx1=Open → needs Idx2=NotAFinding
    "V-264360": "NotAFinding",   # Idx1=NF → needs Idx2=Open (also fix empty statuses)
    "V-264361": "NotAFinding",   # Idx1=NF → needs Idx2=Open (also fix empty statuses)
    "V-279029": "NotAFinding",   # Idx1=NF → needs Idx2=Open
}

# Index 2 templates — the "opposite" status entry
INDEX2_TEMPLATE_OPEN = """      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <!--Index 2: Open status — system does not meet this requirement-->
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>The automated scan determined this system does not meet the requirement. Review FINDING_DETAILS for specific technical evidence. Implement corrective actions per the STIG Check_Content guidance, then re-scan to verify compliance.</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>Automated scan returned Open but answer file validation did not match. Manual review required.</ValidFalseComment>
      </Answer>"""

INDEX2_TEMPLATE_NF = """      <Answer Index="2" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <!--Index 2: NotAFinding status — system meets this requirement-->
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>The automated scan determined this system meets the requirement. The technical evidence in FINDING_DETAILS confirms compliance with the STIG check criteria.</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>Automated scan returned NotAFinding but answer file validation did not match. Manual review required.</ValidFalseComment>
      </Answer>"""


def normalize_status(text):
    """Normalize ExpectedStatus, ValidTrueStatus, ValidFalseStatus values."""
    # ExpectedStatus attribute normalization
    text = re.sub(r'ExpectedStatus="NF"', 'ExpectedStatus="NotAFinding"', text)
    text = re.sub(r'ExpectedStatus="O"', 'ExpectedStatus="Open"', text)
    text = re.sub(r'ExpectedStatus="NA"', 'ExpectedStatus="Not_Applicable"', text)

    # ValidTrueStatus element normalization
    text = re.sub(r'<ValidTrueStatus>NF</ValidTrueStatus>', '<ValidTrueStatus>NotAFinding</ValidTrueStatus>', text)
    text = re.sub(r'<ValidTrueStatus>O</ValidTrueStatus>', '<ValidTrueStatus>Open</ValidTrueStatus>', text)
    text = re.sub(r'<ValidTrueStatus>NA</ValidTrueStatus>', '<ValidTrueStatus>Not_Applicable</ValidTrueStatus>', text)

    # ValidFalseStatus element normalization (NR stays as NR, but fix shorthand)
    text = re.sub(r'<ValidFalseStatus>NF</ValidFalseStatus>', '<ValidFalseStatus>NotAFinding</ValidFalseStatus>', text)
    text = re.sub(r'<ValidFalseStatus>O</ValidFalseStatus>', '<ValidFalseStatus>Open</ValidFalseStatus>', text)
    text = re.sub(r'<ValidFalseStatus>NA</ValidFalseStatus>', '<ValidFalseStatus>Not_Applicable</ValidFalseStatus>', text)

    return text


def fix_empty_statuses(text):
    """Fix entries with empty ValidTrueStatus/ValidFalseStatus.

    For VulnIDs with ExpectedStatus="NotAFinding", fill in:
    - ValidTrueStatus = NotAFinding
    - ValidFalseStatus = NR
    """
    # Pattern: Answer with NotAFinding and empty ValidTrueStatus
    # We need to be careful — only fix where they're truly empty
    # Match the specific pattern of empty status within an Answer block

    def fix_answer_block(match):
        block = match.group(0)
        # Only fix if this is an Index 1 with NotAFinding and empty statuses
        if 'ExpectedStatus="NotAFinding"' in block:
            block = block.replace(
                '<ValidTrueStatus></ValidTrueStatus>',
                '<ValidTrueStatus>NotAFinding</ValidTrueStatus>'
            )
            # Fix empty ValidFalseStatus — set to NR (standard pattern)
            block = block.replace(
                '<ValidFalseStatus></ValidFalseStatus>',
                '<ValidFalseStatus>NR</ValidFalseStatus>'
            )
            # Fix empty ValidFalseComment
            if '<ValidFalseComment></ValidFalseComment>' in block:
                block = block.replace(
                    '<ValidFalseComment></ValidFalseComment>',
                    '<ValidFalseComment>Automated scan returned NotAFinding but answer file validation did not match. Manual review required.</ValidFalseComment>'
                )
        return block

    # Match each <Answer ...>...</Answer> block
    text = re.sub(
        r'<Answer\s+Index="1"[^>]*>.*?</Answer>',
        fix_answer_block,
        text,
        flags=re.DOTALL
    )
    return text


def add_missing_index2(text):
    """Add Index 2 entries for VulnIDs that only have Index 1."""
    for vuln_id, idx1_status in MISSING_INDEX2.items():
        # Determine what Index 2 should be (opposite of Index 1)
        if idx1_status == "NotAFinding":
            idx2_template = INDEX2_TEMPLATE_OPEN
        else:  # Open
            idx2_template = INDEX2_TEMPLATE_NF

        # Find the closing </Answer> tag for the last Answer in this VulnID's AnswerKey
        # Pattern: find the Vuln block for this ID, then insert Index 2 before </AnswerKey>
        pattern = rf'(<Vuln ID="{vuln_id}">.*?)(</AnswerKey>)'

        def add_index2(match):
            before = match.group(1)
            closing = match.group(2)
            # Only add if Index 2 doesn't already exist
            if 'Index="2"' in before:
                return match.group(0)
            return before + idx2_template + "\n    " + closing

        text = re.sub(pattern, add_index2, text, flags=re.DOTALL)

    return text


def remove_extra_index3(text):
    """Remove Index 3 entries from V-206389 and V-264357."""
    for vuln_id in ["V-206389", "V-264357"]:
        # Find the Vuln block and remove Index 3 Answer
        pattern = rf'(<Vuln ID="{vuln_id}">.*?)'
        vuln_pattern = rf'(<Vuln ID="{vuln_id}">)(.*?)(</AnswerKey>)'

        def remove_idx3(match):
            before = match.group(1)
            content = match.group(2)
            closing = match.group(3)
            # Remove Index="3" Answer block
            content = re.sub(
                r'\s*<Answer\s+Index="3"[^>]*>.*?</Answer>',
                '',
                content,
                flags=re.DOTALL
            )
            return before + content + closing

        text = re.sub(vuln_pattern, remove_idx3, text, flags=re.DOTALL)

    return text


def fix_v264357_index1(text):
    """Fix V-264357 Index 1 from Not_Reviewed to NotAFinding.

    V-264357 currently has:
    - Index 1: Not_Reviewed (wrong — should be NotAFinding for crypto key safeguards)
    - Index 2: Open
    - Index 3: NotAFinding (will be removed)

    After fix: Index 1=NotAFinding, Index 2=Open
    """
    # Find V-264357's Index 1 and change Not_Reviewed to NotAFinding
    pattern = r'(<Vuln ID="V-264357">.*?<Answer Index="1"[^>]*ExpectedStatus=")Not_Reviewed(")'
    text = re.sub(pattern, r'\1NotAFinding\2', text, flags=re.DOTALL)

    # Also fix the ValidTrueStatus inside that block
    # This is trickier — need to find it within the V-264357 context
    vuln_pattern = r'(<Vuln ID="V-264357">.*?<Answer Index="1".*?<ValidTrueStatus>)Not_Reviewed(</ValidTrueStatus>)'
    text = re.sub(vuln_pattern, r'\1NotAFinding\2', text, flags=re.DOTALL)

    return text


def main():
    if not ANSWER_FILE.exists():
        print(f"ERROR: Answer file not found: {ANSWER_FILE}")
        sys.exit(1)

    print(f"Reading: {ANSWER_FILE}")
    original = ANSWER_FILE.read_text(encoding='utf-8')
    text = original

    # Step 1: Normalize status values (NF→NotAFinding, O→Open, etc.)
    text = normalize_status(text)
    nf_count = original.count('ExpectedStatus="NF"')
    o_count = original.count('ExpectedStatus="O"')
    na_count = original.count('ExpectedStatus="NA"')
    print(f"Step 1: Normalized {nf_count} NF + {o_count} O + {na_count} NA ExpectedStatus values")

    # Step 2: Fix V-264357 Index 1 (Not_Reviewed → NotAFinding) BEFORE adding Index 2
    text = fix_v264357_index1(text)
    print("Step 2: Fixed V-264357 Index 1: Not_Reviewed -> NotAFinding")

    # Step 3: Fix empty ValidTrueStatus/ValidFalseStatus
    text = fix_empty_statuses(text)
    print("Step 3: Fixed empty ValidTrueStatus/ValidFalseStatus entries")

    # Step 4: Remove extra Index 3 entries
    text = remove_extra_index3(text)
    print("Step 4: Removed Index 3 from V-206389, V-264357")

    # Step 5: Add missing Index 2 entries
    text = add_missing_index2(text)
    added = sum(1 for vid in MISSING_INDEX2 if f'<Vuln ID="{vid}">' in text)
    print(f"Step 5: Added Index 2 to {added} VulnIDs")

    # Verify
    # Count VulnIDs with only 1 Answer
    vuln_blocks = re.findall(r'<Vuln ID="(V-\d+)">(.*?)</Vuln>', text, re.DOTALL)
    single_idx = []
    triple_idx = []
    for vid, block in vuln_blocks:
        idx_count = len(re.findall(r'<Answer\s+Index=', block))
        if idx_count == 1:
            single_idx.append(vid)
        elif idx_count >= 3:
            triple_idx.append(vid)

    print(f"\nVerification:")
    print(f"  Total VulnIDs: {len(vuln_blocks)}")
    print(f"  VulnIDs with 1 Answer: {len(single_idx)} {single_idx if single_idx else ''}")
    print(f"  VulnIDs with 3+ Answers: {len(triple_idx)} {triple_idx if triple_idx else ''}")

    # Check for remaining shorthand statuses
    remaining_nf = len(re.findall(r'ExpectedStatus="NF"', text))
    remaining_o = re.findall(r'ExpectedStatus="O"', text)
    # Filter out "Open" matches (ExpectedStatus="Open" shouldn't be caught)
    remaining_o_count = len([m for m in re.finditer(r'ExpectedStatus="O"', text)
                            if text[m.end():m.end()+3] != 'pen'])
    print(f"  Remaining shorthand NF: {remaining_nf}")
    print(f"  Remaining shorthand O: {remaining_o_count}")

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
