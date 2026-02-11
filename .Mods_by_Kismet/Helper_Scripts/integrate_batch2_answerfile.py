#!/usr/bin/env python3
"""
Session #32 Batch 2 - Answer File Integration Script
Integrates 10 answer file entries (5 functions x 2 indices) into XO_v5.x_WebSRG_AnswerFile.xml
"""

import re
import os

# Configuration
BASE_DIR = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode"
ANSWER_FILE = os.path.join(BASE_DIR, r"Evaluate-STIG\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml")
ENTRIES_FILE = os.path.join(BASE_DIR, "batch2_answer_file_entries.xml")

# Batch 2 Vuln IDs
BATCH2_VULNS = [
    "V-206416",
    "V-206417",
    "V-206418",
    "V-206421",
    "V-206422"
]

def extract_vuln_entry(entries_content, vuln_id):
    """Extract a single Vuln entry from the entries file"""
    # Pattern to match <Vuln ID="V-XXXXXX">...</Vuln>
    pattern = rf'<Vuln ID="{re.escape(vuln_id)}".*?>(.*?)</Vuln>'
    match = re.search(pattern, entries_content, re.DOTALL)

    if not match:
        raise ValueError(f"Vuln entry {vuln_id} not found in entries file")

    return match.group(0)  # Return the full <Vuln> element

def find_stub_entry(answer_content, vuln_id):
    """Find the stub entry for a Vuln ID in the answer file"""
    # Pattern to match stub entry (should be a simple stub with just Index 1)
    pattern = rf'(<Vuln ID="{re.escape(vuln_id)}".*?</Vuln>)'
    match = re.search(pattern, answer_content, re.DOTALL)

    if not match:
        raise ValueError(f"Stub entry {vuln_id} not found in answer file")

    return match.start(), match.end()

def integrate_entry(answer_content, vuln_id, new_entry):
    """Replace stub entry with new entry in answer file"""
    start_pos, end_pos = find_stub_entry(answer_content, vuln_id)

    # Get old entry for reporting
    old_entry = answer_content[start_pos:end_pos]
    old_lines = len(old_entry.split('\n'))
    new_lines = len(new_entry.split('\n'))

    # Replace the entry
    updated_content = answer_content[:start_pos] + new_entry + answer_content[end_pos:]

    print(f"[OK] {vuln_id}: {old_lines} -> {new_lines} lines (+{new_lines - old_lines})")

    return updated_content, old_lines, new_lines

def main():
    print("=" * 70)
    print("Session #32 Batch 2 - Answer File Integration")
    print("=" * 70)
    print()

    # Read answer file
    print(f"Reading answer file: {ANSWER_FILE}")
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        answer_content = f.read()

    original_lines = len(answer_content.split('\n'))
    print(f"Original answer file: {original_lines:,} lines")
    print()

    # Read entries file
    print(f"Reading entries file: {ENTRIES_FILE}")
    with open(ENTRIES_FILE, 'r', encoding='utf-8') as f:
        entries_content = f.read()

    entries_lines = len(entries_content.split('\n'))
    print(f"Entries file: {entries_lines:,} lines")
    print()

    # Integrate each entry
    total_old_lines = 0
    total_new_lines = 0

    print("Integrating answer file entries:")
    print("-" * 70)

    for vuln_id in BATCH2_VULNS:
        try:
            new_entry = extract_vuln_entry(entries_content, vuln_id)
            answer_content, old_lines, new_lines = integrate_entry(answer_content, vuln_id, new_entry)
            total_old_lines += old_lines
            total_new_lines += new_lines
        except Exception as e:
            print(f"[ERROR] {vuln_id}: {e}")
            return 1

    print("-" * 70)
    print(f"Total: {total_old_lines} -> {total_new_lines} lines (+{total_new_lines - total_old_lines})")
    print()

    # Write updated answer file
    print(f"Writing updated answer file...")
    with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
        f.write(answer_content)

    final_lines = len(answer_content.split('\n'))
    print(f"Final answer file: {final_lines:,} lines")
    print()

    print("=" * 70)
    print(f"Integration complete! Answer file updated: {ANSWER_FILE}")
    print("=" * 70)

    return 0

if __name__ == "__main__":
    exit(main())
