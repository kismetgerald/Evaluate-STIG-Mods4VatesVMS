#!/usr/bin/env python3
"""integrate_answer_file.py - Integrate Session #32 Batch 1 answer file entries"""

import os
import re

# Paths
PROJECT_ROOT = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode"
ANSWER_FILE = os.path.join(PROJECT_ROOT, "Evaluate-STIG", "AnswerFiles", "XO_v5.x_WebSRG_AnswerFile.xml")
ENTRIES_FILE = os.path.join(PROJECT_ROOT, "answer_file_entries_session32_batch1.xml")
BACKUP_FILE = os.path.join(PROJECT_ROOT, "Evaluate-STIG", "AnswerFiles", "XO_v5.x_WebSRG_AnswerFile_backup_session32.xml")

# Entry boundaries from generated file
ENTRIES = [
    {"vuln_id": "V-206425", "start": 5, "end": 116},
    {"vuln_id": "V-206426", "start": 117, "end": 262},
    {"vuln_id": "V-264341", "start": 263, "end": 440},
    {"vuln_id": "V-264358", "start": 441, "end": 659},
    {"vuln_id": "V-264359", "start": 660, "end": 790},
]

def main():
    print("=" * 70)
    print("Session #32 Batch 1 Answer File Integration")
    print("=" * 70)
    print()

    # Step 1: Verify files
    print("[1/6] Verifying files...")
    if not os.path.exists(ANSWER_FILE):
        print(f"ERROR: Answer file not found: {ANSWER_FILE}")
        return
    if not os.path.exists(ENTRIES_FILE):
        print(f"ERROR: Entries file not found: {ENTRIES_FILE}")
        return
    print("   [OK] All files found")
    print()

    # Step 2: Create backup
    print("[2/6] Creating backup...")
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        original_content = f.read()
    with open(BACKUP_FILE, 'w', encoding='utf-8') as f:
        f.write(original_content)
    print(f"   [OK] Backup created: {BACKUP_FILE}")
    print()

    # Step 3: Read entries file
    print("[3/6] Reading new entries...")
    with open(ENTRIES_FILE, 'r', encoding='utf-8') as f:
        entries_lines = f.readlines()

    # Extract each entry
    new_entries = {}
    for entry in ENTRIES:
        vuln_id = entry["vuln_id"]
        start = entry["start"] - 1  # Convert to 0-indexed
        end = entry["end"]
        entry_lines = entries_lines[start:end]
        new_entries[vuln_id] = ''.join(entry_lines)
        print(f"   [OK] Read {vuln_id}: {len(entry_lines)} lines")
    print()

    # Step 4: Replace stubs in answer file
    print("[4/6] Replacing stubs...")
    updated_content = original_content

    for entry in ENTRIES:
        vuln_id = entry["vuln_id"]
        new_entry = new_entries[vuln_id]

        print(f"   Processing {vuln_id}...")

        # Pattern to match the entire Vuln block (from <Vuln ID="..." to </Vuln>)
        pattern = rf'(<Vuln ID="{vuln_id}">.*?</Vuln>)'
        match = re.search(pattern, updated_content, re.DOTALL)

        if match:
            old_entry = match.group(1)
            old_lines = old_entry.count('\n')

            # Replace old entry with new entry
            updated_content = updated_content.replace(old_entry, new_entry.rstrip())

            new_lines = new_entry.count('\n')
            diff = new_lines - old_lines

            print(f"      [OK] Replaced stub ({old_lines} lines) with complete entry ({new_lines} lines, {diff:+d} net)")
        else:
            print(f"      WARNING: Could not find entry for {vuln_id}")

    print()

    # Step 5: Write updated answer file
    print("[5/6] Writing updated answer file...")
    with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
        f.write(updated_content)

    new_size = len(updated_content)
    size_diff = new_size - len(original_content)
    print(f"   [OK] Answer file updated successfully")
    print(f"   Old size: {len(original_content)} characters")
    print(f"   New size: {new_size} characters ({size_diff:+d})")
    print()

    # Step 6: Cleanup
    print("[6/6] Cleaning up...")
    # Move entries file to Docs folder
    docs_path = os.path.join(PROJECT_ROOT, "Evaluate-STIG", ".Mods_by_Kismet", "Docs", "answer_file_entries_session32_batch1.xml")
    os.rename(ENTRIES_FILE, docs_path)
    print(f"   [OK] Moved entries file to: {docs_path}")
    print()

    print("=" * 70)
    print("Integration Complete!")
    print("=" * 70)
    print()
    print("Answer file entries integrated:")
    print("- V-206425: UTC/GMT Timestamps (2 indices)")
    print("- V-206426: Timestamp Granularity (2 indices)")
    print("- V-264341: Enforcement Audit (2 indices)")
    print("- V-264358: Synchronize Clocks (2 indices)")
    print("- V-264359: Clock Comparison (1 index)")
    print()
    print("Total: 9 new answer indices integrated")
    print()
    print("Next step: Run Test112 framework validation on XO1.WGSDAC.NET")
    print()

if __name__ == "__main__":
    main()
