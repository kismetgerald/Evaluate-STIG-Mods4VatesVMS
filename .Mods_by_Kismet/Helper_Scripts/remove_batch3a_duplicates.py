#!/usr/bin/env python3
"""
Remove duplicate stub entries for Session #32 Batch 3a functions
Removes the FIRST occurrence (stub) and keeps the SECOND occurrence (full implementation)
"""

import re
import sys

VULN_IDS = ['V-206423', 'V-206424', 'V-206430', 'V-264339', 'V-264340']

def read_file(filepath):
    """Read file content."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(filepath, content):
    """Write content to file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def find_vuln_entry_boundaries(content, vuln_id, occurrence=1):
    """
    Find the start and end positions of a Vuln entry.
    occurrence: 1 for first (stub), 2 for second (full implementation)
    Returns (start_pos, end_pos) or None
    """
    pattern = rf'^\s*<Vuln ID="{vuln_id}">'
    matches = list(re.finditer(pattern, content, re.MULTILINE))

    if len(matches) < occurrence:
        return None

    start_match = matches[occurrence - 1]
    start_pos = start_match.start()

    # Find the closing </Vuln> tag
    # Count nested Vuln tags to handle properly
    pos = start_pos
    depth = 0
    in_vuln = False

    while pos < len(content):
        # Check for opening <Vuln> tag
        if content[pos:pos+6] == '<Vuln ':
            depth += 1
            in_vuln = True
        # Check for closing </Vuln> tag
        elif content[pos:pos+7] == '</Vuln>':
            depth -= 1
            if in_vuln and depth == 0:
                end_pos = pos + 7
                return (start_pos, end_pos)
        pos += 1

    return None

def main():
    """Remove duplicate stub entries."""
    print("=" * 70)
    print("Remove Batch 3a Duplicate Stub Entries")
    print("=" * 70)

    answer_file = '../../AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml'
    print(f"\nReading: {answer_file}")
    content = read_file(answer_file)
    original_lines = content.count('\n') + 1
    print(f"Original lines: {original_lines:,}")

    # Backup
    backup_file = answer_file + '.before_duplicate_removal'
    write_file(backup_file, content)
    print(f"Backup saved: {backup_file}")

    # Remove stubs (first occurrence of each Vuln ID)
    removed_count = 0
    total_removed_chars = 0

    for vuln_id in VULN_IDS:
        print(f"\nProcessing {vuln_id}...")
        boundaries = find_vuln_entry_boundaries(content, vuln_id, occurrence=1)

        if boundaries:
            start, end = boundaries
            stub_size = end - start

            # Remove the stub entry (including the newline after </Vuln>)
            if end < len(content) and content[end] == '\n':
                end += 1

            content = content[:start] + content[end:]
            removed_count += 1
            total_removed_chars += (end - start)

            print(f"  [OK] Removed stub entry ({end - start} characters)")
        else:
            print(f"  [WARNING] Could not find stub entry")

    new_lines = content.count('\n') + 1

    print("\n" + "=" * 70)
    print("Removal Summary")
    print("=" * 70)
    print(f"Original lines:     {original_lines:,}")
    print(f"New lines:          {new_lines:,}")
    print(f"Lines removed:      {original_lines - new_lines:,}")
    print(f"Stubs removed:      {removed_count}")
    print(f"Characters removed: {total_removed_chars:,}")

    # Write updated file
    write_file(answer_file, content)
    print(f"\n[OK] Updated: {answer_file}")

    print("\n" + "=" * 70)
    print("Next Step: Re-run Test114a")
    print("=" * 70)

if __name__ == '__main__':
    main()
