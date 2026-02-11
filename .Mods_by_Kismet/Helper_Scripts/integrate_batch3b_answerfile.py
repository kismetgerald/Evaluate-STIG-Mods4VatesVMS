#!/usr/bin/env python3
"""
Integrate Session #32 Batch 3b answer file entries.

This script:
1. Reads batch3b_answerfile_entries.xml
2. Extracts <Vuln> elements (5 functions)
3. Inserts before closing </AnswerFile> tag
4. Creates backup before modification
5. Validates XML structure

Usage:
    python integrate_batch3b_answerfile.py
"""

import os
import re
import shutil
from datetime import datetime

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
ANSWERFILE_PATH = os.path.join(PROJECT_ROOT, 'AnswerFiles', 'XO_v5.x_WebSRG_AnswerFile.xml')
ENTRIES_PATH = os.path.join(SCRIPT_DIR, 'batch3b_answerfile_entries.xml')


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def extract_vuln_entries(entries_file):
    """Extract <Vuln> elements from entries file."""
    with open(entries_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find all <Vuln ID="..."> ... </Vuln> blocks
    pattern = r'<Vuln ID="(V-\d+)">(.*?)</Vuln>'
    matches = re.findall(pattern, content, re.DOTALL)

    entries = []
    for vuln_id, vuln_content in matches:
        vuln_element = f'<Vuln ID="{vuln_id}">{vuln_content}</Vuln>'
        entries.append((vuln_id, vuln_element))

    return entries


def find_closing_tag(content):
    """Find the </STIGComments> closing tag position."""
    pattern = r'</STIGComments>'
    match = re.search(pattern, content)
    if match:
        return match.start()
    return None


def count_vuln_entries(content):
    """Count <Vuln> entries in answer file."""
    pattern = r'<Vuln ID="V-\d+">'
    matches = re.findall(pattern, content)
    return len(matches)


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Answer File Integration")
    print("=" * 80)
    print()

    # Read answer file
    print(f"Reading answer file: {os.path.basename(ANSWERFILE_PATH)}")
    with open(ANSWERFILE_PATH, 'r', encoding='utf-8') as f:
        answerfile_content = f.read()

    original_size = len(answerfile_content)
    original_lines = answerfile_content.count('\n') + 1
    original_entries = count_vuln_entries(answerfile_content)
    print(f"  Original: {original_lines:,} lines, {original_size:,} chars, {original_entries} Vuln entries")
    print()

    # Extract new entries
    print(f"Extracting entries from: {os.path.basename(ENTRIES_PATH)}")
    new_entries = extract_vuln_entries(ENTRIES_PATH)
    print(f"  Found {len(new_entries)} Vuln entries")
    print()

    # Create backup
    backup_path = create_backup(ANSWERFILE_PATH)
    print()

    # Find insertion point
    closing_pos = find_closing_tag(answerfile_content)
    if closing_pos is None:
        print("[ERROR] Cannot find </STIGComments> closing tag")
        return 1

    print(f"Found </STIGComments> at position {closing_pos:,}")
    print()

    # Build new content
    print("Integrating entries:")
    before = answerfile_content[:closing_pos].rstrip()
    after = answerfile_content[closing_pos:]

    # Format new entries with proper indentation
    formatted_entries = []
    for vuln_id, vuln_element in new_entries:
        # Indent the element (4 spaces)
        indented = '\n'.join('    ' + line if line.strip() else ''
                             for line in vuln_element.split('\n'))
        formatted_entries.append(indented)
        print(f"  [OK] {vuln_id} - {vuln_element.count(chr(10))+1} lines")

    new_entries_text = '\n\n'.join(formatted_entries)

    # Combine
    updated_content = f"{before}\n\n{new_entries_text}\n\n{after}"

    # Verify entry count increased by 5
    new_entries_count = count_vuln_entries(updated_content)
    expected_count = original_entries + len(new_entries)

    if new_entries_count != expected_count:
        print(f"[ERROR] Vuln entry count mismatch!")
        print(f"  Expected: {expected_count} ({original_entries} + {len(new_entries)})")
        print(f"  Got: {new_entries_count}")
        print("  Integration aborted - answer file not modified")
        return 1

    # Validate XML structure
    print()
    print("Validating XML structure...")
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(updated_content)
        print("[OK] XML validation passed")
    except ET.ParseError as e:
        print(f"[ERROR] XML validation failed: {e}")
        print("  Integration aborted - answer file not modified")
        return 1

    # Write updated answer file
    with open(ANSWERFILE_PATH, 'w', encoding='utf-8') as f:
        f.write(updated_content)

    new_size = len(updated_content)
    new_lines = updated_content.count('\n') + 1
    size_diff = new_size - original_size
    line_diff = new_lines - original_lines

    print()
    print("Answer file updated:")
    print(f"  New size: {new_lines:,} lines ({line_diff:+,}), {new_size:,} chars ({size_diff:+,})")
    print(f"  Vuln entries: {original_entries} -> {new_entries_count} (+{len(new_entries)})")
    print()

    print("=" * 80)
    print("[OK] Batch 3b answer file integration complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Check for duplicate Vuln IDs: grep -E '^\\s*<Vuln ID=\"V-' ... | sort | uniq -d")
    print("  2. User runs Test115 for framework validation")
    print("  3. Verify COMMENTS fields populated in CKL file")

    return 0


if __name__ == '__main__':
    exit(main())
