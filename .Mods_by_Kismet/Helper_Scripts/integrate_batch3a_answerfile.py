#!/usr/bin/env python3
"""
Integration script for Session #32 Batch 3a answer file entries
Integrates 12 answer indices (5 functions) into XO_v5.x_WebSRG_AnswerFile.xml
"""

import re
import sys

def read_file(filepath):
    """Read file content."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        sys.exit(1)

def write_file(filepath, content):
    """Write content to file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Successfully wrote {filepath}")
    except Exception as e:
        print(f"Error writing {filepath}: {e}")
        sys.exit(1)

def validate_xml(content):
    """Basic XML validation."""
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(content)
        return True
    except Exception as e:
        print(f"XML validation error: {e}")
        return False

def main():
    """Main integration process."""
    print("=" * 70)
    print("Session #32 Batch 3a Answer File Integration")
    print("=" * 70)

    # Paths
    answer_file_path = '../../AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml'
    entries_path = 'batch3a_answerfile_entries.xml'

    # Read files
    print(f"\nReading answer file: {answer_file_path}")
    answer_content = read_file(answer_file_path)
    original_lines = answer_content.count('\n') + 1
    print(f"Original lines: {original_lines:,}")

    print(f"\nReading entries: {entries_path}")
    entries_content = read_file(entries_path)
    entries_lines = entries_content.count('\n') + 1
    print(f"Entries lines: {entries_lines:,}")

    # Count Vuln entries in batch
    vuln_pattern = r'<Vuln ID="(V-\d+)">'
    vuln_ids = re.findall(vuln_pattern, entries_content)
    print(f"Vuln IDs to integrate: {', '.join(vuln_ids)}")

    # Find insertion point (before closing </STIGComments> tag)
    closing_tag = '</STIGComments>'
    insert_pos = answer_content.rfind(closing_tag)

    if insert_pos == -1:
        print("Error: Could not find </STIGComments> closing tag in answer file")
        sys.exit(1)

    # Insert entries before closing tag (with proper indentation)
    new_content = (
        answer_content[:insert_pos] +
        '\n' +
        entries_content +
        '\n' +
        answer_content[insert_pos:]
    )

    new_lines = new_content.count('\n') + 1
    net_change = new_lines - original_lines

    print("\n" + "=" * 70)
    print("Integration Summary")
    print("=" * 70)
    print(f"Original lines:  {original_lines:,}")
    print(f"New lines:       {new_lines:,}")
    print(f"Net change:      {net_change:+,}")
    print(f"Vuln IDs added:  {len(vuln_ids)}")

    # Backup original
    backup_path = answer_file_path + '.batch3a_backup'
    write_file(backup_path, answer_content)
    print(f"\n[OK] Backup saved: {backup_path}")

    # Validate before writing
    print("\n[...] Validating XML structure...")
    if not validate_xml(new_content):
        print("[ERROR] XML validation failed! Not writing file.")
        print("Please check the entries file for XML errors.")
        sys.exit(1)

    print("[OK] XML validation passed")

    # Write new answer file
    write_file(answer_file_path, new_content)
    print(f"[OK] Answer file updated: {answer_file_path}")

    print("\n" + "=" * 70)
    print("Next Steps:")
    print("  1. Run Test114a on XO1.WGSDAC.NET to validate Batch 3a functions")
    print("  2. Verify all 5 functions have populated COMMENTS fields in CKL")
    print("=" * 70)

if __name__ == '__main__':
    main()
