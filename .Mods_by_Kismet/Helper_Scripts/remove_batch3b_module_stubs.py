#!/usr/bin/env python3
"""
Remove duplicate Batch 3b stub function declarations from module.

The append script added full implementations, but stub declarations remain.
This script removes the FIRST occurrence (stub) and keeps the SECOND (full).

Stubs to remove (first occurrences):
- V-264346: line 28758
- V-264347: line 28869
- V-264354: line 30673
- V-264357: line 31479
- V-279028: line 33725

Usage:
    python remove_batch3b_module_stubs.py
"""

import os
import re
import shutil
from datetime import datetime

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Modules', 'Scan-XO_WebSRG_Checks', 'Scan-XO_WebSRG_Checks.psm1')

# Function names to process (remove first occurrence of each)
FUNCTION_NAMES = [
    'Get-V264346',
    'Get-V264347',
    'Get-V264354',
    'Get-V264357',
    'Get-V279028'
]


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def find_function(content, function_name, start_pos=0):
    """
    Find a complete function declaration.
    Returns tuple: (start_pos, end_pos, function_text) or (None, None, None) if not found.
    """
    # Find opening declaration (case-insensitive for Function/function)
    pattern = rf'(?i)^function\s+{re.escape(function_name)}\s*\{{'
    match = re.search(pattern, content[start_pos:], re.MULTILINE)

    if not match:
        return None, None, None

    actual_start = start_pos + match.start()

    # Find matching closing brace (simple brace counting)
    brace_count = 0
    in_function = False
    end_pos = None

    for i in range(actual_start, len(content)):
        char = content[i]

        if char == '{':
            brace_count += 1
            in_function = True
        elif char == '}':
            brace_count -= 1
            if in_function and brace_count == 0:
                end_pos = i + 1
                break

    if end_pos is None:
        raise ValueError(f"No closing brace found for {function_name}")

    # Include trailing newline
    if end_pos < len(content) and content[end_pos] == '\n':
        end_pos += 1

    function_text = content[actual_start:end_pos]

    return actual_start, end_pos, function_text


def count_functions(content):
    """Count function declarations in module content."""
    pattern = r'(?i)^function\s+Get-V\d+\s*\{'
    matches = re.findall(pattern, content, re.MULTILINE)
    return len(matches)


def is_stub(function_text):
    """Check if function is a stub by looking for [STUB] in Rule Title."""
    return '[STUB]' in function_text


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Remove Duplicate Module Stubs")
    print("=" * 80)
    print()

    # Read module
    print(f"Reading module: {os.path.basename(MODULE_PATH)}")
    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    original_size = len(content)
    original_lines = content.count('\n') + 1
    original_functions = count_functions(content)
    print(f"  Original: {original_lines:,} lines, {original_size:,} chars, {original_functions} functions")
    print()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Process each function
    print("Removing first occurrence (stub) of each function:")
    chars_removed = 0
    lines_removed = 0

    for function_name in FUNCTION_NAMES:
        # Find first occurrence
        start, end, function_text = find_function(content, function_name)

        if start is None:
            print(f"  [WARNING] {function_name} not found")
            continue

        # Verify it's a stub
        if not is_stub(function_text):
            print(f"  [WARNING] {function_name} first occurrence is NOT a stub - skipping")
            continue

        function_lines = function_text.count('\n') + 1
        function_chars = len(function_text)

        # Remove from content
        content = content[:start] + content[end:]

        chars_removed += function_chars
        lines_removed += function_lines

        print(f"  [OK] Removed {function_name} stub - {function_lines} lines, {function_chars} chars")

    print()

    # Verify function count decreased by 5
    new_functions = count_functions(content)
    expected_functions = original_functions - len(FUNCTION_NAMES)

    if new_functions != expected_functions:
        print(f"[ERROR] Function count mismatch!")
        print(f"  Expected: {expected_functions} ({original_functions} - {len(FUNCTION_NAMES)})")
        print(f"  Got: {new_functions}")
        print("  Removal aborted - module not modified")
        return 1

    # Write updated module
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    new_size = len(content)
    new_lines = content.count('\n') + 1

    print("Module updated:")
    print(f"  New size: {new_lines:,} lines ({new_lines - original_lines:+,})")
    print(f"  Functions: {original_functions} -> {new_functions} (-{len(FUNCTION_NAMES)})")
    print(f"  Removed: {lines_removed} lines, {chars_removed} chars")
    print()

    # Verify no duplicates remain
    print("Verifying no duplicates remain:")
    for function_name in FUNCTION_NAMES:
        # Count occurrences
        pattern = rf'(?i)^function\s+{re.escape(function_name)}\s*\{{'
        occurrences = len(re.findall(pattern, content, re.MULTILINE))

        if occurrences == 1:
            print(f"  [OK] {function_name}: 1 occurrence")
        else:
            print(f"  [ERROR] {function_name}: {occurrences} occurrences (expected 1)")

    print()
    print("=" * 80)
    print("[OK] Batch 3b module stub removal complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Test module loading: Import-Module ... -Force")
    print("  2. Verify function count: 131 (was 136)")
    print("  3. User runs Test115 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
