#!/usr/bin/env python3
"""
Integrate Session #32 Batch 3b functions by APPENDING to module.

These are new functions (not stub replacements), so we append them
before the final Export-ModuleMember line.

Usage:
    python integrate_batch3b_append.py
"""

import os
import re
import shutil
from datetime import datetime

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Modules', 'Scan-XO_WebSRG_Checks', 'Scan-XO_WebSRG_Checks.psm1')

# Batch 3b implementation files
BATCH3B_FILES = [
    'batch3b_v264346.ps1',
    'batch3b_v264347.ps1',
    'batch3b_v264357.ps1',
    'batch3b_v264354.ps1',
    'batch3b_v279028.ps1'
]


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def extract_full_function(filepath):
    """
    Extract complete function from implementation file.
    Returns tuple: (function_name, complete_function_text)
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find the function declaration and everything up to the final closing brace
    pattern = r'(function\s+Get-V\d+\s*\{.*\}\s*)$'
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        raise ValueError(f"Cannot find function in {filepath}")

    function_text = match.group(1).strip()

    # Extract function name for reporting
    name_match = re.search(r'function\s+(Get-V\d+)\s*\{', function_text)
    function_name = name_match.group(1) if name_match else "Unknown"

    return function_name, function_text


def verify_function_count(content):
    """Count function declarations in module content."""
    pattern = r'^function\s+Get-V\d+\s*\{'
    matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
    return len(matches)


def find_export_line(content):
    """Find the Export-ModuleMember line position."""
    pattern = r'^Export-ModuleMember\s+-Function\s+'
    match = re.search(pattern, content, re.MULTILINE)
    if match:
        return match.start()
    return None


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Module Integration (APPEND)")
    print("=" * 80)
    print()

    # Read module
    print(f"Reading module: {os.path.basename(MODULE_PATH)}")
    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        module_content = f.read()

    original_size = len(module_content)
    original_lines = module_content.count('\n') + 1
    original_functions = verify_function_count(module_content)
    print(f"  Original: {original_lines:,} lines, {original_size:,} chars, {original_functions} functions")
    print()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Find insertion point (before Export-ModuleMember)
    export_pos = find_export_line(module_content)
    if export_pos is None:
        print("[ERROR] Cannot find Export-ModuleMember line")
        return 1

    print(f"Found Export-ModuleMember at position {export_pos:,}")
    print()

    # Extract all new functions
    print("Extracting functions:")
    functions_to_add = []

    for impl_file in BATCH3B_FILES:
        impl_path = os.path.join(SCRIPT_DIR, impl_file)

        if not os.path.exists(impl_path):
            print(f"  [ERROR] File not found: {impl_file}")
            continue

        function_name, function_text = extract_full_function(impl_path)
        function_lines = function_text.count('\n') + 1
        functions_to_add.append((function_name, function_text))

        print(f"  [OK] {function_name} - {function_lines} lines")

    print()

    # Build new module content
    print("Inserting functions before Export-ModuleMember...")

    # Content before insertion point
    before = module_content[:export_pos].rstrip()

    # New functions with proper spacing
    new_functions = '\n\n'.join(func_text for _, func_text in functions_to_add)

    # Content from insertion point onward
    after = module_content[export_pos:]

    # Combine with double newline separation
    updated_content = f"{before}\n\n{new_functions}\n\n{after}"

    # Verify function count increased by 5
    new_functions_count = verify_function_count(updated_content)
    expected_count = original_functions + len(functions_to_add)

    if new_functions_count != expected_count:
        print(f"[ERROR] Function count mismatch!")
        print(f"  Expected: {expected_count} ({original_functions} + {len(functions_to_add)})")
        print(f"  Got: {new_functions_count}")
        print("  Integration aborted - module not modified")
        return 1

    # Write updated module
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(updated_content)

    new_size = len(updated_content)
    new_lines = updated_content.count('\n') + 1
    size_diff = new_size - original_size
    line_diff = new_lines - original_lines

    print(f"[OK] Added {len(functions_to_add)} new functions")
    print()

    print("Module updated:")
    print(f"  New size: {new_lines:,} lines ({line_diff:+,}), {new_size:,} chars ({size_diff:+,})")
    print(f"  Functions: {original_functions} -> {new_functions_count} (+{len(functions_to_add)})")
    print()

    print("=" * 80)
    print("[OK] Batch 3b integration complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Test module loading: Import-Module ... -Force")
    print("  2. Update .psd1 FunctionsToExport (add 5 new functions)")
    print("  3. Create answer file entries for Batch 3b")
    print("  4. User runs Test115 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
