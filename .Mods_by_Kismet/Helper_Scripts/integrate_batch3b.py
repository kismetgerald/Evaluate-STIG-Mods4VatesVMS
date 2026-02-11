#!/usr/bin/env python3
"""
Integrate Session #32 Batch 3b functions into Scan-XO_WebSRG_Checks module.

This script:
1. Reads all 5 batch3b_*.ps1 implementation files
2. Extracts function bodies (everything inside function Get-V######)
3. Finds corresponding stub functions in module by VulnID
4. Replaces stub implementations with full implementations
5. Creates backup before modification
6. Verifies function count remains 126 (stub replacement, not addition)

Usage:
    python integrate_batch3b.py
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

# Vuln IDs to function names mapping (note: no hyphen after V)
VULN_TO_FUNCTION = {
    'V-264346': 'Get-V264346',
    'V-264347': 'Get-V264347',
    'V-264357': 'Get-V264357',
    'V-264354': 'Get-V264354',
    'V-279028': 'Get-V279028'
}


def create_backup(filepath):
    """Create timestamped backup of file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def extract_function_body(filepath):
    """
    Extract function body from implementation file.
    Returns tuple: (vuln_id, function_name, function_body)
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract Vuln ID from filename (e.g., batch3b_v264346.ps1 -> V-264346)
    filename = os.path.basename(filepath)
    match = re.search(r'v(\d+)', filename.lower())
    if not match:
        raise ValueError(f"Cannot extract Vuln ID from filename: {filename}")

    vuln_num = match.group(1)
    vuln_id = f"V-{vuln_num}"
    function_name = VULN_TO_FUNCTION.get(vuln_id)

    if not function_name:
        raise ValueError(f"Unknown Vuln ID: {vuln_id}")

    # Extract everything inside the function declaration
    # Pattern: function Get-V###### { ... }
    pattern = rf'function\s+{re.escape(function_name)}\s*\{{(.*)\}}\s*$'
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        raise ValueError(f"Cannot find function {function_name} in {filename}")

    function_body = match.group(1).strip()

    return vuln_id, function_name, function_body


def find_stub_function(module_content, function_name):
    """
    Find stub function location in module.
    Returns tuple: (start_pos, end_pos) or (None, None) if not found.
    """
    # Pattern to match the stub function declaration and find its closing brace
    pattern = rf'function\s+{re.escape(function_name)}\s*\{{'

    match = re.search(pattern, module_content)
    if not match:
        return None, None

    start_pos = match.start()

    # Find matching closing brace (simple brace counting)
    brace_count = 0
    in_function = False
    end_pos = None

    for i in range(start_pos, len(module_content)):
        char = module_content[i]

        if char == '{':
            brace_count += 1
            in_function = True
        elif char == '}':
            brace_count -= 1
            if in_function and brace_count == 0:
                end_pos = i + 1
                break

    if end_pos is None:
        raise ValueError(f"Cannot find closing brace for function {function_name}")

    return start_pos, end_pos


def replace_stub_with_implementation(module_content, function_name, new_body):
    """
    Replace stub function with full implementation.
    Returns updated module content.
    """
    start_pos, end_pos = find_stub_function(module_content, function_name)

    if start_pos is None:
        raise ValueError(f"Stub function {function_name} not found in module")

    # Construct new function
    new_function = f"function {function_name} {{\n{new_body}\n}}"

    # Replace old function with new
    updated_content = (
        module_content[:start_pos] +
        new_function +
        module_content[end_pos:]
    )

    return updated_content


def verify_function_count(content):
    """Count function declarations in module content."""
    pattern = r'^function\s+Get-V\d+\s*\{'
    matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
    return len(matches)


def main():
    print("=" * 80)
    print("Session #32 Batch 3b - Module Integration")
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

    # Process each implementation file
    print("Integrating functions:")
    updated_content = module_content

    for impl_file in BATCH3B_FILES:
        impl_path = os.path.join(SCRIPT_DIR, impl_file)

        if not os.path.exists(impl_path):
            print(f"  [ERROR] File not found: {impl_file}")
            continue

        # Extract function
        vuln_id, function_name, function_body = extract_function_body(impl_path)
        body_lines = function_body.count('\n') + 1

        # Replace stub
        updated_content = replace_stub_with_implementation(
            updated_content,
            function_name,
            function_body
        )

        print(f"  [OK] {vuln_id} ({function_name}) - {body_lines} lines")

    print()

    # Verify function count hasn't changed
    new_functions = verify_function_count(updated_content)
    if new_functions != original_functions:
        print(f"[ERROR] ERROR: Function count changed from {original_functions} to {new_functions}")
        print("  Integration aborted - module not modified")
        return 1

    # Write updated module
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(updated_content)

    new_size = len(updated_content)
    new_lines = updated_content.count('\n') + 1
    size_diff = new_size - original_size
    line_diff = new_lines - original_lines

    print("Module updated:")
    print(f"  New size: {new_lines:,} lines ({line_diff:+,}), {new_size:,} chars ({size_diff:+,})")
    print(f"  Functions: {new_functions} (unchanged - stub replacement)")
    print()

    print("=" * 80)
    print("[OK] Batch 3b integration complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Test module loading: Import-Module ... -Force")
    print("  2. Create answer file entries for Batch 3b")
    print("  3. User runs Test115 for framework validation")

    return 0


if __name__ == '__main__':
    exit(main())
