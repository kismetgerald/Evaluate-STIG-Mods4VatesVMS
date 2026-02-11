#!/usr/bin/env python3
"""
Integrate Session #34 implementations into Scan-XO_WebSRG_Checks.psm1

Replaces 7 stub functions with full implementations:
- V-206430: DoD PKI Client Certificate Validation
- V-264339: Centralized Audit Record Review
- V-264346: Password List Update Frequency
- V-264347: Password List Update When Compromised
- V-264354: Local Cache for Certificate Revocation
- V-264357: Protected Cryptographic Key Storage
- V-279028: Uniquely Identify Information Transfer Source

Usage:
    python integrate_session34_functions.py
"""

import os
import re
from datetime import datetime
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
MODULE_PATH = os.path.join(PROJECT_ROOT, 'Modules', 'Scan-XO_WebSRG_Checks', 'Scan-XO_WebSRG_Checks.psm1')
IMPL_DIR = "d:\\tmp"

# Map Vuln IDs to implementation files and line numbers
IMPLEMENTATIONS = {
    'V-206430': {'file': 'V-206430_implementation.ps1', 'line': 21348},
    'V-264339': {'file': 'V-264339_implementation.ps1', 'line': 26500},
    'V-264346': {'file': 'V-264346_implementation.ps1', 'line': 33569},
    'V-264347': {'file': 'V-264347_implementation.ps1', 'line': 33759},
    'V-264354': {'file': 'V-264354_implementation.ps1', 'line': 34164},
    'V-264357': {'file': 'V-264357_implementation.ps1', 'line': 33948},
    'V-279028': {'file': 'V-279028_implementation.ps1', 'line': 34379},
}


def create_backup(filepath):
    """Create timestamped backup."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def find_function_bounds(lines, vuln_id):
    """Find the start and end lines of a function by pattern search."""
    func_name = f"Get-V{vuln_id.replace('V-', '').replace('-', '')}"

    # Search entire file for function start
    func_start = None
    for i, line in enumerate(lines):
        if re.match(rf'^Function {func_name}\s*{{', line):
            func_start = i
            break

    if func_start is None:
        raise ValueError(f"Could not find function {func_name} in module")

    # Find function end (matching closing brace)
    brace_count = 0
    func_end = None
    for i in range(func_start, len(lines)):
        line = lines[i]
        # Count braces
        brace_count += line.count('{') - line.count('}')
        if brace_count == 0 and i > func_start:
            func_end = i
            break

    if func_end is None:
        raise ValueError(f"Could not find end of function {func_name}")

    return func_start, func_end


def integrate_implementations():
    """Replace stub functions with implementations."""
    print("=" * 80)
    print("Session #34: Integrate 7 Function Implementations")
    print("=" * 80)
    print()

    # Read module
    print(f"Reading module: {os.path.basename(MODULE_PATH)}")
    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    original_line_count = len(lines)
    print(f"  Original line count: {original_line_count:,}")
    print()

    # Create backup
    backup_path = create_backup(MODULE_PATH)
    print()

    # Process each implementation
    replacements_made = 0
    total_lines_added = 0

    for vuln_id in sorted(IMPLEMENTATIONS.keys()):
        impl_info = IMPLEMENTATIONS[vuln_id]
        impl_file = os.path.join(IMPL_DIR, impl_info['file'])
        target_line = impl_info['line']

        print(f"Processing {vuln_id}...")

        # Read implementation
        if not os.path.exists(impl_file):
            print(f"  [WARNING] Implementation file not found: {impl_file}")
            continue

        with open(impl_file, 'r', encoding='utf-8') as f:
            impl_content = f.read()

        impl_lines = impl_content.split('\n')
        print(f"  Implementation: {len(impl_lines)} lines")

        # Find function bounds
        try:
            func_start, func_end = find_function_bounds(lines, vuln_id)
            stub_length = func_end - func_start + 1
            print(f"  Stub location: lines {func_start + 1}-{func_end + 1} ({stub_length} lines)")

            # Replace stub with implementation
            # Keep everything before the function
            new_lines = lines[:func_start]

            # Keep the Function declaration line
            new_lines.append(lines[func_start])

            # Add implementation (ensure newlines)
            for impl_line in impl_lines:
                new_lines.append(impl_line + '\n' if not impl_line.endswith('\n') else impl_line)

            # Add the closing brace
            new_lines.append('}\n')

            # Add everything after the function
            new_lines.extend(lines[func_end + 1:])

            # Update lines for next iteration
            lines = new_lines

            lines_added = len(impl_lines) - stub_length
            total_lines_added += lines_added
            replacements_made += 1

            print(f"  [OK] Replaced ({lines_added:+d} lines)")
            print()

        except ValueError as e:
            print(f"  [ERROR] {e}")
            print()
            continue

    # Write updated module
    new_line_count = len(lines)
    print(f"Total replacements: {replacements_made}/7")
    print(f"New line count: {new_line_count:,} ({total_lines_added:+,} lines)")
    print()

    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    print("=" * 80)
    print("[OK] Integration complete!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Test module load: Import-Module ./Modules/Scan-XO_WebSRG_Checks -Force")
    print("  2. Verify 126 functions exported")
    print("  3. Create answer file entries for 7 new implementations")
    print("  4. Run Test119 framework test")

    return 0


if __name__ == '__main__':
    exit(integrate_implementations())
