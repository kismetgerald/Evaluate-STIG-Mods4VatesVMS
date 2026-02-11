#!/usr/bin/env python3
"""
Session #32 Batch 2 - Module Integration Script
Integrates 5 remote access and logging infrastructure functions into Scan-XO_WebSRG_Checks module
"""

import re
import os

# Configuration
BASE_DIR = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode"
MODULE_FILE = os.path.join(BASE_DIR, r"Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1")

# Batch 2 Vuln IDs
BATCH2_VULNS = [
    "V-206416",
    "V-206417",
    "V-206418",
    "V-206421",
    "V-206422"
]

def read_implementation(vuln_id):
    """Read implementation file for a Vuln ID"""
    impl_file = os.path.join(BASE_DIR, f"{vuln_id.replace('-', '')}_implementation.ps1")
    if not os.path.exists(impl_file):
        raise FileNotFoundError(f"Implementation file not found: {impl_file}")

    with open(impl_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract just the function body (remove Function declaration wrapper if present)
    # Implementation files should contain the full function including the wrapper
    return content

def integrate_function(module_content, vuln_id, implementation):
    """Replace stub function with implementation"""
    func_name = f"Get-{vuln_id.replace('-', '')}"

    # Pattern to match the entire function from "Function Get-VXXXXXX {" to the closing "}"
    # This is complex because we need to match nested braces correctly

    # Find the start of the function
    func_start_pattern = rf"(Function {re.escape(func_name)}\s*\{{)"
    match = re.search(func_start_pattern, module_content)

    if not match:
        raise ValueError(f"Function {func_name} not found in module")

    start_pos = match.start()

    # Find the matching closing brace
    # Start after the opening brace
    pos = match.end()
    brace_count = 1

    while pos < len(module_content) and brace_count > 0:
        if module_content[pos] == '{':
            brace_count += 1
        elif module_content[pos] == '}':
            brace_count -= 1
        pos += 1

    if brace_count != 0:
        raise ValueError(f"Could not find matching closing brace for {func_name}")

    end_pos = pos

    # Get the old function for reporting
    old_function = module_content[start_pos:end_pos]
    old_lines = len(old_function.split('\n'))

    # Extract just the function body from implementation (remove Function wrapper)
    impl_body_match = re.search(r'Function\s+' + re.escape(func_name) + r'\s*\{(.+)\}\s*$', implementation, re.DOTALL)
    if impl_body_match:
        # Implementation has Function wrapper, extract body
        impl_body = impl_body_match.group(1)
        new_function = f"Function {func_name} {{\n{impl_body}}}\n"
    else:
        # Implementation is just the body, wrap it
        new_function = f"Function {func_name} {{\n{implementation}\n}}\n"

    new_lines = len(new_function.split('\n'))

    # Replace the function
    updated_content = module_content[:start_pos] + new_function + module_content[end_pos:]

    print(f"[OK] {vuln_id}: {old_lines} stub lines -> {new_lines} impl lines (+{new_lines - old_lines} net)")

    return updated_content, old_lines, new_lines

def main():
    print("=" * 70)
    print("Session #32 Batch 2 - Module Integration")
    print("=" * 70)
    print()

    # Read module file
    print(f"Reading module: {MODULE_FILE}")
    with open(MODULE_FILE, 'r', encoding='utf-8') as f:
        module_content = f.read()

    original_lines = len(module_content.split('\n'))
    print(f"Original module: {original_lines:,} lines")
    print()

    # Integrate each function
    total_old_lines = 0
    total_new_lines = 0

    print("Integrating functions:")
    print("-" * 70)

    for vuln_id in BATCH2_VULNS:
        try:
            implementation = read_implementation(vuln_id)
            module_content, old_lines, new_lines = integrate_function(module_content, vuln_id, implementation)
            total_old_lines += old_lines
            total_new_lines += new_lines
        except Exception as e:
            print(f"[ERROR] {vuln_id}: {e}")
            return 1

    print("-" * 70)
    print(f"Total: {total_old_lines} stub lines -> {total_new_lines} impl lines (+{total_new_lines - total_old_lines} net)")
    print()

    # Write updated module
    print(f"Writing updated module...")
    with open(MODULE_FILE, 'w', encoding='utf-8') as f:
        f.write(module_content)

    final_lines = len(module_content.split('\n'))
    print(f"Final module: {final_lines:,} lines")
    print()

    print("=" * 70)
    print(f"Integration complete! Module updated: {MODULE_FILE}")
    print("=" * 70)

    return 0

if __name__ == "__main__":
    exit(main())
