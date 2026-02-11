#!/usr/bin/env python3
"""
Integration script for Session #32 Batch 3a functions (V-206423, V-206424, V-206430, V-264339, V-264340)
Replaces stub implementations with full implementations in Scan-XO_WebSRG_Checks.psm1
"""

import re
import sys

# Function VulnIDs for Batch 3a
VULN_IDS = [
    'V206423',
    'V206424',
    'V206430',
    'V264339',
    'V264340'
]

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

def find_function_boundaries(module_content, vuln_id):
    """
    Find the start and end positions of a function in the module.
    Returns (start_pos, end_pos) or None if not found.
    """
    # Pattern: Function Get-V###### { ... }
    # Note: Function names don't have hyphens (Get-V206423, not Get-V-206423)
    pattern = rf'^Function Get-{vuln_id}\s*\{{'

    match = re.search(pattern, module_content, re.MULTILINE)
    if not match:
        print(f"Warning: Function Get-{vuln_id} not found in module")
        return None

    start_pos = match.start()

    # Find matching closing brace
    brace_count = 0
    in_function = False
    end_pos = start_pos

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

    if end_pos == start_pos:
        print(f"Warning: Could not find closing brace for Get-{vuln_id}")
        return None

    return (start_pos, end_pos)

def integrate_function(module_content, vuln_id, implementation_file):
    """
    Replace stub function with implementation.
    """
    print(f"\nProcessing {vuln_id}...")

    # Read implementation
    impl_content = read_file(implementation_file)

    # Extract just the function content (without the outer "function" wrapper if present)
    # Implementation files should have: function Get-V###### { ... }
    impl_pattern = rf'^function Get-{vuln_id}\s*\{{'
    impl_match = re.search(impl_pattern, impl_content, re.MULTILINE | re.IGNORECASE)

    if not impl_match:
        print(f"  Error: Could not find function definition in {implementation_file}")
        return module_content

    # Extract function content (everything after "function Get-V###### {")
    impl_start = impl_match.end()

    # Find the matching closing brace for the implementation
    brace_count = 1  # We're already past the opening brace
    impl_end = impl_start

    for i in range(impl_start, len(impl_content)):
        char = impl_content[i]
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                impl_end = i
                break

    # Get the implementation body (without outer braces)
    impl_body = impl_content[impl_start:impl_end].strip()

    # Find stub function in module
    boundaries = find_function_boundaries(module_content, vuln_id)
    if not boundaries:
        return module_content

    start_pos, end_pos = boundaries

    # Extract function header (up to opening brace)
    stub_text = module_content[start_pos:end_pos]
    header_match = re.match(r'(Function Get-' + vuln_id + r'\s*\{)', stub_text, re.IGNORECASE)
    if not header_match:
        print(f"  Error: Could not extract function header")
        return module_content

    function_header = header_match.group(1)

    # Construct new function
    new_function = f"{function_header}\n{impl_body}\n}}"

    # Replace in module
    new_content = module_content[:start_pos] + new_function + module_content[end_pos:]

    print(f"  [OK] Replaced function Get-{vuln_id}")
    print(f"    Old size: {end_pos - start_pos} chars")
    print(f"    New size: {len(new_function)} chars")
    print(f"    Net change: {len(new_function) - (end_pos - start_pos):+d} chars")

    return new_content

def main():
    """Main integration process."""
    print("=" * 70)
    print("Session #32 Batch 3a Integration")
    print("=" * 70)

    # Read module
    module_path = './Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1'
    print(f"\nReading module: {module_path}")
    module_content = read_file(module_path)
    original_size = len(module_content)
    print(f"Original size: {original_size:,} characters")

    # Process each function
    for vuln_id in VULN_IDS:
        impl_file = f'batch3a_{vuln_id.lower()}.ps1'
        module_content = integrate_function(module_content, vuln_id, impl_file)

    # Write updated module
    new_size = len(module_content)
    net_change = new_size - original_size

    print("\n" + "=" * 70)
    print("Integration Summary")
    print("=" * 70)
    print(f"Original module size: {original_size:,} characters")
    print(f"New module size:      {new_size:,} characters")
    print(f"Net change:           {net_change:+,} characters")
    print(f"Functions integrated: {len(VULN_IDS)}")

    # Backup original
    backup_path = module_path + '.batch3a_backup'
    write_file(backup_path, read_file(module_path))
    print(f"\n[OK] Backup saved: {backup_path}")

    # Write new module
    write_file(module_path, module_content)
    print(f"[OK] Module updated: {module_path}")

    print("\n" + "=" * 70)
    print("Next Steps:")
    print("  1. Test module loading: Import-Module ./Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psd1 -Force")
    print("  2. Create answer file entries for Batch 3a (10 indices)")
    print("  3. Run Test114a on XO1.WGSDAC.NET")
    print("=" * 70)

if __name__ == '__main__':
    main()
