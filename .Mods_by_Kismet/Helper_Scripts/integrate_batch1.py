#!/usr/bin/env python3
"""integrate_batch1.py - Integrate Session #32 Batch 1 functions into module"""

import os
import re
import sys

# Paths
PROJECT_ROOT = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode"
MODULE_PATH = os.path.join(PROJECT_ROOT, "Evaluate-STIG", "Modules", "Scan-XO_WebSRG_Checks", "Scan-XO_WebSRG_Checks.psm1")
BACKUP_PATH = os.path.join(PROJECT_ROOT, "Evaluate-STIG", "Modules", "Scan-XO_WebSRG_Checks", "Scan-XO_WebSRG_Checks_backup_python.psm1")

# Implementation files
IMPL_FILES = [
    {"vuln_id": "V-206426", "file": os.path.join(PROJECT_ROOT, "V206426_implementation.ps1")},
    {"vuln_id": "V-264341", "file": os.path.join(PROJECT_ROOT, "V264341_implementation.ps1")},
    {"vuln_id": "V-264358", "file": os.path.join(PROJECT_ROOT, "V264358_implementation.ps1")},
    {"vuln_id": "V-264359", "file": os.path.join(PROJECT_ROOT, "V264359_implementation.ps1")},
]

def main():
    print("=" * 70)
    print("Session #32 Batch 1 Integration - Python Approach")
    print("=" * 70)
    print()

    # Step 1: Verify files
    print("[1/5] Verifying files...")
    if not os.path.exists(MODULE_PATH):
        print(f"ERROR: Module file not found: {MODULE_PATH}")
        sys.exit(1)

    for impl in IMPL_FILES:
        if not os.path.exists(impl["file"]):
            print(f"ERROR: Implementation file not found: {impl['file']}")
            sys.exit(1)

    print("   [OK] All files found")
    print()

    # Step 2: Create backup
    print("[2/5] Creating backup...")
    with open(MODULE_PATH, 'r', encoding='utf-8') as f:
        original_content = f.read()

    with open(BACKUP_PATH, 'w', encoding='utf-8') as f:
        f.write(original_content)

    print(f"   [OK] Backup created: {BACKUP_PATH}")
    print(f"   Original size: {len(original_content)} characters")
    print()

    # Step 3: Read implementations
    print("[3/5] Reading implementation files...")
    implementations = {}
    for impl in IMPL_FILES:
        with open(impl["file"], 'r', encoding='utf-8') as f:
            implementations[impl["vuln_id"]] = f.read()
        print(f"   [OK] Read {impl['vuln_id']}: {len(implementations[impl['vuln_id']])} characters")
    print()

    # Step 4: Integrate functions
    print("[4/5] Integrating functions...")
    updated_content = original_content

    for impl in IMPL_FILES:
        vuln_id = impl["vuln_id"]
        # Remove hyphen from vuln_id for function name (V-206426 -> V206426)
        func_name = f"Get-{vuln_id.replace('-', '')}"
        impl_content = implementations[vuln_id]

        print(f"   Processing {vuln_id}...")

        # Find stub function (from "Function Get-V######" until just before next function or end of file)
        # This captures the entire function including all braces
        pattern = rf"(Function {func_name}\s*\{{.*?)(?=\nFunction Get-V|\Z)"
        match = re.search(pattern, updated_content, re.DOTALL)

        if match:
            stub_content = match.group(1)
            stub_lines = stub_content.count('\n')

            # Replace stub with implementation
            updated_content = updated_content.replace(stub_content, impl_content.rstrip())

            impl_lines = impl_content.count('\n')
            diff = impl_lines - stub_lines

            print(f"      [OK] Replaced stub ({stub_lines} lines) with implementation ({impl_lines} lines, {diff:+d} net)")
        else:
            print(f"      WARNING: Could not find stub for {vuln_id}")

    print()

    # Step 5: Write updated module
    print("[5/5] Writing updated module...")
    with open(MODULE_PATH, 'w', encoding='utf-8') as f:
        f.write(updated_content)

    new_size = len(updated_content)
    size_diff = new_size - len(original_content)
    new_lines = updated_content.count('\n')

    print(f"   [OK] Module updated successfully")
    print(f"   Old size: {len(original_content)} characters")
    print(f"   New size: {new_size} characters ({size_diff:+d})")
    print(f"   New lines: {new_lines}")
    print()

    print("=" * 70)
    print("Integration Complete!")
    print("=" * 70)
    print()
    print("Next steps:")
    print("1. Test module loading: Import-Module (should export 126 functions)")
    print("2. Delete implementation files from project root")
    print("3. Create answer file entries")
    print("4. Run Test111 validation")
    print()

if __name__ == "__main__":
    main()
