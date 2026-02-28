#!/usr/bin/env python3
"""
Add diagnostic Details output to CHECK 4 "NOT DETECTED" blocks.

When Get-XOAuditPluginInfo returns Enabled=false, the Details field contains
the specific failure reason (token not found, REST API failure, plugin not
in response). This script adds that diagnostic line to all 22 occurrences
so the next test run reveals WHY detection failed.

Target pattern (before):
    $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    $FindingDetails += "  [INFO] No application-layer audit compensation available" + $nl

Target pattern (after):
    $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    $FindingDetails += "  Reason: $($xoAuditInfo.Details)" + $nl
    $FindingDetails += "  [INFO] No application-layer audit compensation available" + $nl
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

def main():
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    # Pattern: line with "NOT DETECTED" followed by line with "[INFO]"
    # We insert a diagnostic line between them
    old_pattern = (
        '$FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl\n'
        '        $FindingDetails += "  [INFO]'
    )
    new_pattern = (
        '$FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl\n'
        '        $FindingDetails += "  Reason: $($xoAuditInfo.Details)" + $nl\n'
        '        $FindingDetails += "  [INFO]'
    )

    count = content.count(old_pattern)
    if count == 0:
        print("ERROR: Pattern not found. Check module file.")
        sys.exit(1)

    new_content = content.replace(old_pattern, new_pattern)

    # Verify count
    verify_count = new_content.count('Reason: $($xoAuditInfo.Details)')

    with open(MODULE_PATH, "w", encoding="utf-8-sig") as f:
        f.write(new_content)

    print(f"SUCCESS: Added diagnostic Details line to {count} CHECK 4 blocks")
    print(f"Verification: {verify_count} 'Reason:' lines found in updated file")

    if count != 22:
        print(f"WARNING: Expected 22 occurrences, found {count}")

if __name__ == "__main__":
    main()
