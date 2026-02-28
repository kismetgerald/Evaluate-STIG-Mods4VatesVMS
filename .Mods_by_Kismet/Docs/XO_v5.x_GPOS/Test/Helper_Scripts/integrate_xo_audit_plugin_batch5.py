#!/usr/bin/env python3
"""
Integrate XO Audit Plugin CHECK 4 into Batch 5 audit functions (10 functions).

Category A (9 functions): V-203604-V-203610, V-203619, V-203697
  - Adds CHECK 4 block with compensating control status logic

Category B (1 function): V-203670
  - Adds CHECK 4 block with informational-only note (no status change)

Insertion point: Before the final status determination block:
    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
    #---=== End Custom Code ===---#
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# Category A: event-specific detail messages for each VulnID
CATEGORY_A = {
    "V-203604": "event type recording via action and subject fields in audit records",
    "V-203605": "precise timestamps (Unix millisecond) in all audit records",
    "V-203606": "object identification in audit records linking actions to specific resources",
    "V-203607": "source identification via user, session, and IP address in audit records",
    "V-203608": "success/failure outcome tracking in all audit records",
    "V-203609": "full-text recording of administrative actions including parameters",
    "V-203610": "individual user identification via authenticated session tracking",
    "V-203619": "comprehensive event coverage including access, logon, account, and configuration changes",
    "V-203697": "privileged function execution recording via authenticated admin action tracking",
}

# Category B: partial coverage functions
CATEGORY_B = {
    "V-203670": "boot-time audit initialization (XO audit starts after application launch, not at OS boot)",
}

def build_check4_block(vuln_id, category, detail_msg):
    """Build the CHECK 4 PowerShell code block."""
    nl = "$nl"

    lines = []
    lines.append("")
    lines.append("    # Check 4: XO Audit Plugin (Application-Layer Auditing)")
    lines.append(f'    $FindingDetails += {nl} + "--- Check 4: XO Audit Plugin ---" + {nl}')
    lines.append("    $xoAuditInfo = Get-XOAuditPluginInfo")
    lines.append("    if ($xoAuditInfo.Enabled) {")
    lines.append(f'        $FindingDetails += "  XO Audit Plugin: ACTIVE" + {nl}')
    lines.append(f'        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + {nl}')
    lines.append(f'        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + {nl}')
    lines.append(f'        $FindingDetails += "  Token source: $($xoAuditInfo.TokenSource)" + {nl}')

    if category == "A":
        lines.append(f'        $FindingDetails += "  [PASS] XO Audit Plugin provides application-layer {detail_msg}" + {nl}')
        lines.append("        $xoAuditCompensates = $true")
    else:
        lines.append(f'        $FindingDetails += "  [INFO] XO Audit Plugin provides {detail_msg}" + {nl}')
        lines.append(f'        $FindingDetails += "  [INFO] Partial coverage only — this check requires OS-level boot-time audit" + {nl}')

    lines.append("    }")
    lines.append("    else {")
    lines.append(f'        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + {nl}')
    lines.append(f'        $FindingDetails += "  [INFO] No application-layer audit compensation available" + {nl}')

    if category == "A":
        lines.append("        $xoAuditCompensates = $false")

    lines.append("    }")
    lines.append(f'    $FindingDetails += {nl}')
    lines.append("")

    return "\n".join(lines)


def build_status_block(category):
    """Build the replacement status determination block."""
    if category == "A":
        return """    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
    elseif ($xoAuditCompensates) {
        $Status = "NotAFinding"
        $FindingDetails += "COMPENSATING CONTROL: While auditd is not active, the XO Audit Plugin" + $nl
        $FindingDetails += "provides application-layer auditing with hash chain integrity that" + $nl
        $FindingDetails += "satisfies this requirement for the Xen Orchestra application." + $nl
    }
    #---=== End Custom Code ===---#"""
    else:
        # Category B: no status change, just informational
        return """    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
    #---=== End Custom Code ===---#"""


def find_function_status_block(content, vuln_id):
    """Find the final status determination block for a given VulnID function.

    Returns (start_pos, end_pos) of the block to replace:
        if ($auditIssues -eq 0) {
            $Status = "NotAFinding"
        }
        #---=== End Custom Code ===---#
    """
    # Find function start
    func_name = "Get-" + vuln_id.replace("-", "")
    func_pattern = f"Function {func_name} " + "{"
    func_start = content.find(func_pattern)
    if func_start == -1:
        print(f"  WARNING: Function {func_name} not found!")
        return None, None

    # Find next function or end of file
    next_func = content.find("\nFunction Get-V", func_start + 1)
    if next_func == -1:
        func_end = len(content)
    else:
        func_end = next_func

    # Within this function, find the LAST occurrence of the status block
    func_body = content[func_start:func_end]

    # Pattern: "    if ($auditIssues -eq 0) {\n        $Status = \"NotAFinding\"\n    }\n    #---=== End Custom Code ===---#"
    status_pattern = '    if ($auditIssues -eq 0) {\n        $Status = "NotAFinding"\n    }\n    #---=== End Custom Code ===---#'

    # Find last occurrence within function
    last_pos = func_body.rfind(status_pattern)
    if last_pos == -1:
        print(f"  WARNING: Status block not found in {func_name}!")
        return None, None

    abs_start = func_start + last_pos
    abs_end = abs_start + len(status_pattern)

    return abs_start, abs_end


def main():
    print(f"Reading module: {MODULE_PATH}")
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    original_len = len(content)
    changes = 0

    # Process all functions (Category A first, then B)
    all_functions = {}
    for vid, msg in CATEGORY_A.items():
        all_functions[vid] = ("A", msg)
    for vid, msg in CATEGORY_B.items():
        all_functions[vid] = ("B", msg)

    # Process in reverse line order to avoid position shifts
    # First, find all positions
    positions = []
    for vid, (cat, msg) in all_functions.items():
        start, end = find_function_status_block(content, vid)
        if start is not None:
            positions.append((start, end, vid, cat, msg))

    # Sort by position (descending) so we replace from bottom to top
    positions.sort(key=lambda x: x[0], reverse=True)

    for start, end, vid, cat, msg in positions:
        check4_block = build_check4_block(vid, cat, msg)
        status_block = build_status_block(cat)

        # The replacement: insert CHECK 4 before status block, then replace status block
        old_text = content[start:end]
        new_text = check4_block + "\n" + status_block

        content = content[:start] + new_text + content[end:]
        changes += 1
        print(f"  [{cat}] {vid}: Inserted CHECK 4 + {'compensating' if cat == 'A' else 'informational'} status logic")

    if changes > 0:
        with open(MODULE_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        new_len = len(content)
        print(f"\nDone! {changes} functions updated.")
        print(f"File size: {original_len:,} -> {new_len:,} chars ({new_len - original_len:+,} chars)")
    else:
        print("\nNo changes made.")

    return changes


if __name__ == "__main__":
    changes = main()
    sys.exit(0 if changes > 0 else 1)
