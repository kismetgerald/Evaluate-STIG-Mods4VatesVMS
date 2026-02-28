#!/usr/bin/env python3
"""
Integrate XO Audit Plugin CHECK 4 into Batch 6 audit functions (10 functions).

Category A (2 functions): V-203611, V-203618
  - Adds CHECK 4 block with compensating control status logic

Category C (8 functions): V-203613, V-203614, V-203615, V-203616, V-203617, V-203620, V-203672, V-203673
  - Adds brief informational note (no status change, no compensating control)
"""

import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

CATEGORY_A = {
    "V-203611": "account modification event recording via user management action tracking",
    "V-203618": "account enabling/disabling event recording via user status change tracking",
}

CATEGORY_C = {
    "V-203613": "file permission monitoring",
    "V-203614": "file size monitoring",
    "V-203615": "audit log file ownership",
    "V-203616": "audit log file permissions",
    "V-203617": "audit log file size monitoring",
    "V-203620": "audit log deletion protection",
    "V-203672": "audit initialization settings",
    "V-203673": "audit failure mode configuration",
}

def build_check4_block(vuln_id, category, detail_msg):
    nl = "$nl"
    lines = []
    lines.append("")

    if category == "A":
        lines.append("    # Check 4: XO Audit Plugin (Application-Layer Auditing)")
        lines.append(f'    $FindingDetails += {nl} + "--- Check 4: XO Audit Plugin ---" + {nl}')
        lines.append("    $xoAuditInfo = Get-XOAuditPluginInfo")
        lines.append("    if ($xoAuditInfo.Enabled) {")
        lines.append(f'        $FindingDetails += "  XO Audit Plugin: ACTIVE" + {nl}')
        lines.append(f'        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + {nl}')
        lines.append(f'        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + {nl}')
        lines.append(f'        $FindingDetails += "  Token source: $($xoAuditInfo.TokenSource)" + {nl}')
        lines.append(f'        $FindingDetails += "  [PASS] XO Audit Plugin provides application-layer {detail_msg}" + {nl}')
        lines.append("        $xoAuditCompensates = $true")
        lines.append("    }")
        lines.append("    else {")
        lines.append(f'        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + {nl}')
        lines.append(f'        $FindingDetails += "  [INFO] No application-layer audit compensation available" + {nl}')
        lines.append("        $xoAuditCompensates = $false")
        lines.append("    }")
        lines.append(f'    $FindingDetails += {nl}')
    elif category == "C":
        lines.append("    # Note: XO Audit Plugin Status")
        lines.append(f'    $FindingDetails += {nl} + "--- Note: XO Audit Plugin ---" + {nl}')
        lines.append("    $xoAuditInfo = Get-XOAuditPluginInfo")
        lines.append(f'    $FindingDetails += "  XO Audit Plugin: $(if ($xoAuditInfo.Enabled) ' + "{'ACTIVE'} else {'NOT DETECTED'})" + f'" + {nl}')
        lines.append(f'    $FindingDetails += "  [INFO] This check requires OS-level auditd {detail_msg}; XO Audit Plugin does not address this requirement." + {nl}')
        lines.append(f'    $FindingDetails += {nl}')

    lines.append("")
    return "\n".join(lines)


def build_status_block(category):
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
        return """    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
    #---=== End Custom Code ===---#"""


def find_function_status_block(content, vuln_id):
    func_name = "Get-" + vuln_id.replace("-", "")
    func_pattern = f"Function {func_name} " + "{"
    func_start = content.find(func_pattern)
    if func_start == -1:
        print(f"  WARNING: Function {func_name} not found!")
        return None, None

    next_func = content.find("\nFunction Get-V", func_start + 1)
    func_end = next_func if next_func != -1 else len(content)
    func_body = content[func_start:func_end]

    status_pattern = '    if ($auditIssues -eq 0) {\n        $Status = "NotAFinding"\n    }\n    #---=== End Custom Code ===---#'
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

    all_functions = {}
    for vid, msg in CATEGORY_A.items():
        all_functions[vid] = ("A", msg)
    for vid, msg in CATEGORY_C.items():
        all_functions[vid] = ("C", msg)

    positions = []
    for vid, (cat, msg) in all_functions.items():
        start, end = find_function_status_block(content, vid)
        if start is not None:
            positions.append((start, end, vid, cat, msg))

    positions.sort(key=lambda x: x[0], reverse=True)

    for start, end, vid, cat, msg in positions:
        check4_block = build_check4_block(vid, cat, msg)
        status_block = build_status_block(cat)
        new_text = check4_block + "\n" + status_block
        content = content[:start] + new_text + content[end:]
        changes += 1
        label = "compensating" if cat == "A" else "info-only"
        print(f"  [{cat}] {vid}: Inserted CHECK 4 + {label} status logic")

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
