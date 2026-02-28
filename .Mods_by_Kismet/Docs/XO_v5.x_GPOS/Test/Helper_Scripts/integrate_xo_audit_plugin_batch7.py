#!/usr/bin/env python3
"""
Integrate XO Audit Plugin CHECK 4 into Batch 7 audit functions (10 functions).

Category A (6 functions): V-203759, V-203760, V-203762, V-203763, V-203765, V-203766
Category B (1 function):  V-203674
Category C (3 functions): V-203761, V-203764, V-203767
"""

import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

CATEGORY_A = {
    "V-203759": "user login/logout event recording via authenticated session tracking",
    "V-203760": "user authentication event recording including login attempts and methods",
    "V-203762": "session termination event recording via logout and session cleanup tracking",
    "V-203763": "privilege escalation recording via admin action tracking in audit records",
    "V-203765": "user/group modification recording via account management action tracking",
    "V-203766": "permission modification recording via ACL and role change tracking",
}

CATEGORY_B = {
    "V-203674": "audit record generation at the application layer (does not cover OS-level audit tool protection)",
}

CATEGORY_C = {
    "V-203761": "session lock event monitoring",
    "V-203764": "privilege elevation failure monitoring",
    "V-203767": "unauthorized access attempt monitoring",
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
    elif category == "B":
        lines.append("    # Check 4: XO Audit Plugin (Application-Layer Auditing)")
        lines.append(f'    $FindingDetails += {nl} + "--- Check 4: XO Audit Plugin ---" + {nl}')
        lines.append("    $xoAuditInfo = Get-XOAuditPluginInfo")
        lines.append("    if ($xoAuditInfo.Enabled) {")
        lines.append(f'        $FindingDetails += "  XO Audit Plugin: ACTIVE" + {nl}')
        lines.append(f'        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + {nl}')
        lines.append(f'        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + {nl}')
        lines.append(f'        $FindingDetails += "  Token source: $($xoAuditInfo.TokenSource)" + {nl}')
        lines.append(f'        $FindingDetails += "  [INFO] XO Audit Plugin provides {detail_msg}" + {nl}')
        lines.append("    }")
        lines.append("    else {")
        lines.append(f'        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + {nl}')
        lines.append(f'        $FindingDetails += "  [INFO] No application-layer audit compensation available" + {nl}')
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
    for vid, msg in CATEGORY_B.items():
        all_functions[vid] = ("B", msg)
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
        labels = {"A": "compensating", "B": "partial", "C": "info-only"}
        print(f"  [{cat}] {vid}: Inserted CHECK 4 + {labels[cat]} status logic")

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
