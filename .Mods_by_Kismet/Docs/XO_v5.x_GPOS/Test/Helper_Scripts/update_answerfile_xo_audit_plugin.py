#!/usr/bin/env python3
"""
Update answer file comments for Category A audit functions to mention
XO Audit Plugin as a compensating control.

Adds text to:
- Index 1 (NotAFinding): Mention XO Audit Plugin as compensating control
- Index 2 (Open): Add XO Audit Plugin as alternative remediation path
"""

import re
import sys

ANSWER_FILE = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# All 18 Category A VulnIDs
CATEGORY_A_VULNS = [
    "V-203604", "V-203605", "V-203606", "V-203607", "V-203608",
    "V-203609", "V-203610", "V-203619", "V-203697",
    "V-203611", "V-203618",
    "V-203759", "V-203760", "V-203762", "V-203763", "V-203765", "V-203766",
    "V-203768",
]

# Text to append to Index 1 (NotAFinding) comments
NF_ADDITION = """

Note: If auditd is not installed, the Xen Orchestra Audit Plugin provides compensating application-layer auditing with cryptographic hash chain integrity. The plugin records all administrative actions including event type, timestamp, user identity, and action details via REST API, satisfying this requirement as a compensating control. See: https://docs.xen-orchestra.com/users#audit-log"""

# Text to append to Index 2 (Open) comments
OPEN_ADDITION = """

Alternative Compensating Control: If auditd installation is not feasible, enable the XO Audit Plugin (Settings &gt; Plugins &gt; audit) which provides application-layer audit records with hash chain integrity verification. The plugin records user actions, login events, permission changes, and configuration modifications. Ensure the API token is configured at /etc/xo-server/stig/api-token for automated scanning. See: https://docs.xen-orchestra.com/users#audit-log"""


def main():
    print(f"Reading answer file: {ANSWER_FILE}")
    with open(ANSWER_FILE, "r", encoding="utf-8-sig") as f:
        content = f.read()

    original_len = len(content)
    changes = 0

    for vuln_id in CATEGORY_A_VULNS:
        # Find the Vuln entry
        vuln_start = content.find(f'<Vuln ID="{vuln_id}">')
        if vuln_start == -1:
            print(f"  WARNING: {vuln_id} not found in answer file!")
            continue

        # Find the end of this Vuln entry
        vuln_end = content.find('</Vuln>', vuln_start)
        if vuln_end == -1:
            print(f"  WARNING: {vuln_id} - no closing </Vuln> tag!")
            continue

        vuln_section = content[vuln_start:vuln_end + len('</Vuln>')]

        # Check if already updated (idempotency)
        if "XO Audit Plugin" in vuln_section:
            print(f"  SKIP: {vuln_id} already has XO Audit Plugin reference")
            continue

        # Find Index 1 ValidTrueComment closing tag
        idx1_close = vuln_section.find('</ValidTrueComment>', 0)
        if idx1_close == -1:
            print(f"  WARNING: {vuln_id} - no Index 1 ValidTrueComment closing tag!")
            continue

        # Insert NF addition before Index 1 closing tag
        new_section = vuln_section[:idx1_close] + NF_ADDITION + vuln_section[idx1_close:]

        # Now find Index 2 ValidTrueComment closing tag (second occurrence)
        idx2_close = new_section.find('</ValidTrueComment>', idx1_close + len(NF_ADDITION) + len('</ValidTrueComment>') + 1)
        if idx2_close == -1:
            print(f"  WARNING: {vuln_id} - no Index 2 ValidTrueComment closing tag!")
            # Still apply Index 1 change
        else:
            # Insert Open addition before Index 2 closing tag
            new_section = new_section[:idx2_close] + OPEN_ADDITION + new_section[idx2_close:]

        # Replace in content
        content = content[:vuln_start] + new_section + content[vuln_end + len('</Vuln>'):]
        changes += 1
        print(f"  OK: {vuln_id} - Updated Index 1 (NF) and Index 2 (Open) comments")

    if changes > 0:
        with open(ANSWER_FILE, "w", encoding="utf-8") as f:
            f.write(content)
        new_len = len(content)
        print(f"\nDone! {changes} Vuln entries updated.")
        print(f"File size: {original_len:,} -> {new_len:,} chars ({new_len - original_len:+,} chars)")
    else:
        print("\nNo changes made.")

    return changes


if __name__ == "__main__":
    changes = main()
    sys.exit(0 if changes > 0 else 1)
