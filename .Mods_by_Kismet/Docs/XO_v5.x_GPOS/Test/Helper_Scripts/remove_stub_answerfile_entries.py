#!/usr/bin/env python3
"""
Remove stub answer file entries for Batch 9 VulnIDs.
Stubs have ExpectedStatus="Not_Reviewed" — we keep the new entries
that have ExpectedStatus="NotAFinding"/"Open".
"""

import re
import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

BATCH9_VULNS = [
    "V-203622", "V-203623", "V-203624", "V-203639", "V-203640",
    "V-203641", "V-203642", "V-203643", "V-203644", "V-203729"
]

def main():
    with open(AF_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    removed = 0
    for vuln_id in BATCH9_VULNS:
        # Find stub entries (contain ExpectedStatus="Not_Reviewed")
        # Pattern: <Vuln ID="V-XXXXXX">...</Vuln> containing Not_Reviewed
        pattern = rf'  <Vuln ID="{vuln_id}">.*?</Vuln>\n'
        matches = list(re.finditer(pattern, content, re.DOTALL))

        if len(matches) >= 2:
            # Find the stub (has Not_Reviewed) and remove it
            for match in matches:
                block = match.group(0)
                if "Not_Reviewed" in block and "NotAFinding" not in block:
                    content = content.replace(block, "", 1)
                    removed += 1
                    print(f"  Removed stub entry for {vuln_id}")
                    break
        elif len(matches) == 1:
            print(f"  {vuln_id}: Only 1 entry found (checking if stub)")

    with open(AF_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"\nRemoved {removed} stub entries")


if __name__ == "__main__":
    main()
