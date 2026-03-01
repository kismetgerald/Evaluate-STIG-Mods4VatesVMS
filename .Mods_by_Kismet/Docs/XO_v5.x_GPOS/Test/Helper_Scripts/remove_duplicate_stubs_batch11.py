#!/usr/bin/env python3
"""Remove duplicate stub entries for 5 VulnIDs that have both old (1-index NR) and new (2-index) entries."""

import re
import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# These 5 VulnIDs have both an old stub (1 index, Not_Reviewed) and new proper entry (2 indices)
DUPE_VULNS = ["V-203657", "V-203659", "V-203661", "V-203664", "V-203684"]

def main():
    with open(AF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    removed = 0
    for vid in DUPE_VULNS:
        # Find all Vuln blocks for this ID
        pattern = rf'(\s*<Vuln ID="{re.escape(vid)}">.*?</Vuln>)'
        matches = list(re.finditer(pattern, content, re.DOTALL))
        if len(matches) < 2:
            print(f"SKIP: {vid} — only {len(matches)} entry (no duplicate)")
            continue

        # Find the stub (has ExpectedStatus="Not_Reviewed" or only 1 Answer index)
        for m in matches:
            block = m.group(1)
            answer_count = block.count("<Answer ")
            if answer_count == 1 and "Not_Reviewed" in block:
                content = content.replace(block, "")
                removed += 1
                print(f"OK: Removed stub entry for {vid} (1-index Not_Reviewed)")
                break
        else:
            print(f"WARNING: Could not identify stub for {vid}")

    # Clean up any double blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)

    with open(AF_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nRemoved {removed}/5 stub entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED — {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
