#!/usr/bin/env python3
"""Remove duplicate stub answer file entries for Batch 17 VulnIDs.
Finds first occurrence (stub) when a second (new comprehensive) entry exists,
and removes the first occurrence only.
"""

import re
import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

VULN_IDS = [
    "V-203651", "V-203671", "V-203675", "V-203677", "V-203678",
    "V-203679", "V-203680", "V-203681", "V-263660", "V-263661",
]


def main():
    with open(AF_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    removed = 0
    for vid in VULN_IDS:
        pattern = re.compile(
            r'(\s*<Vuln ID="' + vid + r'">.*?</Vuln>)',
            re.DOTALL
        )
        matches = list(pattern.finditer(content))
        if len(matches) >= 2:
            # Remove first occurrence (stub), keep second (comprehensive)
            first = matches[0]
            content = content[:first.start()] + content[first.end():]
            removed += 1
            print(f"  [OK] {vid} - removed stub (1st of {len(matches)} occurrences)")
        elif len(matches) == 1:
            print(f"  [SKIP] {vid} - only 1 occurrence (already clean)")
        else:
            print(f"  [WARN] {vid} - not found in answer file")

    with open(AF_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"\nRemoved {removed}/10 stubs")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED - {e}")
        sys.exit(1)

    # Check for remaining duplicates
    dup_pattern = re.compile(r'<Vuln ID="(V-\d+)">')
    all_ids = dup_pattern.findall(content)
    seen = set()
    dups = set()
    for vid in all_ids:
        if vid in seen:
            dups.add(vid)
        seen.add(vid)
    if dups:
        print(f"WARNING: Duplicate VulnIDs remaining: {dups}")
    else:
        print("No duplicate VulnIDs detected")


if __name__ == "__main__":
    main()
