#!/usr/bin/env python3
"""Remove stub answer file entries for Batch 15 VulnIDs.

These stubs were created during earlier sessions and are now superseded
by the comprehensive entries added by integrate_batch15_answerfile.py.
Only removes the FIRST occurrence of each VulnID (the stub), keeping
the second (the new comprehensive entry).
"""

import re
import sys

ANSWER_FILE = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

VULN_IDS = [
    "V-203747", "V-203752", "V-203753", "V-203754", "V-203755",
    "V-203756", "V-203757", "V-203758", "V-203780", "V-203781",
]


def main():
    with open(ANSWER_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    removed = 0
    for vid in VULN_IDS:
        pattern = rf'  <Vuln ID="{re.escape(vid)}">\s*\n(.*?\n)*?  </Vuln>\n'
        match = re.search(pattern, content)
        if match:
            second = re.search(pattern, content[match.end():])
            if second:
                content = content[:match.start()] + content[match.end():]
                removed += 1
                print(f"OK: Removed stub for {vid}")
            else:
                print(f"SKIP: {vid} has only one entry (keeping it)")
        else:
            print(f"WARNING: {vid} not found")

    with open(ANSWER_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nRemoved {removed}/10 stub entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(ANSWER_FILE)
        print("XML validation: PASSED")
    except Exception as e:
        print(f"XML validation: FAILED - {e}")
        return 1

    # Verify no duplicates remain
    import collections
    vuln_ids = re.findall(r'<Vuln ID="(V-\d+)">', content)
    dupes = [vid for vid, count in collections.Counter(vuln_ids).items() if count > 1]
    if dupes:
        print(f"WARNING: Duplicate Vuln IDs still exist: {dupes}")
        return 1
    else:
        print("Duplicate check: PASSED (no duplicates)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
