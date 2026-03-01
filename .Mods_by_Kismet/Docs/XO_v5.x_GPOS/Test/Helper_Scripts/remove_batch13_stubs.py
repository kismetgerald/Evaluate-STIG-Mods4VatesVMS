#!/usr/bin/env python3
"""Remove stub answer file entries for Batch 13 VulnIDs.

These stubs were created during earlier sessions and are now superseded
by the comprehensive entries added by integrate_batch13_answerfile.py.
Only removes the FIRST occurrence of each VulnID (the stub), keeping
the second (the new comprehensive entry).
"""

import re
import sys

ANSWER_FILE = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

VULN_IDS = [
    "V-203711", "V-203712", "V-203713", "V-203715", "V-203716",
    "V-203717", "V-203721", "V-203750", "V-203751", "V-259333",
]


def main():
    with open(ANSWER_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    removed = 0
    for vid in VULN_IDS:
        # Find the first occurrence of this Vuln block
        pattern = rf'  <Vuln ID="{re.escape(vid)}">\s*\n(.*?\n)*?  </Vuln>\n'
        match = re.search(pattern, content)
        if match:
            # Only remove the FIRST occurrence
            # Check if there's a second one
            second = re.search(pattern, content[match.end():])
            if second:
                # Remove the first (stub), keep the second (new)
                content = content[:match.start()] + content[match.end():]
                removed += 1
                print(f"OK: Removed stub for {vid} (lines ~{content[:match.start()].count(chr(10))+1})")
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
