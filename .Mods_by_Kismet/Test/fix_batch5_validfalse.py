"""
Fix Batch 5 answer file entries: add missing <ValidFalseStatus> and <ValidFalseComment>
elements to each <Answer> block for V-222436 through V-222452.

The update_batch5_answerfile.py script omitted these required schema elements.
"""
import re

AF_PATH = r'd:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml'

BATCH5_VULNIDS = [
    "V-222436", "V-222437", "V-222438", "V-222439",
    "V-222441", "V-222442", "V-222443", "V-222444", "V-222445",
    "V-222446", "V-222447", "V-222448", "V-222449", "V-222450",
    "V-222451", "V-222452",
]

with open(AF_PATH, 'r', encoding='utf-8') as f:
    content = f.read()

fixes = 0

for vid in BATCH5_VULNIDS:
    # Find the entire <Vuln> block for this VulnID
    vuln_pat = r'(<Vuln ID="' + re.escape(vid) + r'">.*?</Vuln>)'
    m = re.search(vuln_pat, content, re.DOTALL)
    if not m:
        print(f"NOT FOUND: {vid}")
        continue

    old_block = m.group(1)

    # In this block, find each </ValidTrueComment> immediately followed by whitespace + </Answer>
    # and insert the missing elements between them.
    # Pattern: </ValidTrueComment>\n      </Answer>
    # Replace:  </ValidTrueComment>\n        <ValidFalseStatus></ValidFalseStatus>\n        <ValidFalseComment></ValidFalseComment>\n      </Answer>

    new_block, n = re.subn(
        r'(</ValidTrueComment>)\s*\n(\s*</Answer>)',
        r'\1\n        <ValidFalseStatus></ValidFalseStatus>\n        <ValidFalseComment></ValidFalseComment>\n\2',
        old_block
    )

    if n > 0:
        content = content.replace(old_block, new_block, 1)
        fixes += n
        print(f"  {vid}: fixed {n} Answer block(s)")
    else:
        print(f"  {vid}: no pattern match (already fixed?)")

print(f"\nTotal fixes: {fixes}")

with open(AF_PATH, 'w', encoding='utf-8') as f:
    f.write(content)

print("Written successfully")
