#!/usr/bin/env python3
"""Update Batch 3 answer file entries from single-index stubs to 2-index entries."""

import re
import sys
import xml.etree.ElementTree as ET

ANSWER_FILE = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Batch 3 entries: VulnID -> (NF_Comment, Open_Comment)
BATCH3 = {
    "V-203625": (
        "The system enforces password complexity requiring at least one uppercase character. The pwquality.conf ucredit setting is configured to -1 or less, requiring a minimum of one uppercase letter. The pam_pwquality module is loaded in the PAM stack via /etc/pam.d/common-password, and the libpam-pwquality package is installed. This configuration meets the STIG requirement for uppercase character enforcement in passwords.",
        "The system does not enforce at least one uppercase character in passwords. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Set ucredit = -1 in /etc/security/pwquality.conf. 3) Ensure pam_pwquality is loaded in /etc/pam.d/common-password with: password requisite pam_pwquality.so retry=3. 4) Verify with: grep ucredit /etc/security/pwquality.conf."
    ),
    "V-203626": (
        "The system enforces password complexity requiring at least one lowercase character. The pwquality.conf lcredit setting is configured to -1 or less, requiring a minimum of one lowercase letter. The pam_pwquality module is loaded in the PAM stack via /etc/pam.d/common-password, and the libpam-pwquality package is installed.",
        "The system does not enforce at least one lowercase character in passwords. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Set lcredit = -1 in /etc/security/pwquality.conf. 3) Ensure pam_pwquality is loaded in /etc/pam.d/common-password with: password requisite pam_pwquality.so retry=3. 4) Verify with: grep lcredit /etc/security/pwquality.conf."
    ),
    "V-203627": (
        "The system enforces password complexity requiring at least one numeric character. The pwquality.conf dcredit setting is configured to -1 or less, requiring a minimum of one digit. The pam_pwquality module is loaded in the PAM stack via /etc/pam.d/common-password, and the libpam-pwquality package is installed.",
        "The system does not enforce at least one numeric character in passwords. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Set dcredit = -1 in /etc/security/pwquality.conf. 3) Ensure pam_pwquality is loaded in /etc/pam.d/common-password with: password requisite pam_pwquality.so retry=3. 4) Verify with: grep dcredit /etc/security/pwquality.conf."
    ),
    "V-203628": (
        "The system requires at least 50 percent of characters to be different when passwords are changed. The pwquality.conf difok setting is configured to 8 or greater (50% of 15-character minimum), and the pam_pwquality module is loaded in the PAM stack. This ensures password changes are sufficiently different from previous passwords.",
        "The system does not require sufficient character changes when passwords are modified. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Set difok = 8 in /etc/security/pwquality.conf (50% of 15-character DoD minimum). 3) Ensure pam_pwquality is loaded in /etc/pam.d/common-password. 4) Verify with: grep difok /etc/security/pwquality.conf."
    ),
    "V-203631": (
        "The system enforces a minimum password lifetime of 24 hours (1 day). The /etc/login.defs PASS_MIN_DAYS is set to 1 or greater, and per-user settings verified via chage confirm all interactive users have a minimum password age of at least 1 day. This prevents rapid password cycling to defeat password history requirements.",
        "The system does not enforce a 24-hour minimum password lifetime. To remediate: 1) Set PASS_MIN_DAYS 1 in /etc/login.defs for new accounts. 2) For existing users, run: chage --mindays 1 [username]. 3) Verify global setting: grep PASS_MIN_DAYS /etc/login.defs. 4) Verify per-user: chage -l [username] | grep Minimum."
    ),
    "V-203632": (
        "The system enforces a maximum password lifetime of 60 days. The /etc/login.defs PASS_MAX_DAYS is set to 60 or less, and per-user settings verified via chage confirm all interactive users have a maximum password age within the 60-day limit. This ensures passwords are changed periodically to reduce compromise risk.",
        "The system does not enforce a 60-day maximum password lifetime. To remediate: 1) Set PASS_MAX_DAYS 60 in /etc/login.defs for new accounts. 2) For existing users, run: chage --maxdays 60 [username]. 3) Verify global setting: grep PASS_MAX_DAYS /etc/login.defs. 4) Verify per-user: chage -l [username] | grep Maximum."
    ),
    "V-203634": (
        "The system enforces a minimum 15-character password length. The pwquality.conf minlen setting is configured to 15 or greater, and the pam_pwquality module is loaded in the PAM stack. This meets the DoD requirement for minimum password length, increasing resistance to brute-force attacks.",
        "The system does not enforce a minimum 15-character password length. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Set minlen = 15 in /etc/security/pwquality.conf. 3) Ensure pam_pwquality is loaded in /etc/pam.d/common-password. 4) Verify with: grep minlen /etc/security/pwquality.conf."
    ),
    "V-203676": (
        "The system enforces password complexity requiring at least one special character. The pwquality.conf ocredit setting is configured to -1 or less, requiring a minimum of one special character (e.g., ~ ! @ # $ % ^ *). The pam_pwquality module is loaded in the PAM stack, and the libpam-pwquality package is installed.",
        "The system does not enforce at least one special character in passwords. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Set ocredit = -1 in /etc/security/pwquality.conf. 3) Ensure pam_pwquality is loaded in /etc/pam.d/common-password with: password requisite pam_pwquality.so retry=3. 4) Verify with: grep ocredit /etc/security/pwquality.conf."
    ),
    "V-203778": (
        "The system prevents the use of dictionary words for passwords. The pwquality dictcheck feature is enabled (default value 1 in pwquality 1.4.4+), the pam_pwquality module is loaded in the PAM stack, and dictionary/wordlist files are available for password checking. This prevents users from selecting easily-guessable dictionary-based passwords.",
        "The system does not adequately prevent dictionary word passwords. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Ensure dictcheck = 1 in /etc/security/pwquality.conf (or leave at default). 3) Install dictionary: apt install cracklib-runtime wamerican. 4) Ensure pam_pwquality is loaded in /etc/pam.d/common-password. 5) Verify with: grep dictcheck /etc/security/pwquality.conf."
    ),
    "V-263653": (
        "The system verifies new passwords are not found on commonly-used or compromised password lists. The pwquality dictcheck feature is enabled, the pam_pwquality module is loaded in the PAM stack, and dictionary/wordlist files are available. This includes cracklib dictionaries that contain known compromised passwords, meeting the IA-5(1)(a) requirement.",
        "The system does not verify passwords against compromised password lists. To remediate: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Install cracklib with compromised password dictionaries: apt install cracklib-runtime. 3) Ensure dictcheck = 1 in /etc/security/pwquality.conf. 4) Optionally configure dictpath for a custom compromised password list. 5) Ensure pam_pwquality is loaded in /etc/pam.d/common-password. 6) Verify with: grep -E 'dictcheck|dictpath' /etc/security/pwquality.conf."
    ),
}

def update_answer_file():
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    for vuln_id, (nf_comment, open_comment) in BATCH3.items():
        # Match the entire Vuln block including all its content
        pattern = rf'(<Vuln ID="{re.escape(vuln_id)}">)(.*?)(</Vuln>)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            print(f"WARNING: Could not find entry for {vuln_id}")
            continue

        # Build replacement with proper 2-index structure
        replacement = f'''<Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding">
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open">
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''

        content = content[:match.start()] + replacement + content[match.end():]
        print(f"Updated {vuln_id}")

    with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    # Validate XML
    try:
        tree = ET.parse(ANSWER_FILE)
        root = tree.getroot()
        vuln_count = len(root.findall('.//Vuln'))
        print(f"\nXML Validation: PASSED ({vuln_count} Vuln entries)")
    except ET.ParseError as e:
        print(f"\nXML Validation: FAILED - {e}")
        sys.exit(1)

if __name__ == '__main__':
    update_answer_file()
