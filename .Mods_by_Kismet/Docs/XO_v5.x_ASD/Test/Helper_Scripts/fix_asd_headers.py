#!/usr/bin/env python3
"""
Fix function headers in Scan-XO_ASD_Checks.psm1:
1. Replace all-zero MD5 hashes with real values computed from XCCDF
2. Fix [STUB] Rule Titles in implemented functions

Usage: python fix_asd_headers.py
"""

import re

PSM1_PATH = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1"

# Real data from XCCDF (computed by compute_asd_header_hashes.py)
HEADER_DATA = {
    "V-222389": {
        "title": "The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.",
        "discuss": "d0684f408e9e8b715471acd160751f05",
        "check":   "62903c7da22f39c959b5661a54534d3b",
        "fix":     "056844e5c2c1ced7d3cc977a718f3d08",
    },
    "V-222390": {
        "title": "The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.",
        "discuss": "8168016c796c3991518b939dc35f6095",
        "check":   "b5abe7d5bd8eab0e239f037bef340c1c",
        "fix":     "c01465dab107bfdfba86d4468a2ddf73",
    },
    "V-222391": {
        "title": "Applications requiring user access authentication must provide a logoff capability for user initiated communication session.",
        "discuss": "2f173b2572b6d4add0e821b32b67f0fe",
        "check":   "906503b6183e39b56628360763377ba0",
        "fix":     "a31d0ba937e640ce790996781ebae235",
    },
    "V-222392": {
        "title": "The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.",
        "discuss": "c16c018a737e50f73ee97d7eb5f52b1b",
        "check":   "55528bf6d1b515df5a4a856276754b20",
        "fix":     "02b3613d2cfb42ce28fce465d80c4a39",
    },
    "V-222393": {
        "title": "The application must associate organization-defined types of security attributes with organization-defined security attribute values to information in storage.",
        "discuss": "7b86f51304113f7978d32303f641a685",
        "check":   "1d78ca3dfb0d644e9363d34b6f215cb0",
        "fix":     "d2e3ab582f82ee4dfe49b96f01b89646",
    },
    "V-222394": {
        "title": "The application must associate organization-defined types of security attributes with organization-defined security attribute values to information in process.",
        "discuss": "ca930f7cb4ed458b9ced3d6e2aae28a1",
        "check":   "b6a30c9623d35b182d2ea13f3c02dc3e",
        "fix":     "106e31028f679c484b8666e71c6ed972",
    },
    "V-222395": {
        "title": "The application must associate organization-defined types of security attributes with organization-defined security attribute values to information in transmission.",
        "discuss": "aaf140e94fbd628ddd539e6ca8556fb1",
        "check":   "e2b796d5af1f2794e7df6d655404ed8f",
        "fix":     "ced40f5eb04c8f2dbdfc95c284b86356",
    },
    "V-222396": {
        "title": "The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.",
        "discuss": "20f02d6bb54d4e28c9a5f00bdf9b0cd2",
        "check":   "f46dc7d7d0df9a6ba719ee7eeb7c669a",
        "fix":     "9f4a0239435b9767ab2c5734ade0ff7d",
    },
    "V-222397": {
        "title": "The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.",
        "discuss": "5c29b33b6468a89441fc6291646dd254",
        "check":   "f46dc7d7d0df9a6ba719ee7eeb7c669a",
        "fix":     "aa6887984a711e031c41d40698a55db7",
    },
    "V-222398": {
        "title": "Applications with SOAP messages requiring integrity must include the following message elements: Message ID and time stamp.",
        "discuss": "c451e633e44576800d9586bac7dd1121",
        "check":   "c072a1ceb15fe9181f1bd39046cc41f4",
        "fix":     "d30eed451593e44118357a99bbaf69af",
    },
    "V-222401": {
        "title": "The application must ensure each unique asserting party provides a unique identifier for each SAML assertion.",
        "discuss": "ba39d2e273ffc0981ca5cb93310c80b2",
        "check":   "83dacf8241dd5c022fe824b0b806696c",
        "fix":     "2c4e579566fa0cc31c2a4b08a13339a9",
    },
    "V-222402": {
        "title": "The application must ensure encrypted assertions, or equivalent confidentiality protections, are used when assertion data is transmitted across the network.",
        "discuss": "741ebd3a5500f194194711344c2b4683",
        "check":   "1fff19efb091e3aeb01b8db0097548e0",
        "fix":     "8211a5bc9a330b260424854c4c3efe62",
    },
    "V-222405": {
        "title": "The application must ensure if a OneTimeUse element is used in an assertion it is not used more than once within the defined window.",
        "discuss": "a10eaa42172588cc002fc2cb9c27a7d4",
        "check":   "73ecfed4fc205c0ae97a492cca57fc90",
        "fix":     "0ab0e1911a1d9d80b9b254ac73203770",
    },
    "V-222406": {
        "title": "The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.",
        "discuss": "3e2d11ced4aa3cae5eadb9d7710801e8",
        "check":   "8f25f376752771a9d34e7d5dcb41c4c7",
        "fix":     "38c9302f65cf87ba87881d753df3d5f8",
    },
    "V-222407": {
        "title": "The application must provide automated mechanisms for supporting account management functions.",
        "discuss": "507acc6a4b7f4f60e46bc18fb53a3da6",
        "check":   "62c7e4ab95e6cee671d868bbdbd12fd5",
        "fix":     "1ca6e082e034d0c477a615606a0aff42",
    },
    "V-222409": {
        "title": "The application must automatically remove or disable temporary user accounts after 72 hours.",
        "discuss": "21390efe291bc0aeb749a0f0a5030d63",
        "check":   "5c51feaf7c5c3a8b1a745be55871c3c8",
        "fix":     "87d07bd9d8eba6d234662d6bcdb71b38",
    },
    "V-222410": {
        "title": "The application must have a process, feature or function that prevents the emergency accounts from remaining active after 72 hours.",
        "discuss": "f5af95e214c3c2665dc87c8beb25daa9",
        "check":   "7ef31a550151bb4cc0cf8c3d0d03958e",
        "fix":     "bd22f04223eb9614f7b849c82df748a7",
    },
    "V-222411": {
        "title": "The application must automatically disable accounts after a 35 day period of account inactivity.",
        "discuss": "0a332090ad726d26fcaf74affa80c3b6",
        "check":   "e935e1c310fbcf84296f918bdc49db38",
        "fix":     "e754074a3730282c516ba7b96fa6fc50",
    },
    "V-222412": {
        "title": "Unnecessary application accounts must be disabled, or deleted.",
        "discuss": "910fbefa071f57cb5b0e89713139579d",
        "check":   "079f85fda1a6dadd48eb95d0b109f4c0",
        "fix":     "c5e0315ffb1a8e525e8db779863850da",
    },
    "V-222413": {
        "title": "The application must automatically audit account creation.",
        "discuss": "515c07e6d96273899a36448cce0360af",
        "check":   "926479b575136ea8014109f65de28bee",
        "fix":     "81ba6665a600ffaa0bcb4d90fdad52ae",
    },
    "V-222414": {
        "title": "The application must automatically audit account modification.",
        "discuss": "dfd3a2e681e434b6a58612199d215246",
        "check":   "db2bf383b84ed2696f4538952363d62e",
        "fix":     "9f52290d9ad9c900d8299271fae4f1b4",
    },
    "V-222415": {
        "title": "The application must automatically audit account disabling actions.",
        "discuss": "5f5d2ae8e0adfe7e68c1f105236b8028",
        "check":   "8d9789bc8bb8184885b0f4b0f7d10b9f",
        "fix":     "8b9d410bd64be3753dd49a238683edf6",
    },
    "V-222416": {
        "title": "The application must automatically audit account removal actions.",
        "discuss": "15abd8ea614062ec61f87d32041b5cdd",
        "check":   "cd2d59b2b1f8a1c95d3ec45644453746",
        "fix":     "2082dbbd0bbb941922d5344d418acc24",
    },
    "V-222417": {
        "title": "The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.",
        "discuss": "8dd31494138157e186bd3f69628dca9f",
        "check":   "8cf87bbb149401f73a69fe9ca32722c6",
        "fix":     "7c2a53166f77b683df4049d5de40e804",
    },
    "V-222418": {
        "title": "The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.",
        "discuss": "9a75fba922d8734c16c88fffaf17124d",
        "check":   "c474bbd20e477b2ff20ea6d0913f28fa",
        "fix":     "f2c6053229d11e0f06db8b2931d62601",
    },
    "V-222419": {
        "title": "The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.",
        "discuss": "8dd31494138157e186bd3f69628dca9f",
        "check":   "b808e3e13ee69eb97f66c286baf688cc",
        "fix":     "a18b7a8265993b35d4ea2e4d1885c8a6",
    },
    "V-222420": {
        "title": "The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.",
        "discuss": "cc0ef03e5e9ac4c6dd0949411cd7e52d",
        "check":   "cc2f0ab761f1dc762a9c91678102ce0c",
        "fix":     "99e6ba767d567651ab3625a09db9cdc1",
    },
    "V-222421": {
        "title": "The application must automatically audit account enabling actions.",
        "discuss": "4d4bf2aaadbde388507d38012ffc65eb",
        "check":   "8b788ef03d196c699c47619cb230199a",
        "fix":     "4ba850927f3f76b18d1ab545a8385687",
    },
    "V-222422": {
        "title": "The application must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.",
        "discuss": "346003eec5e8474d3e9a8098251de3e6",
        "check":   "5677abfd45f2040714515f4a9aabe211",
        "fix":     "044b3263eefbeac143c944322c8afbd5",
    },
    "V-222423": {
        "title": "Application data protection requirements must be identified and documented.",
        "discuss": "5c67990880167e6cc7baf5a0b1cdd496",
        "check":   "706ffa3b6904ebbea8ef7df4763fb425",
        "fix":     "3fd2412b1331bbe8c500a1ca17289d3a",
    },
    "V-222424": {
        "title": "The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.",
        "discuss": "2dd41657a55096bddb593c3c6d6ef74f",
        "check":   "44f6936e7814d58b29ca5b9585242188",
        "fix":     "5ae868fcb2defda8c80abf207eb06cc4",
    },
    # Batch 4: Access Control & RBAC (V-222425, V-222430, V-222432 already implemented)
    "V-222425": {
        "title": "The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        "discuss": "c8937c15ae7a86a2b55a0787bfb8f9e3",
        "check":   "87095229e086a884ca8afadd9954d47e",
        "fix":     "fc15d318ed4df676baaab220263b4314",
    },
    "V-222426": {
        "title": "The application must enforce organization-defined discretionary access control policies over defined subjects and objects.",
        "discuss": "6b5163ec9a0ab85852d981ecfbfaa422",
        "check":   "c7ab3271807eaff1b3b5be1f447f3a0c",
        "fix":     "f74dde4309979f77251b62c33376ffab",
    },
    "V-222427": {
        "title": "The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.",
        "discuss": "4786377fe9f1276d499eb7b4a4c3a3fc",
        "check":   "a82ae9bead764bae6b856cac79b42ade",
        "fix":     "0b145f6e4df0c8eeef1256e0c62870d4",
    },
    "V-222428": {
        "title": "The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.",
        "discuss": "4786377fe9f1276d499eb7b4a4c3a3fc",
        "check":   "1ed5f3f0ef295e6001d2d2f84886d9aa",
        "fix":     "0b145f6e4df0c8eeef1256e0c62870d4",
    },
    "V-222429": {
        "title": "The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.",
        "discuss": "ae3006fcea7446c656c31d5405683307",
        "check":   "4bc624cef64ad231a4a021b9252b4abd",
        "fix":     "708d6e9f451f5b9403378de78290dd72",
    },
    "V-222430": {
        "title": "The application must execute without excessive account permissions.",
        "discuss": "1c1dd4fcade7baaaaa322238711c4d0b",
        "check":   "983a1a15d18cff98a889efcd76b38d2e",
        "fix":     "18f8936df2a4c6c82bcf65c4675000ce",
    },
    "V-222431": {
        "title": "The application must audit the execution of privileged functions.",
        "discuss": "0cd47b539c4419c29fe0f6129f158649",
        "check":   "9d386c9600e3cef7328d0a11a3e2c8db",
        "fix":     "daef81a9341692f8ee1f7dbc76b8a218",
    },
    "V-222432": {
        "title": "The application must enforce the limit of three consecutive invalid login attempts by a user during a 15 minute time period.",
        "discuss": "5d05eba9fcda3d0310a02706c4605881",
        "check":   "b06613cdfe5931a085b99c978eb9aee1",
        "fix":     "369f0b6662fef6bc7b7f7e801f420c22",
    },
    "V-222433": {
        "title": "The application administrator must follow an approved process to unlock locked user accounts.",
        "discuss": "af15f2b461bee552438151c7a457f007",
        "check":   "39fcd52ec9eced5e2289b4eb665eda3f",
        "fix":     "ae6cd45270af3db07a185c5229c6c010",
    },
    "V-222434": {
        "title": "The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.",
        "discuss": "e84a72e8b50cbc9635e228d9acb4c1e2",
        "check":   "e790c7854dc9f40feeefe4f51ac76383",
        "fix":     "064bc2cfb8f163bf2cc03557c4b2a267",
    },
    "V-222435": {
        "title": "The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.",
        "discuss": "d201e9f9f35898c1dcbaf349b8e204a5",
        "check":   "7fdce9747db2fdb8f08940f628182dd9",
        "fix":     "2f6673667e891a80c8bd4609de1643ba",
    },
    # Batch 5: Audit Record Generation & Non-Repudiation (V-222440 missing from XCCDF)
    "V-222436": {  # [CAT III]
        "title": "The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.",
        "discuss": "7957ea6cacbdec0926adb7afa4063c24",
        "check":   "e298960995f0df0e4e715fdfbf40a954",
        "fix":     "064bc2cfb8f163bf2cc03557c4b2a267",
    },
    "V-222437": {  # [CAT III]
        "title": "The application must display the time and date of the users last successful logon.",
        "discuss": "16ffa1fd87a2dccdd6b3f9e023e37750",
        "check":   "0b2ad7f6ba37645f8bb89aa1697e778a",
        "fix":     "2fb586f3f45b342a65f696c71ffb5462",
    },
    "V-222438": {  # [CAT II]
        "title": "The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.",
        "discuss": "f37bf69662a6b229cb5df1a30baea17a",
        "check":   "9059b86bc8dddf8e898e38b28c6ee34d",
        "fix":     "e1627c0424df0676f43a8a99ae79044e",
    },
    "V-222439": {  # [CAT II]
        "title": "For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.",
        "discuss": "a3b192ab5d8e75ceabad32f5ca739432",
        "check":   "080c946e5d592d1f64293fd465178bc5",
        "fix":     "b1f294bcde1f58fa415aad563aace3f9",
    },
    "V-222441": {  # [CAT II]
        "title": "The application must provide audit record generation capability for the creation of session IDs.",
        "discuss": "5790d425772d466d0291ac48ed48abc3",
        "check":   "b593d0f5208db2b1fbed5dbcd085a6ae",
        "fix":     "e4426adad94c0d615756a271c578a8c8",
    },
    "V-222442": {  # [CAT II]
        "title": "The application must provide audit record generation capability for the destruction of session IDs.",
        "discuss": "9667d25856ebbfa43ad2a0fffb583b16",
        "check":   "492d4c0e0c96650f148215b07da88658",
        "fix":     "95d06ded8b98077fbb15cc8e7978c663",
    },
    "V-222443": {  # [CAT II]
        "title": "The application must provide audit record generation capability for the renewal of session IDs.",
        "discuss": "80c66b34e3809f8528d3983a2cad211d",
        "check":   "dda68a00b04ba688f2517142f8b17f2f",
        "fix":     "aae087891b4c7ab157701dac2ac1e4d8",
    },
    "V-222444": {  # [CAT II]
        "title": "The application must not write sensitive data into the application logs.",
        "discuss": "3da3d7bd2ddc9c34af1fa474dec911d3",
        "check":   "41473c355242a8957f03e4ef5877a06c",
        "fix":     "cb70a3d25b96460276b7958c9e27e886",
    },
    "V-222445": {  # [CAT II]
        "title": "The application must provide audit record generation capability for session timeouts.",
        "discuss": "7161fec628d156cae8adb9a4cc52ba6f",
        "check":   "5b35585016b69ef3eba8a3ca4e426ec5",
        "fix":     "c80d6184d5009014786ccf1fc6446c92",
    },
    "V-222446": {  # [CAT II]
        "title": "The application must record a time stamp indicating when the event occurred.",
        "discuss": "9c8b676776f5ef871e07ad26be58859e",
        "check":   "e4521b6b1ef1630f38007a1ef9ee5e7f",
        "fix":     "e697aaacc570924a321cbb985abcf7a7",
    },
    "V-222447": {  # [CAT II]
        "title": "The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.",
        "discuss": "62ea43f7664115a70f55af0ccd978a50",
        "check":   "be51e4101f91e0a1f2477f890a4b20db",
        "fix":     "ad3cd17436f23f6d6a3d2febc412bb03",
    },
    "V-222448": {  # [CAT II]
        "title": "The application must provide audit record generation capability for connecting system IP addresses.",
        "discuss": "92ada8b550ad999ca0d5562a0b4f867f",
        "check":   "af628113d6864091f0d1d57ef7f394a1",
        "fix":     "aabd116a9a00eec2383be26345c44841",
    },
    "V-222449": {  # [CAT II]
        "title": "The application must record the username or user ID of the user associated with the event.",
        "discuss": "de135163f28d0339512862b177868180",
        "check":   "6a201c6c1f2e177540fd7f9d7c8ab2d3",
        "fix":     "a422a9124f451cce891074750efa63e7",
    },
    "V-222450": {  # [CAT II]
        "title": "The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.",
        "discuss": "8ab16e9049d6ee787495fc7d09d7e9ec",
        "check":   "eabadc2ced38e9ea7591396a0a49eea7",
        "fix":     "e347b435ea953807ef0ee8304691fc69",
    },
    "V-222451": {  # [CAT II]
        "title": "The application must generate audit records when successful/unsuccessful attempts to access security objects occur.",
        "discuss": "7ec12c83afb4c85a67622bb30b6ba4e5",
        "check":   "f65e456ff50283febe4b3d4437fdcf55",
        "fix":     "f614192dc28ad4cd3d988eb5abc61d52",
    },
    "V-222452": {  # [CAT II]
        "title": "The application must generate audit records when successful/unsuccessful attempts to access security levels occur.",
        "discuss": "5fab01a6004e5d5ea7a6dd2a79a7a0cd",
        "check":   "802613c5394978eb3cdc37a86c93b073",
        "fix":     "e7b611e6b679e7f45cf3cc436af7f8c4",
    },
}

def fix_header_block(text, vuln_id, data):
    """
    Find the header block for vuln_id and fix Rule Title and MD5 hashes.
    The header block looks like:
        Vuln ID    : V-222389
        STIG ID    : ...
        Rule ID    : ...
        Rule Title : <title>
        DiscussMD5 : <hash>
        CheckMD5   : <hash>
        FixMD5     : <hash>
    """
    # Pattern: from "Vuln ID    : V-222389" to the closing "#>"
    # We'll replace the Rule Title and MD5 lines within the header block

    count = 0

    # Fix Rule Title
    # Match "Rule Title : [anything including STUB]" within this function's block
    # We need to be careful to only update within the correct function
    # Strategy: find the function header block for this VulnID and do targeted replacement

    # Find the specific header block: between "Vuln ID    : V-XXXXXX" and "#>"
    vuln_pattern = re.escape(f"Vuln ID    : {vuln_id}")

    # Split text around the vuln_id occurrence
    match = re.search(vuln_pattern, text)
    if not match:
        print(f"  WARNING: Could not find header for {vuln_id}")
        return text, 0

    # Find the #> closing the description block (within ~20 lines after Vuln ID)
    block_start = match.start()
    block_end_match = re.search(r'#>', text[block_start:block_start + 1000])
    if not block_end_match:
        print(f"  WARNING: Could not find closing #> for {vuln_id}")
        return text, 0

    block_end = block_start + block_end_match.end()
    header_block = text[block_start:block_end]
    new_block = header_block

    # Fix Rule Title if it contains [STUB]
    if '[STUB]' in header_block:
        new_block = re.sub(
            r'Rule Title : \[STUB\] Application Security and Development STIG check',
            f'Rule Title : {data["title"]}',
            new_block
        )
        count += 1
        print(f"  Fixed [STUB] Rule Title for {vuln_id}")

    # Fix DiscussMD5 (replace any 32+ character hex string or all-zeros)
    new_block = re.sub(
        r'DiscussMD5 : [0-9a-f]{32,}',
        f'DiscussMD5 : {data["discuss"]}',
        new_block
    )
    # Fix CheckMD5
    new_block = re.sub(
        r'CheckMD5   : [0-9a-f]{32,}',
        f'CheckMD5   : {data["check"]}',
        new_block
    )
    # Fix FixMD5
    new_block = re.sub(
        r'FixMD5     : [0-9a-f]{32,}',
        f'FixMD5     : {data["fix"]}',
        new_block
    )

    if new_block != header_block:
        count += 1
        text = text[:block_start] + new_block + text[block_end:]

    return text, count


def main():
    print(f"Reading: {PSM1_PATH}")
    with open(PSM1_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    original_len = len(content)
    total_changes = 0

    for vuln_id, data in HEADER_DATA.items():
        new_content, changes = fix_header_block(content, vuln_id, data)
        if changes > 0:
            total_changes += changes
        content = new_content

    print(f"\nTotal header blocks updated: {total_changes}")
    print(f"Content length: {original_len} -> {len(content)} bytes")

    # Verify no more [STUB] in implemented functions (check just the Batch 1-3 range)
    # Also verify no more all-zero MD5 hashes in those functions
    stub_remaining = len(re.findall(r'V-22241[3-9]|V-22242[0-4]|V-22239[0-9]|V-22240[0-9]', content))
    zeros_remaining = content.count('00000000000000000000000000000000')
    print(f"Remaining zero-MD5 hashes (all functions): {zeros_remaining}")

    with open(PSM1_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nWritten: {PSM1_PATH}")
    print("Done.")


if __name__ == "__main__":
    main()
