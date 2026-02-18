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
    # Batch 6: Access Control Continuation
    "V-222453": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.",
        "discuss": "6781876214411749a653adddcd1894d9",
        "check":   "67c6a04f9dd3e4b9e8a28a4670e5bcfe",
        "fix":     "30a9cb4c2502bd73389ce24a42bc20f6",
    },
    "V-222454": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.",
        "discuss": "95ca92f92e802cda1c84a76178b3478d",
        "check":   "6865909887ac9aa9450ccbf8ca299b5c",
        "fix":     "904886778409509da0ccdf83d6379ab6",
    },
    "V-222455": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.",
        "discuss": "95ca92f92e802cda1c84a76178b3478d",
        "check":   "8662f7dc8ae7bd16febfd25c796de6d9",
        "fix":     "892492db4f8db9133cf843173778ac72",
    },
    "V-222456": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.",
        "discuss": "2b772c4e510d65ea8fc466d9bb3957cb",
        "check":   "48dc9b657f7b8e710cbf2df48906787e",
        "fix":     "0ca785ab4a3479d73d9908d910264674",
    },
    "V-222457": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.",
        "discuss": "95ca92f92e802cda1c84a76178b3478d",
        "check":   "7ee951a1e297373d63e7c0bba51b8099",
        "fix":     "4c81ed04ca36cc0ea241e9a94dfe9d1b",
    },
    "V-222458": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.",
        "discuss": "95ca92f92e802cda1c84a76178b3478d",
        "check":   "9ed1472f0b99de726793d594e861dcfa",
        "fix":     "e9a9d0d80b5af97e9df0dc39aa2e0fef",
    },
    "V-222459": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.",
        "discuss": "5d2899d9754a1f89269c6b52a6733299",
        "check":   "1366dce8e410dbcc72a974b5d1e22ba3",
        "fix":     "8c7e91fcb6d8f1ebdd937db201c86bbe",
    },
    "V-222460": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.",
        "discuss": "95ca92f92e802cda1c84a76178b3478d",
        "check":   "51d46862d55e241742cc99591c23c357",
        "fix":     "32429d96ab5dd4660525368744a6c8ba",
    },
    "V-222461": {
        "title": "The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.",
        "discuss": "95ca92f92e802cda1c84a76178b3478d",
        "check":   "133530fadbd4486794bf0d4378350677",
        "fix":     "7b0dd854a88555c56670b69580a3bcb4",
    },
    "V-222462": {
        "title": "The application must generate audit records when successful/unsuccessful logon attempts occur.",
        "discuss": "c66e9db2b5290b2fb1a6fbeb91bd3224",
        "check":   "c881c8190d9d88fe649e813c2ee68270",
        "fix":     "49da3ff43e750a1dcff085237ceb32cd",
    },
    "V-222463": {
        "title": "The application must generate audit records for privileged activities or other system-level access.",
        "discuss": "9c70a1f2ad145daed202c0512ad00601",
        "check":   "ed4890292c581e9f689f5accc1397078",
        "fix":     "c423678ed853559d7582ca7b1c509261",
    },
    "V-222464": {
        "title": "The application must generate audit records showing starting and ending time for user access to the system.",
        "discuss": "b857f1c30db00a785eb25311077190f8",
        "check":   "419b7edfdb215fd4578128de2b915680",
        "fix":     "c7a0804925e2548340da799b180e7793",
    },
    "V-222465": {
        "title": "The application must generate audit records when successful/unsuccessful accesses to objects occur.",
        "discuss": "6d377ba0588d13e5a581ed3d02bbc0a2",
        "check":   "6fa82f09798b6eb2714a5cb8c72857e5",
        "fix":     "ef2190d35959b471723125ba0d737b1c",
    },
    "V-222466": {
        "title": "The application must generate audit records for all direct access to the information system.",
        "discuss": "03eb93c2ad907626e47451424bd1f9b6",
        "check":   "2a42077e3ebe356b020d35fb40a99c2f",
        "fix":     "ec4163f7206a7072587538e411f730b0",
    },
    "V-222467": {
        "title": "The application must generate audit records for all account creations, modifications, disabling, and termination events.",
        "discuss": "ffa0ae05fe95d5980f0af7f79acd50c1",
        "check":   "72f08f3ce04f530c0601ad86dd454581",
        "fix":     "9413d73aea64fae9e5180bc3a468e0b3",
    },
    "V-222468": {
        "title": "The application must initiate session auditing upon startup.",
        "discuss": "4e1be28885f087f0ec3881729ba77493",
        "check":   "6755e757f48f4436eab3b202888ad88f",
        "fix":     "2bd25eec3b7a2c2c1c7e8c49f6259c3c",
    },
    "V-222469": {
        "title": "The application must log application shutdown events.",
        "discuss": "d7beb1ec48a4ac91d0f64bd1b95c3cd9",
        "check":   "460c305d22ab545b68d6796effc896f2",
        "fix":     "85741d16f09f57e6dfa4a9191a6d2b6e",
    },
    "V-222470": {
        "title": "The application must log destination IP addresses.",
        "discuss": "1bcedb8e16a94e2c52d64d6187d1198b",
        "check":   "c8b4757132e1497424c12016a62502a7",
        "fix":     "41eda77cf8ac03b2ad34d26f60e17929",
    },
    # Batch 7: Audit Record Generation & Logging
    "V-222471": {
        "title": "The application must log user actions involving access to data.",
        "discuss": "33c80554e60bd35889553f415b54e501",
        "check":   "1a67aee6f4328c89dae969c2e124f7aa",
        "fix":     "328a6620d65385da2a3b988762d7981b",
    },
    "V-222472": {
        "title": "The application must log user actions involving changes to data.",
        "discuss": "b28343d5a6f517ed385bc871558d666f",
        "check":   "12a63a95c8d5f026c7fc4adb1cf7e3d6",
        "fix":     "365d6fb05e6c216c1d0cbc6f4d7599ab",
    },
    "V-222473": {
        "title": "The application must produce audit records containing information to establish when (date and time) the events occurred.",
        "discuss": "fd522b67a11cc96b4983b78e8db83159",
        "check":   "27f9b35fb245da7b5fed0de230a69925",
        "fix":     "f5977b8fcd4514416043be6910e79093",
    },
    "V-222474": {
        "title": "The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.",
        "discuss": "e93e30565c11d376607ed1c969269e61",
        "check":   "55c21109659f9f92ea157bd6e534d7af",
        "fix":     "b2b239de08ecd4d7351349d0bc52b528",
    },
    "V-222475": {
        "title": "When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.",
        "discuss": "b6f5deae24af30df6cbc0e7493d2ac88",
        "check":   "038cdaa6943627d6edf401ac41ef6fa6",
        "fix":     "1c9c1f76dd6e6e4df9b5688316db72d2",
    },
    "V-222476": {
        "title": "The application must produce audit records that contain information to establish the outcome of the events.",
        "discuss": "19a9da26a724f728c51e3c41357b11b7",
        "check":   "b8bdaada5c4f55ac0ebc3cb1e3729116",
        "fix":     "8dbe61e742a7d4423f79de587445e8a6",
    },
    "V-222477": {
        "title": "The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.",
        "discuss": "d712b95ff652eca5c92e8654b00fb9bb",
        "check":   "033e1c9aad6a2fbd3b405e602998c630",
        "fix":     "9e996529e788d0fad6c540f3b362f064",
    },
    "V-222478": {
        "title": "The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.",
        "discuss": "9ec91aa9d8cf3ac909daa1c267839d52",
        "check":   "3a8382273ec2ff964c06b4629d3f9268",
        "fix":     "180fd092c80caec0c0ea24c31e8ca514",
    },
    "V-222479": {
        "title": "The application must implement transaction recovery logs when transaction based.",
        "discuss": "3647c0d3cb48c92e87e4004cc878b282",
        "check":   "d9ac9f7f13ca254e1e05f9ca97f8b680",
        "fix":     "23f7be94beffac18b37bda2d3640e199",
    },
    "V-222480": {
        "title": "The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.",
        "discuss": "d688ed0f6b86ff844ee19eff6a87daf0",
        "check":   "c5f26cac0577d56583ee8c00a5bcde5f",
        "fix":     "46251447e92e523d17ecda260c4112f1",
    },
    "V-222481": {
        "title": "The application must off-load audit records onto a different system or media than the system being audited.",
        "discuss": "a30dea26afcd82b61b65098d17a5326e",
        "check":   "0ff4830e28689502f22c84d5ae247857",
        "fix":     "f97b632758ad22203275aeeb95b8c3e2",
    },
    # Batch 8: Audit Record Management
    "V-222482": {
        "title": "The application must be configured to write application logs to a centralized log repository.",
        "discuss": "3c7551f6238fc6c9acd2598fa5ba1efe",
        "check":   "f3b2dcd12f783fd645f02c44d1cd63c8",
        "fix":     "7c956c8a59b9613eacda2bc94fe89ff1",
    },
    "V-222483": {
        "title": "The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.",
        "discuss": "927a2018cf0d9450dea797c27ae4053e",
        "check":   "bf68d2d85a34b868b0114b1fcf3b4a8b",
        "fix":     "b161b1b212bfacf3cb0ed2d9c838444a",
    },
    "V-222484": {
        "title": "Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.",
        "discuss": "b624e5de459bcf728d1bdd7a00ed6145",
        "check":   "3cec492f2310da9440922da27dd5396b",
        "fix":     "cc50f3950e2a131f2a5ae80f496b16e6",
    },
    "V-222485": {
        "title": "The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.",
        "discuss": "5a39f0c6247b9edd8f21b89e4427e1c1",
        "check":   "6164bc06fcf5dcac4071845d2f15ce4c",
        "fix":     "3e0ba992cd1c7061b66800425ee0da24",
    },
    "V-222486": {
        "title": "The application must shut down by default upon audit failure (unless availability is an overriding concern).",
        "discuss": "c618557aa8e0f8789de90abf2995f548",
        "check":   "5557dcf49bad8f148de334e9ab271947",
        "fix":     "59bc561fb5864b4e2583c21145b6d772",
    },
    "V-222487": {
        "title": "The application must provide the capability to centrally review and analyze audit records from multiple components within the system.",
        "discuss": "fe55418e288a172929fdbd395ea896a5",
        "check":   "dec48a5d9bee3c2f5309ce856835999b",
        "fix":     "a86fffb86332fd969662bd9cd8e9b7c7",
    },
    "V-222488": {
        "title": "The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.",
        "discuss": "ddff0c58e23626f0bc61b2fccccd0809",
        "check":   "350066bfba1f7fafd30b351e78b25407",
        "fix":     "311a93f02d3b42780431a144011535a1",
    },
    "V-222489": {
        "title": "The application must provide an audit reduction capability that supports on-demand reporting requirements.",
        "discuss": "ba9ac776e45398e3d1895055923e0ec6",
        "check":   "da0d4cbcc98c80de4721464514f5f788",
        "fix":     "c2308ed62e392ed814c1b11cfd3fdd1c",
    },
    "V-222490": {
        "title": "The application must provide an audit reduction capability that supports on-demand audit review and analysis.",
        "discuss": "11db7444bcdecea58bf404c41acfcfb6",
        "check":   "930d0a8b5680a21018e7c3216f1870ef",
        "fix":     "c391ae8e10b1ad7555190d91e7056f71",
    },
    "V-222491": {
        "title": "The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.",
        "discuss": "ed384143911d05627463a062c28bcce6",
        "check":   "a20284162b43aff723d4aa04b02d7658",
        "fix":     "4a981db9b2eeb898cf01096495f532d2",
    },
    "V-222492": {
        "title": "The application must provide a report generation capability that supports on-demand audit review and analysis.",
        "discuss": "4a1435a76f8c22334057d5814f070307",
        "check":   "57638e084c110cc4a382a7b17ded9d5f",
        "fix":     "f77f85abba606afe26ceae6a35d26f73",
    },
    "V-222493": {
        "title": "The application must provide a report generation capability that supports on-demand reporting requirements.",
        "discuss": "6834f15dca3ef029e92767f9fcec82eb",
        "check":   "18532bf8f30529c7cfbf5c5858746d79",
        "fix":     "c0c081fdf448515103a6920202da30cb",
    },
    "V-222494": {
        "title": "The application must provide a report generation capability that supports after-the-fact investigations of security incidents.",
        "discuss": "5f9c5fb281bf9a55b9f62193f9750c35",
        "check":   "268df1d295c6abb9fdfa6625070d13e9",
        "fix":     "b554c0ae1329f160f40229ff698a8721",
    },
    "V-222495": {
        "title": "The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.",
        "discuss": "2c4ec6f8b3d67bd76fafd292e7bc516f",
        "check":   "b19ef2c3170bd996016929cf2231dad7",
        "fix":     "e3ac71300ae7d04df488829b8f6f4cbc",
    },
    # Batch 9: Audit Info Protection, Software/Config Controls
    "V-222496": {
        "title": "The application must provide a report generation capability that does not alter original content or time ordering of audit records.",
        "discuss": "b021192ec72330b0b235331061ff3199",
        "check":   "88406ad90b75527a8010909eeb72572d",
        "fix":     "6f39e9e77dfab1aa90e7c53a403914fa",
    },
    "V-222497": {
        "title": "The applications must use internal system clocks to generate time stamps for audit records.",
        "discuss": "55a3afa30f6c5d93e0c2983fe0ef2173",
        "check":   "68efb84e309623cc736776ddc87a7917",
        "fix":     "1f2c995ec789f03dba320f716811901d",
    },
    "V-222498": {
        "title": "The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).",
        "discuss": "1d5c3b2a9667f8b464748a0b0ebdd65e",
        "check":   "514d005503d423cd96a40a4b779cb4c7",
        "fix":     "5c36d0cc3754bcc1e32fea94d1bb7956",
    },
    "V-222499": {
        "title": "The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.",
        "discuss": "0a30163cac234c41c66f54b25ce68676",
        "check":   "a91883a6b5925487bf0c9e0773da0f89",
        "fix":     "d7b582997a0436c68ad716f666f51052",
    },
    "V-222500": {
        "title": "The application must protect audit information from any type of unauthorized read access.",
        "discuss": "151079673680c49f42424673b58bf649",
        "check":   "116fb56a96b46d9a05096482673b5498",
        "fix":     "3880df6049bec69e56108723ae013bf2",
    },
    "V-222501": {
        "title": "The application must protect audit information from unauthorized modification.",
        "discuss": "bf7502e5ea6590b91dfaf18877a52578",
        "check":   "e873317113cdd86523fb85fd27ec9df9",
        "fix":     "779311bef390ecd6cfd9d8021db6e419",
    },
    "V-222502": {
        "title": "The application must protect audit information from unauthorized deletion.",
        "discuss": "e12e37873456113bfb7e09af25263339",
        "check":   "172e9a38d52cac1e019537bc431d085a",
        "fix":     "7c062529d064323493e464cb253ce5b9",
    },
    "V-222503": {
        "title": "The application must protect audit tools from unauthorized access.",
        "discuss": "ba93c676b66455a41d149f5152d48a95",
        "check":   "b0fd7b1a6c73ec0013009f23d8195567",
        "fix":     "c3a271d6ec87db572a9b96f028b961de",
    },
    "V-222504": {
        "title": "The application must protect audit tools from unauthorized modification.",
        "discuss": "6c3031d81aa53da54384f753775a3d75",
        "check":   "09a1119af66b3a9a453e194bcf2bbb55",
        "fix":     "64a7d66dc20524c13e5ebf77509e4d8f",
    },
    "V-222505": {
        "title": "The application must protect audit tools from unauthorized deletion.",
        "discuss": "c0c118294e4780766c380348445e1fda",
        "check":   "a6915186c388a85d6b435012e61c3ff5",
        "fix":     "ee2c62347a85f236eaacbd0099ab2dde",
    },
    "V-222506": {
        "title": "The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.",
        "discuss": "a2f1a3f67a56dc4a75e729d5567cf6e1",
        "check":   "371d4b88ff2052aed2fcd56a0ae523fb",
        "fix":     "e55630ffb867c0149faa42785cae8fc2",
    },
    "V-222507": {
        "title": "The application must use cryptographic mechanisms to protect the integrity of audit information.",
        "discuss": "4bf81d9a2757cf94213a9757b069d0be",
        "check":   "255281751417503019a8a803e24670b5",
        "fix":     "c9f35161e3ed840ff33dd7e252c27bbc",
    },
    "V-222508": {
        "title": "Application audit tools must be cryptographically hashed.",
        "discuss": "689bb2eba0fcab47a006b1f81fb7aa7f",
        "check":   "a38f0347967bff6dd2dd566a56701cc2",
        "fix":     "e82ed7411c4df98da3ff4e09abbe7809",
    },
    "V-222509": {
        "title": "The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.",
        "discuss": "32eda6139ff7e839d8dda422f56deb38",
        "check":   "e0ed1b2b3388455d6a33779635213d2a",
        "fix":     "83d8027b5d363cce76026142db26a0ea",
    },
    "V-222510": {
        "title": "The application must prohibit user installation of software without explicit privileged status.",
        "discuss": "0cd388157297f060089ddeb466739160",
        "check":   "0108877b746ed09358a0a7da0c969f9c",
        "fix":     "aa1f7b16ca9c14ca6d4b964f4c12af4b",
    },
    "V-222511": {
        "title": "The application must enforce access restrictions associated with changes to application configuration.",
        "discuss": "f10940838a7f688ad0efd79719cc9219",
        "check":   "084f5500c28054535885f36b774467e8",
        "fix":     "30d4ac338836b5e892323bda62a9819d",
    },
    "V-222512": {
        "title": "The application must audit who makes configuration changes to the application.",
        "discuss": "fae020bc9576634218419c4784e2d2a5",
        "check":   "f6c29e73eb806663b54414d805042d4d",
        "fix":     "bc586d96a75bd76e7406668d0da465a4",
    },
    "V-222513": {
        "title": "The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.",
        "discuss": "a987ae928889ab3ab1a120d324adaefe",
        "check":   "2605352e3b3494d63f3d82d678deede0",
        "fix":     "243f8a62905e652fb8871255a9f9f791",
    },
    "V-222514": {
        "title": "The applications must limit privileges to change the software resident within software libraries.",
        "discuss": "9aaec184bf245c3599310e6e3877821f",
        "check":   "7b9e4e1184a760884d3b8617092fb59f",
        "fix":     "17046744cde5735ac915d8258b76b53c",
    },
    "V-222515": {
        "title": "An application vulnerability assessment must be conducted.",
        "discuss": "cb2c9734ed8e25c06864d5c23f86030b",
        "check":   "58ed4ba396095339f87c1552a223584f",
        "fix":     "f39d2e14ddc3cdbe8aa5e48cd8102421",
    },
    "V-222516": {
        "title": "The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.",
        "discuss": "f0da000e810ed162a236e590d74ab360",
        "check":   "3b312aadc24aaa0822f59ad49c41dbdf",
        "fix":     "ccab5a6839626fd9b23b92c37da9d440",
    },
    "V-222517": {
        "title": "The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.",
        "discuss": "ebb94c60e0c63210725ba7cbc8046095",
        "check":   "3db9b69cdd1e97a20c4497a644becca7",
        "fix":     "b1c32083f64fa2abefe8979a1183edfa",
    },
    "V-222518": {
        "title": "The application must be configured to disable non-essential capabilities.",
        "discuss": "eb32d0a70b6e48ac07039f2e817b5d29",
        "check":   "47c694ae911c013a32e33d5535ee3941",
        "fix":     "b5bf0592b05cde05ee8e6a1db82aa375",
    },
    "V-222519": {
        "title": "The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.",
        "discuss": "23c0559d347e841de26360ffcbb9524c",
        "check":   "73e9ab41b619015f5898ed6527e6ac20",
        "fix":     "4a5351adb8f1eb1e304add863c741df4",
    },
    "V-222520": {
        "title": "The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.",
        "discuss": "518032ce9e84d41aedf553fecf25a935",
        "check":   "f23910675562107a9a3c1c9ba3d88cf2",
        "fix":     "3e2729976ebc4febfbf03245bfc3f05e",
    },
    "V-222521": {
        "title": "The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.",
        "discuss": "1761c7e158ce4795395f6155cc021834",
        "check":   "4efd5e60c5b503bf524d01f2dba60e72",
        "fix":     "12731d2d4c80d7732d683ad903558675",
    },
    # Batch 10: Authentication Methods (Phase 4)
    "V-222523": {
        "title": "The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.",
        "discuss": "e07cfd11e8c37311f4edc6b7dfbd66d7",
        "check":   "a50ae9ad0b59bcb3d23e5d5e48b79e40",
        "fix":     "00e55fce2b83b2e76820a2f3bc23f0a7",
    },
    "V-222524": {
        "title": "The application must accept Personal Identity Verification (PIV) credentials.",
        "discuss": "0f44bb6e82f2829bb8e9ef9e319f2f60",
        "check":   "6359f90d98f6ca75e34e3b38a966f8e8",
        "fix":     "35e8ef7ec4cff6aee50eb4e0a9dbe1d8",
    },
    "V-222525": {
        "title": "The application must electronically verify Personal Identity Verification (PIV) credentials.",
        "discuss": "0f44bb6e82f2829bb8e9ef9e319f2f60",
        "check":   "b77f9424fa2e5dea0bcaf49afd34d51f",
        "fix":     "35e8ef7ec4cff6aee50eb4e0a9dbe1d8",
    },
    "V-222526": {
        "title": "The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.",
        "discuss": "e07cfd11e8c37311f4edc6b7dfbd66d7",
        "check":   "ca366fbdb8f5bfa426a75e1f16ac2e24",
        "fix":     "1e77f1e9a8eb3fbc94e8fec99f7ba21a",
    },
    "V-222527": {
        "title": "The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.",
        "discuss": "55dd0951cc6684addbb55e7e6ca1d0ad",
        "check":   "4d2c879e56e7e7a53520ac7d2e6eedcf",
        "fix":     "b506dc5a24e91f5f8b6e460db7b3e80e",
    },
    "V-222528": {
        "title": "The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.",
        "discuss": "55dd0951cc6684addbb55e7e6ca1d0ad",
        "check":   "780d03c4300ee664800521bc46fe8154",
        "fix":     "7c37c5e004d0e058ad8b7c8031b33669",
    },
    "V-222529": {
        "title": "The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.",
        "discuss": "f39612da465c696e164b5d425883f0db",
        "check":   "d127e24c2c9594b7c2788c7e8118e82d",
        "fix":     "1111a4247e43932077236d8520f60f97",
    },
    "V-222530": {
        "title": "The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.",
        "discuss": "208fc895c02f64ea58c84964c1a8c036",
        "check":   "20dcf53bb77e3a8f28afed413995bf50",
        "fix":     "a898552982afa98cd15ec5657cd6b1b0",
    },
    "V-222531": {
        "title": "The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.",
        "discuss": "23c28b2d072d179cdf0da9f09e54bb03",
        "check":   "cd531057c7950d493d6a7b8d75130130",
        "fix":     "12c8a3439db7d05c1e60e5f0d9e582b3",
    },
    "V-222532": {
        "title": "The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.",
        "discuss": "2577b1f47c2657f2a443d73d10b457a0",
        "check":   "f516443c6be3ad622c419dda9d2018b0",
        "fix":     "3b9d09b4d0395d1ccd2a5c06d974b30b",
    },
    "V-222533": {
        "title": "The application must authenticate all network connected endpoint devices before establishing any connection.",
        "discuss": "8d16913c424573973ad0a290d751a653",
        "check":   "b21a12673a6fcdc9c9ec320c6e426318",
        "fix":     "c4b67db230e8e4219b0ef6537019582d",
    },
    "V-222534": {
        "title": "Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.",
        "discuss": "d4a0aa8e2ee8ef79467f5adbced237a2",
        "check":   "379bf6831b7f830480105517a3ee9599",
        "fix":     "bb70034d989bf84cd107307f3d6842b8",
    },
    "V-222535": {
        "title": "The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.",
        "discuss": "5a420f520fbe06bd2477442cd7239596",
        "check":   "6b8f3b2201f82f7a1356789527e07a1b",
        "fix":     "789c50175282309d32cdbd37040c98d3",
    },
    # Batch 11: Password Complexity (Phase 4)
    "V-222537": {
        "title": "The application must enforce password complexity by requiring that at least one uppercase character be used.",
        "discuss": "db6c9b9db71f6aa150eedc274a499e0b",
        "check":   "0b49493228f52600117c4eb372a90d96",
        "fix":     "d6feea4854e717830ea848388a81e9a6",
    },
    "V-222538": {
        "title": "The application must enforce password complexity by requiring that at least one lowercase character be used.",
        "discuss": "7d678efbbb88ff17e2d7cb83f40446ad",
        "check":   "9dc62e47cdd8a220a6a76cb2b2ee9fe7",
        "fix":     "c7ac931ddc32c7960633e03caa6a8977",
    },
    "V-222539": {
        "title": "The application must enforce password complexity by requiring that at least one numeric character be used.",
        "discuss": "7d678efbbb88ff17e2d7cb83f40446ad",
        "check":   "1410967244f344f336500e2b30136083",
        "fix":     "757be56b3292675e1d651446858c2c8b",
    },
    "V-222540": {
        "title": "The application must enforce password complexity by requiring that at least one special character be used.",
        "discuss": "7d678efbbb88ff17e2d7cb83f40446ad",
        "check":   "dafe6327b434463b9277d9ab9a59acfe",
        "fix":     "9ccdf4e55757ae20b3f68952984a9141",
    },
    "V-222541": {
        "title": "The application must require the change of at least eight of the total number of characters when passwords are changed.",
        "discuss": "7d678efbbb88ff17e2d7cb83f40446ad",
        "check":   "27300d11e6bf5ac35b88c41e3f80d3c0",
        "fix":     "13e59024059aca3abde5286fec379f2a",
    },
    "V-222544": {
        "title": "The application must enforce 24 hours/1 day as the minimum password lifetime.",
        "discuss": "098458d344563d01cb53ac0c15e70dbd",
        "check":   "71ce06309bda0f1447d841add6a77845",
        "fix":     "f9243295e8333da63ebb3ddce2968215",
    },
    "V-222545": {
        "title": "The application must enforce a 60-day maximum password lifetime restriction.",
        "discuss": "a9d56fed803a00b1e3c81b690ffa0a0b",
        "check":   "1e35f0792b91b744aee1697ad25c6489",
        "fix":     "8eb8d0e690466363d9f6c94b718d4427",
    },
    # Batch 12: Password Reuse, Temp Passwords, PKI, PIV, FICAM (Phase 5)
    "V-222546": {
        "title": "The application must prohibit password reuse for a minimum of five generations.",
        "discuss": "befa15d73ad29a202d859daf5f7a9c2f",
        "check":   "abd331e054af4ea614d91a918c247833",
        "fix":     "c538161433503d9de7fcff0d4ca92edd",
    },
    "V-222547": {
        "title": "The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.",
        "discuss": "4542d1e9c979c45b3c54d34ecf946eb5",
        "check":   "ba6332f90ff94933d23ff6ccb8562f5a",
        "fix":     "01bb5c706be1b48ad1abc7b6b76330fe",
    },
    "V-222548": {
        "title": "The application password must not be changeable by users other than the administrator or the user with which the password is associated.",
        "discuss": "183a1f902a615ac221b5787d4d1001f9",
        "check":   "884d1f59a4ab821dbb379c94662a635c",
        "fix":     "9d0628f3988616e87289cbd22a2d1dd1",
    },
    "V-222549": {
        "title": "The application must terminate existing user sessions upon account deletion.",
        "discuss": "c1ffbb0b84f98ee6fec1cc5ac14b6a40",
        "check":   "b0f72abc650542488c784310657a0944",
        "fix":     "0c1b5e79e5c05a80c59d61623399a0e6",
    },
    "V-222552": {
        "title": "The application must map the authenticated identity to the individual user or group account for PKI-based authentication.",
        "discuss": "c89714178f186a3e4ddfcfbc5a5012e2",
        "check":   "50f3e72239de7d96c1baff85f8476217",
        "fix":     "592fb6a95c1e1d5b77b9dff848028295",
    },
    "V-222553": {
        "title": "The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.",
        "discuss": "a472861fbb6f041e7e309cb1f2d3003d",
        "check":   "daddbbede83a97a1731f8ba1c3a23d4c",
        "fix":     "b855ccafae0edc9af2dc3622d2601e6a",
    },
    "V-222556": {
        "title": "The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).",
        "discuss": "862e4617b1d22f82edc9342afd4ab7f1",
        "check":   "dd03642c7d66e7fb33bf32b969121474",
        "fix":     "f6a9a9275adaaf4796e7c95f52ca50c3",
    },
    "V-222557": {
        "title": "The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.",
        "discuss": "1a94563f8e6a67e1c13d82ffa63c18dc",
        "check":   "1419c1a3cb720304388f7023526919f9",
        "fix":     "bfbe6054138f774666be8e493da402e4",
    },
    "V-222558": {
        "title": "The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.",
        "discuss": "0365090e92a389eb9f00c42b06795b96",
        "check":   "23644a8e2de30fac30c8eecd68e17a08",
        "fix":     "2157da5334614a2083b4acd2da46cbb1",
    },
    "V-222559": {
        "title": "The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.",
        "discuss": "71fe90010fc4ed3cb5cf7e7db7da762e",
        "check":   "fc5b60a233b8ef778d280891527e8feb",
        "fix":     "8df2bd4bee9f2042803ba040cebf793d",
    },
    "V-222560": {
        "title": "The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.",
        "discuss": "f1969e448f4b122dd4b1ab0e53e34874",
        "check":   "0e9d3984180d75e2bc515c0eb816bf30",
        "fix":     "158e627d18cc3ff03dde3dbfcf777ef9",
    },
    # Batch 13: Non-Local Maintenance, Race Conditions, FIPS, SAML, Cookies (Phase 5)
    "V-222561": {
        "title": "Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.",
        "discuss": "f150ef0e06a672c8ba14dcb640e44f83",
        "check":   "18d8b797a5bccd863e3de236a8ddb10d",
        "fix":     "31662d5235a0513592f7c58b36c9bb61",
    },
    "V-222562": {
        "title": "Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the integrity of non-local maintenance and diagnostic communications.",
        "discuss": "d0e458b76993a60fb347eeb63defe2b2",
        "check":   "76fd976b30ae5f5715da928696c0abfd",
        "fix":     "8a45bc1e4e0a17582e7386c466d5ed08",
    },
    "V-222563": {
        "title": "Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of non-local maintenance and diagnostic communications.",
        "discuss": "76f01cac2078026e6f8e7a2c4456a41f",
        "check":   "7718d6d4e0e4159dd444cb0adf94bf59",
        "fix":     "8a45bc1e4e0a17582e7386c466d5ed08",
    },
    "V-222564": {
        "title": "Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.",
        "discuss": "d1ae89470d44e3328fe0947e1ae83fd8",
        "check":   "b9790d47b6d510b12cc6bf1ba8c67848",
        "fix":     "40390845488ebd44db06ae08356e9081",
    },
    "V-222565": {
        "title": "The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.",
        "discuss": "590b1baf25194f7031e97cde9fdd0ffa",
        "check":   "32f017c5fc650e075b8f33c97782182a",
        "fix":     "44f9686ba85c23a2662a51aff10d2122",
    },
    "V-222566": {
        "title": "The application must terminate all sessions and network connections when nonlocal maintenance is completed.",
        "discuss": "e4e1cf722f8cc580ce6e6994ccec3fc4",
        "check":   "695c350b725a0651fa33f00671320f23",
        "fix":     "7ad0ba91ea5a7f6f51b109ed0722865b",
    },
    "V-222567": {
        "title": "The application must not be vulnerable to race conditions.",
        "discuss": "84032943e5d86a6c9870f4c807a011a8",
        "check":   "97f19680c3ebb53cfcb89513f7039811",
        "fix":     "c2683c915c4805801dd09e444c432a34",
    },
    "V-222568": {
        "title": "The application must terminate all network connections associated with a communications session at the end of the session.",
        "discuss": "721d692f500137d96d4d55a983391c4d",
        "check":   "583196ac49b8cf1a8a9d86aff7383d8d",
        "fix":     "01b5d01a3b865cc01f90dd69d6c8755d",
    },
    "V-222570": {
        "title": "The application must utilize FIPS-validated cryptographic modules when signing application components.",
        "discuss": "6136485331a55a51cd25a835f470ed53",
        "check":   "9ccb7420feabf4c9b91bc41c8360e272",
        "fix":     "f3170e325e548890aa516a925484fed4",
    },
    "V-222571": {
        "title": "The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.",
        "discuss": "9cb878c0a02cdbd8c2cc129d335145ea",
        "check":   "e0cf9683d216961be768ad8e5a400fc8",
        "fix":     "41c659f3d438748bc6063fce8c95cfbf",
    },
    "V-222572": {
        "title": "The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.",
        "discuss": "8543befe037eefc7a3b5d534735115ce",
        "check":   "f8375f67c74315860fd9e6b2061d9410",
        "fix":     "fff845939654a6e615e64bbe25e034f6",
    },
    "V-222573": {
        "title": "Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.",
        "discuss": "7d767b589f658d7cbc04cd4cc2d790b5",
        "check":   "729b89ecfa09bd88f8469ee28ff9cfbe",
        "fix":     "fff845939654a6e615e64bbe25e034f6",
    },
    "V-222574": {
        "title": "The application user interface must be either physically or logically separated from data storage and management interfaces.",
        "discuss": "74b10a8ada24230f420bc787a037a8c5",
        "check":   "f04743f82a956cca525170f6e0b1f5e8",
        "fix":     "33246abc1ed706d557cf8cd25d996436",
    },
    "V-222575": {
        "title": "The application must set the HTTPOnly flag on session cookies.",
        "discuss": "0522fc52516a823a55bad5a9c1e9e0f8",
        "check":   "382aa8b069ab5d5723e72852c89e62ee",
        "fix":     "52405614068cf3bd12afc55ced0f1efe",
    },
    "V-222576": {
        "title": "The application must set the secure flag on session cookies.",
        "discuss": "982655f0e0ffd57f0232943d540fdb88",
        "check":   "f6e3be19c510df2d9bafac05bdf4de28",
        "fix":     "6189517abe9975270a0db2bf28cd4b0a",
    },
    "V-222579": {
        "title": "Applications must use system-generated session identifiers that protect against session fixation.",
        "discuss": "86b0b2d43b14a8dd92a661761071a0eb",
        "check":   "ecd9c1412184e3ffdb36352229360407",
        "fix":     "70a349b3be57f79d8a052d190ab08284",
    },
    "V-222580": {
        "title": "Applications must validate session identifiers.",
        "discuss": "ac230309d08a711ac1b88f32ce141a73",
        "check":   "b51b3486b1ede9eadbb6e58071d406ac",
        "fix":     "8ba8d801e4476d62b22508daea5d5e5f",
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
