#!/usr/bin/env python3
"""
Compute MD5 hashes for ASD STIG XCCDF Discussion/Check/Fix text
and extract Rule Titles for implemented functions.

Usage: python compute_asd_header_hashes.py
"""

import hashlib
import xml.etree.ElementTree as ET
import sys
import re

XCCDF_PATH = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\StigContent\U_ASD_STIG_V6R4_Manual-xccdf.xml"

# All implemented VulnIDs (Batches 1-9)
IMPLEMENTED_VULNIDS = [
    "V-222389", "V-222390", "V-222391", "V-222392", "V-222393",
    "V-222394", "V-222395", "V-222396", "V-222397", "V-222398",
    "V-222401", "V-222402", "V-222405", "V-222406", "V-222407",
    "V-222409", "V-222410", "V-222411", "V-222412",
    "V-222413", "V-222414", "V-222415", "V-222416", "V-222417",
    "V-222418", "V-222419", "V-222420", "V-222421", "V-222422",
    "V-222423", "V-222424",
    # Batch 4: Access Control & RBAC
    "V-222425", "V-222426", "V-222427", "V-222428", "V-222429",
    "V-222430", "V-222431", "V-222432", "V-222433", "V-222434",
    "V-222435",
    # Batch 5: Audit Record Generation & Non-Repudiation (V-222440 missing from XCCDF)
    "V-222436", "V-222437", "V-222438", "V-222439",
    "V-222441", "V-222442", "V-222443", "V-222444", "V-222445",
    "V-222446", "V-222447", "V-222448", "V-222449", "V-222450",
    "V-222451", "V-222452",
    # Batch 6: Access Control Continuation
    "V-222453", "V-222454", "V-222455", "V-222456", "V-222457",
    "V-222458", "V-222459", "V-222460", "V-222461", "V-222462",
    "V-222463", "V-222464", "V-222465", "V-222466", "V-222467",
    "V-222468", "V-222469", "V-222470",
    # Batch 7: Audit Record Generation & Logging
    "V-222471", "V-222472", "V-222473", "V-222474", "V-222475",
    "V-222476", "V-222477", "V-222478", "V-222479", "V-222480",
    "V-222481",
    # Batch 8: Audit Record Management
    "V-222482", "V-222483", "V-222484", "V-222485", "V-222486",
    "V-222487", "V-222488", "V-222489", "V-222490", "V-222491",
    "V-222492", "V-222493", "V-222494", "V-222495",
    # Batch 9: Audit Info Protection, Software/Config Controls
    "V-222496", "V-222497", "V-222498", "V-222499", "V-222500",
    "V-222501", "V-222502", "V-222503", "V-222504", "V-222505",
    "V-222506", "V-222507", "V-222508", "V-222509", "V-222510",
    "V-222511", "V-222512", "V-222513", "V-222514", "V-222515",
    "V-222516", "V-222517", "V-222518", "V-222519", "V-222520",
    "V-222521",
    # Batch 10: Authentication Methods (Phase 4)
    "V-222523", "V-222524", "V-222525", "V-222526", "V-222527",
    "V-222528", "V-222529", "V-222530", "V-222531", "V-222532",
    "V-222533", "V-222534", "V-222535",
    # Batch 11: Password Complexity (Phase 4)
    "V-222537", "V-222538", "V-222539", "V-222540", "V-222541",
    "V-222544", "V-222545",
    # Batch 12: Password Reuse, Temp Passwords, PKI, PIV, FICAM (Phase 5)
    "V-222546", "V-222547", "V-222548", "V-222549", "V-222552",
    "V-222553", "V-222556", "V-222557", "V-222558", "V-222559",
    "V-222560",
    # Batch 13: Non-Local Maintenance, Race Conditions, FIPS, SAML, Cookies (Phase 5)
    "V-222561", "V-222562", "V-222563", "V-222564", "V-222565",
    "V-222566", "V-222567", "V-222568", "V-222570", "V-222571",
    "V-222572", "V-222573", "V-222574", "V-222575", "V-222576",
    "V-222579", "V-222580",
    # Batch 14: Session IDs, Certificates, Data Protection (Phase 6)
    "V-222581", "V-222582", "V-222583", "V-222584", "V-222586",
    "V-222587", "V-222591", "V-222592",
    # Batch 15: DoS, HA, Transmission Security, Info Disclosure (Phase 6)
    "V-222593", "V-222594", "V-222595", "V-222597", "V-222598",
    "V-222599", "V-222600",
    # Batch 16: Input Validation, Error Handling, Security Functions (Phase 7)
    "V-222603", "V-222605", "V-222606", "V-222610", "V-222611",
    "V-222613", "V-222614", "V-222615", "V-222616", "V-222617",
    "V-222618", "V-222619",
    # Batch 17: Audit Retention, Vuln Testing, Design, CM (Phase 7)
    "V-222621", "V-222622", "V-222623", "V-222624", "V-222625",
    "V-222626", "V-222627", "V-222628", "V-222629", "V-222630",
    # Batch 18: CM, IPv6, HA, DR, Backup, Crypto (Phase 7)
    "V-222631", "V-222632", "V-222633", "V-222634", "V-222635",
    "V-222636", "V-222637", "V-222638", "V-222639", "V-222640",
    "V-222641",
]

def md5(text):
    if not text:
        return "d41d8cd98f00b204e9800998ecf8427e"  # MD5 of empty string
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def clean_text(text):
    """Normalize whitespace to match what NAVSEA tools use."""
    if text is None:
        return ""
    # Collapse all whitespace to single spaces, strip leading/trailing
    return re.sub(r'\s+', ' ', text).strip()

def get_all_text(elem):
    """Get all text content from element and its children."""
    parts = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        parts.append(get_all_text(child))
        if child.tail:
            parts.append(child.tail)
    return ''.join(parts)

def main():
    print(f"Parsing XCCDF: {XCCDF_PATH}")
    tree = ET.parse(XCCDF_PATH)
    root = tree.getroot()

    # Define namespaces
    ns = {
        'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
        'dc': 'http://purl.org/dc/elements/1.1/',
    }

    results = {}

    for group in root.iter('{http://checklists.nist.gov/xccdf/1.1}Group'):
        group_id = group.get('id', '')
        # group_id looks like "V-222389"
        vuln_id = group_id

        if vuln_id not in IMPLEMENTED_VULNIDS:
            continue

        rule = group.find('{http://checklists.nist.gov/xccdf/1.1}Rule')
        if rule is None:
            continue

        # Get Rule Title
        title_elem = rule.find('{http://checklists.nist.gov/xccdf/1.1}title')
        title = clean_text(get_all_text(title_elem)) if title_elem is not None else ""

        # Get Description (Discussion) - it's in the <description> element
        desc_elem = rule.find('{http://checklists.nist.gov/xccdf/1.1}description')
        discussion = ""
        if desc_elem is not None:
            raw = get_all_text(desc_elem)
            # XCCDF description may contain XML-like tags embedded as text
            # Strip them
            discussion = clean_text(re.sub(r'<[^>]+>', '', raw))

        # Get Check content
        check_content = ""
        for check in rule.findall('.//{http://checklists.nist.gov/xccdf/1.1}check-content'):
            check_content = clean_text(get_all_text(check))
            break

        # Get Fix text
        fix_text = ""
        for fix in rule.findall('{http://checklists.nist.gov/xccdf/1.1}fixtext'):
            fix_text = clean_text(get_all_text(fix))
            break

        results[vuln_id] = {
            'title': title,
            'discuss_md5': md5(discussion),
            'check_md5': md5(check_content),
            'fix_md5': md5(fix_text),
            'discuss_len': len(discussion),
            'check_len': len(check_content),
            'fix_len': len(fix_text),
        }

    # Print results
    print(f"\nFound {len(results)} matching VulnIDs\n")
    print(f"{'VulnID':<12} {'DiscussMD5':<34} {'CheckMD5':<34} {'FixMD5':<34} Title")
    print("-" * 160)
    for vid in IMPLEMENTED_VULNIDS:
        if vid in results:
            r = results[vid]
            title_short = r['title'][:60] + "..." if len(r['title']) > 60 else r['title']
            print(f"{vid:<12} {r['discuss_md5']:<34} {r['check_md5']:<34} {r['fix_md5']:<34} {title_short}")
        else:
            print(f"{vid:<12} {'NOT FOUND IN XCCDF':<34}")

    # Output PowerShell-style sed commands for easy patching
    print("\n\n# --- PowerShell patch commands ---")
    for vid in IMPLEMENTED_VULNIDS:
        if vid in results:
            r = results[vid]
            print(f"# {vid}: Title='{r['title'][:70]}'")
            print(f"#   DiscussMD5={r['discuss_md5']}  CheckMD5={r['check_md5']}  FixMD5={r['fix_md5']}")

if __name__ == "__main__":
    main()
