#!/usr/bin/env python3
"""Batch 16 answer file integration — adds 2-index entries for 10 VulnIDs."""

import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

ENTRIES = {
    "V-203783": {
        "nf_comment": "DOCUMENTATION: Home directory permissions have been verified to restrict non-privileged user access. Home directories use permissions of 0750 or more restrictive, HOME_MODE is configured in /etc/login.defs, and USERGROUPS_ENAB ensures private user groups. Non-privileged users cannot grant other users direct access to their home directory contents. UMASK settings enforce appropriate default permissions on new files and directories.",
        "open_comment": "FINDING: Home directory permissions may allow excessive access by non-privileged users. REMEDIATION: 1) Set HOME_MODE to 0750 in /etc/login.defs. 2) Set UMASK to 027 or more restrictive. 3) Fix existing home directories: chmod 0750 /home/*. 4) Enable USERGROUPS_ENAB in /etc/login.defs for private user groups. 5) Verify no world-readable or world-writable home directories exist.",
    },
    "V-203784": {
        "nf_comment": "DOCUMENTATION: Application firewall is enabled and active on this system. UFW (Uncomplicated Firewall) or iptables/nftables rules are configured to control inbound and outbound network traffic. Firewall rules restrict access to authorized services only. For XOA deployments, UFW is enabled by default. For XOCE deployments, the firewall has been manually configured per organizational security requirements.",
        "open_comment": "FINDING: No active application firewall detected on the system. REMEDIATION: 1) Install UFW: apt install ufw. 2) Enable UFW: ufw enable. 3) Configure default deny policy: ufw default deny incoming. 4) Allow required services: ufw allow ssh, ufw allow 443/tcp. 5) Verify firewall status: ufw status verbose. 6) For XOA, UFW should be enabled by default - verify it has not been disabled.",
    },
    "V-263650": {
        "nf_comment": "DOCUMENTATION: System accounts are properly locked and organizational procedures exist to disable accounts no longer associated with a user. SSSD or LDAP/AD integration provides centralized account lifecycle management. The INACTIVE parameter in /etc/default/useradd ensures accounts are disabled after a period of inactivity. Regular account reviews are performed per organizational policy.",
        "open_comment": "FINDING: Account lifecycle management requires organizational verification. REMEDIATION: 1) Set INACTIVE in /etc/default/useradd (e.g., INACTIVE=35). 2) Lock system accounts: passwd -l &lt;account&gt;. 3) Implement centralized account management via SSSD/LDAP/AD. 4) Establish procedures to review accounts quarterly. 5) Implement automated account disabling for separated personnel within 72 hours. 6) Document account lifecycle procedures in System Security Plan.",
    },
    "V-263651": {
        "nf_comment": "DOCUMENTATION: Unauthorized hardware components are prohibited through modprobe blacklisting, USB storage restrictions, and organizational hardware authorization policies. The usb_storage kernel module is blacklisted in /etc/modprobe.d/. Only approved PCI and USB devices are connected. Hardware inventory is maintained and verified against the approved hardware list.",
        "open_comment": "FINDING: Hardware authorization policy requires organizational verification. REMEDIATION: 1) Blacklist USB storage: echo 'blacklist usb_storage' &gt; /etc/modprobe.d/usb-storage.conf. 2) Blacklist thunderbolt if not needed: echo 'blacklist thunderbolt' &gt; /etc/modprobe.d/thunderbolt.conf. 3) Create and maintain an approved hardware inventory list. 4) Implement USBGuard for fine-grained USB device control. 5) Document hardware authorization procedures in System Security Plan.",
    },
    "V-263652": {
        "nf_comment": "DOCUMENTATION: Multifactor authentication is implemented for local, network, and remote access to both privileged and non-privileged accounts. PAM is configured with MFA modules (pam_pkcs11 for smart card, pam_u2f for hardware tokens, or pam_duo for push-based MFA). SSH is configured to require multiple authentication methods. XO integrates with LDAP/AD which enforces MFA through the directory service.",
        "open_comment": "FINDING: Multifactor authentication is not fully implemented. REMEDIATION: 1) Install smart card packages: apt install opensc pcscd libpam-pkcs11. 2) Configure PAM for MFA in /etc/pam.d/common-auth. 3) Set SSH AuthenticationMethods to require two factors: publickey,keyboard-interactive. 4) Integrate XO with LDAP/AD that enforces MFA. 5) Deploy CAC/PIV readers for DoD smart card authentication. 6) Document MFA implementation in System Security Plan.",
    },
    "V-263654": {
        "nf_comment": "DOCUMENTATION: Password-based authentication is configured to require immediate selection of a new password upon account recovery. The chage utility enforces password change at next login (chage -d 0). PAM pwquality module ensures new passwords meet complexity requirements. LDAP/AD integration delegates password recovery to the directory service which enforces immediate password change.",
        "open_comment": "FINDING: Password recovery procedures require organizational verification. REMEDIATION: 1) After account recovery, force password change: chage -d 0 &lt;username&gt;. 2) Document password recovery procedures requiring immediate new password selection. 3) Ensure temporary passwords expire at first use. 4) Log all password recovery actions for audit trail. 5) If using LDAP/AD, verify the directory service enforces immediate password change on recovery.",
    },
    "V-263655": {
        "nf_comment": "DOCUMENTATION: The system supports user selection of long passwords and passphrases including spaces and all printable characters. The password hashing algorithm (SHA-512 or yescrypt) supports passwords of any practical length. PAM does not impose character restrictions. Linux accepts all printable ASCII characters including spaces in passwords by default.",
        "open_comment": "FINDING: Long password support could not be fully verified. REMEDIATION: 1) Set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs. 2) Ensure PAM pwquality minlen allows long passwords (minlen=15 minimum per DoD). 3) Do not set maxlen restrictions in pwquality.conf. 4) Verify PAM configuration does not restrict character sets. 5) Test that passwords with spaces and special characters are accepted.",
    },
    "V-263656": {
        "nf_comment": "DOCUMENTATION: Automated password complexity tools are installed and configured. The libpam-pwquality package provides password strength checking through PAM. Configuration in /etc/security/pwquality.conf enforces minimum length, character class requirements, and dictionary checks. PAM is configured to use pam_pwquality for password validation during password changes.",
        "open_comment": "FINDING: Automated password complexity tools are not fully configured. REMEDIATION: 1) Install libpam-pwquality: apt install libpam-pwquality. 2) Configure /etc/security/pwquality.conf: minlen=15, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1. 3) Enable in PAM: add 'password requisite pam_pwquality.so' to /etc/pam.d/common-password. 4) Install dictionary files: apt install wamerican. 5) Set dictcheck=1 in pwquality.conf for dictionary checking.",
    },
    "V-263657": {
        "nf_comment": "DOCUMENTATION: The system accepts only external credentials that are NIST-compliant. SSH host keys use approved algorithms (RSA 2048+, ECDSA, Ed25519). TLS certificates use NIST-approved signature algorithms. LDAP/AD integration ensures external credentials meet NIST SP 800-63 requirements. OpenSSL provides NIST-compliant cryptographic operations for credential validation.",
        "open_comment": "FINDING: NIST credential compliance requires organizational verification. REMEDIATION: 1) Configure SSH to use only NIST-approved key algorithms in /etc/ssh/sshd_config. 2) Ensure TLS certificates use RSA 2048+ or ECDSA P-256/P-384 keys. 3) Enable FIPS mode if required: install dracut-fips and configure kernel boot parameter fips=1. 4) Verify LDAP/AD credentials meet NIST SP 800-63 Digital Identity Guidelines. 5) Document NIST compliance in System Security Plan.",
    },
    "V-263659": {
        "nf_comment": "DOCUMENTATION: The system trust store contains only organization-approved trust anchors. The ca-certificates package is installed and managed through apt. Custom trust anchors in /usr/local/share/ca-certificates/ are approved by the organization. DoD root CA certificates are installed where required. Trust anchor management follows organizational change control procedures.",
        "open_comment": "FINDING: Trust anchor approval requires organizational verification. REMEDIATION: 1) Review all certificates in /etc/ssl/certs/. 2) Install DoD root CAs: download from https://militarycac.com/dodcerts.htm and place in /usr/local/share/ca-certificates/. 3) Run update-ca-certificates to rebuild trust store. 4) Remove any unauthorized or expired trust anchors. 5) Document approved trust anchors in System Security Plan. 6) Implement periodic trust anchor review process.",
    },
}


def main():
    with open(AF_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    insertion_point = content.rfind("</STIGComments>")
    if insertion_point == -1:
        print("ERROR: Could not find </STIGComments> tag")
        sys.exit(1)

    new_entries = ""
    for vuln_id, comments in ENTRIES.items():
        new_entries += f'''
  <Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{comments["nf_comment"]}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{comments["open_comment"]}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>
'''

    content = content[:insertion_point] + new_entries + content[insertion_point:]

    with open(AF_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"Integrated {len(ENTRIES)} answer file entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED - {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
