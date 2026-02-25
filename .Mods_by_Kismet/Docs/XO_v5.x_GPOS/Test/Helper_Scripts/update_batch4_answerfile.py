#!/usr/bin/env python3
"""Update answer file with Batch 4 (SSH Configuration) entries.

Replaces 10 stub Vuln entries with proper 2-index (or 3-index for NA) entries.
"""

import re
import sys
import xml.etree.ElementTree as ET

ANSWER_FILE = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Batch 4 entries: (VulnID, RuleTitle, has_NA, NF_comment, Open_comment, NA_comment)
BATCH4 = [
    {
        "id": "V-203602",
        "title": "The operating system must monitor remote access methods.",
        "has_na": False,
        "nf_comment": "The automated check verified that remote access monitoring is properly configured on this Debian 12 system.\n\nEvidence found:\n(1) SSH LogLevel set to INFO or VERBOSE, ensuring all authentication events are logged\n(2) rsyslog auth facility configured to capture authentication and authorization events\n(3) /var/log/auth.log present with recent SSH session entries\n(4) Systemd journal recording SSH service events\n\nFinding: Not a Finding\n\nJustification: The system monitors all remote access methods through SSH logging at an appropriate verbosity level, syslog auth facility capture, and persistent log storage. This meets the GPOS SRG requirement to monitor remote access sessions for unauthorized activity detection.",
        "open_comment": "The automated check found deficiencies in remote access monitoring on this Debian 12 system.\n\nFindings:\n- SSH LogLevel may not be set to INFO or VERBOSE\n- rsyslog auth facility logging may not be configured\n- /var/log/auth.log may not contain SSH session events\n\nRemediation Steps:\n(1) Set SSH LogLevel to INFO or VERBOSE in /etc/ssh/sshd_config:\n    LogLevel VERBOSE\n(2) Ensure rsyslog captures auth events in /etc/rsyslog.conf:\n    auth,authpriv.* /var/log/auth.log\n(3) Restart services: systemctl restart ssh rsyslog\n(4) Verify logging: tail -f /var/log/auth.log during SSH login\n\nThe ISSO/ISSM must verify that remote access monitoring meets organizational requirements and that logs are reviewed regularly."
    },
    {
        "id": "V-203636",
        "title": "The operating system must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        "has_na": False,
        "nf_comment": "The automated check verified that access control mechanisms are properly enforced on this Debian 12 system.\n\nEvidence found:\n(1) SSH access restrictions configured (AllowUsers/AllowGroups/DenyUsers/DenyGroups)\n(2) Critical file permissions enforced (/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow)\n(3) sudo installed and configured for privilege escalation control\n(4) PAM access control rules present in /etc/security/access.conf\n\nFinding: Not a Finding\n\nJustification: The system enforces approved authorizations through SSH access restrictions, file permission enforcement, sudo privilege management, and PAM access control. This satisfies the GPOS SRG requirement for logical access control enforcement.",
        "open_comment": "The automated check found deficiencies in access control enforcement on this Debian 12 system.\n\nFindings:\n- No SSH AllowUsers/AllowGroups/DenyUsers/DenyGroups configured\n- sudo may not be installed or properly configured\n- PAM access control rules may not be active\n\nRemediation Steps:\n(1) Configure SSH access restrictions in /etc/ssh/sshd_config:\n    AllowGroups sshusers admins\n(2) Install and configure sudo: apt install sudo\n(3) Add access rules in /etc/security/access.conf:\n    + : root : LOCAL\n    + : admins : ALL\n    - : ALL : ALL\n(4) Enable pam_access in /etc/pam.d/common-auth\n(5) Restart SSH: systemctl restart ssh\n\nThe ISSO/ISSM must verify that access control policies align with organizational requirements."
    },
    {
        "id": "V-203637",
        "title": "The operating system must be configured to disable non-essential capabilities.",
        "has_na": False,
        "nf_comment": "The automated check verified that non-essential capabilities are disabled on this Debian 12 system.\n\nEvidence found:\n(1) SSH non-essential features disabled (X11Forwarding, AllowTcpForwarding, AllowAgentForwarding, PermitTunnel, GatewayPorts)\n(2) No non-essential services running (avahi-daemon, cups, bluetooth, rpcbind, nfs-server, vsftpd, telnet)\n(3) No non-essential packages installed (telnetd, rsh-server, ypserv, tftp-server, xinetd)\n\nFinding: Not a Finding\n\nJustification: The system has non-essential SSH features disabled, no unnecessary services running, and no unnecessary packages installed. This meets the GPOS SRG requirement to disable non-essential capabilities to reduce the attack surface.",
        "open_comment": "The automated check found non-essential capabilities enabled on this Debian 12 system.\n\nFindings:\n- One or more SSH non-essential features are enabled\n- Non-essential services may be running\n- Non-essential packages may be installed\n\nRemediation Steps:\n(1) Disable SSH non-essential features in /etc/ssh/sshd_config:\n    X11Forwarding no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n    PermitTunnel no\n    GatewayPorts no\n(2) Stop and disable non-essential services:\n    systemctl stop avahi-daemon &amp;&amp; systemctl disable avahi-daemon\n(3) Remove non-essential packages:\n    apt remove telnetd rsh-server ypserv\n(4) Restart SSH: systemctl restart ssh\n\nThe ISSO/ISSM must verify that only mission-essential capabilities remain enabled."
    },
    {
        "id": "V-203638",
        "title": "The operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.",
        "has_na": False,
        "nf_comment": "The automated check verified that the system restricts functions, ports, protocols, and services on this Debian 12 system.\n\nEvidence found:\n(1) Host-based firewall active (UFW/nftables/iptables) with restrictive default policy\n(2) Listening ports enumerated and limited to essential services\n(3) SSH port configuration documented\n\nFinding: Not a Finding\n\nJustification: The system has an active host-based firewall enforcing port and protocol restrictions. Only authorized services are listening on network ports. This meets the GPOS SRG requirement to restrict functions, ports, protocols, and services per the PPSM CAL.",
        "open_comment": "The automated check found insufficient port and protocol restrictions on this Debian 12 system.\n\nFindings:\n- No active host-based firewall detected (UFW/nftables/iptables)\n- Listening ports may include unauthorized services\n\nRemediation Steps:\n(1) Install and enable UFW:\n    apt install ufw\n    ufw default deny incoming\n    ufw default allow outgoing\n    ufw allow ssh\n    ufw allow 443/tcp\n    ufw enable\n(2) Review listening ports: ss -tlnp\n(3) Disable unnecessary services listening on network ports\n(4) Document authorized ports/protocols per PPSM CAL\n(5) Verify firewall rules match organizational security policy\n\nThe ISSO/ISSM must verify firewall configuration aligns with the PPSM CAL and organizational vulnerability assessments."
    },
    {
        "id": "V-203686",
        "title": "The operating system must control remote access methods.",
        "has_na": False,
        "nf_comment": "The automated check verified that remote access methods are controlled on this Debian 12 system.\n\nEvidence found:\n(1) SSH is the primary remote access service and is active\n(2) No unauthorized remote access services detected (telnet, VNC, xrdp, rsh, rlogin, rexec)\n(3) SSH security restrictions configured (PermitRootLogin, MaxAuthTries, MaxSessions)\n\nFinding: Not a Finding\n\nJustification: SSH is the only active remote access method. No unauthorized remote access services were detected. SSH security restrictions are in place to control access. This meets the GPOS SRG requirement to control remote access methods.",
        "open_comment": "The automated check found deficiencies in remote access method control on this Debian 12 system.\n\nFindings:\n- Unauthorized remote access services may be running\n- SSH security restrictions may not be properly configured\n- PermitRootLogin may allow direct root access\n\nRemediation Steps:\n(1) Remove unauthorized remote access services:\n    apt remove telnetd xrdp\n    systemctl stop vnc &amp;&amp; systemctl disable vnc\n(2) Configure SSH restrictions in /etc/ssh/sshd_config:\n    PermitRootLogin prohibit-password\n    MaxAuthTries 4\n    MaxSessions 10\n(3) Restart SSH: systemctl restart ssh\n(4) Verify no unauthorized services: ss -tlnp\n\nThe ISSO/ISSM must verify that only authorized remote access methods are enabled and configured per organizational policy."
    },
    {
        "id": "V-203687",
        "title": "The operating system must provide the capability to immediately disconnect or disable remote access to the operating system.",
        "has_na": False,
        "nf_comment": "The automated check verified that immediate disconnect/disable capabilities exist on this Debian 12 system.\n\nEvidence found:\n(1) SSH service can be stopped via systemctl stop ssh\n(2) Firewall tool available for immediate traffic blocking (UFW or iptables)\n(3) Session termination tools available (pkill, kill) for individual session disconnection\n\nFinding: Not a Finding\n\nJustification: The system provides multiple mechanisms to immediately disconnect or disable remote access: SSH service control, firewall blocking, and process termination. This meets the GPOS SRG requirement for immediate remote access disconnection capability.",
        "open_comment": "The automated check found insufficient disconnect/disable capabilities on this Debian 12 system.\n\nFindings:\n- Firewall tools may not be available for immediate blocking\n- Session termination capabilities may be limited\n\nRemediation Steps:\n(1) Install UFW for immediate block capability:\n    apt install ufw\n(2) Document emergency disconnect procedures:\n    - Stop SSH: systemctl stop ssh\n    - Block all traffic: ufw deny in\n    - Kill sessions: pkill -u username\n(3) Test disconnect procedures periodically\n(4) Establish documented emergency remote access disconnection procedures\n\nThe ISSO/ISSM must verify that disconnect procedures are documented, tested, and authorized personnel are trained on their use."
    },
    {
        "id": "V-203688",
        "title": "The operating system must protect wireless access to and from the system using encryption.",
        "has_na": True,
        "nf_comment": "The automated check verified that wireless access is protected with encryption on this Debian 12 system.\n\nEvidence found:\n(1) Wireless interface detected and active\n(2) WPA2/WPA3 encryption configured via wpa_supplicant\n(3) Encryption protocol meets DoD requirements (CCMP/AES)\n\nFinding: Not a Finding\n\nJustification: Wireless access is protected using WPA2/WPA3 encryption with CCMP/AES cipher suite. This meets the GPOS SRG requirement for encrypted wireless access.",
        "open_comment": "The automated check found deficiencies in wireless access encryption on this Debian 12 system.\n\nFindings:\n- Wireless interface detected but encryption not properly configured\n- WPA2/WPA3 may not be enabled\n\nRemediation Steps:\n(1) Configure WPA2-Enterprise in /etc/wpa_supplicant/wpa_supplicant.conf:\n    network={\n        ssid=your_network\n        key_mgmt=WPA-EAP\n        proto=RSN\n        pairwise=CCMP\n    }\n(2) Alternatively, disable wireless if not required:\n    ip link set wlan0 down\n    rfkill block wifi\n(3) If wireless is not mission-essential, remove wireless hardware or blacklist drivers\n\nThe ISSO/ISSM must verify wireless encryption meets DoD requirements or that wireless capability is disabled.",
        "na_comment": "This system does not have wireless interfaces. The automated check confirmed no wireless network adapters (wlan*, wlp*) are present in /sys/class/net/ and no IEEE 802.11 interfaces were detected by iwconfig or iw dev.\n\nXen Orchestra typically runs on server hardware without wireless capability. This requirement is Not Applicable for systems without wireless interfaces."
    },
    {
        "id": "V-203689",
        "title": "The operating system must protect wireless access to the system using authentication of users and/or devices.",
        "has_na": True,
        "nf_comment": "The automated check verified that wireless access requires proper authentication on this Debian 12 system.\n\nEvidence found:\n(1) Wireless interface detected and active\n(2) WPA-Enterprise (802.1X) authentication configured\n(3) User/device authentication required before wireless access\n\nFinding: Not a Finding\n\nJustification: Wireless access requires WPA-Enterprise (802.1X) authentication, which provides user and device authentication via RADIUS. This meets the GPOS SRG requirement for wireless access authentication.",
        "open_comment": "The automated check found deficiencies in wireless access authentication on this Debian 12 system.\n\nFindings:\n- Wireless interface detected but proper authentication not configured\n- WPA-PSK (pre-shared key) does not meet DoD requirements\n\nRemediation Steps:\n(1) Configure WPA-Enterprise in /etc/wpa_supplicant/wpa_supplicant.conf:\n    network={\n        ssid=your_network\n        key_mgmt=WPA-EAP\n        eap=PEAP\n        identity=user@domain\n    }\n(2) Alternatively, disable wireless if not required:\n    ip link set wlan0 down\n    rfkill block wifi\n(3) DoD requires WPA-Enterprise (802.1X) with RADIUS, not WPA-PSK\n\nThe ISSO/ISSM must verify wireless authentication meets DoD 802.1X requirements or that wireless is disabled.",
        "na_comment": "This system does not have wireless interfaces. The automated check confirmed no wireless network adapters (wlan*, wlp*) are present in /sys/class/net/ and no IEEE 802.11 interfaces were detected by iwconfig or iw dev.\n\nXen Orchestra typically runs on server hardware without wireless capability. This requirement is Not Applicable for systems without wireless interfaces."
    },
    {
        "id": "V-203727",
        "title": "The operating system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.",
        "has_na": False,
        "nf_comment": "The automated check verified that multifactor authentication is implemented for remote privileged access on this Debian 12 system.\n\nEvidence found:\n(1) SSH AuthenticationMethods configured to require multiple factors\n(2) PAM MFA module(s) configured (pam_google_authenticator, pam_u2f, pam_pkcs11, or pam_yubico)\n(3) Smartcard/PIV packages installed (opensc, libpam-pkcs11, pcscd)\n(4) SSSD certificate authentication may be enabled\n\nFinding: Not a Finding\n\nJustification: The system implements multifactor authentication for remote privileged access using a combination of SSH key/password and a separate device factor (smartcard, hardware token, or TOTP app). This meets the GPOS SRG requirement for MFA with a separate device factor.",
        "open_comment": "The automated check found that multifactor authentication is not configured for remote privileged access on this Debian 12 system.\n\nFindings:\n- SSH AuthenticationMethods not configured for multiple factors\n- No PAM MFA modules detected\n- Smartcard/PIV packages not installed\n\nRemediation Steps:\n(1) Install MFA packages: apt install libpam-google-authenticator\n(2) Configure PAM for MFA in /etc/pam.d/sshd:\n    auth required pam_google_authenticator.so\n(3) Configure SSH for MFA in /etc/ssh/sshd_config:\n    AuthenticationMethods publickey,keyboard-interactive\n    ChallengeResponseAuthentication yes\n(4) For CAC/PIV: apt install opensc libpam-pkcs11 pcscd\n(5) Restart SSH: systemctl restart ssh\n\nThe ISSO/ISSM must verify MFA implementation uses a separate device factor (CAC, hardware token, or authenticator app)."
    },
    {
        "id": "V-203728",
        "title": "The operating system must accept Personal Identity Verification (PIV) credentials.",
        "has_na": False,
        "nf_comment": "The automated check verified that PIV credential acceptance is configured on this Debian 12 system.\n\nEvidence found:\n(1) PIV/smartcard packages installed (opensc, libpam-pkcs11, pcscd, libccid)\n(2) PC/SC Smart Card Daemon (pcscd) running\n(3) PAM PKCS#11 configuration present\n(4) SSH certificate-based authentication enabled\n\nFinding: Not a Finding\n\nJustification: The system accepts PIV credentials through PKCS#11 smart card integration with PAM and SSH. The required middleware (opensc, pcscd) and authentication module (libpam-pkcs11) are installed and configured. This meets the GPOS SRG requirement for PIV credential acceptance.",
        "open_comment": "The automated check found that PIV credential acceptance is not configured on this Debian 12 system.\n\nFindings:\n- PIV/smartcard packages not installed (opensc, libpam-pkcs11, pcscd)\n- Smart card daemon not running\n- PAM PKCS#11 not configured\n\nRemediation Steps:\n(1) Install PIV packages:\n    apt install opensc libpam-pkcs11 pcscd libccid libnss3-tools\n(2) Enable smart card daemon:\n    systemctl enable pcscd\n    systemctl start pcscd\n(3) Configure PAM PKCS#11 in /etc/pam_pkcs11/pam_pkcs11.conf\n(4) Add pam_pkcs11 to /etc/pam.d/common-auth:\n    auth sufficient pam_pkcs11.so\n(5) Configure SSH for certificate auth in /etc/ssh/sshd_config:\n    PubkeyAuthentication yes\n(6) Import DoD root CA certificates for PIV validation\n\nThe ISSO/ISSM must verify PIV credential acceptance works with DoD CAC cards and organizational PKI infrastructure."
    },
]


def build_entry(v):
    """Build a proper Vuln entry with 2 or 3 indices."""
    lines = []
    lines.append(f'  <Vuln ID="{v["id"]}">')
    lines.append(f'    <!--RuleTitle: {v["title"]}-->')
    lines.append(f'    <AnswerKey Name="XO">')
    lines.append(f'      <!--Session #56: Automated SSH configuration check-->')

    # Index 1: NotAFinding
    lines.append(f'      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">')
    lines.append(f'        <!--Compliant systems-->')
    lines.append(f'        <ValidationCode></ValidationCode>')
    lines.append(f'        <ValidTrueStatus>NotAFinding</ValidTrueStatus>')
    lines.append(f'        <ValidTrueComment>{v["nf_comment"]}</ValidTrueComment>')
    lines.append(f'        <ValidFalseStatus>NR</ValidFalseStatus>')
    lines.append(f'        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>')
    lines.append(f'      </Answer>')

    # Index 2: Open
    lines.append(f'      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">')
    lines.append(f'        <!--Non-compliant systems requiring remediation-->')
    lines.append(f'        <ValidationCode></ValidationCode>')
    lines.append(f'        <ValidTrueStatus>Open</ValidTrueStatus>')
    lines.append(f'        <ValidTrueComment>{v["open_comment"]}</ValidTrueComment>')
    lines.append(f'        <ValidFalseStatus>NR</ValidFalseStatus>')
    lines.append(f'        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>')
    lines.append(f'      </Answer>')

    # Index 3: Not_Applicable (if applicable)
    if v.get("has_na"):
        lines.append(f'      <Answer Index="3" ExpectedStatus="Not_Applicable" Hostname="" Instance="" Database="" Site="" ResultHash="">')
        lines.append(f'        <!--Requirement does not apply-->')
        lines.append(f'        <ValidationCode></ValidationCode>')
        lines.append(f'        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>')
        lines.append(f'        <ValidTrueComment>{v["na_comment"]}</ValidTrueComment>')
        lines.append(f'        <ValidFalseStatus>NR</ValidFalseStatus>')
        lines.append(f'        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>')
        lines.append(f'      </Answer>')

    lines.append(f'    </AnswerKey>')
    lines.append(f'  </Vuln>')
    return '\n'.join(lines)


def main():
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    replacements = 0
    for v in BATCH4:
        vuln_id = v["id"]
        # Find and replace the existing stub entry
        pattern = rf'(  <Vuln ID="{re.escape(vuln_id)}">)(.*?)(  </Vuln>)'
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            print(f"WARNING: {vuln_id} not found in answer file")
            continue

        old_block = match.group(0)
        new_block = build_entry(v)
        content = content.replace(old_block, new_block)
        replacements += 1
        print(f"Replaced {vuln_id}")

    with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nReplaced {replacements} of {len(BATCH4)} entries")

    # Validate XML
    try:
        tree = ET.parse(ANSWER_FILE)
        root = tree.getroot()
        vuln_count = len(root.findall('.//Vuln'))
        print(f"XML Validation: PASSED ({vuln_count} Vuln entries)")
    except ET.ParseError as e:
        print(f"XML Validation: FAILED - {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
