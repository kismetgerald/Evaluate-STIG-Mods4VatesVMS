#!/usr/bin/env python3
"""Replace 5 stub answer file entries with proper 2-index entries for Batch 11."""

import sys
import re

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Replacement entries for the 5 VulnIDs that already existed as stubs
REPLACEMENTS = {
    "V-203649": {
        "NF": """This system uses cryptographic mechanisms that comply with applicable federal requirements for authentication.

Automated scan verified:
- OpenSSL FIPS mode status checked via /proc/sys/crypto/fips_enabled
- OpenSSL FIPS provider availability verified
- libgcrypt20 cryptographic library installed
- PAM authentication modules configured in /etc/pam.d/common-auth
- SSH daemon uses FIPS-approved cipher algorithms (AES-128/256-CTR/GCM)

On Debian 12 systems running Xen Orchestra, the kernel FIPS mode must be enabled for full compliance. When FIPS mode is active, all cryptographic operations use FIPS 140-2 validated modules.

ISSO/ISSM: Verify that organizational cryptographic policy is documented and that all authentication uses FIPS-approved algorithms.""",
        "O": """The system does not fully meet federal cryptographic requirements for authentication to a cryptographic module.

Automated scan found:
- Kernel FIPS mode is NOT enabled (/proc/sys/crypto/fips_enabled != 1)
- System may be using non-FIPS-validated cryptographic modules for authentication

Remediation steps:
1. Install FIPS packages: apt install libgcrypt20 openssl
2. Enable FIPS mode in kernel boot parameters
3. Verify OpenSSL FIPS provider is loaded: openssl list -providers
4. Configure SSH to use only FIPS-approved ciphers
5. Verify PAM modules use FIPS-compliant hashing algorithms

Note: Full FIPS 140-2 compliance on Debian 12 may require additional kernel configuration. Consult Vates documentation for XO-specific FIPS guidance.

ISSO/ISSM: Document compensating controls if full FIPS mode cannot be enabled.""",
    },
    "V-203658": {
        "NF": """The operating system manages excess capacity and bandwidth to limit denial of service effects.

Automated scan verified:
- Firewall status checked (UFW/nftables/iptables)
- TCP SYN cookies enabled (net.ipv4.tcp_syncookies = 1)
- Connection tracking limits configured
- System resource limits reviewed (/etc/security/limits.conf)

SYN cookie protection prevents TCP SYN flood attacks. Connection tracking and resource limits provide additional DoS mitigation at the OS level.

ISSO/ISSM: Verify organizational DoS mitigation policy and that network-level protections complement OS-level controls.""",
        "O": """The operating system does not adequately manage excess capacity to limit denial of service effects.

Automated scan found:
- TCP SYN cookies may not be enabled
- Firewall rate limiting may not be configured
- Resource limits may not be defined

Remediation steps:
1. Enable SYN cookies: echo 1 &gt; /proc/sys/net/ipv4/tcp_syncookies
2. Persist in /etc/sysctl.d/: net.ipv4.tcp_syncookies = 1
3. Configure firewall rate limiting (e.g., ufw limit ssh)
4. Set resource limits in /etc/security/limits.conf
5. Load nf_conntrack module if needed for connection tracking

ISSO/ISSM: Document organizational DoS mitigation strategy including network and OS-level controls.""",
    },
    "V-203660": {
        "NF": """The operating system fails to a secure state if system initialization fails, shutdown fails, or aborts fail.

Automated scan verified:
- Default boot target is multi-user.target (secure non-GUI mode)
- Emergency and rescue modes require root authentication via sulogin
- Ctrl-Alt-Delete reboot is masked (disabled)
- Kernel panic behavior reviewed for fail-secure configuration

The combination of sulogin for emergency/rescue modes and masked Ctrl-Alt-Delete ensures the system requires authentication even during failure recovery, preventing unauthorized access during degraded states.

ISSO/ISSM: Verify that boot-time authentication requirements are documented in the system security plan.""",
        "O": """The operating system may not fail to a secure state during initialization or shutdown failures.

Automated scan found:
- Emergency/rescue modes may not require root authentication (sulogin)
- Ctrl-Alt-Delete reboot may not be disabled
- Kernel panic behavior may not be configured for fail-secure

Remediation steps:
1. Ensure sulogin is configured for emergency mode:
   Verify /usr/lib/systemd/system/emergency.service uses sulogin
2. Mask Ctrl-Alt-Delete: systemctl mask ctrl-alt-del.target
3. Set kernel panic on oops: echo 1 &gt; /proc/sys/kernel/panic_on_oops
4. Persist in /etc/sysctl.d/: kernel.panic_on_oops = 1
5. Verify default target: systemctl set-default multi-user.target

ISSO/ISSM: Document fail-secure behavior in system security plan.""",
    },
    "V-203663": {
        "NF": """The operating system generates error messages that provide necessary information without revealing exploitable details.

Automated scan verified:
- /etc/issue checked for OS identification escape sequences
- /etc/issue.net checked for remote login banner content
- SSH banner configuration verified
- System logging (rsyslog) configured to capture error information

Login banners do not contain OS identification escape sequences that could reveal system details to attackers. Error messages are logged via rsyslog for authorized administrator review.

ISSO/ISSM: Verify login banners display the approved DoD consent banner text.""",
        "O": """The operating system may reveal exploitable information in error messages or login banners.

Automated scan found:
- /etc/issue or /etc/issue.net may contain OS identification escape sequences
- SSH banner may not be properly configured
- System logging may not be capturing error information

Remediation steps:
1. Remove OS escape sequences from /etc/issue and /etc/issue.net
2. Set approved DoD consent banner text in /etc/issue
3. Configure SSH banner: Banner /etc/issue.net in sshd_config
4. Verify rsyslog is active: systemctl status rsyslog
5. Check log rotation: ls -la /etc/logrotate.d/

ISSO/ISSM: Ensure login banners contain only the approved DoD consent banner without system identification.""",
    },
    "V-203683": {
        "NF": """The operating system automatically terminates user sessions after inactivity timeouts expire or at shutdown.

Automated scan verified:
- SSH ClientAliveInterval within 600-second limit for session termination
- SSH ClientAliveCountMax configured
- Shell TMOUT variable checked for interactive session timeout
- systemd-logind idle action configuration reviewed
- Terminal lock capability (vlock/tmux) checked

SSH session termination after inactivity is the primary mechanism ensuring idle sessions are closed. This prevents unauthorized access through unattended terminals.

ISSO/ISSM: Verify inactivity timeouts are enforced for all session types and meet DoD requirements.""",
        "O": """The operating system does not automatically terminate user sessions after inactivity timeouts.

Automated scan found:
- SSH ClientAliveInterval may not be configured or exceeds limits
- Shell TMOUT may not be set
- systemd-logind idle action may not be configured

Remediation steps:
1. Configure SSH inactivity timeout in /etc/ssh/sshd_config:
   ClientAliveInterval 600
   ClientAliveCountMax 0
2. Set shell TMOUT in /etc/profile.d/tmout.sh:
   TMOUT=900
   readonly TMOUT
   export TMOUT
3. Configure systemd-logind idle action:
   IdleAction=lock in /etc/systemd/logind.conf
4. Install terminal lock utility: apt install vlock
5. Restart SSH: systemctl restart sshd

ISSO/ISSM: Document session timeout policy and verify enforcement across all access methods.""",
    },
}

def escape_xml(text):
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text

def build_replacement(vid, data):
    nf = escape_xml(data["NF"])
    o = escape_xml(data["O"])
    return f'''  <Vuln ID="{vid}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{o}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''

def main():
    with open(AF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    changes = 0
    for vid, data in REPLACEMENTS.items():
        # Find existing Vuln block
        pattern = rf'(\s*<Vuln ID="{re.escape(vid)}">.*?</Vuln>)'
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            print(f"WARNING: {vid} not found in answer file")
            continue

        old_block = match.group(1)
        new_block = "\n" + build_replacement(vid, data)
        content = content.replace(old_block, new_block)
        changes += 1
        print(f"OK: Replaced {vid} stub with 2-index entry")

    with open(AF_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nReplaced {changes}/5 stub entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED — {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
