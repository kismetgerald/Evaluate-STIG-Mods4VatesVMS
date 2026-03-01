#!/usr/bin/env python3
"""Add answer file entries for Batch 11 (System Configuration) functions.

Inserts entries before the closing </STIGComments> tag.
"""

import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

ENTRIES = [
    # V-203649 — FIPS crypto module auth
    {
        "VulnID": "V-203649",
        "NF_Comment": """This system uses cryptographic mechanisms that comply with applicable federal requirements for authentication.

Automated scan verified:
- OpenSSL FIPS mode status checked via /proc/sys/crypto/fips_enabled
- OpenSSL FIPS provider availability verified
- libgcrypt20 cryptographic library installed
- PAM authentication modules configured in /etc/pam.d/common-auth
- SSH daemon uses FIPS-approved cipher algorithms (AES-128/256-CTR/GCM)

On Debian 12 systems running Xen Orchestra, the kernel FIPS mode must be enabled for full compliance. When FIPS mode is active, all cryptographic operations use FIPS 140-2 validated modules.

ISSO/ISSM: Verify that organizational cryptographic policy is documented and that all authentication uses FIPS-approved algorithms.""",
        "O_Comment": """The system does not fully meet federal cryptographic requirements for authentication to a cryptographic module.

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
    # V-203657 — Prevent unauthorized info transfer via shared resources
    {
        "VulnID": "V-203657",
        "NF_Comment": """The operating system prevents unauthorized and unintended information transfer via shared system resources.

Automated scan verified:
- Protected hardlinks enabled (fs.protected_hardlinks = 1)
- Protected symlinks enabled (fs.protected_symlinks = 1)
- /tmp and /dev/shm mount options checked for nosuid, nodev, noexec
- Core dump restrictions verified (suid_dumpable = 0)

These kernel protections prevent race condition attacks via symlinks/hardlinks and restrict information leakage through shared memory and temporary filesystems.

ISSO/ISSM: Verify organizational policy documents shared resource protection requirements.""",
        "O_Comment": """The operating system does not fully prevent unauthorized information transfer via shared system resources.

Automated scan found one or more issues:
- Hardlink/symlink protections may not be enabled
- /tmp or /dev/shm may lack nosuid/nodev/noexec mount options
- SUID core dumps may not be restricted (suid_dumpable should be 0)

Remediation steps:
1. Enable protections: echo 1 &gt; /proc/sys/fs/protected_hardlinks
2. Persist in /etc/sysctl.d/: fs.protected_hardlinks = 1, fs.protected_symlinks = 1
3. Mount /tmp with nosuid,nodev,noexec in /etc/fstab
4. Mount /dev/shm with nosuid,nodev,noexec
5. Set suid_dumpable to 0: echo 0 &gt; /proc/sys/fs/suid_dumpable
6. Persist: fs.suid_dumpable = 0 in /etc/sysctl.d/

ISSO/ISSM: Verify all shared resource protections are active and persistent across reboots.""",
    },
    # V-203658 — DoS protection
    {
        "VulnID": "V-203658",
        "NF_Comment": """The operating system manages excess capacity and bandwidth to limit denial of service effects.

Automated scan verified:
- Firewall status checked (UFW/nftables/iptables)
- TCP SYN cookies enabled (net.ipv4.tcp_syncookies = 1)
- Connection tracking limits configured
- System resource limits reviewed (/etc/security/limits.conf)

SYN cookie protection prevents TCP SYN flood attacks. Connection tracking and resource limits provide additional DoS mitigation at the OS level.

ISSO/ISSM: Verify organizational DoS mitigation policy and that network-level protections complement OS-level controls.""",
        "O_Comment": """The operating system does not adequately manage excess capacity to limit denial of service effects.

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
    # V-203659 — Session termination after inactivity
    {
        "VulnID": "V-203659",
        "NF_Comment": """The operating system terminates network connections after session end and enforces inactivity timeouts.

Automated scan verified:
- SSH ClientAliveInterval configured within 600-second (10-minute) limit
- SSH ClientAliveCountMax checked for reasonable value
- Shell TMOUT variable checked in login profiles
- systemd-logind idle configuration reviewed
- XO application session timeout settings checked

SSH inactivity timeout ensures privileged management sessions are terminated within the 10-minute DoD requirement. Shell TMOUT provides additional protection for interactive console sessions.

ISSO/ISSM: Verify inactivity timeouts meet organizational requirements (privileged: 10 min, non-privileged: 15 min).""",
        "O_Comment": """The operating system does not properly terminate sessions after inactivity timeouts.

Automated scan found:
- SSH ClientAliveInterval may not be configured or exceeds 600 seconds
- Shell TMOUT may not be set in login profiles
- systemd-logind idle action may not be configured

Remediation steps:
1. Set SSH timeout in /etc/ssh/sshd_config:
   ClientAliveInterval 600
   ClientAliveCountMax 0
2. Set shell timeout in /etc/profile.d/tmout.sh:
   TMOUT=900
   readonly TMOUT
   export TMOUT
3. Configure systemd-logind in /etc/systemd/logind.conf:
   IdleAction=lock
   StopIdleSessionSec=900
4. Restart services: systemctl restart sshd; systemctl restart systemd-logind

ISSO/ISSM: Verify timeouts meet DoD requirements (privileged 10 min, non-privileged 15 min).""",
    },
    # V-203660 — Fail to secure state
    {
        "VulnID": "V-203660",
        "NF_Comment": """The operating system fails to a secure state if system initialization fails, shutdown fails, or aborts fail.

Automated scan verified:
- Default boot target is multi-user.target (secure non-GUI mode)
- Emergency and rescue modes require root authentication via sulogin
- Ctrl-Alt-Delete reboot is masked (disabled)
- Kernel panic behavior reviewed for fail-secure configuration

The combination of sulogin for emergency/rescue modes and masked Ctrl-Alt-Delete ensures the system requires authentication even during failure recovery, preventing unauthorized access during degraded states.

ISSO/ISSM: Verify that boot-time authentication requirements are documented in the system security plan.""",
        "O_Comment": """The operating system may not fail to a secure state during initialization or shutdown failures.

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
    # V-203661 — Protect info at rest
    {
        "VulnID": "V-203661",
        "NF_Comment": """The operating system protects the confidentiality and integrity of all information at rest.

Automated scan verified:
- LUKS/dm-crypt encrypted volumes detected
- /etc/crypttab configuration reviewed
- Sensitive file permissions verified (/etc/shadow, /etc/gshadow, /etc/ssl/private)
- XO data directory permissions checked

Disk encryption via LUKS ensures data confidentiality at rest. Restrictive file permissions on sensitive system files and XO data directories protect data integrity.

ISSO/ISSM: Verify encryption key management procedures and that all sensitive data partitions are encrypted.""",
        "O_Comment": """The operating system does not fully protect the confidentiality and integrity of information at rest.

Automated scan found:
- No LUKS/dm-crypt encrypted volumes detected
- Sensitive file permissions may not meet requirements

Remediation steps:
1. Implement full disk encryption using LUKS:
   cryptsetup luksFormat /dev/sdX
   cryptsetup luksOpen /dev/sdX encrypted_vol
2. Configure /etc/crypttab for automatic unlocking
3. Verify sensitive file permissions:
   chmod 640 /etc/shadow
   chmod 640 /etc/gshadow
   chmod 700 /etc/ssl/private
4. Restrict XO data directories:
   chmod 750 /var/lib/xo-server
   chmod 750 /etc/xo-server

ISSO/ISSM: Document data-at-rest encryption policy and key management procedures. If LUKS is not feasible, document compensating controls.""",
    },
    # V-203663 — Error messages provide info without exploitation details
    {
        "VulnID": "V-203663",
        "NF_Comment": """The operating system generates error messages that provide necessary information without revealing exploitable details.

Automated scan verified:
- /etc/issue checked for OS identification escape sequences
- /etc/issue.net checked for remote login banner content
- SSH banner configuration verified
- System logging (rsyslog) configured to capture error information

Login banners do not contain OS identification escape sequences that could reveal system details to attackers. Error messages are logged via rsyslog for authorized administrator review.

ISSO/ISSM: Verify login banners display the approved DoD consent banner text.""",
        "O_Comment": """The operating system may reveal exploitable information in error messages or login banners.

Automated scan found:
- /etc/issue or /etc/issue.net may contain OS identification escape sequences
- SSH banner may not be properly configured
- System logging may not be capturing error information

Remediation steps:
1. Remove OS escape sequences from /etc/issue and /etc/issue.net
   (remove \\l, \\n, \\m, \\r, \\s, \\v, \\o, \\O sequences)
2. Set approved DoD consent banner text in /etc/issue
3. Configure SSH banner: Banner /etc/issue.net in sshd_config
4. Verify rsyslog is active: systemctl status rsyslog
5. Check log rotation: ls -la /etc/logrotate.d/

ISSO/ISSM: Ensure login banners contain only the approved DoD consent banner without system identification.""",
    },
    # V-203664 — Error messages only to authorized users
    {
        "VulnID": "V-203664",
        "NF_Comment": """The operating system reveals error messages only to authorized users.

Automated scan verified:
- /var/log directory permissions restrict unauthorized access
- Individual log file permissions verified (syslog, auth.log, kern.log)
- journald access controlled by systemd permissions
- Kernel message access restricted (dmesg_restrict = 1)

Log files containing error messages are readable only by root and authorized groups. Kernel messages are restricted from unprivileged users via dmesg_restrict, preventing information disclosure.

ISSO/ISSM: Verify log access controls align with organizational least-privilege requirements.""",
        "O_Comment": """The operating system may reveal error messages to unauthorized users.

Automated scan found:
- Log file permissions may be too permissive
- Kernel dmesg_restrict may not be enabled
- Log directory access may not be properly restricted

Remediation steps:
1. Set log file permissions:
   chmod 640 /var/log/syslog /var/log/auth.log /var/log/kern.log
   chown root:adm /var/log/syslog /var/log/auth.log
2. Restrict kernel messages:
   echo 1 &gt; /proc/sys/kernel/dmesg_restrict
   Persist: kernel.dmesg_restrict = 1 in /etc/sysctl.d/
3. Set /var/log permissions: chmod 750 /var/log
4. Configure logrotate to maintain permissions on rotated files

ISSO/ISSM: Verify only authorized administrators have access to system error logs.""",
    },
    # V-203683 — Auto-terminate session after inactivity
    {
        "VulnID": "V-203683",
        "NF_Comment": """The operating system automatically terminates user sessions after inactivity timeouts expire or at shutdown.

Automated scan verified:
- SSH ClientAliveInterval within 600-second limit for session termination
- SSH ClientAliveCountMax configured
- Shell TMOUT variable checked for interactive session timeout
- systemd-logind idle action configuration reviewed
- Terminal lock capability (vlock/tmux) checked

SSH session termination after inactivity is the primary mechanism ensuring idle sessions are closed. This prevents unauthorized access through unattended terminals.

ISSO/ISSM: Verify inactivity timeouts are enforced for all session types and meet DoD requirements.""",
        "O_Comment": """The operating system does not automatically terminate user sessions after inactivity timeouts.

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
    # V-203684 — Logoff capability
    {
        "VulnID": "V-203684",
        "NF_Comment": """The operating system provides a logoff capability for user-initiated communications sessions.

Automated scan verified:
- Valid login shells defined in /etc/shells (all support exit/logout)
- SSH service active and provides session termination
- XO web application provides Sign Out button for user logoff
- systemd-logind manages user sessions (loginctl terminate-session available)

All user session types (SSH, console, XO web interface) provide explicit logoff mechanisms. Users can terminate their own sessions at any time via exit, logout, or the XO Sign Out button.

ISSO/ISSM: Verify all user-accessible interfaces provide visible logoff capability.""",
        "O_Comment": """The operating system may not provide adequate logoff capability for user sessions.

Automated scan found:
- SSH service may not be active
- Shell logout capability may not be properly configured
- XO web application logoff may not be verified

Remediation steps:
1. Ensure SSH service is running: systemctl enable --now ssh
2. Verify /etc/shells contains valid shells with exit/logout support
3. Verify XO web interface provides Sign Out functionality
4. Ensure loginctl is available for session management
5. Test logoff from each session type (SSH, console, web)

ISSO/ISSM: Verify and document that all user session types provide explicit logoff capability.""",
    },
]

def escape_xml(text):
    """Ensure text is properly XML-escaped."""
    # Already escaped entities should not be double-escaped
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text

def build_entry(entry):
    """Build XML entry for one VulnID."""
    nf = escape_xml(entry["NF_Comment"])
    o = escape_xml(entry["O_Comment"])
    return f'''  <Vuln ID="{entry["VulnID"]}">
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

    # Check for existing entries
    for entry in ENTRIES:
        vid = entry["VulnID"]
        if f'Vuln ID="{vid}"' in content:
            print(f"WARNING: {vid} already exists in answer file — skipping")
            ENTRIES.remove(entry)

    if not ENTRIES:
        print("No new entries to add")
        return 0

    # Build all new entries
    new_xml = "\n".join(build_entry(e) for e in ENTRIES)

    # Insert before closing </STIGComments>
    closing_tag = "  </STIGComments>"
    if closing_tag not in content:
        closing_tag = "</STIGComments>"

    content = content.replace(closing_tag, new_xml + "\n" + closing_tag)

    with open(AF_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Added {len(ENTRIES)} entries to answer file")

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
