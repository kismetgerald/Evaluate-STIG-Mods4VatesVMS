#!/usr/bin/env python3
"""Integrate Batch 13 answer file entries into XO GPOS Debian12 answer file.

Batch 13: Time, Patching and Software (10 functions)
"""

import sys

ANSWER_FILE = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Each entry: (VulnID, NF_comment, Open_comment)
ENTRIES = [
    (
        "V-203711",
        # NotAFinding comment
        """The operating system compares internal clocks with an authoritative time source at least every 24 hours.

Automated scan verified:
- Time synchronization service (chrony/NTP/systemd-timesyncd) is active
- Configured time sources respond and are reachable
- Poll interval is well within the 24-hour requirement (chrony default maxpoll ~17 minutes)
- timedatectl confirms NTP synchronization is active

The system maintains accurate time through regular synchronization with authoritative sources, meeting the 24-hour comparison requirement.

ISSO/ISSM: Verify the configured time sources are organization-approved authoritative sources (e.g., DoD NTP servers).""",
        # Open comment
        """The operating system may not compare internal clocks with an authoritative time source at least every 24 hours.

Automated scan found:
- No active time synchronization service detected (chrony, NTP, or systemd-timesyncd)
- Poll interval may exceed the 24-hour requirement

Remediation steps:
1. Install chrony: apt install chrony
2. Configure authoritative time sources in /etc/chrony/chrony.conf
3. Enable and start the service: systemctl enable --now chrony
4. Verify synchronization: chronyc sources -v
5. Confirm poll interval is within 24 hours (default is adequate)

ISSO/ISSM: Verify time sources are organization-approved DoD authoritative sources."""
    ),
    (
        "V-203712",
        # NotAFinding
        """The operating system synchronizes clocks to the authoritative time source when the time difference is greater than one second.

Automated scan verified:
- chrony makestep or NTP tinker step configuration is present
- Step correction threshold set to handle offsets greater than one second
- Current time offset is minimal (within acceptable range)
- NTP synchronization is active and functioning

The chrony makestep directive (default: 1.0 3) ensures the system steps the clock if the offset exceeds 1 second during the first 3 updates, satisfying this requirement.

ISSO/ISSM: Verify makestep configuration aligns with organizational time accuracy requirements.""",
        # Open
        """The operating system may not synchronize clocks when the time difference is greater than one second.

Automated scan found:
- chrony makestep or NTP tinker step configuration may not be present
- Unable to verify step correction threshold
- Current time offset could not be determined

Remediation steps:
1. Ensure chrony is installed and configured
2. Verify makestep directive in /etc/chrony/chrony.conf (default: makestep 1.0 3)
3. For NTP: add 'tinker step 1' to /etc/ntp.conf
4. Restart time service: systemctl restart chrony
5. Verify offset: chronyc tracking

ISSO/ISSM: Verify time synchronization step correction is properly configured."""
    ),
    (
        "V-203713",
        # NotAFinding
        """The operating system records audit timestamps with a minimum granularity of one second.

Automated scan verified:
- systemd journal provides microsecond precision timestamps (exceeds 1-second requirement)
- auditd uses Unix epoch timestamps with sub-second granularity (when installed)
- XO Audit Plugin records timestamps in Unix milliseconds (ms precision)
- Sample log entries confirm timestamp granularity meets requirement

All audit subsystems (systemd journal, auditd, XO Audit Plugin) exceed the minimum one-second granularity requirement.

ISSO/ISSM: No additional action required - timestamp granularity exceeds minimum requirement.""",
        # Open
        """The operating system may not record audit timestamps with minimum granularity of one second.

Automated scan found:
- auditd may not be installed or configured
- systemd journal may not be available
- Unable to verify timestamp granularity from log entries

Remediation steps:
1. Verify systemd journal is active: systemctl status systemd-journald
2. Install auditd if required: apt install auditd
3. Verify journal timestamp format: journalctl -n 5 -o short-precise
4. Confirm audit log format in /etc/audit/auditd.conf (log_format = RAW)

ISSO/ISSM: Verify audit timestamps provide at least one-second granularity."""
    ),
    (
        "V-203715",
        # NotAFinding
        """The operating system enforces dual authorization for movement and/or deletion of audit information.

Automated scan verified:
- Audit log files are protected with appropriate permissions (root-only access)
- Immutable file attributes may be set on critical audit logs
- sudo is installed requiring separate authentication for administrative actions
- File permissions restrict audit log deletion to root

Dual authorization procedures are supported through restrictive file permissions and sudo-based administrative controls.

ISSO/ISSM: Verify organizational dual authorization procedures are documented and enforced for audit log deletion/movement.""",
        # Open
        """The operating system may not enforce dual authorization for audit information deletion.

Automated scan found:
- Audit log permissions may not sufficiently restrict deletion
- No immutable attributes detected on audit logs
- Dual authorization requires organizational procedures beyond technical controls

Remediation steps:
1. Set audit log permissions to 600 root:root
2. Apply immutable attributes: chattr +i /var/log/audit/audit.log
3. Implement organizational dual authorization procedures
4. Document approval workflow for audit log deletion/movement
5. Configure SIEM forwarding for audit log backup

ISSO/ISSM: Implement and document dual authorization procedures for audit log management."""
    ),
    (
        "V-203716",
        # NotAFinding
        """The operating system prohibits user installation of system software without explicit privileged status.

Automated scan verified:
- Package management tools (apt, dpkg) require root/sudo privileges
- dpkg lock files restrict concurrent package operations
- No world-writable files in /usr/local/bin or /usr/local/sbin
- Non-system package managers (pip3, npm) have appropriate ownership

Standard users cannot install system software without explicit root or sudo privileges, satisfying this requirement.

ISSO/ISSM: Verify sudo policies appropriately restrict package installation privileges.""",
        # Open
        """The operating system may not prohibit user software installation without privileged status.

Automated scan found:
- Package manager privilege restrictions may not be properly configured
- World-writable files may exist in system binary directories
- Non-system package managers may allow unprivileged installation

Remediation steps:
1. Verify apt/dpkg binary permissions: chmod 755 /usr/bin/apt /usr/bin/dpkg
2. Remove world-writable bits from /usr/local/bin: chmod o-w /usr/local/bin/*
3. Configure sudo policies to restrict package installation
4. Review and restrict npm/pip3 global installation permissions

ISSO/ISSM: Verify all software installation requires explicit privileged status."""
    ),
    (
        "V-203717",
        # NotAFinding
        """The operating system notifies designated personnel when baseline configurations are changed in an unauthorized manner.

Automated scan verified:
- File integrity monitoring tool (AIDE/Tripwire) is installed and configured
- Periodic integrity checks are scheduled via cron
- Notification mechanism available (mail, rsyslog, SIEM integration)
- dpkg --verify confirms package integrity status

Baseline configuration change detection and notification are configured through file integrity monitoring with scheduled checks.

ISSO/ISSM: Verify FIM scan results are reviewed and notification recipients are current.""",
        # Open
        """The operating system may not notify personnel when baseline configurations change.

Automated scan found:
- No file integrity monitoring tools detected (AIDE, Tripwire, OSSEC, Samhain)
- No scheduled integrity checks found in cron
- Notification mechanism may not be configured

Remediation steps:
1. Install AIDE: apt install aide
2. Initialize database: aideinit
3. Configure monitored paths in /etc/aide/aide.conf
4. Schedule periodic checks: echo '0 5 * * * root /usr/bin/aide --check' &gt; /etc/cron.d/aide-check
5. Configure alerting: pipe AIDE output to mail or rsyslog for SIEM forwarding
6. Document notification procedures and designated personnel

ISSO/ISSM: Implement FIM with automated notification to designated security personnel."""
    ),
    (
        "V-203721",
        # NotAFinding
        """The operating system prevents program execution in accordance with local security policies.

Automated scan verified:
- AppArmor mandatory access control is active with profiles loaded
- Profiles enforce program execution restrictions per security policy
- No world-writable directories found in PATH
- Filesystem execution restrictions (noexec) may be applied to appropriate partitions

AppArmor provides mandatory access control that restricts program execution according to defined security profiles, satisfying this requirement.

ISSO/ISSM: Verify AppArmor profiles are appropriate for the environment and in enforce mode.""",
        # Open
        """The operating system may not prevent program execution per local security policies.

Automated scan found:
- AppArmor is not active or not enforcing profiles
- SELinux is not installed (Debian default)
- Program execution restrictions may not be enforced

Remediation steps:
1. Install AppArmor: apt install apparmor apparmor-utils
2. Enable AppArmor: systemctl enable --now apparmor
3. Set profiles to enforce mode: aa-enforce /etc/apparmor.d/*
4. Verify status: aa-status
5. Apply noexec to /tmp and /var/tmp partitions if separate
6. Review and restrict world-writable directories in PATH

ISSO/ISSM: Verify mandatory access control enforces organizational program execution policies."""
    ),
    (
        "V-203750",
        # NotAFinding
        """The operating system maintains confidentiality and integrity of information during preparation for transmission.

Automated scan verified:
- SSH is configured with approved ciphers, MACs, and key exchange algorithms
- TLS 1.2+ is active for XO web interface (HTTPS on port 443)
- Encryption protects data confidentiality and integrity before transmission

SSH and TLS provide cryptographic protection for data during preparation for transmission, ensuring both confidentiality and integrity.

ISSO/ISSM: Verify SSH and TLS configurations use only FIPS-approved algorithms.""",
        # Open
        """The operating system may not maintain confidentiality/integrity during transmission preparation.

Automated scan found:
- SSH encryption configuration may not use approved algorithms
- TLS may not be properly configured for XO web interface
- Unable to verify encryption for data during transmission preparation

Remediation steps:
1. Configure SSH ciphers in /etc/ssh/sshd_config: Ciphers aes256-ctr,aes256-gcm@openssh.com
2. Configure SSH MACs: MACs hmac-sha2-512,hmac-sha2-256
3. Ensure XO uses HTTPS (TLS 1.2+) for all communications
4. Verify TLS certificate is valid and properly configured
5. Restart SSH: systemctl restart ssh

ISSO/ISSM: Verify all transmission channels use approved encryption algorithms."""
    ),
    (
        "V-203751",
        # NotAFinding
        """The operating system maintains confidentiality and integrity of information during reception.

Automated scan verified:
- SSH host keys are configured for server authentication during reception
- StrictModes is enabled for SSH security
- TLS 1.2+ protects incoming connections to XO web interface
- Firewall filtering may be active for incoming traffic

SSH and TLS provide cryptographic protection for data during reception, ensuring both confidentiality and integrity verification.

ISSO/ISSM: Verify all incoming communication channels use approved encryption.""",
        # Open
        """The operating system may not maintain confidentiality/integrity during reception.

Automated scan found:
- SSH host key configuration may be incomplete
- TLS for incoming connections may not be verified
- Firewall input filtering may not be active

Remediation steps:
1. Verify SSH host keys exist: ls -la /etc/ssh/ssh_host_*_key.pub
2. Regenerate if needed: ssh-keygen -A
3. Enable StrictModes in sshd_config
4. Ensure XO HTTPS is properly configured with valid certificate
5. Configure firewall: ufw enable &amp;&amp; ufw allow ssh &amp;&amp; ufw allow https

ISSO/ISSM: Verify all incoming data reception channels use approved encryption."""
    ),
    (
        "V-259333",
        # NotAFinding
        """The operating system installs security-relevant software updates within the directed timeframe.

Automated scan verified:
- No pending security updates detected (system is current)
- Automatic updates may be configured (unattended-upgrades)
- Package lists are regularly refreshed
- OS version is current and within support lifecycle

The system is current with security updates, with no pending security-relevant patches requiring installation.

ISSO/ISSM: Verify update schedule aligns with IAVM/CTO/DTM/STIG directed timeframes.""",
        # Open
        """The operating system may not install security updates within the directed timeframe.

Automated scan found:
- Security updates are available but not installed
- Automatic update mechanism may not be configured
- Package lists may be stale

Remediation steps:
1. Update package lists: apt update
2. Install security updates: apt upgrade -y
3. Install unattended-upgrades: apt install unattended-upgrades
4. Configure automatic security updates in /etc/apt/apt.conf.d/20auto-upgrades
5. Enable the service: systemctl enable --now unattended-upgrades
6. Verify: apt list --upgradable | grep security

ISSO/ISSM: Implement and document patch management per IAVM/CTO/DTM/STIG requirements."""
    ),
]


def main():
    with open(ANSWER_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    # Build the XML entries
    new_entries = []
    for vuln_id, nf_comment, open_comment in ENTRIES:
        entry = f"""  <Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>"""
        new_entries.append(entry)

    all_entries = "\n".join(new_entries) + "\n"

    # Insert before closing </STIGComments>
    closing_tag = "  </STIGComments>"
    if closing_tag not in content:
        print("ERROR: </STIGComments> not found")
        return 1

    content = content.replace(closing_tag, all_entries + closing_tag)

    with open(ANSWER_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Integrated {len(ENTRIES)} answer file entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(ANSWER_FILE)
        print("XML validation: PASSED")
    except Exception as e:
        print(f"XML validation: FAILED - {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
