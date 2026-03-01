#!/usr/bin/env python3
"""Integrate Batch 15 answer file entries into XO GPOS Debian12 answer file.

Batch 15: Hardening, Permissions and Firewall (10 functions)
"""

import sys

ANSWER_FILE = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Each entry: (VulnID, NF_comment, Open_comment)
ENTRIES = [
    (
        "V-203747",
        # NotAFinding
        """The operating system protects against or limits the effects of Denial of Service (DoS) attacks with rate-limiting measures.

Automated scan verified:
- Firewall (UFW/iptables) is active with appropriate rules
- Kernel SYN flood protection (tcp_syncookies) is enabled
- Connection tracking limits are configured
- fail2ban or equivalent application-layer DoS protection is active

Rate-limiting measures are implemented at both network and application layers.

ISSO/ISSM: Verify rate-limiting configuration is appropriate for the operational environment.""",
        # Open
        """The operating system may not adequately protect against DoS attacks with rate-limiting measures.

Automated scan found:
- Firewall may not be active or may lack rate-limiting rules
- Application-layer DoS protection (fail2ban) may not be installed
- Rate-limiting configuration requires organizational review

Remediation steps:
1. Enable firewall: ufw enable
2. Add rate limiting: ufw limit ssh/tcp
3. Install fail2ban: apt install fail2ban
4. Configure fail2ban jails for SSH and web services
5. Verify kernel SYN cookies: sysctl net.ipv4.tcp_syncookies=1
6. Document rate-limiting thresholds per organizational requirements

ISSO/ISSM: Implement and document DoS protection measures appropriate for the environment."""
    ),
    (
        "V-203752",
        # NotAFinding
        """The operating system behaves in a predictable and documented manner when invalid inputs are received.

Automated scan verified:
- Kernel panic behavior is configured (panic_on_oops, panic timeout)
- Core dump configuration is documented (suid_dumpable, core_pattern)
- systemd default target ensures predictable boot behavior
- XO application handles errors through Node.js exception handling

System behavior on invalid inputs is predictable and documented through kernel and systemd configuration.

ISSO/ISSM: No additional action required — kernel and systemd provide documented error handling.""",
        # Open
        """The operating system may not behave predictably when invalid inputs are received.

Automated scan found:
- Kernel panic configuration may not be documented
- Error handling behavior may not meet organizational requirements

Remediation steps:
1. Configure kernel panic behavior: sysctl kernel.panic_on_oops=1
2. Set panic reboot timeout: sysctl kernel.panic=10
3. Restrict core dumps: sysctl fs.suid_dumpable=0
4. Verify systemd default target: systemctl set-default multi-user.target
5. Document expected system behavior for invalid inputs

ISSO/ISSM: Document expected system behavior and error handling procedures."""
    ),
    (
        "V-203753",
        # NotAFinding
        """The operating system implements non-executable data (NX/DEP) to protect memory from unauthorized code execution.

Automated scan verified:
- CPU supports NX (No-Execute) bit (detected in /proc/cpuinfo)
- 64-bit kernel architecture (x86_64) enforces NX at hardware level
- Kernel NX protection is active by default on Debian 12

NX bit protection prevents execution of code in data memory regions, mitigating buffer overflow exploits.

ISSO/ISSM: No additional action required — NX is hardware-enforced on 64-bit systems.""",
        # Open
        """The operating system may not implement non-executable data (NX/DEP) protection.

Automated scan found:
- NX bit support could not be verified in CPU flags
- Kernel may not be enforcing NX protection

Remediation steps:
1. Verify CPU NX support: grep nx /proc/cpuinfo
2. Verify 64-bit kernel: uname -m (should show x86_64)
3. Check BIOS/UEFI settings for NX/XD bit enablement
4. Verify kernel boot parameters do not disable NX (noexec=off)

ISSO/ISSM: Verify NX/DEP is active in hardware and kernel configuration."""
    ),
    (
        "V-203754",
        # NotAFinding
        """The operating system implements address space layout randomization (ASLR) to protect memory from unauthorized code execution.

Automated scan verified:
- kernel.randomize_va_space is set to 2 (full randomization)
- ASLR randomizes stack, VDSO, mmap, and heap memory regions
- Debian 12 default is full ASLR (randomize_va_space=2)
- No sysctl overrides disabling ASLR were detected

Full ASLR is active, randomizing memory addresses to prevent exploitation of memory corruption vulnerabilities.

ISSO/ISSM: No additional action required — ASLR is enabled at the Debian 12 default level.""",
        # Open
        """The operating system may not implement address space layout randomization (ASLR).

Automated scan found:
- kernel.randomize_va_space may be set to 0 (ASLR disabled)
- A sysctl override may be disabling ASLR

Remediation steps:
1. Enable full ASLR: sysctl -w kernel.randomize_va_space=2
2. Make persistent: echo 'kernel.randomize_va_space=2' &gt; /etc/sysctl.d/99-aslr.conf
3. Apply: sysctl --system
4. Verify: cat /proc/sys/kernel/randomize_va_space (should be 2)
5. Remove any sysctl overrides that set randomize_va_space to 0 or 1

ISSO/ISSM: Verify ASLR is enabled with full randomization (value=2)."""
    ),
    (
        "V-203755",
        # NotAFinding
        """The operating system removes old software components after updated versions have been installed.

Automated scan verified:
- APT package manager replaces old package versions during upgrade
- apt autoremove removes orphaned dependency packages
- No significant residual configuration packages detected
- Kernel package management handles version cleanup

The Debian APT package management system automatically replaces superseded software components during updates.

ISSO/ISSM: Periodically run 'apt autoremove' to clean orphaned packages.""",
        # Open
        """The operating system may not remove old software components after updates.

Automated scan found:
- Residual configuration packages may exist (dpkg -l | grep ^rc)
- Old kernel versions may still be installed
- Automatic cleanup may not be configured

Remediation steps:
1. Remove residual packages: apt autoremove --purge
2. Clean old kernels: apt autoremove
3. Configure automatic cleanup in /etc/apt/apt.conf.d/20auto-upgrades
4. Verify: dpkg -l | grep ^rc (should be empty)
5. Schedule periodic cleanup via cron or unattended-upgrades

ISSO/ISSM: Verify old software components are removed per organizational policy."""
    ),
    (
        "V-203756",
        # NotAFinding
        """The operating system verifies correct operation of all security functions.

Automated scan verified:
- AppArmor mandatory access control is active with profiles loaded
- No failed systemd services detected (or failures documented)
- SSH service is active and operational
- Package integrity verification (dpkg --verify) shows no critical discrepancies

Security functions are operational and verifiable through AppArmor, systemd, and package integrity mechanisms.

ISSO/ISSM: Verify security function testing procedures are documented and followed.""",
        # Open
        """The operating system may not verify correct operation of security functions.

Automated scan found:
- AppArmor may not be active or may have unloaded profiles
- Failed systemd services may indicate security function issues
- Package integrity discrepancies detected
- Security function verification procedures may not be documented

Remediation steps:
1. Enable AppArmor: systemctl enable --now apparmor
2. Load profiles: aa-enforce /etc/apparmor.d/*
3. Resolve failed services: systemctl --failed
4. Verify package integrity: dpkg --verify
5. Document security function verification procedures

ISSO/ISSM: Implement and document security function verification procedures."""
    ),
    (
        "V-203757",
        # NotAFinding
        """The operating system performs periodic verification of security functions upon startup, on privileged command, and at least every 30 days.

Automated scan verified:
- AIDE file integrity monitoring is installed and scheduled
- Systemd timers handle periodic security checks (apt updates)
- AppArmor profiles are loaded at boot via systemd integration
- Security function verification occurs at system startup

Periodic security function verification is implemented through AIDE scheduling, systemd timers, and boot-time profile loading.

ISSO/ISSM: Verify 30-day verification cycle is documented and AIDE checks are reviewed.""",
        # Open
        """The operating system may not perform periodic verification of security functions.

Automated scan found:
- AIDE may not be installed or scheduled for periodic checks
- No evidence of 30-day security function verification cycle
- Boot-time verification may be incomplete

Remediation steps:
1. Install AIDE: apt install aide
2. Initialize AIDE database: aideinit
3. Schedule daily check: echo '0 5 * * * root /usr/bin/aide --check' &gt; /etc/cron.d/aide-check
4. Document 30-day verification cycle
5. Configure privileged-user-initiated verification procedures
6. Review AIDE reports and address discrepancies

ISSO/ISSM: Implement 30-day security function verification cycle with AIDE or equivalent."""
    ),
    (
        "V-203758",
        # NotAFinding
        """The operating system shuts down, restarts, or notifies the administrator when security function anomalies are discovered.

Automated scan verified:
- Kernel panic_on_oops is configured for security anomaly response
- systemd logs service failures to journal for administrator review
- Notification mechanisms (mail, rsyslog, SIEM) are available
- XO Audit Plugin tracks application-level anomalies

Security function anomaly response is implemented through kernel panic handling, systemd failure logging, and available notification mechanisms.

ISSO/ISSM: Verify notification procedures reach designated administrators.""",
        # Open
        """The operating system may not properly respond to security function anomalies.

Automated scan found:
- Security function anomaly notification may not be configured
- Mail or alerting mechanisms may not be available
- Administrator notification procedures may not be documented

Remediation steps:
1. Configure kernel panic: sysctl kernel.panic_on_oops=1
2. Install mail utilities: apt install mailutils
3. Configure rsyslog forwarding to SIEM
4. Set up systemd failure notification (systemd-notify or monitoring agent)
5. Enable XO Audit Plugin for application anomaly tracking
6. Document notification procedures and designated administrators

ISSO/ISSM: Implement and document security anomaly notification procedures."""
    ),
    (
        "V-203780",
        # NotAFinding
        """The operating system is configured in accordance with DoD security configuration guidance.

Automated scan verified:
- Operating system is current Debian 12 (supported version)
- STIG compliance scanning is actively being performed (this scan)
- Security hardening measures are in place (AppArmor, ASLR)
- System is maintained with current security patches

The system is configured per applicable DoD security guidance and is actively undergoing STIG compliance assessment.

ISSO/ISSM: Maintain documentation of security configuration baseline and compliance status.""",
        # Open
        """The operating system may not be configured in accordance with DoD security configuration guidance.

Automated scan found:
- Security configuration baseline documentation may be incomplete
- Not all STIG requirements may be addressed
- Configuration may deviate from DoD security guidance

Remediation steps:
1. Complete STIG compliance assessment and generate checklist
2. Document security configuration baseline
3. Address all Open findings per STIG requirements
4. Implement applicable NSA configuration guides
5. Document and track CTOs and DTMs
6. Maintain configuration management documentation

ISSO/ISSM: Complete and document security configuration per all applicable DoD guidance."""
    ),
    (
        "V-203781",
        # NotAFinding
        """The operating system defines default permissions so authenticated users can only read and modify their own files.

Automated scan verified:
- System umask is set to restrictive value (077 or equivalent) in /etc/login.defs
- Home directory permissions restrict access to owner
- PAM session configuration enforces umask
- USERGROUPS_ENAB provides per-user group privacy

Default file permissions ensure authenticated users can only access their own files through restrictive umask settings.

ISSO/ISSM: No additional action required — umask restricts default file permissions appropriately.""",
        # Open
        """The operating system may not define restrictive default permissions for authenticated users.

Automated scan found:
- System umask may be too permissive (less restrictive than 077)
- Home directory permissions may allow other users to access files
- Default permissions may not restrict users to their own files

Remediation steps:
1. Set umask in /etc/login.defs: UMASK 077
2. Set umask in /etc/profile: umask 077
3. Verify home directories: chmod 700 /home/*
4. Verify PAM umask: grep umask /etc/pam.d/common-session
5. Set USERGROUPS_ENAB yes in /etc/login.defs

ISSO/ISSM: Verify umask is 077 or more restrictive for all authenticated users."""
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
