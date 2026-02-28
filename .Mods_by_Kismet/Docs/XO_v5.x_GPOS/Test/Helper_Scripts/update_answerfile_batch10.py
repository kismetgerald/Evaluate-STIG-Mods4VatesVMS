#!/usr/bin/env python3
"""
Update answer file entries for Batch 10 (Access Control & Privilege)
Replaces stub entries with proper 2-index entries (NotAFinding + Open)
"""

import re

AF = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Each entry: vulnid -> (rule_title, expected_nf_status, nf_comment, open_comment)
ENTRIES = {
    "V-203645": {
        "title": "The operating system must implement replay-resistant authentication mechanisms for network access to privileged accounts.",
        "expected": "NotAFinding",
        "nf_comment": (
            "SSHv2 protocol provides replay-resistant authentication for privileged network access on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) OpenSSH uses SSHv2 protocol exclusively (SSHv1 removed since OpenSSH 7.6)\n"
            "(2) SSHv2 uses unique session keys, sequence numbers, and MAC verification per connection\n"
            "(3) Key exchange algorithms (ECDH, Curve25519, DH-GEX) provide ephemeral session keys\n"
            "(4) Each authentication attempt uses fresh cryptographic material preventing replay\n\n"
            "The ISSO/ISSM should verify that SSH is the only remote access method for privileged accounts "
            "and that no legacy protocols (telnet, rsh, rlogin) are enabled."
        ),
        "open_comment": (
            "Replay-resistant authentication is not fully verified for privileged network access.\n\n"
            "Possible findings:\n"
            "(1) Non-SSH remote access methods detected (telnet, rsh, rlogin)\n"
            "(2) SSHv1 protocol support enabled (should be disabled)\n"
            "(3) Weak key exchange algorithms configured\n\n"
            "Remediation:\n"
            "1. Ensure only SSHv2 is used: verify OpenSSH version &gt;= 7.6\n"
            "2. Disable any legacy remote access services: systemctl disable telnet.socket rsh.socket\n"
            "3. Configure strong KexAlgorithms in /etc/ssh/sshd_config\n"
            "4. Restart sshd: systemctl restart sshd"
        ),
    },
    "V-203646": {
        "title": "The operating system must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.",
        "expected": "NotAFinding",
        "nf_comment": (
            "SSHv2 protocol provides replay-resistant authentication for non-privileged network access on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) OpenSSH SSHv2 protections apply equally to all account types\n"
            "(2) Unique session keys and sequence numbers prevent replay attacks\n"
            "(3) All non-privileged users authenticate through the same SSHv2 channel\n\n"
            "The ISSO/ISSM should verify that all non-privileged network access uses SSHv2 "
            "and that no legacy remote access protocols are available."
        ),
        "open_comment": (
            "Replay-resistant authentication is not fully verified for non-privileged network access.\n\n"
            "Possible findings:\n"
            "(1) Non-SSH remote access available to non-privileged users\n"
            "(2) Legacy protocols enabled alongside SSH\n\n"
            "Remediation:\n"
            "1. Ensure all network access uses SSHv2\n"
            "2. Remove any legacy remote access services\n"
            "3. Verify non-privileged users cannot bypass SSH authentication"
        ),
    },
    "V-203647": {
        "title": "The operating system must uniquely identify peripherals before establishing a connection.",
        "expected": "NotAFinding",
        "nf_comment": (
            "The Linux kernel uniquely identifies all peripherals before establishing connections on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) USB devices identified by bus/device/vendor/product IDs via kernel USB subsystem\n"
            "(2) PCI devices identified by bus/slot/function addressing\n"
            "(3) udev device manager handles device enumeration and rule-based access control\n"
            "(4) Kernel assigns unique device nodes (/dev/) for each connected peripheral\n\n"
            "The ISSO/ISSM should verify that unauthorized USB devices are not connected "
            "and that udev rules restrict device access as required by organizational policy."
        ),
        "open_comment": (
            "Peripheral identification may not meet organizational requirements.\n\n"
            "Possible findings:\n"
            "(1) USB auto-authorization enabled without device whitelisting\n"
            "(2) No custom udev rules restricting unauthorized devices\n"
            "(3) Unauthorized peripherals detected on the system\n\n"
            "Remediation:\n"
            "1. Create udev rules in /etc/udev/rules.d/ to whitelist authorized devices\n"
            "2. Set USB authorized_default to 0: echo 0 &gt; /sys/bus/usb/devices/usb1/authorized_default\n"
            "3. Remove unauthorized peripherals and document authorized device inventory"
        ),
    },
    "V-203650": {
        "title": "The operating system must uniquely identify and must authenticate non-organizational users (or processes acting on behalf of non-organizational users).",
        "expected": "NotAFinding",
        "nf_comment": (
            "All users are uniquely identified and authenticated on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) No duplicate UIDs detected in /etc/passwd\n"
            "(2) No generic or shared accounts detected (guest, shared, anonymous, etc.)\n"
            "(3) SSH authentication requires individual credentials (password or key)\n"
            "(4) PAM authentication stack enforces per-user authentication\n\n"
            "The ISSO/ISSM should verify that all non-organizational users have individual accounts "
            "and that no shared credentials are in use."
        ),
        "open_comment": (
            "Issues detected with user account uniqueness or authentication.\n\n"
            "Possible findings:\n"
            "(1) Duplicate UIDs detected in /etc/passwd\n"
            "(2) Generic or shared accounts found (guest, temp, shared, etc.)\n"
            "(3) Non-organizational users without individual authentication\n\n"
            "Remediation:\n"
            "1. Resolve duplicate UIDs: usermod -u &lt;new_uid&gt; &lt;username&gt;\n"
            "2. Remove or rename generic accounts\n"
            "3. Create individual accounts for all non-organizational users\n"
            "4. Disable direct root login: set PermitRootLogin to no in sshd_config"
        ),
    },
    "V-203655": {
        "title": "The operating system must separate user functionality (including user interface services) from operating system management functionality.",
        "expected": "NotAFinding",
        "nf_comment": (
            "User functionality is separated from OS management on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) Administrative tools restricted to /usr/sbin with root ownership\n"
            "(2) sudo installed and configured for privilege separation\n"
            "(3) Service accounts use nologin/false shells (no interactive access)\n"
            "(4) Linux kernel supports namespace-based process isolation\n\n"
            "The ISSO/ISSM should verify that non-administrative users cannot access "
            "OS management tools without explicit sudo authorization."
        ),
        "open_comment": (
            "User functionality may not be fully separated from OS management.\n\n"
            "Possible findings:\n"
            "(1) sudo not installed (no privilege separation mechanism)\n"
            "(2) Service accounts have interactive shells\n"
            "(3) Administrative tools accessible to non-privileged users\n\n"
            "Remediation:\n"
            "1. Install sudo: apt install sudo\n"
            "2. Configure sudo group: usermod -aG sudo &lt;admin_user&gt;\n"
            "3. Set nologin shell for service accounts: usermod -s /usr/sbin/nologin &lt;svc_account&gt;\n"
            "4. Verify /usr/sbin permissions restrict non-root access"
        ),
    },
    "V-203656": {
        "title": "The operating system must isolate security functions from nonsecurity functions.",
        "expected": "NotAFinding",
        "nf_comment": (
            "Security functions are isolated from nonsecurity functions on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) AppArmor MAC framework active with profiles in enforce mode\n"
            "(2) Kernel LSM (Linux Security Module) loaded and enforcing\n"
            "(3) ASLR (Address Space Layout Randomization) enabled (value=2)\n"
            "(4) Process isolation enforced by kernel memory protection\n\n"
            "The ISSO/ISSM should verify that AppArmor profiles are properly configured "
            "for security-critical services and that no profiles are in complain-only mode for production systems."
        ),
        "open_comment": (
            "Security function isolation may not be adequate.\n\n"
            "Possible findings:\n"
            "(1) AppArmor/SELinux not active (no mandatory access control)\n"
            "(2) ASLR disabled or partially enabled\n"
            "(3) Security modules not loaded in kernel\n\n"
            "Remediation:\n"
            "1. Install AppArmor: apt install apparmor apparmor-utils\n"
            "2. Enable AppArmor: systemctl enable --now apparmor\n"
            "3. Enable ASLR: echo 2 &gt; /proc/sys/kernel/randomize_va_space\n"
            "4. Make ASLR persistent: add kernel.randomize_va_space=2 to /etc/sysctl.d/99-security.conf"
        ),
    },
    "V-203696": {
        "title": "The operating system must prevent all software from executing at higher privilege levels than users executing the software.",
        "expected": "NotAFinding",
        "nf_comment": (
            "Privilege escalation controls are in place on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) SUID/SGID binaries limited to standard system utilities in /usr\n"
            "(2) Sudo configured for controlled privilege escalation\n"
            "(3) Mount options (nosuid) applied where appropriate\n"
            "(4) DAC permissions restrict execution of privileged software\n\n"
            "The ISSO/ISSM should periodically review SUID/SGID binaries to ensure "
            "no unauthorized setuid programs have been installed."
        ),
        "open_comment": (
            "Software privilege escalation controls may be insufficient.\n\n"
            "Possible findings:\n"
            "(1) Unauthorized SUID/SGID binaries detected\n"
            "(2) Temporary directories lack nosuid mount option\n"
            "(3) Overly broad sudo rules grant excessive privileges\n\n"
            "Remediation:\n"
            "1. Audit SUID binaries: find / -perm -4000 -type f 2&gt;/dev/null\n"
            "2. Remove unnecessary SUID bits: chmod u-s &lt;binary&gt;\n"
            "3. Add nosuid to /tmp and /var/tmp in /etc/fstab\n"
            "4. Restrict sudo rules to specific commands instead of ALL"
        ),
    },
    "V-203718": {
        "title": "The operating system must enforce access restrictions.",
        "expected": "NotAFinding",
        "nf_comment": (
            "Access restrictions are enforced on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) DAC file permissions properly configured on critical directories\n"
            "(2) /etc/shadow has restrictive permissions (600 or 640, root-owned)\n"
            "(3) Default umask restricts new file permissions\n"
            "(4) No unauthorized world-writable files detected\n\n"
            "The ISSO/ISSM should verify that access restrictions align with organizational policy "
            "and that periodic file permission audits are conducted."
        ),
        "open_comment": (
            "Access restriction enforcement may have gaps.\n\n"
            "Possible findings:\n"
            "(1) World-writable files found outside expected locations\n"
            "(2) Weak umask allowing permissive default permissions\n"
            "(3) Critical files with incorrect ownership or permissions\n\n"
            "Remediation:\n"
            "1. Set restrictive umask: echo 'umask 027' &gt;&gt; /etc/profile.d/umask.sh\n"
            "2. Fix shadow permissions: chmod 640 /etc/shadow; chown root:shadow /etc/shadow\n"
            "3. Remove world-writable bits: find / -xdev -perm -0002 -type f -exec chmod o-w {} \\;\n"
            "4. Review directory permissions for /etc, /var/log, /root, /boot"
        ),
    },
    "V-203719": {
        "title": "The operating system must audit the enforcement actions used to restrict access associated with changes to the system.",
        "expected": "Open",
        "nf_comment": (
            "Audit enforcement actions for access restrictions are properly configured on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) auditd service active and running\n"
            "(2) Permission change syscalls audited (chmod, chown, fchmod, setxattr, etc.)\n"
            "(3) Access denial events (EACCES, EPERM) captured in audit log\n"
            "(4) XO Audit Plugin provides application-layer access enforcement logging\n\n"
            "The ISSO/ISSM should verify audit rules cover all required access enforcement actions "
            "and that audit logs are reviewed regularly."
        ),
        "open_comment": (
            "Audit enforcement of access restrictions is not fully configured.\n\n"
            "Possible findings:\n"
            "(1) auditd service not active\n"
            "(2) Insufficient audit rules for permission change syscalls\n"
            "(3) Access denial events not captured\n\n"
            "Remediation:\n"
            "1. Install auditd: apt install auditd\n"
            "2. Enable auditd: systemctl enable --now auditd\n"
            "3. Add permission change rules to /etc/audit/rules.d/access.rules:\n"
            "   -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -k perm_mod\n"
            "   -a always,exit -F arch=b64 -S chown,fchown,fchownat -F auid&gt;=1000 -k perm_mod\n"
            "4. Add access denial rules:\n"
            "   -a always,exit -F arch=b64 -S open,creat,truncate -F exit=-EACCES -k access\n"
            "5. Reload rules: augenrules --load"
        ),
    },
    "V-203722": {
        "title": "The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.",
        "expected": "Open",
        "nf_comment": (
            "A deny-all, permit-by-exception policy is implemented on this Debian 12 system.\n\n"
            "Evidence:\n"
            "(1) AppArmor active with profiles in enforce mode (application whitelisting)\n"
            "(2) Firewall configured with deny-all default incoming policy\n"
            "(3) Limited APT package sources configured (authorized repositories only)\n"
            "(4) Execution restrictions on temporary directories (noexec mount options)\n\n"
            "The ISSO/ISSM should verify that AppArmor profiles cover all critical applications "
            "and that the firewall deny-all policy is maintained."
        ),
        "open_comment": (
            "Deny-all, permit-by-exception policy is not fully implemented.\n\n"
            "Possible findings:\n"
            "(1) AppArmor not active (no application confinement)\n"
            "(2) No firewall with deny-all default policy\n"
            "(3) Temporary directories allow execution\n\n"
            "Remediation:\n"
            "1. Enable AppArmor: apt install apparmor apparmor-utils; systemctl enable --now apparmor\n"
            "2. Enable firewall with deny-all: ufw default deny incoming; ufw enable\n"
            "3. Add noexec to /tmp and /var/tmp in /etc/fstab\n"
            "4. Restrict APT sources to authorized repositories only\n"
            "5. Create AppArmor profiles for critical applications: aa-genprof &lt;application&gt;"
        ),
    },
}


def build_entry(vulnid, data):
    """Build a proper 2-index answer file entry."""
    # Determine NF expected status
    nf_expected = data["expected"]  # What the function actually returns
    # The other status
    open_expected = "Open" if nf_expected == "NotAFinding" else "NotAFinding"

    return f'''  <Vuln ID="{vulnid}">
    <!--RuleTitle: {data["title"]}-->
    <AnswerKey Name="XO">
      <!--AnswerKey created by Evaluate-STIG_GUI.ps1 and modified by Kismet Agbasi (KismetG17@gmail.com)-->
      <Answer Index="1" ExpectedStatus="{nf_expected}" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <!--Index created by Evaluate-STIG_GUI.ps1-->
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>{nf_expected}</ValidTrueStatus>
        <ValidTrueComment>{data["nf_comment"]}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="{open_expected}" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <!--Index created by Evaluate-STIG_GUI.ps1-->
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>{open_expected}</ValidTrueStatus>
        <ValidTrueComment>{data["open_comment"]}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''


def main():
    with open(AF, 'r', encoding='utf-8') as f:
        content = f.read()

    replacements = 0
    for vulnid, data in ENTRIES.items():
        # Find existing stub entry
        pattern = rf'  <Vuln ID="{vulnid}">.*?</Vuln>'
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            print(f"ERROR: Could not find {vulnid} in answer file")
            continue

        new_entry = build_entry(vulnid, data)
        content = content[:match.start()] + new_entry + content[match.end():]
        replacements += 1
        print(f"OK: {vulnid} updated (ExpectedStatus={data['expected']})")

    with open(AF, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nTotal replacements: {replacements}/10")


if __name__ == "__main__":
    main()
