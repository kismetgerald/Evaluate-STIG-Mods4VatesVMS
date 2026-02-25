#!/usr/bin/env python3
"""Update answer file entries for Batch 2: Authentication & Login (10 functions)."""

import re
import sys

AF_PATH = r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Define 2-index entries for each Batch 2 VulnID
ENTRIES = {
    "V-203595": {
        "title": "Display Standard Mandatory DoD Notice and Consent Banner",
        "nf_comment": """The system displays the Standard Mandatory DoD Notice and Consent Banner.
Automated checks verified:
1. /etc/issue contains DoD banner keywords (USG, consent to monitoring, authorized use)
2. /etc/issue.net contains DoD banner keywords for remote connections
3. SSH banner file is configured in sshd_config
Both local and remote login banners contain the required DoD notice text.""",
        "open_comment": """The system does not display the Standard Mandatory DoD Notice and Consent Banner.
Remediation:
1. Create /etc/issue with the exact DoD banner text
2. Create /etc/issue.net with the same DoD banner text
3. Configure SSH: echo 'Banner /etc/issue.net' &gt;&gt; /etc/ssh/sshd_config
4. Restart SSH: systemctl restart sshd
5. Verify: cat /etc/issue; cat /etc/issue.net"""
    },
    "V-203596": {
        "title": "Display banner until user acknowledges and logs on",
        "nf_comment": """The system displays the DoD banner before user authentication.
Automated checks verified:
1. SSH banner file is configured and points to a valid file
2. /etc/issue contains DoD banner content displayed before login prompt
3. GDM3 graphical login (if installed) shows banner before authentication
The banner is displayed before login and requires user acknowledgment via authentication.""",
        "open_comment": """The system does not properly display banner before authentication.
Remediation:
1. Configure SSH banner: echo 'Banner /etc/issue.net' &gt;&gt; /etc/ssh/sshd_config
2. Populate /etc/issue with DoD banner text
3. Populate /etc/issue.net with DoD banner text
4. If GDM3 installed: gsettings set org.gnome.login-screen banner-message-enable true
5. Restart SSH: systemctl restart sshd"""
    },
    "V-203597": {
        "title": "Limit concurrent sessions to ten",
        "nf_comment": """The system limits concurrent sessions to 10 or fewer.
Automated checks verified:
1. /etc/security/limits.conf contains maxlogins entry &lt;= 10
2. /etc/security/limits.d/ drop-in files checked for maxlogins
3. SSH MaxSessions configured to &lt;= 10
Session limits are enforced through PAM limits or SSH configuration.""",
        "open_comment": """The system does not limit concurrent sessions to 10.
Remediation:
1. Add to /etc/security/limits.conf: * hard maxlogins 10
2. Verify SSH: grep MaxSessions /etc/ssh/sshd_config (set to 10 or less)
3. Restart SSH if changed: systemctl restart sshd
4. Verify: ulimit -u; ssh MaxSessions setting"""
    },
    "V-203598": {
        "title": "Retain session lock until re-authentication",
        "nf_comment": """The system retains session lock until user re-authenticates.
Automated checks verified:
1. tmux or screen installed for session lock capability
2. vlock or physlock available for console lock requiring password
3. SSH ClientAliveInterval configured to drop idle sessions
Session lock requires re-authentication via password or key to unlock.""",
        "open_comment": """The system does not retain session lock until re-authentication.
Remediation:
1. Install tmux: apt install tmux
2. Install vlock: apt install vlock (or physlock)
3. Configure SSH: ClientAliveInterval 900 in /etc/ssh/sshd_config
4. Configure tmux lock: set -g lock-command vlock in /etc/tmux.conf
5. Restart SSH: systemctl restart sshd"""
    },
    "V-203599": {
        "title": "Initiate session lock after 15-minute inactivity",
        "nf_comment": """The system initiates session lock after 15 minutes of inactivity.
Automated checks verified:
1. SSH ClientAliveInterval set to &lt;= 900 seconds (15 minutes)
2. TMOUT shell variable configured to &lt;= 900 seconds
3. tmux lock-after-time configured (if applicable)
Inactivity timeout enforced through SSH and/or shell timeout.""",
        "open_comment": """The system does not lock sessions after 15 minutes of inactivity.
Remediation:
1. SSH: Set ClientAliveInterval 900 and ClientAliveCountMax 0 in /etc/ssh/sshd_config
2. Shell: Add 'TMOUT=900; export TMOUT; readonly TMOUT' to /etc/profile.d/tmout.sh
3. tmux: Add 'set -g lock-after-time 900' to /etc/tmux.conf
4. Restart SSH: systemctl restart sshd
5. Verify: sshd -T | grep clientaliveinterval"""
    },
    "V-203600": {
        "title": "User-initiated session lock capability",
        "nf_comment": """The system provides user-initiated session lock capability.
Automated checks verified:
1. vlock or physlock installed for console lock (user can lock terminal)
2. tmux installed (lock-session via Ctrl-b + L)
3. GNU screen installed (lock via Ctrl-a + x)
At least one session lock mechanism is available for user-initiated locking.""",
        "open_comment": """The system does not provide user-initiated session lock capability.
Remediation:
1. Install tmux: apt install tmux (provides Ctrl-b + L lock)
2. Install vlock: apt install vlock (provides console lock)
3. Or install screen: apt install screen (provides Ctrl-a + x lock)
4. Configure default tmux lock: echo 'set -g lock-command vlock' &gt;&gt; /etc/tmux.conf
5. Verify: which tmux; which vlock"""
    },
    "V-203601": {
        "title": "Conceal display with publicly viewable image on session lock",
        "nf_comment": """The system conceals display content when session is locked.
Automated checks verified:
1. GDM3 screensaver lock clears display (if GUI installed)
2. tmux lock-session clears terminal and shows lock screen
3. vlock/physlock clears terminal display
4. SSH timeout disconnects remote sessions clearing display
Session lock utilities conceal previously visible information.""",
        "open_comment": """The system does not conceal display content on session lock.
Remediation:
1. Install tmux: apt install tmux (lock-session clears display)
2. Install vlock: apt install vlock (clears terminal on lock)
3. If GUI: gsettings set org.gnome.desktop.screensaver lock-enabled true
4. Configure tmux: set -g lock-command vlock in /etc/tmux.conf
5. Verify lock conceals display by testing: tmux lock-session"""
    },
    "V-203635": {
        "title": "Obscure authentication feedback",
        "nf_comment": """The system obscures authentication feedback during password entry.
Automated checks verified:
1. PAM uses standard password input (no echo to terminal)
2. SSH password authentication uses terminal no-echo mode by design
3. sudo pwfeedback option is NOT enabled (no asterisk display)
All authentication mechanisms properly obscure password input.""",
        "open_comment": """The system does not properly obscure authentication feedback.
Remediation:
1. Remove pwfeedback from sudoers: visudo, remove 'Defaults pwfeedback'
2. Verify PAM config: grep -v '^#' /etc/pam.d/common-password
3. Ensure no custom login programs echo passwords
4. Verify SSH: password input is not displayed (default behavior)
5. Test: attempt SSH login and verify no characters displayed during password entry"""
    },
    "V-203665": {
        "title": "Public connection DoD banner",
        "nf_comment": """The system displays the DoD banner for public/remote connections.
Automated checks verified:
1. SSH banner file configured and contains DoD notice text
2. /etc/motd checked for post-login DoD banner
3. /etc/issue.net contains DoD banner for remote connections
The SSH banner file contains the required DoD consent and monitoring notice.""",
        "open_comment": """The system does not display DoD banner for public connections.
Remediation:
1. Create banner file: echo 'You are accessing a U.S. Government...' &gt; /etc/issue.net
2. Configure SSH: echo 'Banner /etc/issue.net' &gt;&gt; /etc/ssh/sshd_config
3. Optionally populate /etc/motd with DoD banner text
4. Restart SSH: systemctl restart sshd
5. Verify: ssh user@host (should see banner before password prompt)"""
    },
    "V-203779": {
        "title": "Enforce 4-second delay after failed logon",
        "nf_comment": """The system enforces a 4-second delay after failed logon attempts.
Automated checks verified:
1. pam_faildelay configured with delay &gt;= 4000000 microseconds (4 seconds)
2. pam_unix nodelay option is NOT set (default delay preserved)
3. SSH LoginGraceTime checked for reasonable timeout
Authentication delay prevents brute-force and timing attacks.""",
        "open_comment": """The system does not enforce a 4-second delay after failed logon.
Remediation:
1. Add to /etc/pam.d/common-auth: auth optional pam_faildelay.so delay=4000000
2. Verify pam_unix does NOT have nodelay: grep nodelay /etc/pam.d/common-auth
3. Remove nodelay if present from pam_unix line
4. Verify: faillock test or attempt failed login and time the delay
5. The delay value is in microseconds: 4000000 = 4 seconds"""
    },
}

def main():
    with open(AF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    for vuln_id, data in ENTRIES.items():
        title = data["title"]
        nf_comment = data["nf_comment"].strip()
        open_comment = data["open_comment"].strip()

        # Build the new entry
        new_entry = f'''  <Vuln ID="{vuln_id}">
    <!--RuleTitle: {title}-->
    <AnswerKey Name="XO">
      <!--AnswerKey created by Evaluate-STIG_GUI.ps1 and modified by Kismet Agbasi (KismetGerald.Agbasi@ngc.com)-->
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''

        # Find and replace the existing stub entry
        pattern = rf'  <Vuln ID="{vuln_id}">.*?</Vuln>'
        match = re.search(pattern, content, re.DOTALL)
        if match:
            content = content[:match.start()] + new_entry + content[match.end():]
            print(f"  Updated {vuln_id}: {title}")
        else:
            print(f"  WARNING: {vuln_id} not found in answer file!")

    with open(AF_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    # Validate Vuln count
    vuln_count = len(re.findall(r'<Vuln ID="V-', content))
    print(f"\nTotal Vuln entries: {vuln_count}")
    print("Done!")

if __name__ == "__main__":
    main()
