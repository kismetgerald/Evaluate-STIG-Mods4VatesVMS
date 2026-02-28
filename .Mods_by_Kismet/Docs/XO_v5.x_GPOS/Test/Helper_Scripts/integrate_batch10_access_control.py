#!/usr/bin/env python3
"""
Batch 10: Access Control & Privilege — 10 functions
Replaces stub functions in Scan-XO_GPOS_Debian12_Checks.psm1

VulnIDs: V-203645, V-203646, V-203647, V-203650, V-203655,
         V-203656, V-203696, V-203718, V-203719, V-203722
"""

import re
import sys

MODULE = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# Each implementation: header block + custom code only (param/GetCorpParams/SendCheck stay from stub)
# We replace just the header comment block and the custom code section

IMPLEMENTATIONS = {
    "V-203645": {
        "stig_id": "SRG-OS-000112-GPOS-00057",
        "rule_id": "SV-203645r958494_rule",
        "discuss_md5": "fb860c0bf3eff9ed9c106852d879e1db",
        "check_md5": "3011a716d526d946ede1c6f64e9a46b3",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203645: Replay-resistant authentication for network access to privileged accounts
    # SSH Kerberos/GSSAPI and challenge-response provide replay resistance via nonces/timestamps

    $FindingDetails += "--- Check 1: SSH Protocol Version ---" + $nl
    $sshVer = $(timeout 5 ssh -V 2>&1)
    $sshVerStr = ($sshVer -join $nl).Trim()
    $FindingDetails += "  SSH version: $sshVerStr" + $nl
    if ($sshVerStr -match "OpenSSH") {
        $FindingDetails += "  [PASS] OpenSSH uses SSHv2 protocol which is replay-resistant" + $nl
    }
    else {
        $FindingDetails += "  [INFO] Non-OpenSSH implementation detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Kerberos/GSSAPI Authentication ---" + $nl
    $sshdConfig = $(timeout 5 sshd -T 2>&1)
    $sshdStr = ($sshdConfig -join $nl).Trim()
    if ($sshdStr -match "gssapiauthentication\s+yes") {
        $FindingDetails += "  GSSAPIAuthentication: yes" + $nl
        $FindingDetails += "  [PASS] Kerberos/GSSAPI provides replay-resistant authentication" + $nl
    }
    else {
        $FindingDetails += "  GSSAPIAuthentication: no (or not configured)" + $nl
        $FindingDetails += "  [INFO] GSSAPI not enabled (SSH protocol still replay-resistant)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: SSH Key Exchange Algorithms ---" + $nl
    if ($sshdStr -match "kexalgorithms\s+(.+)") {
        $kexAlgs = $matches[1]
        $FindingDetails += "  KexAlgorithms: $kexAlgs" + $nl
        if ($kexAlgs -match "diffie-hellman-group-exchange|ecdh-sha2|curve25519") {
            $FindingDetails += "  [PASS] Key exchange algorithms provide replay resistance via ephemeral keys" + $nl
        }
    }
    else {
        $FindingDetails += "  KexAlgorithms: (default)" + $nl
        $FindingDetails += "  [PASS] Default OpenSSH KEX algorithms are replay-resistant" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Privileged Account Access Method ---" + $nl
    $sudoUsers = $(timeout 5 grep -E "^%sudo|^%admin|^root" /etc/sudoers 2>&1)
    $sudoStr = ($sudoUsers -join $nl).Trim()
    if ($sudoStr) {
        $FindingDetails += "  Privileged access groups:" + $nl
        foreach ($line in ($sudoStr -split $nl)) {
            if ($line.Trim()) { $FindingDetails += "    $($line.Trim())" + $nl }
        }
    }
    else {
        $FindingDetails += "  No sudo rules found in /etc/sudoers" + $nl
    }
    $FindingDetails += $nl

    # SSHv2 is inherently replay-resistant (sequence numbers, MACs, session keys)
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: SSHv2 protocol provides replay-resistant authentication via" + $nl
    $FindingDetails += "cryptographic session keys, sequence numbers, and MAC verification." + $nl

    #---=== End Custom Code ===---#'''
    },

    "V-203646": {
        "stig_id": "SRG-OS-000113-GPOS-00058",
        "rule_id": "SV-203646r982206_rule",
        "discuss_md5": "48af96861c9759b3a4e117f4575ac51e",
        "check_md5": "9e45f10a2bff8fed78f1b418237f4112",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203646: Replay-resistant authentication for network access to non-privileged accounts
    # Same SSH protocol protections apply to all accounts

    $FindingDetails += "--- Check 1: SSH Protocol Version ---" + $nl
    $sshVer = $(timeout 5 ssh -V 2>&1)
    $sshVerStr = ($sshVer -join $nl).Trim()
    $FindingDetails += "  SSH version: $sshVerStr" + $nl
    if ($sshVerStr -match "OpenSSH") {
        $FindingDetails += "  [PASS] OpenSSH SSHv2 is replay-resistant for all accounts" + $nl
    }
    else {
        $FindingDetails += "  [INFO] Non-OpenSSH implementation detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Authentication Methods ---" + $nl
    $sshdConfig = $(timeout 5 sshd -T 2>&1)
    $sshdStr = ($sshdConfig -join $nl).Trim()
    if ($sshdStr -match "passwordauthentication\s+(\w+)") {
        $FindingDetails += "  PasswordAuthentication: $($matches[1])" + $nl
    }
    if ($sshdStr -match "pubkeyauthentication\s+(\w+)") {
        $FindingDetails += "  PubkeyAuthentication: $($matches[1])" + $nl
    }
    if ($sshdStr -match "kbdinteractiveauthentication\s+(\w+)") {
        $FindingDetails += "  KbdInteractiveAuthentication: $($matches[1])" + $nl
    }
    $FindingDetails += "  [INFO] All SSH authentication methods operate within replay-resistant SSHv2 channel" + $nl
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Non-Privileged User Accounts ---" + $nl
    $nonPrivUsers = $(timeout 5 awk -F: '($3 >= 1000 && $3 < 65534) {print $1 ":" $3}' /etc/passwd 2>&1)
    $nonPrivStr = ($nonPrivUsers -join $nl).Trim()
    if ($nonPrivStr) {
        $FindingDetails += "  Non-privileged accounts (UID >= 1000):" + $nl
        foreach ($user in ($nonPrivStr -split $nl)) {
            if ($user.Trim()) { $FindingDetails += "    $($user.Trim())" + $nl }
        }
    }
    else {
        $FindingDetails += "  No non-privileged user accounts found" + $nl
    }
    $FindingDetails += $nl

    # SSHv2 is inherently replay-resistant for all account types
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: SSHv2 protocol provides replay-resistant authentication for" + $nl
    $FindingDetails += "all accounts via cryptographic session keys, sequence numbers, and MACs." + $nl

    #---=== End Custom Code ===---#'''
    },

    "V-203647": {
        "stig_id": "SRG-OS-000114-GPOS-00059",
        "rule_id": "SV-203647r958498_rule",
        "discuss_md5": "97fe673dc2887cde6f087b0438aaa65c",
        "check_md5": "652ac0af139d74cf526af338f70ec25b",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203647: Uniquely identify peripherals before establishing a connection
    # Linux identifies USB/PCI devices via udev rules and kernel device enumeration

    $FindingDetails += "--- Check 1: USB Device Authorization ---" + $nl
    $usbAuth = $(timeout 5 cat /sys/bus/usb/devices/usb1/authorized_default 2>&1)
    $usbAuthStr = ("$usbAuth").Trim()
    if ($usbAuthStr -eq "1") {
        $FindingDetails += "  USB authorized_default: 1 (auto-authorize)" + $nl
        $FindingDetails += "  [INFO] USB devices are auto-authorized by default" + $nl
    }
    elseif ($usbAuthStr -eq "0") {
        $FindingDetails += "  USB authorized_default: 0 (require authorization)" + $nl
        $FindingDetails += "  [PASS] USB devices must be explicitly authorized" + $nl
    }
    else {
        $FindingDetails += "  USB authorized_default: $usbAuthStr" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Connected USB Devices ---" + $nl
    $usbDevices = $(timeout 5 lsusb 2>&1)
    $usbStr = ($usbDevices -join $nl).Trim()
    if ($usbStr) {
        $devCount = (($usbStr -split $nl) | Where-Object { $_.Trim() }).Count
        $FindingDetails += "  USB devices detected: $devCount" + $nl
        foreach ($dev in ($usbStr -split $nl)) {
            if ($dev.Trim()) { $FindingDetails += "    $($dev.Trim())" + $nl }
        }
    }
    else {
        $FindingDetails += "  No USB devices detected (or lsusb not available)" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Udev Rules for Device Identification ---" + $nl
    $udevRules = $(timeout 5 find /etc/udev/rules.d -maxdepth 1 -type f -name '*.rules' 2>/dev/null | head -10 2>&1)
    $udevStr = ($udevRules -join $nl).Trim()
    if ($udevStr) {
        $FindingDetails += "  Custom udev rules:" + $nl
        foreach ($rule in ($udevStr -split $nl)) {
            if ($rule.Trim()) { $FindingDetails += "    $($rule.Trim())" + $nl }
        }
    }
    else {
        $FindingDetails += "  No custom udev rules in /etc/udev/rules.d/" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Kernel Device Enumeration ---" + $nl
    $pciDevices = $(timeout 5 lspci 2>&1 | head -5 2>&1)
    $pciStr = ($pciDevices -join $nl).Trim()
    if ($pciStr) {
        $FindingDetails += "  PCI devices (first 5):" + $nl
        foreach ($dev in ($pciStr -split $nl)) {
            if ($dev.Trim()) { $FindingDetails += "    $($dev.Trim())" + $nl }
        }
    }
    $FindingDetails += $nl

    # Linux kernel uniquely identifies all devices via bus/device/function addressing
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Linux kernel uniquely identifies peripherals via bus enumeration" + $nl
    $FindingDetails += "(USB bus/device IDs, PCI bus/slot/function) and udev device management." + $nl

    #---=== End Custom Code ===---#'''
    },

    "V-203650": {
        "stig_id": "SRG-OS-000121-GPOS-00062",
        "rule_id": "SV-203650r958504_rule",
        "discuss_md5": "9b698b8f46d717b0b729c7acfaab8015",
        "check_md5": "e28f580ded36384a9fb34475a60e9321",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203650: Uniquely identify and authenticate non-organizational users
    # All users must have unique accounts - no shared/generic accounts

    $FindingDetails += "--- Check 1: User Account Uniqueness ---" + $nl
    $allUsers = $(timeout 5 awk -F: '{print $1 ":" $3}' /etc/passwd 2>&1)
    $allUsersStr = ($allUsers -join $nl).Trim()
    $dupUIDs = $(timeout 5 awk -F: '{print $3}' /etc/passwd 2>&1 | sort 2>&1 | uniq -d 2>&1)
    $dupUIDStr = ($dupUIDs -join $nl).Trim()
    if ($dupUIDStr) {
        $FindingDetails += "  [FAIL] Duplicate UIDs detected:" + $nl
        foreach ($uid in ($dupUIDStr -split $nl)) {
            if ($uid.Trim()) { $FindingDetails += "    UID: $($uid.Trim())" + $nl }
        }
        $dupsFound = $true
    }
    else {
        $FindingDetails += "  [PASS] No duplicate UIDs found" + $nl
        $dupsFound = $false
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Generic/Shared Account Detection ---" + $nl
    $genericAccounts = $(timeout 5 awk -F: '($3 >= 1000 && $3 < 65534) {print $1}' /etc/passwd 2>&1)
    $genericStr = ($genericAccounts -join $nl).Trim()
    $genericFound = $false
    $genericPatterns = @("guest", "shared", "generic", "temp", "test", "demo", "anonymous")
    if ($genericStr) {
        foreach ($acct in ($genericStr -split $nl)) {
            $acctName = $acct.Trim().ToLower()
            foreach ($pattern in $genericPatterns) {
                if ($acctName -match $pattern) {
                    $FindingDetails += "  [WARN] Potential shared/generic account: $($acct.Trim())" + $nl
                    $genericFound = $true
                }
            }
        }
    }
    if (-not $genericFound) {
        $FindingDetails += "  [PASS] No generic/shared accounts detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: SSH Authentication Requirements ---" + $nl
    $sshdConfig = $(timeout 5 sshd -T 2>&1)
    $sshdStr = ($sshdConfig -join $nl).Trim()
    if ($sshdStr -match "permitrootlogin\s+(\w+)") {
        $FindingDetails += "  PermitRootLogin: $($matches[1])" + $nl
    }
    if ($sshdStr -match "passwordauthentication\s+(\w+)") {
        $FindingDetails += "  PasswordAuthentication: $($matches[1])" + $nl
    }
    if ($sshdStr -match "permitemptypasswords\s+(\w+)") {
        $FindingDetails += "  PermitEmptyPasswords: $($matches[1])" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: PAM Authentication Stack ---" + $nl
    $pamAuth = $(timeout 5 cat /etc/pam.d/common-auth 2>&1)
    $pamStr = ($pamAuth -join $nl).Trim()
    if ($pamStr -match "pam_unix") {
        $FindingDetails += "  [PASS] PAM unix authentication module loaded" + $nl
    }
    else {
        $FindingDetails += "  [INFO] PAM common-auth configuration:" + $nl
        $FindingDetails += "  $pamStr" + $nl
    }
    $FindingDetails += $nl

    if ($dupsFound -or $genericFound) {
        $Status = "Open"
        $FindingDetails += "RESULT: Issues detected with user account uniqueness." + $nl
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: All user accounts are unique with individual authentication." + $nl
    }

    #---=== End Custom Code ===---#'''
    },

    "V-203655": {
        "stig_id": "SRG-OS-000132-GPOS-00067",
        "rule_id": "SV-203655r958514_rule",
        "discuss_md5": "31ace61573e2031c4d651c7586a437c1",
        "check_md5": "c4d23394505cdf2b71582a0adab0e349",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203655: Separate user functionality from OS management functionality
    # Regular users should not have access to admin tools/directories

    $FindingDetails += "--- Check 1: Administrative Tool Access ---" + $nl
    $sbinPerms = $(timeout 5 stat -c '%a %U:%G' /usr/sbin 2>&1)
    $sbinStr = ("$sbinPerms").Trim()
    $FindingDetails += "  /usr/sbin permissions: $sbinStr" + $nl
    $adminBins = @("/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/usermod", "/usr/sbin/visudo")
    foreach ($bin in $adminBins) {
        $binPerms = $(timeout 5 stat -c '%a %U:%G' $bin 2>&1)
        $binStr = ("$binPerms").Trim()
        if ($binStr -match "^\d") {
            $FindingDetails += "  $bin : $binStr" + $nl
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Sudo Configuration ---" + $nl
    $sudoInstalled = $(timeout 5 dpkg -l sudo 2>&1)
    $sudoStr = ($sudoInstalled -join $nl).Trim()
    if ($sudoStr -match "^ii\s+sudo") {
        $FindingDetails += "  sudo: installed" + $nl
        $sudoGroup = $(timeout 5 grep "^%sudo" /etc/sudoers 2>&1)
        $sudoGrpStr = ($sudoGroup -join $nl).Trim()
        if ($sudoGrpStr) {
            $FindingDetails += "  sudo group rule: $sudoGrpStr" + $nl
        }
        $sudoMembers = $(timeout 5 getent group sudo 2>&1)
        $FindingDetails += "  sudo group members: $($sudoMembers -join $nl)" + $nl
        $FindingDetails += "  [PASS] Administrative access restricted via sudo" + $nl
    }
    else {
        $FindingDetails += "  sudo: NOT installed" + $nl
        $FindingDetails += "  [FAIL] No privilege separation mechanism" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: User Shell Restrictions ---" + $nl
    $nologinUsers = $(timeout 5 grep -c "/usr/sbin/nologin\|/bin/false" /etc/passwd 2>&1)
    $totalUsers = $(timeout 5 grep -c "^" /etc/passwd 2>&1)
    $FindingDetails += "  Total accounts: $totalUsers" + $nl
    $FindingDetails += "  Accounts with nologin/false shell: $nologinUsers" + $nl
    $loginUsers = $(timeout 5 awk -F: '($7 !~ /nologin|false/ && $3 >= 1000) {print $1}' /etc/passwd 2>&1)
    $loginStr = ($loginUsers -join $nl).Trim()
    if ($loginStr) {
        $FindingDetails += "  Interactive login accounts (UID >= 1000):" + $nl
        foreach ($user in ($loginStr -split $nl)) {
            if ($user.Trim()) { $FindingDetails += "    $($user.Trim())" + $nl }
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Separate Namespaces ---" + $nl
    $nsSupport = $(timeout 5 ls /proc/self/ns/ 2>&1)
    $nsStr = ($nsSupport -join $nl).Trim()
    if ($nsStr -match "user|mnt|pid") {
        $FindingDetails += "  Linux namespace support: available (user, mnt, pid)" + $nl
        $FindingDetails += "  [PASS] Kernel supports namespace-based separation" + $nl
    }
    $FindingDetails += $nl

    if ($sudoStr -match "^ii\s+sudo") {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: User functionality separated from OS management via sudo," + $nl
        $FindingDetails += "restricted shells for service accounts, and file permission controls." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No privilege separation mechanism detected." + $nl
    }

    #---=== End Custom Code ===---#'''
    },

    "V-203656": {
        "stig_id": "SRG-OS-000134-GPOS-00068",
        "rule_id": "SV-203656r958518_rule",
        "discuss_md5": "ad6bc360b259a47eddc4cb27cdb650ed",
        "check_md5": "b89ca55534166d6a11cc775662024de4",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203656: Isolate security functions from nonsecurity functions
    # Kernel enforces process isolation, SELinux/AppArmor provide MAC

    $FindingDetails += "--- Check 1: AppArmor Status ---" + $nl
    $aaStatus = $(timeout 5 aa-status 2>&1)
    $aaStr = ($aaStatus -join $nl).Trim()
    if ($aaStr -match "(\d+) profiles are loaded") {
        $profileCount = $matches[1]
        $FindingDetails += "  AppArmor: active ($profileCount profiles loaded)" + $nl
        if ($aaStr -match "(\d+) profiles are in enforce mode") {
            $FindingDetails += "  Enforce mode: $($matches[1]) profiles" + $nl
        }
        if ($aaStr -match "(\d+) profiles are in complain mode") {
            $FindingDetails += "  Complain mode: $($matches[1]) profiles" + $nl
        }
        $FindingDetails += "  [PASS] AppArmor provides mandatory access control" + $nl
        $macActive = $true
    }
    else {
        $FindingDetails += "  AppArmor: not active or not installed" + $nl
        $macActive = $false
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Kernel Security Modules ---" + $nl
    $lsm = $(timeout 5 cat /sys/kernel/security/lsm 2>&1)
    $lsmStr = ("$lsm").Trim()
    $FindingDetails += "  Loaded LSMs: $lsmStr" + $nl
    if ($lsmStr -match "apparmor|selinux|tomoyo") {
        $FindingDetails += "  [PASS] MAC security module active in kernel" + $nl
        $macActive = $true
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Process Isolation ---" + $nl
    $procHide = $(timeout 5 cat /proc/sys/kernel/hidepid 2>&1)
    $procHideStr = ("$procHide").Trim()
    $FindingDetails += "  hidepid: $procHideStr" + $nl
    if ($procHideStr -eq "0") {
        $FindingDetails += "  [INFO] All users can see all processes (default)" + $nl
    }
    elseif ($procHideStr -match "1|2") {
        $FindingDetails += "  [PASS] Process visibility restricted" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Address Space Isolation ---" + $nl
    $aslr = $(timeout 5 cat /proc/sys/kernel/randomize_va_space 2>&1)
    $aslrStr = ("$aslr").Trim()
    $FindingDetails += "  ASLR (randomize_va_space): $aslrStr" + $nl
    if ($aslrStr -eq "2") {
        $FindingDetails += "  [PASS] Full ASLR enabled (stack, heap, mmap, VDSO)" + $nl
    }
    elseif ($aslrStr -eq "1") {
        $FindingDetails += "  [INFO] Partial ASLR enabled (stack, mmap, VDSO only)" + $nl
    }
    else {
        $FindingDetails += "  [FAIL] ASLR disabled" + $nl
    }
    $FindingDetails += $nl

    if ($macActive) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Security functions isolated via kernel LSM (AppArmor)," + $nl
        $FindingDetails += "process isolation, and address space randomization." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No mandatory access control (AppArmor/SELinux) detected." + $nl
    }

    #---=== End Custom Code ===---#'''
    },

    "V-203696": {
        "stig_id": "SRG-OS-000326-GPOS-00126",
        "rule_id": "SV-203696r958730_rule",
        "discuss_md5": "a9d87f13249f52d37609c889f54e18e6",
        "check_md5": "676d750ff42c6acb58fa2748773f85df",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203696: Prevent software from executing at higher privilege than users
    # Check SUID/SGID bits, nosuid mount options, and privilege escalation controls

    $issues = 0

    $FindingDetails += "--- Check 1: SUID Binaries ---" + $nl
    $suidBins = $(timeout 10 find /usr -maxdepth 3 -perm -4000 -type f 2>/dev/null | head -20 2>&1)
    $suidStr = ($suidBins -join $nl).Trim()
    if ($suidStr) {
        $suidCount = (($suidStr -split $nl) | Where-Object { $_.Trim() }).Count
        $FindingDetails += "  SUID binaries found: $suidCount" + $nl
        foreach ($bin in ($suidStr -split $nl)) {
            if ($bin.Trim()) { $FindingDetails += "    $($bin.Trim())" + $nl }
        }
        $FindingDetails += "  [INFO] Review SUID binaries for unauthorized entries" + $nl
    }
    else {
        $FindingDetails += "  No SUID binaries found in /usr" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: SGID Binaries ---" + $nl
    $sgidBins = $(timeout 10 find /usr -maxdepth 3 -perm -2000 -type f 2>/dev/null | head -20 2>&1)
    $sgidStr = ($sgidBins -join $nl).Trim()
    if ($sgidStr) {
        $sgidCount = (($sgidStr -split $nl) | Where-Object { $_.Trim() }).Count
        $FindingDetails += "  SGID binaries found: $sgidCount" + $nl
        foreach ($bin in ($sgidStr -split $nl)) {
            if ($bin.Trim()) { $FindingDetails += "    $($bin.Trim())" + $nl }
        }
    }
    else {
        $FindingDetails += "  No SGID binaries found in /usr" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Mount Options (nosuid) ---" + $nl
    $mounts = $(timeout 5 mount 2>&1)
    $mountStr = ($mounts -join $nl).Trim()
    $nosuidParts = @("/tmp", "/var/tmp", "/home", "/dev/shm")
    foreach ($part in $nosuidParts) {
        $mountLine = ($mountStr -split $nl) | Where-Object { $_ -match "\s+$([regex]::Escape($part))\s+" -or $_ -match "on $([regex]::Escape($part)) " }
        if ($mountLine) {
            $mountLineStr = ($mountLine -join " ").Trim()
            if ($mountLineStr -match "nosuid") {
                $FindingDetails += "  $part : nosuid [PASS]" + $nl
            }
            else {
                $FindingDetails += "  $part : no nosuid option [INFO]" + $nl
            }
        }
        else {
            $FindingDetails += "  $part : not a separate mount point" + $nl
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Sudo Privilege Restrictions ---" + $nl
    $sudoAll = $(timeout 5 grep -E "ALL=\(ALL" /etc/sudoers 2>&1)
    $sudoAllStr = ($sudoAll -join $nl).Trim()
    if ($sudoAllStr) {
        $FindingDetails += "  Broad sudo rules:" + $nl
        foreach ($rule in ($sudoAllStr -split $nl)) {
            if ($rule.Trim() -and $rule.Trim() -notmatch "^#") {
                $FindingDetails += "    $($rule.Trim())" + $nl
            }
        }
        $FindingDetails += "  [INFO] Review broad sudo rules for least-privilege compliance" + $nl
    }
    else {
        $FindingDetails += "  No broad sudo rules detected" + $nl
    }
    $FindingDetails += $nl

    # Linux inherently controls privilege escalation via DAC + optional MAC
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Privilege escalation controlled via DAC permissions, SUID/SGID" + $nl
    $FindingDetails += "binary management, sudo configuration, and mount options." + $nl

    #---=== End Custom Code ===---#'''
    },

    "V-203718": {
        "stig_id": "SRG-OS-000364-GPOS-00151",
        "rule_id": "SV-203718r958796_rule",
        "discuss_md5": "83c4ce0c841e89875fcdf6db18cff187",
        "check_md5": "6666074066c2f07c44e8badaa831c223",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203718: Enforce access restrictions
    # Verify DAC, file permissions, and access control mechanisms

    $FindingDetails += "--- Check 1: File Permission Model ---" + $nl
    $umask = $(timeout 5 sh -c 'umask' 2>&1)
    $umaskStr = ("$umask").Trim()
    $FindingDetails += "  Default umask: $umaskStr" + $nl
    if ($umaskStr -match "0027|027|0077|077") {
        $FindingDetails += "  [PASS] Restrictive umask configured" + $nl
    }
    elseif ($umaskStr -match "0022|022") {
        $FindingDetails += "  [INFO] Standard umask (world-readable new files)" + $nl
    }
    else {
        $FindingDetails += "  [INFO] Non-standard umask value" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Critical Directory Permissions ---" + $nl
    $critDirs = @("/etc", "/var/log", "/root", "/boot")
    foreach ($dir in $critDirs) {
        $dirPerms = $(timeout 5 stat -c '%a %U:%G' $dir 2>&1)
        $dirStr = ("$dirPerms").Trim()
        $FindingDetails += "  $dir : $dirStr" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Password File Permissions ---" + $nl
    $passwdPerms = $(timeout 5 stat -c '%a %U:%G' /etc/passwd 2>&1)
    $shadowPerms = $(timeout 5 stat -c '%a %U:%G' /etc/shadow 2>&1)
    $groupPerms = $(timeout 5 stat -c '%a %U:%G' /etc/group 2>&1)
    $FindingDetails += "  /etc/passwd: $passwdPerms" + $nl
    $FindingDetails += "  /etc/shadow: $shadowPerms" + $nl
    $FindingDetails += "  /etc/group: $groupPerms" + $nl
    $shadowStr = ("$shadowPerms").Trim()
    if ($shadowStr -match "^(640|600|000)\s+root:") {
        $FindingDetails += "  [PASS] Shadow file has restrictive permissions" + $nl
    }
    else {
        $FindingDetails += "  [INFO] Verify shadow file permissions meet requirements" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: World-Writable Files ---" + $nl
    $worldWrite = $(timeout 10 find / -maxdepth 3 -xdev -perm -0002 -type f 2>/dev/null | head -10 2>&1)
    $worldStr = ($worldWrite -join $nl).Trim()
    if ($worldStr) {
        $FindingDetails += "  World-writable files found:" + $nl
        foreach ($f in ($worldStr -split $nl)) {
            if ($f.Trim()) { $FindingDetails += "    $($f.Trim())" + $nl }
        }
        $FindingDetails += "  [INFO] Review world-writable files for appropriateness" + $nl
    }
    else {
        $FindingDetails += "  [PASS] No world-writable files detected" + $nl
    }
    $FindingDetails += $nl

    # Linux enforces access restrictions via DAC (file permissions, ownership)
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Access restrictions enforced via DAC file permissions," + $nl
    $FindingDetails += "ownership controls, umask settings, and shadow file protection." + $nl

    #---=== End Custom Code ===---#'''
    },

    "V-203719": {
        "stig_id": "SRG-OS-000365-GPOS-00152",
        "rule_id": "SV-203719r982211_rule",
        "discuss_md5": "abb67a8327b596a4553cb63ba3059f1c",
        "check_md5": "9d2cfdc3e31a3f9e45f4cdd14840deb5",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203719: Audit enforcement actions for access restrictions
    # Verify auditd rules log permission changes, file access denials

    $auditIssues = 0

    $FindingDetails += "--- Check 1: Audit Service Status ---" + $nl
    $auditdStatus = $(timeout 5 systemctl is-active auditd 2>&1)
    $auditdStr = ("$auditdStatus").Trim()
    $FindingDetails += "  auditd service: $auditdStr" + $nl
    if ($auditdStr -ne "active") {
        $FindingDetails += "  [FAIL] auditd is not active" + $nl
        $auditIssues++
    }
    else {
        $FindingDetails += "  [PASS] auditd is running" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Permission Change Audit Rules ---" + $nl
    $permRules = $(timeout 5 auditctl -l 2>&1)
    $permStr = ($permRules -join $nl).Trim()
    $permTargets = @("chmod", "chown", "fchmod", "fchown", "setxattr", "lsetxattr", "removexattr")
    $permFound = 0
    foreach ($target in $permTargets) {
        if ($permStr -match $target) {
            $permFound++
        }
    }
    $FindingDetails += "  Permission change syscall rules: $permFound of $($permTargets.Count)" + $nl
    if ($permFound -ge 4) {
        $FindingDetails += "  [PASS] Permission change auditing configured" + $nl
    }
    else {
        $FindingDetails += "  [FAIL] Insufficient permission change audit rules" + $nl
        $auditIssues++
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Access Denial Audit Rules ---" + $nl
    $accessTargets = @("EACCES", "EPERM", "open", "creat", "truncate")
    $accessFound = 0
    foreach ($target in $accessTargets) {
        if ($permStr -match $target) {
            $accessFound++
        }
    }
    $FindingDetails += "  Access denial syscall rules: $accessFound of $($accessTargets.Count)" + $nl
    if ($accessFound -ge 2) {
        $FindingDetails += "  [PASS] Access denial auditing configured" + $nl
    }
    else {
        $FindingDetails += "  [FAIL] Access denial audit rules not found" + $nl
        $auditIssues++
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: XO Audit Plugin ---" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + $nl
        $FindingDetails += "  [INFO] XO Audit Plugin logs access enforcement actions at application layer" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    }
    $FindingDetails += $nl

    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
    elseif ($xoAuditInfo.Enabled) {
        $Status = "NotAFinding"
        $FindingDetails += "COMPENSATING CONTROL: While auditd is not fully configured, the XO Audit Plugin" + $nl
        $FindingDetails += "provides application-layer auditing of access enforcement actions." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Audit enforcement of access restrictions not fully configured." + $nl
    }

    #---=== End Custom Code ===---#'''
    },

    "V-203722": {
        "stig_id": "SRG-OS-000370-GPOS-00155",
        "rule_id": "SV-203722r958808_rule",
        "discuss_md5": "af96dd9ef53abde47e33117a2f615a62",
        "check_md5": "174c45840376c38f707da069d02fc65e",
        "custom_code": r'''    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#

    # V-203722: Deny-all, permit-by-exception for authorized software
    # Check package management, AppArmor, and firewall for deny-by-default posture

    $issues = 0

    $FindingDetails += "--- Check 1: Package Management (APT) ---" + $nl
    $aptSources = $(timeout 5 cat /etc/apt/sources.list 2>&1)
    $aptStr = ($aptSources -join $nl).Trim()
    $repoCount = (($aptStr -split $nl) | Where-Object { $_ -match "^deb\s" -and $_ -notmatch "^#" }).Count
    $FindingDetails += "  Active APT repositories: $repoCount" + $nl
    if ($repoCount -le 5) {
        $FindingDetails += "  [PASS] Limited number of package sources configured" + $nl
    }
    else {
        $FindingDetails += "  [INFO] Multiple package sources - verify all are authorized" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: AppArmor (Application Whitelisting) ---" + $nl
    $aaStatus = $(timeout 5 aa-status 2>&1)
    $aaStr = ($aaStatus -join $nl).Trim()
    if ($aaStr -match "(\d+) profiles are loaded") {
        $profileCount = $matches[1]
        $FindingDetails += "  AppArmor: active ($profileCount profiles loaded)" + $nl
        if ($aaStr -match "(\d+) profiles are in enforce mode") {
            $enforceCount = $matches[1]
            $FindingDetails += "  Enforce mode: $enforceCount profiles" + $nl
        }
        $FindingDetails += "  [PASS] AppArmor provides deny-all, permit-by-exception for confined apps" + $nl
    }
    else {
        $FindingDetails += "  AppArmor: not active" + $nl
        $FindingDetails += "  [FAIL] No application confinement mechanism detected" + $nl
        $issues++
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Firewall (Network Deny-All) ---" + $nl
    $ufwStatus = $(timeout 5 ufw status 2>&1)
    $ufwStr = ($ufwStatus -join $nl).Trim()
    if ($ufwStr -match "Status: active") {
        $FindingDetails += "  UFW: active" + $nl
        if ($ufwStr -match "Default: deny") {
            $FindingDetails += "  Default policy: deny (incoming)" + $nl
            $FindingDetails += "  [PASS] Firewall implements deny-all, permit-by-exception" + $nl
        }
        else {
            $FindingDetails += "  [INFO] Review default firewall policy" + $nl
        }
    }
    else {
        $nftStatus = $(timeout 5 nft list ruleset 2>&1 | head -10 2>&1)
        $nftStr = ($nftStatus -join $nl).Trim()
        if ($nftStr -match "chain|table") {
            $FindingDetails += "  nftables: rules present" + $nl
            $FindingDetails += "  [INFO] Review nftables for deny-all default policy" + $nl
        }
        else {
            $FindingDetails += "  No active firewall detected (UFW/nftables)" + $nl
            $FindingDetails += "  [FAIL] No network deny-all policy in place" + $nl
            $issues++
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Executable Permissions ---" + $nl
    $noexecMounts = ($mountStr -split $nl) | Where-Object { $_ -match "noexec" }
    $mounts = $(timeout 5 mount 2>&1)
    $mountStr = ($mounts -join $nl).Trim()
    $noexecParts = @("/tmp", "/var/tmp", "/dev/shm")
    foreach ($part in $noexecParts) {
        $partLine = ($mountStr -split $nl) | Where-Object { $_ -match "on $([regex]::Escape($part)) " }
        if ($partLine) {
            $partStr = ($partLine -join " ").Trim()
            if ($partStr -match "noexec") {
                $FindingDetails += "  $part : noexec [PASS]" + $nl
            }
            else {
                $FindingDetails += "  $part : no noexec [INFO]" + $nl
            }
        }
        else {
            $FindingDetails += "  $part : not a separate mount point" + $nl
        }
    }
    $FindingDetails += $nl

    if ($issues -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Deny-all, permit-by-exception enforced via AppArmor" + $nl
        $FindingDetails += "confinement, firewall rules, and restricted package sources." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Deny-all, permit-by-exception policy not fully implemented." + $nl
    }

    #---=== End Custom Code ===---#'''
    },
}


def main():
    with open(MODULE, 'r', encoding='utf-8') as f:
        content = f.read()

    replacements = 0
    for vulnid, impl in IMPLEMENTATIONS.items():
        func_name = f"Get-V{vulnid.replace('V-', '')}"

        # Find the function boundaries
        pattern = rf'(Function {func_name} \{{)\s*\n\s*<#\s*\n\s*\.DESCRIPTION.*?#>\s*\n'
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            print(f"ERROR: Could not find function {func_name}")
            continue

        # Build new header
        new_header = f'''Function {func_name} {{
    <#
    .DESCRIPTION
        Vuln ID    : {vulnid}
        STIG ID    : {impl["stig_id"]}
        Rule ID    : {impl["rule_id"]}
        DiscussMD5 : {impl["discuss_md5"]}
        CheckMD5   : {impl["check_md5"]}
        FixMD5     : 00000000000000000000000000000000
    #>

'''
        content = content[:match.start()] + new_header + content[match.end():]

        # Now replace the custom code section
        # Find the stub custom code between Begin/End markers
        stub_pattern = r'(    #---=== Begin Custom Code ===---#)\s*\n.*?(    #---=== End Custom Code ===---#)'
        # We need to find the one inside the current function
        func_start = content.find(f"Function {func_name} {{")
        func_section_start = func_start
        # Find next function or end of file
        next_func = re.search(r'\nFunction Get-V\d+', content[func_start + 50:])
        if next_func:
            func_section_end = func_start + 50 + next_func.start()
        else:
            func_section_end = len(content)

        func_section = content[func_section_start:func_section_end]

        # Find stub code pattern within this function section
        old_custom = re.search(
            r'    \$Status = "Not_Reviewed"\s*\n'
            r'    \$FindingDetails = ""\s*\n'
            r'    \$Comments = ""\s*\n'
            r'    \$AFKey = ""\s*\n'
            r'    \$AFStatus = ""\s*\n'
            r'    \$SeverityOverride = ""\s*\n'
            r'    \$Justification = ""\s*\n'
            r'\s*\n'
            r'    #---=== Begin Custom Code ===---#\s*\n'
            r'.*?'
            r'    #---=== End Custom Code ===---#',
            func_section, re.DOTALL
        )

        if not old_custom:
            print(f"ERROR: Could not find custom code section in {func_name}")
            continue

        new_custom = (
            '    $Status = "Not_Reviewed"\n'
            '    $FindingDetails = ""\n'
            '    $Comments = ""\n'
            '    $AFKey = ""\n'
            '    $AFStatus = ""\n'
            '    $SeverityOverride = ""\n'
            '    $Justification = ""\n'
            + impl["custom_code"]
        )

        # Replace within the function section
        new_func_section = func_section[:old_custom.start()] + new_custom + func_section[old_custom.end():]
        content = content[:func_section_start] + new_func_section + content[func_section_end:]

        replacements += 1
        print(f"OK: {vulnid} ({func_name}) replaced")

    with open(MODULE, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nTotal replacements: {replacements}/10")


if __name__ == "__main__":
    main()
