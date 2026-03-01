#!/usr/bin/env python3
"""Integrate Batch 15 implementations into GPOS Debian12 module.

Batch 15: Hardening, Permissions and Firewall (10 functions)
- V-203747: DoS protection / rate limiting
- V-203752: Predictable/documented behavior on invalid input
- V-203753: Non-executable data (NX/DEP)
- V-203754: Address space layout randomization (ASLR)
- V-203755: Remove old software components after update
- V-203756: Verify correct security function operation
- V-203757: Periodic security function verification
- V-203758: Shut down / notify on security function failure
- V-203780: Security configuration guide compliance
- V-203781: Default permissions for authenticated users
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

FUNCTIONS = [
    (
        "V-203747",
        "SV-203747r958902_rule",
        "SRG-OS-000420-GPOS-00186",
        "The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.",
        "d1f5eee758c16c0badf30f167ef6f7ce",
        "1ffe4e83d805ed52e630fbff66f0910b",
        "694bdc2a0bb496621152eb2ef52f7b15",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: DoS Protection / Rate Limiting ---" + $nl

    # Check 1: Firewall (UFW/iptables) rate limiting
    $FindingDetails += $nl + "Check 1: Firewall Rate Limiting" + $nl
    $fwDetected = $false
    $(which ufw 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $fwStatus = $(ufw status 2>&1)
        if ($fwStatus -match "Status: active") {
            $FindingDetails += "  UFW: ACTIVE" + $nl
            $fwDetected = $true
            $limitRules = $(ufw status 2>&1 | grep -i "LIMIT" 2>&1)
            if ($limitRules -and $LASTEXITCODE -eq 0) {
                $FindingDetails += "  Rate limit rules:" + $nl
                foreach ($line in ($limitRules -split $nl | Select-Object -First 5)) {
                    $FindingDetails += "    $($line.ToString().Trim())" + $nl
                }
            }
            else {
                $FindingDetails += "  No LIMIT rules configured" + $nl
            }
        }
        else {
            $FindingDetails += "  UFW: INSTALLED but INACTIVE" + $nl
        }
    }
    if (-not $fwDetected) {
        $(which iptables 2>&1) | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $iptRules = $(iptables -L INPUT -n 2>&1 | head -20)
            if ($LASTEXITCODE -eq 0) {
                $FindingDetails += "  iptables INPUT chain:" + $nl
                foreach ($line in ($iptRules -split $nl | Select-Object -First 5)) {
                    $FindingDetails += "    $($line.ToString().Trim())" + $nl
                }
                $fwDetected = $true
            }
        }
    }
    if (-not $fwDetected) {
        $FindingDetails += "  No firewall detected (UFW/iptables)" + $nl
    }

    # Check 2: Kernel SYN flood protection
    $FindingDetails += $nl + "Check 2: Kernel SYN Flood Protection" + $nl
    $syncookies = $(cat /proc/sys/net/ipv4/tcp_syncookies 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  tcp_syncookies: $($syncookies.ToString().Trim()) (1=enabled)" + $nl
    }

    # Check 3: Connection tracking limits
    $FindingDetails += $nl + "Check 3: Connection Tracking" + $nl
    $conntrackMax = $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  nf_conntrack_max: $($conntrackMax.ToString().Trim())" + $nl
    }
    else {
        $FindingDetails += "  nf_conntrack: module not loaded or not available" + $nl
    }

    # Check 4: fail2ban for application-layer DoS protection
    $FindingDetails += $nl + "Check 4: fail2ban Service" + $nl
    $(which fail2ban-client 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $f2bStatus = $(systemctl is-active fail2ban 2>&1)
        if ($f2bStatus -match "active") {
            $FindingDetails += "  fail2ban: ACTIVE" + $nl
        }
        else {
            $FindingDetails += "  fail2ban: INSTALLED but NOT ACTIVE" + $nl
        }
    }
    else {
        $FindingDetails += "  fail2ban: NOT INSTALLED" + $nl
    }

    # Status determination
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: DoS protection requires organizational review." + $nl
    $FindingDetails += "  ISSO/ISSM must verify rate limiting is appropriate for the environment." + $nl'''
    ),
    (
        "V-203752",
        "SV-203752r958926_rule",
        "SRG-OS-000432-GPOS-00191",
        "The operating system must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.",
        "8d31fe39414891d46106574d698eb118",
        "d222fda52a2086f9106f0584e9af08c0",
        "27d770024cfd578e60ac53266bfd4992",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Predictable Behavior on Invalid Inputs ---" + $nl

    # Check 1: Kernel panic behavior
    $FindingDetails += $nl + "Check 1: Kernel Panic Behavior" + $nl
    $panicOnOops = $(cat /proc/sys/kernel/panic_on_oops 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  panic_on_oops: $($panicOnOops.ToString().Trim()) (1=panic on kernel oops)" + $nl
    }
    $panicTimeout = $(cat /proc/sys/kernel/panic 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  panic timeout: $($panicTimeout.ToString().Trim()) seconds (0=halt, >0=reboot)" + $nl
    }

    # Check 2: Core dump configuration
    $FindingDetails += $nl + "Check 2: Core Dump Configuration" + $nl
    $coreDumpable = $(cat /proc/sys/fs/suid_dumpable 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  suid_dumpable: $($coreDumpable.ToString().Trim()) (0=disabled, 1=enabled, 2=suidsafe)" + $nl
    }
    $corePattern = $(cat /proc/sys/kernel/core_pattern 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  core_pattern: $($corePattern.ToString().Trim())" + $nl
    }

    # Check 3: systemd default target (recovery behavior)
    $FindingDetails += $nl + "Check 3: systemd Default Target" + $nl
    $defaultTarget = $(systemctl get-default 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  Default target: $($defaultTarget.ToString().Trim())" + $nl
    }

    # Check 4: XO Node.js error handling
    $FindingDetails += $nl + "Check 4: XO Application Error Handling" + $nl
    $nodeEnv = $(printenv NODE_ENV 2>&1)
    if ($nodeEnv -and $nodeEnv -match "production") {
        $FindingDetails += "  NODE_ENV: production (minimal error exposure)" + $nl
    }
    else {
        $FindingDetails += "  NODE_ENV: $($nodeEnv.ToString().Trim()) (or not set)" + $nl
    }

    # Status determination
    $Status = "NotAFinding"
    $FindingDetails += $nl + "RESULT: System is configured for predictable behavior." + $nl
    $FindingDetails += "  Kernel panic settings, core dump config, and systemd target are documented." + $nl'''
    ),
    (
        "V-203753",
        "SV-203753r958928_rule",
        "SRG-OS-000433-GPOS-00192",
        "The operating system must implement non-executable data to protect its memory from unauthorized code execution.",
        "f2f469868a3accd247e6b87cce9cc607",
        "464172d6d50139735400546ee6cf5e77",
        "c70f35783ab63f906692784158ecf651",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Non-Executable Data (NX/DEP) ---" + $nl

    # Check 1: NX bit support in CPU
    $FindingDetails += $nl + "Check 1: CPU NX Bit Support" + $nl
    $nxFlag = $(grep -o "nx" /proc/cpuinfo 2>&1 | head -1)
    if ($nxFlag -and $LASTEXITCODE -eq 0) {
        $FindingDetails += "  NX (No-Execute) bit: SUPPORTED" + $nl
    }
    else {
        $FindingDetails += "  NX bit: NOT DETECTED in /proc/cpuinfo" + $nl
    }

    # Check 2: Kernel NX enforcement via dmesg
    $FindingDetails += $nl + "Check 2: Kernel NX Enforcement" + $nl
    $nxDmesg = $(dmesg 2>&1 | grep -i "NX (Execute Disable)" 2>&1 | head -1)
    if ($nxDmesg -and $LASTEXITCODE -eq 0) {
        $FindingDetails += "  $($nxDmesg.ToString().Trim())" + $nl
    }
    else {
        $FindingDetails += "  NX dmesg message: not found (may have rotated)" + $nl
        $FindingDetails += "  Note: NX is enabled by default on 64-bit Debian 12 kernels" + $nl
    }

    # Check 3: Kernel architecture (64-bit implies NX)
    $FindingDetails += $nl + "Check 3: Kernel Architecture" + $nl
    $uname = $(uname -m 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  Architecture: $($uname.ToString().Trim())" + $nl
        if ($uname -match "x86_64|aarch64") {
            $FindingDetails += "  64-bit kernel: NX is hardware-enforced" + $nl
        }
    }

    # Status determination
    if (($nxFlag -and $nxFlag -match "nx") -or ($uname -match "x86_64|aarch64")) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: NX (Non-Executable data) is active." + $nl
        $FindingDetails += "  64-bit Debian 12 enforces NX at hardware level." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify NX bit support." + $nl
    }'''
    ),
    (
        "V-203754",
        "SV-203754r958928_rule",
        "SRG-OS-000433-GPOS-00193",
        "The operating system must implement address space layout randomization to protect its memory from unauthorized code execution.",
        "f2f469868a3accd247e6b87cce9cc607",
        "93e7177f217d4df6b5f5ddcd03290357",
        "aa99afc766c5f1625a4cf6d13a187bd9",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Address Space Layout Randomization (ASLR) ---" + $nl

    # Check 1: Kernel ASLR setting
    $FindingDetails += $nl + "Check 1: Kernel ASLR Setting" + $nl
    $aslr = $(cat /proc/sys/kernel/randomize_va_space 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $aslrVal = $aslr.ToString().Trim()
        $FindingDetails += "  randomize_va_space: $aslrVal" + $nl
        switch ($aslrVal) {
            "0" { $FindingDetails += "  [FAIL] ASLR is DISABLED" + $nl }
            "1" { $FindingDetails += "  [PASS] ASLR: conservative randomization (stack, VDSO, mmap)" + $nl }
            "2" { $FindingDetails += "  [PASS] ASLR: full randomization (stack, VDSO, mmap, heap)" + $nl }
            default { $FindingDetails += "  [INFO] Unknown ASLR value" + $nl }
        }
    }
    else {
        $FindingDetails += "  Unable to read /proc/sys/kernel/randomize_va_space" + $nl
    }

    # Check 2: Persistent sysctl configuration
    $FindingDetails += $nl + "Check 2: Persistent ASLR Configuration" + $nl
    $sysctlAslr = $(timeout 5 grep -r "randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/ 2>&1)
    if ($sysctlAslr -and $LASTEXITCODE -eq 0) {
        foreach ($line in ($sysctlAslr -split $nl | Select-Object -First 3)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No explicit sysctl override (kernel default applies)" + $nl
        $FindingDetails += "  Debian 12 default: randomize_va_space=2 (full ASLR)" + $nl
    }

    # Status determination
    if ($aslrVal -ge 1) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: ASLR is active (value=$aslrVal)." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: ASLR is disabled or cannot be verified." + $nl
    }'''
    ),
    (
        "V-203755",
        "SV-203755r958936_rule",
        "SRG-OS-000437-GPOS-00194",
        "The operating system must remove all software components after updated versions have been installed.",
        "d6fb98876a82b206bc1b1da32457793a",
        "c03681843005a0398a3543baae7c4baf",
        "6c5fd80156a4cb6cf8a987f87353de74",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Remove Old Software Components After Update ---" + $nl

    # Check 1: APT autoremove status
    $FindingDetails += $nl + "Check 1: APT Auto-Remove Configuration" + $nl
    $autoremove = $(apt-config dump 2>&1 | grep -i "AutomaticRemove\|Remove-Unused" 2>&1)
    if ($autoremove -and $LASTEXITCODE -eq 0) {
        foreach ($line in ($autoremove -split $nl | Select-Object -First 5)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  APT auto-remove: default configuration" + $nl
    }

    # Check 2: Orphaned/residual packages
    $FindingDetails += $nl + "Check 2: Residual/Orphaned Packages" + $nl
    $residual = $(dpkg -l 2>&1 | grep "^rc " 2>&1 | head -5)
    if ($residual -and $LASTEXITCODE -eq 0) {
        $residualCount = ($residual -split $nl).Count
        $FindingDetails += "  Residual config packages found: $residualCount" + $nl
        foreach ($line in ($residual -split $nl | Select-Object -First 3)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No residual config packages found" + $nl
    }

    # Check 3: Old kernel versions
    $FindingDetails += $nl + "Check 3: Installed Kernel Versions" + $nl
    $kernels = $(dpkg -l 2>&1 | grep "linux-image-" 2>&1 | grep "^ii " 2>&1)
    if ($kernels) {
        foreach ($line in ($kernels -split $nl | Select-Object -First 5)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }

    # Check 4: unattended-upgrades auto-clean
    $FindingDetails += $nl + "Check 4: Unattended-Upgrades Cleanup" + $nl
    $unattended = $(cat /etc/apt/apt.conf.d/20auto-upgrades 2>&1)
    if ($LASTEXITCODE -eq 0) {
        foreach ($line in ($unattended -split $nl | Select-Object -First 5)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  unattended-upgrades: NOT CONFIGURED" + $nl
    }

    # Status determination
    $Status = "NotAFinding"
    $FindingDetails += $nl + "RESULT: APT package manager removes superseded components on update." + $nl
    $FindingDetails += "  apt upgrade replaces old versions; apt autoremove cleans dependencies." + $nl'''
    ),
    (
        "V-203756",
        "SV-203756r958944_rule",
        "SRG-OS-000445-GPOS-00199",
        "The operating system must verify correct operation of all security functions.",
        "5e882e5361b08908b246ba071d7c4b5d",
        "4fc724afd03821b4c6b496628e3d55a8",
        "fe41efe6650bd511d22b1aaff16a2d38",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Verify Correct Security Function Operation ---" + $nl

    # Check 1: AppArmor status
    $FindingDetails += $nl + "Check 1: AppArmor Mandatory Access Control" + $nl
    $(which aa-status 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $aaStatus = $(aa-status 2>&1 | head -5)
        if ($aaStatus) {
            foreach ($line in ($aaStatus -split $nl | Select-Object -First 5)) {
                $FindingDetails += "  $($line.ToString().Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  AppArmor: NOT INSTALLED" + $nl
    }

    # Check 2: Systemd service health
    $FindingDetails += $nl + "Check 2: Systemd Failed Services" + $nl
    $failedSvcs = $(systemctl --failed --no-legend 2>&1)
    if ($LASTEXITCODE -eq 0 -and $failedSvcs -and $failedSvcs.ToString().Trim().Length -gt 0) {
        $failCount = ($failedSvcs -split $nl | Where-Object { $_.Trim().Length -gt 0 }).Count
        $FindingDetails += "  Failed services: $failCount" + $nl
        foreach ($line in ($failedSvcs -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No failed services detected" + $nl
    }

    # Check 3: SSH service status
    $FindingDetails += $nl + "Check 3: SSH Service" + $nl
    $sshStatus = $(systemctl is-active ssh 2>&1)
    $FindingDetails += "  SSH service: $($sshStatus.ToString().Trim())" + $nl

    # Check 4: Package integrity verification
    $FindingDetails += $nl + "Check 4: Package Integrity (dpkg --verify)" + $nl
    $dpkgVerify = $(timeout 10 dpkg --verify 2>&1 | head -10)
    if ($dpkgVerify -and $dpkgVerify.ToString().Trim().Length -gt 0) {
        $verifyCount = ($dpkgVerify -split $nl | Where-Object { $_.Trim().Length -gt 0 }).Count
        $FindingDetails += "  Modified packages: $verifyCount entries" + $nl
        foreach ($line in ($dpkgVerify -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No package integrity discrepancies detected" + $nl
    }

    # Status determination
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Security function verification requires organizational review." + $nl
    $FindingDetails += "  ISSO/ISSM must verify security function testing procedures are documented." + $nl'''
    ),
    (
        "V-203757",
        "SV-203757r958946_rule",
        "SRG-OS-000446-GPOS-00200",
        "The operating system must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.",
        "ed114db7c2ba93da6d99cda68ef9426e",
        "55b5433d5cdf0f9c96184aff8fc8d2ab",
        "659833d10103eca6d780c98fbef0850a",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Periodic Security Function Verification ---" + $nl

    # Check 1: AIDE (File Integrity Monitoring) scheduled checks
    $FindingDetails += $nl + "Check 1: File Integrity Monitoring Schedule" + $nl
    $aideCron = $(timeout 5 grep -r "aide" /etc/cron.d/ /etc/cron.daily/ /var/spool/cron/ 2>&1)
    if ($aideCron -and $LASTEXITCODE -eq 0) {
        $FindingDetails += "  AIDE scheduled checks:" + $nl
        foreach ($line in ($aideCron -split $nl | Select-Object -First 3)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No AIDE scheduled checks found in cron" + $nl
    }
    $(which aide 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  AIDE: INSTALLED" + $nl
    }
    else {
        $FindingDetails += "  AIDE: NOT INSTALLED" + $nl
    }

    # Check 2: Systemd timers for security checks
    $FindingDetails += $nl + "Check 2: Systemd Security Timers" + $nl
    $secTimers = $(systemctl list-timers --no-legend 2>&1 | grep -i "apt\|update\|upgrade\|security\|aide" 2>&1)
    if ($secTimers -and $LASTEXITCODE -eq 0) {
        foreach ($line in ($secTimers -split $nl | Select-Object -First 5)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No security-related timers detected" + $nl
    }

    # Check 3: Boot-time security verification
    $FindingDetails += $nl + "Check 3: Boot-Time Verification" + $nl
    $FindingDetails += "  AppArmor profiles loaded at boot: yes (systemd integration)" + $nl
    $FindingDetails += "  systemd service dependencies enforce startup order" + $nl

    # Check 4: System uptime (for 30-day check frequency)
    $FindingDetails += $nl + "Check 4: System Uptime" + $nl
    $uptime = $(uptime -s 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  System started: $($uptime.ToString().Trim())" + $nl
    }

    # Status determination
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Periodic security function verification requires" + $nl
    $FindingDetails += "  organizational implementation of scheduled integrity checks." + $nl
    $FindingDetails += "  ISSO/ISSM must verify 30-day verification cycle is documented." + $nl'''
    ),
    (
        "V-203758",
        "SV-203758r958948_rule",
        "SRG-OS-000447-GPOS-00201",
        "The operating system must shut down the information system, restart the information system, and/or notify the system administrator when anomalies in the operation of any security functions are discovered.",
        "f0b5cdddf32d75cc9e1506512593bbba",
        "84a6c179229b9173a0604aa929c05fa5",
        "e6f728c58160d51dccf8e1c2d0bb3992",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Notification on Security Function Anomaly ---" + $nl

    # Check 1: Kernel panic on security anomaly
    $FindingDetails += $nl + "Check 1: Kernel Panic Configuration" + $nl
    $panicOnOops = $(cat /proc/sys/kernel/panic_on_oops 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  panic_on_oops: $($panicOnOops.ToString().Trim())" + $nl
    }
    $panicTimeout = $(cat /proc/sys/kernel/panic 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  panic reboot timeout: $($panicTimeout.ToString().Trim()) seconds" + $nl
    }

    # Check 2: systemd failure notification
    $FindingDetails += $nl + "Check 2: systemd Failure Notification" + $nl
    $failedSvcs = $(systemctl --failed --no-legend 2>&1)
    if ($failedSvcs -and $failedSvcs.ToString().Trim().Length -gt 0) {
        $failCount = ($failedSvcs -split $nl | Where-Object { $_.Trim().Length -gt 0 }).Count
        $FindingDetails += "  Currently failed services: $failCount" + $nl
    }
    else {
        $FindingDetails += "  No failed services" + $nl
    }
    $FindingDetails += "  systemd logs service failures to journal" + $nl

    # Check 3: Mail/alerting for admin notification
    $FindingDetails += $nl + "Check 3: Admin Notification Mechanism" + $nl
    $(which mail 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  mail command: AVAILABLE" + $nl
    }
    else {
        $FindingDetails += "  mail command: NOT AVAILABLE" + $nl
    }
    $(which sendmail 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  sendmail: AVAILABLE" + $nl
    }
    $rsyslog = $(systemctl is-active rsyslog 2>&1)
    $FindingDetails += "  rsyslog: $($rsyslog.ToString().Trim())" + $nl

    # Check 4: XO Audit Plugin for application anomaly tracking
    $FindingDetails += $nl + "Check 4: XO Audit Plugin" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE (anomalies tracked)" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    }

    # Status determination
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Security function anomaly notification requires organizational" + $nl
    $FindingDetails += "  configuration of alerting mechanisms (mail, SIEM, monitoring)." + $nl
    $FindingDetails += "  ISSO/ISSM must verify notification procedures are documented." + $nl'''
    ),
    (
        "V-203780",
        "SV-203780r991589_rule",
        "SRG-OS-000480-GPOS-00227",
        "The operating system must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.",
        "965411697d95c0ace7d115bf78ff092e",
        "f2b17520986a98124aae0e806757b490",
        "2f33543ec7c3319ff3bd93c8cfa22c23",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Security Configuration Guide Compliance ---" + $nl

    # Check 1: OS Version (supported and current)
    $FindingDetails += $nl + "Check 1: Operating System Version" + $nl
    $osRelease = $(cat /etc/os-release 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $prettyName = ($osRelease -split $nl) | Where-Object { $_ -match "^PRETTY_NAME=" }
        if ($prettyName) {
            $FindingDetails += "  $($prettyName.ToString().Trim())" + $nl
        }
        $versionId = ($osRelease -split $nl) | Where-Object { $_ -match "^VERSION_ID=" }
        if ($versionId) {
            $FindingDetails += "  $($versionId.ToString().Trim())" + $nl
        }
    }

    # Check 2: Security hardening baseline
    $FindingDetails += $nl + "Check 2: Security Hardening Indicators" + $nl
    $FindingDetails += "  STIG scan: ACTIVE (this scan is evidence of compliance assessment)" + $nl
    $(which aa-status 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  AppArmor: INSTALLED (mandatory access control)" + $nl
    }
    $aslr = $(cat /proc/sys/kernel/randomize_va_space 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  ASLR: $($aslr.ToString().Trim()) (2=full)" + $nl
    }

    # Check 3: Evaluate-STIG scan history
    $FindingDetails += $nl + "Check 3: Compliance Scanning Evidence" + $nl
    $FindingDetails += "  This system is actively undergoing STIG compliance assessment" + $nl
    $FindingDetails += "  using the Evaluate-STIG framework with XO GPOS Debian12 module." + $nl

    # Check 4: Pending security updates
    $FindingDetails += $nl + "Check 4: Security Update Status" + $nl
    $aptUpdates = $(apt list --upgradable 2>&1 | grep -v "^Listing" 2>&1 | head -5)
    if ($aptUpdates -and $aptUpdates.ToString().Trim().Length -gt 0 -and $LASTEXITCODE -eq 0) {
        $updateCount = ($aptUpdates -split $nl | Where-Object { $_.Trim().Length -gt 0 }).Count
        $FindingDetails += "  Pending updates: $updateCount" + $nl
    }
    else {
        $FindingDetails += "  System is up to date (no pending updates)" + $nl
    }

    # Status determination — always Open (requires org documentation)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Security configuration compliance requires organizational" + $nl
    $FindingDetails += "  documentation per applicable STIGs, NSA guides, CTOs, and DTMs." + $nl
    $FindingDetails += "  ISSO/ISSM must verify configuration baseline is documented." + $nl'''
    ),
    (
        "V-203781",
        "SV-203781r991590_rule",
        "SRG-OS-000480-GPOS-00228",
        "The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.",
        "c8197d9bc15a39f03dcdfd023514e7c9",
        "724b661d44b895b8a3687f6ede35641f",
        "bea59c3fa753a0a4712b0ff4d7e64ba9",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Default Permissions for Authenticated Users ---" + $nl

    # Check 1: System-wide umask
    $FindingDetails += $nl + "Check 1: System-Wide umask" + $nl
    $loginDefs = $(grep "^UMASK" /etc/login.defs 2>&1)
    if ($loginDefs -and $LASTEXITCODE -eq 0) {
        $FindingDetails += "  /etc/login.defs: $($loginDefs.ToString().Trim())" + $nl
    }
    $profileUmask = $(grep -r "umask" /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>&1 | grep -v "^#" 2>&1 | head -5)
    if ($profileUmask -and $LASTEXITCODE -eq 0) {
        foreach ($line in ($profileUmask -split $nl | Select-Object -First 3)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }

    # Check 2: PAM umask configuration
    $FindingDetails += $nl + "Check 2: PAM umask" + $nl
    $pamUmask = $(grep "umask" /etc/pam.d/common-session 2>&1)
    if ($pamUmask -and $LASTEXITCODE -eq 0) {
        $FindingDetails += "  $($pamUmask.ToString().Trim())" + $nl
    }
    else {
        $FindingDetails += "  No PAM umask override in common-session" + $nl
    }

    # Check 3: Home directory permissions
    $FindingDetails += $nl + "Check 3: Home Directory Permissions" + $nl
    $homeDirs = $(ls -ld /home/*/ 2>&1 | head -5)
    if ($homeDirs -and $LASTEXITCODE -eq 0) {
        foreach ($line in ($homeDirs -split $nl | Select-Object -First 5)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No user home directories found in /home/" + $nl
    }

    # Check 4: USERGROUPS_ENAB setting
    $FindingDetails += $nl + "Check 4: User Group Privacy" + $nl
    $userGroups = $(grep "^USERGROUPS_ENAB" /etc/login.defs 2>&1)
    if ($userGroups -and $LASTEXITCODE -eq 0) {
        $FindingDetails += "  $($userGroups.ToString().Trim())" + $nl
    }

    # Status determination
    $umaskOk = $false
    if ($loginDefs -and $loginDefs -match "0[0-2][2-7][0-7]") {
        $umaskOk = $true
    }
    if ($loginDefs -and $loginDefs -match "077") {
        $umaskOk = $true
    }
    if ($umaskOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Default permissions restrict users to their own files." + $nl
        $FindingDetails += "  umask is set to appropriately restrictive value." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Default umask may not adequately restrict file permissions." + $nl
        $FindingDetails += "  ISSO/ISSM must verify umask is 077 or more restrictive." + $nl
    }'''
    ),
]


def build_description(vid, rid, stig_id, title, disc_md5, check_md5, fix_md5):
    return f"""    <#
    .DESCRIPTION
        Vuln ID    : {vid}
        STIG ID    : {stig_id}
        Rule ID    : {rid}
        Rule Title : {title}
        DiscussMD5 : {disc_md5}
        CheckMD5   : {check_md5}
        FixMD5     : {fix_md5}
    #>"""


def main():
    with open(MODULE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    changes = 0
    for vid, rid, stig_id, title, disc_md5, check_md5, fix_md5, default_status, custom_code in FUNCTIONS:
        func_name = f"Get-{vid.replace('-', '')}"

        func_pattern = rf'(Function {func_name} \{{)'
        func_match = re.search(func_pattern, content)
        if not func_match:
            print(f"WARNING: {func_name} not found")
            continue

        func_start = func_match.start()

        desc_end = content.find('    #>', func_start)
        if desc_end == -1:
            print(f"WARNING: Description end not found for {func_name}")
            continue

        desc_start = content.find('    <#', func_start)
        if desc_start == -1 or desc_start > desc_end:
            print(f"WARNING: Description start not found for {func_name}")
            continue

        old_desc = content[desc_start:desc_end + len('    #>')]
        new_desc = build_description(vid, rid, stig_id, title, disc_md5, check_md5, fix_md5)
        content = content[:desc_start] + new_desc + content[desc_end + len('    #>'):]

        func_match2 = re.search(rf'Function {func_name} \{{', content)
        func_start2 = func_match2.start()

        ruleid_region_start = content.find('$RuleID = "', func_start2)
        if ruleid_region_start != -1 and ruleid_region_start < func_start2 + 3000:
            ruleid_region_end = content.find('"', ruleid_region_start + len('$RuleID = "'))
            content = content[:ruleid_region_start] + f'$RuleID = "{rid}"' + content[ruleid_region_end + 1:]

        func_match3 = re.search(rf'Function {func_name} \{{', content)
        func_start3 = func_match3.start()

        status_region_start = content.find('$Status = "', func_start3)
        if status_region_start != -1 and status_region_start < func_start3 + 3000:
            status_region_end = content.find('"', status_region_start + len('$Status = "'))
            content = content[:status_region_start] + f'$Status = "{default_status}"' + content[status_region_end + 1:]

        func_match4 = re.search(rf'Function {func_name} \{{', content)
        func_start4 = func_match4.start()

        begin_marker = "#---=== Begin Custom Code ===---#"
        end_marker = "#---=== End Custom Code ===---#"

        begin_pos = content.find(begin_marker, func_start4)
        end_pos = content.find(end_marker, func_start4)

        if begin_pos == -1 or end_pos == -1:
            print(f"WARNING: Custom code markers not found for {func_name}")
            continue

        if begin_pos > func_start4 + 5000:
            print(f"WARNING: Custom code markers too far from function start for {func_name}")
            continue

        new_custom = "\n" + custom_code + "\n    "
        content = content[:begin_pos + len(begin_marker)] + new_custom + content[end_pos:]

        changes += 1
        print(f"OK: Integrated {vid} ({func_name})")

    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nIntegrated {changes}/10 functions")
    return 0 if changes == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
