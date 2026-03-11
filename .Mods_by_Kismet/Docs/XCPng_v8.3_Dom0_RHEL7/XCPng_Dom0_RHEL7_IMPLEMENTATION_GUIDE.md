# XCP-ng Dom0 RHEL7 Implementation Guide

**Module:** Scan-XCP-ng_Dom0_RHEL7_Checks
**STIG:** Red Hat Enterprise Linux 7 STIG V3R15 (adapted for XCP-ng Dom0)
**Target:** XCP-ng 8.3 Dom0 (CentOS 7-based)
**Created:** March 11, 2026

---

## Quick Reference: 8 Critical Coding Rules

| # | Rule | WRONG | RIGHT |
|---|------|-------|-------|
| 1 | No backtick-n | `` `n `` | `$nl = [Environment]::NewLine` |
| 2 | No escaped quotes | `\"value\"` | `[char]34 + "value" + [char]34` |
| 3 | Function naming | `Get-V-204392` | `Get-V204392` |
| 4 | No bash -c wrapper | `bash -c "cmd"` | `$(cmd 2>&1)` |
| 5 | Array-to-string before regex | `$arr -match "pat"` | `($arr -join $nl) -match "pat"` |
| 6 | timeout + maxdepth on find/grep | `find /etc -name "*.conf"` | `timeout 10 find /etc -maxdepth 3 -name "*.conf"` |
| 7 | VulnTimeout 15 for scans | Default timeout | `-VulnTimeout 15` |
| 8 | 9-param block (mandatory) | Missing $Username/$UserSID/$Hostname | All 9 params from function-template.md |

---

## Dom0 RHEL7-Specific Architecture

### Target System

- **OS:** CentOS 7 (el7 packages), XCP-ng 8.3 Dom0
- **PowerShell:** 7.3.12 (glibc constraint — no 7.4+)
- **Connectivity:** SSH-based PSRemoting from Windows workstation
- **Key service:** xapi (XCP-ng management daemon)

### Critical Configuration Paths

| Category | Path(s) |
|----------|---------|
| PAM | `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`, `/etc/pam.d/postlogin` |
| SSH | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` |
| Password | `/etc/security/pwquality.conf`, `/etc/login.defs`, `/etc/default/useradd` |
| Audit | `/etc/audit/auditd.conf`, `/etc/audit/rules.d/`, `/etc/audit/audit.rules` |
| Accounts | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` |
| Sysctl | `/etc/sysctl.conf`, `/etc/sysctl.d/` |
| Banner | `/etc/issue`, `/etc/motd` |
| Crypto | `/etc/crypto-policies/config`, `/proc/sys/crypto/fips_enabled` |
| Security | `/etc/security/limits.conf`, `/etc/security/limits.d/` |
| SELinux | `/etc/selinux/config`, `getenforce` |
| GRUB | `/etc/default/grub`, `/boot/grub2/grub.cfg`, `/boot/efi/EFI/*/grub.cfg` |
| Firewall | `/etc/sysconfig/iptables`, `iptables -L`, `firewall-cmd` |
| Packages | `rpm -q`, `yum list installed`, `/etc/yum.repos.d/` |
| Cron | `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` |
| NTP | `/etc/chrony.conf`, `/etc/ntp.conf` |

### CentOS 7-Specific Commands

```powershell
# Package management
$packages = $(rpm -qa --queryformat '%{NAME}\n' 2>&1)
$rshInstalled = $(rpm -q rsh-server 2>&1)

# Service management
$sshdStatus = $(systemctl is-active sshd 2>&1)
$auditdEnabled = $(systemctl is-enabled auditd 2>&1)

# User/Account management
$passwdContent = $(cat /etc/passwd 2>&1)
$shadowContent = $(cat /etc/shadow 2>&1)
$chageOutput = $(chage -l root 2>&1)
$loginDefs = $(cat /etc/login.defs 2>&1)

# PAM configuration
$systemAuth = $(cat /etc/pam.d/system-auth 2>&1)
$passwordAuth = $(cat /etc/pam.d/password-auth 2>&1)

# SSH configuration
$sshdConfig = $(cat /etc/ssh/sshd_config 2>&1)

# Audit system
$auditRules = $(auditctl -l 2>&1)
$auditConf = $(cat /etc/audit/auditd.conf 2>&1)

# Sysctl / Kernel parameters
$kernelParam = $(sysctl -n kernel.randomize_va_space 2>&1)

# SELinux
$selinuxStatus = $(getenforce 2>&1)
$selinuxConfig = $(cat /etc/selinux/config 2>&1)

# File permissions
$statResult = $(stat -c '%a %U %G' /etc/passwd 2>&1)

# FIPS mode
$fipsEnabled = $(cat /proc/sys/crypto/fips_enabled 2>&1)

# Firewall
$iptablesRules = $(timeout 10 iptables -L -n 2>&1)
$firewalldStatus = $(systemctl is-active firewalld 2>&1)

# GRUB
$grubConfig = $(timeout 10 cat /boot/grub2/grub.cfg 2>&1)
$grubDefault = $(cat /etc/default/grub 2>&1)

# NTP/Chrony
$chronyConf = $(cat /etc/chrony.conf 2>&1)
$chronySources = $(chronyc sources 2>&1)

# Find with timeout and maxdepth (Rule 6)
$worldWritable = $(timeout 15 find / -maxdepth 5 -xdev -type f -perm -0002 2>/dev/null)
$suidFiles = $(timeout 15 find / -maxdepth 5 -xdev -type f -perm -4000 2>/dev/null)
```

---

## Function Template (Complete)

```powershell
Function Get-V204392 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204392
        STIG ID    : RHEL-07-010010
        Rule ID    : SV-204392r991558_rule
        Rule Title : The Red Hat Enterprise Linux operating system must be configured...
        DiscussMD5 : 0afe26f66204090b10a2480f90524935
        CheckMD5   : 13a177c378f1ac5f48edf383c8ba158a
        FixMD5     : 43f178e85c4d89cefbedad693f8afa91
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$Hostname,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-204392"
    $RuleID = "SV-204392r991558_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine

    # === Implementation goes here ===
    # Use $(cmd 2>&1) for all shell commands
    # Set $Status to "NotAFinding", "Open", or "Not_Applicable"
    # Build $FindingDetails with check evidence

    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $SiteName
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFKey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $SiteName
        HeadHash         = $ResultHash
    }

    return Send-CheckResult @SendCheckParams
}
```

**Key patterns:**
- **GetCorpParams:** 17 parameters (includes Hostname, Username, UserSID, OSPlatform)
- **SendCheckParams:** Uses `HeadHash` (not `ResultHash`)
- **Custom code block:** Between `#---=== Begin/End Custom Code ===---#` markers
- **$nl:** Always define at start of custom code block

---

## Status Decision Logic

| Condition | Status | Example |
|-----------|--------|---------|
| Check passes, system is compliant | `NotAFinding` | SSH root login disabled |
| Check fails, system is non-compliant | `Open` | SSH root login enabled |
| Check not applicable to this system | `Not_Applicable` | GNOME checks on headless server |
| Check cannot execute (rare) | `Not_Reviewed` | Only when check itself can't run |

**Rule:** The automated check execution IS the review. Inconclusive results = `Open`, not `Not_Reviewed`.

---

## Check Type Templates (RHEL 7-Specific)

### Type A: Package Check

```powershell
$nl = [Environment]::NewLine
$packageName = "rsh-server"
$rpmResult = $(rpm -q $packageName 2>&1)
$FindingDetails = "Package Check: $packageName" + $nl
$FindingDetails += "rpm -q result: " + $rpmResult + $nl

if ($rpmResult -match "not installed") {
    $Status = "NotAFinding"
    $FindingDetails += $nl + "Result: Package $packageName is not installed."
}
else {
    $Status = "Open"
    $FindingDetails += $nl + "Result: Package $packageName is installed and must be removed."
}
```

### Type B: SSH Configuration Check

```powershell
$nl = [Environment]::NewLine
$sshdConfig = $(cat /etc/ssh/sshd_config 2>&1)
$FindingDetails = "SSH Configuration Check" + $nl

if ($null -ne $sshdConfig -and $sshdConfig -ne "") {
    $sshdContent = ($sshdConfig -join $nl)
    $FindingDetails += "sshd_config content reviewed." + $nl

    if ($sshdContent -match "(?m)^\s*PermitRootLogin\s+no") {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "PermitRootLogin is set to 'no'."
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "PermitRootLogin is not set to 'no'."
    }
}
else {
    $Status = "Open"
    $FindingDetails += "Unable to read /etc/ssh/sshd_config."
}
```

### Type C: PAM Configuration Check

```powershell
$nl = [Environment]::NewLine
$systemAuth = $(cat /etc/pam.d/system-auth 2>&1)
$passwordAuth = $(cat /etc/pam.d/password-auth 2>&1)
$FindingDetails = "PAM Configuration Check" + $nl

$pamContent = ""
if ($null -ne $systemAuth) { $pamContent += ($systemAuth -join $nl) }
if ($null -ne $passwordAuth) { $pamContent += $nl + ($passwordAuth -join $nl) }

$FindingDetails += "Checked /etc/pam.d/system-auth and /etc/pam.d/password-auth" + $nl

# Example: Check for pam_faillock with deny=3
if ($pamContent -match "pam_faillock.*deny=(\d+)") {
    $denyValue = [int]$matches[1]
    if ($denyValue -le 3) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "pam_faillock deny=$denyValue (meets requirement of 3 or fewer)."
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "pam_faillock deny=$denyValue (exceeds maximum of 3)."
    }
}
else {
    $Status = "Open"
    $FindingDetails += $nl + "pam_faillock is not configured."
}
```

### Type D: Audit Rule Check

```powershell
$nl = [Environment]::NewLine
$auditRules = $(auditctl -l 2>&1)
$FindingDetails = "Audit Rule Check" + $nl

if ($null -ne $auditRules -and $auditRules -ne "") {
    $rulesContent = ($auditRules -join $nl)
    $FindingDetails += "Current audit rules:" + $nl + $rulesContent + $nl

    # Example: Check for passwd monitoring
    if ($rulesContent -match "-w /etc/passwd" -and $rulesContent -match "-p wa") {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "/etc/passwd is being monitored by auditd."
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "Required audit rule for /etc/passwd not found."
    }
}
else {
    $Status = "Open"
    $FindingDetails += "Unable to retrieve audit rules (auditctl -l failed)."
}
```

### Type E: Sysctl / Kernel Parameter Check

```powershell
$nl = [Environment]::NewLine
$paramName = "kernel.randomize_va_space"
$paramValue = $(sysctl -n $paramName 2>&1)
$FindingDetails = "Kernel Parameter Check: $paramName" + $nl
$FindingDetails += "Current value: $paramValue" + $nl

if ($paramValue -eq "2") {
    $Status = "NotAFinding"
    $FindingDetails += $nl + "$paramName is set to 2 (full randomization)."
}
else {
    $Status = "Open"
    $FindingDetails += $nl + "$paramName must be set to 2."
}
```

### Type F: File Permission Check

```powershell
$nl = [Environment]::NewLine
$targetFile = "/etc/passwd"
$statResult = $(stat -c '%a %U %G' $targetFile 2>&1)
$FindingDetails = "File Permission Check: $targetFile" + $nl
$FindingDetails += "stat result: $statResult" + $nl

if ($statResult -match "(\d+)\s+(\w+)\s+(\w+)") {
    $perms = $matches[1]
    $owner = $matches[2]
    $group = $matches[3]
    $FindingDetails += "Permissions: $perms, Owner: $owner, Group: $group" + $nl

    if ([int]$perms -le 644 -and $owner -eq "root" -and $group -eq "root") {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "File permissions and ownership are correct."
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "File must be owned by root:root with permissions 0644 or more restrictive."
    }
}
else {
    $Status = "Open"
    $FindingDetails += "Unable to stat $targetFile."
}
```

### Type G: SELinux Check

```powershell
$nl = [Environment]::NewLine
$selinuxMode = $(getenforce 2>&1)
$selinuxConfig = $(cat /etc/selinux/config 2>&1)
$FindingDetails = "SELinux Status Check" + $nl
$FindingDetails += "getenforce: $selinuxMode" + $nl

if ($null -ne $selinuxConfig) {
    $configContent = ($selinuxConfig -join $nl)
    $FindingDetails += "SELinux config:" + $nl + $configContent + $nl
}

# XCP-ng typically has SELinux disabled
if ($selinuxMode -match "Enforcing") {
    $Status = "NotAFinding"
    $FindingDetails += $nl + "SELinux is in Enforcing mode."
}
else {
    $Status = "Open"
    $FindingDetails += $nl + "SELinux is not in Enforcing mode (current: $selinuxMode). XCP-ng Dom0 typically has SELinux disabled."
}
```

### Type H: Login.defs / Password Aging Check

```powershell
$nl = [Environment]::NewLine
$loginDefs = $(cat /etc/login.defs 2>&1)
$FindingDetails = "Password Policy Check (/etc/login.defs)" + $nl

if ($null -ne $loginDefs) {
    $defsContent = ($loginDefs -join $nl)

    # Example: PASS_MAX_DAYS
    if ($defsContent -match "(?m)^\s*PASS_MAX_DAYS\s+(\d+)") {
        $maxDays = [int]$matches[1]
        $FindingDetails += "PASS_MAX_DAYS: $maxDays" + $nl

        if ($maxDays -le 60) {
            $Status = "NotAFinding"
            $FindingDetails += $nl + "PASS_MAX_DAYS is $maxDays (meets requirement of 60 or fewer)."
        }
        else {
            $Status = "Open"
            $FindingDetails += $nl + "PASS_MAX_DAYS is $maxDays (must be 60 or fewer)."
        }
    }
    else {
        $Status = "Open"
        $FindingDetails += "PASS_MAX_DAYS not defined in /etc/login.defs."
    }
}
else {
    $Status = "Open"
    $FindingDetails += "Unable to read /etc/login.defs."
}
```

---

## Dom0 Check Topic Categories

| Topic | Typical Checks | Primary Tools |
|-------|---------------|---------------|
| Login Banner | /etc/issue, /etc/motd, SSH Banner | cat, sshd_config |
| Password Complexity | ucredit, lcredit, dcredit, ocredit, difok, minlen | /etc/security/pwquality.conf |
| Password Aging | PASS_MAX_DAYS, PASS_MIN_DAYS, remember | /etc/login.defs, chage |
| Account Management | Account expiration, inactive, GID/UID | /etc/passwd, /etc/shadow, chage |
| Authentication / PAM | faillock, delay, pam_unix | /etc/pam.d/system-auth, password-auth |
| SSH | PermitRootLogin, Ciphers, MACs, Banner, etc. | /etc/ssh/sshd_config |
| Audit Rules | File watches, syscall rules, privileged cmds | auditctl -l, /etc/audit/rules.d/ |
| Audit Management | auditd.conf, space actions, syslog | /etc/audit/auditd.conf |
| File Permissions | System commands, libraries, config files | stat, find, rpm -V |
| Kernel / Sysctl | ASLR, core dumps, IPv6, network params | sysctl -n, /etc/sysctl.conf |
| SELinux | Mode, policy, context | getenforce, /etc/selinux/config |
| Packages / Services | Unwanted packages, required services | rpm -q, systemctl |
| FIPS / Crypto | FIPS mode, crypto policy | /proc/sys/crypto/fips_enabled |
| GRUB / Boot | GRUB password, kernel parameters | /boot/grub2/grub.cfg |
| Firewall | iptables rules, firewalld status | iptables -L, firewall-cmd |
| NTP / Time | Chrony, NTP configuration | chronyc, /etc/chrony.conf |

---

## Answer File Template

### Standard 2-Index Entry

```xml
  <Vuln ID="V-204392">
    <!--RuleTitle: [Full title from XCCDF]-->
    <AnswerKey Name="XCP-ng">
      <!--Batch N: [Brief description]-->
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>[150-250 words: what was checked, what was found, why compliant]</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>[150-250 words: what failed, STIG requirement, remediation steps]</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>
```

### 3-Index Entry (when Not_Applicable is possible)

```xml
  <Vuln ID="V-######">
    <!--RuleTitle: [Full title from XCCDF]-->
    <AnswerKey Name="XCP-ng">
      <Answer Index="1" ExpectedStatus="NotAFinding" ...>
        ...
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" ...>
        ...
      </Answer>
      <Answer Index="3" ExpectedStatus="Not_Applicable" ...>
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>
        <ValidTrueComment>[Explanation of why not applicable to XCP-ng Dom0]</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>
```

---

## XML Entity Escaping (Mandatory)

| Character | Escaped | Example |
|-----------|---------|---------|
| `&` | `&amp;` | `systemctl enable auditd &amp;&amp; systemctl start auditd` |
| `<` | `&lt;` | `if value &lt; 60 then...` |
| `>` | `&gt;` | `permissions &gt; 644` |
| `"` | `&quot;` | Inside attribute values only |

Never use `--` inside XML comments. Never put unescaped `<Tag>` in comment text.

---

## XCP-ng Dom0 Considerations

1. **SELinux disabled by default:** Most SELinux checks will return Open. Document as known gap.
2. **FIPS mode:** XCP-ng kernel may not support FIPS. Check `/proc/sys/crypto/fips_enabled`.
3. **GNOME not installed:** XCP-ng Dom0 is headless. GNOME/screensaver checks -> Not_Applicable.
4. **Firewalld may not be present:** XCP-ng uses iptables directly. Check both.
5. **PowerShell 7.3.12:** Cannot use 7.4+ features (glibc constraint).
6. **rpm -V for file integrity:** Use `timeout 30 rpm -V` to avoid hangs.
7. **xapi service:** XCP-ng's management daemon; avoid interfering with it.
8. **Dom0 kernel:** Custom Xen-enabled kernel; standard RHEL kernel checks may differ.

---

## Per-Batch Workflow Checklist

1. [ ] Extract XCCDF check content for all VulnIDs in batch
2. [ ] Implement all functions (replace stub custom code block)
3. [ ] Verify all 8 coding rules (zero violations)
4. [ ] Replace NR answer file stubs with 2-index entries
5. [ ] Validate function count (explicit = 244)
6. [ ] Validate coding rules (grep for backtick-n, bash -c, escaped quotes)
7. [ ] Validate answer file XML (no unescaped ampersands)
8. [ ] Commit to feature branch
9. [ ] User runs scan test
10. [ ] Analyze test results, fix issues
11. [ ] Push, PR, merge
