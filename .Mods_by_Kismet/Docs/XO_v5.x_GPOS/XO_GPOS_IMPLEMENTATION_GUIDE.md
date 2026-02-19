# XO_GPOS Debian 12 Implementation Guide

**Created:** February 18, 2026 (Session #50)
**Purpose:** GPOS-specific patterns, templates, and reusable code blocks for implementing
Scan-XO_GPOS_Debian12_Checks functions. Mirrors XO_ASD_IMPLEMENTATION_GUIDE.md structure.
**Module:** `Evaluate-STIG/Modules/Scan-XO_GPOS_Debian12_Checks/Scan-XO_GPOS_Debian12_Checks.psm1`
**Answer File:** `Evaluate-STIG/AnswerFiles/XO_v5.x_GPOS_Debian12_AnswerFile.xml`

---

## Quick Reference: 8 Critical Coding Rules

Every GPOS function **MUST** follow these rules (violations cause scan hangs or broken output):

| # | Rule | WRONG | RIGHT |
|---|------|-------|-------|
| 1 | No backtick escapes | `` `n `` | `$nl = [Environment]::NewLine` |
| 2 | No escaped quotes | `\"` | `[char]34` |
| 3 | Function naming | `Get-V-203591` | `Get-V203591` |
| 4 | No bash/sh wrapper | `$(bash -c "cmd")` | `$(cmd 2>&1)` |
| 5 | Array to string before regex | `$arr -match "pat"` | `($arr -join $nl) -match "pat"` |
| 6 | GetCorpParams always 18 params | (fewer params) | See template below |
| 7 | find/grep always have timeout+maxdepth | `find /` | `timeout 10 find /etc -maxdepth 5` |
| 8 | FINDING_DETAILS = output only | Guidance in FindingDetails | All guidance goes to answer file COMMENTS |

**VulnTimeout:** Always use `-VulnTimeout 15` when running framework tests for GPOS module.

---

## GPOS-Specific Architecture

### Target System

The GPOS SRG is applied to the **Debian 12** operating system that hosts Xen Orchestra.
Unlike ASD/WebSRG (which check the XO application), GPOS checks the underlying OS:
- User accounts, PAM, password policy
- File permissions, ownership, ACLs
- SSH configuration
- Audit system (auditd, systemd-journal)
- Kernel parameters (sysctl)
- Firewall (UFW/iptables/nftables)
- AppArmor/SELinux
- System services (systemd)
- Package management (apt)

### Deployment Models (OS-Level Differences)

| Aspect | XOCE (Community Edition) | XOA (Appliance) |
|--------|--------------------------|-----------------|
| Base OS | Debian 12 | Debian 12 (Vates image) |
| User accounts | Root + custom | Root + xo |
| Firewall | Not configured by default | UFW enabled by default |
| Package manager | apt (full access) | apt (may be restricted) |
| SSH | Configured by admin | Enabled by default |
| Audit system | Typically auditd | Typically auditd |
| AppArmor | Available but may not be enforcing | May be pre-configured |

### Key Configuration Paths (Debian 12)

```
/etc/ssh/sshd_config          # SSH daemon configuration
/etc/ssh/sshd_config.d/       # Drop-in SSH configs (Debian 12 pattern)
/etc/pam.d/                    # PAM configuration modules
/etc/security/                 # PAM security limits, access.conf, pwquality.conf
/etc/login.defs                # Login defaults (PASS_MAX_DAYS, etc.)
/etc/audit/                    # auditd configuration
/etc/audit/rules.d/            # auditd rules (persistent)
/etc/sysctl.conf               # Kernel parameters
/etc/sysctl.d/                 # Drop-in kernel parameters
/etc/default/grub              # GRUB boot parameters (FIPS, audit=1)
/etc/fstab                     # Filesystem mount options
/etc/apt/                      # Package management configuration
/etc/apparmor.d/               # AppArmor profiles
/etc/ufw/                      # UFW firewall configuration
/etc/chrony/chrony.conf        # Chrony NTP configuration (Debian 12 default)
/etc/systemd/                  # systemd unit overrides
/etc/issue                     # Pre-login banner (local)
/etc/issue.net                 # Pre-login banner (remote/SSH)
```

### Debian 12-Specific Commands

```powershell
# Package management
$(dpkg -l 2>&1)                              # List installed packages
$(dpkg -l package-name 2>&1)                 # Check specific package
$(apt list --installed 2>&1)                 # Alternative package list

# PAM configuration
$(timeout 5 cat /etc/pam.d/common-auth 2>&1)        # Auth PAM stack
$(timeout 5 cat /etc/pam.d/common-password 2>&1)     # Password PAM stack
$(timeout 5 cat /etc/pam.d/common-account 2>&1)      # Account PAM stack
$(timeout 5 cat /etc/pam.d/common-session 2>&1)      # Session PAM stack

# SSH effective configuration (Debian 12 supports Include directive)
$(timeout 5 sshd -T 2>&1)                    # Show effective SSH config

# Kernel parameters
$(timeout 5 sysctl -a 2>&1)                  # All kernel parameters
$(timeout 5 sysctl specific.param 2>&1)      # Specific parameter

# Firewall
$(timeout 5 ufw status verbose 2>&1)         # UFW status
$(timeout 5 iptables -L -n 2>&1)             # iptables rules
$(timeout 5 nft list ruleset 2>&1)           # nftables rules

# Audit system
$(timeout 5 auditctl -l 2>&1)               # Current audit rules
$(timeout 5 systemctl is-active auditd 2>&1) # auditd status

# User/account management
$(timeout 5 cat /etc/passwd 2>&1)            # User accounts
$(timeout 5 cat /etc/shadow 2>&1)            # Password hashes (root only)
$(timeout 5 cat /etc/group 2>&1)             # Group membership
$(timeout 5 cat /etc/login.defs 2>&1)        # Login defaults
$(timeout 5 chage -l username 2>&1)          # Password aging for user
$(timeout 5 lastlog 2>&1)                    # Last login times

# AppArmor
$(timeout 5 apparmor_status 2>&1)            # AppArmor status
$(timeout 5 aa-status 2>&1)                  # Alternative command

# Systemd services
$(timeout 5 systemctl list-unit-files --type=service 2>&1) # All services
$(timeout 5 systemctl is-enabled service-name 2>&1)        # Service enablement
```

---

## Function Template (Complete)

```powershell
Function Get-V######() {
    <#
    .SYNOPSIS
        V-######
        Rule Title: [RULE TITLE]
        Severity: CAT II
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
    $VulnID = "V-######"
    $RuleID = "SV-######r#_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    $nl = [Environment]::NewLine
    $output = ""

    # -----------------------------------------------------------------------
    # CHECK LOGIC
    # -----------------------------------------------------------------------

    $Status = "Open"   # or "NotAFinding" or "Not_Applicable"

    $output += "Check 1: [Description]${nl}"
    try {
        $result = $(timeout 10 some-command 2>&1)
        $resultStr = $result -join $nl
        if ($resultStr -match "pattern") {
            $output += "  [PASS] Compliant: evidence${nl}"
        }
        else {
            $output += "  [FAIL] Non-compliant: evidence${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    $FindingDetails = $output.TrimEnd()

    # -----------------------------------------------------------------------
    # ANSWER FILE LOOKUP (copy exactly - all 18 params required)
    # -----------------------------------------------------------------------

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile    = $PSBoundParameters.AnswerFile
            VulnID        = $VulnID
            RuleID        = $RuleID
            AnswerKey     = $PSBoundParameters.AnswerKey
            Status        = $Status
            Hostname      = $Hostname
            Username      = $Username
            UserSID       = $UserSID
            Instance      = $Instance
            Database      = $Database
            Site          = $SiteName
            ResultHash    = $ResultHash
            ResultData    = $FindingDetails
            ESPath        = $ESPath
            LogPath       = $LogPath
            LogComponent  = $LogComponent
            OSPlatform    = $OSPlatform
            StigType      = $StigType
        }
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey         = $AnswerData.AFKey
            $AFStatus      = $AnswerData.AFStatus
            $Comments      = $AnswerData.AFComment | Out-String
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

---

## Status Decision Logic

### When to return each Status

| Status | When to Use |
|--------|-------------|
| `NotAFinding` | CLI check CONFIRMS compliance (evidence present) |
| `Open` | CLI check CONFIRMS non-compliance, OR check is inconclusive, OR requires org verification |
| `Not_Applicable` | STIG explicitly states "If X is not present, this is N/A" AND confirmed not present |
| `Not_Reviewed` | **NEVER use.** The automated check execution IS the review. |

### Open vs Not_Reviewed clarification
**If the automated check can't confirm compliance, return `Open`** (requires ISSO/ISSM manual review).
**Never return `Not_Reviewed`** - that means the check wasn't run at all.

---

## Check Type Templates (GPOS-Specific)

### Type A: SSH Configuration Check

Use for: SSH daemon settings (ciphers, MACs, key exchange, protocol settings)

```powershell
$Status = "Open"    # assume non-compliant until proven otherwise

$output += "Check 1: SSH configuration verification${nl}"
try {
    # Use sshd -T for effective config (includes Include'd files)
    $sshdConfig = $(timeout 5 sshd -T 2>&1)
    $sshdStr = $sshdConfig -join $nl

    if ($sshdStr -match "(?i)^setting_name\s+expected_value") {
        $output += "  [PASS] setting_name is set to expected_value${nl}"
        $Status = "NotAFinding"
    }
    else {
        $output += "  [FAIL] setting_name not set to expected value${nl}"
        # Extract actual value
        $actual = ($sshdStr -split $nl) | Where-Object { $_ -match "(?i)^setting_name" }
        if ($actual) {
            $output += "  Actual: $actual${nl}"
        }
    }
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type B: PAM Configuration Check

Use for: Password policy, authentication settings, account lockout

```powershell
$output += "Check 1: PAM configuration check${nl}"
try {
    # Check common-password for password requirements
    $pamConfig = $(timeout 5 cat /etc/pam.d/common-password 2>&1)
    $pamStr = $pamConfig -join $nl

    if ($pamStr -match "pam_pwquality\.so.*minlen=(\d+)") {
        $minlen = $matches[1]
        if ([int]$minlen -ge 15) {
            $output += "  [PASS] Minimum password length: $minlen (meets DoD 15-char requirement)${nl}"
            $Status = "NotAFinding"
        }
        else {
            $output += "  [FAIL] Minimum password length: $minlen (DoD requires 15)${nl}"
        }
    }
    else {
        $output += "  [FAIL] pam_pwquality not configured in common-password${nl}"
    }

    # Also check pwquality.conf
    $pwqConfig = $(timeout 5 cat /etc/security/pwquality.conf 2>&1)
    $pwqStr = $pwqConfig -join $nl
    if ($pwqStr -match "minlen\s*=\s*(\d+)") {
        $output += "  pwquality.conf minlen=$($matches[1])${nl}"
    }
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type C: Kernel Parameter Check (sysctl)

Use for: Network hardening, memory protection, kernel security settings

```powershell
$output += "Check 1: Kernel parameter verification${nl}"
try {
    $paramValue = $(timeout 5 sysctl -n kernel.parameter_name 2>&1)
    $paramStr = ($paramValue -join $nl).Trim()

    if ($paramStr -eq "expected_value") {
        $output += "  [PASS] kernel.parameter_name = $paramStr${nl}"
        $Status = "NotAFinding"
    }
    else {
        $output += "  [FAIL] kernel.parameter_name = $paramStr (expected: expected_value)${nl}"
    }

    # Also check persistent configuration
    $persistCheck = $(timeout 5 grep -r "parameter_name" /etc/sysctl.conf /etc/sysctl.d/ 2>&1)
    $persistStr = ($persistCheck -join $nl).Trim()
    if ($persistStr) {
        $output += "  Persistent config: $persistStr${nl}"
    }
    else {
        $output += "  [WARN] No persistent configuration found in sysctl.conf or sysctl.d/${nl}"
    }
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type D: Audit Rule Check

Use for: auditd rules for file access, privilege escalation, system calls

```powershell
$output += "Check 1: Audit rule verification${nl}"
try {
    # Check loaded rules
    $auditRules = $(timeout 5 auditctl -l 2>&1)
    $auditStr = $auditRules -join $nl

    if ($auditStr -match "expected_rule_pattern") {
        $output += "  [PASS] Audit rule found: $(($auditStr -split $nl | Where-Object { $_ -match 'expected_rule' })[0])${nl}"
        $Status = "NotAFinding"
    }
    else {
        $output += "  [FAIL] Required audit rule not found${nl}"
    }

    # Also check persistent rules files
    $persistRules = $(timeout 5 grep -r "rule_pattern" /etc/audit/rules.d/ 2>&1)
    $persistStr = ($persistRules -join $nl).Trim()
    if ($persistStr) {
        $output += "  Persistent rule: $persistStr${nl}"
    }
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type E: File Permission Check

Use for: Sensitive file ownership, permissions, world-readable/writable detection

```powershell
$output += "Check 1: File permission verification${nl}"
try {
    $statOut = $(timeout 5 stat -c "%a %U:%G %n" /path/to/file 2>&1)
    $statStr = ($statOut -join $nl).Trim()
    $output += "  File: $statStr${nl}"

    if ($statStr -match "^(\d+)\s") {
        $perms = $matches[1]
        # Check for overly permissive (world-readable = x4x, world-writable = xx2+)
        $worldBits = [int]($perms[-1].ToString())
        if ($worldBits -gt 0) {
            $output += "  [FAIL] World-accessible permissions detected: $perms${nl}"
        }
        else {
            $output += "  [PASS] Permissions $perms - not world-accessible${nl}"
            $Status = "NotAFinding"
        }
    }
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type F: Package/Service Check

Use for: Required package installed, unwanted package removed, service enabled/disabled

```powershell
$output += "Check 1: Package/service status${nl}"
try {
    # Check if package is installed
    $pkgCheck = $(dpkg -l package-name 2>&1)
    $pkgStr = $pkgCheck -join $nl

    if ($pkgStr -match "^ii\s+package-name") {
        $output += "  [PASS] package-name is installed${nl}"
        # For required packages: $Status = "NotAFinding"
        # For unwanted packages: keep $Status = "Open"
    }
    else {
        $output += "  [INFO] package-name is not installed${nl}"
        # For required packages: keep $Status = "Open"
        # For unwanted packages: $Status = "NotAFinding"
    }

    # Check service status
    $svcStatus = $(timeout 5 systemctl is-enabled service-name 2>&1)
    $svcStr = ($svcStatus -join $nl).Trim()
    $output += "  Service status: $svcStr${nl}"
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type G: Login Banner Check

Use for: DoD consent banner in /etc/issue, /etc/issue.net, /etc/motd

```powershell
$output += "Check 1: Login banner verification${nl}"
try {
    $banner = $(timeout 5 cat /etc/issue 2>&1)
    $bannerStr = ($banner -join $nl).Trim()

    # Check for required DoD banner text elements
    $requiredPhrases = @(
        "USG Information System",
        "consent to monitoring",
        "unauthorized use"
    )
    $missingPhrases = @()
    foreach ($phrase in $requiredPhrases) {
        if ($bannerStr -notmatch [regex]::Escape($phrase)) {
            $missingPhrases += $phrase
        }
    }

    if ($missingPhrases.Count -eq 0) {
        $output += "  [PASS] DoD consent banner contains all required elements${nl}"
        $Status = "NotAFinding"
    }
    else {
        $output += "  [FAIL] Banner missing required phrases:${nl}"
        foreach ($mp in $missingPhrases) {
            $output += "    - $mp${nl}"
        }
    }
}
catch {
    $output += "  [ERROR] $($_.Exception.Message)${nl}"
}
$output += $nl
```

---

## GPOS Check Topic Categories

The 198 GPOS checks map to these major Debian 12 topics:

| Topic | Typical Checks | Primary Tools |
|-------|----------------|---------------|
| Account Management | Account creation/modification auditing, temp account expiry, inactivity lockout | `/etc/shadow`, `chage`, `lastlog`, `useradd` defaults |
| Authentication | Login banner, session lock, screen lock timeout, concurrent sessions | `/etc/issue`, `/etc/pam.d/`, `tmout`, `vlock` |
| Password Policy | Complexity, length, aging, history, dictionary check, encrypted storage | `/etc/security/pwquality.conf`, `/etc/login.defs`, `/etc/pam.d/common-password` |
| SSH Configuration | Ciphers, MACs, KexAlgorithms, banner, root login, empty passwords | `sshd -T`, `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` |
| Audit System | auditd rules, log protection, centralized logging, audit reduction | `auditctl -l`, `/etc/audit/`, `journalctl`, `rsyslog` |
| File Permissions | Sensitive file ownership, world-writable, SUID/SGID | `stat`, `find`, `ls -la` |
| Kernel/System | Sysctl parameters, ASLR, NX/DEP, FIPS mode, boot params | `sysctl`, `/proc/sys/`, `/etc/default/grub` |
| Firewall | UFW/iptables/nftables rules, deny-all default | `ufw status`, `iptables -L`, `nft list` |
| PKI/Certificates | DoD PKI trust anchors, certificate validation, OCSP | `/etc/ssl/certs/`, `openssl verify` |
| Time Synchronization | NTP/Chrony config, sync sources, authoritative time | `chronyc sources`, `timedatectl`, `/etc/chrony/` |
| Software Management | Security updates, removed components, package verification | `apt`, `dpkg`, `unattended-upgrades` |
| Mandatory Access Control | AppArmor profiles, enforcement mode | `apparmor_status`, `aa-status` |
| Cryptography | FIPS mode, encrypted transmissions, key management | `openssl`, `/proc/sys/crypto/fips_enabled` |

---

## Answer File Template

### Standard 2-Index Entry (most functions)

```xml
<Vuln ID="V-######">
  <AnswerKey Name="XO">
    <Answer Index="1" ExpectedStatus="NotAFinding">
      <ValidationCode />
      <ValidTrueStatus>NotAFinding</ValidTrueStatus>
      <ValidTrueComment>
[Rule Title] - Compliant

The automated check confirmed [specific evidence]. This satisfies the GPOS SRG requirement
that [brief requirement summary].

Verified:
- [Check 1 result]
- [Check 2 result]

No further action required. Document this finding in the site STIG checklist.
      </ValidTrueComment>
      <ValidFalseStatus />
      <ValidFalseComment />
    </Answer>
    <Answer Index="2" ExpectedStatus="Open">
      <ValidationCode />
      <ValidTrueStatus>Open</ValidTrueStatus>
      <ValidTrueComment>
[Rule Title] - Open Finding

The automated check determined that [specific deficiency]. This must be remediated
or accepted via a Plan of Action and Milestones (POA&amp;M).

Remediation Steps:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Reference: GPOS SRG V3R2, [specific SRG-OS-###### reference]

ISSO Action: Document this finding. If remediation is not possible, submit a
compensating control or waiver request to the Authorizing Official (AO).
      </ValidTrueComment>
      <ValidFalseStatus />
      <ValidFalseComment />
    </Answer>
  </AnswerKey>
</Vuln>
```

### 3-Index Entry (when Not_Applicable is possible)

```xml
<Vuln ID="V-######">
  <AnswerKey Name="XO">
    <Answer Index="1" ExpectedStatus="NotAFinding">
      <ValidationCode />
      <ValidTrueStatus>NotAFinding</ValidTrueStatus>
      <ValidTrueComment>[Compliant explanation]</ValidTrueComment>
      <ValidFalseStatus />
      <ValidFalseComment />
    </Answer>
    <Answer Index="2" ExpectedStatus="Open">
      <ValidationCode />
      <ValidTrueStatus>Open</ValidTrueStatus>
      <ValidTrueComment>[Open finding + remediation]</ValidTrueComment>
      <ValidFalseStatus />
      <ValidFalseComment />
    </Answer>
    <Answer Index="3" ExpectedStatus="Not_Applicable">
      <ValidationCode />
      <ValidTrueStatus>Not_Applicable</ValidTrueStatus>
      <ValidTrueComment>[Explanation of why N/A - e.g., feature not present on Debian 12]</ValidTrueComment>
      <ValidFalseStatus />
      <ValidFalseComment />
    </Answer>
  </AnswerKey>
</Vuln>
```

---

## XML Entity Escaping (Mandatory)

All special characters in answer file XML content must be escaped:

| Character | Escaped Form | Example |
|-----------|-------------|---------|
| `<` | `&lt;` | `if x &lt; 5` |
| `>` | `&gt;` | `x &gt;= 10` |
| `&` | `&amp;` | `cmd1 &amp;&amp; cmd2` |
| `"` | `&quot;` | (rarely needed in text content) |

**Common violations:**
- Bash `&&` in remediation steps: must be `&amp;&amp;`
- Comparison operators: `>=` must be `&gt;=`, `<=` must be `&lt;=`
- HTML/XML tags in examples: `<tag>` must be `&lt;tag&gt;`
- Double hyphens in XML comments: `--` is not allowed inside `<!-- -->` blocks

---

## Per-Batch Workflow Checklist

For each batch of functions:

1. **Identify VulnIDs** from the Implementation Plan batch list
2. **Read XCCDF** check content for each VulnID (rule title, check text, fix text)
3. **Implement function** inline (NEVER use Task agents for code generation)
4. **Create answer file entries** (2 indices: NotAFinding + Open)
5. **Validate XML**: `[xml]$xml = Get-Content 'AnswerFile.xml'` (must not throw)
6. **Check for duplicate VulnIDs**: `grep -E '^\s*<Vuln ID="V-' AnswerFile.xml | sort | uniq -d`
7. **Commit to feature branch**
8. **Run framework test** on xo1.wgsdac.net
9. **Verify** COMMENTS populated for all functions in CKL
10. **Update tracker** with test results
11. **Commit test results** to branch

---

## Common Patterns by Topic

### Password Aging (login.defs + chage)

```powershell
# Check PASS_MAX_DAYS
$loginDefs = $(timeout 5 cat /etc/login.defs 2>&1)
$loginStr = $loginDefs -join $nl
if ($loginStr -match "(?m)^PASS_MAX_DAYS\s+(\d+)") {
    $maxDays = [int]$matches[1]
    # DoD: PASS_MAX_DAYS <= 60
}

# Check per-user password aging
$shadowEntries = $(timeout 5 awk -F: '{print $1":"$5}' /etc/shadow 2>&1)
```

### Firewall Detection (multi-method)

```powershell
# Try UFW first (common on Debian)
$ufwCheck = $null
$hasUfw = $(Get-Command ufw -ErrorAction SilentlyContinue)
if ($hasUfw) {
    $ufwCheck = $(timeout 5 ufw status verbose 2>&1)
    $ufwStr = ($ufwCheck -join $nl).Trim()
}

# Fallback to iptables
if (-not $ufwStr -or $ufwStr -match "inactive") {
    $iptCheck = $(timeout 5 iptables -L -n 2>&1)
    $iptStr = ($iptCheck -join $nl).Trim()
}

# Fallback to nftables (Debian 12 native)
if (-not $iptStr -or $iptStr -match "no rules") {
    $nftCheck = $(timeout 5 nft list ruleset 2>&1)
    $nftStr = ($nftCheck -join $nl).Trim()
}
```

### Auditd Rule Verification

```powershell
# Check if auditd is running
$auditdStatus = $(timeout 5 systemctl is-active auditd 2>&1)
$auditdStr = ($auditdStatus -join $nl).Trim()

if ($auditdStr -eq "active") {
    # Check loaded rules
    $rules = $(timeout 5 auditctl -l 2>&1)
    $rulesStr = $rules -join $nl
    # Check persistent rules
    $persistRules = $(timeout 10 grep -r "specific_rule" /etc/audit/rules.d/ 2>&1)
}
```

### FIPS Mode Detection

```powershell
$fipsEnabled = $(timeout 5 cat /proc/sys/crypto/fips_enabled 2>&1)
$fipsStr = ($fipsEnabled -join $nl).Trim()
$isFips = ($fipsStr -eq "1")

# Also check boot parameter
$cmdline = $(timeout 5 cat /proc/cmdline 2>&1)
$cmdlineStr = ($cmdline -join $nl).Trim()
$fipsBoot = ($cmdlineStr -match "fips=1")
```
