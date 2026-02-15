# XO_ASD CAT II Implementation Guide

**Created:** February 14, 2026 (Session #36)
**Purpose:** ASD-specific patterns, templates, and reusable code blocks for implementing
Scan-XO_ASD_Checks functions. Mirrors XO_WebSRG_IMPLEMENTATION_GUIDE_CAT_II.md structure.
**Module:** `Evaluate-STIG/Modules/Scan-XO_ASD_Checks/Scan-XO_ASD_Checks.psm1`
**Answer File:** `Evaluate-STIG/AnswerFiles/XO_v5.x_ASD_AnswerFile.xml`

---

## Quick Reference: 8 Critical Coding Rules

Every ASD function **MUST** follow these rules (violations cause scan hangs or broken output):

| # | Rule | WRONG | RIGHT |
|---|------|-------|-------|
| 1 | No backtick escapes | `` `n `` | `$nl = [Environment]::NewLine` |
| 2 | No escaped quotes | `\"` | `[char]34` |
| 3 | Function naming | `Get-V-222389` | `Get-V222389` |
| 4 | No bash/sh wrapper | `$(bash -c "cmd")` | `$(cmd 2>&1)` |
| 5 | Array → string before regex | `$arr -match "pat"` | `($arr -join $nl) -match "pat"` |
| 6 | GetCorpParams always 18 params | (fewer params) | See template below |
| 7 | find/grep always have timeout+maxdepth | `find /` | `timeout 10 find /opt/xo -maxdepth 5` |
| 8 | FINDING_DETAILS = output only | Guidance in FindingDetails | All guidance → answer file COMMENTS |

**VulnTimeout:** Always use `-VulnTimeout 15` when running framework tests for ASD module.

---

## ASD-Specific Architecture

### Deployment Models

| Aspect | XOCE (Community Edition) | XOA (Appliance) |
|--------|--------------------------|-----------------|
| Config root | `/opt/xo/xo-server/` | `/etc/xo-server/` |
| Install root | `/opt/xo/` | `/usr/share/xo-server/` |
| Packages | `/opt/xo/packages/` | `/usr/lib/xo-server/node_modules/` |
| Firewall | Not configured by default | UFW enabled by default |
| Service | `xo-server.service` | `xo-server.service` |
| Node process | `node /opt/xo/xo-server/dist/cli.mjs` | `node ...cli.mjs` |

### Config File Locations (check both)
```powershell
$configPaths = @(
    "/opt/xo/xo-server/config.toml",      # XOCE primary
    "/opt/xo/.xo-server.config.toml",     # XOCE alternate
    "/etc/xo-server/config.toml",         # XOA primary
    "/etc/xo-server/.config.toml"         # XOA alternate
)
```

### Package Locations (check both)
```powershell
$pkgPaths = @(
    "/opt/xo/packages",                   # XOCE
    "/usr/lib/xo-server/node_modules",    # XOA
    "/opt/xo/xo-server/node_modules"      # XOCE alternate
)
```

### API Token (for XO REST API checks)
```powershell
$tokenPaths = @(
    "/etc/xo-server/stig/api-token",      # Recommended (STIG-specific)
    "/etc/xo-server/.api-token",           # XOA alternate
    "/opt/xo/.api-token"                   # XOCE alternate
)
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
    # ANSWER FILE LOOKUP (copy exactly — all 18 params required)
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
**If the automated check can't confirm compliance → return `Open`** (requires ISSO/ISSM manual review)
**Never return `Not_Reviewed`** — that means the check wasn't run at all.

---

## Check Type Templates

### Type A: Technical CLI Check (automated)

Use for: TLS config, file permissions, service status, package detection, npm audit

```powershell
$Status = "Open"    # assume non-compliant until proven otherwise

$output += "Check 1: [Specific configuration check]${nl}"
try {
    $result = $(timeout 10 grep -r "pattern" /opt/xo/xo-server 2>&1)
    $resultStr = $result -join $nl
    if ($resultStr -match "expected-pattern") {
        $output += "  [PASS] Configuration confirmed: $(($resultStr -split $nl)[0])${nl}"
        $Status = "NotAFinding"
    }
    else {
        $output += "  [FAIL] Configuration not found${nl}"
        # Status remains Open
    }
}
catch {
    $output += "  [ERROR] Unable to check: $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type B: Organizational Policy Check (manual)

Use for: Security training records, threat model docs, change management evidence, architecture review

```powershell
# Organizational policy checks always return Open
# Automated check confirms what CAN be verified; ISSO/ISSM confirms the rest
$Status = "Open"

$output += "Check 1: [Automated evidence scan]${nl}"
try {
    $policyDocs = $(timeout 10 find /etc/xo-server /opt/xo -maxdepth 4 -name "*.md" -o -name "*.txt" -o -name "security*" 2>&1)
    $policyStr = $policyDocs -join $nl
    if ($policyStr -match "security|policy|procedure|training") {
        $output += "  [INFO] Policy documents found:${nl}"
        ($policyStr -split $nl) | Where-Object { $_ -match "security|policy" } | ForEach-Object {
            $output += "    $_${nl}"
        }
    }
    else {
        $output += "  [INFO] No policy documents detected in standard paths${nl}"
    }
}
catch {
    $output += "  [INFO] Unable to scan for policy docs: $($_.Exception.Message)${nl}"
}
$output += $nl

$output += "MANUAL REVIEW REQUIRED${nl}"
$output += "  ISSO/ISSM must verify [specific requirement] per organizational policy.${nl}"
$output += "  See COMMENTS for verification procedures.${nl}"
```

### Type C: Code-Level Source Scan (npm/Node.js)

Use for: Library detection, pattern existence in source, API endpoint analysis

```powershell
$output += "Check 1: Dependency/library detection${nl}"
try {
    # Check package.json for library
    $pkgJson = $(timeout 5 cat /opt/xo/xo-server/package.json 2>&1)
    $pkgStr = $pkgJson -join $nl
    if ($pkgStr -match '"express-validator"' -or $pkgStr -match '"joi"' -or $pkgStr -match '"yup"') {
        $output += "  [PASS] Input validation library detected in package.json${nl}"
    }
    else {
        $output += "  [FAIL] No recognized input validation library in package.json${nl}"
    }

    # Check node_modules existence
    $nmCheck = $(timeout 5 ls /opt/xo/xo-server/node_modules/express-validator 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $output += "  [PASS] express-validator module directory exists${nl}"
    }
}
catch {
    $output += "  [INFO] Package check error: $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type D: npm audit (vulnerability scanning)

Use for: Dependency vulnerability checks (reuse from V-222585 pattern)

```powershell
$output += "Check 1: npm audit vulnerability scan${nl}"
try {
    # Locate package directory
    $pkgDir = $null
    foreach ($path in @("/opt/xo/xo-server", "/usr/share/xo-server")) {
        if ($(test -d $path 2>&1; echo $LASTEXITCODE) -eq "0") {
            $pkgDir = $path
            break
        }
    }

    if ($pkgDir) {
        $auditResult = $(timeout 120 npm audit --prefix $pkgDir --json 2>&1)
        $auditStr = $auditResult -join $nl
        if ($auditStr -match '"critical"\s*:\s*([1-9]\d*)') {
            $critCount = $matches[1]
            $output += "  [FAIL] Critical vulnerabilities: $critCount${nl}"
        }
        elseif ($auditStr -match '"high"\s*:\s*([1-9]\d*)') {
            $highCount = $matches[1]
            $output += "  [WARN] High vulnerabilities: $highCount${nl}"
        }
        else {
            $output += "  [PASS] No critical/high vulnerabilities detected${nl}"
            $Status = "NotAFinding"
        }
    }
    else {
        $output += "  [WARN] XO package directory not found${nl}"
    }
}
catch {
    $output += "  [INFO] npm audit error: $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type E: TLS/Certificate Check (reuse from V-222400/V-222403)

```powershell
$output += "Check 1: TLS protocol version verification${nl}"
try {
    $xoHostname = "localhost"
    $xoPort = "443"

    # Test TLS 1.2 support
    $tls12 = $(echo "" | timeout 10 openssl s_client -connect "${xoHostname}:${xoPort}" -tls1_2 2>&1)
    $tls12Str = $tls12 -join $nl
    $tls12Supported = $tls12Str -match "Cipher\s*:" -and $tls12Str -notmatch "no peer certificate|handshake failure"

    # Test TLS 1.1 (should be disabled)
    $tls11 = $(echo "" | timeout 10 openssl s_client -connect "${xoHostname}:${xoPort}" -tls1_1 2>&1)
    $tls11Str = $tls11 -join $nl
    $tls11Enabled = $tls11Str -match "Cipher\s*:" -and $tls11Str -notmatch "handshake failure"

    if ($tls12Supported -and -not $tls11Enabled) {
        $output += "  [PASS] TLS 1.2+ supported, TLS 1.1 disabled${nl}"
        $Status = "NotAFinding"
    }
    elseif ($tls11Enabled) {
        $output += "  [FAIL] TLS 1.1 still enabled — DoD requires TLS 1.2 minimum${nl}"
    }
    else {
        $output += "  [WARN] Unable to confirm TLS configuration${nl}"
    }
}
catch {
    $output += "  [INFO] TLS check error: $($_.Exception.Message)${nl}"
}
$output += $nl
```

### Type F: File Permission Check (reuse from V-222425/V-222554)

```powershell
$output += "Check 1: File permission verification${nl}"
try {
    $sensitiveFiles = $(timeout 15 find /opt/xo /etc/xo-server -maxdepth 5 -name "*.key" -o -name "*.pem" -o -name "config.toml" 2>&1)
    $filesStr = $sensitiveFiles -join $nl
    $permIssues = @()

    ($filesStr -split $nl) | Where-Object { $_ -match "^/" } | ForEach-Object {
        $file = $_
        $statOut = $(stat -c "%a %U:%G %n" $file 2>&1)
        $statStr = $statOut -join $nl
        # Check for world-readable/writable
        if ($statStr -match "^[0-7][0-7][1-7] ") {
            $permIssues += "  [FAIL] World-accessible: $statStr${nl}"
        }
        else {
            $output += "  [PASS] $statStr${nl}"
        }
    }

    if ($permIssues.Count -gt 0) {
        $output += ($permIssues -join "")
    }
    else {
        $output += "  [PASS] No world-accessible sensitive files detected${nl}"
        $Status = "NotAFinding"
    }
}
catch {
    $output += "  [INFO] Permission check error: $($_.Exception.Message)${nl}"
}
$output += $nl
```

---

## Reusable Pattern Functions (Existing Implementations)

These functions are already implemented in the ASD module and can be referenced for patterns:

| VulnID | Pattern Available |
|--------|------------------|
| V-222400 | TLS protocol version check (openssl s_client) |
| V-222403 | Cipher suite verification |
| V-222408 | XO startup arguments / process inspection |
| V-222425 | File permission check (stat, find) |
| V-222430 | Data at rest / sensitive file scan |
| V-222432 | Security logging (log directory, systemd journal) |
| V-222522 | Session management / config.toml parsing |
| V-222536 | Password policy (PAM, /etc/login.defs) |
| V-222542 | Session timeout (cookie settings, maxAge) |
| V-222543 | Session invalidation (logout handler) |
| V-222550 | Audit log user attribution |
| V-222551 | Authentication mechanisms (LDAP/SAML/OAuth plugins) |
| V-222554 | RBAC / ACL plugin detection |
| V-222555 | Firewall / network access control (UFW, iptables) |
| V-222585 | npm audit (vulnerability scan) |
| V-222588 | System password policy |
| V-222589 | Account lockout / fail2ban |
| V-222590 | Inactivity timeout |
| V-222659 | LDAP/external auth delegation |
| V-222662 | Node.js version / platform check |

---

## Answer File Template

### Standard 2-Index Entry (most functions)

```xml
<Vuln ID="V-######">
  <AnswerKey Name="XO">
    <Answer Index="1" ExpectedStatus="NotAFinding">
      <ValidTrueStatus>NotAFinding</ValidTrueStatus>
      <ValidTrueComment>
[Rule Title] — Compliant

The automated check confirmed [specific evidence]. This satisfies the STIG requirement
that [brief requirement summary].

Verified:
- [Check 1 result]
- [Check 2 result]

No further action required. Document this finding in the site's STIG checklist.
      </ValidTrueComment>
    </Answer>
    <Answer Index="2" ExpectedStatus="Open">
      <ValidTrueStatus>Open</ValidTrueStatus>
      <ValidTrueComment>
[Rule Title] — Open Finding

The automated check determined that [specific deficiency]. This must be remediated
or accepted via a Plan of Action and Milestones (POA&amp;M).

Remediation Steps:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Reference: [applicable STIG/SRG reference or Vates documentation]

ISSO Action: Document this finding. If remediation is not possible, submit a
compensating control or waiver request to the Authorizing Official (AO).
      </ValidTrueComment>
    </Answer>
  </AnswerKey>
</Vuln>
```

### 3-Index Entry (when Not_Applicable is possible)

```xml
<Vuln ID="V-######">
  <AnswerKey Name="XO">
    <Answer Index="1" ExpectedStatus="NotAFinding">
      <ValidTrueStatus>NotAFinding</ValidTrueStatus>
      <ValidTrueComment>...</ValidTrueComment>
    </Answer>
    <Answer Index="2" ExpectedStatus="Open">
      <ValidTrueStatus>Open</ValidTrueStatus>
      <ValidTrueComment>...</ValidTrueComment>
    </Answer>
    <Answer Index="3" ExpectedStatus="Not_Applicable">
      <ValidTrueStatus>Not_Applicable</ValidTrueStatus>
      <ValidTrueComment>
[Rule Title] — Not Applicable

The STIG specifies: "If [condition], this is Not Applicable."
The automated check confirmed [condition is true] for this deployment.

No action required for this control.
      </ValidTrueComment>
    </Answer>
  </AnswerKey>
</Vuln>
```

### XML Entity Escaping (MANDATORY)

| Character | Must become |
|-----------|-------------|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `<=` | `&lt;=` |
| `>=` | `&gt;=` |
| `&&` (bash AND) | `&amp;&amp;` |

---

## Per-Batch Workflow Checklist

Before each batch session, verify the batch scope using the TRACKER:

```
Phase N / Batch N: V-XXXXXX to V-XXXXXX
Topic: [topic area]
Functions: N stubs to implement
```

**Implementation Steps (per function):**
1. [ ] Look up rule title in STIG XCCDF or STIGViewer
2. [ ] Determine check type (A/B/C/D/E/F or combination)
3. [ ] Implement function inline (NO subagents for code generation)
4. [ ] Add answer file entry (2–3 indices)
5. [ ] XML validate: `[xml]$x = Get-Content XO_v5.x_ASD_AnswerFile.xml`
6. [ ] Duplicate check: `Select-String -Path AnswerFile.xml -Pattern 'Vuln ID="V-' | ...`
7. [ ] Module load: `Import-Module Scan-XO_ASD_Checks.psd1 -Force` → 286 functions
8. [ ] Framework test: `-SelectSTIG XO_ASD -VulnTimeout 15 -AllowIntegrityViolations`
9. [ ] Verify COMMENTS populated in CKL output for batch functions
10. [ ] Update TRACKER status (Pending → Done)

**Pass Criteria:**
- Exit code: 0
- All batch functions: NotAFinding or Open (not Not_Reviewed)
- All batch functions: COMMENTS field populated in CKL
- No new errors vs previous baseline
- EvalScore increases monotonically

---

## Common ASD STIG Patterns by Topic

### Design Review / Threat Modeling (Phases 1-2)
- **Always Open** (requires documented evidence from the organization)
- Check for evidence files: `find /etc/xo-server /opt/xo -maxdepth 3 -name "*.md" -o -name "threat*" 2>&1`
- Document what was scanned; ISSO confirms evidence existence

### Access Control / RBAC (Phase 2)
- Reuse V-222554 (ACL plugin) and V-222555 (firewall) patterns
- Check: `xo-cli acl.getAll` via API or config.toml `acls` section
- sudo rules: `sudo -l 2>&1`, `/etc/sudoers.d/xo*`

### Input Validation (Phase 3)
- Check package.json for: `express-validator`, `joi`, `yup`, `zod`, `validator`
- Check source for SQL patterns: `timeout 10 grep -r "raw\|query(" /opt/xo/xo-server/dist --include="*.js" -l -maxdepth 5 2>&1`
- ORM detection: `grep -r "typeorm\|knex\|sequelize" /opt/xo/xo-server/package.json 2>&1`

### Audit / Logging (Phase 4)
- Reuse V-222432 (log directory) and V-222550 (user attribution) patterns
- Winston config: `grep -r "winston\|createLogger\|transports" /opt/xo/xo-server/dist -l --include="*.js" 2>&1`
- Audit plugin: `ls /opt/xo/packages/xo-server-audit* 2>&1 || ls /usr/lib/xo-server/node_modules/xo-server-audit 2>&1`

### Session Management (Phase 5)
- Reuse V-222542/V-222543 (session timeout/invalidation) patterns
- Config check: `grep -A5 "session\|token\|jwt\|cookie" /opt/xo/xo-server/config.toml 2>&1`
- Redis session store: `systemctl is-active redis 2>&1 || systemctl is-active redis-server 2>&1`

### Data Protection / Cryptography (Phase 6)
- Reuse V-222430 (LUKS/dm-crypt) and V-222589 (encryption at rest) patterns
- Key storage: `timeout 15 find /etc/ssl /etc/xo-server /opt/xo -maxdepth 5 -name "*.key" -o -name "*.pem" 2>&1`
- Hardcoded secrets scan: `timeout 15 grep -r "password\s*=\|secret\s*=\|apikey\s*=" /etc/xo-server /opt/xo/xo-server -l --include="*.toml" --include="*.json" -maxdepth 3 2>&1`

### Error Handling (Phase 7)
- NODE_ENV: `$(systemctl show xo-server.service --property=Environment 2>&1) -match "NODE_ENV=production"`
- Debug flags: `$(ps aux 2>&1 | grep "node.*xo") -match "\-\-inspect|\-\-debug"`

### SDLC / Development (Phase 8)
- Reuse V-222585 (npm audit) pattern
- Outdated packages: `timeout 120 npm outdated --prefix /opt/xo/xo-server 2>&1`
- SBOM: `timeout 120 npm ls --prefix /opt/xo/xo-server --json 2>&1`

---

## ASD File Organization

| File type | Location |
|-----------|----------|
| Batch scripts (`batch*.ps1`) | `Docs/XO_v5.x_ASD/Test/` |
| Integration scripts (`integrate_*.py`) | `Docs/XO_v5.x_ASD/Test/` |
| Standalone test scripts (`test_*.ps1`) | `Docs/XO_v5.x_ASD/Test/` |
| Helper scripts (Python, shell) | `Docs/XO_v5.x_ASD/Test/Helper_Scripts/` |
| Framework test log output | `Docs/XO_v5.x_ASD/Test/Logs/` |
| CKL/CKLB results from framework tests | `Docs/XO_v5.x_ASD/Test/Results/` |
| Answer file snippet drafts (`*_entries.xml`) | `Docs/XO_v5.x_ASD/Test/` |
| Documentation and trackers | `Docs/XO_v5.x_ASD/` (root) |

**Test naming:** Continue from WebSRG sequence. WebSRG last test was Test124 → ASD baseline is **Test125**.

---

## Module Stats Baseline (Session #36 Start)

| Metric | Value |
|--------|-------|
| Module file | `Scan-XO_ASD_Checks.psm1` |
| Total lines | 35,841 |
| Total functions | 286 |
| CAT I implemented | 14 (6 NotAFinding, 6 Open, 2 Not_Applicable) |
| CAT I stubs (Not_Reviewed) | 20 |
| CAT II/III implemented | ~8 |
| CAT II/III stubs | ~244 |
| Answer file | `XO_v5.x_ASD_AnswerFile.xml` |
| Last test | Test39 (baseline, Exit 0, EvalScore 0.7%) |

*Note: Exact implemented vs stub counts to be reconciled in Phase 0B.*

---

## Testing Commands Reference

```powershell
# Module load test
Import-Module "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psd1" -Force
(Get-Module Scan-XO_ASD_Checks).ExportedCommands.Count  # Must be 286

# XML answer file validation
[xml]$af = Get-Content "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"

# Duplicate VulnID check
Select-String -Path "d:\...\XO_v5.x_ASD_AnswerFile.xml" -Pattern '<Vuln ID="V-' |
    ForEach-Object { ($_.Line -match '<Vuln ID="(V-\d+)"') | Out-Null; $matches[1] } |
    Sort-Object | Group-Object | Where-Object { $_.Count -gt 1 }

# Framework test (from Evaluate-STIG folder)
.\Evaluate-STIG.ps1 -ComputerName xo1.wgsdac.net -SelectSTIG XO_ASD `
    -Output CKL -VulnTimeout 15 -AllowIntegrityViolations

# Clear remote cache between tests
# ssh root@xo1.wgsdac.net "rm -rf /tmp/Evaluate-STIG_RemoteComputer"

# Quick function stub count
Select-String -Path ".\Scan-XO_ASD_Checks.psm1" -Pattern "Status = .Not_Reviewed" | Measure-Object
```
