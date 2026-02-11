# Answer File Development Plan for VatesVMS STIGs

**Created:** January 22, 2026
**Purpose:** Systematic development of answer files for XCP-ng and Xen Orchestra STIG compliance
**Status:** XO WebSRG module 100% complete as of February 9, 2026

---

## ⚠️ CRITICAL CODING REQUIREMENTS

### **1. NO BACKTICK ESCAPES IN SCAN MODULE CODE**

**Issue Discovered:** January 23, 2026 (Tests 58-63)
**Symptom:** Infinite loop with 90%+ CPU usage, scan hangs indefinitely
**Root Cause:** Backtick escape sequences (e.g., `` `n ``, `` `t ``) in Custom Code sections cause PowerShell to enter infinite loop

**REQUIRED APPROACH:**
```powershell
# ❌ NEVER DO THIS - Causes infinite loop:
$FindingDetails = "Line 1`n"
$FindingDetails += "Line 2`n"

# ✅ ALWAYS DO THIS - Works correctly:
$nl = [Environment]::NewLine
$FindingDetails = "Line 1" + $nl
$FindingDetails += "Line 2" + $nl
```

**Verified Safe Alternatives:**
- `[Environment]::NewLine` for line breaks
- `[Environment]::Tab` for tabs
- String concatenation with `+` operator
- PowerShell string formatting with `-f` operator

---

### **2. NO ESCAPED QUOTES OR BACKSLASHES IN CUSTOM CODE**

**Issue Discovered:** January 23, 2026 (Tests 67-68)
**Symptom:** Module import hangs/crashes, scan terminates abruptly
**Root Cause:** ANY escaped characters (`\"`, `\'`, `\\`) in Custom Code cause infinite loop during module parsing

**FAILED ATTEMPTS:**
```powershell
# ❌ Attempt 1 - Double quotes with escaped inner quotes:
$result = bash -c "node -e 'require(\"crypto\").getFips()'"
# Result: CRASH

# ❌ Attempt 2 - Single quotes with escaped inner quotes:
$result = bash -c 'node -e "console.log(require(\"crypto\").getFips())"'
# Result: STILL CRASHES - PowerShell parser sees \" even in single quotes!
```

**WORKING SOLUTION - Use [char] for quotes:**
```powershell
# ✅ Build command with character codes to avoid escape sequences:
$cmd = 'timeout 5 node -e ' + [char]34 + 'console.log(require(' + [char]34 + 'crypto' + [char]34 + ').getFips())' + [char]34 + ' 2>&1'
$result = bash -c $cmd
# [char]34 is double quote character - no escaping needed!
```

**Pattern for Complex Commands:**
- Never use `\"` or `\'` escape sequences anywhere in Custom Code
- Build strings dynamically using `[char]##` for special characters
- Common character codes:
  - `[char]34` = double quote `"`
  - `[char]39` = single quote `'`
  - `[char]92` = backslash `\`
- Concatenate with `+` operator to build complex commands
- This completely bypasses PowerShell's escape sequence parser

**Why This Matters:**
- Backtick escapes and escaped quotes work fine in normal PowerShell scripts
- They cause infinite loops ONLY in scan module Custom Code sections
- Issue occurs during module import/parsing by Evaluate-STIG framework
- All special character handling must avoid triggering parser loops
- This applies to ALL scan modules (XO_WebSRG, XO_ASD, XO_GPOS, etc.)

---

### **3. FUNCTION NAMING CONVENTION - NO HYPHENS IN VULNERABILITY ID**

**Issue Discovered:** January 24, 2026 (Test76)
**First Occurrence:** January 23, 2026 (Test57-58) - Fixed for V-206390
**Second Occurrence:** January 24, 2026 (Test76) - Discovered for V-206399 and V-279029
**Symptom:** Function never executes, Status remains "Not_Reviewed", FINDING_DETAILS empty
**Root Cause:** Framework's vulnerability-to-function mapping algorithm removes hyphens from vulnerability IDs when searching for functions

**THE PROBLEM:**
```powershell
# Vulnerability ID in XCCDF: V-206399
# Framework constructs function name by removing hyphen: "Get-V206399"
# If function declared with hyphen in ID portion: "Get-V-206399"
# Result: Framework can't find function, never executes it

# ❌ WRONG - Function will never be called by framework:
Function Get-V-206399 {
    # Implementation here
}

# ✅ CORRECT - Framework can find and call this function:
Function Get-V206399 {
    # Implementation here
}
```

**CRITICAL RULE:**
- Vulnerability ID format: `V-######` (with hyphen)
- Function name format: `Get-V######` (NO hyphen between V and numbers)
- The hyphen after "Get-" is REQUIRED (PowerShell cmdlet naming convention)
- The hyphen in the vulnerability ID portion must be REMOVED
- Export-ModuleMember uses wildcard `Get-V*` so both formats export, but framework can't find hyphenated versions

**VALIDATION:**
```powershell
# Test if function name follows correct pattern:
# Vulnerability: V-206390 → Function: Get-V206390 ✓
# Vulnerability: V-206399 → Function: Get-V206399 ✓ (not Get-V-206399)
# Vulnerability: V-279029 → Function: Get-V279029 ✓ (not Get-V-279029)
```

**THIS IS THE SECOND TIME THIS ISSUE OCCURRED** - Must be remembered for all future function implementations!

---

### **4. VULNTIMEOUT 15 MINUTES FOR XO WEBSRG**

**Issue Discovered:** January 23, 2026 (Tests 73-74)
**Symptom:** Scan times out before completing all checks, results not generated
**Root Cause:** Default 10-minute VulnTimeout insufficient for XO WebSRG checks due to environmental performance issues

**REQUIRED PARAMETER:**
```powershell
# ❌ NEVER DO THIS - Default 10-minute timeout insufficient:
.\Evaluate-STIG.ps1 -SelectSTIG XO_WebSRG -ComputerName xo1.wgsdac.net

# ✅ ALWAYS DO THIS - Use 15-minute timeout:
.\Evaluate-STIG.ps1 -SelectSTIG XO_WebSRG -ComputerName xo1.wgsdac.net -VulnTimeout 15
```

**Test Evidence:**
- Test73: Hit 10-minute VulnTimeout, scan incomplete
- Test74: 13min 42sec with VulnTimeout 15, SUCCESS
- Note: Individual functions execute in <1 second standalone; delay is environmental/framework overhead

---

### **5. BASH MULTI-LINE OUTPUT HANDLING**

**Issue Discovered:** January 24, 2026 (V-279029 standalone testing)
**Symptom:** Wrong values extracted from bash output (e.g., "Debian 22" instead of "Debian 12")
**Root Cause:** Bash commands returning multiple lines create PowerShell arrays, not strings; `-match` on arrays does filtering not regex, uses stale `$matches` values

**THE PROBLEM:**
```powershell
# Bash command returns 4 lines (array with 4 elements)
$debianInfoRaw = $(timeout 3 lsb_release -a 2>&1)
# $debianInfoRaw.GetType().Name = "Object[]"

# ❌ WRONG - -match on array does filtering, not regex matching:
if ($debianInfoRaw -match 'Release:\s+(\d+)') {
    $version = $matches[1]  # Uses STALE $matches from previous operation!
}
```

**WORKING SOLUTION:**
```powershell
# ✅ ALWAYS DO THIS - Convert array to string before regex:
$debianInfoRaw = $(timeout 3 lsb_release -a 2>&1)
$debianInfo = $debianInfoRaw -join "`n"  # Convert array to single string

if ($debianInfo -match 'Release:\s+(\d+)') {
    $version = $matches[1]  # Now extracts correct value
}
```

**Why This Matters:**
- Bash multi-line output automatically becomes PowerShell array
- `-match` operator behaves differently on arrays vs strings
- On arrays: filters array elements, doesn't update `$matches`
- On strings: performs regex matching, populates `$matches[1]` correctly
- Always join array to string before regex operations

---

### **6. DIRECT COMMAND EXECUTION - NEVER USE `bash -c` WRAPPER**

**Issue Discovered:** January 24, 2026 (Test79 analysis, RHEL9 module comparison)
**Symptom:** 6-10+ minute execution times for functions that run in <1 second standalone
**Root Cause:** Using `bash -c` wrapper causes stdin handling issues in framework execution context; production RHEL modules use direct command execution

**PRODUCTION PATTERN (from Scan-RHEL9_Checks.psm1):**
```powershell
# ✅ Production modules call Linux commands directly:
$finding = $(grep -I -s -i pattern /etc/config)
$result = $(timeout 3 cat /proc/sys/kernel/parameter 2>&1)
$version = $(systemctl status service 2>&1)
```

**OUR FAILED APPROACH:**
```powershell
# ❌ WRONG - bash -c wrapper causes stdin hanging:
$result = bash -c "timeout 3 cat file 2>&1 </dev/null"
# Execution time: 6-10 minutes in framework (hangs waiting for stdin)
# Standalone time: <1 second
```

**CORRECT IMPLEMENTATION:**
```powershell
# ✅ CORRECT - Direct command execution:
$result = $(timeout 3 cat file 2>&1)
# Execution time: <1 second in both framework and standalone

# ✅ For complex commands with quote nesting, use Invoke-Expression:
$cmd = "timeout 5 node -e 'console.log(require(\"crypto\").getFips())' 2>&1"
$result = Invoke-Expression $cmd

# ✅ Only use sh -c when shell operators required:
$result = $(timeout 3 sh -c 'pgrep nginx >/dev/null && echo running || echo stopped')
```

**Why This Matters:**
- PowerShell on Linux can execute Linux commands natively
- `bash -c` creates extra shell layer with stdin/stdout handling issues
- Framework execution context amplifies these issues (100x+ slowdown)
- Standalone scripts less affected due to different execution environment
- Production RHEL8/RHEL9 modules never use `bash -c` - follow their pattern
- Direct execution eliminates stdin redirect placement issues entirely

**Migration Pattern:**
- Remove all `bash -c` wrappers from custom modules
- Use `$(command args 2>&1)` for simple commands
- Use `Invoke-Expression $cmd` for complex quote nesting
- Use `sh -c` only for shell-specific operators (&&, ||, pipes with multiple commands)
- No need for `</dev/null` stdin redirects with direct execution

---

### **7. FIND/GREP PERFORMANCE - ALWAYS USE TIMEOUT AND DEPTH LIMITS**

**Issue Discovered:** February 9, 2026 (Session #34, V-264347)
**Symptom:** Single check function taking 830 seconds (13+ minutes), causing full scan timeout
**Root Cause:** Unbounded `grep -ri` and `find` commands recursively scanning entire filesystem with no time limit

**THE PROBLEM:**
```powershell
# ❌ WRONG - Unbounded recursive search hangs on hypervisor with many VMs/mounts:
$incidentLogs = $(find /var/log -type f -name '*audit*' 2>/dev/null)
$siemConfig = $(grep -ri 'splunk\|syslog' /etc/xo-server /opt/xo 2>/dev/null)
$breachScripts = $(find / -name '*breach*' 2>/dev/null)
# Result: 830 second execution time
```

**CORRECT IMPLEMENTATION:**
```powershell
# ✅ CORRECT - Always add timeout, maxdepth, and use find|xargs instead of grep -r:
$incidentLogs = $(timeout 5 find /var/log -maxdepth 3 -type f -name '*audit*' 2>/dev/null | head -10 2>&1)

# ✅ Replace grep -ri with find + xargs grep -l (finds matching files, not content):
$siemConfig = $(timeout 5 find /etc/xo-server /opt/xo -maxdepth 3 -type f \( -name '*.toml' -o -name '*.json' \) 2>/dev/null | xargs -r grep -l 'splunk\|syslog' 2>/dev/null | head -5 2>&1)

# ✅ Never search from / - always use specific known paths:
$breachScripts = $(timeout 5 find /opt/xo /etc/xo-server /usr/local/bin -maxdepth 3 -type f -name '*breach*' 2>/dev/null 2>&1)
# Result: <3 second execution time (97.6% improvement)
```

**Rules:**
- **Always** add `timeout 5` (or lower) to every `find` and `grep -r` command
- **Always** add `-maxdepth 3` to every `find` command (deeper is rarely needed)
- **Never** search from `/` - use specific known paths (`/var/log`, `/etc`, `/opt/xo`, `/usr`)
- **Replace** `grep -ri pattern /dir` with `find /dir -maxdepth 3 -type f | xargs -r grep -l pattern`
- **Always** pipe `find` output through `| head -N` to cap results
- XO/XCP-ng hypervisors have many mounted filesystems and VM disk paths that make unbounded searches extremely slow

**Performance Impact:**
- V-264347: 830 seconds → 3 seconds after fix
- Full scan time: 19 minutes → 4 minutes after fix

---

*Planning content removed - WebSRG module 100% complete as of February 9, 2026.*
