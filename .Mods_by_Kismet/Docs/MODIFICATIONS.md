# Evaluate-STIG Modifications by Kismet Agbasi
**Created:** January 16, 2026
**Last Updated:** March 14, 2026 (QA Phase 2 — Linux Summary Report disk fix)
**Purpose:** XCP-ng hypervisor STIG compliance scanning with Xen Orchestra application support
**Original Source:** NAVSEA Evaluate-STIG v1.2507.6
**Repository:** [https://github.com/NAVSEA/Evaluate-STIG](https://github.com/NAVSEA/Evaluate-STIG)

---

> **CRITICAL UPDATES (January 17, 2026 - Claude Code Session)**:
> 1. **Module Location Change**: All custom modules moved from `.Mods_by_Kismet/Modules/` to `Evaluate-STIG/Modules/` (required for framework to load them)
> 2. **RHEL Version Correction**: XCP-ng 8.3 is based on **RHEL 7/CentOS 7** (not RHEL 8) - RPM packages have `el7` suffix
> 3. **FileList.xml Updated**: 10 path entries changed to `\Modules\` from `\.Mods_by_Kismet\Modules\`
> 4. **PowerShell Compatibility**: XCP-ng requires PowerShell 7.3.12 (7.4+ incompatible due to glibc)

---

## Overview

This document details all modifications made to Evaluate-STIG to enable comprehensive STIG compliance scanning on XCP-ng hypervisor environments, including both the hypervisor Dom0 and Xen Orchestra management application.

### Objective
Implement complete STIG compliance checking across:
- **XCP-ng Hypervisor** - Virtual Machine Manager (VMM) SRG (204 controls) — framework baseline
- **XCP-ng Dom0** - General Purpose OS (GPOS) SRG (198 controls) — framework baseline
- **XCP-ng Dom0** - RHEL 7 STIG (244 controls) — framework baseline, needs naming remediation
- **Xen Orchestra Application** - Application Security and Development STIG (286 controls) — **100% COMPLETE**
- **Xen Orchestra Web Server** - Web Server SRG (126 controls) — **100% COMPLETE**
- **Xen Orchestra OS** - GPOS SRG for Debian 12 (198 controls) — **100% COMPLETE**

### Philosophy
- **Minimal upstream changes** - Original Evaluate-STIG files remain ~95% untouched
- **Clear attribution** - All changes marked with inline `# MODIFIED_BY: Kismet Agbasi on MM/DD/YYYY` comments
- **PR-ready diff** - Structure enables submission of Feature Request/PR to NAVSEA maintainers
- **Phased implementation** - Prioritize by CAT level (I → II → III) with automated + Not_Reviewed guidance

---

## Modified Upstream Files

### 1. `Modules/Master_Functions/STIGDetection/STIGDetection.psm1`

**Purpose:** OS detection engine; determine if STIG applies to current system  
**Changes:** Added XCP-ng hypervisor detection logic

#### Line 1049: Added XCPng to ValidateSet
```powershell
[ValidateSet("Oracle7", "Oracle8", "Oracle9", "RHEL7", "RHEL8", "RHEL9", "Ubuntu16", 
             "Ubuntu18", "Ubuntu20", "Ubuntu22", "Ubuntu24", "AL2023", "XCPng", "Debian12", ...)]
```
**Rationale:** Enable STIG selection targeting XCP-ng specifically  
**Impact:** Minimal - just adds new supported OS parameter

#### Line 1049+: Added attribution comment
```powershell
# MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCPng to ValidateSet for XCP-ng hypervisor support
```

#### Line 1163: Added XCPng case detection logic
```powershell
"XCPng" {
    # MODIFIED_BY: Kismet Agbasi on 01/16/2026 - XCP-ng hypervisor detection (CentOS 7-based for 8.x)
    If (($OSRelease -like '*ID=xcp-ng*') -or ($OSRelease -like '*ID="xcp-ng"*') -or 
        ($OSRelease -like '*ID=xenenterprise*') -or ($OSRelease -like '*ID="xenenterprise"*')) {
        $STIGRequired = $true
    }
    ElseIf ($OSRelease -like '*PLATFORM_NAME="XCP-ng"*') {
        $STIGRequired = $true
    }
}
```
**Rationale:** Handles multiple XCP-ng os-release formats (xenenterprise vs xcp-ng IDs)  
**Impact:** Detects XCP-ng 8.x and 9.x via /etc/os-release parsing

#### Line 1271+: Added Get-XCPngVersion helper function
```powershell
# MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCP-ng version detection helper function
Function Get-XCPngVersion {
    # Returns version info object: @{IsXCPng, Version, Build, IsSupported, VersionString}
}
```
**Rationale:** Enables version-conditional check execution (e.g., only run checks for 8.x or 9.x)  
**Impact:** Helper function for check modules to determine compatibility

---

### 2. `xml/STIGList.xml`

**Purpose:** Master list of all available STIGs for scanning  
**Changes:** Added 4 new STIG entries (2 existing, 2 updated module references)

#### Lines 2148-2165: XCP-ng VMM SRG entry (NEW)
```xml
<!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCP-ng VMM SRG -->
<STIG>
  <Name>Virtual Machine Manager (VMM) SRG - XCP-ng</Name>
  <ShortName>XCP-ng_VMM</ShortName>
  <StigContent>U_Virtual_Machine_Manager_SRG_V2R2_Manual-xccdf.xml</StigContent>
  <DetectionCode>Return (Test-IsRunningOS -Version XCPng)</DetectionCode>
  <PsModule>Scan-XCP-ng_VMM_Checks</PsModule>
  <PsModuleVer>1.2026.1.16</PsModuleVer>
  <Counts CATI="0" CATII="162" CATIII="31" />
  ...
</STIG>
```
**Rationale:** Enable VMM SRG scanning on XCP-ng Dom0  
**Scope:** 193 controls (0 CAT I, 162 CAT II, 31 CAT III)

#### Lines 2166-2189: XCP-ng Dom0 GPOS SRG entry (NEW)
```xml
<!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCP-ng Dom0 GPOS SRG -->
<STIG>
  <Name>General Purpose Operating System (GPOS) SRG - XCP-ng Dom0</Name>
  <ShortName>XCP-ng_Dom0_GPOS</ShortName>
  <StigContent>U_GPOS_SRG_V3R2_Manual-xccdf.xml</StigContent>
  <DetectionCode>Return (Test-IsRunningOS -Version XCPng)</DetectionCode>
  <PsModule>Scan-XCP-ng_Dom0_GPOS_Checks</PsModule>
  <PsModuleVer>1.2026.1.16</PsModuleVer>
  <Counts CATI="18" CATII="170" CATIII="10" />
  ...
</STIG>
```
**Rationale:** Enable GPOS SRG scanning for Dom0 OS hardening
**Scope:** 198 controls (18 CAT I, 170 CAT II, 10 CAT III)

#### Lines 2208-2225: XO_ASD module reference updated
```xml
<!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added Xen Orchestra ASD STIG check module -->
<STIG>
  ...
  <PsModule>Scan-XO_ASD_Checks</PsModule>        <!-- Changed from "Manual" -->
  <PsModuleVer>1.2026.1.16</PsModuleVer>         <!-- Changed from "0.0.0.0" -->
  ...
</STIG>
```
**Rationale:** Use dedicated check module instead of placeholder Manual module  
**Impact:** Enables future ASD STIG check implementation

#### Lines 2226-2245: XO_WebSRG module reference updated
```xml
<!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added Xen Orchestra Web Server SRG check module -->
<STIG>
  ...
  <PsModule>Scan-XO_WebSRG_Checks</PsModule>    <!-- Changed from "Manual" -->
  <PsModuleVer>1.2026.1.16</PsModuleVer>        <!-- Changed from "0.0.0.0" -->
  ...
</STIG>
```
**Rationale:** Use dedicated check module instead of placeholder Manual module
**Impact:** Enables future Web SRG check implementation

#### Line 2218 & 2239: XO detection method changed (MODIFIED_BY: Kismet Agbasi on 01/19/2026)
```xml
<DetectionCode>Return (Test-IsRunningOS -Version Debian12)</DetectionCode>
```
**Issue:** Bash pgrep commands don't work in PowerShell Invoke-Expression during detection phase
**Fix:** Changed to OS-based detection since XO only runs on Debian 12 systems
**Rationale:** XO is Debian 12-specific application; detection by OS is sufficient for this use case
**Impact:** XO_ASD and XO_WebSRG modules detected on all Debian 12 systems (assumes XO presence)

#### XO_ASD Module Parameter Fixes (MODIFIED_BY: Kismet Agbasi on 01/19/2026)
**Issue:** Multiple Get-V functions failed with "ParameterArgumentValidationErrorEmptyStringNotAllowed" due to incorrect parameter templates
**Fix:** Updated Get-V222555, Get-V222585, Get-V222588, Get-V222589, Get-V222590 with correct parameter blocks and variable declarations
**Root Cause:** Functions used incomplete parameter templates missing ScanType (mandatory), Instance, Database, SiteName parameters
**Impact:** XO_ASD module functions now execute properly with framework's parameter validation

#### XO Modules Bash Helper Function (MODIFIED_BY: Kismet Agbasi on 01/19/2026)
**Issue:** XO_ASD and XO_WebSRG modules failed with "unable to determine Status" because bash helper function was missing
**Fix:** Added bash filter function to both modules for shell command execution
**Root Cause:** Modules assumed bash helper function existed but it was never defined
**Impact:** XO modules can now perform required system checks using shell commands

#### V-222550 Log Search Optimization (MODIFIED_BY: Kismet Agbasi on 01/19/2026)
**Issue:** Get-V222550 (non-repudiation check) hangs when searching through many/large log files
**Fix:** Added intelligent log file filtering - limits search to <100 files and <100MB each, uses targeted find commands
**Root Cause:** Unbounded grep search across all .log files in directory, including potentially thousands of large files
**Impact:** Non-repudiation check completes quickly while still finding user attribution evidence in logs

#### XO_WebSRG Module Export Fix (MODIFIED_BY: Kismet Agbasi on 01/19/2026)
**Issue:** Potential wildcard export issues in constrained environments
**Fix:** Replaced `Export-ModuleMember -Function Get-V*` with explicit function list (9 functions)
**Impact:** XO_WebSRG module now loads reliably in all PowerShell environments

---

### 3. `Modules/Master_Functions/FormatOutput/FormatOutput.psm1`

**Purpose:** XCCDF/CKL/CKLB output generation
**Changes:** Fixed null reference during XCCDF generation for XCP-ng systems

#### Lines 1441-1461: Null reference fix (MODIFIED_BY: Kismet Agbasi on 01/18/2026)
```powershell
# Added null/empty checking before .GetType() call on TargetData fields
# XCP-ng systems may have null IpAddress/MacAddress fields
If ($null -eq $ItemValue -or $ItemValue -eq "") {
    $xmlWriter.WriteAttributeString("type", "string")
    ...
}
```
**Rationale:** XCP-ng TargetData fields (IpAddress, MacAddress) can be null, causing `.GetType()` exception
**Impact:** XCCDF generation now works for all systems including XCP-ng

---

### 4. `Modules/Master_Functions/Master_Functions.psm1`

**Purpose:** Asset data collection functions for system inventory and network information
**Changes:** Fixed Linux interface detection to prevent false positives from virtual interfaces

#### Line 2647: Fixed Linux interface enumeration (MODIFIED_BY: Kismet Agbasi on 01/19/2026)
```powershell
# MODIFIED_BY: Kismet Agbasi on 01/19/2026 - Filter for interfaces that actually have IPv4 addresses assigned
$NetAdapters = @(ip -4 addr | grep -B1 "inet " | grep "^[0-9]\+:" | awk '{print $2}' | sed 's/://')
```
**Rationale:** Prevent detection of virtual/dummy interfaces in hypervisor environments (XCP-ng, KVM, etc.)
**Impact:** Reduces false positive interfaces from 14+ to only active interfaces with real IP addresses
**Compatibility:** Works on all Linux distributions; no impact on Windows interface detection

#### Lines 1573-1598: Fixed Linux disk collection for Summary Report (MODIFIED_BY: Kismet Agbasi on 03/15/2026)
```powershell
# MODIFIED_BY: Kismet Agbasi on 03/15/2026 - Fix broken lsblk/lvscan parsing, populate all 7 disk fields
# Original code only collected 3 of 7 fields (Index, DeviceID, Size) and had broken parsing
# producing "Name Value ---- ------" garbage in Summary Report HTML.
# Fix: Use lsblk -Pdno NAME,SIZE,MODEL,SERIAL,TRAN,TYPE (pairs output with quoted values)
# to handle fields containing spaces (e.g., MODEL="QEMU DVD-ROM"), then parse KEY="VALUE" pairs
# matching the Windows CIM structure (Index, DeviceID, Size, Caption, SerialNumber, MediaType, InterfaceType)
```
**Rationale:** Linux disk data in Summary Report was malformed — only 3 fields populated, `lsblk` output parsing was broken (piping hashtables through `cut`), and `lvscan` Try/Catch path produced raw strings instead of structured data. Initial fix (v1) used whitespace splitting which broke on MODEL values containing spaces (e.g., "QEMU DVD-ROM"); v2 uses `-P` pairs output with regex KEY="VALUE" parsing.
**Impact:** Summary Report HTML now shows complete disk information on Linux systems matching the Windows 7-column table format
**Compatibility:** Linux only; no impact on Windows disk detection. Uses `lsblk -Pd` (physical disks, pairs output), available on all supported Linux distributions (util-linux 2.22+)

---

### 5. `xml/FileList.xml`

**Purpose:** File manifest controlling which files are packaged for remote scanning
**Changes:** Updated 6 existing entries + added 4 new entries (10 total changes)

#### Lines 1852+: Module file entries
All custom modules are registered in FileList.xml with paths under `\Modules\`:
- Scan-XCP-ng_VMM_Checks (.psd1, .psm1)
- Scan-XCP-ng_Dom0_RHEL7_Checks (.psd1, .psm1)
- Scan-XO_GPOS_Debian12_Checks (.psd1, .psm1)
- Scan-XO_ASD_Checks (.psd1, .psm1)
- Scan-XO_WebSRG_Checks (.psd1, .psm1)
- Manual (.psd1, .psm1)

> **Note:** Paths were initially set to `\.Mods_by_Kismet\Modules\` (Jan 16) then corrected to `\Modules\` (Jan 17) when modules were moved for framework loading. SHA256 hashes trigger integrity warnings; use `-AllowIntegrityViolations` flag.

**Impact:** Ensures remote scanning includes all custom modules

---

## Custom Module Locations

> **UPDATE (Jan 17, 2026)**: All custom modules are now in `Evaluate-STIG/Modules/` (moved from `.Mods_by_Kismet/Modules/`). This is required for the framework to load them.

### Module Structure: 6 Custom Check Modules (in Modules/)

#### 1. `Modules/Scan-XO_WebSRG_Checks/` — **100% COMPLETE**
- **126 functions** (5 CAT I + 121 CAT II), ~35,000 lines
- XO REST API integration, multi-method detection, comprehensive answer file
- Last test: Test124 — EvalScore 41.27%

#### 2. `Modules/Scan-XO_ASD_Checks/` — **100% COMPLETE**
- **286 functions** (34 CAT I + 252 CAT II/III), ~50,000 lines
- Node.js application security, code practices, session management
- Last test: Test148b — EvalScore 43.36%

#### 3. `Modules/Scan-XO_GPOS_Debian12_Checks/` — **100% COMPLETE**
- **198 functions** (18 CAT I + 170 CAT II + 10 CAT III), ~35,000 lines
- Renamed from Scan-Debian12_GPOS_Checks (Session #50)
- XO Audit Plugin integration, AD/LDAP compensating controls, XOA/XOCE detection
- Last test: Test173b — EvalScore 46.46%

#### 4. `Modules/Scan-XCP-ng_VMM_Checks/` — Framework Baseline
- **204 functions** (corrected from 193, Session #3)
- Dynamic function generation + explicit functions, 3 CAT I enhanced
- **Note**: XCP-ng 8.3 is based on RHEL 7/CentOS 7, not RHEL 8

#### 5. `Modules/Scan-XCP-ng_Dom0_RHEL7_Checks/` — Framework Baseline
- **244 functions** (26 CAT I + 205 CAT II + 13 CAT III), 12 CAT I enhanced
- Only 171/244 exported due to naming mismatch; needs Session #50-style remediation
- **Note**: Uses RHEL 7 STIG patterns for CentOS 7-based Dom0

#### 6. `Modules/Manual/`
- Fallback Not_Reviewed placeholder functions for non-automatable checks

### Documentation Files (`.Mods_by_Kismet/Docs/`)

- **MODIFICATIONS.md** (this file) — Upstream changes and module status
- **STATUS.md** — Quick status reference dashboard
- **CHANGELOG.md** — Version history
- **VATES_COMPLIANCE_BLOCKERS.md** — Compliance blockers for Vates
- **ANSWER_FILE_DEVELOPMENT_PLAN.md** — 8 critical coding rules
- **XCP-ng_RHEL7_Compatibility_Issue.md** — Resolved PS compatibility issue
- **XO_v5.x_GPOS/** — GPOS implementation tracker and guide
- **XO_v5.x_WebSRG/** — WebSRG implementation trackers
- **XO_v5.x_ASD/** — ASD implementation plan and trackers

---

## Impact Analysis

### Backward Compatibility
✅ **Fully backward compatible** - All changes are additive or isolated to new modules
- Existing STIGs unaffected
- Original Modules/ folder structure preserved for non-custom modules
- No modifications to core scanning engine (except OS detection)

### File Changes Summary
| File | Type | Changes | Lines | Impact |
|------|------|---------|-------|--------|
| STIGDetection.psm1 | Modified | 4 sections | ~20 | Low - detection logic only |
| Master_Functions.psm1 | Modified | 2 sections | ~10 | Low - interface filtering + storage |
| STIGList.xml | Modified | 4 STIG entries + 2 detection codes | ~105 | Medium - adds new STIGs + fixes detection |
| FileList.xml | Modified | 10 file entries | ~50 | Medium - path updates |
| Scan-XO_ASD_Checks.psm1 | Modified | 6 functions + bash helper | ~160 | High - parameter templates + shell execution |
| Scan-XO_WebSRG_Checks.psm1 | Modified | 1 section + bash helper | ~20 | Medium - explicit exports + shell execution |
| FormatOutput.psm1 | Modified | 1 section | ~20 | Low - null reference fix for XCCDF |
| **Total upstream** | | **7 files** | **~375 lines** | **Medium** |
| **Total new** | | **5 modules + answer files** | **~170,000 lines** | **High** |

### Deployment Impact
- **Local scanning**: Uses module paths from `Evaluate-STIG/Modules/`
- **Remote scanning**: FileList.xml controls what gets transferred to target
- **Package size**: ~5MB additional files (all 5 custom modules + answer files)
- **Scan execution time**: ~4 minutes for XO (3 modules), ~1 minute for XCP-ng (2 modules)
- **Integrity**: Use `-AllowIntegrityViolations` flag (custom modules change hashes)

---

## Verification

### Files Modified ✓
- [x] Modules/Master_Functions/STIGDetection/STIGDetection.psm1
- [x] xml/STIGList.xml
- [x] xml/FileList.xml

### Inline Comments Added ✓
- [x] STIGDetection.psm1 - 3 `# MODIFIED_BY` comments
- [x] STIGList.xml - 4 `<!-- MODIFIED_BY -->` comments
- [x] FileList.xml - 1 `<!-- MODIFIED_BY -->` comment

### New Modules Created ✓
- [x] Scan-XCP-ng_VMM_Checks (psd1 + psm1)
- [x] Scan-XCP-ng_Dom0_GPOS_Checks (psd1 + psm1) - moved from Modules/
- [x] Scan-XO_ASD_Checks (psd1 + psm1)
- [x] Scan-XO_WebSRG_Checks (psd1 + psm1)
- [x] Manual (psd1 + psm1) - moved from Modules/

### Documentation Created ✓
- [x] MODIFICATIONS.md (this file)
- [x] IMPLEMENTATION_STATUS.md (tracking table)
- [x] REORGANIZATION_PLAN.md (planning document)

---

## Implementation Status

### Completed Modules (XO — All 3 Done)

| Module | Functions | Completed | Sessions |
|--------|-----------|-----------|----------|
| XO WebSRG | 126 | Feb 11, 2026 | #17-35 |
| XO ASD | 286 | Feb 18, 2026 | #36-49 |
| XO GPOS Debian12 | 198 | Mar 1, 2026 | #50-65 |

### Remaining Work (XCP-ng)

| Module | Functions | Status | Priority |
|--------|-----------|--------|----------|
| XCP-ng VMM | 204 | Framework baseline, 3 CAT I enhanced | Next |
| XCP-ng Dom0 RHEL7 | 244 | Framework baseline, 12 CAT I enhanced, needs naming remediation | Next |

**Key XCP-ng Tasks:**
1. Dom0 RHEL7 naming remediation (Session #50-style: align function names with manifest exports)
2. VMM CAT I/II enhancement using `xe` CLI commands
3. Dom0 GPOS CAT I/II enhancement using RHEL 7 patterns
4. Answer file creation for both XCP-ng modules

---

## Contributing Changes

### To Apply These Modifications
1. Copy `.Mods_by_Kismet/` directory structure as-is
2. Apply changes to STIGDetection.psm1, STIGList.xml, FileList.xml
3. Update FileList.xml hashes if modules are modified
4. Test detection: `Test-IsRunningOS -Version XCPng` on XCP-ng system

### To Submit Upstream PR/Feature Request
1. Prepare diff showing only upstream file changes (STIGDetection.psm1, STIGList.xml, FileList.xml)
2. Include explanation of XCP-ng support additions
3. Propose new modules as optional feature/extension
4. Reference: [NAVSEA Evaluate-STIG](https://github.com/NAVSEA/Evaluate-STIG)

---

## Attribution

**Modified By:** Kismet Agbasi  
**Date:** January 16, 2026  
**Contact:** See project documentation for contact methods

All inline modifications are marked with:
```
# MODIFIED_BY: Kismet Agbasi on MM/DD/YYYY - [Brief description]
```

This enables easy tracking of changes for code review and upstream contribution.
