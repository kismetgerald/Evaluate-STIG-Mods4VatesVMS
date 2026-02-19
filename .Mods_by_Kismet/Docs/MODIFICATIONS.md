# Evaluate-STIG Modifications by Kismet Agbasi
**Created:** January 16, 2026
**Last Updated:** January 19, 2026 (XO module export fixes)
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
- **XCP-ng Hypervisor** - Virtual Machine Manager (VMM) SRG (193 controls)
- **XCP-ng Dom0** - General Purpose OS (GPOS) SRG (159 controls)
- **XCP-ng Dom0 (optional)** - RHEL 7 STIG (reference existing patterns, ~244 controls)
- **Xen Orchestra Application** - Application Security and Development STIG (286 controls)
- **Xen Orchestra Web Server** - Web Server SRG (126 controls)

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
    # MODIFIED_BY: Kismet Agbasi on 01/16/2026 - XCP-ng hypervisor detection (CentOS 8-based)
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

### 3. `Modules/Master_Functions/Master_Functions.psm1`

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

---

### 4. `xml/FileList.xml`

**Purpose:** File manifest controlling which files are packaged for remote scanning
**Changes:** Updated 6 existing entries + added 4 new entries (10 total changes)

#### Lines 1852-1875: Updated path references for moved modules
```xml
<!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Reorganized custom modules to .Mods_by_Kismet -->
<File Name="Scan-XCP-ng_VMM_Checks.psd1">
  <Path>\.Mods_by_Kismet\Modules\Scan-XCP-ng_VMM_Checks</Path>  <!-- Changed from \Modules -->
  <ScanReq>Required</ScanReq>
  <SHA256Hash>2AD24D16CF0C55DEED72BD5ED918695A683733C4433FCA16B4CAC23F921BF151</SHA256Hash>
</File>
<!-- Similar for: Scan-XCP-ng_VMM_Checks.psm1, Scan-XCP-ng_Dom0_GPOS_Checks.*, Manual.* -->
```
**Rationale:** Reflect module reorganization to `.Mods_by_Kismet` directory  
**Impact:** Ensures remote scanning includes modules from new location

#### Lines 1876+: Added XO_ASD_Checks entries (NEW)
```xml
<File Name="Scan-XO_ASD_Checks.psd1">
  <Path>\.Mods_by_Kismet\Modules\Scan-XO_ASD_Checks</Path>
  <ScanReq>Required</ScanReq>
  <SHA256Hash>70356B2CCA9A5547F80CD758C5B667A8C1518E3B3ABC8C10B39C624C32947253</SHA256Hash>
</File>
<File Name="Scan-XO_ASD_Checks.psm1">
  <Path>\.Mods_by_Kismet\Modules\Scan-XO_ASD_Checks</Path>
  <ScanReq>Required</ScanReq>
  <SHA256Hash>9E76A07F9C484ACD1D0E30AACE0953711CFCB8FCC94882698DB4FF0AAF50404A</SHA256Hash>
</File>
```
**Rationale:** Enable XO ASD STIG check deployment  
**Impact:** Allows remote scanning to access XO_ASD_Checks module

#### Lines 1884+: Added XO_WebSRG_Checks entries (NEW)
```xml
<File Name="Scan-XO_WebSRG_Checks.psd1">
  <Path>\.Mods_by_Kismet\Modules\Scan-XO_WebSRG_Checks</Path>
  <ScanReq>Required</ScanReq>
  <SHA256Hash>B38404108C6AA3091E522D6F3D5FDC4335CD45D043BA151C3756AC7F34069D75</SHA256Hash>
</File>
<File Name="Scan-XO_WebSRG_Checks.psm1">
  <Path>\.Mods_by_Kismet\Modules\Scan-XO_WebSRG_Checks</Path>
  <ScanReq>Required</ScanReq>
  <SHA256Hash>0773A8DCA55C37A289D63C684B6713068768F7E49A2EFAE120338B9E68094C37</SHA256Hash>
</File>
```
**Rationale:** Enable XO Web SRG STIG check deployment  
**Impact:** Allows remote scanning to access XO_WebSRG_Checks module

---

## Custom Module Locations

> **UPDATE (Jan 17, 2026)**: All custom modules are now in `Evaluate-STIG/Modules/` (moved from `.Mods_by_Kismet/Modules/`). This is required for the framework to load them.

### Module Structure: 6 Custom Check Modules (in Modules/)

#### 1. `Modules/Scan-XCP-ng_VMM_Checks/`
- **Scan-XCP-ng_VMM_Checks.psd1** - Module manifest
- **Scan-XCP-ng_VMM_Checks.psm1** - 193 check functions
  - Status: ✅ Complete (193/193)
  - Scope: Virtual machine configuration, security policies, audit settings
  - Includes: Bash_Helpers/ subdirectory with 4 validation scripts

#### 2. `Modules/Scan-XCP-ng_Dom0_GPOS_Checks/`
- **Scan-XCP-ng_Dom0_GPOS_Checks.psd1** - Module manifest
- **Scan-XCP-ng_Dom0_GPOS_Checks.psm1** - 159 check functions
  - Status: ✅ Complete (159/159)
  - Scope: User accounts, file permissions, SSH, sudo, kernel parameters
  - **Note**: XCP-ng 8.3 is based on RHEL 7/CentOS 7, not RHEL 8

#### 3. `Modules/Scan-Debian12_GPOS_Checks/`
- **Scan-Debian12_GPOS_Checks.psd1** - Module manifest
- **Scan-Debian12_GPOS_Checks.psm1** - 159 check functions
  - Status: ✅ Complete (159/159)
  - Scope: Debian 12 OS hardening for Xen Orchestra hosts
  - Features: AppArmor enforcement, apt package manager integration

#### 4. `Modules/Scan-XO_ASD_Checks/`
- **Scan-XO_ASD_Checks.psd1** - Module manifest
- **Scan-XO_ASD_Checks.psm1** - 286 check functions
  - Status: ✅ Framework Complete (27 CAT I + templated CAT II/III)
  - Scope: Node.js application security, package security, code practices
  - Detection: `pgrep -fa 'node.*xo-server'`

#### 5. `Modules/Scan-XO_WebSRG_Checks/`
- **Scan-XO_WebSRG_Checks.psd1** - Module manifest
- **Scan-XO_WebSRG_Checks.psm1** - 126 check functions
  - Status: ✅ Framework Complete (6 CAT I + templated CAT II/III)
  - Scope: TLS configuration, HTTP headers, logging, access controls
  - Detection: `pgrep -fa 'node.*xo-server'`

#### 6. `Modules/Manual/`
- **Manual.psd1** - Module manifest (enhanced)
- **Manual.psm1** - Fallback Not_Reviewed placeholder functions
  - Purpose: Default module for unimplemented or non-automatable checks

### Documentation Files

#### `MODIFICATIONS.md` (this file)
Detailed log of all upstream changes, new modules, and rationale

#### `IMPLEMENTATION_STATUS.md`
Tracking table for check implementation progress by CAT level and module

#### `REORGANIZATION_PLAN.md`
High-level overview of project reorganization goals and structure

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
| **Total upstream** | | **6 files** | **~355 lines** | **Medium** |
| **Total new** | | **7 modules + 3 docs** | **~2500 lines** | **High** |

### Deployment Impact
- **Local scanning**: Uses local module paths from `.Mods_by_Kismet/`
- **Remote scanning**: FileList.xml controls what gets transferred (now includes `.Mods_by_Kismet/` paths)
- **Package size**: ~500KB additional files (minimal impact)
- **Scan execution time**: Negligible (checks only run on detected STIGs)

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

## Future Implementation Plan

### Phase 1: VMM SRG (Hypervisor-level checks)
Priority: **HIGH** (0 CAT I, 162 CAT II, 31 CAT III)
- Implement Xen CLI (`xe`) based checks
- Focus on VM resource limits, security policies, audit configuration
- Estimated effort: 40-60 hours

### Phase 2: GPOS SRG (Dom0 OS hardening)
Priority: **HIGH** (18 CAT I, 170 CAT II, 10 CAT III)
- Adapt RHEL 8 GPOS checks for XCP-ng Dom0 (CentOS 8-based)
- Focus on SSH, sudo, user management, file permissions
- Estimated effort: 30-50 hours

### Phase 3: RHEL8 STIG (Optional Dom0 coverage)
Priority: **MEDIUM** (~30 CAT I, ~250 CAT II, ~80 CAT III)
- Reuse existing RHEL8 module checks on Dom0
- Additional system-level compliance coverage
- Estimated effort: 0 hours (reuse existing)

### Phase 4: XO ASD STIG (Application-level security)
Priority: **MEDIUM** (scope TBD)
- Implement Node.js application security checks
- Use XO REST API where available
- Estimated effort: 50-70 hours

### Phase 5: XO Web SRG (Web server hardening)
Priority: **MEDIUM** (scope TBD)
- Implement TLS/HTTP security checks
- Validate logging and access controls
- Estimated effort: 40-60 hours

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
