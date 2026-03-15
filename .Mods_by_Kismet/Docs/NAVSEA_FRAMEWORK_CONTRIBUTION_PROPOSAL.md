# Proposal: Vates Virtualization Management Stack Support for Evaluate-STIG

**From:** Kismet Agbasi
**To:** NAVSEA / NIWC Atlantic — Evaluate-STIG Development Team
**Date:** March 14, 2026
**Subject:** Feature Request — Native support for Xen Orchestra and XCP-ng STIG compliance scanning

---

## Executive Summary

I am requesting that the Evaluate-STIG framework incorporate native support for the **Vates Virtualization Management Stack** — specifically **Xen Orchestra** (management console) and **XCP-ng** (Type 1 hypervisor). Vates is a commercial virtualization vendor whose products are fully open-source, offering an alternative to closed-source platforms like VMware vSphere and Microsoft Hyper-V. DoD organizations are beginning to evaluate the Vates stack as a potential replacement for legacy closed-source virtualization.

I have developed and production-tested a complete set of five custom scan modules covering **1,047 automated STIG checks** across five applicable STIGs/SRGs. The implementation required only **~375 lines of changes to four upstream framework files**, is fully backward-compatible, and has been designed from day one for upstream contribution.

This proposal outlines the work completed, the minimal upstream changes required, and the value this would provide to the broader DoD STIG compliance community.

---

## The Problem

**There are no official DISA STIGs or SCAP Benchmarks for Xen Orchestra or XCP-ng.** Organizations evaluating the Vates stack for DoD environments — whether for an IATT (Interim Authority to Test) or a full ATO (Authority to Operate) — currently have no standardized way to assess its compliance posture.

The Evaluate-STIG framework already supports VMware, Hyper-V, and other commercial virtualization platforms. Adding Vates VMS support would extend coverage to the leading open-source alternative, enabling DoD organizations to perform the same rigorous compliance assessments they apply to commercial closed-source products.

### Why This Matters Now

- **VMware licensing changes** (Broadcom acquisition, subscription-only pricing) are driving DoD organizations to evaluate alternatives to closed-source virtualization
- **XCP-ng is a mature, commercially supported Type 1 hypervisor** based on the Xen Project (same hypervisor family used by AWS), backed by Vates with enterprise support, SLA options, and a dedicated appliance (XOA)
- **Xen Orchestra provides centralized management** comparable to vCenter, including backup, replication, and multi-host orchestration
- **Multiple DoD organizations** are currently assessing Vates VMS for classified and unclassified environments, but lack the tooling to generate the STIG checklists required for their security packages

---

## What Has Been Built

### Five Complete Scan Modules

| Module | STIG/SRG Applied | Target System | Checks | EvalScore |
|--------|-----------------|---------------|--------|-----------|
| `Scan-XO_WebSRG_Checks` | Web Server SRG V4R4 | Xen Orchestra | 126 | 43.65% |
| `Scan-XO_ASD_Checks` | ASD STIG V6R4 | Xen Orchestra | 286 | 43.36% |
| `Scan-XO_GPOS_Debian12_Checks` | GPOS SRG V3R2 | XO (Debian 12) | 198 | 46.46% |
| `Scan-XCP-ng_VMM_Checks` | VMM SRG V2R2 | XCP-ng Dom0 | 193 | 34.72% |
| `Scan-XCP-ng_Dom0_RHEL7_Checks` | RHEL 7 STIG V3R15 (adapted) | XCP-ng Dom0 | 244 | 42.21% |
| **Total** | | | **1,047** | |

Every function has been individually implemented, tested, and validated. All five modules produce **zero scan errors, zero VulnTimeouts**, and generate valid **CKL, CKLB, and XCCDF output**. Over 200 framework test runs were performed during development.

### Answer Files

Five comprehensive answer files provide ISSO/ISSM guidance for every finding, using the standard 2-index pattern (ExpectedStatus = NotAFinding and ExpectedStatus = Open) with remediation comments:

- `XO_v5.x_WebSRG_AnswerFile.xml` (126 entries)
- `XO_v5.x_ASD_AnswerFile.xml` (286 entries)
- `XO_v5.x_GPOS_Debian12_AnswerFile.xml` (198 entries)
- `XCP-ng_v8.3_VMM_AnswerFile.xml` (193 entries)
- `XCP-ng_v8.3_Dom0_RHEL7_AnswerFile.xml` (244 entries)

### STIG/SRG Rationale

The five STIGs/SRGs were selected based on the architecture of the Vates stack:

**Xen Orchestra** is a Node.js web application running on Debian 12, requiring:
1. **Application Security and Development (ASD) STIG** — for the application layer (authentication, session management, input validation, error handling, cryptography)
2. **Web Server SRG** — for the HTTPS service layer (TLS configuration, access control, logging, content handling)
3. **General Purpose Operating System (GPOS) SRG** — for the underlying Debian 12 OS (account management, audit, access control, system hardening)

**XCP-ng** is a Type 1 bare-metal hypervisor based on the Xen Project, running a CentOS 7-based Dom0:
4. **Virtual Machine Manager (VMM) SRG** — for the hypervisor layer (VM isolation, resource management, privilege separation, encryption, auditing)
5. **RHEL 7 STIG** (adapted for CentOS 7 Dom0) — for the Dom0 operating system (SSH hardening, audit rules, PAM configuration, file permissions, kernel parameters)

This provides **defense-in-depth coverage** across all layers of the virtualization stack — from the host OS through the hypervisor to the management application.

---

## Upstream Framework Changes Required

The entire implementation requires modifications to only **four upstream files**, totaling approximately **400 lines of changes**. All modifications are additive and backward-compatible — no existing functionality is altered.

### 1. `Modules/Master_Functions/STIGDetection/STIGDetection.psm1`

**~40 lines changed** — Adds XCP-ng and Debian 12 OS detection.

- Added `XCPng` and `Debian12` to the `ValidateSet` for the `-Version` parameter of `Test-IsRunningOS`
- Added detection logic for XCP-ng via `/etc/os-release` parsing (`ID=xcp-ng` or `ID=xenenterprise`)
- Added detection logic for Debian 12 via `/etc/os-release` parsing (`NAME="Debian"` + `VERSION_ID="12"`)
- Added `Get-XCPngVersion` helper function for version-conditional checks

**This is the most significant upstream change**, and it follows the exact same pattern used for Oracle Linux, Ubuntu, and Amazon Linux detection already present in the file.

### 2. `Modules/Master_Functions/FormatOutput/FormatOutput.psm1`

**~20 lines changed** — Fixes a null reference during XCCDF generation.

XCP-ng systems can return null values for `IpAddress` and `MacAddress` in TargetData fields. The existing code calls `.GetType()` on these values without null-checking, causing an unhandled exception. The fix adds a null/empty check before the `.GetType()` call.

**This is a bug fix that benefits all Linux systems**, not just XCP-ng. Any system with a null network field would hit this error.

### 3. `Modules/Master_Functions/Master_Functions.psm1`

**~35 lines changed** — Two fixes for Linux asset data collection.

**Fix 1: Virtual network interface filter (~10 lines)**
Hypervisor environments (XCP-ng, KVM, etc.) create dozens of virtual bridge and tap interfaces that pollute the network adapter inventory. The fix filters `ip -4 addr` output to only include interfaces with assigned IPv4 addresses.

**Fix 2: Linux disk collection for Summary Report (~25 lines)**
The existing Linux disk collection code uses `lsblk`/`lvscan` with broken parsing — it only populates 3 of 7 disk fields (Index, DeviceID, Size) and pipes hashtable objects through `cut` commands, producing "Name Value ---- ------" garbage in the Summary Report HTML. The fix replaces this with proper `lsblk -dno NAME,SIZE,MODEL,SERIAL,TRAN,TYPE` parsing, populating all 7 fields (Index, DeviceID, Size, Caption, SerialNumber, MediaType, InterfaceType) to match the Windows CIM structure.

**Both are general improvements** that benefit any Linux system scanned by the framework, not just XCP-ng/XO targets.

### 4. `xml/STIGList.xml`

**~105 lines added** — Registers the five new STIG entries with detection codes, module references, and content hashes.

Each entry follows the exact same XML schema used by every other STIG in the file. No existing entries are modified.

### 5. `xml/FileList.xml`

**~50 lines added** — Registers the module files (.psm1, .psd1) in the file manifest for remote scanning.

---

## Why Incorporate This Into the Framework?

### 1. It Fills a Real and Growing Gap

No DISA STIGs exist for Xen Orchestra or XCP-ng. As organizations evaluate the Vates stack as an alternative to closed-source virtualization, they need standardized compliance tooling. Including this in Evaluate-STIG means every organization doing a Vates assessment uses the same checks, the same output format, and the same answer file structure — rather than each organization building their own ad-hoc solution.

### 2. Minimal Maintenance Burden

The upstream changes are small (~375 lines across 4 files), backward-compatible, and follow existing framework patterns exactly. The scan modules themselves are self-contained in their own directories and do not interact with other modules. If DISA eventually publishes official STIGs for these products, the modules can be updated or replaced without affecting the rest of the framework.

### 3. Production-Tested and Documented

This is not a proof-of-concept. All 1,047 functions have been individually implemented and validated through 200+ test iterations. Every upstream change is annotated with inline `# MODIFIED_BY` comments. A complete modifications guide documents every line changed and why.

### 4. Three of Four Framework Fixes Benefit All Users

The FormatOutput null-reference fix, the network interface filter, and the Linux Summary Report disk collection fix all benefit **any** Linux system scanned by the framework, not just XCP-ng/XO targets. These should be incorporated regardless of whether the full Vates VMS support is accepted.

### 5. Consistent Architecture

The modules use the exact same patterns as every other Evaluate-STIG module:
- Standard `Get-V######` function naming
- `GetCorpParams` / `SendCheckParams` integration
- Answer file 2-index matching
- CKL, CKLB, and XCCDF output generation
- SSH-based PSRemoting for remote execution
- Framework VulnTimeout handling

An assessor familiar with any other Evaluate-STIG module would immediately understand these.

---

## Proposed Integration Path

I see three possible approaches, in order of preference:

### Option A: Full Integration (Preferred)

Incorporate all five modules, answer files, and upstream changes into a future Evaluate-STIG release. I would provide:

- All module source code (.psm1, .psd1) ready for packaging
- All answer files (.xml) ready for the AnswerFiles directory
- Exact diffs for the four upstream file changes
- Documentation updates for the user guide

I am willing to work with the development team to adapt the code to any framework conventions or coding standards that differ from what I've followed.

### Option B: Upstream Fixes Only + Module Distribution

Incorporate only the three upstream bug fixes / improvements (FormatOutput null-check, network interface filter, STIGDetection OS additions) into the main framework. Distribute the scan modules separately as a community extension, with documentation on how to integrate them into a standard Evaluate-STIG installation.

This is already how the project works today with step-by-step integration instructions. Framework-side fixes would eliminate the need for users to manually patch Master_Functions files.

### Option C: Module Template / Extension Framework

If neither of the above fits the project's direction, I would welcome guidance on a supported extension mechanism — a way to register custom scan modules without modifying upstream files. The current architecture requires changes to STIGList.xml and FileList.xml to register new modules, and STIGDetection.psm1 to add OS detection. A plugin-style architecture would allow community-contributed modules to coexist cleanly with the official framework.

---

## Technical Details

### System Requirements

| Component | Requirement |
|-----------|-------------|
| **Xen Orchestra scanning** | SSH access to XO host (Debian 12), PowerShell 7.3+ on target |
| **XCP-ng scanning** | SSH access to Dom0, PowerShell 7.3.12 on target (7.4+ incompatible due to glibc) |
| **XCCDF files** | Already included in Evaluate-STIG StigContent (VMM SRG V2R2, RHEL 7 V3R15, GPOS V3R2, ASD V6R4, Web SRG V4R4) |
| **Scan time** | ~4 minutes for XO (3 modules), ~2.5 minutes for XCP-ng (2 modules) |

### Known Compliance Gaps (Product-Level)

These findings return Open due to product limitations, not module deficiencies. They are documented in our compliance blockers guide for inclusion in POA&Ms:

| Finding | Severity | Root Cause |
|---------|----------|------------|
| bcrypt not FIPS 140-2 validated | CAT I | XO uses bcrypt for password hashing; mitigated via LDAP/AD delegation |
| No built-in MFA/2FA | CAT II | Mitigated via LDAP + smart card integration |
| TLS 1.1 still enabled (default) | CAT II | Configurable — documented remediation steps provided |
| No DoD consent banner | CAT II | Mitigated via nginx reverse proxy or native feature request to Vates |

These are not framework issues — they represent genuine compliance gaps that assessors need to see and document. The modules correctly identify them as Open findings.

---

## Separate Feature Request: `-SSHUser` Parameter for Non-Interactive Linux Scanning

During the development and testing of these modules, I ran over 200 scans against Linux hosts (XCP-ng Dom0 and Debian 12). Every scan requires the operator to manually type the SSH username at the `Read-Host` prompt in `RemoteScan.psm1` (line 1113), even when key-based authentication is fully configured and no password is needed.

**Current behavior:**
```
Enter username to SSH to 2 Linux host(s): _
```

This prompt cannot be bypassed or pre-populated via command-line parameters. For environments scanning multiple Linux hosts on a recurring basis — especially in automated or semi-automated workflows — this is a significant usability friction point.

**Proposed enhancement:** Add an `-SSHUser` parameter (dynamic, exposed when `-ComputerName` is specified) that pre-fills the SSH username, skipping the interactive prompt:

```powershell
# Current (always prompts)
.\Evaluate-STIG.ps1 -ComputerName vmh01.domain.com,vmh02.domain.com -SelectSTIG XCP-ng_VMM

# Proposed (no prompt when -SSHUser provided)
.\Evaluate-STIG.ps1 -ComputerName vmh01.domain.com,vmh02.domain.com -SelectSTIG XCP-ng_VMM -SSHUser stigadmin
```

The implementation would be straightforward:
1. Add `-SSHUser` as a dynamic parameter in `Evaluate-STIG.ps1` (same pattern as `-AltCredential`)
2. Pass it through `$HashArguments` to `RemoteScan.psm1`
3. In `RemoteScan.psm1`, use the provided value instead of calling `Read-Host` when `-SSHUser` is present; fall back to the existing prompt when it is not

This change is fully backward-compatible — existing behavior is preserved when `-SSHUser` is omitted. It would benefit anyone scanning Linux hosts with Evaluate-STIG, not just Vates VMS users.

---

## About the Implementation

This work was performed as part of an effort to evaluate the Vates Virtualization Management Stack for use in a DoD environment. The goal is to enable the same rigorous STIG compliance assessment process that exists for VMware, Hyper-V, and other closed-source platforms already supported by Evaluate-STIG.

The modules were developed over approximately 80 working sessions spanning January through March 2026, with extensive iterative testing against production XCP-ng and Xen Orchestra systems. Development assistance was provided by GitHub Copilot and Claude Code (Anthropic), with all code reviewed and validated by me.

The complete source code, documentation, and integration guide are publicly available at:
**https://github.com/kismetgerald/Evaluate-STIG-Mods4VatesVMS**

---

## Summary

| Metric | Value |
|--------|-------|
| **Modules** | 5 (3 XO + 2 XCP-ng) |
| **Total automated checks** | 1,047 |
| **STIGs/SRGs covered** | ASD V6R4, Web SRG V4R4, GPOS V3R2, VMM SRG V2R2, RHEL 7 V3R15 |
| **Upstream files changed** | 4 (STIGDetection, FormatOutput, Master_Functions, STIGList.xml) |
| **Upstream lines changed** | ~400 (all additive, backward-compatible) |
| **Test iterations** | 200+ framework test runs |
| **Output formats** | CKL, CKLB, XCCDF — all validated |
| **EvalScores** | 34.72% — 46.46% (meaningful compliance assessment, post-QA) |

I believe this work provides significant value to the DoD STIG compliance community and would be a natural extension of Evaluate-STIG's existing platform coverage. I welcome any questions, feedback, or guidance on how to move forward.

Thank you for your consideration and for building such an excellent framework.

---

**Kismet Agbasi**
**GitHub:** https://github.com/kismetgerald/Evaluate-STIG-Mods4VatesVMS

---

*This document is UNCLASSIFIED and approved for public release.*
