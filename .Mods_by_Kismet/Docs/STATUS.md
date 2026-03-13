# Quick Status Reference

## Project Overview
**XCP-ng & Xen Orchestra STIG Compliance Framework for Evaluate-STIG**

**Last Updated:** March 13, 2026 (Session #79)
**Phase:** XO + VMM 100% Complete — Dom0 RHEL7 CAT II In Progress

---

## Completion Dashboard

| Module | Functions | Implemented | EvalScore | Last Test | Status |
|--------|-----------|-------------|-----------|-----------|--------|
| **Scan-XO_WebSRG_Checks** | 126 (5 CAT I + 121 CAT II) | 126/126 | 41.27% | Test124 (Feb 11) | **100% COMPLETE** |
| **Scan-XO_ASD_Checks** | 286 (34 CAT I + 252 CAT II/III) | 286/286 | 43.36% | Test148b (Feb 18) | **100% COMPLETE** |
| **Scan-XO_GPOS_Debian12_Checks** | 198 (18 CAT I + 170 CAT II + 10 CAT III) | 198/198 | 46.46% | Test173b (Mar 1) | **100% COMPLETE** |
| **Scan-XCP-ng_VMM_Checks** | 193 (3 CAT I + 159 CAT II + 31 CAT III) | 193/193 | 34.72% | Test187b (Mar 11) | **100% COMPLETE** |
| **Scan-XCP-ng_Dom0_RHEL7_Checks** | 244 (26 CAT I + 205 CAT II + 13 CAT III) | 144/244 | 25.41% | Test198 (Mar 13) | **In Progress** — CAT II Batch 7/14 |
| **Total** | **1,047** | **803 XO+VMM + 144 Dom0** | — | — | **XO+VMM 100%, Dom0 59.0%** |

---

## XO Module Highlights

### All 3 XO Modules — 610/610 Functions Complete

- **WebSRG:** ~35,000 lines, 4-minute scan, XO REST API integration, multi-method detection
- **ASD:** ~50,000 lines, 286 functions covering application security and development
- **GPOS Debian12:** ~35,000 lines, XO Audit Plugin integration, AD/LDAP compensating controls, XOA/XOCE deployment model detection

### Key Infrastructure Built
- **XO Audit Plugin** (`Get-XOAuditPluginInfo`): 18 audit functions use XO's built-in audit as compensating control (EvalScore +9%)
- **Deployment Model Detection** (`Get-XODeploymentModel`): Distinguishes XOA (UFW default) vs XOCE (no default firewall)
- **AD/LDAP Compensating Control**: 5 PKI/certificate functions credit enterprise auth delegation
- **Answer Files**: Comprehensive 2-index entries for all 610 functions with remediation guidance

---

## XCP-ng Modules

### VMM — 100% COMPLETE
- 193/193 functions, all explicit (0 stubs), EvalScore 34.72%
- Test187b validated (Mar 11), PRs #47-58 merged
- Bash helpers in `Modules/Scan-XCP-ng_VMM_Checks/Bash_Helpers/`

### Dom0 RHEL7 — In Progress (144/244, 59.0%)
- Phase 0 remediation complete (Session #76, PR #60)
- CAT I: 26/26 complete (Session #77, PR #61)
- CAT III: 13/13 complete (Session #77, PR #62)
- CAT II: 105/205 done (Batches 1-7)
- EvalScore: 25.41%, Test198 (Mar 13)
- Remaining: 100 CAT II functions across Batches 8-14

### Key Technical Notes
- XCP-ng 8.3 is based on **RHEL 7/CentOS 7** (not RHEL 8)
- Requires PowerShell 7.3.12 (7.4+ incompatible due to glibc)
- Dom0 is headless — GNOME checks return Not_Applicable

---

## Testing Status

| Test Series | Module | Range | Latest | Result |
|-------------|--------|-------|--------|--------|
| WebSRG | XO_WebSRG | Test1–Test124 | Test124 | Exit 0, 41.27% |
| ASD | XO_ASD | Test125–Test148b | Test148b | Exit 0, 43.36% |
| GPOS Debian12 | XO_GPOS_Debian12 | Test149–Test173b | Test173b | Exit 0, 46.46% |
| XCP-ng VMM | XCP-ng_VMM | Test176–Test187b | Test187b | Exit 0, 34.72% |
| XCP-ng Dom0 | XCP-ng_Dom0_RHEL7 | Test188–Test198 | Test198 | Exit 0, 25.41% |

All scans: zero errors, zero VulnTimeouts, CKL/CKLB generation verified.

---

## File Locations

### Modules (in `Evaluate-STIG/Modules/`)
```
Scan-XO_WebSRG_Checks/          # 100% COMPLETE
Scan-XO_ASD_Checks/             # 100% COMPLETE
Scan-XO_GPOS_Debian12_Checks/   # 100% COMPLETE
Scan-XCP-ng_VMM_Checks/         # 100% COMPLETE
Scan-XCP-ng_Dom0_RHEL7_Checks/  # In progress (144/244)
```

### Answer Files (in `Evaluate-STIG/AnswerFiles/`)
```
XO_v5.x_WebSRG_AnswerFile.xml
XO_v5.x_ASD_AnswerFile.xml
XO_v5.x_GPOS_Debian12_AnswerFile.xml
XCP-ng_v8.3_VMM_AnswerFile.xml
XCP-ng_v8.3_Dom0_RHEL7_AnswerFile.xml
```

### Documentation (in `.Mods_by_Kismet/Docs/`)
```
STATUS.md                  # This file
CHANGELOG.md               # Version history
MODIFICATIONS.md           # Upstream file changes
VATES_COMPLIANCE_BLOCKERS.md  # Compliance blockers for Vates
ANSWER_FILE_DEVELOPMENT_PLAN.md  # 8 critical coding rules
XCP-ng_RHEL7_Compatibility_Issue.md  # Resolved PS compatibility issue
XO_v5.x_GPOS/             # GPOS implementation tracker and guide
XO_v5.x_WebSRG/           # WebSRG implementation trackers
XO_v5.x_ASD/              # ASD implementation plan and trackers
XCPng_v8.3_Dom0_RHEL7/    # Dom0 RHEL7 plan, guide, tracker, test logs/results
```

---

## Known Compliance Gaps (Requiring Vates Action)

| ID | Issue | Severity | Affected VulnIDs |
|----|-------|----------|------------------|
| CRYPT-001 | bcrypt not FIPS 140-2 validated | CAT I | V-206391, V-206434, V-239371 |
| TLS-001 | TLS 1.1 still enabled | CAT II | V-206439 |
| AUTH-001 | No MFA/2FA | CAT II | V-264343, V-264344 |
| BANNER-001 | No DoD consent banner | CAT II | V-222434, V-222435 |
| PWD-001 | 15-char password not enforced | CAT II | V-264351, V-264352 |

See `VATES_COMPLIANCE_BLOCKERS.md` for full details and remediation options.

---

**Status:** XO + VMM 100% Complete (803/803) | Dom0 RHEL7 84/244 (34.4%) | **Next:** Dom0 CAT II Batches 4-14
