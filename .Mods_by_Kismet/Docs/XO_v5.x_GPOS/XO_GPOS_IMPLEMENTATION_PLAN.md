# XO_GPOS Debian 12 Module - Batch Implementation Plan

## Context

The XO_GPOS_Debian12 module (`Scan-XO_GPOS_Debian12_Checks`) implements the General Purpose
Operating System (GPOS) SRG V3R2 for the Debian 12 host running Xen Orchestra. The module has
full stub coverage - all 198 functions exist and the framework runs without errors - but all
198 return `Not_Reviewed` with placeholder text.

This plan mirrors the approach used for ASD (Sessions #36-49) and WebSRG (Sessions #17-35):
topic-grouped batches of 8-10 functions, each validated by a framework test before moving on.

**Goal:** 198/198 functions returning `NotAFinding`, `Open`, or `Not_Applicable` - none returning `Not_Reviewed`.

---

## Current State

| Category  | Total | Stubs (Not_Reviewed) | Implemented | Notes |
|-----------|-------|----------------------|-------------|-------|
| CAT I     | 18    | 0                    | 18          | Phase 1 COMPLETE (Test150c validated) |
| CAT II    | 170   | 160                  | 10          | Phase 2 Batch 1 complete (Session #53) |
| CAT III   | 10    | 10                   | 0           | Phase 3 pending |
| **TOTAL** | **198** | **170**            | **28**      | 14.1% complete |

**VulnID range:** V-203591 through V-203784 (with gaps), V-252688, V-259333, V-263650 through V-263661
**Module file:** `Evaluate-STIG/Modules/Scan-XO_GPOS_Debian12_Checks/Scan-XO_GPOS_Debian12_Checks.psm1` (~20,388 lines)
**Answer file:** `Evaluate-STIG/AnswerFiles/XO_v5.x_GPOS_Debian12_AnswerFile.xml` (198 stub entries)
**Export mechanism:** `Export-ModuleMember -Function Get-V*` at end of psm1

---

## Critical Defects (Phase 0 Must-Fix)

### Defect 1: Function Naming Convention (CRITICAL)

**Issue:** All 198 functions use `Function Get-V-######` (WITH hyphen after V).
**Required:** `Function Get-V######` (NO hyphen) per coding rule #3.
**Impact:** Framework exports use `Get-V*` glob pattern. Hyphenated names still match the glob,
but the answer file uses non-hyphenated VulnIDs, causing potential mismatches.
**Fix:** Rename all 198 functions: `Get-V-XXXXXX` to `Get-VXXXXXX`.

### Defect 2: PSD1 Manifest VulnID Mismatch (CRITICAL)

**Issue:** The `.psd1` manifest exports 159 functions in the `V-254xxx` range (e.g., `Get-V254317`),
but the `.psm1` defines functions in the `V-203xxx`/`V-252xxx`/`V-259xxx`/`V-263xxx` ranges.
The PSD1 export list is from a completely different STIG.
**Impact:** The `Export-ModuleMember -Function Get-V*` line at the end of the psm1 overrides the
psd1 exports, so functions still load correctly. However, the psd1 should be corrected.
**Fix:** Regenerate the psd1 FunctionsToExport list to match actual psm1 function names,
OR remove FunctionsToExport from psd1 (since Export-ModuleMember handles it).

### Defect 3: Missing Parameter Declarations (HIGH)

**Issue:** All 198 stub functions are missing `$Username`, `$UserSID`, `$Hostname` parameters.
**Impact:** Framework passes these parameters to all check functions. Missing declarations
cause parameter binding errors during remote SSH execution (10+ minute hangs per function).
**Fix:** Add all three parameters to every function's param block.

### Defect 4: STIGList.xml CAT Counts Wrong (MEDIUM)

**Issue:** STIGList.xml entry shows `CATI="0" CATII="152" CATIII="8"` (total 160).
**Actual XCCDF:** 18 CAT I, 170 CAT II, 10 CAT III (total 198).
**Impact:** Informational only - does not affect scan execution.
**Fix:** Update to `CATI="18" CATII="170" CATIII="10"`.

### Defect 5: DiscussMD5 Placeholder Length (LOW)

**Issue:** All stubs use a 33-character placeholder for DiscussMD5 instead of 32 characters.
**Impact:** Cosmetic - does not affect scan execution. Will be replaced with real hashes.
**Fix:** Will be corrected when implementing functions (header hash scripts handle this).

---

## Phase 0: Module Remediation - 1 Session

**Objective:** Fix all critical defects so the module passes a clean baseline framework test.

### 0A: Function Naming Fix
1. Create Python script to rename all 198 functions: `Get-V-######` to `Get-V######`
2. Verify function count after rename (should still be 198 + helpers)
3. Verify `Export-ModuleMember -Function Get-V*` still works

### 0B: PSD1 Manifest Fix
1. Regenerate FunctionsToExport list from actual psm1 function names
2. Or: Remove FunctionsToExport and rely on Export-ModuleMember

### 0C: Parameter Fix
1. Create Python script to add `$Username`, `$UserSID`, `$Hostname` to all 198 param blocks
2. Verify all 198 functions have 9 parameters (ScanType, AnswerFile, AnswerKey, Username, UserSID, Hostname, Instance, Database, SiteName)

### 0D: STIGList.xml Fix
1. Update CAT counts: `CATI="18" CATII="170" CATIII="10"`

### 0E: Baseline Test
1. Run framework scan on xo1.wgsdac.net
2. Verify: Exit code 0, all 198 functions execute, 0 errors
3. Record baseline EvalScore (should be 0% - all Not_Reviewed)

**Phase 0 Status:** COMPLETE (Test149 validated - Exit 0, EvalScore 0%, all 198 functions execute)

---

## Phase 1: CAT I Implementation - COMPLETE

**Objective:** All 18 CAT I functions return NotAFinding, Open, or Not_Applicable.
**Status:** COMPLETE (Test150c validated - Exit 0, EvalScore 4.04%, 18/18 CAT I implemented)
**Results:** 7 NotAFinding, 10 Open, 1 Not_Applicable
**Sessions:** #50 (Phase 0), #51 (CAT1-A+B), #52 (CAT1-C + answer file fixes)

### CAT I VulnIDs (18 functions)

| Vuln ID | STIG ID | Rule Title (abbreviated) | Topic |
|---------|---------|-------------------------|-------|
| V-203603 | SRG-OS-000033 | DoD-approved encryption for remote access | SSH/TLS |
| V-203629 | SRG-OS-000073 | Store only encrypted passwords | /etc/shadow hashing |
| V-203630 | SRG-OS-000074 | Transmit only encrypted passwords | SSH/TLS |
| V-203653 | SRG-OS-000125 | Strong authenticators for nonlocal maintenance | SSH keys/MFA |
| V-203669 | SRG-OS-000250 | Cryptographic integrity of audit tools | auditd integrity |
| V-203682 | SRG-OS-000278 | Cryptographic integrity of transmitted info | TLS config |
| V-203695 | SRG-OS-000324 | Prevent nonprivileged users from executing privileged functions | sudo/RBAC |
| V-203720 | SRG-OS-000366 | Prevent unauthorized patch/update installation | apt config |
| V-203736 | SRG-OS-000393 | Cryptographic integrity of nonlocal maintenance | SSH ciphers |
| V-203737 | SRG-OS-000394 | Cryptographic confidentiality of nonlocal maintenance | SSH ciphers |
| V-203739 | SRG-OS-000396 | NSA-approved cryptography for classified info | FIPS mode |
| V-203745 | SRG-OS-000404 | Cryptographic mechanisms prevent unauthorized disclosure | FIPS/TLS |
| V-203746 | SRG-OS-000405 | Cryptographic mechanisms prevent unauthorized modification | FIPS/TLS |
| V-203748 | SRG-OS-000423 | Protect confidentiality/integrity of transmitted info | TLS enforcement |
| V-203749 | SRG-OS-000424 | Cryptographic mechanisms prevent unauthorized disclosure of transmitted info | TLS ciphers |
| V-203776 | SRG-OS-000478 | NIST FIPS-validated cryptography | FIPS 140-2 |
| V-203782 | SRG-OS-000480 | No unattended/automatic logon | Auto-login check |
| V-252688 | SRG-OS-000481 | Protect confidentiality/integrity of communications | TLS enforcement |

### CAT I Batch Organization

**Batch CAT1-A: Cryptography & FIPS (10 functions)**
V-203603, V-203630, V-203682, V-203736, V-203737, V-203739, V-203745, V-203746, V-203748, V-203749

Common pattern: SSH cipher/TLS verification, FIPS mode check, openssl s_client testing

**Batch CAT1-B: Authentication & Access Control (5 functions)**
V-203629, V-203653, V-203695, V-203720, V-203782

Common pattern: /etc/shadow analysis, sudo config, SSH key auth, auto-login detection

**Batch CAT1-C: Audit & Communications (3 functions)**
V-203669, V-203776, V-252688

Common pattern: auditd integrity, FIPS validation, TLS enforcement

---

## Phase 2: CAT II Implementation - 8-12 Sessions

**Objective:** All 170 CAT II functions return NotAFinding, Open, or Not_Applicable.

### Batch Organization by Topic

**Batch 1: Account Management (10 functions)**
V-203591, V-203592, V-203593, V-203594, V-203648, V-203652, V-203666, V-203667, V-203668, V-203690
*Topics: Account provisioning, temp accounts, account auditing, disabling inactive accounts*

**Batch 2: Authentication & Login (10 functions)**
V-203595, V-203596, V-203597 (CAT III), V-203598, V-203599, V-203600, V-203601, V-203635, V-203665, V-203779
*Topics: DoD login banner, session lock, screen saver, inactivity timeout, logon delay*

**Batch 3: Password Policy (10 functions)**
V-203625, V-203626, V-203627, V-203628, V-203631, V-203632, V-203634, V-203676, V-203778, V-263653
*Topics: Complexity (upper/lower/numeric/special), change %, min/max age, min length, dictionary*

**Batch 4: SSH Configuration (10 functions)**
V-203602, V-203636, V-203637, V-203638, V-203686, V-203687, V-203688, V-203689, V-203727, V-203728
*Topics: SSH monitoring, access restrictions, non-essential capabilities, wireless, MFA, PIV*

**Batch 5: Audit System - Rules (10 functions)**
V-203604, V-203605, V-203606, V-203607, V-203608, V-203609, V-203610, V-203619, V-203670, V-203697
*Topics: Audit record content (what/when/where/who/outcome), audit at startup, privileged functions*

**Batch 6: Audit System - Management (10 functions)**
V-203611, V-203613, V-203614, V-203615, V-203616, V-203617, V-203618, V-203620, V-203672, V-203673
*Topics: Audit failure alerts, centralized review, time stamps, audit info protection, audit tools*

**Batch 7: Audit System - Events (10 functions)**
V-203674, V-203759, V-203760, V-203761, V-203762, V-203763, V-203764, V-203765, V-203766, V-203767
*Topics: Audit tool deletion protection, security-relevant event auditing (various categories)*

**Batch 8: Audit System - Advanced (10 functions)**
V-203768, V-203769, V-203770, V-203771, V-203772, V-203773, V-203774, V-203775, V-203777, V-263658
*Topics: Privileged activities, kernel module auditing, concurrent logons, direct access, maintenance tools*

**Batch 9: PKI & Certificates (10 functions)**
V-203622, V-203623, V-203624, V-203639, V-203640, V-203641, V-203642, V-203643, V-203644, V-203729
*Topics: Certificate validation, authorized access, identity mapping, MFA (local/network), PIV*

**Batch 10: Access Control & Privilege (10 functions)**
V-203645, V-203646, V-203647, V-203650, V-203655, V-203656, V-203696, V-203718, V-203719, V-203722
*Topics: Replay-resistant auth, peripheral ID, user/function separation, isolation, deny-all policy*

**Batch 11: System Configuration (10 functions)**
V-203649, V-203657, V-203658, V-203659, V-203660, V-203661, V-203663, V-203664, V-203683, V-203684
*Topics: Cryptographic mechanisms, info transfer, excess capacity, session termination, fail-safe, error msgs*

**Batch 12: System Security (10 functions)**
V-203685, V-203691, V-203692, V-203693, V-203694, V-203698, V-203699, V-203703, V-203709, V-203710
*Topics: Logoff message, admin notifications, privilege delegation, account lockout, audit integrity*

**Batch 13: Time, Patching & Software (10 functions)**
V-203711, V-203712, V-203713, V-203715, V-203716, V-203717, V-203721, V-203750, V-203751, V-259333
*Topics: NTP sync, time stamps, dual authorization, software installation, baseline config, updates*

**Batch 14: Kernel & Memory Protection (10 functions)**
V-203723, V-203724, V-203725, V-203730, V-203731, V-203733, V-203734, V-203735, V-203738, V-203744
*Topics: Re-auth for escalation/role change/authenticator change, endpoint auth, cached auth, PKI CRL, audit maintenance*

**Batch 15: Hardening, Permissions & Firewall (10 functions)**
V-203747, V-203752, V-203753, V-203754, V-203755, V-203756, V-203757, V-203758, V-203780, V-203781
*Topics: DoS protection, predictable behavior, NX/DEP, ASLR, removed components, security function verification, permissions*

**Batch 16: Remaining & Compliance (10 functions)**
V-203783, V-203784, V-263650, V-263651, V-263652, V-263654, V-263655, V-263656, V-263657, V-263659
*Topics: Privilege grants, firewall, disabled accounts, unauthorized hardware, MFA, password change, trust anchors*

**Batch 17: Final (10 functions)**
V-203651, V-203671, V-203675, V-203677, V-203678, V-203679, V-203680, V-203681, V-263660, V-263661
*Topics: Audit reduction, event source, software privilege limits, system failure preservation, admin notifications, key storage, clock sync*

---

## Phase 3: CAT III Implementation - 1 Session

**Objective:** All 10 CAT III functions return NotAFinding, Open, or Not_Applicable.

### CAT III VulnIDs (10 functions)

| Vuln ID | Rule Title (abbreviated) | Topic |
|---------|-------------------------|-------|
| V-203597 | Limit concurrent sessions to 10 | PAM limits |
| V-203700 | Audit storage capacity (1 week min) | Disk space |
| V-203701 | Offload audit records | rsyslog/remote |
| V-203702 | Notify SA/ISSO on audit failure | auditd action |
| V-203704 | Audit reduction - on-demand | aureport |
| V-203705 | Audit reduction - after-the-fact | aureport |
| V-203706 | Report generation - on-demand | aureport |
| V-203707 | Report generation - after-the-fact | aureport |
| V-203708 | Report generation - after-the-fact (alt) | aureport |
| V-203714 | Time stamps mappable to UTC | chronyd/NTP |

---

## Per-Batch Workflow

For each batch:

1. **Create feature branch** (if not already on one): `git checkout -b feature/xo-gpos-<phase>`
2. **Read XCCDF** check content for each VulnID
3. **Implement functions** inline (NO subagents for code)
4. **Create answer file entries** (2 indices per function: NotAFinding + Open)
5. **Validate XML**: `[xml]$xml = Get-Content 'AnswerFile.xml'`
6. **Check for duplicate VulnIDs**: `grep -E '^\s*<Vuln ID="V-' AnswerFile.xml | sort | uniq -d`
7. **Commit** to feature branch
8. **User runs framework test** on xo1.wgsdac.net
9. **Verify** COMMENTS populated for all functions in CKL
10. **Update tracker** with test results
11. **Commit test results** to branch

---

## Testing Commands

```powershell
# Clean remote temp files (user runs before each test)
ssh root@xo1.wgsdac.net "rm -rf /tmp/Evaluate-STIG*"

# Framework test (from workstation)
cd "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG"
.\Evaluate-STIG.ps1 -ComputerName xo1.wgsdac.net -SelectSTIG "XO_GPOS_Debian12" -Output Console -AllowIntegrityViolations -VulnTimeout 15

# Full XO scan (all 3 modules)
.\Evaluate-STIG.ps1 -ComputerName xo1.wgsdac.net -SelectSTIG "Debian12","XO_ASD","XO_WebSRG" -Output Console -AllowIntegrityViolations -VulnTimeout 15
```

---

## Git Workflow

```bash
# Start Phase 0
git checkout main && git pull origin main
git checkout -b feature/xo-gpos-phase0-remediation

# After Phase 0 validated:
# Push, PR, merge to main

# Start Phase 1
git checkout main && git pull origin main
git checkout -b feature/xo-gpos-cat1

# After Phase 1 validated:
# Push, PR, merge to main

# Phases 2-3 follow same pattern with descriptive branch names
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Phase 0 complete | All defects fixed, baseline test passes, exit code 0 |
| Phase 1 complete | 18/18 CAT I return definitive status |
| Phase 2 complete | 170/170 CAT II return definitive status |
| Phase 3 complete | 10/10 CAT III return definitive status |
| Final | 198/198 functions automated, EvalScore reflects actual compliance |

---

## Estimated Timeline

| Phase | Sessions | Functions | Cumulative |
|-------|----------|-----------|------------|
| Phase 0 | 1 | 0 (remediation) | 0/198 (0%) |
| Phase 1 | 2-3 | 18 CAT I | 18/198 (9.1%) |
| Phase 2 | 8-12 | 170 CAT II | 188/198 (94.9%) |
| Phase 3 | 1 | 10 CAT III | 198/198 (100%) |
| **Total** | **12-17 sessions** | **198** | **100%** |

---

## Key Differences from ASD/WebSRG Modules

| Aspect | ASD/WebSRG | GPOS |
|--------|-----------|------|
| Target | XO application (Node.js) | Debian 12 OS |
| Primary tools | npm, config.toml, curl, XO API | dpkg, sysctl, auditctl, sshd -T, PAM |
| Config paths | /opt/xo/, /etc/xo-server/ | /etc/ssh/, /etc/pam.d/, /etc/audit/ |
| Deployment models | XOCE vs XOA | Same OS for both |
| CAT I count | 34 (ASD), 5 (WebSRG) | 18 |
| Org policy checks | ~40% of rules | ~20% of rules (more are CLI-checkable) |
| Code reuse | XO API, npm, Express.js patterns | Standard Linux CLI patterns |
| Expected NF rate | ~40-50% | ~50-60% (more automation possible) |
