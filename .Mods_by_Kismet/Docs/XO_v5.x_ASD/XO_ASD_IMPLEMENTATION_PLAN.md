# XO_ASD Module — Batch Implementation Plan

## Context

The XO_ASD module (`Scan-XO_ASD_Checks`) implements the Application Security and Development (ASD) STIG V6R4 for Xen Orchestra. The module has full stub coverage — all 286 functions exist and the framework runs without errors — but only 22 functions (7.7%) have real CLI verification. The remaining 264 return `Not_Reviewed` with placeholder text.

This plan mirrors the approach used to bring the WebSRG module from 0% → 100% (Sessions #17–35): topic-grouped batches of 8–10 functions, each validated by a framework test before moving on.

**Goal:** 286/286 functions returning `NotAFinding`, `Open`, or `Not_Applicable` — none returning `Not_Reviewed`.

---

## Current State

| Category  | Total | Stubs (Not_Reviewed) | Implemented | Notes |
|-----------|-------|----------------------|-------------|-------|
| CAT I     | 34    | 20                   | 14 (6 NF, 6 O, 2 NA) | Tracker confirmed Jan 22, 2026 |
| CAT II/III | 252  | 252                  | 0           | All return Not_Reviewed |
| **TOTAL** | **286** | **272**            | **14**      | 4.9% complete |

**VulnID range:** V-222387 through V-222673 (with V-222440 and V-222569 missing), plus V-265634
**Module file:** `Evaluate-STIG/Modules/Scan-XO_ASD_Checks/Scan-XO_ASD_Checks.psm1` (35,841 lines)
**Answer file:** `Evaluate-STIG/AnswerFiles/XO_v5.x_ASD_AnswerFile.xml` (exists)
**Export mechanism:** `Export-ModuleMember -Function Get-V*` at end of psm1 — all `Get-V######` functions are exported correctly regardless of psd1 manifest list.

**Already implemented (22 functions):**
V-222387, V-222388, V-222399, V-222400, V-222403, V-222408, V-222425, V-222430, V-222432, V-222522, V-222536, V-222542, V-222543, V-222550, V-222551, V-222554, V-222555, V-222585, V-222588, V-222589, V-222590, V-222659, V-222662
*(Note: 22 in psm1, 14 per CAT I tracker — reconcile at Phase 0 start)*

---

## New Folder and Files to Create

The **`.Mods_by_Kismet/Docs/XO_v5.x_ASD/`** folder exists. Populate it with:

| File | Purpose | When |
|------|---------|------|
| `XO_ASD_IMPLEMENTATION_PLAN.md` | This document | ✅ Done |
| `XO_ASD_IMPLEMENTATION_TRACKER_CAT_II.md` | Session-by-session progress table for all 252 CAT II functions | Phase 0 setup |
| `XO_ASD_IMPLEMENTATION_GUIDE.md` | ASD-specific patterns (reusable code blocks, check templates) | Phase 0 setup |

**Also:** Move `XO_ASD_IMPLEMENTATION_TRACKER_CAT_I.md` from `Docs/` root → `Docs/XO_v5.x_ASD/` and update the CLAUDE.md reference.

---

## Implementation Approach

### Reference Model
- All patterns from `MASTER_PROMPT_FOR_LLMs.md` (4 prompt templates: function, answer file, batch, testing)
- Full coding rules from `ANSWER_FILE_DEVELOPMENT_PLAN.md`

### 8 Critical Coding Rules (non-negotiable)
1. `$nl = [Environment]::NewLine` — no backtick escapes
2. `[char]34` for `"`, `[char]39` for `'` — no escaped quotes
3. `Get-V######` — no hyphen after V in function name
4. `$(command 2>&1)` — no `bash -c` or `sh -c` unless shell operators needed
5. `-join $nl` before regex on multi-line bash output
6. GetCorpParams requires exactly 18 parameters
7. `timeout N` + `-maxdepth N` on all find/grep commands
8. FINDING_DETAILS = automated output only; all guidance → answer file COMMENTS

### ASD-Specific Considerations
- **Target:** Xen Orchestra (Node.js/Express.js, Debian 12)
- **Config paths:** XOCE `/opt/xo/`, XOA `/etc/xo-server/`
- **API token:** `/etc/xo-server/stig/api-token`
- **VulnTimeout:** 15 minutes (same as WebSRG)
- **Primary tools:** `npm audit`, `node -e`, `grep` on source, `find` with `-maxdepth`, `openssl`, `stat`, `systemctl`
- **ASD vs WebSRG:** More organizational policy controls (→ Open + manual guidance), fewer real-time network checks, more code-level analysis

### Reusable Pattern Functions (from existing implementations)
| Pattern | Reuse From |
|---------|------------|
| Auth mechanisms detection | V-222551 |
| RBAC / file permission checks | V-222554, V-222425 |
| Firewall / network access control | V-222555 |
| Session timeout / cookie config | V-222542, V-222543 |
| Audit log directory / attribution | V-222432, V-222550 |
| TLS / cipher verification | V-222400, V-222403 |
| npm audit / vulnerability scanning | V-222585 |
| Password / PAM policy | V-222536, V-222588 |
| Data encryption / LUKS detection | V-222589, V-222430 |
| Inactivity timeout | V-222590 |

---

## Phase 0: Setup and CAT I Completion — 1–2 Sessions

**Objective:** Create folder structure, initialize tracker docs, and ensure all 34 CAT I functions return NotAFinding, Open, or Not_Applicable (not Not_Reviewed).

### 0A: Setup (first session, first 30 minutes)
1. ✅ `.Mods_by_Kismet/Docs/XO_v5.x_ASD/` folder exists
2. ✅ This plan written to `XO_ASD_IMPLEMENTATION_PLAN.md`
3. Create `XO_ASD_IMPLEMENTATION_TRACKER_CAT_II.md` with table of all 252 CAT II VulnIDs
4. Create `XO_ASD_IMPLEMENTATION_GUIDE.md` with ASD-specific code templates
5. Move `XO_ASD_IMPLEMENTATION_TRACKER_CAT_I.md` to this subfolder
6. Update CLAUDE.md doc reference
7. Run baseline module load test (`Import-Module` → confirm 286 functions)
8. Run baseline framework test (record current EvalScore baseline)

### 0B: Complete Remaining 20 CAT I Functions
Identify the 20 CAT I VulnIDs still returning Not_Reviewed (cross-reference psm1 stubs with CAT I tracker), then implement each with real CLI verification. Expected split:
- ~8 functions: technically automatable (run CLI checks, return Open or NotAFinding)
- ~12 functions: organizational policy (manual procedures documented in FINDING_DETAILS, return Open)

**Framework test after Phase 0:** All 34 CAT I must show NotAFinding/Open/NA. Capture new EvalScore baseline.

**Git:** `feature/xo-asd-phase0-cat1-completion`

---

## Phase 1: Design, Architecture & Cryptography Foundations — 3 Sessions

**VulnID range:** V-222389 through V-222430 (excluding already-implemented: V-222387, V-222388, V-222399, V-222400, V-222403, V-222408, V-222425, V-222430)
**Unimplemented in range:** ~34 functions
**ASD Topic areas:** Application design reviews, threat modeling, cryptographic algorithm selection, key management, data classification

### Batch 1 (~10 functions): V-222389 to V-222398
*Topics: Design review documentation, threat modeling, security architecture*
Mostly organizational policy → Open. Verify design docs, threat model evidence, security architecture review records.

### Batch 2 (~10 functions): V-222401, V-222402, V-222404 to V-222412
*Topics: Digital signatures, certificate management, cryptographic module selection*
Mix of technical (openssl cert checks, TLS config) and policy (approved algorithm documentation).
Reuse: V-222403 (TLS/crypto patterns), V-222400 (certificate checks)

### Batch 3 (~10 functions): V-222413 to V-222424
*Topics: Application isolation, security boundaries, interface definition*
Mix of technical filesystem checks and organizational policy.

**Git branches:** `feature/xo-asd-batch1`, `feature/xo-asd-batch2`, `feature/xo-asd-batch3`

---

## Phase 2: Access Control & Authorization — 3 Sessions

**VulnID range:** V-222426 to V-222470
**Unimplemented in range:** ~40 functions (V-222425, V-222430, V-222432 already done)
**ASD Topics:** RBAC, least privilege, privilege separation, resource access control, account management

### Batch 4 (~10 functions): V-222426 to V-222435 (skip V-222425, V-222430, V-222432)
*Topics: Privilege assignment, separation of duties, admin account controls*
Technical checks: sudo config, group membership, wheel/adm group analysis.
Reuse: V-222554 (RBAC detection), V-222555 (firewall rules)

### Batch 5 (~10 functions): V-222436 to V-222450
*Topics: Resource authorization, API access controls, object-level access enforcement*
Technical: XO API endpoint inspection, permission checks.

### Batch 6 (~10 functions): V-222451 to V-222470
*Topics: Privilege escalation prevention, non-privileged account restrictions*
Technical: sudo rules analysis, setuid file detection, capability checks.

**Git branches:** `feature/xo-asd-batch4` through `feature/xo-asd-batch6`

---

## Phase 3: Input Validation & Injection Prevention — 3 Sessions

**VulnID range:** V-222471 to V-222521
**Unimplemented in range:** ~50 functions
**ASD Topics:** SQL injection, XSS, CSRF, command injection, buffer overflow, input sanitization, output encoding

### Batch 7 (~10 functions): V-222471 to V-222481
*Topics: SQL injection prevention, parameterized queries, ORM usage*
Technical: Search XO source for raw SQL, parameterized query evidence, ORM detection (typeorm/knex).

### Batch 8 (~10 functions): V-222482 to V-222495
*Topics: XSS prevention, output encoding, CSP headers*
Technical: HTTP response header inspection (curl -sI), helmet.js detection, CSP configuration.

### Batch 9 (~10 functions): V-222496 to V-222521
*Topics: CSRF protection, command injection prevention, input validation framework*
Technical: CSRF token detection in source/config, express-validator/joi/yup library detection.

**Git branches:** `feature/xo-asd-batch7` through `feature/xo-asd-batch9`

---

## Phase 4: Audit, Logging & Non-Repudiation — 2 Sessions

**VulnID range:** V-222522 to V-222545 (V-222522, V-222536, V-222542, V-222543 already done)
**Unimplemented in range:** ~18 functions
**ASD Topics:** Audit trail completeness, log attribution, log integrity, non-repudiation

### Batch 10 (~9 functions): V-222523 to V-222535 (skip V-222522, V-222536)
*Topics: Audit record content, user attribution, event outcome logging*
Technical: Winston logger config analysis, XO audit plugin detection, systemd journal review.
Reuse: V-222550 (audit attribution patterns), V-222432 (log directory checks)

### Batch 11 (~9 functions): V-222537 to V-222545 (skip V-222542, V-222543)
*Topics: Session audit, audit log protection, log review procedures*
Technical: Log file permissions, immutable attributes, log rotation config.

**Git branches:** `feature/xo-asd-batch10`, `feature/xo-asd-batch11`

---

## Phase 5: Session Management & Authentication — 2 Sessions

**VulnID range:** V-222546 to V-222580 (V-222550, V-222551, V-222554, V-222555 already done)
**Unimplemented in range:** ~27 functions
**ASD Topics:** Session token management, MFA enforcement, credential management, authentication protocols

### Batch 12 (~10 functions): V-222546 to V-222549, V-222552, V-222553, V-222556 to V-222560
*Topics: Authentication protocol selection, credential storage, session binding*
Technical: bcrypt/scrypt detection, LevelDB inspection, auth plugin enumeration.
Reuse: V-222551, V-222542, V-222543 patterns

### Batch 13 (~10 functions): V-222561 to V-222580
*Topics: MFA configuration, token revocation, concurrent session limits*
Mostly organizational policy → Open. MFA enrollment documentation, fail2ban/rate limiting checks.

**Git branches:** `feature/xo-asd-batch12`, `feature/xo-asd-batch13`

---

## Phase 6: Data Protection & Cryptography — 2 Sessions

**VulnID range:** V-222581 to V-222600 (V-222585, V-222588, V-222589, V-222590 already done)
**Unimplemented in range:** ~16 functions
**ASD Topics:** Encryption in transit/at rest, key management, certificate lifecycle, FIPS compliance

### Batch 14 (~8 functions): V-222581 to V-222584, V-222586, V-222587, V-222591, V-222592
*Topics: Data classification, sensitive data handling, PII protection*
Technical: Config file scanning for hardcoded secrets, file permission checks.

### Batch 15 (~8 functions): V-222593 to V-222600
*Topics: Encryption key storage, cryptographic module selection, key rotation*
Technical: Private key file detection, permission checks, key storage paths.
Reuse: V-222588, V-222430 (data at rest patterns)

**Git branches:** `feature/xo-asd-batch14`, `feature/xo-asd-batch15`

---

## Phase 7: Error Handling & Configuration Management — 3 Sessions

**VulnID range:** V-222601 to V-222640
**Unimplemented in range:** ~40 functions
**ASD Topics:** Error message minimization, exception handling, baseline configuration, change management

### Batch 16 (~10 functions): V-222601 to V-222612
*Topics: Error handling patterns, debug mode detection, stack trace suppression*
Technical: NODE_ENV check, error middleware detection, debug flag inspection.

### Batch 17 (~10 functions): V-222613 to V-222625
*Topics: Configuration baseline, hardening settings, environment variable security*
Mostly organizational policy → Open. Config file analysis, environment inspection.

### Batch 18 (~10 functions): V-222626 to V-222640
*Topics: Change management evidence, configuration change control, rollback capability*
Mostly organizational policy → Open.

**Git branches:** `feature/xo-asd-batch16` through `feature/xo-asd-batch18`

---

## Phase 8: SDLC, Development Controls & Testing — 3 Sessions

**VulnID range:** V-222641 to V-222658, V-222660, V-222661, V-222663 to V-222673
**(V-222659, V-222662 already done)**
**Unimplemented in range:** ~29 functions
**ASD Topics:** Security in SDLC, developer training, peer code review, security testing evidence, static/dynamic analysis

### Batch 19 (~10 functions): V-222641 to V-222651
*Topics: Security design requirements, threat modeling evidence, architecture review*
Mostly organizational policy → Open. Evidence-based checks.

### Batch 20 (~10 functions): V-222652 to V-222665 (skip V-222659, V-222662)
*Topics: Code review, security testing, penetration testing evidence*
Mostly organizational policy → Open. Automated where npm audit / SAST tool detection is possible.
Reuse: V-222585 (npm audit pattern)

### Batch 21 (~10 functions): V-222666 to V-222673, V-265634
*Topics: Software supply chain, third-party library controls, SBOM, patch management*
Technical: npm audit, outdated package detection, node_modules scanning.

**Git branches:** `feature/xo-asd-batch19` through `feature/xo-asd-batch21`

---

## Per-Batch Workflow (Each Session)

1. **Identify functions:** List unimplemented stubs in batch range; verify rule titles against STIG XCCDF or STIGViewer
2. **Determine check type:** Technical (CLI-verifiable) vs. organizational policy (manual procedure documentation)
3. **Implement inline:** Use `implement-stig-check` skill — NO Task agents for code generation
4. **Add answer file entries:** 2 indices per function (Index 1: NotAFinding, Index 2: Open); 3 indices if Not_Applicable is possible
5. **Validate XML:** `[xml]$x = Get-Content XO_v5.x_ASD_AnswerFile.xml` — fix any escaping errors before testing
6. **Check for duplicate VulnIDs:** `grep 'Vuln ID="V-' XO_v5.x_ASD_AnswerFile.xml | sort | uniq -d`
7. **Module load test:** `Import-Module Scan-XO_ASD_Checks.psd1 -Force` → confirm 286 functions
8. **Framework test:** `.\Evaluate-STIG.ps1 -ComputerName xo1.wgsdac.net -SelectSTIG XO_ASD -Output CKL -VulnTimeout 15 -AllowIntegrityViolations`
9. **Verify COMMENTS populated:** All batch functions must have COMMENTS in CKL output
10. **Git commit and PR**

### Pass Criteria Per Batch
- Exit Code: 0
- All batch functions: NotAFinding or Open (not Not_Reviewed)
- All batch functions: COMMENTS populated in CKL
- No new errors vs previous test baseline
- XML validation passes
- EvalScore monotonically increases

---

## Testing Commands

```powershell
# 1. Module load test
Import-Module "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psd1" -Force
(Get-Module Scan-XO_ASD_Checks).ExportedCommands.Count  # Must be 286

# 2. Answer file XML validation
[xml]$af = Get-Content "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"

# 3. Duplicate VulnID check
Select-String -Path "...\XO_v5.x_ASD_AnswerFile.xml" -Pattern '<Vuln ID="V-' |
    ForEach-Object { ($_.Line -match '<Vuln ID="(V-\d+)"') | Out-Null; $matches[1] } |
    Sort-Object | Group-Object | Where-Object { $_.Count -gt 1 }

# 4. Framework test (from Evaluate-STIG folder)
.\Evaluate-STIG.ps1 -ComputerName xo1.wgsdac.net -SelectSTIG XO_ASD `
    -Output CKL -VulnTimeout 15 -AllowIntegrityViolations

# 5. Clear remote cache between tests
# ssh root@xo1.wgsdac.net "rm -rf /tmp/Evaluate-STIG_RemoteComputer"
```

---

## Git Workflow

```bash
git checkout main && git pull origin main
git checkout -b feature/xo-asd-phase0-setup

# After completing batch:
git add Evaluate-STIG/Modules/Scan-XO_ASD_Checks/Scan-XO_ASD_Checks.psm1
git add Evaluate-STIG/AnswerFiles/XO_v5.x_ASD_AnswerFile.xml
git add .Mods_by_Kismet/Docs/XO_v5.x_ASD/
git commit -m "feat: implement XO_ASD Batch N — <topic> (V-xxxxxx–V-xxxxxx)"
git push -u origin feature/xo-asd-<batch-name>
gh pr create --title "XO_ASD Batch N: <topic description>"
```

---

## Success Metrics & Progress Tracking

| Phase | Batches | Functions | Cumulative | % Complete |
|-------|---------|-----------|------------|------------|
| Phase 0: CAT I Complete | — | 34 CAT I | 34 | 11.9% |
| Phase 1: Design/Crypto | 1–3 | ~34 | ~56 | 19.6% |
| Phase 2: Access Control | 4–6 | ~30 | ~86 | 30.1% |
| Phase 3: Input Validation | 7–9 | ~30 | ~116 | 40.6% |
| Phase 4: Audit/Logging | 10–11 | ~18 | ~134 | 46.9% |
| Phase 5: Session/Auth | 12–13 | ~20 | ~154 | 53.8% |
| Phase 6: Data/Crypto | 14–15 | ~16 | ~170 | 59.4% |
| Phase 7: Error/Config | 16–18 | ~30 | ~200 | 69.9% |
| Phase 8: SDLC/Dev | 19–21 | ~30 | ~230 | 80.4% |
| Phase 9: Remaining | 22–26 | ~56 | 286 | 100.0% |

**Estimated total sessions:** ~22–26 (comparable to WebSRG's 18 sessions for 121 functions)

---

## Files to Modify

| File | Change |
|------|--------|
| `Evaluate-STIG/Modules/Scan-XO_ASD_Checks/Scan-XO_ASD_Checks.psm1` | Replace stub function bodies with CLI implementations (main work) |
| `Evaluate-STIG/AnswerFiles/XO_v5.x_ASD_AnswerFile.xml` | Add Answer entries (2–3 indices per function) |
| `.Mods_by_Kismet/Docs/XO_v5.x_ASD/XO_ASD_IMPLEMENTATION_TRACKER_CAT_II.md` | Update after each batch |
| `CLAUDE.md` (project root) | Update doc reference for moved CAT I tracker |

**Do NOT modify:**
- `Evaluate-STIG/Modules/Master_Functions/` (framework files)
- `Evaluate-STIG/xml/STIGList.xml` or `FileList.xml`
- Any module other than `Scan-XO_ASD_Checks`
