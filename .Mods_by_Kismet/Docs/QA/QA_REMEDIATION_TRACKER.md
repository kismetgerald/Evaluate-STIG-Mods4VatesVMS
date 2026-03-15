# QA Remediation Tracker

**Created:** March 14, 2026
**Purpose:** Track progress of QA remediation across all 5 modules and answer files
**Plan:** `.claude/plans/qa-remediation-plan.md`
**Branch:** `feature/qa-remediation-phase1`

---

## Phase 1: Answer File Fixes

### 1A: WebSRG Answer File (13 VulnIDs + normalization)

| VulnID | Issue | Fix | Status | Session |
|--------|-------|-----|--------|---------|
| V-206351 | Missing Index 2 | Add Index 2 (Open) | DONE | #81 |
| V-206352 | Missing Index 2 + empty statuses | Add Index 2 (Open), fix statuses | DONE | #81 |
| V-206353 | Missing Index 2 + empty statuses | Add Index 2 (Open), fix statuses | DONE | #81 |
| V-206390 | Missing Index 2 | Add Index 2 (NotAFinding) | DONE | #81 |
| V-206399 | Missing Index 2 | Add Index 2 (Open) | DONE | #81 |
| V-206431 | Missing Index 2 | Add Index 2 (NotAFinding) | DONE | #81 |
| V-206434 | Missing Index 2 | Add Index 2 (Open) | DONE | #81 |
| V-264348 | Missing Index 2 | Add Index 2 (NotAFinding) | DONE | #81 |
| V-264360 | Missing Index 2 + empty statuses | Add Index 2 (Open), fix statuses | DONE | #81 |
| V-264361 | Missing Index 2 + empty statuses | Add Index 2 (Open), fix statuses | DONE | #81 |
| V-279029 | Missing Index 2 | Add Index 2 (Open) | DONE | #81 |
| V-206389 | Extra Index 3 | Remove Index 3 | DONE | #81 |
| V-264357 | Extra Index 3 + Not_Reviewed Idx1 | Remove Index 3, fix Idx1 to NotAFinding | DONE | #81 |
| (all 126) | Mixed NF/O format | Normalize to NotAFinding/Open (85 NF + 79 O + 1 NA) | DONE | #81 |

**Script:** `.Mods_by_Kismet/Docs/QA/fix_websrg_answerfile.py`
**Result:** 126/126 VulnIDs now have exactly 2 Answer entries, 0 shorthand statuses

### 1B: ASD Answer File (~133 fixes)

| Issue Category | Count | Fix | Status | Session |
|----------------|-------|-----|--------|---------|
| Missing attributes | 68 | Add Hostname/Instance/Database/Site/ResultHash="" | DONE | #81 |
| Index 3 entries (Not_Applicable) | 18 | Remove Index 3 | DONE | #81 |
| Index 3 entries (V-222413-416, V-222421) | 5 | Remove Index 3, consolidate to NF/Open | DONE | #81 |
| Missing Index 2 | 42 | Add Index 2 (opposite status) | DONE | #81 |

**Script:** `.Mods_by_Kismet/Docs/QA/fix_asd_answerfile.py`
**Result:** 286/286 VulnIDs now have exactly 2 Answer entries, 0 missing attributes

### 1C: GPOS Debian12 Answer File (2 VulnIDs)

| VulnID | Issue | Fix | Status | Session |
|--------|-------|-----|--------|---------|
| V-203719 | Index 1/2 ExpectedStatus swapped | Swapped: Idx1=NF, Idx2=Open | DONE | #81 |
| V-203722 | Index 1/2 ExpectedStatus swapped | Swapped: Idx1=NF, Idx2=Open | DONE | #81 |

**Method:** Direct edit (2 VulnIDs only)
**Result:** Both VulnIDs now follow standard pattern (Index 1=NotAFinding, Index 2=Open)

### 1D: VMM Answer File (1 VulnID)

| VulnID | Issue | Fix | Status | Session |
|--------|-------|-----|--------|---------|
| V-207467 | Missing Index 2 | Add Index 2 (NotAFinding) | DONE | #81 |

**Method:** Direct edit (1 VulnID only)
**Result:** V-207467 now has 2 Answer entries (Index 1=Open, Index 2=NotAFinding)

### 1E: Dom0 RHEL7 Answer File

No fixes needed. 7 Index 3 entries are legitimate (BIOS/UEFI, GNOME present/absent).

---

## Phase 2: Rule 4 -- Remove sh -c / bash -c Wrappers

| Module | Violations | Fix Method | Status | Test | Session |
|--------|-----------|------------|--------|------|---------|
| Dom0 RHEL7 | 20 | Unwrap sh -c (awk, rpm, grep) | DONE | -- | #81 |
| VMM | 73 | Unwrap sh -c (test, grep, openssl, config) | DONE | -- | #81 |
| GPOS Debian12 | 187 | 2 variable-based + 184 standard unwraps (1 comment remains) | DONE | -- | #81 |
| ASD | 638 | Remove bash filter + 28 var-based + 42 literal + 482 standard + 9 curl + 2 xargs->foreach | DONE | -- | #81 |
| WebSRG | 583 | 55 var-based + 308 bash + 42 sh + 110 bare bash + 31 bare bash sq + 38 bare sh (1 comment remains) | DONE | -- | #81 |
| **TOTAL** | **1,501** | | **DONE** | | |

**Scripts:** `fix_rule4_dom0.py`, `fix_rule4_vmm.py`, `fix_rule4_gpos.py`, `fix_rule4_asd.py`, `fix_rule4_asd_remaining.py`, `fix_rule4_websrg.py`

---

## Phase 3: Rule 1 -- Replace backtick-n with $nl

| Module | Violations | Fix Method | Status | Test | Session |
|--------|-----------|------------|--------|------|---------|
| WebSRG | 1,152 | Script (1,149) + 3 manual (nested $() subexpressions) | DONE | -- | #81 |
| ASD | 317 | Script (all 317) | DONE | -- | #81 |
| VMM | 168 | Script (all 168) | DONE | -- | #81 |
| **TOTAL** | **1,637** | 66 $nl declarations added | **DONE** | | |

**Script:** `fix_rule1_backtick_n.py`
**Note:** GPOS and Dom0 already clean (0 backtick-n violations)

---

## Phase 4: Rule 7 -- Add timeout+maxdepth to find Commands

| Module | Violations | Fix Method | Status | Test | Session |
|--------|-----------|------------|--------|------|---------|
| WebSRG | 48 | Add timeout 10 + maxdepth 5 | DONE | -- | #81 |
| ASD | 14 | Add timeout 10 + maxdepth 5 | DONE | -- | #81 |
| Dom0 RHEL7 | 4 | Add timeout 10 (maxdepth already present) | DONE | -- | #81 |
| GPOS Debian12 | 2 | Add maxdepth 5 (timeout already present) | DONE | -- | #81 |
| **TOTAL** | **68** | | **DONE** | | |

**Script:** `fix_rule7_find_timeout.py`
**Note:** VMM already clean (0 find violations)

---

## Phase 5: Minor Fixes

| Module | Issue | Fix | Status | Session |
|--------|-------|-----|--------|---------|
| WebSRG | 1 corrupted quote (line 25693, node -e) | Rewrote with single-quoted require('crypto') | DONE | #81 |
| GPOS | 1 escaped-quote awk (line 9492) | Single-quoted awk pattern | DONE | #81 |
| GPOS | 1 corrupted awk (line 34987, from Phase 2) | Rewrote with single-quoted awk pattern | DONE | #81 |
| ASD | 12 escaped-quote grep/tr patterns | Single-quoted grep -oP and tr -d patterns | DONE | #81 |
| VMM PSD1 | Stale comment ("14 explicit + 179 stubs") | Updated to "all explicit" | DONE | #81 |
| ASD | bash filter function (lines 30-39) | Removed (covered by Phase 2) | DONE | #81 |

---

## Phase 6: Regression Testing

| Target | Modules | Baseline EvalScore | Post-QA EvalScore | Test # | Status | Session |
|--------|---------|-------------------|-------------------|--------|--------|---------|
| xo1.wgsdac.net | WebSRG | 41.27% | -- | Test206-209 FAIL / Test210 pending | Phase 6A-6G fixes applied | #81 |
| xo1.wgsdac.net | ASD | 43.36% | -- | Test206-209 FAIL / Test210 pending | Phase 6A-6G fixes applied | #81 |
| xo1.wgsdac.net | GPOS Debian12 | 46.46% | 46.46% | Test208 PASS | DONE | #81 |
| vmh01.wgsdac.net | VMM | 34.72% | 35.23% | Test207-208 PASS | DONE | #81 |
| vmh01.wgsdac.net | Dom0 RHEL7 | 42.21% | 42.62% | Test208 PASS | DONE | #81 |

### Phase 6A: Fix Duplicate Stderr Redirections (Test206 Regression)

**Root cause:** Phase 2 sh -c removal scripts added `2>&1` to commands that already had `2>/dev/null`, creating `2>/dev/null 2>&1` — PowerShell ParserError "StreamAlreadyRedirected".

| Module | Violations | Fix | Status | Session |
|--------|-----------|-----|--------|---------|
| GPOS Debian12 | 45 | `2>/dev/null 2>&1` → `2>/dev/null` (replace_all) | DONE | #81 |
| ASD | 29 | `2>/dev/null 2>&1` → `2>/dev/null` (replace_all) | DONE | #81 |
| WebSRG | 52 | `2>/dev/null 2>&1` → `2>/dev/null` (replace_all) | DONE | #81 |
| **TOTAL** | **126** | | **DONE** | |

### Phase 6B: Fix Shell While-Loop in VMM (Test206 Regression)

**Root cause:** Phase 2 unwrapped `sh -c` around a `while read u; do ... done` shell loop — PowerShell `do` keyword causes "MissingLoopStatement" ParserError.

| Module | Line | Fix | Status | Session |
|--------|------|-----|--------|---------|
| VMM | 28113 | Rewrote shell while-loop as PowerShell foreach (get user list, iterate with passwd -S) | DONE | #81 |

### Phase 6C: Fix Duplicate `2>&1 2>&1` Redirections (Test207 Regression)

**Root cause:** Phase 2 added `2>&1` to commands already having `2>&1` in piped contexts, creating `2>&1 2>&1`.

| Module | Violations | Fix | Status | Session |
|--------|-----------|-----|--------|---------|
| ASD | 4 | `2>&1 2>&1` → `2>&1` (replace_all) | DONE | #81 |
| WebSRG | 79 | `2>&1 2>&1` → `2>&1` (replace_all) | DONE | #81 |
| **TOTAL** | **83** | | **DONE** | |

### Phase 6D: Fix Bare Command Calls — CommandNotFoundException (Test207 Regression)

**Root cause:** Phase 2 unwrapped `sh -c 'auditctl ...'` / `sh -c 'iptables ...'` etc. to bare commands. When command doesn't exist on target, PowerShell throws CommandNotFoundException before pipe can execute. Fix: wrap with `timeout 5` (which always exists).

| Module | Command | Instances | Fix | Status | Session |
|--------|---------|-----------|-----|--------|---------|
| GPOS | auditctl | 5 | Add `timeout 5` prefix | DONE | #81 |
| GPOS | iptables | 3 | Add `timeout 5` prefix | DONE | #81 |
| GPOS | ufw | 3 | Add `timeout 5` prefix | DONE | #81 |
| GPOS | getenforce | 1 | Add `timeout 5` prefix | DONE | #81 |
| ASD | ufw | 1 | Add `timeout 5` prefix | DONE | #81 |
| ASD | iptables | 1 | Add `timeout 5` prefix | DONE | #81 |
| ASD | getenforce | 1 | Add `timeout 5` prefix | DONE | #81 |
| WebSRG | ufw | 3 | Add `timeout 5` prefix | DONE | #81 |
| WebSRG | iptables | 4 | Add `timeout 5` prefix | DONE | #81 |
| WebSRG | getenforce | 1 | Add `timeout 5` prefix | DONE | #81 |
| **TOTAL** | | **23** | | **DONE** | |

### Phase 6E: Fix Mangled node -e Commands + .Trim() on Char (Test207 Regression)

| Module | Line | Issue | Fix | Status | Session |
|--------|------|-------|-----|--------|---------|
| ASD | 27377 (×2) | Mangled `node -e " + [char]34 + "..."` string | Extract to `$nodeScript` variable, pass to node -e | DONE | #81 |
| ASD | 24983 (×2) | Escaped-quote grep pattern (missed in Phase 5) | Single-quoted grep -oP pattern | DONE | #81 |
| WebSRG | 13240 | Mangled `node -e " + [char]34 + "..."` | Extract to `$nodeScript` variable | DONE | #81 |
| Dom0 | 9358 | `.Trim()` on `[System.Char]` (single result → not array) | Wrap in `@()` to force array | DONE | #81 |

### Phase 6F: Fix Shell if/then/fi Constructs — MissingOpenParenthesisInIfStatement (Test208 Regression)

**Root cause:** Phase 2 unwrapped `sh -c 'if [ -f FILE ]; then CMD; fi'` to bare `$(if [ -f FILE ]; then CMD; fi)`. PowerShell parses `if` as its own keyword (requires `(condition)` not `[ -f FILE ]`).

**Fix:** Convert all `$(if [ ... ]; then CMD; fi)` to `$(test -f ... && CMD)` / `$(test -f ... && CMD || CMD2)`.

| Module | Violations | Fix | Status | Session |
|--------|-----------|-----|--------|---------|
| ASD | 6 | `if/then/else/elif/fi` → `test && ... \|\| ...` | DONE | #81 |
| WebSRG | 18 | `if/then/fi` → `test && ...` (simple + elif + multi-if) | DONE | #81 |
| **TOTAL** | **24** | | **DONE** | |

### Phase 6G: Fix Remaining Shell Constructs (Test209 Regression)

| Module | Line | Issue | Fix | Status | Session |
|--------|------|-------|-----|--------|---------|
| ASD | 44992 | Backtick-escaped quotes in grep `` `"`"$alg`" `` | Build pattern with `[char]34` into variable, pass to grep | DONE | #81 |
| WebSRG | 30975 | `while read cert; do ... done` shell loop | Rewrite as PowerShell foreach with openssl checkend | DONE | #81 |
| WebSRG | 34968 | Shell subshell `(echo 'X'; ls ...)` with `;` | Replace `(cmd; cmd)` with `cmd && cmd` | DONE | #81 |

---

## Overall Progress

| Phase | Description | Items | Done | % |
|-------|-------------|-------|------|---|
| 1 | Answer file fixes | 136 | 136 | 100% |
| 2 | Rule 4 (sh -c removal) | 1,501 | 1,501 | 100% |
| 3 | Rule 1 (backtick-n) | 1,637 | 1,637 | 100% |
| 4 | Rule 7 (find timeout) | 68 | 68 | 100% |
| 5 | Minor fixes | 17 | 17 | 100% |
| 6 | Regression testing | 5 | 3 | 60% |
| 6A | Fix `2>/dev/null 2>&1` | 126 | 126 | 100% |
| 6B | Fix VMM while-loop | 1 | 1 | 100% |
| 6C | Fix `2>&1 2>&1` | 83 | 83 | 100% |
| 6D | Fix bare commands (CommandNotFoundException) | 23 | 23 | 100% |
| 6E | Fix mangled node -e + .Trim() on Char | 6 | 6 | 100% |
| 6F | Fix shell if/then/fi constructs | 24 | 24 | 100% |
| 6G | Fix remaining shell constructs | 3 | 3 | 100% |
| **TOTAL** | | **3,630** | **3,628** | **99.9%** |

**Phase 6A-6G regression fixes applied.** Test209: GPOS PASS (46.46%), VMM PASS (35.23%), Dom0 PASS (42.62%). ASD/WebSRG failed (backtick quotes, while-read loop, shell subshell). Test210 needed for ASD + WebSRG.

---

## Fix Scripts Created

All scripts in `.Mods_by_Kismet/Docs/QA/`:

| Script | Phase | Purpose |
|--------|-------|---------|
| `fix_websrg_answerfile.py` | 1A | WebSRG answer file fixes (13 VulnIDs + normalization) |
| `fix_asd_answerfile.py` | 1B | ASD answer file fixes (133 items) |
| `fix_rule4_dom0.py` | 2A | Remove sh -c in Dom0 RHEL7 (20) |
| `fix_rule4_vmm.py` | 2B | Remove sh -c in VMM (73) |
| `fix_rule4_gpos.py` | 2C | Remove sh -c in GPOS (187) |
| `fix_rule4_asd.py` | 2D | Remove bash -c/sh -c in ASD (main pass, 552) |
| `fix_rule4_asd_remaining.py` | 2D | Remove variable-based sh -c in ASD (86) |
| `fix_rule4_websrg.py` | 2E | Remove bash -c/sh -c in WebSRG (583) |
| `fix_rule1_backtick_n.py` | 3 | Replace backtick-n across WebSRG/ASD/VMM (1,637) |
| `fix_rule7_find_timeout.py` | 4 | Add timeout+maxdepth to find commands (68) |

---

## Test History

| Test # | Date | Module(s) | Phase | Result | Notes |
|--------|------|-----------|-------|--------|-------|
| Test206 | 2026-03-14 | XO1: WebSRG+ASD+GPOS | 6 | FAIL | StreamAlreadyRedirected ParserError — duplicate `2>/dev/null 2>&1` (126 total) |
| Test206 | 2026-03-14 | VMH01: VMM | 6 | FAIL | MissingLoopStatement ParserError — shell while-loop at line 28113 |
| Test206 | 2026-03-14 | VMH01: Dom0 RHEL7 | 6 | PASS | Loaded and scanned successfully |
| Test207 | 2026-03-14 | XO1: GPOS | 6 | PASS | EvalScore 44.44% (was 46.46%), 5 func errors (auditctl/iptables CommandNotFoundException) |
| Test207 | 2026-03-14 | XO1: ASD | 6 | FAIL | `2>&1 2>&1` (4) + mangled node -e (2) + escaped-quote grep (2) |
| Test207 | 2026-03-14 | XO1: WebSRG | 6 | FAIL | `2>&1 2>&1` (79) + mangled node -e (1) |
| Test207 | 2026-03-14 | VMH01: VMM | 6 | PASS | EvalScore 35.23% (was 34.72%), exit code 0 |
| Test207 | 2026-03-14 | VMH01: Dom0 RHEL7 | 6 | PASS | EvalScore 42.21%, 1 func error (V-204462 .Trim() on Char) |
| Test208 | 2026-03-14 | XO1: GPOS | 6 | PASS | EvalScore 46.46% (back to baseline), 0 func errors |
| Test208 | 2026-03-14 | XO1: ASD | 6 | FAIL | Shell if/then/fi (6 patterns) — MissingOpenParenthesisInIfStatement |
| Test208 | 2026-03-14 | XO1: WebSRG | 6 | FAIL | Shell if/then/fi (18 patterns) — MissingOpenParenthesisInIfStatement |
| Test208 | 2026-03-14 | VMH01: VMM | 6 | PASS | EvalScore 35.23%, exit code 0 |
| Test208 | 2026-03-14 | VMH01: Dom0 RHEL7 | 6 | PASS | EvalScore 42.62% (up from 42.21%), 0 func errors |
| Test209 | 2026-03-14 | XO1: GPOS | 6 | PASS | EvalScore 46.46%, exit code 0 |
| Test209 | 2026-03-14 | XO1: ASD | 6 | FAIL | Backtick-escaped quotes in grep (line 44992) |
| Test209 | 2026-03-14 | XO1: WebSRG | 6 | FAIL | while-read loop (line 30975) + shell subshell (line 34968) |
| Test209 | 2026-03-14 | VMH01: VMM | 6 | PASS | EvalScore 35.23%, exit code 0 |
| Test209 | 2026-03-14 | VMH01: Dom0 RHEL7 | 6 | PASS | EvalScore 42.62%, exit code 0 |
| Test210 | 2026-03-14 | XO1: ASD+WebSRG+GPOS | 6 | PARTIAL | GPOS: PASS 46.46%. ASD: 5 func errors (-name×3, iptables×1, ulimit×1). WebSRG: 16 func errors (-name×9, 2>&1×2, ufw×2, ntpq×1, configPath×1, xoServerPath×1) |
| Test211 | 2026-03-14 | XO1: GPOS+ASD+WebSRG | 6H | PARTIAL | GPOS: PASS 46.46% ✓. ASD: 43.71% (above baseline!), 2 errors (V-222554, V-222601 — `{}` ScriptBlock). WebSRG: 43.65% (above baseline!), 2 errors (V-206443 `'$xoServerPath'`, V-264356 `{}` ScriptBlock) |
| Test212 | 2026-03-14 | XO1: GPOS+ASD+WebSRG | 6I | **PASS** | **ZERO errors.** GPOS: 46.46% (=baseline). ASD: 44.06% (+0.70%). WebSRG: 42.86% (+1.59%). All 3 XO modules clean. |
| Test213 | 2026-03-14 | XO1: GPOS+ASD+WebSRG | Phase 2 | PARTIAL | Summary Report disk fix validated (lsblk -dno). 2 Not_Reviewed: V-222425 (ASD), V-206414 (WebSRG) — xargs -I {} ScriptBlock parsing. |
| Test214 | 2026-03-14 | XO1: GPOS+ASD+WebSRG | Phase 2 | **PASS** | **ZERO errors.** GPOS: 46.46%. ASD: 43.36%. WebSRG: 43.65%. xargs -I {} fixes validated. |
| Test215 | 2026-03-15 | XO1: GPOS+ASD+WebSRG | Phase 2 | **PASS** | **ZERO errors.** GPOS: 46.46%. ASD: 43.36%. WebSRG: 42.86%. Disk fix v2 (lsblk -P pairs) validated — MODEL="QEMU DVD-ROM" parsed correctly. |

---

## QA Phase 2: Linux Summary Report Disk Fix + Remaining xargs Fixes

### Framework Fix: Master_Functions.psm1 Linux Disk Collection

**Root cause:** Original code used `lsblk`/`lvscan` with broken parsing — only 3 of 7 fields populated, hashtable objects piped through `cut`. Initial fix (v1) used whitespace splitting which broke on MODEL values with spaces (e.g., "QEMU DVD-ROM"). Final fix (v2) uses `lsblk -Pdno` (pairs output with quoted KEY="VALUE" format) and regex parsing.

**Impact:** Summary Report HTML now shows complete 7-column disk table on Linux matching Windows.

### Module Fix: xargs -I {} ScriptBlock Parsing

| Fix | Module | Line | VulnID | Status |
|-----|--------|------|--------|--------|
| `xargs -I {} ... {}` → `xargs -I '{}' ... '{}'` | ASD | 40356 | V-222574 | DONE |
| `xargs -I {} ... {}` → `xargs -I '{}' ... '{}'` | ASD | 40370 | V-222574 | DONE |
| `xargs -I {} ... {}` → `xargs -I '{}' ... '{}'` | ASD | 42938 | V-222425 | DONE |
| `xargs -I {} ... {}` → `xargs -I '{}' ... '{}'` | WebSRG | 16996 | V-206414 | DONE |
| `xargs -I {} ... {}` → `xargs -I '{}' ... '{}'` + `'$certDir'` → `$certDir` | WebSRG | 35119 | V-264352 | DONE |
| **Total** | | | | **5 fixes** |

---

## Phase 6H: PowerShell Parsing — find `\(` grouping, `\;` exec, bare commands, single-quoted variables

**Root cause:** `\(` in find commands causes PowerShell to parse `(` as subexpression start, making `-name` appear as a command. `\;` causes `;` to be parsed as statement separator. Bare commands (`ufw`, `ntpq`, `ulimit`) cause CommandNotFoundException. Single-quoted `'$var'` prevents variable expansion.

| Fix Category | Module | Count | Fix | Status |
|---|---|---|---|---|
| `\(` → `'('` in find grouping | WebSRG | 20 | replace_all | DONE |
| `\)` → `')'` in find grouping | WebSRG | 20 | replace_all | DONE |
| `\(` → `'('` in find grouping | ASD | 5 | replace_all | DONE |
| `\)` → `')'` in find grouping | ASD | 5 | replace_all | DONE |
| `\;` → `';'` in find -exec | WebSRG | 6 | replace_all | DONE |
| `\\;` → `';'` in find -exec | WebSRG | 1 | targeted | DONE |
| `\;` → `';'` in find -exec | ASD | 3 | replace_all | DONE |
| `cat \`"$path\`"` → `cat $path` | WebSRG | 7 | replace_all | DONE |
| bare `ufw` → `timeout 5 ufw` | WebSRG | 2 | targeted | DONE |
| bare `ntpq` → `timeout 5 ntpq` | WebSRG | 2 | replace_all | DONE |
| `'$configPath'` → `$configPath` + grep -E | WebSRG | 1 | targeted | DONE |
| `cd '$xoServerPath'` → `cd $xoServerPath` | WebSRG | 1 | targeted | DONE |
| bare `iptables` in `||` chain | ASD | 1 | targeted | DONE |
| `ulimit -s` → `grep /proc/self/limits` | ASD | 1 | targeted | DONE |
| `iptables-L` → `iptables -L` (missing space) | WebSRG | 4 | replace_all | DONE |
| `iptables-L` → `iptables -L` (missing space) | ASD | 1 | replace_all | DONE |
| **Total** | | **80** | | **DONE** |

## Phase 6I: PowerShell Parsing — find -exec `{}` ScriptBlock, single-quoted variables

**Root cause:** PowerShell interprets bare `{}` as an empty ScriptBlock (System.Object) instead of passing the literal string `{}` to find's `-exec`. Fix: quote as `'{}'`. Also remaining `'$xoServerPath'` preventing variable expansion.

| Fix Category | Module | Count | Fix | Status |
|---|---|---|---|---|
| `{}` → `'{}'` in find -exec (+ terminator) | ASD | 31 | replace_all | DONE |
| `{}` → `'{}'` in find -exec (';' terminator) | ASD | 3 | replace_all | DONE |
| `{}` → `'{}'` in find -exec (';' terminator) | WebSRG | 6 | replace_all | DONE |
| `'$xoServerPath'` → `$xoServerPath` in cd | WebSRG | 1 | targeted | DONE |
| **Total** | | **41** | | **DONE** |

---

## Session Log

| Session | Date | Phase(s) | Work Done | Commits |
|---------|------|----------|-----------|---------|
| #81 | 2026-03-14 | Phase 1-5 (all) | Phase 1: Fixed all 4 answer files (136 items). Phase 2: Removed 1,501 sh -c/bash -c wrappers across all 5 modules. Phase 3: Replaced 1,637 backtick-n with $nl across 3 modules (66 declarations added). Phase 4: Added timeout+maxdepth to 68 find commands across 4 modules. Phase 5: Fixed 17 minor issues (escaped quotes, corrupted patterns, stale comment). Phase 6: Test206 revealed 2 regression categories — fixed 126 duplicate stderr redirections (Phase 6A) and 1 shell while-loop (Phase 6B). Dom0 RHEL7 passed Test206. | pending |
| #82 | 2026-03-14 | Phase 6C-6H | Phase 6C: Fixed 83 `2>&1 2>&1` duplicates (ASD 4, WebSRG 79). Phase 6D: Wrapped 23 bare commands with timeout 5 (auditctl, iptables, ufw, getenforce). Phase 6E: Fixed mangled node -e (3), escaped-quote grep (2), .Trim() on Char (1). Phase 6F: Converted 24 shell if/then/fi to test && pattern (ASD 6, WebSRG 18). Phase 6G: Fixed backtick-escaped grep quotes (1), while-read loop (1), shell subshell (1). Phase 6H: Fixed find `\(` → `'('` (25), `\)` → `')'` (25), `\;` → `';'` (10), cat backtick-quotes (7), bare commands (6), single-quoted vars (2), iptables-L spacing (5). Total: 80 fixes in Phase 6H. | pending |
