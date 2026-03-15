# XCP-ng Dom0 RHEL7 Implementation Tracker

**Module:** Scan-XCP-ng_Dom0_RHEL7_Checks
**STIG:** Red Hat Enterprise Linux 7 STIG V3R15 (adapted for XCP-ng Dom0)
**Version:** 1.0
**Created:** March 11, 2026

---

## Overall Progress

| Phase | Functions | Status |
|-------|-----------|--------|
| Phase 0: Remediation | -- | COMPLETE (Session #76, PR #60) |
| Phase 1: CAT I | 26/26 | COMPLETE (Session #77, PR #61) |
| Phase 2: CAT II | 205/205 | COMPLETE (Sessions #78-80, Batches 1-14) |
| Phase 3: CAT III | 13/13 | COMPLETE (Session #77, PR #62) |
| **Total** | **244/244** | **100% COMPLETE** |

**Last Test:** Test205 (Mar 14) — EvalScore 42.21%, 0 errors, 0 Not_Reviewed, exit code 0

---

## Status Legend

| Code | Meaning |
|------|---------|
| NF | NotAFinding |
| O | Open |
| NA | Not_Applicable |
| NR | Not_Reviewed (stub) |
| -- | Not yet tested |

---

## Phase 0: Module Remediation � COMPLETE

| Defect | Fix | Status |
|--------|-----|--------|
| Function naming: `Get-V-######` | Renamed all 244 to `Get-V######` | DONE |
| Param block: missing 3 params | Added `$Username`, `$UserSID`, `$Hostname` | DONE |
| PSD1: wrong VulnIDs (RHEL 8 IDs) | Rebuilt with wildcard export, correct metadata | DONE |
| Docblocks: zero MD5 hashes | Updated all 244 with correct XCCDF metadata | DONE |
| CheckPermissions: no timeout | Added `timeout 30` + `maxdepth 5` | DONE |
| Folder structure | Created `.Mods_by_Kismet/Docs/XCPng_v8.3_Dom0_RHEL7/` | DONE |

---

## Phase 1: CAT I Implementation (26 functions)

### Batch CAT1-A: FIPS, Crypto & Package Removal (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-204392 | SV-204392r991558_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | O |
| V-204424 | SV-204424r991589_rule | The Red Hat Enterprise Linux operating system must not allow accounts | DONE | Test188 | #77 | O |
| V-204425 | SV-204425r958486_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | O |
| V-204432 | SV-204432r991591_rule | The Red Hat Enterprise Linux operating system must not allow an unatte | DONE | Test188 | #77 | NA |
| V-204433 | SV-204433r991591_rule | The Red Hat Enterprise Linux operating system must not allow an unrest | DONE | Test188 | #77 | NA |
| V-204438 | SV-204438r958472_rule | Red Hat Enterprise Linux operating systems version 7.2 or newer with a | DONE | Test188 | #77 | O |
| V-204440 | SV-204440r958472_rule | Red Hat Enterprise Linux operating systems version 7.2 or newer using | DONE | Test188 | #77 | O |
| V-204442 | SV-204442r958478_rule | The Red Hat Enterprise Linux operating system must not have the rsh-se | DONE | Test188 | #77 | NF |
| V-204443 | SV-204443r958478_rule | The Red Hat Enterprise Linux operating system must not have the ypserv | DONE | Test188 | #77 | NF |
| V-204447 | SV-204447r982212_rule | The Red Hat Enterprise Linux operating system must prevent the install | DONE | Test188 | #77 | O |

### Batch CAT1-B: Account Security & SSH (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-204448 | SV-204448r982212_rule | The Red Hat Enterprise Linux operating system must prevent the install | DONE | Test188 | #77 | O |
| V-204455 | SV-204455r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | O |
| V-204456 | SV-204456r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | NF |
| V-204458 | SV-204458r991589_rule | The Red Hat Enterprise Linux operating system must be a vendor support | DONE | Test188 | #77 | O |
| V-204462 | SV-204462r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | O |
| V-204497 | SV-204497r958408_rule | The Red Hat Enterprise Linux operating system must implement NIST FIPS | DONE | Test188 | #77 | O |
| V-204502 | SV-204502r958478_rule | The Red Hat Enterprise Linux operating system must not have the telnet | DONE | Test188 | #77 | NF |
| V-204594 | SV-204594r987796_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | O |
| V-204606 | SV-204606r991589_rule | The Red Hat Enterprise Linux operating system must not contain .shosts | DONE | Test188 | #77 | NF |
| V-204607 | SV-204607r991589_rule | The Red Hat Enterprise Linux operating system must not contain shosts. | DONE | Test188 | #77 | NF |

### Batch CAT1-C: Remaining CAT I (6 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-204620 | SV-204620r991589_rule | The Red Hat Enterprise Linux operating system must not have a File Tra | DONE | Test188 | #77 | NF |
| V-204621 | SV-204621r991589_rule | The Red Hat Enterprise Linux operating system must not have the Trivia | DONE | Test188 | #77 | NF |
| V-204627 | SV-204627r991589_rule | SNMP community strings on the Red Hat Enterprise Linux operating syste | DONE | Test188 | #77 | O |
| V-214799 | SV-214799r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | DONE | Test188 | #77 | O |
| V-214801 | SV-214801r991589_rule | The Red Hat Enterprise Linux operating system must use a virus scan pr | DONE | Test188 | #77 | O |
| V-251702 | SV-251702r991589_rule | The Red Hat Enterprise Linux operating system must not have accounts c | DONE | Test188 | #77 | NF |

---

## Phase 2: CAT II Implementation (205 functions)

### Batch 1: Login Banner & Display (15 functions)
STIG range: RHEL-07-010030 through RHEL-07-010130

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204393 | SV-204393r958390_rule | RHEL-07-010030 | The Red Hat Enterprise Linux operating system must display t | DONE | Test192 | #78 | NA |
| V-204394 | SV-204394r958390_rule | RHEL-07-010040 | The Red Hat Enterprise Linux operating system must display t | DONE | Test192 | #78 | NA |
| V-204395 | SV-204395r958390_rule | RHEL-07-010050 | The Red Hat Enterprise Linux operating system must display t | DONE | Test192 | #78 | NA |
| V-204396 | SV-204396r958400_rule | RHEL-07-010060 | The Red Hat Enterprise Linux operating system must enable a | DONE | Test192 | #78 | NA |
| V-204397 | SV-204397r982216_rule | RHEL-07-010061 | The Red Hat Enterprise Linux operating system must uniquely | DONE | Test192 | #78 | NA |
| V-204398 | SV-204398r958402_rule | RHEL-07-010070 | The Red Hat Enterprise Linux operating system must initiate | DONE | Test192 | #78 | NA |
| V-204399 | SV-204399r958402_rule | RHEL-07-010081 | The Red Hat Enterprise Linux operating system must prevent a | DONE | Test192 | #78 | NA |
| V-204400 | SV-204400r958402_rule | RHEL-07-010082 | The Red Hat Enterprise Linux operating system must prevent a | DONE | Test192 | #78 | NA |
| V-204402 | SV-204402r958402_rule | RHEL-07-010100 | The Red Hat Enterprise Linux operating system must initiate | DONE | Test192 | #78 | NA |
| V-204403 | SV-204403r958402_rule | RHEL-07-010101 | The Red Hat Enterprise Linux operating system must prevent a | DONE | Test192 | #78 | NA |
| V-204404 | SV-204404r958402_rule | RHEL-07-010110 | The Red Hat Enterprise Linux operating system must initiate | DONE | Test192 | #78 | NA |
| V-204405 | SV-204405r982195_rule | RHEL-07-010118 | The Red Hat Enterprise Linux operating system must be config | DONE | Test192 | #78 | O |
| V-204406 | SV-204406r982195_rule | RHEL-07-010119 | The Red Hat Enterprise Linux operating system must be config | DONE | Test192 | #78 | O |
| V-204407 | SV-204407r982195_rule | RHEL-07-010120 | The Red Hat Enterprise Linux operating system must be config | DONE | Test192 | #78 | O |
| V-204408 | SV-204408r982196_rule | RHEL-07-010130 | The Red Hat Enterprise Linux operating system must be config | DONE | Test192 | #78 | O |

### Batch 2: Password Complexity & Aging (15 functions)
STIG range: RHEL-07-010140 through RHEL-07-010280

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204409 | SV-204409r982197_rule | RHEL-07-010140 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204410 | SV-204410r991561_rule | RHEL-07-010150 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204411 | SV-204411r982198_rule | RHEL-07-010160 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204412 | SV-204412r982198_rule | RHEL-07-010170 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204413 | SV-204413r982198_rule | RHEL-07-010180 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204414 | SV-204414r982198_rule | RHEL-07-010190 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204415 | SV-204415r982199_rule | RHEL-07-010200 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | NF |
| V-204416 | SV-204416r982199_rule | RHEL-07-010210 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | NF |
| V-204417 | SV-204417r982199_rule | RHEL-07-010220 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | NF |
| V-204418 | SV-204418r982188_rule | RHEL-07-010230 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204419 | SV-204419r982188_rule | RHEL-07-010240 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204420 | SV-204420r982200_rule | RHEL-07-010250 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204421 | SV-204421r982200_rule | RHEL-07-010260 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204422 | SV-204422r982201_rule | RHEL-07-010270 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |
| V-204423 | SV-204423r982202_rule | RHEL-07-010280 | The Red Hat Enterprise Linux operating system must be config | DONE | Test193 | #78 | O |

### Batch 3: Authentication & PAM (15 functions)
STIG range: RHEL-07-010310 through RHEL-07-020101

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204426 | SV-204426r982189_rule | RHEL-07-010310 | The Red Hat Enterprise Linux operating system must disable a | DONE | Test194b | #78 | O |
| V-204427 | SV-204427r958736_rule | RHEL-07-010320 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |
| V-204428 | SV-204428r958736_rule | RHEL-07-010330 | The Red Hat Enterprise Linux operating system must lock the | DONE | Test194b | #78 | O |
| V-204429 | SV-204429r987879_rule | RHEL-07-010340 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |
| V-204430 | SV-204430r987879_rule | RHEL-07-010350 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | NF |
| V-204431 | SV-204431r991588_rule | RHEL-07-010430 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |
| V-204434 | SV-204434r991591_rule | RHEL-07-010460 | The Red Hat Enterprise Linux operating system must not allow | DONE | Test194b | #78 | O |
| V-204435 | SV-204435r991591_rule | RHEL-07-010470 | The Red Hat Enterprise Linux operating system must not allow | DONE | Test194b | #78 | O |
| V-204437 | SV-204437r958472_rule | RHEL-07-010481 | The Red Hat Enterprise Linux operating system must require a | DONE | Test194b | #78 | NF |
| V-204441 | SV-204441r958482_rule | RHEL-07-010500 | The Red Hat Enterprise Linux operating system must uniquely | DONE | Test194b | #78 | NF |
| V-204444 | SV-204444r958726_rule | RHEL-07-020020 | The Red Hat Enterprise Linux operating system must prevent n | DONE | Test194b | #78 | O |
| V-204445 | SV-204445r958794_rule | RHEL-07-020030 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |
| V-204446 | SV-204446r958794_rule | RHEL-07-020040 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |
| V-204449 | SV-204449r958498_rule | RHEL-07-020100 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |
| V-204450 | SV-204450r958820_rule | RHEL-07-020101 | The Red Hat Enterprise Linux operating system must be config | DONE | Test194b | #78 | O |

### Batch 4: System Integrity & Software (15 functions)
STIG range: RHEL-07-020110 through RHEL-07-020670

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204451 | SV-204451r958498_rule | RHEL-07-020110 | The Red Hat Enterprise Linux operating system must disable t | DONE | Test195 | #78 | NF |
| V-204453 | SV-204453r958944_rule | RHEL-07-020210 | The Red Hat Enterprise Linux operating system must enable SE | DONE | Test195 | #78 | O |
| V-204454 | SV-204454r958944_rule | RHEL-07-020220 | The Red Hat Enterprise Linux operating system must enable th | DONE | Test195 | #78 | O |
| V-204457 | SV-204457r991590_rule | RHEL-07-020240 | The Red Hat Enterprise Linux operating system must define de | DONE | Test195 | #78 | NF |
| V-204459 | SV-204459r991589_rule | RHEL-07-020260 | The Red Hat Enterprise Linux operating system security patch | DONE | Test195 | #78 | O |
| V-204460 | SV-204460r991589_rule | RHEL-07-020270 | The Red Hat Enterprise Linux operating system must not have | DONE | Test195 | #78 | O |
| V-204463 | SV-204463r991589_rule | RHEL-07-020320 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | O |
| V-204464 | SV-204464r991589_rule | RHEL-07-020330 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | O |
| V-204466 | SV-204466r991589_rule | RHEL-07-020610 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |
| V-204467 | SV-204467r991589_rule | RHEL-07-020620 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |
| V-204468 | SV-204468r991589_rule | RHEL-07-020630 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |
| V-204469 | SV-204469r991589_rule | RHEL-07-020640 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |
| V-204470 | SV-204470r991589_rule | RHEL-07-020650 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |
| V-204471 | SV-204471r991589_rule | RHEL-07-020660 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |
| V-204472 | SV-204472r991589_rule | RHEL-07-020670 | The Red Hat Enterprise Linux operating system must be config | DONE | Test195 | #78 | NF |

### Batch 5: User/Group Management & Filesystem (15 functions)
STIG range: RHEL-07-020680 through RHEL-07-021110

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204473 | SV-204473r991589_rule | RHEL-07-020680 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204474 | SV-204474r991589_rule | RHEL-07-020690 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204475 | SV-204475r991589_rule | RHEL-07-020700 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204476 | SV-204476r991589_rule | RHEL-07-020710 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204477 | SV-204477r991589_rule | RHEL-07-020720 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | O |
| V-204478 | SV-204478r991589_rule | RHEL-07-020730 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204479 | SV-204479r991589_rule | RHEL-07-020900 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | O |
| V-204480 | SV-204480r991589_rule | RHEL-07-021000 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204481 | SV-204481r991589_rule | RHEL-07-021010 | The Red Hat Enterprise Linux operating system must prevent f | DONE | Test196 | #78 | NF |
| V-204482 | SV-204482r991589_rule | RHEL-07-021020 | The Red Hat Enterprise Linux operating system must prevent f | DONE | Test196 | #78 | NF |
| V-204483 | SV-204483r991589_rule | RHEL-07-021021 | The Red Hat Enterprise Linux operating system must prevent b | DONE | Test196 | #78 | NF |
| V-204487 | SV-204487r991589_rule | RHEL-07-021030 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |
| V-204488 | SV-204488r991589_rule | RHEL-07-021040 | The Red Hat Enterprise Linux operating system must set the u | DONE | Test196 | #78 | NF |
| V-204489 | SV-204489r991589_rule | RHEL-07-021100 | The Red Hat Enterprise Linux operating system must have cron | DONE | Test196 | #78 | NF |
| V-204490 | SV-204490r991589_rule | RHEL-07-021110 | The Red Hat Enterprise Linux operating system must be config | DONE | Test196 | #78 | NF |

### Batch 6: File Permissions & Audit Setup (15 functions)
STIG range: RHEL-07-021120 through RHEL-07-030340

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204491 | SV-204491r991589_rule | RHEL-07-021120 | The Red Hat Enterprise Linux operating system must be config | DONE | Test197 | #79 | NF |
| V-204492 | SV-204492r991589_rule | RHEL-07-021300 | The Red Hat Enterprise Linux operating system must disable K | DONE | Test197 | #79 | O |
| V-204500 | SV-204500r991589_rule | RHEL-07-021620 | The Red Hat Enterprise Linux operating system must use a fil | DONE | Test197 | #79 | O |
| V-204501 | SV-204501r958796_rule | RHEL-07-021700 | The Red Hat Enterprise Linux operating system must not allow | DONE | Test197 | #79 | O |
| V-204503 | SV-204503r958414_rule | RHEL-07-030000 | The Red Hat Enterprise Linux operating system must be config | DONE | Test197 | #79 | O |
| V-204504 | SV-204504r958424_rule | RHEL-07-030010 | The Red Hat Enterprise Linux operating system must shut down | DONE | Test197 | #79 | O |
| V-204506 | SV-204506r958754_rule | RHEL-07-030201 | The Red Hat Enterprise Linux operating system must be config | DONE | Test197 | #79 | O |
| V-204507 | SV-204507r958754_rule | RHEL-07-030210 | The Red Hat Enterprise Linux operating system must take appr | DONE | Test197 | #79 | O |
| V-204508 | SV-204508r958754_rule | RHEL-07-030211 | The Red Hat Enterprise Linux operating system must label all | DONE | Test197 | #79 | O |
| V-204509 | SV-204509r958754_rule | RHEL-07-030300 | The Red Hat Enterprise Linux operating system must off-load | DONE | Test197 | #79 | O |
| V-204510 | SV-204510r958754_rule | RHEL-07-030310 | The Red Hat Enterprise Linux operating system must encrypt t | DONE | Test197 | #79 | O |
| V-204511 | SV-204511r958754_rule | RHEL-07-030320 | The Red Hat Enterprise Linux operating system must be config | DONE | Test197 | #79 | O |
| V-204512 | SV-204512r958754_rule | RHEL-07-030321 | The Red Hat Enterprise Linux operating system must be config | DONE | Test197 | #79 | O |
| V-204513 | SV-204513r971542_rule | RHEL-07-030330 | The Red Hat Enterprise Linux operating system must initiate | DONE | Test197 | #79 | O |
| V-204514 | SV-204514r971542_rule | RHEL-07-030340 | The Red Hat Enterprise Linux operating system must immediate | DONE | Test197 | #79 | O |

### Batch 7: Audit Rules � File & Access (15 functions)
STIG range: RHEL-07-030350 through RHEL-07-030650

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204515 | SV-204515r971542_rule | RHEL-07-030350 | The Red Hat Enterprise Linux operating system must immediate | DONE | Test198 | #79 | O |
| V-204516 | SV-204516r958732_rule | RHEL-07-030360 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204517 | SV-204517r958446_rule | RHEL-07-030370 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204521 | SV-204521r991570_rule | RHEL-07-030410 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204524 | SV-204524r991570_rule | RHEL-07-030440 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204531 | SV-204531r958446_rule | RHEL-07-030510 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204536 | SV-204536r958846_rule | RHEL-07-030560 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | NF |
| V-204537 | SV-204537r958846_rule | RHEL-07-030570 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204538 | SV-204538r958846_rule | RHEL-07-030580 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204539 | SV-204539r958846_rule | RHEL-07-030590 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204540 | SV-204540r958846_rule | RHEL-07-030610 | The Red Hat Enterprise Linux operating system must generate | DONE | Test198 | #79 | O |
| V-204541 | SV-204541r958846_rule | RHEL-07-030620 | The Red Hat Enterprise Linux operating system must generate | DONE | Test198 | #79 | O |
| V-204542 | SV-204542r958422_rule | RHEL-07-030630 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204543 | SV-204543r958422_rule | RHEL-07-030640 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |
| V-204544 | SV-204544r958422_rule | RHEL-07-030650 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test198 | #79 | O |

### Batch 8: Audit Rules � Execution & Privilege (15 functions)
STIG range: RHEL-07-030660 through RHEL-07-030819

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204545 | SV-204545r958422_rule | RHEL-07-030660 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204546 | SV-204546r958422_rule | RHEL-07-030670 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204547 | SV-204547r958412_rule | RHEL-07-030680 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204548 | SV-204548r958412_rule | RHEL-07-030690 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204549 | SV-204549r958412_rule | RHEL-07-030700 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204550 | SV-204550r958412_rule | RHEL-07-030710 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204551 | SV-204551r958412_rule | RHEL-07-030720 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204552 | SV-204552r958422_rule | RHEL-07-030740 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204553 | SV-204553r958422_rule | RHEL-07-030750 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204554 | SV-204554r958422_rule | RHEL-07-030760 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204555 | SV-204555r958422_rule | RHEL-07-030770 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204556 | SV-204556r958422_rule | RHEL-07-030780 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204557 | SV-204557r958422_rule | RHEL-07-030800 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204558 | SV-204558r991579_rule | RHEL-07-030810 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |
| V-204559 | SV-204559r991580_rule | RHEL-07-030819 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test199 | #79 | O |

### Batch 9: Audit Advanced & Network (15 functions)
STIG range: RHEL-07-030820 through RHEL-07-040170

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204560 | SV-204560r991580_rule | RHEL-07-030820 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test200 | #79 | O |
| V-204562 | SV-204562r991580_rule | RHEL-07-030830 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test200 | #79 | O |
| V-204563 | SV-204563r991580_rule | RHEL-07-030840 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test200 | #79 | O |
| V-204564 | SV-204564r958368_rule | RHEL-07-030870 | The Red Hat Enterprise Linux operating system must generate | DONE | Test200 | #79 | O |
| V-204565 | SV-204565r958368_rule | RHEL-07-030871 | The Red Hat Enterprise Linux operating system must generate | DONE | Test200 | #79 | O |
| V-204566 | SV-204566r958368_rule | RHEL-07-030872 | The Red Hat Enterprise Linux operating system must generate | DONE | Test200 | #79 | O |
| V-204567 | SV-204567r958368_rule | RHEL-07-030873 | The Red Hat Enterprise Linux operating system must generate | DONE | Test200 | #79 | O |
| V-204568 | SV-204568r958368_rule | RHEL-07-030874 | The Red Hat Enterprise Linux operating system must generate | DONE | Test200 | #79 | O |
| V-204572 | SV-204572r991575_rule | RHEL-07-030910 | The Red Hat Enterprise Linux operating system must audit all | DONE | Test200 | #79 | O |
| V-204574 | SV-204574r991589_rule | RHEL-07-031000 | The Red Hat Enterprise Linux operating system must send rsys | DONE | Test200 | #79 | NF |
| V-204575 | SV-204575r991589_rule | RHEL-07-031010 | The Red Hat Enterprise Linux operating system must be config | DONE | Test200 | #79 | NF |
| V-204577 | SV-204577r958480_rule | RHEL-07-040100 | The Red Hat Enterprise Linux operating system must be config | DONE | Test200 | #79 | NF |
| V-204578 | SV-204578r958408_rule | RHEL-07-040110 | The Red Hat Enterprise Linux 7 operating system must impleme | DONE | Test200 | #79 | O |
| V-204579 | SV-204579r970703_rule | RHEL-07-040160 | The Red Hat Enterprise Linux operating system must be config | DONE | Test200 | #79 | O |
| V-204580 | SV-204580r958390_rule | RHEL-07-040170 | The Red Hat Enterprise Linux operating system must display t | DONE | Test200 | #79 | O |

### Batch 10: SSH & Remote Access (15 functions)
STIG range: RHEL-07-040180 through RHEL-07-040410

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204581 | SV-204581r991554_rule | RHEL-07-040180 | The Red Hat Enterprise Linux operating system must implement | DONE | Test201 | #80 | NA |
| V-204582 | SV-204582r991554_rule | RHEL-07-040190 | The Red Hat Enterprise Linux operating system must implement | DONE | Test201 | #80 | NA |
| V-204583 | SV-204583r991554_rule | RHEL-07-040200 | The Red Hat Enterprise Linux operating system must implement | DONE | Test201 | #80 | NA |
| V-204584 | SV-204584r991589_rule | RHEL-07-040201 | The Red Hat Enterprise Linux operating system must implement | DONE | Test201 | #80 | NF |
| V-204585 | SV-204585r958908_rule | RHEL-07-040300 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | NF |
| V-204586 | SV-204586r958908_rule | RHEL-07-040310 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | NF |
| V-204587 | SV-204587r970703_rule | RHEL-07-040320 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | O |
| V-204588 | SV-204588r991589_rule | RHEL-07-040330 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | O |
| V-204589 | SV-204589r970703_rule | RHEL-07-040340 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | O |
| V-204590 | SV-204590r991589_rule | RHEL-07-040350 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | O |
| V-204591 | SV-204591r991589_rule | RHEL-07-040360 | The Red Hat Enterprise Linux operating system must display t | DONE | Test201 | #80 | O |
| V-204592 | SV-204592r991589_rule | RHEL-07-040370 | The Red Hat Enterprise Linux operating system must not permi | DONE | Test201 | #80 | O |
| V-204593 | SV-204593r991589_rule | RHEL-07-040380 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | O |
| V-204595 | SV-204595r991554_rule | RHEL-07-040400 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | O |
| V-204596 | SV-204596r991589_rule | RHEL-07-040410 | The Red Hat Enterprise Linux operating system must be config | DONE | Test201 | #80 | NF |

### Batch 11: Network Services & Security (15 functions)
STIG range: RHEL-07-040420 through RHEL-07-040641

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204597 | SV-204597r991589_rule | RHEL-07-040420 | The Red Hat Enterprise Linux operating system must be config | DONE | Test202 | #80 | NF |
| V-204598 | SV-204598r958796_rule | RHEL-07-040430 | The Red Hat Enterprise Linux operating system must be config | DONE | Test202 | #80 | NF |
| V-204599 | SV-204599r958796_rule | RHEL-07-040440 | The Red Hat Enterprise Linux operating system must be config | DONE | Test202 | #80 | O |
| V-204600 | SV-204600r991589_rule | RHEL-07-040450 | The Red Hat Enterprise Linux operating system must be config | DONE | Test202 | #80 | O |
| V-204601 | SV-204601r991589_rule | RHEL-07-040460 | The Red Hat Enterprise Linux operating system must be config | DONE | Test202 | #80 | NF |
| V-204602 | SV-204602r991589_rule | RHEL-07-040470 | The Red Hat Enterprise Linux operating system must be config | DONE | Test202 | #80 | O |
| V-204603 | SV-204603r982208_rule | RHEL-07-040500 | The Red Hat Enterprise Linux operating system must, for netw | DONE | Test202 | #80 | NF |
| V-204604 | SV-204604r991589_rule | RHEL-07-040520 | The Red Hat Enterprise Linux operating system must enable an | DONE | Test202 | #80 | NF |
| V-204609 | SV-204609r991589_rule | RHEL-07-040610 | The Red Hat Enterprise Linux operating system must not forwa | DONE | Test202 | #80 | NF |
| V-204610 | SV-204610r991589_rule | RHEL-07-040611 | The Red Hat Enterprise Linux operating system must use a rev | DONE | Test202 | #80 | O |
| V-204611 | SV-204611r991589_rule | RHEL-07-040612 | The Red Hat Enterprise Linux operating system must use a rev | DONE | Test202 | #80 | O |
| V-204612 | SV-204612r991589_rule | RHEL-07-040620 | The Red Hat Enterprise Linux operating system must not forwa | DONE | Test202 | #80 | NF |
| V-204613 | SV-204613r991589_rule | RHEL-07-040630 | The Red Hat Enterprise Linux operating system must not respo | DONE | Test202 | #80 | NF |
| V-204614 | SV-204614r991589_rule | RHEL-07-040640 | The Red Hat Enterprise Linux operating system must prevent I | DONE | Test202 | #80 | O |
| V-204615 | SV-204615r991589_rule | RHEL-07-040641 | The Red Hat Enterprise Linux operating system must ignore In | DONE | Test202 | #80 | NF |

### Batch 12: Firewall, DNS & Miscellaneous (15 functions)
STIG range: RHEL-07-040650 through RHEL-07-041003

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204616 | SV-204616r991589_rule | RHEL-07-040650 | The Red Hat Enterprise Linux operating system must not allow | DONE | Test203 | #80 | O |
| V-204617 | SV-204617r991589_rule | RHEL-07-040660 | The Red Hat Enterprise Linux operating system must not send | DONE | Test203 | #80 | O |
| V-204618 | SV-204618r991589_rule | RHEL-07-040670 | Network interfaces configured on the Red Hat Enterprise Linu | DONE | Test203 | #80 | NF |
| V-204619 | SV-204619r991589_rule | RHEL-07-040680 | The Red Hat Enterprise Linux operating system must be config | DONE | Test203 | #80 | NA |
| V-204622 | SV-204622r991589_rule | RHEL-07-040710 | The Red Hat Enterprise Linux operating system must be config | DONE | Test203 | #80 | O |
| V-204623 | SV-204623r991589_rule | RHEL-07-040720 | The Red Hat Enterprise Linux operating system must be config | DONE | Test203 | #80 | NA |
| V-204624 | SV-204624r991589_rule | RHEL-07-040730 | The Red Hat Enterprise Linux operating system must not have | DONE | Test203 | #80 | O |
| V-204625 | SV-204625r991589_rule | RHEL-07-040740 | The Red Hat Enterprise Linux operating system must not be pe | DONE | Test203 | #80 | O |
| V-204626 | SV-204626r991589_rule | RHEL-07-040750 | The Red Hat Enterprise Linux operating system must be config | DONE | Test203 | #80 | NA |
| V-204628 | SV-204628r991589_rule | RHEL-07-040810 | The Red Hat Enterprise Linux operating system access control | DONE | Test203 | #80 | NF |
| V-204629 | SV-204629r991589_rule | RHEL-07-040820 | The Red Hat Enterprise Linux operating system must not have | DONE | Test203 | #80 | NF |
| V-204630 | SV-204630r991589_rule | RHEL-07-040830 | The Red Hat Enterprise Linux operating system must not forwa | DONE | Test203 | #80 | NF |
| V-204631 | SV-204631r982216_rule | RHEL-07-041001 | The Red Hat Enterprise Linux operating system must have the | DONE | Test203 | #80 | O |
| V-204632 | SV-204632r982216_rule | RHEL-07-041002 | The Red Hat Enterprise Linux operating system must implement | DONE | Test203 | #80 | NA |
| V-204633 | SV-204633r982216_rule | RHEL-07-041003 | The Red Hat Enterprise Linux operating system must implement | DONE | Test203 | #80 | O |

### Batch 13: Additional Controls (V-214xxx-V-250xxx) (15 functions)
STIG range: RHEL-07-041010 through RHEL-07-020023

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204634 | SV-204634r971547_rule | RHEL-07-041010 | The Red Hat Enterprise Linux operating system must be config | DONE | Test204b | #80 | NA |
| V-214800 | SV-214800r991589_rule | RHEL-07-020019 | The Red Hat Enterprise Linux operating system must implement | DONE | Test204b | #80 | O |
| V-214937 | SV-214937r958402_rule | RHEL-07-010062 | The Red Hat Enterprise Linux operating system must prevent a | DONE | Test204b | #80 | NA |
| V-219059 | SV-219059r958498_rule | RHEL-07-020111 | The Red Hat Enterprise Linux operating system must disable t | DONE | Test204b | #80 | NA |
| V-228563 | SV-228563r991589_rule | RHEL-07-021031 | The Red Hat Enterprise Linux operating system must be config | DONE | Test204b | #80 | NF |
| V-228564 | SV-228564r958434_rule | RHEL-07-910055 | The Red Hat Enterprise Linux operating system must protect a | DONE | Test204b | #80 | NF |
| V-233307 | SV-233307r991589_rule | RHEL-07-040711 | The Red Hat Enterprise Linux operating system SSH daemon mus | DONE | Test204b | #80 | NF |
| V-237633 | SV-237633r991589_rule | RHEL-07-010341 | The Red Hat Enterprise Linux operating system must restrict | DONE | Test204b | #80 | NF |
| V-237634 | SV-237634r991589_rule | RHEL-07-010342 | The Red Hat Enterprise Linux operating system must use the i | DONE | Test204b | #80 | O |
| V-237635 | SV-237635r987879_rule | RHEL-07-010343 | The Red Hat Enterprise Linux operating system must require r | DONE | Test204b | #80 | O |
| V-244557 | SV-244557r958472_rule | RHEL-07-010483 | Red Hat Enterprise Linux operating systems version 7.2 or ne | DONE | Test204b | #80 | O |
| V-244558 | SV-244558r958472_rule | RHEL-07-010492 | Red Hat Enterprise Linux operating systems version 7.2 or ne | DONE | Test204b | #80 | NA |
| V-250312 | SV-250312r958726_rule | RHEL-07-020021 | The Red Hat Enterprise Linux operating system must confine S | DONE | Test204b | #80 | O |
| V-250313 | SV-250313r958726_rule | RHEL-07-020022 | The Red Hat Enterprise Linux operating system must not allow | DONE | Test204b | #80 | O |
| V-250314 | SV-250314r958726_rule | RHEL-07-020023 | The Red Hat Enterprise Linux operating system must elevate t | DONE | Test204b | #80 | O |

### Batch 14: Final Controls (V-251xxx-V-256xxx) (10 functions)
STIG range: RHEL-07-010339 through RHEL-07-020028

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-251703 | SV-251703r991589_rule | RHEL-07-010339 | The Red Hat Enterprise Linux operating system must specify t | DONE | Test205 | #80 | NA |
| V-251704 | SV-251704r987879_rule | RHEL-07-010344 | The Red Hat Enterprise Linux operating system must not be co | DONE | Test205 | #80 | NF |
| V-251705 | SV-251705r958944_rule | RHEL-07-020029 | The Red Hat Enterprise Linux operating system must use a fil | DONE | Test205 | #80 | O |
| V-254523 | SV-254523r958508_rule | RHEL-07-010271 | The Red Hat Enterprise Linux operating system must automatic | DONE | Test205 | #80 | NF |
| V-255925 | SV-255925r958408_rule | RHEL-07-040712 | The Red Hat Enterprise Linux operating system SSH server mus | DONE | Test205 | #80 | O |
| V-255926 | SV-255926r958402_rule | RHEL-07-010090 | The Red Hat Enterprise Linux operating system must have the | DONE | Test205 | #80 | NF |
| V-255928 | SV-255928r982199_rule | RHEL-07-010199 | The Red Hat Enterprise Linux operating system must be config | DONE | Test205 | #80 | O |
| V-256968 | SV-256968r982212_rule | RHEL-07-010019 | The Red Hat Enterprise Linux operating system must ensure cr | DONE | Test205 | #80 | NF |
| V-256969 | SV-256969r991589_rule | RHEL-07-010063 | The Red Hat Enterprise Linux operating system must disable t | DONE | Test205 | #80 | NA |
| V-256970 | SV-256970r958794_rule | RHEL-07-020028 | The Red Hat Enterprise Linux operating system must be config | DONE | Test205 | #80 | NF |

---

## Phase 3: CAT III Implementation (13 functions)

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204452 | SV-204452r958936_rule | RHEL-07-020200 | The Red Hat Enterprise Linux operating system must remove al | DONE | Test191 | #77 | O |
| V-204461 | SV-204461r958482_rule | RHEL-07-020300 | The Red Hat Enterprise Linux operating system must be config | DONE | Test191 | #77 | NF |
| V-204486 | SV-204486r958804_rule | RHEL-07-021024 | The Red Hat Enterprise Linux operating system must mount /de | DONE | Test191 | #77 | O |
| V-204493 | SV-204493r991589_rule | RHEL-07-021310 | The Red Hat Enterprise Linux operating system must be config | DONE | Test191 | #77 | NF |
| V-204494 | SV-204494r991589_rule | RHEL-07-021320 | The Red Hat Enterprise Linux operating system must use a sep | DONE | Test191 | #77 | O |
| V-204495 | SV-204495r991589_rule | RHEL-07-021330 | The Red Hat Enterprise Linux operating system must use a sep | DONE | Test191 | #77 | O |
| V-204496 | SV-204496r991589_rule | RHEL-07-021340 | The Red Hat Enterprise Linux operating system must use a sep | DONE | Test191 | #77 | O |
| V-204498 | SV-204498r991589_rule | RHEL-07-021600 | The Red Hat Enterprise Linux operating system must be config | DONE | Test191 | #77 | O |
| V-204499 | SV-204499r991589_rule | RHEL-07-021610 | The Red Hat Enterprise Linux operating system must be config | DONE | Test191 | #77 | O |
| V-204576 | SV-204576r958398_rule | RHEL-07-040000 | The Red Hat Enterprise Linux operating system must limit the | DONE | Test191 | #77 | O |
| V-204605 | SV-204605r991589_rule | RHEL-07-040530 | The Red Hat Enterprise Linux operating system must display t | DONE | Test191 | #77 | O |
| V-204608 | SV-204608r991589_rule | RHEL-07-040600 | For Red Hat Enterprise Linux operating systems using DNS res | DONE | Test191 | #77 | NF |
| V-255927 | SV-255927r958524_rule | RHEL-07-010375 | The Red Hat Enterprise Linux operating system must restrict | DONE | Test191 | #77 | O |

---

## Test History

| Test | Date | Session | Phase/Batch | Functions | Result | EvalScore | Notes |
|------|------|---------|-------------|-----------|--------|-----------|-------|
| Test188 | Mar 11 | #76 | Phase 0 baseline | 244 stubs | Pass | 0% | Remediation baseline |
| Test189 | Mar 11 | #77 | CAT I Batch 1 | 10 CAT I | Pass | 6.56% | First CAT I functions |
| Test190 | Mar 11 | #77 | CAT I Batch 2 | 10 CAT I | Pass | 9.84% | |
| Test191 | Mar 11 | #77 | CAT I Batch 3 | 6 CAT I + 13 CAT III | Pass | 12.30% | CAT I + CAT III complete |
| Test192 | Mar 12 | #78 | CAT II Batch 1 | 15 CAT II | Pass | 12.30% | Account & login |
| Test193 | Mar 12 | #78 | CAT II Batch 2 | 15 CAT II | Pass | 13.52% | Password & auth policy |
| Test194b | Mar 12 | #78 | CAT II Batch 3 | 15 CAT II | Pass | 15.16% | SSH & PAM config |
| Test195 | Mar 12 | #78 | CAT II Batch 4 | 15 CAT II | Pass | 18.85% | System integrity & software |
| Test196 | Mar 12 | #78 | CAT II Batch 5 | 15 CAT II | Pass | 24.18% | User/group mgmt & filesystem |
| Test197 | Mar 12 | #79 | CAT II Batch 6 | 15 CAT II | Pass | 24.59% | File permissions & audit setup |
| Test198 | Mar 13 | #79 | CAT II Batch 7 | 15 CAT II | Pass | 25.41% | Audit rules — file & access |
| Test199 | Mar 13 | #79 | CAT II Batch 8 | 15 CAT II | Pass | 25.41% | Audit rules — execution & privilege |
| Test200 | Mar 13 | #79 | CAT II Batch 9 | 15 CAT II | Pass | 26.23% | Audit advanced & network |
| Test201 | Mar 14 | #80 | CAT II Batch 10 | 15 CAT II | Pass | 29.1% | SSH & remote access |
| Test202 | Mar 14 | #80 | CAT II Batch 11 | 15 CAT II | Pass | 32.79% | Network services & security |
| Test203 | Mar 14 | #80 | CAT II Batch 12 | 15 CAT II | Pass | 36.07% | Firewall, DNS & misc |
| Test204b | Mar 14 | #80 | CAT II Batch 13 | 15 CAT II | Pass | 39.34% | Additional controls (V-204634 fix) |
| Test205 | Mar 14 | #80 | CAT II Batch 14 FINAL | 10 CAT II | Pass | 42.21% | **244/244 COMPLETE**, 0 NR |

