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
| Phase 1: CAT I | 0/26 | Not Started |
| Phase 2: CAT II | 0/205 | Not Started |
| Phase 3: CAT III | 0/13 | Not Started |
| **Total** | **0/244** | **Remediation complete, awaiting baseline test** |

**Last Test:** Test188 (pending) -- Phase 0 baseline

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

## Phase 0: Module Remediation — COMPLETE

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
| V-204392 | SV-204392r991558_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-204424 | SV-204424r991589_rule | The Red Hat Enterprise Linux operating system must not allow accounts | NR | -- | -- | -- |
| V-204425 | SV-204425r958486_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-204432 | SV-204432r991591_rule | The Red Hat Enterprise Linux operating system must not allow an unatte | NR | -- | -- | -- |
| V-204433 | SV-204433r991591_rule | The Red Hat Enterprise Linux operating system must not allow an unrest | NR | -- | -- | -- |
| V-204438 | SV-204438r958472_rule | Red Hat Enterprise Linux operating systems version 7.2 or newer with a | NR | -- | -- | -- |
| V-204440 | SV-204440r958472_rule | Red Hat Enterprise Linux operating systems version 7.2 or newer using | NR | -- | -- | -- |
| V-204442 | SV-204442r958478_rule | The Red Hat Enterprise Linux operating system must not have the rsh-se | NR | -- | -- | -- |
| V-204443 | SV-204443r958478_rule | The Red Hat Enterprise Linux operating system must not have the ypserv | NR | -- | -- | -- |
| V-204447 | SV-204447r982212_rule | The Red Hat Enterprise Linux operating system must prevent the install | NR | -- | -- | -- |

### Batch CAT1-B: Account Security & SSH (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-204448 | SV-204448r982212_rule | The Red Hat Enterprise Linux operating system must prevent the install | NR | -- | -- | -- |
| V-204455 | SV-204455r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-204456 | SV-204456r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-204458 | SV-204458r991589_rule | The Red Hat Enterprise Linux operating system must be a vendor support | NR | -- | -- | -- |
| V-204462 | SV-204462r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-204497 | SV-204497r958408_rule | The Red Hat Enterprise Linux operating system must implement NIST FIPS | NR | -- | -- | -- |
| V-204502 | SV-204502r958478_rule | The Red Hat Enterprise Linux operating system must not have the telnet | NR | -- | -- | -- |
| V-204594 | SV-204594r987796_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-204606 | SV-204606r991589_rule | The Red Hat Enterprise Linux operating system must not contain .shosts | NR | -- | -- | -- |
| V-204607 | SV-204607r991589_rule | The Red Hat Enterprise Linux operating system must not contain shosts. | NR | -- | -- | -- |

### Batch CAT1-C: Remaining CAT I (6 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-204620 | SV-204620r991589_rule | The Red Hat Enterprise Linux operating system must not have a File Tra | NR | -- | -- | -- |
| V-204621 | SV-204621r991589_rule | The Red Hat Enterprise Linux operating system must not have the Trivia | NR | -- | -- | -- |
| V-204627 | SV-204627r991589_rule | SNMP community strings on the Red Hat Enterprise Linux operating syste | NR | -- | -- | -- |
| V-214799 | SV-214799r991589_rule | The Red Hat Enterprise Linux operating system must be configured so th | NR | -- | -- | -- |
| V-214801 | SV-214801r991589_rule | The Red Hat Enterprise Linux operating system must use a virus scan pr | NR | -- | -- | -- |
| V-251702 | SV-251702r991589_rule | The Red Hat Enterprise Linux operating system must not have accounts c | NR | -- | -- | -- |

---

## Phase 2: CAT II Implementation (205 functions)

### Batch 1: Login Banner & Display (15 functions)
STIG range: RHEL-07-010030 through RHEL-07-010130

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204393 | SV-204393r958390_rule | RHEL-07-010030 | The Red Hat Enterprise Linux operating system must display t | NR | -- | -- | -- |
| V-204394 | SV-204394r958390_rule | RHEL-07-010040 | The Red Hat Enterprise Linux operating system must display t | NR | -- | -- | -- |
| V-204395 | SV-204395r958390_rule | RHEL-07-010050 | The Red Hat Enterprise Linux operating system must display t | NR | -- | -- | -- |
| V-204396 | SV-204396r958400_rule | RHEL-07-010060 | The Red Hat Enterprise Linux operating system must enable a | NR | -- | -- | -- |
| V-204397 | SV-204397r982216_rule | RHEL-07-010061 | The Red Hat Enterprise Linux operating system must uniquely | NR | -- | -- | -- |
| V-204398 | SV-204398r958402_rule | RHEL-07-010070 | The Red Hat Enterprise Linux operating system must initiate | NR | -- | -- | -- |
| V-204399 | SV-204399r958402_rule | RHEL-07-010081 | The Red Hat Enterprise Linux operating system must prevent a | NR | -- | -- | -- |
| V-204400 | SV-204400r958402_rule | RHEL-07-010082 | The Red Hat Enterprise Linux operating system must prevent a | NR | -- | -- | -- |
| V-204402 | SV-204402r958402_rule | RHEL-07-010100 | The Red Hat Enterprise Linux operating system must initiate | NR | -- | -- | -- |
| V-204403 | SV-204403r958402_rule | RHEL-07-010101 | The Red Hat Enterprise Linux operating system must prevent a | NR | -- | -- | -- |
| V-204404 | SV-204404r958402_rule | RHEL-07-010110 | The Red Hat Enterprise Linux operating system must initiate | NR | -- | -- | -- |
| V-204405 | SV-204405r982195_rule | RHEL-07-010118 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204406 | SV-204406r982195_rule | RHEL-07-010119 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204407 | SV-204407r982195_rule | RHEL-07-010120 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204408 | SV-204408r982196_rule | RHEL-07-010130 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

### Batch 2: Password Complexity & Aging (15 functions)
STIG range: RHEL-07-010140 through RHEL-07-010280

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204409 | SV-204409r982197_rule | RHEL-07-010140 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204410 | SV-204410r991561_rule | RHEL-07-010150 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204411 | SV-204411r982198_rule | RHEL-07-010160 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204412 | SV-204412r982198_rule | RHEL-07-010170 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204413 | SV-204413r982198_rule | RHEL-07-010180 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204414 | SV-204414r982198_rule | RHEL-07-010190 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204415 | SV-204415r982199_rule | RHEL-07-010200 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204416 | SV-204416r982199_rule | RHEL-07-010210 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204417 | SV-204417r982199_rule | RHEL-07-010220 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204418 | SV-204418r982188_rule | RHEL-07-010230 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204419 | SV-204419r982188_rule | RHEL-07-010240 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204420 | SV-204420r982200_rule | RHEL-07-010250 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204421 | SV-204421r982200_rule | RHEL-07-010260 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204422 | SV-204422r982201_rule | RHEL-07-010270 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204423 | SV-204423r982202_rule | RHEL-07-010280 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

### Batch 3: Authentication & PAM (15 functions)
STIG range: RHEL-07-010310 through RHEL-07-020101

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204426 | SV-204426r982189_rule | RHEL-07-010310 | The Red Hat Enterprise Linux operating system must disable a | NR | -- | -- | -- |
| V-204427 | SV-204427r958736_rule | RHEL-07-010320 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204428 | SV-204428r958736_rule | RHEL-07-010330 | The Red Hat Enterprise Linux operating system must lock the | NR | -- | -- | -- |
| V-204429 | SV-204429r987879_rule | RHEL-07-010340 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204430 | SV-204430r987879_rule | RHEL-07-010350 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204431 | SV-204431r991588_rule | RHEL-07-010430 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204434 | SV-204434r991591_rule | RHEL-07-010460 | The Red Hat Enterprise Linux operating system must not allow | NR | -- | -- | -- |
| V-204435 | SV-204435r991591_rule | RHEL-07-010470 | The Red Hat Enterprise Linux operating system must not allow | NR | -- | -- | -- |
| V-204437 | SV-204437r958472_rule | RHEL-07-010481 | The Red Hat Enterprise Linux operating system must require a | NR | -- | -- | -- |
| V-204441 | SV-204441r958482_rule | RHEL-07-010500 | The Red Hat Enterprise Linux operating system must uniquely | NR | -- | -- | -- |
| V-204444 | SV-204444r958726_rule | RHEL-07-020020 | The Red Hat Enterprise Linux operating system must prevent n | NR | -- | -- | -- |
| V-204445 | SV-204445r958794_rule | RHEL-07-020030 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204446 | SV-204446r958794_rule | RHEL-07-020040 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204449 | SV-204449r958498_rule | RHEL-07-020100 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204450 | SV-204450r958820_rule | RHEL-07-020101 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

### Batch 4: System Integrity & Software (15 functions)
STIG range: RHEL-07-020110 through RHEL-07-020670

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204451 | SV-204451r958498_rule | RHEL-07-020110 | The Red Hat Enterprise Linux operating system must disable t | NR | -- | -- | -- |
| V-204453 | SV-204453r958944_rule | RHEL-07-020210 | The Red Hat Enterprise Linux operating system must enable SE | NR | -- | -- | -- |
| V-204454 | SV-204454r958944_rule | RHEL-07-020220 | The Red Hat Enterprise Linux operating system must enable th | NR | -- | -- | -- |
| V-204457 | SV-204457r991590_rule | RHEL-07-020240 | The Red Hat Enterprise Linux operating system must define de | NR | -- | -- | -- |
| V-204459 | SV-204459r991589_rule | RHEL-07-020260 | The Red Hat Enterprise Linux operating system security patch | NR | -- | -- | -- |
| V-204460 | SV-204460r991589_rule | RHEL-07-020270 | The Red Hat Enterprise Linux operating system must not have | NR | -- | -- | -- |
| V-204463 | SV-204463r991589_rule | RHEL-07-020320 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204464 | SV-204464r991589_rule | RHEL-07-020330 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204466 | SV-204466r991589_rule | RHEL-07-020610 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204467 | SV-204467r991589_rule | RHEL-07-020620 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204468 | SV-204468r991589_rule | RHEL-07-020630 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204469 | SV-204469r991589_rule | RHEL-07-020640 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204470 | SV-204470r991589_rule | RHEL-07-020650 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204471 | SV-204471r991589_rule | RHEL-07-020660 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204472 | SV-204472r991589_rule | RHEL-07-020670 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

### Batch 5: User/Group Management & Filesystem (15 functions)
STIG range: RHEL-07-020680 through RHEL-07-021110

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204473 | SV-204473r991589_rule | RHEL-07-020680 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204474 | SV-204474r991589_rule | RHEL-07-020690 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204475 | SV-204475r991589_rule | RHEL-07-020700 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204476 | SV-204476r991589_rule | RHEL-07-020710 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204477 | SV-204477r991589_rule | RHEL-07-020720 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204478 | SV-204478r991589_rule | RHEL-07-020730 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204479 | SV-204479r991589_rule | RHEL-07-020900 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204480 | SV-204480r991589_rule | RHEL-07-021000 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204481 | SV-204481r991589_rule | RHEL-07-021010 | The Red Hat Enterprise Linux operating system must prevent f | NR | -- | -- | -- |
| V-204482 | SV-204482r991589_rule | RHEL-07-021020 | The Red Hat Enterprise Linux operating system must prevent f | NR | -- | -- | -- |
| V-204483 | SV-204483r991589_rule | RHEL-07-021021 | The Red Hat Enterprise Linux operating system must prevent b | NR | -- | -- | -- |
| V-204487 | SV-204487r991589_rule | RHEL-07-021030 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204488 | SV-204488r991589_rule | RHEL-07-021040 | The Red Hat Enterprise Linux operating system must set the u | NR | -- | -- | -- |
| V-204489 | SV-204489r991589_rule | RHEL-07-021100 | The Red Hat Enterprise Linux operating system must have cron | NR | -- | -- | -- |
| V-204490 | SV-204490r991589_rule | RHEL-07-021110 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

### Batch 6: File Permissions & Audit Setup (15 functions)
STIG range: RHEL-07-021120 through RHEL-07-030340

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204491 | SV-204491r991589_rule | RHEL-07-021120 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204492 | SV-204492r991589_rule | RHEL-07-021300 | The Red Hat Enterprise Linux operating system must disable K | NR | -- | -- | -- |
| V-204500 | SV-204500r991589_rule | RHEL-07-021620 | The Red Hat Enterprise Linux operating system must use a fil | NR | -- | -- | -- |
| V-204501 | SV-204501r958796_rule | RHEL-07-021700 | The Red Hat Enterprise Linux operating system must not allow | NR | -- | -- | -- |
| V-204503 | SV-204503r958414_rule | RHEL-07-030000 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204504 | SV-204504r958424_rule | RHEL-07-030010 | The Red Hat Enterprise Linux operating system must shut down | NR | -- | -- | -- |
| V-204506 | SV-204506r958754_rule | RHEL-07-030201 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204507 | SV-204507r958754_rule | RHEL-07-030210 | The Red Hat Enterprise Linux operating system must take appr | NR | -- | -- | -- |
| V-204508 | SV-204508r958754_rule | RHEL-07-030211 | The Red Hat Enterprise Linux operating system must label all | NR | -- | -- | -- |
| V-204509 | SV-204509r958754_rule | RHEL-07-030300 | The Red Hat Enterprise Linux operating system must off-load | NR | -- | -- | -- |
| V-204510 | SV-204510r958754_rule | RHEL-07-030310 | The Red Hat Enterprise Linux operating system must encrypt t | NR | -- | -- | -- |
| V-204511 | SV-204511r958754_rule | RHEL-07-030320 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204512 | SV-204512r958754_rule | RHEL-07-030321 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204513 | SV-204513r971542_rule | RHEL-07-030330 | The Red Hat Enterprise Linux operating system must initiate | NR | -- | -- | -- |
| V-204514 | SV-204514r971542_rule | RHEL-07-030340 | The Red Hat Enterprise Linux operating system must immediate | NR | -- | -- | -- |

### Batch 7: Audit Rules — File & Access (15 functions)
STIG range: RHEL-07-030350 through RHEL-07-030650

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204515 | SV-204515r971542_rule | RHEL-07-030350 | The Red Hat Enterprise Linux operating system must immediate | NR | -- | -- | -- |
| V-204516 | SV-204516r958732_rule | RHEL-07-030360 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204517 | SV-204517r958446_rule | RHEL-07-030370 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204521 | SV-204521r991570_rule | RHEL-07-030410 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204524 | SV-204524r991570_rule | RHEL-07-030440 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204531 | SV-204531r958446_rule | RHEL-07-030510 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204536 | SV-204536r958846_rule | RHEL-07-030560 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204537 | SV-204537r958846_rule | RHEL-07-030570 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204538 | SV-204538r958846_rule | RHEL-07-030580 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204539 | SV-204539r958846_rule | RHEL-07-030590 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204540 | SV-204540r958846_rule | RHEL-07-030610 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204541 | SV-204541r958846_rule | RHEL-07-030620 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204542 | SV-204542r958422_rule | RHEL-07-030630 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204543 | SV-204543r958422_rule | RHEL-07-030640 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204544 | SV-204544r958422_rule | RHEL-07-030650 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |

### Batch 8: Audit Rules — Execution & Privilege (15 functions)
STIG range: RHEL-07-030660 through RHEL-07-030819

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204545 | SV-204545r958422_rule | RHEL-07-030660 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204546 | SV-204546r958422_rule | RHEL-07-030670 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204547 | SV-204547r958412_rule | RHEL-07-030680 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204548 | SV-204548r958412_rule | RHEL-07-030690 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204549 | SV-204549r958412_rule | RHEL-07-030700 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204550 | SV-204550r958412_rule | RHEL-07-030710 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204551 | SV-204551r958412_rule | RHEL-07-030720 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204552 | SV-204552r958422_rule | RHEL-07-030740 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204553 | SV-204553r958422_rule | RHEL-07-030750 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204554 | SV-204554r958422_rule | RHEL-07-030760 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204555 | SV-204555r958422_rule | RHEL-07-030770 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204556 | SV-204556r958422_rule | RHEL-07-030780 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204557 | SV-204557r958422_rule | RHEL-07-030800 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204558 | SV-204558r991579_rule | RHEL-07-030810 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204559 | SV-204559r991580_rule | RHEL-07-030819 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |

### Batch 9: Audit Advanced & Network (15 functions)
STIG range: RHEL-07-030820 through RHEL-07-040170

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204560 | SV-204560r991580_rule | RHEL-07-030820 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204562 | SV-204562r991580_rule | RHEL-07-030830 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204563 | SV-204563r991580_rule | RHEL-07-030840 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204564 | SV-204564r958368_rule | RHEL-07-030870 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204565 | SV-204565r958368_rule | RHEL-07-030871 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204566 | SV-204566r958368_rule | RHEL-07-030872 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204567 | SV-204567r958368_rule | RHEL-07-030873 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204568 | SV-204568r958368_rule | RHEL-07-030874 | The Red Hat Enterprise Linux operating system must generate | NR | -- | -- | -- |
| V-204572 | SV-204572r991575_rule | RHEL-07-030910 | The Red Hat Enterprise Linux operating system must audit all | NR | -- | -- | -- |
| V-204574 | SV-204574r991589_rule | RHEL-07-031000 | The Red Hat Enterprise Linux operating system must send rsys | NR | -- | -- | -- |
| V-204575 | SV-204575r991589_rule | RHEL-07-031010 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204577 | SV-204577r958480_rule | RHEL-07-040100 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204578 | SV-204578r958408_rule | RHEL-07-040110 | The Red Hat Enterprise Linux 7 operating system must impleme | NR | -- | -- | -- |
| V-204579 | SV-204579r970703_rule | RHEL-07-040160 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204580 | SV-204580r958390_rule | RHEL-07-040170 | The Red Hat Enterprise Linux operating system must display t | NR | -- | -- | -- |

### Batch 10: SSH & Remote Access (15 functions)
STIG range: RHEL-07-040180 through RHEL-07-040410

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204581 | SV-204581r991554_rule | RHEL-07-040180 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |
| V-204582 | SV-204582r991554_rule | RHEL-07-040190 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |
| V-204583 | SV-204583r991554_rule | RHEL-07-040200 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |
| V-204584 | SV-204584r991589_rule | RHEL-07-040201 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |
| V-204585 | SV-204585r958908_rule | RHEL-07-040300 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204586 | SV-204586r958908_rule | RHEL-07-040310 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204587 | SV-204587r970703_rule | RHEL-07-040320 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204588 | SV-204588r991589_rule | RHEL-07-040330 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204589 | SV-204589r970703_rule | RHEL-07-040340 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204590 | SV-204590r991589_rule | RHEL-07-040350 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204591 | SV-204591r991589_rule | RHEL-07-040360 | The Red Hat Enterprise Linux operating system must display t | NR | -- | -- | -- |
| V-204592 | SV-204592r991589_rule | RHEL-07-040370 | The Red Hat Enterprise Linux operating system must not permi | NR | -- | -- | -- |
| V-204593 | SV-204593r991589_rule | RHEL-07-040380 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204595 | SV-204595r991554_rule | RHEL-07-040400 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204596 | SV-204596r991589_rule | RHEL-07-040410 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

### Batch 11: Network Services & Security (15 functions)
STIG range: RHEL-07-040420 through RHEL-07-040641

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204597 | SV-204597r991589_rule | RHEL-07-040420 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204598 | SV-204598r958796_rule | RHEL-07-040430 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204599 | SV-204599r958796_rule | RHEL-07-040440 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204600 | SV-204600r991589_rule | RHEL-07-040450 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204601 | SV-204601r991589_rule | RHEL-07-040460 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204602 | SV-204602r991589_rule | RHEL-07-040470 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204603 | SV-204603r982208_rule | RHEL-07-040500 | The Red Hat Enterprise Linux operating system must, for netw | NR | -- | -- | -- |
| V-204604 | SV-204604r991589_rule | RHEL-07-040520 | The Red Hat Enterprise Linux operating system must enable an | NR | -- | -- | -- |
| V-204609 | SV-204609r991589_rule | RHEL-07-040610 | The Red Hat Enterprise Linux operating system must not forwa | NR | -- | -- | -- |
| V-204610 | SV-204610r991589_rule | RHEL-07-040611 | The Red Hat Enterprise Linux operating system must use a rev | NR | -- | -- | -- |
| V-204611 | SV-204611r991589_rule | RHEL-07-040612 | The Red Hat Enterprise Linux operating system must use a rev | NR | -- | -- | -- |
| V-204612 | SV-204612r991589_rule | RHEL-07-040620 | The Red Hat Enterprise Linux operating system must not forwa | NR | -- | -- | -- |
| V-204613 | SV-204613r991589_rule | RHEL-07-040630 | The Red Hat Enterprise Linux operating system must not respo | NR | -- | -- | -- |
| V-204614 | SV-204614r991589_rule | RHEL-07-040640 | The Red Hat Enterprise Linux operating system must prevent I | NR | -- | -- | -- |
| V-204615 | SV-204615r991589_rule | RHEL-07-040641 | The Red Hat Enterprise Linux operating system must ignore In | NR | -- | -- | -- |

### Batch 12: Firewall, DNS & Miscellaneous (15 functions)
STIG range: RHEL-07-040650 through RHEL-07-041003

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204616 | SV-204616r991589_rule | RHEL-07-040650 | The Red Hat Enterprise Linux operating system must not allow | NR | -- | -- | -- |
| V-204617 | SV-204617r991589_rule | RHEL-07-040660 | The Red Hat Enterprise Linux operating system must not send | NR | -- | -- | -- |
| V-204618 | SV-204618r991589_rule | RHEL-07-040670 | Network interfaces configured on the Red Hat Enterprise Linu | NR | -- | -- | -- |
| V-204619 | SV-204619r991589_rule | RHEL-07-040680 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204622 | SV-204622r991589_rule | RHEL-07-040710 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204623 | SV-204623r991589_rule | RHEL-07-040720 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204624 | SV-204624r991589_rule | RHEL-07-040730 | The Red Hat Enterprise Linux operating system must not have | NR | -- | -- | -- |
| V-204625 | SV-204625r991589_rule | RHEL-07-040740 | The Red Hat Enterprise Linux operating system must not be pe | NR | -- | -- | -- |
| V-204626 | SV-204626r991589_rule | RHEL-07-040750 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204628 | SV-204628r991589_rule | RHEL-07-040810 | The Red Hat Enterprise Linux operating system access control | NR | -- | -- | -- |
| V-204629 | SV-204629r991589_rule | RHEL-07-040820 | The Red Hat Enterprise Linux operating system must not have | NR | -- | -- | -- |
| V-204630 | SV-204630r991589_rule | RHEL-07-040830 | The Red Hat Enterprise Linux operating system must not forwa | NR | -- | -- | -- |
| V-204631 | SV-204631r982216_rule | RHEL-07-041001 | The Red Hat Enterprise Linux operating system must have the | NR | -- | -- | -- |
| V-204632 | SV-204632r982216_rule | RHEL-07-041002 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |
| V-204633 | SV-204633r982216_rule | RHEL-07-041003 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |

### Batch 13: Additional Controls (V-214xxx-V-250xxx) (15 functions)
STIG range: RHEL-07-041010 through RHEL-07-020023

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204634 | SV-204634r971547_rule | RHEL-07-041010 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-214800 | SV-214800r991589_rule | RHEL-07-020019 | The Red Hat Enterprise Linux operating system must implement | NR | -- | -- | -- |
| V-214937 | SV-214937r958402_rule | RHEL-07-010062 | The Red Hat Enterprise Linux operating system must prevent a | NR | -- | -- | -- |
| V-219059 | SV-219059r958498_rule | RHEL-07-020111 | The Red Hat Enterprise Linux operating system must disable t | NR | -- | -- | -- |
| V-228563 | SV-228563r991589_rule | RHEL-07-021031 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-228564 | SV-228564r958434_rule | RHEL-07-910055 | The Red Hat Enterprise Linux operating system must protect a | NR | -- | -- | -- |
| V-233307 | SV-233307r991589_rule | RHEL-07-040711 | The Red Hat Enterprise Linux operating system SSH daemon mus | NR | -- | -- | -- |
| V-237633 | SV-237633r991589_rule | RHEL-07-010341 | The Red Hat Enterprise Linux operating system must restrict | NR | -- | -- | -- |
| V-237634 | SV-237634r991589_rule | RHEL-07-010342 | The Red Hat Enterprise Linux operating system must use the i | NR | -- | -- | -- |
| V-237635 | SV-237635r987879_rule | RHEL-07-010343 | The Red Hat Enterprise Linux operating system must require r | NR | -- | -- | -- |
| V-244557 | SV-244557r958472_rule | RHEL-07-010483 | Red Hat Enterprise Linux operating systems version 7.2 or ne | NR | -- | -- | -- |
| V-244558 | SV-244558r958472_rule | RHEL-07-010492 | Red Hat Enterprise Linux operating systems version 7.2 or ne | NR | -- | -- | -- |
| V-250312 | SV-250312r958726_rule | RHEL-07-020021 | The Red Hat Enterprise Linux operating system must confine S | NR | -- | -- | -- |
| V-250313 | SV-250313r958726_rule | RHEL-07-020022 | The Red Hat Enterprise Linux operating system must not allow | NR | -- | -- | -- |
| V-250314 | SV-250314r958726_rule | RHEL-07-020023 | The Red Hat Enterprise Linux operating system must elevate t | NR | -- | -- | -- |

### Batch 14: Final Controls (V-251xxx-V-256xxx) (10 functions)
STIG range: RHEL-07-010339 through RHEL-07-020028

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-251703 | SV-251703r991589_rule | RHEL-07-010339 | The Red Hat Enterprise Linux operating system must specify t | NR | -- | -- | -- |
| V-251704 | SV-251704r987879_rule | RHEL-07-010344 | The Red Hat Enterprise Linux operating system must not be co | NR | -- | -- | -- |
| V-251705 | SV-251705r958944_rule | RHEL-07-020029 | The Red Hat Enterprise Linux operating system must use a fil | NR | -- | -- | -- |
| V-254523 | SV-254523r958508_rule | RHEL-07-010271 | The Red Hat Enterprise Linux operating system must automatic | NR | -- | -- | -- |
| V-255925 | SV-255925r958408_rule | RHEL-07-040712 | The Red Hat Enterprise Linux operating system SSH server mus | NR | -- | -- | -- |
| V-255926 | SV-255926r958402_rule | RHEL-07-010090 | The Red Hat Enterprise Linux operating system must have the | NR | -- | -- | -- |
| V-255928 | SV-255928r982199_rule | RHEL-07-010199 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-256968 | SV-256968r982212_rule | RHEL-07-010019 | The Red Hat Enterprise Linux operating system must ensure cr | NR | -- | -- | -- |
| V-256969 | SV-256969r991589_rule | RHEL-07-010063 | The Red Hat Enterprise Linux operating system must disable t | NR | -- | -- | -- |
| V-256970 | SV-256970r958794_rule | RHEL-07-020028 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |

---

## Phase 3: CAT III Implementation (13 functions)

| Vuln ID | Rule ID | STIG ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|---------|------------|--------|------|---------|---------|
| V-204452 | SV-204452r958936_rule | RHEL-07-020200 | The Red Hat Enterprise Linux operating system must remove al | NR | -- | -- | -- |
| V-204461 | SV-204461r958482_rule | RHEL-07-020300 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204486 | SV-204486r958804_rule | RHEL-07-021024 | The Red Hat Enterprise Linux operating system must mount /de | NR | -- | -- | -- |
| V-204493 | SV-204493r991589_rule | RHEL-07-021310 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204494 | SV-204494r991589_rule | RHEL-07-021320 | The Red Hat Enterprise Linux operating system must use a sep | NR | -- | -- | -- |
| V-204495 | SV-204495r991589_rule | RHEL-07-021330 | The Red Hat Enterprise Linux operating system must use a sep | NR | -- | -- | -- |
| V-204496 | SV-204496r991589_rule | RHEL-07-021340 | The Red Hat Enterprise Linux operating system must use a sep | NR | -- | -- | -- |
| V-204498 | SV-204498r991589_rule | RHEL-07-021600 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204499 | SV-204499r991589_rule | RHEL-07-021610 | The Red Hat Enterprise Linux operating system must be config | NR | -- | -- | -- |
| V-204576 | SV-204576r958398_rule | RHEL-07-040000 | The Red Hat Enterprise Linux operating system must limit the | NR | -- | -- | -- |
| V-204605 | SV-204605r991589_rule | RHEL-07-040530 | The Red Hat Enterprise Linux operating system must display t | NR | -- | -- | -- |
| V-204608 | SV-204608r991589_rule | RHEL-07-040600 | For Red Hat Enterprise Linux operating systems using DNS res | NR | -- | -- | -- |
| V-255927 | SV-255927r958524_rule | RHEL-07-010375 | The Red Hat Enterprise Linux operating system must restrict | NR | -- | -- | -- |

---

## Test History

| Test | Date | Session | Phase/Batch | Functions | Result | EvalScore | Notes |
|------|------|---------|-------------|-----------|--------|-----------|-------|
| Test188 | pending | #76 | Phase 0 baseline | 244 stubs | pending | ~0% | Remediation baseline |

