# Implementation Tracker - XO GPOS Debian 12 Module

**Document Version:** 1.0
**Created:** February 18, 2026
**Module:** Scan-XO_GPOS_Debian12_Checks (GPOS SRG V3R2)
**Total Functions:** 198 (18 CAT I + 170 CAT II + 10 CAT III)

---

## Overall Progress

| Metric | Value |
|--------|-------|
| **Total Functions** | 198 |
| **Implemented** | 158 (18 CAT I + 139 CAT II + 1 CAT III) |
| **Stubs (Not_Reviewed)** | 40 |
| **Completion** | 79.8% |

**Last validated test:** Test172 (Mar 1, 2026) — Exit 0, EvalScore 40.4%, Batch 17 validated (10/10 pass, 5 NF + 5 O)

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| NF | NotAFinding |
| O | Open |
| NA | Not_Applicable |
| NR | Not_Reviewed (stub) |
| -- | Not yet tested |

---

## Phase 0: Module Remediation - COMPLETE

| Defect | Status | Notes |
|--------|--------|-------|
| Function naming (Get-V- to Get-V) | DONE | 198 functions renamed (Session #50) |
| PSD1 manifest mismatch | DONE | Regenerated FunctionsToExport (Session #50) |
| Missing params ($Username, $UserSID, $Hostname) | DONE | 198 functions fixed (Session #50) |
| STIGList.xml CAT counts | DONE | CATI=18, CATII=170, CATIII=10 (Session #50) |
| Baseline framework test | DONE | Test149 — Exit 0, EvalScore 0%, all 198 execute (Session #50) |

---

## Phase 1: CAT I Implementation (18 functions) - COMPLETE

### Batch CAT1-A: Cryptography and FIPS (10 functions) - Test150c

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203603 | SV-203603r958408 | DoD-approved encryption for remote access | O | Test150c | #51 | umac-64 weak MAC |
| V-203630 | SV-203630r987796 | Transmit only encrypted representations of passwords | NF | Test150c | #51 | SHA-512 hashing |
| V-203682 | SV-203682r991567 | Cryptographic integrity of transmitted info | NF | Test150c | #51 | TLS 1.2+ configured |
| V-203736 | SV-203736r958848 | Cryptographic integrity of nonlocal maintenance | O | Test150c | #51 | umac-64 weak MAC |
| V-203737 | SV-203737r958850 | Cryptographic confidentiality of nonlocal maintenance | NF | Test150c | #51 | Approved ciphers |
| V-203739 | SV-203739r987791 | NSA-approved cryptography for classified info | NF | Test150c | #51 | Approved ciphers |
| V-203745 | SV-203745r958870 | Crypto mechanisms prevent unauthorized disclosure | NF | Test150c | #51 | Approved ciphers |
| V-203746 | SV-203746r958872 | Crypto mechanisms prevent unauthorized modification | NF | Test150c | #51 | Approved MACs/ciphers |
| V-203748 | SV-203748r958908 | Protect confidentiality/integrity of transmitted info | O | Test150c | #51 | umac-64 weak MAC |
| V-203749 | SV-203749r971547 | Crypto mechanisms prevent unauthorized disclosure (transmit) | NF | Test150c | #51 | Approved ciphers |

### Batch CAT1-B: Authentication and Access Control (5 functions) - Test150c

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203629 | SV-203629r982199 | Store only encrypted representations of passwords | NF | Test150c | #51 | SHA-512 hashing |
| V-203653 | SV-203653r958510 | Strong authenticators for nonlocal maintenance | O | Test150c | #51 | MFA not configured |
| V-203695 | SV-203695r958726 | Prevent nonprivileged users executing privileged functions | O | Test150c | #51 | sudo not installed |
| V-203720 | SV-203720r982212 | Prevent unauthorized patch/update installation | O | Test150c | #51 | apt config review |
| V-203782 | SV-203782r991591 | No unattended/automatic logon | O | Test150c | #51 | Auto-login check |

### Batch CAT1-C: Audit and Communications (3 functions) - Test150c

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203669 | SV-203669r991554 | Cryptographic integrity of audit tools | O | Test150c | #52 | Audit tool integrity |
| V-203776 | SV-203776r959006 | NIST FIPS-validated cryptography | O | Test150c | #51 | FIPS not enabled |
| V-252688 | SV-252688r958358 | Protect confidentiality/integrity of communications | NA | Test150c | #52 | Wireless N/A |

---

## Phase 2: CAT II Implementation (170 functions)

### Batch 1: Account Management (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203591 | SV-203591r958362 | Automated account management support | O | Test151 | #53 | No SSSD/LDAP/AD |
| V-203592 | SV-203592r958364 | Auto-remove/disable temp accounts | O | Test151 | #53 | No automated cleanup |
| V-203593 | SV-203593r958368 | Audit all account creations | O | Test151 | #53 | auditd inactive |
| V-203594 | SV-203594r958388 | 3 consecutive invalid logon attempts | O | Test151 | #53 | No faillock config |
| V-203648 | SV-203648r982189 | Disable accounts after 35 days inactivity | O | Test151 | #53 | INACTIVE not set |
| V-203652 | SV-203652r958508 | Auto-remove/disable emergency accounts | O | Test151 | #53 | No automated cleanup |
| V-203666 | SV-203666r991551 | Audit all account modifications | O | Test151 | #53 | auditd inactive |
| V-203667 | SV-203667r991552 | Audit all account disabling actions | O | Test151 | #53 | auditd inactive |
| V-203668 | SV-203668r991553 | Audit all account removal actions | O | Test151 | #53 | auditd inactive |
| V-203690 | SV-203690r958684 | Audit all account enabling actions | O | Test151 | #53 | auditd inactive |

### Batch 2: Authentication and Login (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203595 | SV-203595r958390 | DoD Notice and Consent Banner (GUI) | O | Test152 | #54 | No DoD keywords in /etc/issue or /etc/issue.net |
| V-203596 | SV-203596r958392 | DoD Notice and Consent Banner (CLI) | O | Test152 | #54 | No banner configured |
| V-203597 | SV-203597r958398 | Limit concurrent sessions to 10 (CAT III) | NF | Test152 | #54 | SSH MaxSessions=10 |
| V-203598 | SV-203598r958400 | Retain session lock until re-auth | O | Test152 | #54 | No tmux/screen/vlock, no SSH timeout |
| V-203599 | SV-203599r958402 | Session lock after 15 min inactivity | O | Test152 | #54 | No SSH timeout or TMOUT configured |
| V-203600 | SV-203600r982194 | User-initiated session lock | O | Test152 | #54 | No lock utilities available |
| V-203601 | SV-203601r958404 | Conceal info via session lock | O | Test152 | #54 | No lock utilities |
| V-203635 | SV-203635r958470 | Obscure auth feedback | NF | Test152 | #54 | Linux naturally obscures, no pwfeedback |
| V-203665 | SV-203665r958586 | Public connection banner | O | Test152 | #54 | No SSH banner file |
| V-203779 | SV-203779r991588 | 4-second delay between logon attempts | O | Test152 | #54 | No pam_faildelay configured |

### Batch 3: Password Policy (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203625 | SV-203625r982195 | At least 1 uppercase character | O | Test153b | #55 | ucredit not configured, pam_pwquality not loaded, libpam-pwquality not installed |
| V-203626 | SV-203626r982196 | At least 1 lowercase character | O | Test153b | #55 | lcredit not configured, pam_pwquality not loaded, libpam-pwquality not installed |
| V-203627 | SV-203627r982197 | At least 1 numeric character | O | Test153b | #55 | dcredit not configured, pam_pwquality not loaded, libpam-pwquality not installed |
| V-203628 | SV-203628r982198 | Change at least 50% of characters | O | Test153b | #55 | difok not configured, pam_pwquality not loaded |
| V-203631 | SV-203631r982188 | 24-hour minimum password lifetime | O | Test153b | #55 | PASS_MIN_DAYS=0 (requires >=1), per-user check failed |
| V-203632 | SV-203632r1038967 | 60-day maximum password lifetime | O | Test153b | #55 | PASS_MAX_DAYS=99999 (requires <=60), per-user check failed |
| V-203634 | SV-203634r982202 | Minimum 15-character password length | O | Test153b | #55 | minlen not configured, pam_pwquality not loaded |
| V-203676 | SV-203676r991561 | At least 1 special character | O | Test153b | #55 | ocredit not configured, pam_pwquality not loaded, libpam-pwquality not installed |
| V-203778 | SV-203778r991587 | Prevent dictionary words | O | Test153b | #55 | dictcheck not configured, pam_pwquality not loaded, no dictionary files |
| V-263653 | SV-263653r982229 | Verify password when changed | O | Test153b | #55 | dictcheck not configured, pam_pwquality not loaded, no wordlist files |

### Batch 4: SSH Configuration (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203602 | SV-203602r958406 | Monitor remote access methods | NF | Test154 | #56 | SSH LogLevel INFO, rsyslog auth, auth.log present, journald SSH events |
| V-203636 | SV-203636r958472 | Enforce approved authorizations for logical access | O | Test154 | #56 | No SSH AllowUsers/AllowGroups configured |
| V-203637 | SV-203637r958478 | Disable non-essential capabilities | O | Test154 | #56 | Non-essential SSH features enabled (X11/TCP forwarding) |
| V-203638 | SV-203638r958480 | Restrict use of functions/ports/protocols/services | O | Test154 | #56 | No active firewall detected (UFW/nftables/iptables) |
| V-203686 | SV-203686r958672 | Control remote access methods | NF | Test154 | #56 | SSH only, no unauthorized remote services |
| V-203687 | SV-203687r958674 | Immediate disconnect/disable capability | NF | Test154 | #56 | SSH stop + session termination capabilities present |
| V-203688 | SV-203688r991568 | Wireless access encryption | NA | Test154 | #56 | No wireless interfaces detected (server) |
| V-203689 | SV-203689r991569 | Wireless access authentication | NA | Test154 | #56 | No wireless interfaces detected (server) |
| V-203727 | SV-203727r982216 | MFA for remote access (privileged) | O | Test154 | #56 | No MFA configured (no PAM MFA, smartcard, or SSSD cert) |
| V-203728 | SV-203728r958816 | Accept PIV credentials | NF | Test154 | #56 | PIV packages present (opensc, pcscd, pam_pkcs11) |

### Batch 5: Audit System - Rules (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203604 | SV-203604r958412 | Audit records: what type of event | O | Test155 | #57 | auditd not active, no syscall event type rules |
| V-203605 | SV-203605r958414 | Audit records: when event occurred | O | Test155 | #57 | auditd not active, no timestamp verification |
| V-203606 | SV-203606r958416 | Audit records: where event occurred | O | Test155 | #57 | auditd not active, no filesystem watch rules |
| V-203607 | SV-203607r958418 | Audit records: source of event | O | Test155 | #57 | auditd not active, no source tracking rules |
| V-203608 | SV-203608r958420 | Audit records: outcome of event | O | Test155 | #57 | auditd not active, no outcome filters |
| V-203609 | SV-203609r958422 | Audit records: full-text recording | O | Test155 | #57 | auditd not active, no execve/SUID rules |
| V-203610 | SV-203610r958422 | Audit records: individual identity | O | Test155 | #57 | auditd not active, no AUID tracking |
| V-203619 | SV-203619r958442 | Audit record generation for DoD events | O | Test155 | #57 | auditd not active, no DoD event coverage |
| V-203670 | SV-203670r991555 | Session audits at startup | O | Test155 | #57 | auditd boot config incomplete, audit=1 missing |
| V-203697 | SV-203697r958732 | Audit execution of privileged functions | O | Test155 | #57 | auditd not active, no privileged exec rules |

### Batch 6: Audit System - Management (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203611 | SV-203611r958424 | Alert ISSO/SA on audit failure | O | O | #58 | Test156 |
| V-203613 | SV-203613r958428 | Centralized review/analysis | O | O | #58 | Test156 |
| V-203614 | SV-203614r958430 | Filter audit records | O | O | #58 | Test156 |
| V-203615 | SV-203615r958432 | Internal clocks for timestamps | O | O | #58 | Test156 |
| V-203616 | SV-203616r958434 | Audit info: unauthorized read protection | O | O | #58 | Test156 |
| V-203617 | SV-203617r958436 | Audit info: unauthorized modification protection | O | O | #58 | Test156 |
| V-203618 | SV-203618r958438 | Audit info: unauthorized deletion protection | O | O | #58 | Test156 |
| V-203620 | SV-203620r958444 | Only ISSM can select auditable events | O | O | #58 | Test156 |
| V-203672 | SV-203672r991557 | Protect audit tools from unauthorized access | O | O | #58 | Test156 |
| V-203673 | SV-203673r991558 | Protect audit tools from unauthorized modification | O | O | #58 | Test156 |

### Batch 7: Audit System - Events (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203674 | SV-203674r991559 | Protect audit tools from unauthorized deletion | O | O | #59 | Test157 |
| V-203759 | SV-203759r991570 | Audit security-relevant events (1) | O | O | #59 | Test157 |
| V-203760 | SV-203760r991571 | Audit security-relevant events (2) | O | O | #59 | Test157 |
| V-203761 | SV-203761r991572 | Audit security-relevant events (3) | O | O | #59 | Test157 |
| V-203762 | SV-203762r991573 | Audit security-relevant events (4) | O | O | #59 | Test157 |
| V-203763 | SV-203763r991574 | Audit security-relevant events (5) | O | O | #59 | Test157 |
| V-203764 | SV-203764r991575 | Audit security-relevant events (6) | O | O | #59 | Test157 |
| V-203765 | SV-203765r991576 | Audit security-relevant events (7) | O | O | #59 | Test157 |
| V-203766 | SV-203766r991577 | Audit security-relevant events (8) | O | O | #59 | Test157 |
| V-203767 | SV-203767r991578 | Audit security-relevant events (9) | O | O | #59 | Test157 |

### Batch 8: Audit System - Advanced (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203768 | SV-203768r991579 | Audit privileged activities | O | O | #60 | Test158 |
| V-203769 | SV-203769r991580 | Audit kernel module load/unload | O | O | #60 | Test158 |
| V-203770 | SV-203770r991581 | Audit session start/end times | O | O | #60 | Test158 |
| V-203771 | SV-203771r991582 | Audit concurrent logons | O | O | #60 | Test158 |
| V-203772 | SV-203772r991583 | Audit access to security objects | O | O | #60 | Test158 |
| V-203773 | SV-203773r991584 | Audit direct access to system | O | O | #60 | Test158 |
| V-203774 | SV-203774r991585 | Audit account creations/modifications/deletions | O | O | #60 | Test158 |
| V-203775 | SV-203775r991586 | Audit kernel module operations | O | O | #60 | Test158 |
| V-203777 | SV-203777r959008 | Off-load audit data | O | O | #60 | Test158 |
| V-263658 | SV-263658r982561 | Monitor maintenance tools | O | O | #60 | Test158 |

### Batch 9: PKI and Certificates (10 functions) — DONE (Session #60b, Test164 validated)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203622 | SV-203622r958448 | PKI certificate validation | O | Test164 | #60b | CA trust store checks |
| V-203623 | SV-203623r958450 | PKI enforce authorized access | O | Test164 | #60b | Private key permissions |
| V-203624 | SV-203624r958452 | Map auth identity to user/group | O | Test164 | #60b | PAM PKCS#11 mapping |
| V-203639 | SV-203639r958482 | Uniquely ID org-defined processes | O | Test164 | #60b | UID uniqueness |
| V-203640 | SV-203640r958484 | MFA for network access (privileged) | NF | Test164 | #60b | auth-ldap + AD MFA |
| V-203641 | SV-203641r958486 | MFA for network access (non-privileged) | NF | Test164 | #60b | auth-ldap + AD MFA |
| V-203642 | SV-203642r982203 | MFA for local access (privileged) | O | Test164 | #60b | No local MFA |
| V-203643 | SV-203643r982204 | MFA for local access (non-privileged) | O | Test164 | #60b | No local MFA |
| V-203644 | SV-203644r982205 | Individual auth before shared account | NF | Test164 | #60b | auth-ldap individual auth |
| V-203729 | SV-203729r958818 | Verify PIV credentials electronically | O | Test164 | #60b | PIV verification |

### Batch 10: Access Control and Privilege (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203645 | SV-203645r958494 | Replay-resistant auth (network, privileged) | NF | -- | #61 | SSHv2 replay-resistant |
| V-203646 | SV-203646r982206 | Replay-resistant auth (network, non-priv) | NF | -- | #61 | SSHv2 replay-resistant |
| V-203647 | SV-203647r958498 | Uniquely identify peripherals | NF | -- | #61 | Kernel device enumeration |
| V-203650 | SV-203650r958504 | Uniquely ID non-org users | NF | -- | #61 | Unique UIDs, PAM auth |
| V-203655 | SV-203655r958514 | Separate user/management functionality | NF | -- | #61 | sudo, nologin shells |
| V-203656 | SV-203656r958518 | Isolate security from nonsecurity functions | NF | -- | #61 | AppArmor, ASLR, LSM |
| V-203696 | SV-203696r958730 | Prevent software execution at higher privilege | NF | -- | #61 | SUID mgmt, sudo, DAC |
| V-203718 | SV-203718r958796 | Enforce access restrictions | NF | -- | #61 | DAC, umask, shadow perms |
| V-203719 | SV-203719r982211 | Audit enforcement actions for access restrictions | O | -- | #61 | auditd not active |
| V-203722 | SV-203722r958808 | Deny-all, permit-by-exception policy | O | -- | #61 | AppArmor/firewall check |

### Batch 11: System Configuration (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203649 | SV-203649r971535 | Mechanisms meeting applicable requirements | NR | -- | -- | -- |
| V-203657 | SV-203657r958524 | Prevent unauthorized info transfer | NR | -- | -- | -- |
| V-203658 | SV-203658r958528 | Manage excess capacity/bandwidth | NR | -- | -- | -- |
| V-203659 | SV-203659r970703 | Terminate connections after session end | NR | -- | -- | -- |
| V-203660 | SV-203660r958550 | Fail to secure state on init failure | NR | -- | -- | -- |
| V-203661 | SV-203661r958552 | Protect confidentiality/integrity of info at rest | NR | -- | -- | -- |
| V-203663 | SV-203663r958564 | Error messages provide needed info | NR | -- | -- | -- |
| V-203664 | SV-203664r958566 | Error messages only to authorized users | NR | -- | -- | -- |
| V-203683 | SV-203683r958636 | Auto-terminate session after inactivity | NR | -- | -- | -- |
| V-203684 | SV-203684r958638 | Provide logoff capability | NR | -- | -- | -- |

### Batch 12: System Security (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203685 | SV-203685r958640 | Explicit logoff message | NR | -- | -- | -- |
| V-203691 | SV-203691r982207 | Notify SAs/ISSOs of threats | NR | -- | -- | -- |
| V-203692 | SV-203692r958702 | Allow admins to pass info | NR | -- | -- | -- |
| V-203693 | SV-203693r958702 | Allow admins to grant privileges | NR | -- | -- | -- |
| V-203694 | SV-203694r958702 | Allow admins to change security attrs | NR | -- | -- | -- |
| V-203698 | SV-203698r958736 | Auto-lock account until released | NR | -- | -- | -- |
| V-203699 | SV-203699r971541 | IMO/ISSO change audit config capability | NR | -- | -- | -- |
| V-203703 | SV-203703r958758 | Real-time alert on audit failure | NR | -- | -- | -- |
| V-203709 | SV-203709r958776 | Preserve original audit content | NR | -- | -- | -- |
| V-203710 | SV-203710r987795 | Preserve original audit time ordering | NR | -- | -- | -- |

### Batch 13: Time, Patching and Software (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203711 | SV-203711r1038944 | Compare internal clocks (networked) | NF | Test168c | #62 | chrony sync active |
| V-203712 | SV-203712r982209 | Sync clocks to authoritative time source | O | Test168c | #62 | chronyc not installed |
| V-203713 | SV-203713r958786 | Timestamp minimum granularity | NF | Test168c | #62 | journal microsecond precision |
| V-203715 | SV-203715r958790 | Dual authorization for audit deletion | O | Test168c | #62 | Org dual-auth procedures |
| V-203716 | SV-203716r982210 | Prohibit user software installation | NF | Test168c | #62 | apt/dpkg root-only |
| V-203717 | SV-203717r958794 | Notify on baseline config changes | O | Test168c | #62 | FIM/AIDE not installed |
| V-203721 | SV-203721r958804 | Prevent program execution per local policy | NF | Test168c | #62 | AppArmor active |
| V-203750 | SV-203750r958912 | Maintain confidentiality of info at rest | NF | Test168c | #62 | SSH + TLS encryption |
| V-203751 | SV-203751r958914 | Maintain integrity of info at rest | NF | Test168c | #62 | SSH + TLS + firewall |
| V-259333 | SV-259333r958940 | Install security updates within timeframe | O | Test168c | #62 | Security updates available |

### Batch 14: Kernel and Memory Protection (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203723 | SV-203723r1050789 | Re-auth for privilege escalation | NF | Test169 | #63 | No NOPASSWD entries |
| V-203724 | SV-203724r1050790 | Re-auth when changing roles | NF | Test169 | #63 | sudo timeout enforced |
| V-203725 | SV-203725r1050791 | Re-auth when changing authenticators | NF | Test169 | #63 | PAM password enforced |
| V-203730 | SV-203730r958820 | Auth peripherals before connection | O | Test169 | #63 | USBGuard not installed |
| V-203731 | SV-203731r971545 | Auth endpoint devices | NF | Test169 | #63 | SSH+TLS bidirectional |
| V-203733 | SV-203733r958828 | Prohibit cached auth after 1 day | NF | Test169 | #63 | sudo 5min cache |
| V-203734 | SV-203734r982217 | PKI local cache of revocation data | O | Test169 | #63 | No local CRL files |
| V-203735 | SV-203735r958846 | Audit all nonlocal maintenance | NF | Test169 | #63 | SSH+journal+XO Audit |
| V-203738 | SV-203738r958852 | Verify remote disconnect at termination | NF | Test169 | #63 | SSH keepalive active |
| V-203744 | SV-203744r958868 | Only DoD PKI-established certificates | O | Test169 | #63 | DoD CA verification needed |

### Batch 15: Hardening, Permissions and Firewall (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203747 | SV-203747r958902 | DoS protection/rate limiting | O | Test170b | #64 | No rate limiting configured |
| V-203752 | SV-203752r958926 | Predictable/documented behavior | NF | Test170b | #64 | Kernel panic+core dump configured |
| V-203753 | SV-203753r958928 | Non-executable data (NX/DEP) | NF | Test170b | #64 | NX flag active |
| V-203754 | SV-203754r958928 | Address space layout randomization (ASLR) | NF | Test170b | #64 | ASLR=2 (full) |
| V-203755 | SV-203755r958936 | Remove old software components | O | Test170b | #64 | Old package check |
| V-203756 | SV-203756r958944 | Verify correct security function operation | O | Test170b | #64 | AppArmor/dpkg verify |
| V-203757 | SV-203757r958946 | Periodic security function verification | O | Test170b | #64 | No AIDE cron detected |
| V-203758 | SV-203758r958948 | Shut down on security function failure | O | Test170b | #64 | Anomaly notification |
| V-203780 | SV-203780r991589 | Security configuration guide compliance | O | Test170b | #64 | Config guide review |
| V-203781 | SV-203781r991590 | Default permissions for authenticated users | O | Test170b | #64 | umask verification |

### Batch 16: Remaining and Compliance (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203783 | SV-203783r991592 | Limit non-privileged user privilege grants | NF | Test171 | #64 | Home dirs restricted |
| V-203784 | SV-203784r991593 | Enable application firewall | O | Test171 | #64 | No active firewall |
| V-263650 | SV-263650r982553 | Disable accounts no longer associated | O | Test171 | #64 | Org policy required |
| V-263651 | SV-263651r982555 | Prohibit unauthorized hardware | O | Test171 | #64 | Org policy required |
| V-263652 | SV-263652r982557 | MFA for local/network/remote access | O | Test171 | #64 | No MFA configured |
| V-263654 | SV-263654r982232 | Require immediate password change on recovery | O | Test171 | #64 | Org policy required |
| V-263655 | SV-263655r982235 | Allow user-selected long passwords | NF | Test171 | #64 | SHA512 supports long passwords |
| V-263656 | SV-263656r982238 | Automated password complexity tools | O | Test171 | #64 | pwquality not configured |
| V-263657 | SV-263657r982559 | NIST-compliant external credentials | O | Test171 | #64 | NIST verification needed |
| V-263659 | SV-263659r982563 | Approved trust anchors only | O | Test171 | #64 | Org approval needed |

### Batch 17: Final (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203651 | SV-203651r958506 | Audit reduction capability | NF | Test172 | #65 | aureport/ausearch available |
| V-203671 | SV-203671r991556 | Audit records: event source identity | NF | Test172 | #65 | auditd + journal source fields |
| V-203675 | SV-203675r991560 | Limit privilege to change software | NF | Test172 | #65 | root-owned /usr/lib,bin,sbin |
| V-203677 | SV-203677r991562 | Preserve info on system failure | NF | Test172 | #65 | journal persistent + coredump |
| V-203678 | SV-203678r991563 | Notify SAs/ISSOs on account creation | O | Test172 | #65 | notification config required |
| V-203679 | SV-203679r991564 | Notify SAs/ISSOs on account modification | O | Test172 | #65 | notification config required |
| V-203680 | SV-203680r991565 | Notify SAs/ISSOs on account disabling | O | Test172 | #65 | notification config required |
| V-203681 | SV-203681r991566 | Notify SAs/ISSOs on account removal | O | Test172 | #65 | notification config required |
| V-263660 | SV-263660r982565 | Protected storage for crypto keys | O | Test172 | #65 | key perms verification needed |
| V-263661 | SV-263661r982567 | Synchronize system clocks | NF | Test172 | #65 | timesyncd active + synced |

---

## Phase 3: CAT III Implementation (10 functions)

| Vuln ID | Rule ID | Rule Title | Status | Test | Session | Finding |
|---------|---------|------------|--------|------|---------|---------|
| V-203597 | SV-203597r958398 | Limit concurrent sessions to 10 | NF | Test152 | #54 | SSH MaxSessions=10 |
| V-203700 | SV-203700r958752 | Audit storage capacity (1 week min) | NR | -- | -- | -- |
| V-203701 | SV-203701r958754 | Offload audit records | NR | -- | -- | -- |
| V-203702 | SV-203702r971542 | Notify SA/ISSO on audit failure | NR | -- | -- | -- |
| V-203704 | SV-203704r958766 | Audit reduction - on-demand | NR | -- | -- | -- |
| V-203705 | SV-203705r958768 | Audit reduction - after-the-fact | NR | -- | -- | -- |
| V-203706 | SV-203706r958770 | Report generation - on-demand | NR | -- | -- | -- |
| V-203707 | SV-203707r958772 | Report generation - after-the-fact (1) | NR | -- | -- | -- |
| V-203708 | SV-203708r958774 | Report generation - after-the-fact (2) | NR | -- | -- | -- |
| V-203714 | SV-203714r958788 | Time stamps mappable to UTC | NR | -- | -- | -- |

---

## Test History

| Test | Date | Session | Phase/Batch | Functions | Result | EvalScore | Notes |
|------|------|---------|-------------|-----------|--------|-----------|-------|
| Test149 | Feb 18 | #50 | Phase 0 baseline | 198 | PASS | 0% | Exit 0, all stubs execute |
| Test150 | Feb 23 | #51 | Phase 1 CAT I | 198 | PASS | 4.04% | 18 CAT I implemented, 5 Open expected |
| Test150b | Feb 23 | #52 | Phase 1 fix | 198 | FAIL | -- | StigType param error in GetCorpParams |
| Test150c | Feb 24 | #52 | Phase 1 final | 198 | PASS | 4.04% | All 18 CAT I COMMENTS populated, 0 errors |
| Test151 | Feb 24 | #53 | Phase 2 Batch 1 | 198 | PASS | 4.04% | 10 Account Mgmt functions, all Open |
| Test152 | Feb 25 | #54 | Phase 2 Batch 2 | 198 | PASS | 5.05% | 10 Auth & Login, 2 NF + 8 Open |
| Test153 | Feb 25 | #55 | Phase 2 Batch 3 | 198 | FAIL | 5.05% | Answer file schema error (missing ValidationCode) |
| Test153b | Feb 25 | #55 | Phase 2 Batch 3 | 198 | PASS | 5.05% | 10 Password Policy, all Open, COMMENTS 198/198 |
| Test154 | Feb 25 | #56 | Phase 2 Batch 4 | 198 | PASS | 8.08% | 10 SSH Config, 6 NF + 4 Open |
| Test155 | Feb 26 | #57 | Phase 2 Batch 5 | 198 | PASS | 12.12% | 10 Audit Rules, 8 NF + 2 Open |
| Test156 | Feb 26 | #58 | Phase 2 Batch 6 | 198 | PASS | 14.14% | 10 Audit Mgmt, 4 NF + 6 Open |
| Test157 | Feb 26 | #59 | Phase 2 Batch 7 | 198 | PASS | 16.16% | 10 Audit Events, 4 NF + 6 Open |
| Test158 | Feb 27 | #60 | Phase 2 Batch 8 | 198 | PASS | 17.17% | 10 Audit Advanced, 2 NF + 8 Open |
| Test162 | Feb 27 | #60 | XO Audit Plugin | 198 | PASS | 17.17% | 18 Cat A functions flip via audit plugin |
| Test164 | Feb 28 | #61 | Phase 2 Batch 9 | 198 | PASS | 24.24% | 10 PKI & Certs, 4 NF + 6 Open |
| Test165b | Feb 28 | #61 | Phase 2 Batch 10 | 198 | PASS | 28.79% | 10 Access Control, 9 NF + 1 Open |
| Test166b | Feb 28 | #62 | Phase 2 Batch 11 | 198 | PASS | 30.30% | 10 System Config, 3 NF + 7 Open |
| Test167b | Mar 1 | #62 | Phase 2 Batch 12 | 198 | PASS | 28.28% | 10 System Security, 5 NF + 5 Open |
| Test168c | Mar 1 | #63 | Phase 2 Batch 13 | 198 | PASS | 32.83% | 10 Network & Maintenance, 9 NF + 1 Open |
| Test169 | Mar 1 | #63 | Phase 2 Batch 14 | 198 | PASS | 34.85% | 10 Auth & PKI, 7 NF + 3 Open |
| Test170 | Mar 1 | #64 | Phase 2 Batch 15 | 198 | FAIL | 36.36% | V-203752 null .ToString() crash |
| Test170b | Mar 1 | #64 | Phase 2 Batch 15 | 198 | PASS | 36.87% | 10 Hardening, 3 NF + 7 Open |
| Test171 | Mar 1 | #64 | Phase 2 Batch 16 | 198 | PASS | 37.88% | 10 Compliance/MFA/Firewall, 2 NF + 8 Open |
| Test172 | Mar 1 | #65 | Phase 2 Batch 17 | 198 | PASS | 40.4% | 10 Audit/Notify/Crypto/Time, 5 NF + 5 Open |
