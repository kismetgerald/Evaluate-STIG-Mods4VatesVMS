# XCP-ng Dom0 RHEL7 Implementation Plan

**Module:** Scan-XCP-ng_Dom0_RHEL7_Checks
**STIG:** Red Hat Enterprise Linux 7 STIG V3R15 (adapted for XCP-ng Dom0)
**Target:** XCP-ng 8.3 Dom0 (CentOS 7-based)
**Total Functions:** 244 (26 CAT I + 205 CAT II + 13 CAT III)
**Created:** March 11, 2026 (Session #76)

---

## Context

The XCP-ng Dom0 RHEL7 module applies the RHEL 7 STIG V3R15 to the XCP-ng hypervisor's
control domain (Dom0), which is CentOS 7-based. All 244 functions currently exist as stubs
returning Not_Reviewed. Phase 0 remediation (Session #76) fixed critical defects: function
naming (Get-V-###### -> Get-V######), param blocks (added $Username/$UserSID/$Hostname),
PSD1 rebuild, XCCDF metadata, and CheckPermissions timeout/maxdepth.

**XCCDF:** `Evaluate-STIG/StigContent/U_RHEL_7_STIG_V3R15_Manual-xccdf.xml`
**PSM1:** `Evaluate-STIG/Modules/Scan-XCP-ng_Dom0_RHEL7_Checks/Scan-XCP-ng_Dom0_RHEL7_Checks.psm1`
**Answer File:** `Evaluate-STIG/AnswerFiles/XCP-ng_v8.3_Dom0_RHEL7_AnswerFile.xml`

---

## Current State

| Category | Count | Status |
|----------|-------|--------|
| CAT I (high) | 26 | Stubs — all return Not_Reviewed |
| CAT II (medium) | 205 | Stubs — all return Not_Reviewed |
| CAT III (low) | 13 | Stubs — all return Not_Reviewed |
| **Total** | **244** | **Phase 0 remediation complete** |

---

## XCP-ng Dom0 vs Standard RHEL 7

| Aspect | Standard RHEL 7 | XCP-ng Dom0 |
|--------|----------------|-------------|
| OS | RHEL 7.x | CentOS 7 (el7 packages) |
| Package manager | yum / rpm | yum / rpm |
| Firewall | firewalld / iptables | iptables (firewalld may not be installed) |
| SELinux | Enforcing by default | Typically disabled |
| PAM | Standard RHEL 7 | Standard CentOS 7 |
| SSH | OpenSSH (RHEL 7) | OpenSSH (CentOS 7) |
| Audit | auditd | auditd |
| FIPS | Supported | May not be supported on XCP-ng kernel |
| PowerShell | 7.4+ | 7.3.12 only (glibc constraint) |
| Paths | `/etc/pam.d/`, `/etc/ssh/`, `/etc/audit/` | Same |
| Key differences | — | Xen hypervisor, xapi service, Dom0 kernel |

**SELinux Note:** XCP-ng typically has SELinux disabled. Many SELinux-enforcement checks
will likely return Open or Not_Applicable depending on whether SELinux can be enabled.

**FIPS Note:** XCP-ng's custom kernel may not support FIPS mode. FIPS checks (V-204497,
V-214799) may return Open as a known compliance gap.

---

## Phase 0: Module Remediation — COMPLETE

Completed in Session #76, PR #60.

| Defect | Fix |
|--------|-----|
| Function naming: `Get-V-######` | Renamed all 244 to `Get-V######` |
| Param block: missing 3 params | Added `$Username`, `$UserSID`, `$Hostname` to all 244 |
| PSD1: wrong VulnIDs (RHEL 8) | Rebuilt with wildcard export, correct metadata |
| Docblocks: zero MD5 hashes | Updated all 244 with correct XCCDF metadata |
| CheckPermissions: no timeout | Added `timeout 30` + `maxdepth 5` |

---

## Phase 1: CAT I Implementation (26 functions, ~3 batches)

### Batch CAT1-A: FIPS, Crypto & Package Removal (10 functions)

| VulnID | STIG ID | Title (abbreviated) |
|--------|---------|---------------------|
| V-204392 | RHEL-07-010010 | File permissions/ownership match vendor values |
| V-204438 | RHEL-07-010482 | BIOS/UEFI require auth for single user/maintenance |
| V-204440 | RHEL-07-010491 | UEFI: unique GRUB superuser account |
| V-204442 | RHEL-07-020000 | No rsh-server package |
| V-204443 | RHEL-07-020010 | No ypserv package |
| V-204455 | RHEL-07-020230 | x86 BIOS ctrl-alt-del disabled |
| V-204456 | RHEL-07-020231 | x86 ctrl-alt-del burst action disabled |
| V-204497 | RHEL-07-021350 | FIPS-validated cryptographic hashing |
| V-204502 | RHEL-07-021710 | No telnet-server package |
| V-214799 | RHEL-07-010020 | Crypto policy not LEGACY |

### Batch CAT1-B: Account Security & SSH (10 functions)

| VulnID | STIG ID | Title (abbreviated) |
|--------|---------|---------------------|
| V-204424 | RHEL-07-010290 | No accounts with blank/null passwords |
| V-204425 | RHEL-07-010300 | SSH must not allow empty passwords |
| V-204432 | RHEL-07-010440 | No unattended/auto logon via GNOME |
| V-204433 | RHEL-07-010450 | No unrestricted logon to GNOME |
| V-204447 | RHEL-07-020050 | Prevent unauthorized software installation (SPC) |
| V-204448 | RHEL-07-020060 | Prevent unauthorized software installation (GPG) |
| V-204458 | RHEL-07-020250 | Vendor supported release |
| V-204462 | RHEL-07-020310 | Root login restricted via console |
| V-204594 | RHEL-07-040390 | SSH no root login |
| V-251702 | RHEL-07-010291 | No accounts with blank password field in shadow |

### Batch CAT1-C: Remaining CAT I (6 functions)

| VulnID | STIG ID | Title (abbreviated) |
|--------|---------|---------------------|
| V-204606 | RHEL-07-040540 | No .shosts files |
| V-204607 | RHEL-07-040550 | No shosts.equiv files |
| V-204620 | RHEL-07-040690 | No vsftpd (FTP server) |
| V-204621 | RHEL-07-040700 | No TFTP server |
| V-204627 | RHEL-07-040800 | SNMP community strings changed from default |
| V-214801 | RHEL-07-032000 | Virus scan program installed |

---

## Phase 2: CAT II Implementation (205 functions, ~14 batches)

### Batch 1: Login Banner & Display (10 functions)
RHEL-07-010030 through RHEL-07-010090 — login banner, session lock, consent notice

### Batch 2: Password Complexity (14 functions)
RHEL-07-010100 through RHEL-07-010190 — ucredit, lcredit, dcredit, ocredit, difok, minlen, minclass

### Batch 3: Password Aging & Reuse (14 functions)
RHEL-07-010200 through RHEL-07-010280 — maxdays, mindays, remember, account expiration, inactivity

### Batch 4: Authentication & PAM (16 functions)
RHEL-07-010310 through RHEL-07-010430 — PAM config, faillock, delay, SSH authentication

### Batch 5: Session & Access Control (16 functions)
RHEL-07-010460 through RHEL-07-020040 — GNOME, screensaver, umask, banners, removable media

### Batch 6: Software & System Integrity (14 functions)
RHEL-07-020100 through RHEL-07-020240 — AIDE, gpgcheck, localpkg_gpgcheck, clean requirements

### Batch 7: User & Group Management (14 functions)
RHEL-07-020260 through RHEL-07-020690 — root path, home dirs, local accounts, group membership

### Batch 8: File System Configuration (16 functions)
RHEL-07-021000 through RHEL-07-021120 — mount options (nosuid, noexec, nodev), /tmp, /var, /home

### Batch 9: File Permissions & Ownership (16 functions)
RHEL-07-021130 through RHEL-07-021620 — world-writable dirs, library files, system commands

### Batch 10: Audit System Setup (16 functions)
RHEL-07-030000 through RHEL-07-030310 — auditd enabled, space alerts, remote audit, syslog

### Batch 11: Audit Rules — User/Group & Access (16 functions)
RHEL-07-030320 through RHEL-07-030560 — passwd, group, shadow, gshadow, chmod, chown, xattr

### Batch 12: Audit Rules — Execution & Privilege (16 functions)
RHEL-07-030560 through RHEL-07-030820 — execve, mount, delete, modules, kmod, finit_module

### Batch 13: Network & Firewall (15 functions)
RHEL-07-040100 through RHEL-07-040500 — SSH config, network params, firewall, IPv6

### Batch 14: Remaining CAT II (12 functions)
RHEL-07-040510 through RHEL-07-910055 — NFS, LDAP TLS, NTP, miscellaneous

---

## Phase 3: CAT III Implementation (13 functions, 1 batch)

| VulnID | STIG ID | Title (abbreviated) |
|--------|---------|---------------------|
| V-204452 | RHEL-07-020200 | Remove unnecessary software |
| V-204461 | RHEL-07-020300 | All GIDs in passwd referenced in group |
| V-204486 | RHEL-07-021024 | /dev/shm mounted with secure options |
| V-204493 | RHEL-07-021310 | Separate /var partition |
| V-204494 | RHEL-07-021320 | Separate /var/log/audit partition |
| V-204495 | RHEL-07-021330 | Separate /tmp partition |
| V-204496 | RHEL-07-021340 | Separate /var/log partition |
| V-204498 | RHEL-07-021600 | Cron logging enabled |
| V-204499 | RHEL-07-021610 | Kernel core dumps disabled |
| V-204576 | RHEL-07-040000 | Concurrent sessions limited to 10 |
| V-204605 | RHEL-07-040530 | Display last logon date/time |
| V-204608 | RHEL-07-040600 | At least 2 DNS name servers |
| V-255927 | RHEL-07-010375 | Restrict access to kernel message buffer |

---

## Per-Batch Workflow

1. Extract XCCDF check content for batch VulnIDs
2. Implement all functions (replace stub code in custom code block)
3. Follow all 8 coding rules (no backtick-n, no bash -c, timeout+maxdepth, etc.)
4. Replace NR answer file stubs with 2-index entries
5. Validate function count: explicit functions = 244
6. Validate coding rules: zero violations
7. Validate answer file: XML well-formed, no unescaped ampersands
8. Commit to feature branch
9. User runs scan test
10. Analyze test results, fix any issues
11. Push, PR, merge

---

## Testing Commands

```powershell
# Dom0 RHEL7 only
.\Evaluate-STIG.ps1 -ComputerName vmh01.wgsdac.net -SelectSTIG XCP-ng_Dom0_RHEL7 -ScanType Classified -AnswerKey XCP-ng -VulnTimeout 15 -Output CKL,CKLB,Summary,Console -AllowIntegrityViolations

# Combined VMM + Dom0
.\Evaluate-STIG.ps1 -ComputerName vmh01.wgsdac.net -SelectSTIG "XCP-ng_VMM","XCP-ng_Dom0_RHEL7" -ScanType Classified -AnswerKey XCP-ng -VulnTimeout 15 -Output CKL,CKLB,Summary,Console -AllowIntegrityViolations
```

---

## Git Workflow

```bash
git checkout main && git pull origin main
git checkout -b feature/xcpng-dom0-cat1-batch1
# ... implement batch ...
git add <files>
git commit -m "feat: implement Dom0 RHEL7 CAT I Batch 1 — 10 functions (V-204392–V-214799)"
git push -u origin feature/xcpng-dom0-cat1-batch1
gh pr create --title "..." --body "..."
```

---

## Estimated Timeline

| Phase | Sessions | Functions |
|-------|----------|-----------|
| Phase 0: Remediation | 1 (#76) | — |
| Phase 1: CAT I | 3 (#77-79) | 26 |
| Phase 2: CAT II | 14 (#80-93) | 205 |
| Phase 3: CAT III | 1 (#94) | 13 |
| **Total** | **~19 sessions** | **244 functions** |

---

## Key Differences from VMM Module

| Aspect | VMM SRG | Dom0 RHEL7 |
|--------|---------|------------|
| Check type | Abstract VMM requirements | Concrete OS hardening |
| Primary tools | xe CLI, xapi, xenstore | rpm, yum, systemctl, auditctl, sshd |
| Configuration | Hypervisor-level | OS-level (/etc/, /var/, /usr/) |
| SELinux | Not applicable | Must check (likely Open on XCP-ng) |
| FIPS | Not applicable | Required (may be compliance gap) |
| Audit | xapi logs | auditd rules and configuration |
| SSH | Hypervisor SSH access | Full sshd_config hardening |
| Password | Account policies | PAM complexity rules |
| Firewall | Network isolation | iptables/firewalld |
| Packages | N/A | rpm -q, yum list |
