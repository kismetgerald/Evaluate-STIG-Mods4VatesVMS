# Vates Virtualization Management Stack — Automated Compliance Implementation Report

**Prepared for:** Vates Engineering Team
**Prepared by:** Kismet Agbasi
**Date:** March 15, 2026
**Version:** 2.0 (Full stack: XO + XCP-ng — all 5 modules, 1,047 automated checks)

---

## 1. Executive Summary

This report presents the results of a comprehensive security compliance assessment of the **Vates Virtualization Management Stack** — both **Xen Orchestra** (management console) and **XCP-ng** (Type 1 hypervisor) — conducted as part of the effort to approve the platform for use in secure and/or air-gapped environments.

There are currently **no official security compliance benchmarks or automated scanning profiles** for Xen Orchestra or XCP-ng. To address this gap, we developed a custom automated scanning framework with five purpose-built modules that map applicable Security Requirements Guides (SRGs) and existing security baselines to the Vates platform. The assessment provides **defense-in-depth coverage** across all layers of the virtualization stack — from the host operating system through the hypervisor to the management application.

### Assessment Scope

| Component | Module | Security Baseline Applied | Rules | Status |
|-----------|--------|--------------------------|-------|--------|
| **Xen Orchestra** | Application Security (ASD) | Application Security and Development STIG V6R4 | 286 | 100% Automated |
| **Xen Orchestra** | Web Server (WebSRG) | Web Server Security Requirements Guide V4R4 | 126 | 100% Automated |
| **Xen Orchestra** | Operating System (GPOS) | General Purpose OS SRG V3R2 (Debian 12) | 198 | 100% Automated |
| **XCP-ng** | Hypervisor (VMM) | Virtual Machine Manager SRG V2R2 | 193 | 100% Automated |
| **XCP-ng** | Host OS (Dom0 RHEL7) | Red Hat Enterprise Linux 7 STIG V3R15 (adapted) | 244 | 100% Automated |
| | **Total** | **5 Security Baselines** | **1,047** | **100% Automated** |

### Why These Five Baselines?

**Xen Orchestra** is a Node.js web application running on Debian 12, requiring assessment at three layers:
1. **ASD STIG** — application layer (authentication, session management, input validation, cryptography)
2. **Web Server SRG** — HTTPS service layer (TLS configuration, access control, logging)
3. **GPOS SRG** — underlying Debian 12 OS (account management, audit, system hardening)

**XCP-ng** is a Type 1 bare-metal hypervisor running a CentOS 7-based Dom0, requiring assessment at two layers:
4. **VMM SRG** — hypervisor layer (VM isolation, resource management, privilege separation, encryption)
5. **RHEL 7 STIG** (adapted for CentOS 7 Dom0) — host OS (SSH hardening, audit rules, PAM, file permissions, kernel parameters)

### Understanding Severity Categories (CAT I / CAT II / CAT III)

Each security rule is assigned a severity category that reflects the potential impact if the requirement is not met:

| Category | Severity | Meaning |
|----------|----------|---------|
| **CAT I** | Critical | Directly and immediately results in loss of confidentiality, availability, or integrity. These are the most serious findings — for example, using non-validated cryptography for sensitive data or running with known critical vulnerabilities. CAT I findings typically must be resolved (or have an approved remediation plan) before a system can receive authorization. |
| **CAT II** | High | Has significant potential to lead to loss of confidentiality, availability, or integrity. Examples include missing login banners, weak password policies, or TLS misconfigurations. CAT II findings represent the bulk of most assessments and are expected to be addressed, though they are less urgent than CAT I. |
| **CAT III** | Medium | Could degrade security measures or indirectly lead to loss of confidentiality, availability, or integrity. These are lower-priority items such as informational logging gaps or minor configuration deviations. They should still be addressed but carry less risk than CAT I or CAT II. |

In the results tables throughout this report, each rule is categorized as one of: **NotAFinding** (compliant), **Open** (non-compliant — requires remediation), **Not Applicable** (rule does not apply to this system), or **Not Reviewed** (assessment could not determine status).

### Key Results

**Xen Orchestra** — scanned on XO1 (XOCE) and XOA (Appliance):

| Metric | XO1 (XOCE) | XOA (Appliance) |
|--------|-----------|-----------------|
| **GPOS EvalScore** | 46.46% | 48.48% |
| **ASD EvalScore** | 43.36% | 40.56% |
| **WebSRG EvalScore** | 42.86% | 41.27% |
| **Not Reviewed** | 0 | 0 |
| **Errors** | 0 | 0 |

**XCP-ng** — scanned on VMH01 (XCP-ng 8.3):

| Metric | VMH01 |
|--------|-------|
| **VMM EvalScore** | 34.72% |
| **Dom0 RHEL7 EvalScore** | 42.21% |
| **Not Reviewed** | 1 |
| **Errors** | 0 |

**Note on EvalScores:** These scores reflect honest, automated assessment results. Many Open findings represent genuine product gaps (FIPS cryptography, mandatory login banner) or organizational configuration requirements (password policy, audit infrastructure, disk encryption). The scores are not inflated — every finding is backed by automated evidence in the generated compliance checklists (CKL/CKLB files).

**Note on Vates Hardening Guide:** During the preparation of this report, we identified the *Vates VMS Hardening Guide* (v0.1, May 2024), a 57-page vendor-published document covering security recommendations for both XCP-ng and Xen Orchestra. This guide addresses several areas we initially believed had no vendor guidance. Its existence and coverage are reflected throughout this report, along with recommendations for expanding it to address compliance-specific requirements.

---

## 2. Systems Under Test

### 2.1 XO1 — Xen Orchestra Community Edition (XOCE)

| Attribute | Value |
|-----------|-------|
| Hostname | xo1.wgsdac.net |
| IP Address | 10.0.10.27 |
| OS | Debian GNU/Linux 12 (bookworm) |
| Architecture | x86_64 |
| XO Install Path | /opt/xo/ |
| Firewall | Not configured (no default firewall) |
| Auth-LDAP Plugin | Active (file-based detection) |
| Audit Plugin | Active (REST API detection) |
| Modules Scanned | GPOS, ASD, WebSRG (3 modules, 610 rules) |

### 2.2 XOA — Xen Orchestra Appliance

| Attribute | Value |
|-----------|-------|
| Hostname | xoa.wgsdac.net |
| IP Address | 10.0.10.40 |
| OS | Debian GNU/Linux 12 (bookworm) |
| Architecture | x86_64 |
| XO Install Path | /usr/share/xo-server/ |
| Firewall | UFW enabled (Vates default) |
| Auth-LDAP Plugin | Active (REST API user detail detection) |
| Audit Plugin | Active (REST API detection) |
| Plugin Naming | Uses `-premium` suffix (e.g., `xo-server-auth-ldap-premium`) |
| Modules Scanned | GPOS, ASD, WebSRG (3 modules, 610 rules) |

### 2.3 VMH01 — XCP-ng Hypervisor Host

| Attribute | Value |
|-----------|-------|
| Hostname | WGSDAC-SV-VMH01 (vmh01.wgsdac.net) |
| IP Addresses | 10.0.10.23 (management), 10.0.20.23 (storage) |
| Hardware | HP ProLiant DL360p Gen8 |
| Serial Number | USE233C3E7 |
| OS | XCP-ng 8.3 (CentOS 7-based Dom0) |
| Architecture | x86_64 |
| PowerShell | 7.3.12 (7.4+ incompatible due to glibc) |
| Storage | 1.05 TiB local (XSLocalEXT SR) |
| Modules Scanned | VMM, Dom0 RHEL7 (2 modules, 437 rules) |

---

## 3. Detailed Results by Module

### 3.1 General Purpose Operating System (GPOS) — Debian 12

**Target:** Xen Orchestra (XO1 / XOA)
**Baseline:** General Purpose Operating System SRG V3R2
**Rules:** 198

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 18 | 1 | 7 | 10 | 0 |
| **CAT II** (High) | 170 | 2 | 74 (XO1) / 78 (XOA) | 94 (XO1) / 90 (XOA) | 0 |
| **CAT III** (Medium) | 10 | 0 | 8 | 2 | 0 |

**EvalScore:** 46.46% (XO1) / 48.48% (XOA)

**XOA scores higher** because:
- UFW firewall enabled by default (3 additional NotAFinding: V-203638, V-203687, V-203722)
- AD/LDAP auth-ldap plugin detected via REST API (1 additional NotAFinding)

**Compensating Controls Applied:**
- **XO Audit Plugin (18 functions):** The XO Audit Plugin provides application-layer auditing with hash chain integrity, satisfying audit requirements where the traditional `auditd` daemon is not installed. These 18 functions return NotAFinding when the audit plugin is active.
- **AD/LDAP auth-ldap (5 functions):** Functions checking account notification and MFA for network access are satisfied when authentication is delegated to Active Directory via the auth-ldap plugin.

### 3.2 Application Security and Development (ASD)

**Target:** Xen Orchestra (XO1 / XOA)
**Baseline:** Application Security and Development STIG V6R4
**Rules:** 286

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 34 | 5 | 13 | 16 | 0 |
| **CAT II** (High) | 230 | 38 | 62 | 130 | 0 |
| **CAT III** (Medium) | 22 | 5 | 1 | 16 | 0 |

**EvalScore:** 43.36% (XO1) / 40.56% (XOA)

**XO1 scores higher** because XOCE has more Not_Applicable determinations (community edition lacks certain enterprise features that would be assessed).

### 3.3 Web Server Security Requirements Guide (WebSRG)

**Target:** Xen Orchestra (XO1 / XOA)
**Baseline:** Web Server Security Requirements Guide V4R4
**Rules:** 126

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 5 | 0 | 3 | 2 | 0 |
| **CAT II** (High) | 121 | 2 | 49 | 70 | 0 |
| **CAT III** (Medium) | 0 | 0 | 0 | 0 | 0 |

**EvalScore:** 42.86% (XO1) / 41.27% (XOA)

### 3.4 Virtual Machine Manager (VMM)

**Target:** XCP-ng Hypervisor (VMH01)
**Baseline:** Virtual Machine Manager SRG V2R2
**Rules:** 193

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 0 | 0 | 0 | 0 | 0 |
| **CAT II** (High) | 193 | 2 | 65 | 126 | 0 |
| **CAT III** (Medium) | 0 | 0 | 0 | 0 | 0 |

**EvalScore:** 34.72%

**Note:** The VMM SRG classifies all 193 rules as CAT II. There are no CAT I or CAT III rules in this baseline.

**Key areas assessed:**
- **VM Isolation:** Guest separation, memory protection, device passthrough controls
- **Hypervisor Access Control:** RBAC via xe CLI, Dom0 access restrictions, XAPI authentication
- **Resource Management:** CPU pinning, memory limits, storage quotas, network isolation
- **Cryptography:** XAPI TLS configuration, storage encryption, VM migration security
- **Audit:** xen.log event recording, xe CLI audit trail, API access logging
- **System Integrity:** Boot verification, pool-wide settings, update management

**Primary compliance gaps (hypervisor layer):**
- No FIPS-validated cryptographic modules in XAPI
- Limited native audit granularity (relies on Dom0 auditd)
- No built-in change management workflow for VM configuration changes

### 3.5 Dom0 Operating System (RHEL 7 STIG Adapted)

**Target:** XCP-ng Dom0 (VMH01)
**Baseline:** Red Hat Enterprise Linux 7 STIG V3R15 (adapted for CentOS 7 Dom0)
**Rules:** 244

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 26 | 5 | 11 | 9 | 1 |
| **CAT II** (High) | 205 | 23 | 61 | 121 | 0 |
| **CAT III** (Medium) | 13 | 0 | 3 | 10 | 0 |

**EvalScore:** 42.21%

**RHEL 7 STIG Adaptation Notes:**

The RHEL 7 STIG was selected because XCP-ng 8.3's Dom0 is based on CentOS 7. This is a legitimate adaptation — the same approach is used industry-wide for CentOS, Oracle Linux, and other RHEL-derivative distributions. Key adaptation considerations:

- **SELinux:** XCP-ng Dom0 ships with SELinux disabled. SELinux-dependent checks return Not_Applicable where SELinux enforcement is required but does not exist. This is a known compliance gap.
- **GNOME/GUI:** Dom0 has no graphical interface. Desktop-related checks return Not_Applicable (5 CAT I rules).
- **NetworkManager:** XCP-ng does not use NetworkManager; network checks use `ip link` and XAPI network configuration instead.
- **Package management:** Uses `yum`/`rpm` with XCP-ng repositories, not Red Hat subscriptions.

**Primary compliance gaps (Dom0 layer):**
- FIPS mode not enabled (CAT I — multiple findings)
- SELinux disabled (CAT I — V-204497)
- Password hashing algorithm not SHA-512 in all contexts
- Missing AIDE/Tripwire file integrity monitoring
- Audit rules not fully configured for privileged operations

---

## 4. Findings Requiring Vates Action

The following findings cannot be resolved through system configuration alone. They require product changes, official guidance, or feature development from Vates.

### 4.1 CRITICAL — FIPS 140-2 Cryptography (CAT I)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | CRYPT-001 |
| **Affected Components** | Xen Orchestra + XCP-ng Dom0 |
| **Affected VulnIDs** | V-206391, V-206434, V-239371, V-222425 (XO); V-204497, V-204502 (Dom0); V-203603, V-203669, V-203739, V-203776 (GPOS) |
| **Severity** | CAT I |
| **Impact** | 10+ Open findings across 4 modules |

**Finding:** Neither Xen Orchestra nor XCP-ng Dom0 operates in FIPS 140-2 validated mode. XO uses **bcrypt** for local password hashing (cryptographically strong but not FIPS-validated). Dom0's CentOS 7 base does not have FIPS mode enabled by default, and the XCP-ng kernel may not support `fips=1` boot parameter.

**Compliance Requirement:** All cryptographic operations in regulated environments must use FIPS 140-2 validated modules per NIST SP 800-53 SC-13.

**Recommended Actions for Vates:**
1. **Publish official statement** on FIPS 140-2 compliance roadmap for both XO and XCP-ng
2. **For XO:** Provide LDAP/AD integration guidance as the recommended authentication method — this delegates password hashing to FIPS-validated directory services
3. **For XCP-ng Dom0:** Document whether `fips=1` kernel boot parameter is supported and test its impact on hypervisor operations
4. **Long-term:** Consider replacing bcrypt with PBKDF2 (NIST SP 800-132 approved) for XO local accounts
5. **Document** which cryptographic libraries are used across the stack (OpenSSL versions, GnuTLS, etc.) and their FIPS validation status

### 4.2 CRITICAL — No Mandatory Notice and Consent Banner (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | BANNER-001 |
| **Affected Components** | Xen Orchestra (web UI) + XCP-ng Dom0 (SSH) |
| **Affected VulnIDs** | V-222434, V-222435 (ASD); V-203595, V-203596, V-203665 (GPOS); Dom0 SSH banner |
| **Severity** | CAT II |
| **Impact** | 5+ Open findings across ASD, GPOS, and Dom0 modules |

**Finding:** Xen Orchestra has **no built-in mechanism** to display a mandatory notice and consent banner before granting access. XCP-ng Dom0 SSH does not ship with a consent banner configured in `/etc/issue.net`.

**Compliance Requirement:** The organization's standard mandatory notice and consent banner must be displayed, and users must explicitly acknowledge it before login proceeds.

**Recommended Actions for Vates:**
1. **Near-term (nginx reverse proxy):** Publish an nginx configuration template that implements a consent page before the XO login. XOA already ships with nginx — this could be a configuration addition.
2. **Long-term (native feature):** Add a configurable pre-login banner to the XO web UI with acknowledgment requirement. Suggested `config.toml` configuration:
   ```toml
   [loginBanner]
   enabled = true
   text = "You are accessing an organizational information system..."
   requireAcknowledgment = true
   ```
3. **For XCP-ng Dom0:** Include a configurable SSH banner template in the Dom0 hardening recommendations (this is site-configurable but should be documented)

### 4.3 HIGH — MFA/2FA Detection Now Automated (CAT II) — PARTIALLY RESOLVED

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | AUTH-001 |
| **Affected Components** | Xen Orchestra |
| **Affected VulnIDs** | V-264343 (WebSRG), V-264344 (WebSRG), V-203642 (GPOS), V-203643 (GPOS) |
| **Severity** | CAT II |
| **Impact** | V-264343 now flips Open &rarr; NotAFinding when all users have 2FA enabled. 3 remaining VulnIDs still require manual review. |

**Update (v1.2, March 4, 2026):** The scanner detection gap for V-264343 has been **resolved**. Our scanner now detects XO's native TOTP 2FA per-user via the REST API:

- **Detection method:** Queries `GET /rest/v0/users` to enumerate all user accounts, then inspects each user's `preferences.otp` field. If the field contains a Base32-encoded TOTP secret, that user has 2FA enabled.
- **Status logic:** If ALL users have `preferences.otp` present &rarr; NotAFinding. If any user lacks it &rarr; Open with a list of non-compliant users.
- **Also detects:** LDAP/AD auth-ldap plugin and SAML/OIDC plugin presence as supplementary evidence.

**Remaining open items:**
- **V-264344** (WebSRG) — Organizational MFA strength/policy verification; cannot be fully automated (requires security officer attestation)
- **V-203642, V-203643** (GPOS) — OS-level PAM/SSH MFA checks; XO's application-level 2FA does not satisfy these OS-level requirements

**Discovery:** XO stores 2FA configuration as `preferences.otp` in the user object within its LevelDB database at `/var/lib/xo-server/data/leveldb/`. The REST API exposes this field (including the actual TOTP secret in plaintext — Vates should consider returning a boolean instead).

**Security observations:**
- **Token invalidation on 2FA enablement:** Enabling 2FA invalidates all existing API tokens. This is correct security behavior — it forces re-authentication through the 2FA flow. Sysadmins must regenerate API tokens via the XO web UI after enabling 2FA.
- **REST API authentication method:** XO's REST API requires `Cookie: authenticationToken=<token>` — the standard `Authorization: Bearer <token>` header returns "invalid credentials." This is undocumented and may cause integration issues for third-party tools expecting Bearer auth.
- **TOTP secret exposure:** The REST API returns the actual Base32-encoded TOTP secret in the `preferences.otp` field rather than a boolean or masked value. An attacker with API access could extract TOTP secrets and clone authenticator tokens, defeating the purpose of 2FA.
- **Rate limiting:** XO enforces "too fast authentication tries" rate limiting on the REST API after failed auth attempts — this is good security practice but should be documented with retry guidance.

**Recommended Actions for Vates:**
1. **PRIORITY: Mask TOTP secrets in REST API** — return `"otp": true` instead of the actual Base32 secret to prevent credential exposure via API. This is a vulnerability that could allow TOTP cloning by any user with API access.
2. **Document REST API authentication method** — clarify that the REST API uses `Cookie: authenticationToken=<token>` rather than `Authorization: Bearer <token>`, and document the token lifecycle (generation, invalidation on 2FA changes, rate limiting behavior)
3. **Publish compliance-specific MFA configuration guide** showing how to integrate XO with smart card / hardware token authentication via SAML/OIDC (e.g., Keycloak + smart card)
4. **Document which 2FA methods are FIDO2/U2F compliant** for regulated environments
5. **Note:** AD-delegated authentication via auth-ldap also satisfies network access MFA when AD enforces MFA policies

### 4.4 HIGH — TLS 1.1 Still Enabled (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | TLS-001 |
| **Affected Components** | Xen Orchestra |
| **Affected VulnIDs** | V-206439, V-206352, V-206353 |
| **Severity** | CAT II |
| **Impact** | 3 Open findings in WebSRG module |

**Finding:** TLS 1.1 is enabled alongside TLS 1.2/1.3 on XO systems.

**Compliance Requirement:** Minimum TLS 1.2 required. TLS 1.0 and TLS 1.1 must be disabled.

**Recommended Actions for Vates:**
1. **Publish hardening guide** with exact steps to disable TLS 1.1 in XO (config.toml, nginx, or Node.js configuration)
2. **Consider disabling TLS 1.1 by default** in future XO/XOA releases
3. **For XOA:** Provide a one-command hardening script that enforces TLS 1.2+ minimum

### 4.5 HIGH — Virtual Disk Devices Lack Unique Hardware Identifiers (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | ASSET-001 |
| **Affected Components** | All VMs running on XCP-ng (XOA, XOCE, and any guest VM) |
| **Severity** | CAT II (asset identification and inventory compliance) |
| **Impact** | Guest VMs cannot inventory or uniquely identify their virtual disks |

**Finding:** Xen paravirtualized (PV) block devices (e.g., `/dev/xvda`, `/dev/xvdb`) expose **no hardware identification metadata** to guest operating systems. Standard Linux disk interrogation tools (`lsblk`, `udevadm`, `/sys/block/`) return empty values for Model, Serial Number, and Transport type. In contrast, QEMU-emulated devices on the same host (e.g., `/dev/sr0`) correctly expose all identification fields.

| Device | Type | Model | Serial Number | Transport | Identifiable? |
|--------|------|-------|---------------|-----------|---------------|
| `/dev/sr0` | QEMU emulated | QEMU DVD-ROM | QM00004 | ATA | Yes |
| `/dev/xvda` | Xen PV block | *(empty)* | *(empty)* | *(empty)* | **No** |

**Why This Matters for Compliance:**

Federal security frameworks mandate that all hardware components be uniquely identifiable:

- **NIST SP 800-53 CM-8 (Component Inventory):** Organizations must maintain an accurate inventory of system components. Disk devices without serial numbers or model identifiers cannot be positively inventoried.
- **NIST SP 800-53 CM-3 (Configuration Change Control):** Change detection requires identifying *which specific component* changed. Indistinguishable virtual disks prevent this.
- **CNSSI 1253:** For high-impact systems, hardware asset tracking must support chain-of-custody verification. A virtual disk that cannot be uniquely identified breaks the chain of evidence.
- **DISA STIG SI-7 (Integrity):** Integrity verification requires unique component identification.

**The information exists — it's just not exposed to guests.** XCP-ng's XAPI maintains rich VDI metadata (UUID, SR association, size) but the Xen PV block driver (`xen-blkfront`) does not propagate it to the guest OS.

**Precedent:** QEMU/KVM hypervisors routinely expose virtual disk serial numbers to guests via virtio-blk. AWS EBS volumes expose volume IDs as serial numbers to EC2 instances. VMware and Hyper-V similarly expose virtual disk identifiers. XCP-ng is the outlier among enterprise hypervisors.

**Recommended Actions for Vates:**
1. **[HIGH]** Expose VDI UUID as virtual disk serial number to guest VMs via the Xen PV block driver (`xen-blkfront` sysfs attributes)
2. **[HIGH]** Expose SR name or "XCP-ng VDI" as the model string for virtual disk devices
3. **[MEDIUM]** Document the VDI-to-VBD-to-guest-device mapping for auditors
4. **[MEDIUM]** Consider extending `xe vbd-param-set` to allow custom serial/model strings per VBD (similar to libvirt's `<serial>` element)

### 4.6 HIGH — CentOS 7 End-of-Life in Dom0 (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | EOL-001 |
| **Affected Components** | XCP-ng Dom0 |
| **Severity** | CAT II |
| **Impact** | Assessors will flag CentOS 7 EOL (June 2024) as a risk |

**Finding:** XCP-ng 8.3 Dom0 is based on CentOS 7, which reached end-of-life in June 2024. While XCP-ng maintains its own security patches for the Dom0 kernel and hypervisor components, the base OS packages no longer receive upstream RHEL 7 security updates.

**Compliance Requirement:** Operating systems must be supported by the vendor with security updates (NIST SP 800-53 SI-2, DISA STIG).

**Recommended Actions for Vates:**
1. **Publish a clear statement** documenting XCP-ng's security update strategy for Dom0 — specifically which components receive patches, the update cadence, and the SLA for critical security patches
2. **Document the roadmap** for migrating Dom0 to a newer base OS in future XCP-ng releases
3. **Provide a security errata feed** that assessors can reference to verify patch currency

### 4.7 HIGH — SELinux Disabled on Dom0 (CAT I)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | MAC-001 |
| **Affected Components** | XCP-ng Dom0 |
| **Affected VulnIDs** | V-204497 (RHEL 7 STIG) |
| **Severity** | CAT I |
| **Impact** | 1 CAT I Open finding |

**Finding:** XCP-ng Dom0 ships with SELinux disabled. The RHEL 7 STIG requires SELinux in Enforcing mode. Enabling SELinux on Dom0 may conflict with hypervisor operations and has not been validated by Vates.

**Recommended Actions for Vates:**
1. **Publish an official position** on SELinux support in Dom0 — whether it can be safely enabled, and if not, what compensating controls exist
2. **If SELinux cannot be enabled:** Document the Xen hypervisor's inherent isolation mechanisms as compensating controls (hardware-enforced VM isolation, Dom0 privilege separation, XAPI access controls)
3. **Long-term:** Consider SELinux policy development for Dom0 in future XCP-ng releases

### 4.8 HIGH — Hardening Guide Exists but Needs Compliance-Specific Expansion (Multiple CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | GUIDE-001 |
| **Affected Components** | Xen Orchestra + XCP-ng |
| **Affected VulnIDs** | Multiple (40+ findings addressable with configuration) |
| **Severity** | CAT II |
| **Impact** | Many Open findings could be resolved with expanded vendor guidance |

**Finding:** The *Vates VMS Hardening Guide* (v0.1, May 2024, 57 pages) exists and covers many general security topics. This is a strong foundation. However, it does not address specific compliance requirements for regulated environments, and some topics need step-by-step technical procedures to be actionable.

**What the existing guide covers well:**
| Topic | Guide Section | Coverage |
|-------|-------------|----------|
| Network segmentation (mgmt, storage, VM) | 3.2 | Comprehensive |
| NTP/time synchronization | 4.4.2 | Conceptual guidance |
| Remote syslog | 4.4.3 | Conceptual guidance |
| SSH disabling | 4.4.4 | Step-by-step with screenshots |
| Audit plugin | 4.4.5 | Feature description + enablement |
| MFA/2FA (SAML, OIDC, hardware tokens) | 5.4 | Feature description |
| ACLs and LDAP/AD integration | 5.5 | Feature description |
| REST API token management | 5.8.1 | Security best practices |
| HTTPS enforcement | 7.1 | Recommendation |
| Privilege management | 7.2 | Conceptual guidance |
| Backup security | 8.x | Comprehensive |

**What the existing guide does NOT cover (compliance-specific gaps):**

| Topic | Specific Guidance Needed | Applies To |
|-------|---------------------------------------|------------|
| **Mandatory consent banner** | nginx config template for mandatory notice and consent | XO |
| **Password policy** | PAM configuration for 15-char minimum, complexity, aging | XO + Dom0 |
| **Account lockout** | PAM faillock configuration for 3-attempt lockout in 15 min | XO + Dom0 |
| **Session timeout** | SSH ClientAliveInterval and web session inactivity values | XO + Dom0 |
| **Certificate management** | Replace self-signed certificates with organization-signed PKI | XO + XAPI |
| **Disk encryption** | LUKS configuration for data-at-rest protection | XO + Dom0 |
| **File permissions** | Specific permission requirements for audit tools and log files | XO + Dom0 |
| **Kernel parameters** | Recommended sysctl settings for security compliance | XO + Dom0 |
| **Smart card / hardware token** | Step-by-step SAML/OIDC config for smart card auth | XO |
| **FIPS 140-2** | Cryptographic module configuration and compliance status | XO + Dom0 |
| **SELinux/AppArmor** | Mandatory access control configuration guidance | Dom0 + XO |
| **Dom0 audit rules** | auditd rule configuration for RHEL 7 STIG compliance | Dom0 |

**Recommended Actions for Vates:** Expand the existing hardening guide (or publish a compliance supplement) with the specific technical procedures listed above. The existing guide provides an excellent framework — adding compliance-specific sections would make it a complete reference for both XO and XCP-ng.

### 4.9 CRITICAL — XCP-ng Requires Root Account for XO Connection (CAT I/CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | AUTH-003 |
| **Affected Components** | XCP-ng Dom0 (all hosts) + Xen Orchestra (management connection) |
| **Severity** | CAT I/CAT II (privilege separation, least privilege, account management) |
| **Impact** | 10-15+ Open findings across VMM and Dom0 RHEL7 modules |

**Finding:** Xen Orchestra connects to XCP-ng hosts **exclusively via the root account**. There is no supported mechanism to use an alternate administrator account. This creates a cascade of compliance failures:

1. **The root account cannot be locked or disabled** — XO requires it to manage the hypervisor
2. **Root SSH login must remain enabled** — violating SSH hardening STIGs requiring `PermitRootLogin no`
3. **No privilege separation** — all management operations run as root, violating least privilege
4. **No individual accountability** — when multiple administrators access Dom0, all operations execute as root, making it impossible to attribute actions to specific individuals
5. **Key-based authentication not enforced** — the default XO-to-XCP-ng connection uses password auth

| STIG Requirement | VulnID Examples | Why It's Open |
|-----------------|----------------|---------------|
| Prohibit direct root login | V-204425, V-204428 | Root login required for XO connection |
| Enforce least privilege | V-207370, V-207383 | All operations run as root |
| Individual accountability | V-207338, V-207347 | Shared root prevents user attribution |
| SSH access restrictions | V-204594, V-204595 | Root SSH must remain open |
| Account lockout | V-204419 | Cannot lock root — would lock out XO |

**Precedent:** VMware ESXi supports non-root administrative accounts and AD-integrated authentication. Microsoft Hyper-V uses AD domain accounts. Proxmox VE supports PAM, LDAP, and AD authentication with RBAC. XCP-ng's mandatory root requirement is the outlier among enterprise hypervisors.

**Recommended Actions for Vates:**
1. **[CRITICAL]** Enable XO to connect to XCP-ng using a non-root service account with appropriate XAPI privileges
2. **[HIGH]** Support key-based authentication as the default method for XO-to-XCP-ng connections
3. **[HIGH]** Document a supported procedure for locking down root once an alternate admin account is configured
4. **[HIGH]** Ensure `sudo` is properly configured on Dom0 for privilege escalation with audit logging
5. **[MEDIUM]** Support individual named accounts for direct SSH access to Dom0

### 4.10 HIGH — XCP-ng Dom0 Lacks External Identity Provider Integration (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | AUTH-002 |
| **Affected Components** | XCP-ng Dom0 (all hosts) |
| **Severity** | CAT II (authentication, account management, MFA delegation) |
| **Impact** | 20-29 Open findings in Dom0 RHEL7 module could be resolved or mitigated |

**Finding:** XCP-ng Dom0 has **no supported mechanism for integrating with an external identity provider** such as Active Directory or LDAP. All authentication is performed against local accounts.

**Why This Matters — Lessons Learned from Xen Orchestra:**

During the XO assessment, the **auth-ldap plugin** proved transformative. When XO authentication is delegated to Active Directory:
- **5 GPOS functions flipped from Open to NotAFinding** (centralized account lifecycle)
- **4 additional functions benefited** from AD as supplementary evidence
- **MFA requirements partially satisfied** — AD enforces organizational MFA policies
- **Account notification requirements met** — AD provides centralized audit and notification

The same pattern would apply to Dom0. CentOS 7 supports AD integration via SSSD/realmd. If Vates officially supported this, 20-29 Dom0 findings could be resolved:

| Finding Area | Approx. Count | How AD Helps |
|-------------|---------------|-------------|
| Account management (creation, modification, disabling) | 5-8 | Centralized lifecycle |
| Password policy (complexity, aging, history) | 8-10 | AD enforces policy |
| MFA/multi-factor authentication | 2-3 | AD enforces MFA |
| Account notification and auditing | 3-5 | Centralized audit trail |
| Individual accountability | 2-3 | Named AD accounts |
| **Total** | **20-29** | **~8-12% EvalScore improvement** |

**Precedent:** VMware ESXi supports AD integration for host authentication — a standard feature in enterprise hypervisors.

**Recommended Actions for Vates:**
1. **[HIGH]** Validate and document whether SSSD/realmd AD integration is safe on XCP-ng Dom0
2. **[HIGH]** If supported: publish step-by-step configuration guide for AD-joining Dom0
3. **[MEDIUM]** Ensure SSSD packages are available in XCP-ng repositories
4. **[MEDIUM]** Document interaction between AD-joined Dom0 and XAPI pool operations

---

## 5. Findings Addressable by Site Configuration

These findings are Open but can be resolved by the deploying organization without Vates product changes. They should be included in a security compliance deployment checklist.

### 5.1 Xen Orchestra — Site-Configurable Findings

#### PAM / Password Policy (12 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203625 thru V-203628 | Password complexity (upper, lower, numeric, special) | Configure `/etc/security/pwquality.conf` |
| V-203631, V-203632 | Password lifetime (1-day min, 60-day max) | Configure `/etc/login.defs` |
| V-203634 | 15-character minimum | `minlen = 15` in pwquality.conf |
| V-203594 | Account lockout after 3 failures | Configure PAM faillock module |
| V-203676 | Special character requirement | `ocredit = -1` in pwquality.conf |
| V-203648 | Disable accounts after 35 days inactivity | `useradd -D -f 35` |
| V-203652 | Remove emergency accounts after 72 hours | Organizational process |

#### PKI / Certificate Management (4 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203622 | PKI certificate path validation | Install organizational root CA certificates |
| V-203623 | Private key access enforcement | Verify key file permissions (600) |
| V-203624 | Map authenticated identity to user | Configure PAM/SSSD for PKI |
| V-206388 | RFC 5280 certificate validation | Replace self-signed with organization-signed cert |

#### Audit System Infrastructure (12 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203613, V-203614 | Centralized audit review and filtering | Deploy SIEM + rsyslog |
| V-203615 | Internal system clocks for timestamps | Configure NTP/chrony + auditd |
| V-203616, V-203617 | Protect audit info from unauthorized access/modification | Set audit log permissions |
| V-203620 | Security officer controls auditable events | Document audit configuration authority |
| V-203670 | Boot-time audit initiation | Install and enable auditd |
| V-203672 thru V-203674 | Protect audit tools | Set AIDE/Tripwire for integrity |

#### System Hardening (8 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203595, V-203596, V-203665 | Mandatory consent banner | SSH: configure `/etc/issue.net`; Web: see Section 4.2 |
| V-203598 thru V-203601 | Session lock (15-min timeout, re-auth) | Configure tmux/screen auto-lock; SSH ClientAliveInterval |
| V-203637 | Disable non-essential capabilities | Remove unnecessary packages/services |
| V-203636 | Enforce access control policies | Configure sudo, file permissions, AppArmor |

#### Data Protection (3 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203661 | Protect information at rest | Enable LUKS on data partitions |
| V-203745, V-203746 | Prevent unauthorized modification/disclosure at rest | Full disk encryption with LUKS |
| V-206407 | Data at rest encryption (WebSRG) | LUKS + XO data directory encryption |

### 5.2 XCP-ng Dom0 — Site-Configurable Findings

#### SSH Hardening (15+ findings)

| Area | Requirement | Remediation |
|------|-------------|-------------|
| SSH Banner | Display mandatory consent banner | Configure `/etc/issue.net` and `Banner` in sshd_config |
| SSH Protocol | Disable weak ciphers, MACs, key exchange | Configure `Ciphers`, `MACs`, `KexAlgorithms` in sshd_config |
| SSH Timeout | Session inactivity lockout | `ClientAliveInterval 600`, `ClientAliveCountMax 0` |
| SSH Access | Restrict root login | `PermitRootLogin no` (requires alternate admin account) |

#### PAM / Password Policy (10+ findings)

| Area | Requirement | Remediation |
|------|-------------|-------------|
| Password complexity | Upper, lower, numeric, special characters | Configure `/etc/security/pwquality.conf` |
| Password aging | Minimum/maximum lifetime | Configure `/etc/login.defs` |
| Account lockout | Lock after 3 failures in 15 minutes | Configure PAM faillock in `/etc/pam.d/` |
| Password hashing | SHA-512 for stored passwords | Verify `/etc/login.defs` ENCRYPT_METHOD |

#### Audit System (20+ findings)

| Area | Requirement | Remediation |
|------|-------------|-------------|
| Audit daemon | Enable auditd at boot | `systemctl enable auditd` |
| Audit rules | Privileged command execution, file access | Configure `/etc/audit/rules.d/` |
| Log protection | Restrict audit log access | Set permissions on `/var/log/audit/` |
| Remote logging | Forward logs to SIEM | Configure rsyslog remote forwarding |

#### File Integrity and System Configuration

| Area | Requirement | Remediation |
|------|-------------|-------------|
| File integrity | AIDE or Tripwire monitoring | Install and configure AIDE |
| Kernel parameters | Security-related sysctl settings | Configure `/etc/sysctl.d/` |
| GRUB password | Boot loader authentication | Set GRUB2 superuser password |

---

## 6. Compensating Controls in Use

The assessment framework recognizes the following controls as compensating evidence:

### 6.1 XO Audit Plugin (Xen Orchestra)

The XO Audit Plugin provides application-layer auditing that compensates for the absence of the traditional Linux `auditd` daemon:

| Feature | Detail |
|---------|--------|
| **Event Recording** | All user actions: login, VM operations, permission changes, configuration changes |
| **Integrity** | Hash chain — each record cryptographically linked to its parent |
| **Tamper Detection** | Daily hash upload to Vates for external verification |
| **API Access** | REST API at `GET /rest/v0/plugins/audit/records` |
| **Impact** | 18 GPOS audit functions return NotAFinding instead of Open |

### 6.2 AD/LDAP auth-ldap Plugin (Xen Orchestra)

When authentication is delegated to Active Directory via the XO auth-ldap plugin:

| Feature | Detail |
|---------|--------|
| **Account Lifecycle** | AD provides centralized account creation, modification, disabling, removal |
| **Notification** | AD includes built-in notification for account events |
| **MFA (Network)** | AD enforces MFA policies for network access |
| **Impact** | 5 GPOS functions return NotAFinding; 4 additional functions benefit |

### 6.3 XOA Deployment Model (Xen Orchestra)

XOA (the official Vates appliance) provides additional security controls:

| Feature | Detail |
|---------|--------|
| **UFW Firewall** | Enabled by default — satisfies 3 firewall requirements |
| **Plugin Management** | Centralized plugin configuration via Vates licensing |
| **GPOS Score Impact** | XOA scores 48.48% vs XOCE 46.46% (+2.02%) |

### 6.4 Xen Hypervisor Isolation (XCP-ng)

XCP-ng leverages Xen's hardware-enforced VM isolation as a compensating control for several VMM SRG requirements:

| Feature | Detail |
|---------|--------|
| **Hardware Isolation** | Each VM runs in a separate hardware domain with dedicated memory pages |
| **Dom0 Privilege Separation** | Dom0 is the only domain with direct hardware access; guest VMs have no direct hardware path |
| **XAPI Access Control** | Role-based access control for hypervisor management operations |
| **Network Isolation** | VLAN tagging and virtual switch configuration enforce network segmentation |
| **Impact** | Satisfies VM isolation, resource protection, and privilege separation requirements |

### 6.5 Dom0 Direct Access Model (XCP-ng)

XCP-ng Dom0 access is inherently restricted:

| Feature | Detail |
|---------|--------|
| **No Web UI on Dom0** | All management through Xen Orchestra or direct SSH |
| **SSH Key Authentication** | Supports key-based authentication for automated scanning |
| **Root-Only Access** | Dom0 typically has only the root account (no multi-user environment) |
| **Impact** | Several account management and session control requirements are satisfied by the restricted access model |

---

## 7. Deployment Recommendations

### 7.1 XOA vs XOCE — Xen Orchestra Deployment

For regulated environments, the assessment data supports a clear recommendation:

| Criterion | XOA (Appliance) | XOCE (Community) |
|-----------|----------------|-------------------|
| **GPOS EvalScore** | 48.48% | 46.46% |
| **ASD EvalScore** | 40.56% | 43.01% |
| **WebSRG EvalScore** | 41.27% | 42.86% |
| **Firewall** | UFW enabled by default | No default firewall |
| **Vendor Support** | Full Vates support | Community only |
| **Plugin Naming** | `-premium` suffix | Standard naming |
| **Plugin Detection** | REST API + JSON-RPC | File-based |
| **Hardening Baseline** | Stronger out-of-box | Requires manual hardening |

**Recommendation:** XOA is the preferred deployment model for regulated environments due to its stronger out-of-box security posture, vendor support commitment, and default firewall configuration.

### 7.2 XCP-ng Host Hardening Priorities

Based on the Dom0 assessment, the highest-impact hardening actions are:

| Priority | Action | Findings Resolved | Effort |
|----------|--------|-------------------|--------|
| 1 | Configure SSH hardening (banner, ciphers, timeout) | 15+ | Low |
| 2 | Configure PAM password policy | 10+ | Low |
| 3 | Enable and configure auditd | 20+ | Medium |
| 4 | Install AIDE for file integrity | 5+ | Medium |
| 5 | Configure sysctl kernel parameters | 5+ | Low |
| 6 | Enable LUKS disk encryption | 3+ | High (requires reinstall) |

---

## 8. Summary of Open Findings by Category

### 8.1 Xen Orchestra — All 3 Modules (XO1 — XOCE)

| Category | Total Rules | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|------------|---------------|-------------|------|-------------|
| **CAT I** | 57 | 6 | 23 | 28 | 0 |
| **CAT II** | 521 | 42 | 185 | 294 | 0 |
| **CAT III** | 32 | 5 | 9 | 18 | 0 |
| **Total** | **610** | **53** | **217** | **340** | **0** |

### 8.2 XCP-ng — Both Modules (VMH01)

| Category | Total Rules | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|------------|---------------|-------------|------|-------------|
| **CAT I** | 26 | 5 | 11 | 9 | 1 |
| **CAT II** | 398 | 25 | 126 | 247 | 0 |
| **CAT III** | 13 | 0 | 3 | 10 | 0 |
| **Total** | **437** | **30** | **140** | **266** | **1** |

### 8.3 Full Vates VMS Stack — All 5 Modules Combined

| Category | Total Rules | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|------------|---------------|-------------|------|-------------|
| **CAT I** | 83 | 11 | 34 | 37 | 1 |
| **CAT II** | 919 | 67 | 311 | 541 | 0 |
| **CAT III** | 45 | 5 | 12 | 28 | 0 |
| **Total** | **1,047** | **83** | **357** | **606** | **1** |

### 8.4 Findings Breakdown by Root Cause

| Root Cause | Approx. Count | Applies To | Responsible Party |
|------------|--------------|------------|-------------------|
| FIPS 140-2 cryptography not validated | 10+ | XO + Dom0 | Vates (product change or guidance) |
| No mandatory consent banner | 5+ | XO + Dom0 | Vates (feature) + Site (nginx/SSH config) |
| Mandatory root account for XO connection | 10-15 | Dom0 + VMM | Vates (non-root service account + key-based auth) |
| No AD/LDAP integration on Dom0 | 20-29 | Dom0 | Vates (SSSD/realmd support and documentation) |
| SELinux disabled on Dom0 | 1 (CAT I) | Dom0 | Vates (official position + compensating controls) |
| MFA/2FA not fully detected | 3 | XO | V-264343 resolved; 3 remaining require manual review |
| TLS 1.1 enabled | 3 | XO | Vates (default change) + Site (config) |
| Virtual disk hardware identifiers | All VMs | XCP-ng | Vates (xen-blkfront driver enhancement) |
| PAM/password policy not configured | 20+ | XO + Dom0 | Site administrator |
| SSH hardening not configured | 15+ | XO + Dom0 | Site administrator |
| Audit infrastructure (auditd, SIEM) | 25+ | XO + Dom0 | Site administrator |
| PKI/certificate management | 4+ | XO + XAPI | Site administrator |
| Session management | 4+ | XO + Dom0 | Site administrator |
| File integrity monitoring | 5+ | XO + Dom0 | Site administrator |
| System hardening (services, permissions, kernel) | 25+ | XO + Dom0 | Site administrator |
| Data-at-rest encryption | 3+ | XO + Dom0 | Site administrator |
| CentOS 7 EOL | Risk factor | Dom0 | Vates (patch strategy documentation) |
| Other organizational/policy items | 30+ | All | Security compliance officer |

---

## 9. Manual Review Burden — The Adoption Cost of Open Findings

### The Challenge for Organizations Adopting Vates VMS

Unlike Broadcom's vSphere/VCF stack — which has **official security baselines, automated scanning benchmarks, and a mature vendor-published hardening guide with compliance-specific procedures** — the Vates Virtualization Management Stack lacks official security baselines and automated scanning benchmarks. Vates does publish a general-purpose hardening guide (v0.1, May 2024), which is a valuable starting point, but it does not yet include the compliance-specific step-by-step procedures (PAM configuration, FIPS compliance, smart card integration, audit rules, etc.) that sysadmins need to close compliance findings.

This is a significant adoption barrier. When an organization evaluates virtualization platforms for secure or regulated environments, the compliance workload is a major factor in the Total Cost of Ownership. A platform with 50 Open findings and a compliance-specific hardening guide is far more attractive than one with 600+ Open findings and only general-purpose security documentation — regardless of licensing cost savings.

### Estimated Manual Review Effort

The following estimates are based on industry experience with security compliance workflows on platforms that lack official vendor documentation:

| Task Per Open Finding | Time (No Vendor Guide) | Time (With Vendor Guide) |
|-----------------------|----------------------|------------------------|
| Read and understand the security requirement | 5-10 min | 5 min |
| Research how the requirement applies to XO/XCP-ng | 15-30 min | 5 min (vendor-documented) |
| Determine if a fix exists or if a remediation plan is needed | 10-20 min | 5 min |
| Implement the fix or draft remediation plan entry | 15-45 min | 10-15 min |
| Verify and document the remediation | 10-15 min | 5-10 min |
| **Total per finding** | **~1-2 hours** | **~30-40 minutes** |

### Projected Workload for Full Vates VMS Stack

Using the combined scan results (606 Open findings across XO + XCP-ng):

| Scenario | Estimated Effort | Calendar Time (1 FTE) |
|----------|-----------------|----------------------|
| **Current state** (general guide exists, 606 Opens) | **400-850 man-hours** | 10-22 weeks |
| **With compliance-specific guide supplement** | ~240-400 man-hours | 6-10 weeks |
| **If Vates resolves product gaps** (~75 fewer Opens) | ~350-750 man-hours | 9-19 weeks |
| **Best case** (compliance guide + product fixes, ~450 Opens) | ~225-300 man-hours | 6-8 weeks |

For comparison, a sysadmin hardening a **VMware ESXi host + vCenter** pair with its official security baseline and automated scanning benchmark can achieve compliance in approximately **80-160 man-hours** — the automated scanning tool handles most checks, the vendor baseline provides exact fix actions, and the community knowledge base covers edge cases.

### The Competitive Implication

Organizations choosing between Vates VMS and Broadcom VCF for regulated environments will weigh:

| Factor | Vates VMS (Today) | Broadcom VCF |
|--------|-------------------|--------------|
| Licensing cost | Significantly lower | High (per-CPU) |
| Official Security Baseline | None | Yes (ESXi, vCenter, vSAN) |
| Automated Scanning Benchmark | None (custom framework fills gap) | Yes (automated scanning) |
| Vendor Hardening Guide | Yes (general-purpose, v0.1) | Yes (compliance-specific, mature) |
| Compliance-specific procedures | Not yet | Yes (step-by-step) |
| Estimated compliance effort | 400-850 hours (full stack) | 80-160 hours (full stack) |
| Community compliance knowledge base | None | Extensive |

**The compliance cost gap is 3-5x.** The existence of Vates' general hardening guide reduces the gap from what it would be with no documentation at all, but the lack of compliance-specific procedures, official security baselines, and automated scanning benchmarks still means significantly more manual effort. When multiplied across a fleet of hosts, this can erode the licensing cost advantage.

### The Mutual Benefit of Reducing Opens

Every action Vates takes to reduce Open findings has a multiplier effect across all deployments in regulated environments:

1. **A compliance supplement to the existing hardening guide** could cut per-finding effort by 50-60%, saving each deploying organization hundreds of hours. The existing v0.1 guide is an excellent foundation — adding compliance-specific procedures (PAM, FIPS, smart card, consent banner, audit rules, SSH hardening) would close the gap
2. **Resolving product gaps** (FIPS, banner, TLS, SELinux, disk identifiers) removes findings that no sysadmin can fix — these are currently hard blockers that require remediation plans
3. **Publishing an automated scanning benchmark** would automate initial assessment, reducing the 5-10 minute "understand the requirement" step to seconds
4. **Each Open finding resolved by Vates is resolved for every customer simultaneously** — the ROI scales with adoption

The goal should be to bring the compliance effort for Vates VMS to within 2-3x of VMware's — close enough that the licensing savings make the business case compelling. Based on our assessment, this is achievable with the actions outlined in Section 10.

---

## 10. Recommendations for Vates

### Immediate Actions (for Security Authorization Support)

1. **[CRITICAL] Enable non-root XO-to-XCP-ng connection** — allow XO to connect using a dedicated service account; support key-based auth; document root lockdown procedure (Section 4.9) — **highest compliance ROI, 10-15+ findings resolved**
2. **[CRITICAL] Provide FIPS 140-2 compliance statement** for both XO and XCP-ng (even if the answer is "not currently validated" — assessors need official documentation)
3. **[HIGH] Validate and document AD/LDAP integration for Dom0** — SSSD/realmd support would resolve 20-29 Dom0 findings by delegating authentication to Active Directory (Section 4.10)
4. **Publish a compliance supplement to the existing Hardening Guide** — add procedures for PAM, FIPS, consent banner, smart card authentication, session management, audit rules, and SSH hardening (Section 4.8)
5. **Publish nginx consent banner template** for regulated XO deployments (no product code changes needed)
6. **Document TLS hardening steps** to disable TLS 1.1 and enforce TLS 1.2+
7. **Publish SELinux position statement** for XCP-ng Dom0 — whether it can be enabled safely, and if not, what compensating controls exist
8. **Document Dom0 security update strategy** — how CentOS 7 EOL is handled, what receives patches, and the update cadence
9. **Document smart card + SAML/OIDC integration** as the recommended MFA architecture for regulated environments
10. **Clarify 2FA/SAML/OIDC configuration storage** — documentation on where XO stores MFA configuration for automated scanner detection

### Product Roadmap Items (for Full Security Authorization)

1. **Non-root service account for XO management connection** — the single highest-impact change for compliance (Section 4.9)
2. **AD/LDAP integration for Dom0** — SSSD/realmd support with official documentation (Section 4.10)
3. **Native pre-login banner with acknowledgment** in the XO web UI
4. **FIPS mode support** (PBKDF2 for local passwords, FIPS-validated TLS libraries)
5. **Disable TLS 1.1 by default** in new releases
6. **Expose VDI UUID/SR name to guest VMs** via `xen-blkfront` sysfs attributes — required for hardware asset inventory compliance (CM-8, SI-7)
7. **Mask TOTP secrets in REST API** — return boolean instead of Base32 secret to prevent credential exposure
8. **Automated scanning benchmark development** for compliance scanning
9. **Dom0 base OS migration** — roadmap for moving to a supported base OS in future XCP-ng releases

### Documentation Deliverables

| Document | Priority | Purpose |
|----------|----------|---------|
| Compliance Supplement to Hardening Guide | Critical | Compliance-specific procedures (PAM, FIPS, banner, smart card, audit, SSH) |
| FIPS 140-2 Compliance Statement | Critical | Official vendor position for authorization package |
| Dom0 Security Update Strategy | Critical | CentOS 7 EOL mitigation documentation |
| SELinux Position Statement | Critical | Official position on mandatory access control for Dom0 |
| Smart Card + SAML/OIDC Integration Guide | High | Step-by-step MFA configuration for hardware token authentication |
| TLS Configuration Guide | High | Steps to enforce TLS 1.2+ minimum |
| XOA Deployment Guide (Regulated Environments) | High | Compliance-specific appliance deployment procedures |
| Dom0 Hardening Guide (RHEL 7 STIG) | High | Step-by-step Dom0 hardening for STIG compliance |
| Audit Plugin Architecture | Medium | Technical documentation for assessor review |
| Key/Certificate Management Guide | Medium | Cryptographic key storage and lifecycle |
| VDI-to-Guest Disk Mapping Reference | Medium | Auditor reference for virtual disk inventory |

---

## 11. Assessment Methodology

### Framework

- **Tool:** Custom automated compliance scanning framework (extension of Evaluate-STIG v1.2507.6)
- **Modules:** 5 custom PowerShell modules (1,047 functions total)
- **Execution:** Remote SSH-based PSRemoting from scanning workstation to target systems
- **Output:** Compliance checklist files (CKL, CKLB, XCCDF) + XML/HTML Summary Reports

### Quality Assurance

- **215+ test iterations** across all systems during development
- **Zero Not_Reviewed findings on XO** — every XO rule has an automated determination
- **1 Not_Reviewed on Dom0** — a single RHEL 7 STIG rule where automated determination was inconclusive
- **Zero scan errors** — all modules complete cleanly with exit code 0
- **Zero VulnTimeouts** — all checks complete within the 15-second timeout
- **Checklist validation** — all generated CKL, CKLB, and XCCDF files pass schema validation
- **Answer files** — 2-index matching pattern provides COMMENTS with remediation guidance for every finding
- **QA remediation** — 2 phases of post-implementation quality assurance eliminating all runtime errors

### Scan Timing

| Target | Modules | Scan Time |
|--------|---------|-----------|
| XO1 (XOCE) | GPOS + ASD + WebSRG | ~4 minutes |
| XOA (Appliance) | GPOS + ASD + WebSRG | ~4 minutes |
| VMH01 (XCP-ng) | VMM + Dom0 RHEL7 | ~4.5 minutes |
| **Full stack** | **All 5 modules** | **~8.5 minutes** |

### Artifacts Provided

The following artifacts are available for assessor review:

| Artifact | Format | Content |
|----------|--------|---------|
| Compliance Checklists | CKL, CKLB, XCCDF | Per-rule findings with automated evidence |
| Summary Reports | XML, HTML | Module-level score summaries with system inventory |
| Scan Logs | LOG | Full execution logs with timing data |
| Answer Files | XML | Remediation guidance for every finding (5 files, 1,047 entries) |
| Source Modules | PSM1 | Full source code for all 1,047 check functions |

---

## 12. Next Steps

1. **Vates Review:** Review this report and prioritize actions in Section 10
2. **Compliance Guide Supplement:** Vates to expand the existing Hardening Guide (v0.1) with compliance-specific procedures for both XO and XCP-ng
3. **Scanner Update (PARTIALLY COMPLETE):** V-264343 now detects native TOTP 2FA via REST API and flips Open &rarr; NotAFinding when all users have 2FA enabled. V-264344 requires organizational attestation (cannot fully automate). V-203642/V-203643 are OS-level PAM/SSH checks not addressable by application-level 2FA.
4. **Authorization Package Assembly:** Compile checklist files, this report, Vates hardening guide, and remediation plans into security authorization submission package
5. **Production Validation:** Run full 5-module scan against production-representative environment with hardening applied to measure improvement in EvalScores
6. **Framework Migration:** Evaluate integration of custom modules into future Evaluate-STIG releases (see separate Framework Contribution Proposal)

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **ASD** | Application Security and Development compliance baseline |
| **CAT I/II/III** | Security severity categories: CAT I (Critical — direct, immediate risk), CAT II (High — significant potential risk), CAT III (Medium — could degrade security). See Section 1 for full definitions. |
| **CKL/CKLB** | Compliance checklist file formats |
| **Dom0** | The privileged domain in a Xen hypervisor that has direct hardware access and manages guest VMs |
| **EvalScore** | Percentage of applicable rules that are NotAFinding |
| **FIPS 140-2** | Federal Information Processing Standard for cryptographic modules |
| **GPOS** | General Purpose Operating System SRG |
| **MFA** | Multi-Factor Authentication |
| **OIDC** | OpenID Connect (authentication protocol) |
| **SAML** | Security Assertion Markup Language (SSO protocol) |
| **SCAP** | Security Content Automation Protocol |
| **SRG** | Security Requirements Guide |
| **VBD** | Virtual Block Device — the connection between a VDI and a VM in XCP-ng |
| **VDI** | Virtual Disk Image — a virtual disk object managed by XAPI in XCP-ng |
| **VMM** | Virtual Machine Manager SRG |
| **WebSRG** | Web Server Security Requirements Guide |
| **XAPI** | The management API and toolstack for XCP-ng hypervisor |
| **XOA** | Xen Orchestra Appliance (official Vates product) |
| **XOCE** | Xen Orchestra Community Edition (built from source) |

## Appendix B: Contact

**Assessment Lead:** Kismet Agbasi (KismetG17@gmail.com)
**Project Repository:** https://github.com/kismetgerald/Evaluate-STIG-Mods4VatesVMS

---

*This report was generated based on automated security compliance scans performed between March 3-15, 2026. All findings are backed by machine-generated evidence in the accompanying CKL/CKLB/XCCDF checklist files. Version 2.0 encompasses the complete Vates VMS stack — 1,047 automated checks across 5 security baselines.*
