# Vates Virtualization Stack - Compliance Blockers & Requirements

**Purpose:** Track compliance blockers, missing packages/features, and items requiring Vates team input for DoD STIG compliance approval (IATT/ATO).

**Last Updated:** March 15, 2026
**Document Owner:** Kismet Agbasi
**Target:** DoD Classified Environment Approval (IATT for PoC or Full ATO for Production)

---

## Executive Summary

The Vates Virtualization Management Stack (Xen Orchestra + XCP-ng) currently has **no official DISA STIG or SCAP Benchmark**. This document tracks blockers and requirements for achieving compliance using adapted SRGs:

| Component | Applicable STIGs/SRGs | Rule Count | Current Status |
|-----------|----------------------|------------|----------------|
| **Xen Orchestra** | ASD STIG + Web SRG + Debian12 GPOS SRG | 286 + 126 + 198 = 610 | **ALL 3 MODULES 100% COMPLETE** |
| **XCP-ng Hypervisor** | VMM SRG + RHEL7 STIG | 193 + 244 = 437 | **BOTH MODULES 100% COMPLETE** |
| **Total** | 5 STIGs/SRGs | 1,047 rules | **ALL 5 MODULES 100% COMPLETE (1,047/1,047)** |

---

## Section 1: Critical Blockers Requiring Vates Action

These items were identified during STIG implementation (Sessions 17-34, January-February 2026) and require either a Vates software change, a formal waiver, or configuration guidance from Vates.

### 1.1 FIPS 140-2 Cryptography - bcrypt Not Validated

| Issue ID | CRYPT-001 |
|----------|-----------|
| **Affected VulnIDs** | V-206391, V-206434, V-239371, V-222425 |
| **Severity** | CAT I |
| **Discovery** | Session #27 (January 31, 2026) |

**Finding:** Xen Orchestra uses **bcrypt** for password hashing by default. bcrypt is **not FIPS 140-2 validated**.

**DoD Requirement:** All cryptographic operations must use FIPS 140-2 validated modules.

**Impact:**
- V-206391 returns **Open** (bcrypt detected - NOT FIPS 140-2 validated)
- V-206434 returns **Open** (FIPS mode not enabled system-wide)
- V-239371 returns **Open** (FIPS cryptographic modules not confirmed)

**Mitigation Options (Vates input needed):**
1. **LDAP/AD Integration (Recommended):** Delegate authentication to FIPS-validated directory services (Active Directory, LDAP with FIPS-validated TLS). This is the most practical path for DoD environments.
2. **Code Modification:** Replace bcrypt with PBKDF2 (NIST SP 800-132 approved) - requires Vates development.
3. **Client Certificate Authentication:** Use FIPS-approved TLS modules for authentication - requires XO configuration.
4. **Waiver Request:** Document compensating controls for ATO package.

**Action Required from Vates:**
- Publish official statement on FIPS 140-2 compliance path for XO authentication
- Provide roadmap for PBKDF2 or equivalent FIPS-approved password hashing
- Document LDAP/AD integration as recommended authentication method for DoD environments

---

### 1.2 TLS 1.1 Still Enabled

| Issue ID | TLS-001 |
|----------|---------|
| **Affected VulnIDs** | V-206439, V-206352, V-206353 |
| **Severity** | CAT II |
| **Discovery** | Session #29 (February 1, 2026) |

**Finding:** XO1 system has TLS 1.1 enabled alongside TLS 1.2/1.3.

**DoD Requirement:** Minimum TLS 1.2. TLS 1.0 and TLS 1.1 must be disabled.

**Impact:**
- V-206439 returns **Open** (TLS 1.1 enabled - partial compliance)

**Action Required:**
- Document how to disable TLS 1.1 in XO configuration (config.toml or nginx configuration)
- Provide hardening guide for TLS version restrictions

---

### 1.3 Timestamps Not Using UTC/GMT

| Issue ID | TIME-001 |
|----------|----------|
| **Affected VulnIDs** | V-206425 |
| **Severity** | CAT II |
| **Discovery** | Session #32 Batch 1 (February 3, 2026) |

**Finding:** XO1 system logs use local timezone (US/Eastern) instead of UTC/GMT.

**DoD Requirement:** All audit log timestamps must use UTC or GMT.

**Impact:**
- V-206425 returns **Open** (local time detected: US/Eastern, not UTC/GMT)

**Remediation:**
```bash
# Set system timezone to UTC
timedatectl set-timezone UTC
# Update XO service environment: TZ=UTC
# Restart XO service: systemctl restart xo-server
```

**Action Required:**
- Document required timezone configuration in XO hardening guide
- Recommend UTC as default timezone for DoD deployments

---

### 1.4 No Centralized Audit Server Configured

| Issue ID | AUDIT-001 |
|----------|-----------|
| **Affected VulnIDs** | V-206422 |
| **Severity** | CAT II |
| **Discovery** | Session #32 Batch 2 (February 3, 2026) |

**Finding:** No evidence of remote syslog/audit server configuration on XO1.

**DoD Requirement:** All audit logs must be forwarded to an approved centralized audit server (SIEM/syslog server).

**Impact:**
- V-206422 returns **Open** (no rsyslog/syslog-ng remote destination detected)

**Action Required:**
- Document rsyslog/syslog-ng configuration for centralized log forwarding
- Provide hardening guide section for audit log offloading to SIEM

---

### 1.5 MFA/2FA Not Implemented

| Issue ID | AUTH-001 |
|----------|----------|
| **Affected VulnIDs** | V-264343, V-264344 |
| **Severity** | CAT II |
| **Discovery** | Session #30 (February 1, 2026) |

**Finding:** No MFA/2FA implementation detected on XO1. XO does not include built-in MFA.

**DoD Requirement:** Multi-factor authentication required for all privileged access.

**Impact:**
- V-264343 returns **Open** (MFA enrollment/policy verification required)
- V-264344 returns **Open** (separate device factor verification required)

**Acceptable MFA Methods (per DoD):**
- CAC/PIV (recommended for DoD)
- Hardware security tokens (FIDO2/U2F)
- **NOT acceptable:** SMS/email OTP, knowledge-based questions

**Action Required:**
- Document supported MFA/2FA integration methods for XO
- Provide guidance for CAC/PIV authentication integration (LDAP + smart card)
- Consider native MFA support as a feature request for DoD deployments

---

### 1.6 Password Policy Not Enforced (15-Character Minimum)

| Issue ID | PWD-001 |
|----------|---------|
| **Affected VulnIDs** | V-264351, V-264352, V-264353 |
| **Severity** | CAT II |
| **Discovery** | Session #32 Batch 1 (February 3, 2026) |

**Finding:** PAM not configured for 15-character minimum password length. No password strength tool detected.

**DoD Requirement:** Minimum 15 characters. Complexity requirements enforced.

**Impact:**
- V-264351 returns **Open** (PAM minlen < 15 or not configured)
- V-264352 returns **Open** (password strength tool not detected)

**Remediation:**
```bash
# Configure PAM pwquality
echo "minlen = 15" >> /etc/security/pwquality.conf
echo "minclass = 4" >> /etc/security/pwquality.conf
```

**Action Required:**
- Include PAM configuration in Debian 12 hardening guide
- Document password policy requirements for XO system accounts

---

### 1.7 Key Storage and Compromise Verification

| Issue ID | KEY-001 |
|----------|---------|
| **Affected VulnIDs** | V-264347, V-264357 |
| **Severity** | CAT II |
| **Discovery** | Session #34 (February 9, 2026) |

**Finding:**
- V-264347: No formal compromised key list or password compromise monitoring detected
- V-264357: Cryptographic key storage practices require manual verification

**DoD Requirement:**
- Compromised keys/credentials must be invalidated and tracked
- Key storage must use hardware-protected or encrypted storage

**Action Required:**
- Document XO key storage architecture (where API tokens, SSH keys, and SSL certificates are stored)
- Provide guidance on credential compromise monitoring and revocation procedures

---

### 1.8 No DoD Mandatory Notice and Consent Banner

| Issue ID | BANNER-001 |
|----------|------------|
| **Affected VulnIDs** | V-222434, V-222435 |
| **Severity** | CAT II |
| **Discovery** | Session #39 — Batch 4 (February 16, 2026) |

**Finding:** Xen Orchestra has **no built-in mechanism** to display the DoD Standard Mandatory Notice and Consent Banner before granting access. The XO login page does not present any banner text, and there is no acknowledgment/consent mechanism before login.

**DoD Requirement (V-222434):** The application must display the following banner (or equivalent) before granting access:
> *"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: ... The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations."*

**DoD Requirement (V-222435):** The banner must remain on screen until the user **explicitly acknowledges** it (e.g., clicks "I Agree" or equivalent) before login proceeds. Simply displaying text that disappears automatically is not sufficient.

**Impact:**
- V-222434 returns **Open** — no DoD banner text found on XO login page (curl scan of `https://localhost/` finds no required keywords)
- V-222435 returns **Open** — no banner acknowledgment mechanism detected (no checkbox, button, or consent form before login)

**Root Cause:** XO's React-based login UI does not include a configurable pre-authentication banner or consent page. This is a platform-level limitation.

**Mitigation Options (Vates input needed):**

1. **Nginx Reverse Proxy (Recommended for near-term):** Deploy nginx in front of XO with a custom `/consent` page. Users are redirected to the consent page before being proxied to XO. Nginx serves the banner HTML, and a session cookie records acknowledgment before allowing the XO login page to render. This approach does NOT require any XO code changes.

   ```nginx
   # Example nginx consent flow
   location / {
       if ($cookie_dod_consent != "acknowledged") {
           return 302 /consent;
       }
       proxy_pass https://127.0.0.1:8443;
   }
   location /consent {
       # Serve banner page with "I Agree" button that sets cookie and redirects to /
   }
   ```

2. **XO Native Banner (Long-term Vates feature request):** Add a configurable pre-login banner to the XO web UI. Configuration in `config.toml`:
   ```toml
   [loginBanner]
   enabled = true
   text = "You are accessing a U.S. Government (USG) Information System..."
   requireAcknowledgment = true
   ```

3. **XOA Appliance Configuration:** For XOA deployments, Vates could provide an nginx configuration template that implements the consent flow as part of the standard deployment.

**Action Required from Vates:**
- **[NEAR-TERM]** Publish nginx reverse proxy configuration template that implements DoD banner + acknowledgment for XO deployments
- **[LONG-TERM]** Add native configurable pre-login banner support to XO web UI with acknowledgment requirement
- **[DOCUMENTATION]** Include DoD banner configuration in the XO hardening guide
- **[XOCE]** Recommend and document use of nginx as required DoD deployment component for XOCE

**Note:** XOA (the official Vates appliance) ships with nginx by default and is better positioned to implement the consent page natively. XOCE deployments will require additional nginx installation.

---

### 1.9 Virtual Disk Devices Lack Unique Hardware Identifiers

| Issue ID | ASSET-001 |
|----------|-----------|
| **Affected Components** | All VMs running on XCP-ng (XOA, XOCE, and any guest VM) |
| **Severity** | CAT II (asset identification and inventory compliance) |
| **Discovery** | Session #83 — QA Phase 2 (March 15, 2026) |

**Finding:** Xen paravirtualized (PV) block devices (e.g., `/dev/xvda`, `/dev/xvdb`) expose **no hardware identification metadata** to guest operating systems. Standard Linux disk interrogation tools (`lsblk`, `udevadm`, `/sys/block/`) return empty values for Model, Serial Number, and Transport type. In contrast, QEMU-emulated devices on the same host (e.g., `/dev/sr0`) correctly expose all identification fields.

| Device | Type | Model | Serial Number | Transport | Identifiable? |
|--------|------|-------|---------------|-----------|---------------|
| `/dev/sr0` | QEMU emulated | QEMU DVD-ROM | QM00004 | ATA | Yes |
| `/dev/xvda` | Xen PV block | *(empty)* | *(empty)* | *(empty)* | **No** |

**Why This Matters for DoD Compliance:**

Federal security frameworks mandate that all hardware components be uniquely identifiable for asset management, change detection, and forensic purposes:

- **NIST SP 800-53 CM-8 (Information System Component Inventory):** Organizations must maintain an accurate, current inventory of information system components that includes "a means for identifying by name, position, and/or role, individuals responsible/accountable for administering those components." Disk devices without serial numbers or model identifiers cannot be positively inventoried.

- **NIST SP 800-53 CM-3 (Configuration Change Control):** Change detection requires the ability to identify *which specific component* changed. If multiple virtual disks are indistinguishable from each other at the OS level, an auditor cannot verify that the correct disk was inspected, replaced, or encrypted.

- **CNSSI 1253 (Security Categorization and Control Selection for National Security Systems):** For classified systems, hardware asset tracking must support chain-of-custody verification. A virtual disk that cannot be uniquely identified by the operating system breaks the chain of evidence from the physical storage layer through the hypervisor to the guest.

- **DISA STIG SI-7 (Software, Firmware, and Information Integrity):** Integrity verification requires unique component identification. An integrity monitoring tool inside a guest VM cannot distinguish between virtual disks if they all report identical empty metadata.

**The information exists — it's just not exposed to guests.** XCP-ng's XAPI management layer maintains rich metadata for every Virtual Disk Image (VDI):

```
xe vdi-list params=uuid,name-label,sr-name-label,virtual-size,physical-utilisation
```

Each VDI has a globally unique UUID, a storage repository association, and size attributes. This metadata is available to the hypervisor and management tools but is **not propagated** to the guest OS through the Xen PV block driver (`xen-blkfront`).

**Precedent — QEMU/KVM Already Does This:**

QEMU-based hypervisors (KVM, Proxmox, OpenStack) routinely expose virtual disk serial numbers and model strings to guest operating systems via virtio-blk or SCSI emulation:

```xml
<!-- libvirt domain XML example -->
<disk type='volume' device='disk'>
  <driver name='qemu' type='qcow2'/>
  <serial>vol-a1b2c3d4</serial>
  <target dev='vda' bus='virtio'/>
</disk>
```

Inside the guest, `lsblk -o NAME,SERIAL,MODEL` then returns the configured serial. This is standard practice in cloud environments (AWS EBS volumes expose volume IDs as serial numbers to EC2 instances).

**Proposed Solution:**

Populate the Xen PV block driver's sysfs attributes with VDI metadata from XAPI. When a VBD (Virtual Block Device) is attached to a VM, the hypervisor should set:

| Linux sysfs attribute | Proposed value | Source |
|-----------------------|---------------|--------|
| `/sys/block/xvda/device/model` | SR name or "XCP-ng VDI" | `xe sr-list` |
| `/sys/block/xvda/device/serial` | VDI UUID (first 20 chars) | `xe vdi-list uuid=` |
| `/sys/block/xvda/device/rev` | XCP-ng version | `xe host-list` |

This could be implemented via:
1. **xenstore entries** that `xen-blkfront` reads during device initialization (similar to how network device MAC addresses are configured)
2. **XAPI VBD parameters** that propagate to the PV backend driver

**Impact Assessment:**
- **Scope:** Affects every guest VM on every XCP-ng host — not just XO, but any workload running on the platform
- **Compliance frameworks affected:** NIST 800-53, CNSSI 1253, DISA STIGs (CM-8, CM-3, SI-7)
- **Competitive disadvantage:** VMware vSphere and Microsoft Hyper-V both expose virtual disk identifiers to guests. QEMU/KVM does as well. XCP-ng is the outlier among enterprise hypervisors in this regard.

**Action Required from Vates:**
- **[HIGH]** Expose VDI UUID as virtual disk serial number to guest VMs via the Xen PV block driver
- **[HIGH]** Expose SR name or "XCP-ng VDI" as the model string for virtual disk devices
- **[MEDIUM]** Document the VDI-to-VBD-to-guest-device mapping for auditors who need to correlate hypervisor-side inventory with guest-side device enumeration
- **[MEDIUM]** Consider extending `xe vbd-param-set` to allow administrators to set custom serial/model strings per VBD (similar to libvirt's `<serial>` element)

### 1.10 XCP-ng Dom0 Lacks External Identity Provider Integration (AD/LDAP)

| Issue ID | AUTH-002 |
|----------|----------|
| **Affected Components** | XCP-ng Dom0 (all hosts) |
| **Severity** | CAT II (authentication, account management, MFA delegation) |
| **Discovery** | Post-implementation analysis (March 15, 2026) |

**Finding:** XCP-ng Dom0 has **no supported mechanism for integrating with an external identity provider** such as Active Directory or LDAP. All Dom0 authentication is performed against local `/etc/passwd` and `/etc/shadow` accounts. There is no Vates-supported method for AD-joining Dom0 or delegating authentication to a centralized directory service.

**Why This Matters — Lessons Learned from Xen Orchestra:**

During the XO compliance implementation, the **auth-ldap plugin** proved to be a transformative compensating control. When XO authentication is delegated to Active Directory:

- **5 GPOS functions flipped from Open to NotAFinding** (account lifecycle management — AD provides centralized creation, modification, disabling, removal with built-in notification)
- **4 additional functions benefited** from AD as supplementary evidence
- **MFA requirements partially satisfied** — AD enforces organizational MFA policies for network access, eliminating the need for XO to implement its own MFA for directory-authenticated users
- **Account notification requirements met** — AD provides centralized audit and notification for account events, satisfying requirements that XO cannot meet natively

**The same pattern would apply to Dom0.** CentOS 7 natively supports AD integration via SSSD (System Security Services Daemon) and `realmd`. If Vates officially supported and documented AD-joining Dom0, the following Dom0 RHEL7 STIG findings could potentially be resolved or mitigated:

| Finding Area | Approx. Count | How AD Integration Helps |
|-------------|---------------|-------------------------|
| Account management (creation, modification, disabling, removal) | 5-8 | AD provides centralized lifecycle management |
| Password policy (complexity, aging, history, reuse) | 8-10 | AD enforces organizational password policy |
| MFA/multi-factor authentication | 2-3 | AD enforces MFA policies for network access |
| Account notification and auditing | 3-5 | AD provides centralized audit trail for account events |
| Individual accountability | 2-3 | Named AD accounts replace shared root access |
| **Total potential impact** | **20-29 findings** | **EvalScore improvement estimated at 8-12%** |

**The compliance score improvement is significant.** Dom0's current EvalScore is 42.21%. Flipping 20+ findings from Open to NotAFinding could raise it above 50% — a meaningful threshold for assessors evaluating the platform's compliance posture.

**Why Vates must lead this:**
- SSSD/realmd packages may not be available in XCP-ng repositories
- AD-joining Dom0 could affect XAPI operations, pool membership, or SSH-based management
- Vates must validate that AD integration does not interfere with hypervisor functionality
- Configuration guidance must account for Dom0's unique role (privileged domain, no GUI, restricted access)

**Precedent:** VMware ESXi supports Active Directory integration for host authentication. This is a standard feature in enterprise hypervisors and is frequently cited in VMware STIG compliance workflows as a key control for meeting authentication and account management requirements.

**Action Required from Vates:**
- **[HIGH]** Validate and document whether SSSD/realmd-based AD integration is safe on XCP-ng Dom0
- **[HIGH]** If supported: publish step-by-step configuration guide for AD-joining Dom0 in regulated environments
- **[HIGH]** If not supported: publish an official statement explaining why, and document what compensating controls exist
- **[MEDIUM]** Ensure SSSD packages are available in XCP-ng repositories (or provide an alternative mechanism)
- **[MEDIUM]** Document the interaction between AD-joined Dom0 and XAPI pool operations (pool join, pool eject, master failover)

### 1.11 XCP-ng Requires Root Account for XO Connection and Dom0 Access

| Issue ID | AUTH-003 |
|----------|----------|
| **Affected Components** | XCP-ng Dom0 (all hosts), Xen Orchestra (management connection) |
| **Severity** | CAT I/CAT II (privilege separation, least privilege, account management) |
| **Discovery** | Post-implementation analysis (March 15, 2026) |

**Finding:** Xen Orchestra connects to XCP-ng hosts **exclusively via the root account**. There is no supported mechanism to use an alternate administrator account for the XO-to-XCP-ng management connection. This means:

1. **The root account cannot be locked or disabled** — XO requires it to manage the hypervisor
2. **Root SSH login must remain enabled** — violating SSH hardening STIGs that require `PermitRootLogin no`
3. **No privilege separation** — all management operations run as root, violating the principle of least privilege
4. **No individual accountability** — when multiple administrators access Dom0 (via XO or direct SSH), all operations execute as root, making it impossible to attribute actions to specific individuals in audit logs
5. **Key-based authentication not enforced** — the default XO-to-XCP-ng connection uses password authentication for root

**Cascade of Open Findings:**

This single architectural decision creates a cascade of compliance failures across both VMM and Dom0 RHEL7 modules:

| STIG Requirement | VulnID Examples | Why It's Open |
|-----------------|----------------|---------------|
| Prohibit direct root login | V-204425, V-204428 | Root login required for XO connection |
| Enforce least privilege | V-207370, V-207383 | All operations run as root — no privilege separation |
| Individual accountability | V-207338, V-207347 | Shared root account prevents user attribution |
| Disable unnecessary accounts | V-204424 | Cannot disable root — XO depends on it |
| SSH access restrictions | V-204594, V-204595 | Root SSH must remain open for management |
| Account lockout | V-204419 | Cannot lock root after failed attempts — would lock out XO |
| Concurrent session control | V-207387 | Cannot limit root sessions — XO holds persistent connection |
| **Estimated total impact** | **10-15+ findings** | **Across VMM and Dom0 modules** |

**What the Fix Looks Like:**

The industry-standard pattern (used by every major Linux distribution and enterprise platform) is straightforward:

1. **Create a dedicated management account** (e.g., `xoadmin` or `stigadmin`) with `sudo` privileges
2. **Configure XO to connect using the management account** instead of root
3. **Lock down root** — disable direct root login, require `su -` or `sudo` from named accounts
4. **Enforce key-based authentication** — XO uses SSH keys to connect to XCP-ng; the management account should require key-based auth
5. **Enable individual accountability** — each administrator gets a named account; XO itself uses a service account with audit trail

**Precedent:**
- **VMware ESXi** supports non-root administrative accounts and AD-integrated authentication. The ESXi STIG explicitly requires disabling direct root login in favor of named accounts.
- **Microsoft Hyper-V** runs as a Windows Server role with full AD integration — root-equivalent access is managed through domain accounts with individual accountability.
- **Proxmox VE** supports PAM, LDAP, and AD authentication with role-based access — no requirement for root login.

XCP-ng's mandatory root access requirement is the outlier among enterprise hypervisors.

**Impact Assessment:**
- **Scope:** Affects every XCP-ng host and every XO deployment in the organization
- **Compliance frameworks:** NIST 800-53 AC-6 (Least Privilege), AC-2 (Account Management), AU-2 (Audit Events), IA-2 (Identification and Authentication)
- **Combined finding impact:** Resolving this single architectural issue could flip 10-15+ findings from Open to NotAFinding across both VMM and Dom0 modules
- **EvalScore improvement:** Estimated 5-8% improvement on Dom0 (42.21% → ~48-50%) and 3-5% on VMM (34.72% → ~38-40%)

**Action Required from Vates:**
- **[CRITICAL]** Enable XO to connect to XCP-ng using a non-root service account with appropriate XAPI privileges
- **[CRITICAL]** Provide a mechanism to create a dedicated XO management account on Dom0 with least-privilege access to XAPI operations
- **[HIGH]** Support key-based authentication as the default (and recommended) method for XO-to-XCP-ng connections
- **[HIGH]** Document a supported procedure for locking down the root account on Dom0 once an alternate admin account is configured
- **[HIGH]** Ensure `sudo` is properly configured on Dom0 for privilege escalation with full audit logging
- **[MEDIUM]** Support individual named accounts for direct SSH access to Dom0 (with `sudo` for privileged operations)
- **[MEDIUM]** Ensure XAPI/xe CLI operations support non-root execution where possible

---

## Section 2: Architecture-Level Blockers (From January 2026)

### 2.1 Xen Orchestra Deployment Models

| Issue ID | Blocker | Impact | XOA Status | XOCE Status | Vates Action Needed |
|----------|---------|--------|------------|-------------|---------------------|
| ARCH-001 | No official hardening guide | Auditors require vendor documentation | UFW enabled by default | No firewall by default | Publish hardening guide |
| ARCH-002 | XOCE has no default firewall | CAT I finding for boundary protection | N/A | FINDING | Document recommended firewall config |
| ARCH-003 | Default ports may conflict | Operational concern | Configurable | Configurable | Document recommended ports |
| ARCH-004 | No FIPS 140-2 validation | Required for classified | Unknown | Unknown | See Section 1.1 above |

### 2.2 XCP-ng Architecture

| Issue ID | Blocker | Impact | Status | Vates Action Needed |
|----------|---------|--------|--------|---------------------|
| ARCH-010 | Dom0 based on CentOS 7 (EOL 2024) | Security update availability | Active XCP-ng support | Document patch/update strategy |
| ARCH-011 | PowerShell 7.4+ incompatible | Limits automation tooling | PS 7.3.12 works | Document glibc dependency |
| ARCH-012 | No SCAP benchmark available | Manual verification required | N/A | Consider SCAP content development |
| ARCH-013 | xe CLI not fully documented for STIG | Auditors need command reference | Partial | Provide STIG-relevant xe command guide |
| ARCH-014 | Xen PV block devices lack hardware identifiers | Guest VMs cannot inventory virtual disks (CM-8, SI-7) | ❌ OPEN | Expose VDI UUID/SR name via xen-blkfront sysfs (See Section 1.9) |
| ARCH-015 | Dom0 has no external IdP integration | Cannot delegate auth to AD/LDAP; 20+ findings impacted | ❌ OPEN | Validate and document SSSD/realmd AD integration (See Section 1.10) |
| ARCH-016 | XO requires root account on Dom0 | No privilege separation, no individual accountability; 10-15+ findings | ❌ OPEN | Support non-root service account for XO connection (See Section 1.11) |

---

## Section 3: Xen Orchestra - All 3 Modules Complete (Findings Summary)

All XO modules are **100% implemented** — WebSRG (126), ASD (286), GPOS Debian12 (198) = 610 functions. Key open findings on XO1 (XOCE deployment):

| VulnID | Rule Title | Status | Root Cause |
|--------|------------|--------|------------|
| V-206388 | RFC 5280 certificate validation | Open | Self-signed certificate in use |
| V-206407 | Data at rest encryption | Open | No LUKS/dm-crypt on XO volumes |
| V-206408 | Separate partition for web app | Open | XO installed on root partition |
| V-206417 | Restrict nonsecure zone connections | Open | Zone filtering requires manual verification |
| V-206422 | Write to audit log server | Open | No centralized audit server (see 1.4) |
| V-206425 | UTC/GMT timestamps | Open | Local timezone in use (see 1.3) |
| V-206439 | TLS version minimum | Open | TLS 1.1 enabled (see 1.2) |
| V-264343 | MFA implementation | Open | No MFA detected (see 1.5) |
| V-264351 | Passwords ≥15 characters | Open | PAM not configured (see 1.6) |

**Remediable with XO Configuration Changes:**
- V-206388: Install DoD-signed certificate
- V-206407: Enable LUKS on data partition
- V-206408: Reconfigure OS partitioning
- V-206425: Set TZ=UTC in system and XO service

**Require Vates Input:**
- V-206391/V-239371: FIPS 140-2 crypto (see 1.1)
- V-264343/V-264344: MFA integration (see 1.5)

---

## Section 4: XCP-ng - STIG Findings Summary

Implementation framework complete. Key open findings on production XCP-ng hosts:

| VulnID | Rule Title | Status | Root Cause |
|--------|------------|--------|------------|
| V-207342 | Account lockout after 3 failures | Open | PAM faillock not configured |
| V-207351 | DoD-approved encryption | Open | Default SSH config not DoD-compliant |
| V-204497 | FIPS-validated cryptography | Open | FIPS mode not enabled in kernel |

---

## Section 5: Debian 12 GPOS - Module Complete (Key Findings)

GPOS Debian12 module is **100% complete** (198/198 functions, Test173b, EvalScore 46.46%).

| Area | Key Open Findings | Notes |
|------|-------------------|-------|
| Audit System | 18 functions resolved via XO Audit Plugin | Compensating control (PR #32) |
| PKI/Certificates | 5 functions resolved via AD/LDAP auth-ldap | Enterprise auth delegation |
| Firewall | V-203638, V-203687, V-203722 | XOA: UFW default; XOCE: needs config |
| PAM Configuration | Password policy, account lockout | Debian 12 PAM needs hardening |
| System Hardening | Kernel params, file permissions, services | Standard Debian hardening |

---

## Section 6: Immediate Actions Required

### From Vates Team (Priority Order)

1. **[CRITICAL] Non-Root Service Account for XO Connection** - Enable XO to connect to XCP-ng using a non-root account; allow root lockdown (Section 1.11) — **highest compliance ROI**
2. **[CRITICAL] FIPS 140-2 Statement** - Official position on bcrypt and FIPS compliance path (Section 1.1)
3. **[CRITICAL] MFA Integration Guide** - CAC/PIV or hardware token integration for DoD (Section 1.5)
4. **[HIGH] AD/LDAP Integration for Dom0** - Validate and document SSSD/realmd-based AD authentication on XCP-ng Dom0 (Section 1.10) — **20-29 findings impacted**
5. **[HIGH] DoD Banner Implementation** - Nginx consent page template OR native XO banner feature (Section 1.8)
6. **[HIGH] Hardening Guide** - Official XOA and XCP-ng hardening documentation
7. **[HIGH] TLS Configuration Guide** - How to disable TLS 1.0/1.1, enforce TLS 1.2+ (Section 1.2)
8. **[HIGH] Virtual Disk Hardware Identifiers** - Expose VDI UUID/SR name to guest VMs via xen-blkfront (Section 1.9)
9. **[HIGH] UTC Timezone Configuration** - XO deployment recommendation for DoD (Section 1.3)
10. **[MEDIUM] Cryptographic Statement** - Key storage architecture documentation (Section 1.7)
11. **[MEDIUM] xe CLI Reference** - Security-relevant xe commands for audit evidence
12. **[MEDIUM] Log Format Documentation** - xen.log and audit log formats for SIEM integration
13. **[LOW] AppArmor-to-SELinux Equivalence** - For Debian 12 GPOS SRG compliance

### From Implementation Team

1. ✅ Complete WebSRG checks (126/126) — **DONE** (February 11, 2026, Test124)
2. ✅ Complete ASD checks (286/286) — **DONE** (February 18, 2026, Test148b)
3. ✅ Complete GPOS Debian12 checks (198/198) — **DONE** (March 1, 2026, Test173b)
4. ✅ Complete XCP-ng VMM checks (193/193) — **DONE** (March 11, 2026, Test187b)
5. ✅ Complete XCP-ng Dom0 RHEL7 checks (244/244) — **DONE** (March 14, 2026, Test205)
6. ✅ Framework baseline stable — **DONE** (all scans exit code 0, zero errors)
7. ✅ QA remediation Phase 1 + Phase 2 — **DONE** (March 15, 2026, Test215)

---

## Section 7: Risk Assessment

### Critical Risk (CAT I)

| Risk | Component | Current Status | Mitigation Path |
|------|-----------|----------------|-----------------|
| No FIPS validation (bcrypt) | XO Auth | ❌ OPEN | Vates roadmap or LDAP delegation |
| Missing firewall (XOCE) | XO Network | ❌ OPEN | Document/enforce firewall requirement |
| CentOS 7 EOL | XCP-ng Dom0 | ⚠️ PARTIAL | XCP-ng extended support documentation |
| No SCAP benchmark | Both | ⚠️ WORKAROUND | This framework (manual STIG adaptation) |

### High Risk (CAT II - Requiring Vates Action)

| Risk | Component | Current Status | Mitigation Path |
|------|-----------|----------------|-----------------|
| No MFA/2FA | XO Access | ❌ OPEN | LDAP + smart card; Vates MFA feature |
| No DoD mandatory banner | XO Login | ❌ OPEN | Nginx consent page or native XO banner feature |
| TLS 1.1 enabled | XO HTTPS | ❌ OPEN | Configuration change (disable in config.toml) |
| UTC timestamps not enforced | XO Logging | ❌ OPEN | Set TZ=UTC; document in hardening guide |
| No centralized audit server | XO Logs | ❌ OPEN | Deploy rsyslog/syslog-ng; SIEM integration |
| Password policy (15-char min) | XO/Dom0 | ❌ OPEN | PAM configuration; LDAP delegation |

### Medium Risk (CAT II - Configurable)

| Risk | Component | Mitigation Path |
|------|-----------|-----------------|
| Self-signed certificate | XO HTTPS | Deploy DoD-signed certificate |
| No data-at-rest encryption | XO Storage | LUKS volume encryption |
| Log retention not configured | Both | logrotate + rsyslog configuration |
| Session timeout defaults | XO | Express-session configuration |

---

## Appendix A: Scan Evidence References

All findings are based on automated scans performed using the custom Evaluate-STIG extension:

| Scan | Date | System | Result |
|------|------|--------|--------|
| Test173b | March 1, 2026 | XO1.WGSDAC.NET (XOCE) | **GPOS Debian12 100% — 198/198, EvalScore 46.46%** |
| Test148b | February 18, 2026 | XO1.WGSDAC.NET (XOCE) | **ASD 100% — 286/286, EvalScore 43.36%** |
| Test124 | February 11, 2026 | XO1.WGSDAC.NET (XOCE) | **WebSRG 100% — 126/126, EvalScore 41.27%** |
| Test162 | February 22, 2026 | XO1.WGSDAC.NET (XOCE) | XO Audit Plugin integration validated, EvalScore 17.17% |
| Test137 | February 16, 2026 | XO1.WGSDAC.NET (XOCE) | ASD Batch 4: V-222426–V-222435, EvalScore 9.79% |

**Framework:** NAVSEA Evaluate-STIG v1.2507.6 with Kismet Agbasi modifications
**Modules:** All 3 XO modules complete (610 functions total)

---

## Appendix B: Contact Information

**Implementation Team:**
- Kismet Agbasi - Project Lead

**Vates Team:**
- Support: https://xen-orchestra.com/contact
- GitHub: https://github.com/vatesfr/xen-orchestra

---

**Document Status:** ACTIVE - Updated March 1, 2026 (all 3 XO modules 100% complete)
**Classification:** UNCLASSIFIED
**Distribution:** Limited to implementation team and Vates engineering
