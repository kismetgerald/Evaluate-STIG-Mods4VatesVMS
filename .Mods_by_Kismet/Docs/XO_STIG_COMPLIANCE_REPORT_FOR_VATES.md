# Xen Orchestra STIG Compliance Assessment Report

**Prepared for:** Vates Engineering Team
**Prepared by:** Kismet Agbasi
**Date:** March 4, 2026
**Classification:** UNCLASSIFIED
**Version:** 1.2 (V-264343 scanner update: automated TOTP 2FA detection via REST API)

---

## 1. Executive Summary

This report presents the results of a comprehensive STIG (Security Technical Implementation Guide) compliance assessment of Xen Orchestra, conducted as part of the effort to approve the Vates Virtualization Management Stack (Xen Orchestra + XCP-ng) for use in U.S. Department of Defense (DoD) classified environments.

There are currently **no official DISA STIGs or SCAP Benchmarks** for Xen Orchestra or XCP-ng. To address this gap, we developed a custom automated scanning framework by extending the NAVSEA Evaluate-STIG tool (v1.2507.6) with purpose-built modules that map applicable Security Requirements Guides (SRGs) and existing STIGs to the Xen Orchestra platform.

### Assessment Scope

| Module | STIG/SRG Applied | Rules | Status |
|--------|-----------------|-------|--------|
| Application Security (ASD) | Application Security and Development STIG V6R4 | 286 | 100% Automated |
| Web Server (WebSRG) | Web Server Security Requirements Guide V4R4 | 126 | 100% Automated |
| Operating System (GPOS) | General Purpose OS SRG V3R2 (Debian 12) | 198 | 100% Automated |
| **Total** | **3 STIGs/SRGs** | **610** | **100% Automated** |

### Key Results (Test174i — March 3, 2026)

All 610 rules were scanned on two Xen Orchestra deployment models:

| Metric | XO1 (XOCE) | XOA (Appliance) |
|--------|-----------|-----------------|
| **GPOS EvalScore** | 46.46% | 48.48% |
| **ASD EvalScore** | 43.01% | 40.56% |
| **WebSRG EvalScore** | 41.27% | 41.27% |
| **Not Reviewed** | 0 | 0 |
| **Errors** | 0 | 0 |
| **CKL Validation** | All Passed | All Passed |

**Note on EvalScores:** These scores reflect honest, automated assessment results. Many Open findings represent genuine product gaps (FIPS cryptography, DoD banner) or features that exist but were not detected by our scanning framework at the time of assessment (MFA/2FA via SAML/OIDC). Others require configuration guidance or organizational policy decisions. The scores are not inflated — every finding is backed by automated evidence in the generated STIG Viewer checklists (CKL/CKLB files).

**Note on Vates Hardening Guide:** During the preparation of this report, we identified the *Vates VMS Hardening Guide* (v0.1, May 2024), a 57-page vendor-published document covering security recommendations for both XCP-ng and Xen Orchestra. This guide addresses several areas we initially believed had no vendor guidance. Its existence and coverage are reflected throughout this report, along with recommendations for expanding it to address DoD-specific requirements.

---

## 2. Systems Under Test

### XO1 — Xen Orchestra Community Edition (XOCE)

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

### XOA — Xen Orchestra Appliance

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

---

## 3. Detailed Results by Module

### 3.1 General Purpose Operating System (GPOS) — Debian 12

**STIG:** General Purpose Operating System SRG V3R2
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

**STIG:** Application Security and Development STIG V6R4
**Rules:** 286

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 34 | 4 (XO1) / 5 (XOA) | 11 (XO1) / 9 (XOA) | 19 (XO1) / 20 (XOA) | 0 |
| **CAT II** (High) | 230 | 38 (XO1) / 34 (XOA) | 64 (XO1) / 62 (XOA) | 128 (XO1) / 134 (XOA) | 0 |
| **CAT III** (Medium) | 22 | 5 | 1 | 16 | 0 |

**EvalScore:** 43.01% (XO1) / 40.56% (XOA)

**XO1 scores higher** because XOCE has more Not_Applicable determinations (community edition lacks certain enterprise features that would be assessed).

### 3.3 Web Server Security Requirements Guide (WebSRG)

**STIG:** Web Server Security Requirements Guide V4R4
**Rules:** 126

| Category | Total | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|-------|---------------|-------------|------|-------------|
| **CAT I** (Critical) | 5 | 0 | 3 | 2 | 0 |
| **CAT II** (High) | 121 | 0 | 49 | 72 | 0 |
| **CAT III** (Medium) | 0 | 0 | 0 | 0 | 0 |

**EvalScore:** 41.27% (both deployments)

---

## 4. Findings Requiring Vates Action

The following findings cannot be resolved through system configuration alone. They require product changes, official guidance, or feature development from Vates.

### 4.1 CRITICAL — FIPS 140-2 Cryptography (CAT I)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | CRYPT-001 |
| **Affected VulnIDs** | V-206391, V-206434, V-239371, V-222425, V-203603, V-203669, V-203739, V-203776 |
| **Severity** | CAT I |
| **Impact** | 8+ Open findings across all 3 modules |

**Finding:** Xen Orchestra uses **bcrypt** for local password hashing. bcrypt is cryptographically strong but is **not FIPS 140-2 validated**. Additionally, the system-wide FIPS mode is not enabled, and FIPS-validated cryptographic modules are not confirmed for TLS operations.

**DoD Requirement:** All cryptographic operations in classified environments must use FIPS 140-2 validated modules per NIST SP 800-53 SC-13 and DoD Instruction 8580.01.

**Recommended Actions for Vates:**
1. **Publish official statement** on FIPS 140-2 compliance roadmap for XO
2. **Provide LDAP/AD integration guidance** as the recommended authentication method for DoD — this delegates password hashing to FIPS-validated directory services
3. **Long-term:** Consider replacing bcrypt with PBKDF2 (NIST SP 800-132 approved) for local accounts
4. **Document** which OpenSSL/GnuTLS libraries XO uses for TLS, and whether they can be configured in FIPS mode

### 4.2 CRITICAL — No DoD Mandatory Notice and Consent Banner (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | BANNER-001 |
| **Affected VulnIDs** | V-222434, V-222435, V-203595, V-203596, V-203665 |
| **Severity** | CAT II |
| **Impact** | 5 Open findings across ASD and GPOS modules |

**Finding:** Xen Orchestra has **no built-in mechanism** to display the DoD Standard Mandatory Notice and Consent Banner before granting access. The login page does not present any banner text, and there is no acknowledgment/consent mechanism.

**DoD Requirement:** The exact text of the DoD Standard Mandatory Notice and Consent Banner must be displayed, and users must explicitly acknowledge it before login proceeds.

**Recommended Actions for Vates:**
1. **Near-term (nginx reverse proxy):** Publish an nginx configuration template that implements a consent page before the XO login. XOA already ships with nginx — this could be a configuration addition. Template design:
   - User navigates to XO URL
   - Nginx serves consent page with the DoD banner and "I Agree" button
   - On acceptance, a session cookie is set and the user is proxied to XO login
2. **Long-term (native feature):** Add a configurable pre-login banner to the XO web UI with acknowledgment requirement. Suggested `config.toml` configuration:
   ```toml
   [loginBanner]
   enabled = true
   text = "You are accessing a U.S. Government Information System..."
   requireAcknowledgment = true
   ```
3. **For XOA:** Include the nginx consent configuration as an optional hardening feature in the appliance

### 4.3 HIGH — MFA/2FA Detection Now Automated (CAT II) — PARTIALLY RESOLVED

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | AUTH-001 |
| **Affected VulnIDs** | V-264343 (WebSRG), V-264344 (WebSRG), V-203642 (GPOS), V-203643 (GPOS) |
| **Severity** | CAT II |
| **Impact** | V-264343 now flips Open &rarr; NotAFinding when all users have 2FA enabled. 3 remaining VulnIDs still require manual review. |

**Update (v1.2, March 4, 2026):** The scanner detection gap for V-264343 has been **resolved**. Our scanner now detects XO's native TOTP 2FA per-user via the REST API:

- **Detection method:** Queries `GET /rest/v0/users` to enumerate all user accounts, then inspects each user's `preferences.otp` field. If the field contains a Base32-encoded TOTP secret, that user has 2FA enabled.
- **Status logic:** If ALL users have `preferences.otp` present &rarr; NotAFinding. If any user lacks it &rarr; Open with a list of non-compliant users.
- **Also detects:** LDAP/AD auth-ldap plugin and SAML/OIDC plugin presence as supplementary evidence.

**Remaining open items:**
- **V-264344** (WebSRG) — Organizational MFA strength/policy verification; cannot be fully automated (requires ISSO attestation)
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
3. **Publish DoD-specific MFA configuration guide** showing how to integrate XO with CAC/PIV via SAML/OIDC (e.g., Keycloak + smart card)
4. **Document which 2FA methods are FIDO2/U2F compliant** for DoD environments
5. **Note:** AD-delegated authentication via auth-ldap also satisfies network access MFA when AD enforces MFA policies

### 4.4 HIGH — TLS 1.1 Still Enabled (CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | TLS-001 |
| **Affected VulnIDs** | V-206439, V-206352, V-206353 |
| **Severity** | CAT II |
| **Impact** | 3 Open findings in WebSRG module |

**Finding:** TLS 1.1 is enabled alongside TLS 1.2/1.3 on XO systems.

**DoD Requirement:** Minimum TLS 1.2 required. TLS 1.0 and TLS 1.1 must be disabled.

**Recommended Actions for Vates:**
1. **Publish hardening guide** with exact steps to disable TLS 1.1 in XO (config.toml, nginx, or Node.js configuration)
2. **Consider disabling TLS 1.1 by default** in future XO/XOA releases
3. **For XOA:** Provide a one-command hardening script that enforces TLS 1.2+ minimum

### 4.5 HIGH — Hardening Guide Exists but Needs DoD-Specific Expansion (Multiple CAT II)

| Attribute | Detail |
|-----------|--------|
| **Issue ID** | GUIDE-001 |
| **Affected VulnIDs** | Multiple (20+ findings addressable with configuration) |
| **Severity** | CAT II |
| **Impact** | Many Open findings could be resolved with expanded vendor guidance |

**Finding:** The *Vates VMS Hardening Guide* (v0.1, May 2024, 57 pages) exists and covers many general security topics. This is a strong foundation. However, it does not address DoD-specific STIG requirements, and some topics need step-by-step technical procedures to be actionable for DoD compliance.

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

**What the existing guide does NOT cover (DoD-specific gaps):**

| Topic | Specific Guidance Needed for DoD |
|-------|--------------------------------|
| **DoD consent banner** | nginx configuration template for mandatory notice and consent |
| **Password policy** | PAM configuration for 15-char minimum, complexity, aging (pwquality.conf) |
| **Account lockout** | PAM faillock configuration for 3-attempt lockout in 15 minutes |
| **Session timeout** | SSH ClientAliveInterval and web session inactivity values (10/15 min) |
| **Certificate management** | Replace self-signed certificates with DoD-signed PKI certificates |
| **Disk encryption** | LUKS configuration for data-at-rest protection |
| **File permissions** | Specific permission requirements for audit tools and log files |
| **Kernel parameters** | Recommended sysctl settings for DoD security requirements |
| **CAC/PIV integration** | Step-by-step SAML/OIDC configuration for smart card authentication |
| **FIPS 140-2** | Cryptographic module configuration and compliance status |

**Recommended Actions for Vates:** Expand the existing hardening guide (or publish a DoD supplement) with the specific technical procedures listed above. The existing guide provides an excellent framework — adding DoD-specific sections would make it a complete compliance reference.

---

## 5. Findings Addressable by Site Configuration

These findings are Open but can be resolved by the deploying organization without Vates product changes. They should be included in a DoD deployment checklist.

### 5.1 PAM / Password Policy (12 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203625 thru V-203628 | Password complexity (upper, lower, numeric, special) | Configure `/etc/security/pwquality.conf` |
| V-203631, V-203632 | Password lifetime (1-day min, 60-day max) | Configure `/etc/login.defs` |
| V-203634 | 15-character minimum | `minlen = 15` in pwquality.conf |
| V-203594 | Account lockout after 3 failures | Configure PAM faillock module |
| V-203676 | Special character requirement | `ocredit = -1` in pwquality.conf |
| V-203648 | Disable accounts after 35 days inactivity | `useradd -D -f 35` |
| V-203652 | Remove emergency accounts after 72 hours | Organizational process |

### 5.2 PKI / Certificate Management (4 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203622 | PKI certificate path validation | Install DoD root CA certificates |
| V-203623 | Private key access enforcement | Verify key file permissions (600) |
| V-203624 | Map authenticated identity to user | Configure PAM/SSSD for PKI |
| V-206388 | RFC 5280 certificate validation | Replace self-signed with DoD cert |

### 5.3 Audit System Infrastructure (12 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203613, V-203614 | Centralized audit review and filtering | Deploy SIEM + rsyslog |
| V-203615 | Internal system clocks for timestamps | Configure NTP/chrony + auditd |
| V-203616, V-203617 | Protect audit info from unauthorized access/modification | Set audit log permissions |
| V-203620 | ISSM controls auditable events | Document audit configuration authority |
| V-203670 | Boot-time audit initiation | Install and enable auditd |
| V-203672 thru V-203674 | Protect audit tools | Set AIDE/Tripwire for integrity |

### 5.4 System Hardening (8 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203595, V-203596, V-203665 | DoD consent banner | SSH: configure `/etc/issue.net`; Web: see Section 4.2 |
| V-203598 thru V-203601 | Session lock (15-min timeout, re-auth) | Configure tmux/screen auto-lock; SSH ClientAliveInterval |
| V-203637 | Disable non-essential capabilities | Remove unnecessary packages/services |
| V-203636 | Enforce access control policies | Configure sudo, file permissions, SELinux/AppArmor |

### 5.5 Data Protection (3 findings)

| VulnIDs | Requirement | Remediation |
|---------|-------------|-------------|
| V-203661 | Protect information at rest | Enable LUKS on data partitions |
| V-203745, V-203746 | Prevent unauthorized modification/disclosure at rest | Full disk encryption with LUKS |
| V-206407 | Data at rest encryption (WebSRG) | LUKS + XO data directory encryption |

---

## 6. Compensating Controls in Use

The assessment framework recognizes the following application-layer controls as compensating evidence:

### 6.1 XO Audit Plugin

The XO Audit Plugin provides application-layer auditing that compensates for the absence of the traditional Linux `auditd` daemon:

| Feature | Detail |
|---------|--------|
| **Event Recording** | All user actions: login, VM operations, permission changes, configuration changes |
| **Integrity** | Hash chain — each record cryptographically linked to its parent |
| **Tamper Detection** | Daily hash upload to Vates for external verification |
| **API Access** | REST API at `GET /rest/v0/plugins/audit/records` |
| **Impact** | 18 GPOS audit functions return NotAFinding instead of Open |

### 6.2 AD/LDAP auth-ldap Plugin

When authentication is delegated to Active Directory via the XO auth-ldap plugin:

| Feature | Detail |
|---------|--------|
| **Account Lifecycle** | AD provides centralized account creation, modification, disabling, removal |
| **Notification** | AD includes built-in notification for account events |
| **MFA (Network)** | AD enforces MFA policies for network access |
| **Impact** | 5 GPOS functions return NotAFinding; 4 additional functions benefit |

### 6.3 XOA Deployment Model

XOA (the official Vates appliance) provides additional security controls:

| Feature | Detail |
|---------|--------|
| **UFW Firewall** | Enabled by default — satisfies 3 firewall requirements |
| **Plugin Management** | Centralized plugin configuration via Vates licensing |
| **GPOS Score Impact** | XOA scores 48.48% vs XOCE 46.46% (+2.02%) |

---

## 7. XOA vs XOCE Deployment Comparison

For DoD environments, the assessment data supports a clear recommendation:

| Criterion | XOA (Appliance) | XOCE (Community) |
|-----------|----------------|-------------------|
| **GPOS EvalScore** | 48.48% | 46.46% |
| **ASD EvalScore** | 40.56% | 43.01% |
| **WebSRG EvalScore** | 41.27% | 41.27% |
| **Firewall** | UFW enabled by default | No default firewall |
| **Vendor Support** | Full Vates support | Community only |
| **Plugin Naming** | `-premium` suffix | Standard naming |
| **Plugin Detection** | REST API + JSON-RPC | File-based |
| **Hardening Baseline** | Stronger out-of-box | Requires manual hardening |

**Recommendation:** XOA is the preferred deployment model for DoD environments due to its stronger out-of-box security posture, vendor support commitment, and default firewall configuration.

---

## 8. Summary of Open Findings by Category

### Across All 3 Modules (XO1 — XOCE)

| Category | Total Rules | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|------------|---------------|-------------|------|-------------|
| **CAT I** | 57 | 5 | 21 | 31 | 0 |
| **CAT II** | 521 | 40 | 187 | 294 | 0 |
| **CAT III** | 32 | 5 | 9 | 18 | 0 |
| **Total** | **610** | **50** | **217** | **343** | **0** |

### Across All 3 Modules (XOA — Appliance)

| Category | Total Rules | Not Applicable | NotAFinding | Open | Not Reviewed |
|----------|------------|---------------|-------------|------|-------------|
| **CAT I** | 57 | 6 | 19 | 32 | 0 |
| **CAT II** | 521 | 36 | 189 | 296 | 0 |
| **CAT III** | 32 | 5 | 9 | 18 | 0 |
| **Total** | **610** | **47** | **217** | **346** | **0** |

### Findings Breakdown by Root Cause

| Root Cause | Approx. Count | Responsible Party |
|------------|--------------|-------------------|
| FIPS 140-2 cryptography not validated | 8 | Vates (product change or guidance) |
| No DoD consent banner | 5 | Vates (feature) + Site (nginx config) |
| MFA/2FA not detected (feature exists) | 3 (was 4; V-264343 now resolved) | V-264343 scanner update DONE; 3 remaining require manual review or OS-level MFA |
| TLS 1.1 enabled | 3 | Vates (default change) + Site (config) |
| PAM/password policy not configured | 12 | Site administrator |
| Audit infrastructure (auditd, SIEM) | 12 | Site administrator |
| PKI/certificate management | 4 | Site administrator |
| Session management | 4 | Site administrator |
| System hardening (services, permissions) | 15+ | Site administrator |
| Data-at-rest encryption | 3 | Site administrator |
| Other organizational/policy items | 20+ | ISSO/ISSM organizational policy |

---

## 9. Manual Review Burden — The Adoption Cost of Open Findings

### The Challenge for DoD Adopters

Unlike Broadcom's vSphere/VCF stack — which has **official DISA STIGs, SCAP benchmarks, and a mature vendor-published hardening guide with DoD-specific procedures** — the Vates Virtualization Management Stack lacks official DISA STIGs and SCAP benchmarks. Vates does publish a general-purpose hardening guide (v0.1, May 2024), which is a valuable starting point, but it does not yet include the DoD-specific step-by-step procedures (PAM configuration, FIPS compliance, CAC/PIV integration, etc.) that sysadmins need to close STIG findings.

This is a significant adoption barrier. When a DoD organization evaluates virtualization platforms, the compliance workload is a major factor in the Total Cost of Ownership. A platform with 50 Open findings and a DoD-specific hardening guide is far more attractive than one with 300+ Open findings and only general-purpose security documentation — regardless of licensing cost savings.

### Estimated Manual Review Effort

The following estimates are based on industry experience with STIG compliance workflows on platforms that lack official vendor documentation:

| Task Per Open Finding | Time (No Vendor Guide) | Time (With Vendor Guide) |
|-----------------------|----------------------|------------------------|
| Read and understand the STIG requirement | 5-10 min | 5 min |
| Research how the requirement applies to XO | 15-30 min | 5 min (vendor-documented) |
| Determine if a fix exists or if a POA&M is needed | 10-20 min | 5 min |
| Implement the fix or draft POA&M entry | 15-45 min | 10-15 min |
| Verify and document the remediation | 10-15 min | 5-10 min |
| **Total per finding** | **~1-2 hours** | **~30-40 minutes** |

### Projected Workload for XO (Current State)

Using the XOA scan results (346 Open findings):

| Scenario | Estimated Effort | Calendar Time (1 FTE) |
|----------|-----------------|----------------------|
| **Current state** (general guide exists, 346 Opens) | **250-500 man-hours** | 6-13 weeks |
| **With DoD-specific guide supplement** (346 Opens) | ~175-230 man-hours | 4-6 weeks |
| **If Vates resolves product gaps + scanner MFA fix** (~50 fewer Opens) | ~150-350 man-hours | 4-9 weeks |
| **Best case** (DoD guide + product fixes, ~250 Opens) | ~125-165 man-hours | 3-4 weeks |

For comparison, a sysadmin hardening a **VMware ESXi host** with its official DISA STIG and SCAP benchmark can achieve compliance in approximately **40-80 man-hours** — the SCAP tool automates most checks, the vendor STIG provides exact fix actions, and the community knowledge base covers edge cases.

### The Competitive Implication

DoD organizations choosing between Vates VMS and Broadcom VCF will weigh:

| Factor | Vates VMS (Today) | Broadcom VCF |
|--------|-------------------|--------------|
| Licensing cost | Significantly lower | High (per-CPU) |
| Official DISA STIG | None | Yes (ESXi, vCenter, vSAN) |
| SCAP Benchmark | None | Yes (automated scanning) |
| Vendor Hardening Guide | Yes (general-purpose, v0.1) | Yes (DoD-specific, mature) |
| DoD-specific procedures | Not yet | Yes (step-by-step) |
| Estimated compliance effort | 250-500 hours per host | 40-80 hours per host |
| Community STIG knowledge base | None | Extensive |

**The compliance cost gap is 3-6x.** The existence of Vates' general hardening guide reduces the gap from what it would be with no documentation at all, but the lack of DoD-specific procedures, official STIGs, and SCAP benchmarks still means significantly more manual effort. When multiplied across a fleet of hosts, this can erode the licensing cost advantage.

### The Mutual Benefit of Reducing Opens

Every action Vates takes to reduce Open findings has a multiplier effect across all DoD deployments:

1. **A DoD supplement to the existing hardening guide** could cut per-finding effort by 50-60%, saving each deploying organization hundreds of hours. The existing v0.1 guide is an excellent foundation — adding DoD-specific procedures (PAM, FIPS, CAC/PIV, consent banner) would close the gap
2. **Resolving product gaps** (FIPS, banner, TLS) removes findings that no sysadmin can fix — these are currently hard blockers that require POA&Ms. Note: MFA was previously listed here but XO already supports 2FA/SAML/OIDC — this is a scanner detection issue being resolved
3. **Publishing a SCAP benchmark** would automate initial assessment, reducing the 5-10 minute "understand the requirement" step to seconds
4. **Each Open finding resolved by Vates is resolved for every DoD customer simultaneously** — the ROI scales with adoption

The goal should be to bring the compliance effort for Vates VMS to within 2-3x of VMware's — close enough that the licensing savings make the business case compelling. Based on our assessment, this is achievable with the actions outlined in Section 10.

---

## 10. Recommendations for Vates

### Immediate Actions (for IATT/ATO support)

1. **Publish a DoD supplement to the existing Hardening Guide** — the v0.1 guide (May 2024) is an excellent foundation; add DoD-specific procedures for PAM, FIPS, consent banner, CAC/PIV, and session management (see Section 4.5 gap table)
2. **Provide FIPS 140-2 compliance statement** (even if the answer is "not currently validated" — assessors need official documentation)
3. **Publish nginx consent banner template** for DoD deployments (can be done without product code changes)
4. **Document TLS hardening steps** to disable TLS 1.1 and enforce TLS 1.2+
5. **Document CAC/PIV + SAML/OIDC integration** as the recommended MFA architecture for DoD — the 2FA capability already exists (Section 5.4 of the hardening guide), but DoD needs step-by-step configuration for smart card authentication
6. **Clarify 2FA/SAML/OIDC configuration storage** — provide documentation on where XO stores MFA configuration so automated scanners can detect it

### Product Roadmap Items (for full ATO)

1. **Native pre-login banner with acknowledgment** in the XO web UI
2. **FIPS mode support** (PBKDF2 for local passwords, FIPS-validated TLS libraries)
3. **Disable TLS 1.1 by default** in new releases
4. **SCAP benchmark development** for automated compliance scanning

### Documentation Deliverables

| Document | Priority | Purpose |
|----------|----------|---------|
| DoD Supplement to Hardening Guide | Critical | DoD-specific procedures (PAM, FIPS, banner, CAC/PIV) |
| FIPS 140-2 Compliance Statement | Critical | Official vendor position for ATO package |
| CAC/PIV + SAML/OIDC Integration Guide | High | Step-by-step MFA configuration for DoD smart cards |
| TLS Configuration Guide | High | Steps to enforce TLS 1.2+ minimum |
| XOA Deployment Guide (DoD) | High | DoD-specific appliance deployment procedures |
| Audit Plugin Architecture | Medium | Technical documentation for assessor review |
| Key/Certificate Management Guide | Medium | Cryptographic key storage and lifecycle |

---

## 11. Assessment Methodology

### Framework

- **Tool:** NAVSEA Evaluate-STIG v1.2507.6, extended with custom scan modules
- **Modules:** 3 custom PowerShell modules (610 functions total)
- **Execution:** Remote SSH-based PSRemoting from scanning workstation to target XO systems
- **Output:** DISA STIG Viewer-compatible CKL and CKLB checklist files + XML Summary Reports

### Quality Assurance

- **174+ test iterations** across both deployment models during development
- **Zero Not_Reviewed findings** — every rule has an automated determination
- **Zero scan errors** — all modules complete cleanly with exit code 0
- **Zero VulnTimeouts** — all checks complete within the 15-second timeout
- **CKL validation** — all generated checklists pass DISA STIG Viewer schema validation
- **Answer files** — 2-index matching pattern provides COMMENTS with remediation guidance for every finding

### Scan Command

```powershell
.\Evaluate-STIG.ps1 -ComputerName <target> `
    -SelectSTIG "XO_GPOS_Debian12","XO_ASD","XO_WebSRG" `
    -ScanType Classified -AnswerKey XO -VulnTimeout 15 `
    -Output CKL,CKLB,Summary,Console -AllowIntegrityViolations
```

### Artifacts Provided

The following artifacts are available for assessor review:

| Artifact | Format | Content |
|----------|--------|---------|
| STIG Checklists | CKL, CKLB | Per-rule findings with automated evidence |
| Summary Reports | XML, HTML | Module-level score summaries |
| Scan Logs | LOG | Full execution logs with timing data |
| Answer Files | XML | Remediation guidance for every finding |
| Source Modules | PSM1 | Full source code for all 610 check functions |

---

## 12. Next Steps

1. **Vates Review:** Review this report and prioritize actions in Section 10
2. **DoD Guide Supplement:** Vates to expand the existing Hardening Guide (v0.1) with DoD-specific procedures
3. **Scanner Update (PARTIALLY COMPLETE):** V-264343 now detects native TOTP 2FA via REST API and flips Open &rarr; NotAFinding when all users have 2FA enabled. V-264344 requires organizational attestation (cannot fully automate). V-203642/V-203643 are OS-level PAM/SSH checks not addressable by application-level 2FA.
4. **XCP-ng Assessment:** Begin STIG compliance assessment of XCP-ng hypervisor (437 additional rules across VMM SRG and RHEL7 STIG)
5. **IATT Package Assembly:** Compile CKL files, this report, Vates hardening guide, and POA&M into IATT submission package

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **ASD** | Application Security and Development STIG |
| **ATO** | Authority to Operate |
| **CAT I/II/III** | DISA severity categories (Critical/High/Medium) |
| **CKL/CKLB** | Checklist file formats for DISA STIG Viewer |
| **DISA** | Defense Information Systems Agency |
| **EvalScore** | Percentage of applicable rules that are NotAFinding |
| **FIPS 140-2** | Federal Information Processing Standard for cryptographic modules |
| **GPOS** | General Purpose Operating System SRG |
| **IATT** | Interim Authority to Test |
| **MFA** | Multi-Factor Authentication |
| **SCAP** | Security Content Automation Protocol |
| **SRG** | Security Requirements Guide |
| **STIG** | Security Technical Implementation Guide |
| **WebSRG** | Web Server Security Requirements Guide |
| **XOA** | Xen Orchestra Appliance (official Vates product) |
| **XOCE** | Xen Orchestra Community Edition (built from source) |
| **OIDC** | OpenID Connect (authentication protocol) |
| **SAML** | Security Assertion Markup Language (SSO protocol) |

## Appendix B: Contact

**Assessment Lead:** Kismet Agbasi (KismetG17@gmail.com)
**Project Repository:** https://github.com/kismetgerald/Evaluate-STIG-Mods4VatesVMS

---

*This report was generated based on automated STIG compliance scans performed on March 3, 2026. All findings are backed by machine-generated evidence in the accompanying CKL/CKLB checklist files.*
