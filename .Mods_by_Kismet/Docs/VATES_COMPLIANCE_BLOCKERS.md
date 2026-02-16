# Vates Virtualization Stack - Compliance Blockers & Requirements

**Purpose:** Track compliance blockers, missing packages/features, and items requiring Vates team input for DoD STIG compliance approval (IATT/ATO).

**Last Updated:** February 16, 2026
**Document Owner:** Kismet Agbasi
**Target:** DoD Classified Environment Approval (IATT for PoC or Full ATO for Production)

---

## Executive Summary

The Vates Virtualization Management Stack (Xen Orchestra + XCP-ng) currently has **no official DISA STIG or SCAP Benchmark**. This document tracks blockers and requirements for achieving compliance using adapted SRGs:

| Component | Applicable STIGs/SRGs | Rule Count | Current Status |
|-----------|----------------------|------------|----------------|
| **Xen Orchestra** | ASD STIG + Web SRG + Debian12 GPOS SRG | 286 + 126 + 198 = 610 | WebSRG 100% complete |
| **XCP-ng Hypervisor** | VMM SRG + RHEL7 STIG + GPOS SRG | 204 + 368 + 198 = 770 | Framework complete, CAT I done |
| **Total** | 5 STIGs/SRGs | ~1,047 rules | XO WebSRG fully automated |

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

---

## Section 3: Xen Orchestra - Web Server SRG (Complete - Findings Summary)

XO WebSRG module is **100% implemented** (121 CAT II + 5 CAT I). Key open findings on XO1 (XOCE deployment):

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

## Section 5: Debian 12 GPOS - Additional Findings

| VulnID | Rule Title | Status | Notes |
|--------|------------|--------|-------|
| V-254521 | SSH Protocol 2 only | Verify | Default Debian 12 SSH |
| V-254540 | Account lockout | Verify | PAM faillock for Debian |

---

## Section 6: Immediate Actions Required

### From Vates Team (Priority Order)

1. **[CRITICAL] FIPS 140-2 Statement** - Official position on bcrypt and FIPS compliance path (Section 1.1)
2. **[CRITICAL] MFA Integration Guide** - CAC/PIV or hardware token integration for DoD (Section 1.5)
3. **[HIGH] DoD Banner Implementation** - Nginx consent page template OR native XO banner feature (Section 1.8)
4. **[HIGH] Hardening Guide** - Official XOA and XCP-ng hardening documentation
5. **[HIGH] TLS Configuration Guide** - How to disable TLS 1.0/1.1, enforce TLS 1.2+ (Section 1.2)
6. **[HIGH] UTC Timezone Configuration** - XO deployment recommendation for DoD (Section 1.3)
7. **[MEDIUM] Cryptographic Statement** - Key storage architecture documentation (Section 1.7)
8. **[MEDIUM] xe CLI Reference** - Security-relevant xe commands for audit evidence
9. **[MEDIUM] Log Format Documentation** - xen.log and audit log formats for SIEM integration
10. **[LOW] AppArmor-to-SELinux Equivalence** - For Debian 12 GPOS SRG compliance

### From Implementation Team

1. ✅ Complete WebSRG checks (121/121 CAT II) - **DONE** (February 9, 2026)
2. ✅ Framework baseline stable - **DONE** (all scans exit code 0)
3. Continue XO ASD CAT II implementation
4. Continue XCP-ng VMM and Dom0 GPOS CAT II implementation
5. Develop answer file entries for remaining modules (ASD, Dom0, VMM)

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
| Test137 | February 16, 2026 | XO1.WGSDAC.NET (XOCE) | ASD Batch 4: V-222426–V-222435, EvalScore 9.79% |
| Test119e | February 9, 2026 | XO1.WGSDAC.NET (XOCE) | WebSRG 100% complete, 4-minute scan |
| Test113d | February 3, 2026 | XO1.WGSDAC.NET (XOCE) | Session #32 Batch 2 validated |
| Test112b | February 3, 2026 | XO1.WGSDAC.NET (XOCE) | Session #32 Batch 1 validated |
| Test111b | February 2, 2026 | XO1.WGSDAC.NET (XOCE) | Session #31 validated |

**Framework:** NAVSEA Evaluate-STIG v1.2507.6 with Kismet Agbasi modifications
**Module:** Scan-XO_WebSRG_Checks v1.0 (32,805 lines, 126 functions)

---

## Appendix B: Contact Information

**Implementation Team:**
- Kismet Agbasi - Project Lead

**Vates Team:**
- Support: https://xen-orchestra.com/contact
- GitHub: https://github.com/vatesfr/xen-orchestra

---

**Document Status:** ACTIVE - Updated based on Session #39 (Batch 4, DoD Banner blocker added)
**Classification:** UNCLASSIFIED
**Distribution:** Limited to implementation team and Vates engineering
