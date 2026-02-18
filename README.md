# Evaluate-STIG Modifications for Vates VMS

Custom STIG compliance scanning modules for **Xen Orchestra (XO)** and **XCP-ng**,
extending the [NAVSEA Evaluate-STIG](https://www.niwcatlantic.navy.mil/Technology/SoftwareFactory/Evaluate-STIG/)
framework to support DoD compliance scanning of the
[Vates Virtualization Management Stack](https://vates.tech).

---

## Purpose

No official DISA STIGs or SCAP Benchmarks exist for Xen Orchestra or XCP-ng. This
project adapts applicable Security Requirements Guides (SRGs) and existing STIGs to
enable automated compliance scanning and STIG checklist (CKL/CKLB) generation — supporting
an IATT (Interim Authority to Test) or full ATO (Authority to Operate) for DoD use.

---

## What's Included

### Custom Scan Modules (`Evaluate-STIG/Modules/`)

| Module | STIG / SRG Applied | Target | Checks | Implementation Status |
|---|---|---|---|---|
| `Scan-XO_WebSRG_Checks` | Web Server SRG V4R4 | Xen Orchestra | 126 | :white_check_mark: **Complete** — all 126 checks automated (121 CAT II + 5 CAT I) |
| `Scan-XO_ASD_Checks` | ASD STIG V6R4 | Xen Orchestra | 286 | :construction: **In Progress** — 212/286 checks automated (74%); 15 CAT II batches + CAT I complete; 74 stubs remaining |
| `Scan-XO_GPOS_Debian12_Checks` | GPOS SRG V3R2 | XO (Debian 12) | 198 | :clipboard: **Stub** — all checks return `Not_Reviewed` with auditor guidance (no CAT I in GPOS SRG) |
| `Scan-XCP-ng_VMM_Checks` | VMM SRG V2R2 | XCP-ng Dom0 | 204 | :hammer_and_wrench: **Partial** — 3 CAT I checks automated; remainder return `Not_Reviewed` with manual guidance |
| `Scan-XCP-ng_Dom0_RHEL7_Checks` | RHEL 7 STIG V3R15 (adapted) | XCP-ng Dom0 | 368 | :hammer_and_wrench: **Partial** — 12 CAT I checks automated; remainder return `Not_Reviewed` with manual guidance |

### Modified Framework Files (`Evaluate-STIG/xml/`)

- **`STIGList.xml`** — custom STIG/SRG entries for all five modules
- **`FileList.xml`** — custom module file manifest entries

### Answer Files (`Evaluate-STIG/AnswerFiles/`)

Pre-populated answer files providing ISSO/ISSM guidance and remediation comments
for findings in each module.

### Integration Guide and Documentation (`.Mods_by_Kismet/`)

- **`README.md`** — step-by-step integration guide (start here after cloning)
- **`Docs/MODIFICATIONS.md`** — complete record of every upstream framework change
- **`Docs/VATES_COMPLIANCE_BLOCKERS.md`** — compliance gaps requiring Vates action
- **`Docs/`** — implementation guides, trackers, and session notes

---

## Getting Started

> **This repository does not include the NAVSEA Evaluate-STIG framework.**
> You must obtain it separately from
> [NISC](https://www.niwcatlantic.navy.mil/Technology/SoftwareFactory/Evaluate-STIG/)
> and integrate these modules into it.

See **[`.Mods_by_Kismet/README.md`](.Mods_by_Kismet/README.md)** for complete
step-by-step integration instructions, including:

- Workstation and target system prerequisites
- Required Linux packages (online and air-gapped installation)
- How to integrate all five modules into a fresh Evaluate-STIG installation
- Scan commands for Xen Orchestra and XCP-ng targets
- Answer file configuration and XO API token setup
- Troubleshooting and known compliance gaps
- Framework update and rollback procedures

---

## Framework Modifications

Three upstream Evaluate-STIG files are modified to support XCP-ng and Debian 12.
These are **not** included in this repository (redistribution restrictions), but all
changes are fully documented with `# MODIFIED_BY` inline comments in
[`Docs/MODIFICATIONS.md`](.Mods_by_Kismet/Docs/MODIFICATIONS.md) so they can be
re-applied to any framework version.

| File | Change |
|---|---|
| `Modules/Master_Functions/STIGDetection/STIGDetection.psm1` | XCPng and Debian 12 OS detection |
| `Modules/Master_Functions/FormatOutput/FormatOutput.psm1` | Null-check fix for XCCDF generation on XCP-ng |
| `Modules/Master_Functions/Master_Functions.psm1` | Network interface filter (hypervisor virtual interfaces) |

---

## XO Deployment Models

Checks support both XO deployment models where applicable:

- **XOA** — Official Vates appliance (UFW firewall enabled by default)
- **XOCE** — Community Edition built from source (user-configurable firewall)

---

## Known Compliance Gaps

The following findings will always return **Open** until addressed at the product level.
Document in your POA&M and System Security Plan:

| Finding | Impact |
|---|---|
| bcrypt password hashing (not FIPS 140-2 validated) | CAT I — requires LDAP/AD integration or code change |
| No built-in MFA/2FA | CAT II — requires LDAP + smart card integration |
| TLS 1.1 enabled | CAT II — requires XO configuration change |
| No centralized audit server | CAT II — organizational requirement |

See [`Docs/VATES_COMPLIANCE_BLOCKERS.md`](.Mods_by_Kismet/Docs/VATES_COMPLIANCE_BLOCKERS.md)
for full details and recommended mitigations.

---

## Authors

**Modifications by:** Kismet Agbasi
**Original Framework:** NAVSEA / NIWC Atlantic
**Developed with:** GitHub Copilot and Claude Code (Anthropic)
