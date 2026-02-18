# Evaluate-STIG Custom Integration Guide
## Vates Virtualization Stack — Xen Orchestra & XCP-ng

**Prepared by:** Kismet Agbasi
**Last Updated:** February 11, 2026 (Session #35)
**Framework Base:** NAVSEA Evaluate-STIG v1.2507.6

---

## Overview

This guide explains how to integrate the custom STIG check modules for Xen Orchestra (XO) and
XCP-ng into a fresh installation of the NAVSEA Evaluate-STIG framework, and how to run
compliance scans against both types of target systems.

The custom modules cover five STIG/SRG documents:

| Module Name | STIG/SRG | Target System | ShortName |
|---|---|---|---|
| `Scan-XCP-ng_VMM_Checks` | Virtual Machine Manager SRG V2R2 | XCP-ng hypervisor | `XCP-ng_VMM` |
| `Scan-XCP-ng_Dom0_RHEL7_Checks` | Red Hat Enterprise Linux 7 STIG V3R15 | XCP-ng Dom0 (RHEL 7-based) | `XCP-ng_Dom0_RHEL7` |
| `Scan-XO_GPOS_Debian12_Checks` | General Purpose OS SRG V3R2 | XO host OS (Debian 12) | `XO_GPOS_Debian12` |
| `Scan-XO_ASD_Checks` | Application Security & Development STIG V6R4 | Xen Orchestra application | `XO_ASD` |
| `Scan-XO_WebSRG_Checks` | Web Server SRG V4R4 | Xen Orchestra web interface | `XO_WebSRG` |

---

## Prerequisites

### Scanning Workstation (where you run Evaluate-STIG)

- **Windows 10/11 or Windows Server 2016+**
- **PowerShell 7.2 or later** (download from https://github.com/PowerShell/PowerShell/releases)
- **OpenSSH client** enabled (Settings → Apps → Optional Features → OpenSSH Client)
- Network access to target systems (TCP port 22 for SSH)
- The Evaluate-STIG framework extracted to a local path (e.g., `C:\Evaluate-STIG\`)

Verify your PowerShell version before proceeding:
```powershell
$PSVersionTable.PSVersion
```

### Target System — XCP-ng Hypervisor

- **XCP-ng 8.x** (based on CentOS 7 / RHEL 7)
- **PowerShell 7.3.12** installed on the Dom0 (NOT 7.4+ — incompatible with XCP-ng's glibc version)
- SSH enabled with root or an account with sudo access
- PowerShell SSH remoting configured (see "SSH Remoting Setup" below)

### Target System — Xen Orchestra (XO)

- **XO installed on Debian 12** (either XOA appliance or XOCE from source)
- **PowerShell 7.4 or later** installed on the Debian 12 host
- SSH enabled with root or an account with sudo access
- PowerShell SSH remoting configured

#### Required Linux Packages on Target Systems

Evaluate-STIG requires these packages to be present on **every Linux target** before running
a scan. Missing packages will cause asset data collection to fail silently or produce
incomplete results.

| Package | Purpose | Required On |
|---|---|---|
| `lshw` | Hardware inventory (CPU, memory, storage) | XCP-ng and Debian 12 (XO) |
| `libicu` | Unicode support required by PowerShell | XCP-ng and Debian 12 (XO) |
| `dmidecode` | BIOS/UEFI and hardware ID retrieval | XCP-ng and Debian 12 (XO) |
| `bc` | Arithmetic used in scoring calculations | XCP-ng and Debian 12 (XO) |

**Install on Debian 12 (XO host):**

```bash
apt-get update
apt-get install -y lshw libicu-dev dmidecode bc
```

**Install on XCP-ng (Dom0 — uses yum/rpm, not apt):**

```bash
yum install -y lshw dmidecode bc
# libicu is typically included with the PowerShell 7.3.12 RPM dependencies;
# if PowerShell fails to start, install it manually:
yum install -y libicu
```

Verify the packages are available before running your first scan:

```bash
# On either target system
for pkg in lshw dmidecode bc; do
    which $pkg && echo "$pkg: OK" || echo "$pkg: MISSING"
done
pwsh --version && echo "PowerShell: OK" || echo "PowerShell: MISSING"
```

#### Offline / Air-Gapped Package Installation

In air-gapped DoD environments, target systems have no direct Internet access. All packages
must be downloaded on an Internet-connected system first, transferred via approved media
(removable drive, jump host, or authorized file transfer), and then installed locally.

---

**Debian 12 (XO host) — Offline Package Download**

Use an Internet-connected system running **Debian 12** (matching the target OS) to download
the packages and all their dependencies into a single folder:

```bash
# On the INTERNET-CONNECTED Debian 12 system
mkdir ~/stig-packages && cd ~/stig-packages

# Download packages and all dependencies into current directory
apt-get install --download-only --reinstall -o Dir::Cache::Archives="$(pwd)" \
    lshw libicu72 dmidecode bc 2>/dev/null

# Verify: list all downloaded .deb files
ls -lh *.deb
```

> **Note:** The PowerShell runtime dependency on Debian 12 is `libicu72` (the shared library),
> not `libicu-dev` (development headers). Use `libicu72` for runtime-only installs.

Transfer the entire folder to the air-gapped XO host via approved media, then install:

```bash
# On the AIR-GAPPED XO host (Debian 12)
cd /path/to/transferred/packages

# Install all .deb files — dpkg resolves order automatically
dpkg -i *.deb

# If dpkg reports dependency errors, fix them in-place (no network needed):
apt-get install --fix-broken -o Dir::Cache::Archives="$(pwd)"
```

---

**XCP-ng Dom0 — Offline Package Download**

Use an Internet-connected system running **RHEL 7 or CentOS 7** (matching Dom0's base OS)
to download the RPM packages and their dependencies:

```bash
# On the INTERNET-CONNECTED RHEL 7/CentOS 7 system
yum install -y yum-utils       # provides yumdownloader
mkdir ~/stig-rpms && cd ~/stig-rpms

# Download packages AND all dependencies recursively
yumdownloader --resolve --destdir="$(pwd)" lshw libicu dmidecode bc

# Verify: list downloaded RPMs
ls -lh *.rpm
```

Transfer the folder to the air-gapped XCP-ng Dom0, then install:

```bash
# On the AIR-GAPPED XCP-ng Dom0
cd /path/to/transferred/rpms

# Install all RPMs (yum localinstall handles dependency ordering)
yum localinstall -y *.rpm

# Alternative if yum is unavailable:
rpm -ivh --nodeps *.rpm
```

---

**PowerShell — Offline Installation**

Download the PowerShell packages on an Internet-connected system and transfer them.

*For XCP-ng (Dom0) — must be version 7.3.12:*

```bash
# On the INTERNET-CONNECTED system
# Download the RPM directly from GitHub Releases
curl -LO https://github.com/PowerShell/PowerShell/releases/download/v7.3.12/powershell-7.3.12-1.rh.x86_64.rpm

# Also download the libicu dependency if not already present on target:
yumdownloader --destdir=. libicu
```

Transfer the `.rpm` file(s) to the air-gapped XCP-ng Dom0:

```bash
# On the AIR-GAPPED XCP-ng Dom0
rpm -ivh libicu-*.rpm          # install dependency first (if needed)
rpm -ivh powershell-7.3.12-1.rh.x86_64.rpm
pwsh --version                 # verify: should show 7.3.12
```

*For Debian 12 (XO host):*

```bash
# On the INTERNET-CONNECTED system
# Download the Microsoft packages-microsoft-prod .deb and the powershell .deb
wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb
# Then resolve and download powershell + its dependencies
dpkg -i packages-microsoft-prod.deb
apt-get update
mkdir ~/ps-packages
apt-get install --download-only -o Dir::Cache::Archives="$(pwd)/ps-packages" powershell
```

Transfer all `.deb` files in `ps-packages/` to the air-gapped XO host:

```bash
# On the AIR-GAPPED XO host (Debian 12)
dpkg -i /path/to/ps-packages/*.deb
pwsh --version                 # verify: should show 7.4.x or later
```

---

**Verifying All Packages After Offline Install**

Run this on the target after installation to confirm everything is in place:

```bash
echo "=== Package Check ===" && \
for pkg in lshw dmidecode bc; do
    which $pkg > /dev/null 2>&1 && echo "$pkg: OK ($(which $pkg))" || echo "$pkg: MISSING"
done && \
pwsh -Command 'Write-Host "PowerShell: OK ($($PSVersionTable.PSVersion))"' 2>/dev/null \
    || echo "PowerShell: MISSING or failed to start"
```

All five items should report OK before proceeding with scans.

---

#### Install PowerShell on XCP-ng (Dom0) — Version 7.3.12 ONLY

```bash
# On the XCP-ng Dom0 shell
# Download PowerShell 7.3.12 RPM for RHEL 7
curl -LO https://github.com/PowerShell/PowerShell/releases/download/v7.3.12/powershell-7.3.12-1.rh.x86_64.rpm
rpm -ivh powershell-7.3.12-1.rh.x86_64.rpm
```

> **WARNING:** Do NOT install PowerShell 7.4+ on XCP-ng. It requires a newer glibc version
> than XCP-ng 8.x provides and will fail to start.

#### Install PowerShell on Debian 12 (XO Host)

```bash
# On the Debian 12 / XO host shell
apt-get update && apt-get install -y wget apt-transport-https software-properties-common
wget -q "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb"
dpkg -i packages-microsoft-prod.deb
apt-get update && apt-get install -y powershell
```

#### Configure SSH Remoting on Target Systems

Run these commands on each target system to allow PowerShell remoting over SSH:

```bash
# On the target Linux host (XCP-ng or Debian 12)

# Edit sshd_config to allow PowerShell subsystem
echo "Subsystem powershell /usr/bin/pwsh -sshs -NoLogo" >> /etc/ssh/sshd_config
systemctl restart sshd

# Verify pwsh path (use the actual path from 'which pwsh')
which pwsh
```

#### Test SSH Remoting from Workstation

Before running scans, verify you can establish a remote PowerShell session:

```powershell
# From your scanning workstation (PowerShell 7)
$session = New-PSSession -HostName "xo1.example.com" -UserName "root" -SSHTransport
Invoke-Command -Session $session -ScriptBlock { $PSVersionTable.PSVersion }
Remove-PSSession $session
```

A successful response shows the remote PowerShell version. If this fails, scans will not work.

---

## File Structure

This `.Mods_by_Kismet/` folder contains all custom files for the integration:

```
.Mods_by_Kismet/
├── README.md                          ← This file
├── Docs/                              ← Implementation documentation
│   ├── STATUS.md                      ← Current project status
│   ├── MODIFICATIONS.md               ← All framework file changes with inline diffs
│   ├── VATES_COMPLIANCE_BLOCKERS.md   ← Known compliance blockers
│   └── XO_v5.x_WebSRG/               ← WebSRG-specific implementation docs
└── Test/                              ← Test and integration scripts
    ├── *.py                           ← Python helper/fix scripts
    └── *.ps1                          ← PowerShell test scripts
```

The custom modules themselves live inside the framework at:

```
Evaluate-STIG/
├── Modules/
│   ├── Scan-XCP-ng_VMM_Checks/        ← VMM SRG checks for XCP-ng
│   ├── Scan-XCP-ng_Dom0_RHEL7_Checks/ ← RHEL 7 STIG checks for XCP-ng Dom0
│   ├── Scan-XO_GPOS_Debian12_Checks/  ← GPOS SRG checks for Debian 12 (XO host)
│   ├── Scan-XO_ASD_Checks/            ← ASD STIG checks for Xen Orchestra
│   └── Scan-XO_WebSRG_Checks/         ← Web SRG checks for Xen Orchestra
├── xml/
│   ├── STIGList.xml                   ← MODIFIED: custom STIG entries added
│   └── FileList.xml                   ← MODIFIED: custom module file entries added
├── StigContent/
│   ├── U_Virtual_Machine_Manager_SRG_V2R2_Manual-xccdf.xml
│   ├── U_RHEL_7_STIG_V3R15_Manual-xccdf.xml
│   ├── U_GPOS_SRG_V3R2_Manual-xccdf.xml
│   ├── U_ASD_STIG_V6R4_Manual-xccdf.xml
│   └── U_Web_Server_SRG_V4R4_Manual-xccdf.xml
└── AnswerFiles/
    └── XO_v5.x_WebSRG_AnswerFile.xml  ← Answer file providing COMMENTS for WebSRG
```

---

## Integration Steps (Fresh Evaluate-STIG Install)

Follow these steps in order when applying this custom integration to a new copy of
Evaluate-STIG v1.2507.6.

### Step 1 — Copy Custom Module Folders

Copy the five custom module folders into the framework's `Modules/` directory:

```
Source (this project):  Evaluate-STIG/Modules/Scan-XCP-ng_VMM_Checks/
Destination:            <Evaluate-STIG-root>/Modules/Scan-XCP-ng_VMM_Checks/

Source:  Evaluate-STIG/Modules/Scan-XCP-ng_Dom0_RHEL7_Checks/
Destination:  <Evaluate-STIG-root>/Modules/Scan-XCP-ng_Dom0_RHEL7_Checks/

Source:  Evaluate-STIG/Modules/Scan-XO_GPOS_Debian12_Checks/
Destination:  <Evaluate-STIG-root>/Modules/Scan-XO_GPOS_Debian12_Checks/

Source:  Evaluate-STIG/Modules/Scan-XO_ASD_Checks/
Destination:  <Evaluate-STIG-root>/Modules/Scan-XO_ASD_Checks/

Source:  Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/
Destination:  <Evaluate-STIG-root>/Modules/Scan-XO_WebSRG_Checks/
```

Each module folder contains two files: a `.psd1` manifest and a `.psm1` implementation file.

### Step 2 — Copy XCCDF Content Files

The framework needs XCCDF benchmark files in the `StigContent/` folder. Copy these five files
from this project's `Evaluate-STIG/StigContent/` to the new install:

- `U_Virtual_Machine_Manager_SRG_V2R2_Manual-xccdf.xml`
- `U_RHEL_7_STIG_V3R15_Manual-xccdf.xml`
- `U_GPOS_SRG_V3R2_Manual-xccdf.xml`
- `U_ASD_STIG_V6R4_Manual-xccdf.xml`
- `U_Web_Server_SRG_V4R4_Manual-xccdf.xml`

If these files are not present, download them from https://public.cyber.mil/stigs/downloads/
(search for "Virtual Machine Manager SRG", "Red Hat Enterprise Linux 7", "General Purpose OS SRG",
"Application Security and Development STIG", "Web Server SRG").

### Step 3 — Copy the Answer File

```
Source:       Evaluate-STIG/AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml
Destination:  <Evaluate-STIG-root>/AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml
```

The answer file provides the COMMENTS field content in generated checklists for the WebSRG module.
It also allows the framework to apply organizational overrides.

### Step 4 — Modify STIGList.xml

Open `<Evaluate-STIG-root>/xml/STIGList.xml` in a text editor. Just before the closing `</List>`
tag at the very end of the file, add the following five STIG entries:

```xml
  <!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCP-ng VMM SRG check module -->
  <STIG>
    <Name>Virtual Machine Manager (VMM) SRG - XCP-ng</Name>
    <ShortName>XCP-ng_VMM</ShortName>
    <StigContent>U_Virtual_Machine_Manager_SRG_V2R2_Manual-xccdf.xml</StigContent>
    <ContentHash>000BDF32E7B39080813F9FF9E4E4CB0F39F30998AD229857679185A4A3C5351D</ContentHash>
    <StigSource>Virtual_Machine_Manager_SRG.zip</StigSource>
    <SourceHash>000BDF32E7B39080813F9FF9E4E4CB0F39F30998AD229857679185A4A3C5351D</SourceHash>
    <Counts CATI="0" CATII="162" CATIII="31" />
    <DisaCommonName>Virtual Machine Manager (VMM) SRG</DisaCommonName>
    <DisaStatus>Active</DisaStatus>
    <DetectionCode>Return (Test-IsRunningOS -Version XCPng)</DetectionCode>
    <PsModule>Scan-XCP-ng_VMM_Checks</PsModule>
    <PsModuleVer>1.2026.1.16</PsModuleVer>
    <UserSettings>false</UserSettings>
    <CanCombine>true</CanCombine>
    <AssetType>Other</AssetType>
    <Classification>UNCLASSIFIED</Classification>
    <ApplicableOS>Linux</ApplicableOS>
    <CklTechArea>Other Review</CklTechArea>
  </STIG>
  <!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCP-ng Dom0 RHEL7 STIG check module -->
  <STIG>
    <Name>XCP-ng Dom0 (derived from Red Hat Enterprise Linux 7)</Name>
    <ShortName>XCP-ng_Dom0_RHEL7</ShortName>
    <StigContent>U_RHEL_7_STIG_V3R15_Manual-xccdf.xml</StigContent>
    <ContentHash>0000000000000000000000000000000000000000000000000000000000000000</ContentHash>
    <StigSource>RHEL_7_STIG.zip</StigSource>
    <SourceHash>0000000000000000000000000000000000000000000000000000000000000000</SourceHash>
    <Counts CATI="26" CATII="205" CATIII="13" />
    <DisaCommonName>Red Hat Enterprise Linux 7 STIG</DisaCommonName>
    <DisaStatus>Sunset</DisaStatus>
    <DetectionCode>Return (Test-IsRunningOS -Version XCPng)</DetectionCode>
    <PsModule>Scan-XCP-ng_Dom0_RHEL7_Checks</PsModule>
    <PsModuleVer>1.2026.1.16</PsModuleVer>
    <UserSettings>false</UserSettings>
    <CanCombine>true</CanCombine>
    <AssetType>Other</AssetType>
    <Classification>UNCLASSIFIED</Classification>
    <ApplicableOS>Linux</ApplicableOS>
    <CklTechArea>UNIX OS</CklTechArea>
  </STIG>
  <!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XO GPOS Debian12 SRG check module -->
  <STIG>
    <Name>Xen Orchestra - Debian 12 - General Purpose Operating System (GPOS) SRG</Name>
    <ShortName>XO_GPOS_Debian12</ShortName>
    <StigContent>U_GPOS_SRG_V3R2_Manual-xccdf.xml</StigContent>
    <ContentHash>916AB279D897DF209F09669BAF9325F834D5D2A5B3F07A12553DA4B650FA2335</ContentHash>
    <StigSource>GPOS_SRG.zip</StigSource>
    <SourceHash>916AB279D897DF209F09669BAF9325F834D5D2A5B3F07A12553DA4B650FA2335</SourceHash>
    <Counts CATI="18" CATII="170" CATIII="10" />
    <DisaCommonName>General Purpose Operating System (GPOS) SRG</DisaCommonName>
    <DisaStatus>Active</DisaStatus>
    <DetectionCode>Return (Test-IsRunningOS -Version Debian12)</DetectionCode>
    <PsModule>Scan-XO_GPOS_Debian12_Checks</PsModule>
    <PsModuleVer>1.2026.1.16</PsModuleVer>
    <UserSettings>false</UserSettings>
    <CanCombine>false</CanCombine>
    <AssetType>Other</AssetType>
    <Classification>UNCLASSIFIED</Classification>
    <ApplicableOS>Linux</ApplicableOS>
    <CklTechArea>UNIX OS</CklTechArea>
  </STIG>
  <!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added Xen Orchestra ASD STIG check module -->
  <STIG>
    <Name>Xen Orchestra Application (ASD STIG)</Name>
    <ShortName>XO_ASD</ShortName>
    <StigContent>U_ASD_STIG_V6R4_Manual-xccdf.xml</StigContent>
    <ContentHash>AA3176DB372C3EC336D9489E59D67A4B8AC5A60BD08FFEF65A5D687EAF7329A3</ContentHash>
    <StigSource>U_ASD_STIG_V6R4_Manual-xccdf.xml</StigSource>
    <SourceHash>AA3176DB372C3EC336D9489E59D67A4B8AC5A60BD08FFEF65A5D687EAF7329A3</SourceHash>
    <Counts CATI="0" CATII="0" CATIII="0" />
    <DisaCommonName>Application Security and Development STIG</DisaCommonName>
    <DisaStatus>Active</DisaStatus>
    <DetectionCode>Return (Test-IsRunningOS -Version Debian12)</DetectionCode>
    <PsModule>Scan-XO_ASD_Checks</PsModule>
    <PsModuleVer>1.2026.1.16</PsModuleVer>
    <UserSettings>false</UserSettings>
    <CanCombine>false</CanCombine>
    <AssetType>Other</AssetType>
    <Classification>UNCLASSIFIED</Classification>
    <ApplicableOS>Linux</ApplicableOS>
    <CklTechArea>Application Review</CklTechArea>
  </STIG>
  <!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added Xen Orchestra Web Server SRG check module -->
  <STIG>
    <Name>Xen Orchestra Web Server (Web SRG)</Name>
    <ShortName>XO_WebSRG</ShortName>
    <StigContent>U_Web_Server_SRG_V4R4_Manual-xccdf.xml</StigContent>
    <ContentHash>7C29E49489B4AF2632988B6E14A25CF753830412A7A2382C9CDB12F6C7E82F21</ContentHash>
    <StigSource>U_Web_Server_SRG_V4R4_Manual-xccdf.xml</StigSource>
    <SourceHash>7C29E49489B4AF2632988B6E14A25CF753830412A7A2382C9CDB12F6C7E82F21</SourceHash>
    <Counts CATI="0" CATII="0" CATIII="0" />
    <DisaCommonName>Web Server SRG</DisaCommonName>
    <DisaStatus>Active</DisaStatus>
    <DetectionCode>Return (Test-IsRunningOS -Version Debian12)</DetectionCode>
    <PsModule>Scan-XO_WebSRG_Checks</PsModule>
    <PsModuleVer>1.2026.1.16</PsModuleVer>
    <UserSettings>false</UserSettings>
    <CanCombine>false</CanCombine>
    <AssetType>Other</AssetType>
    <Classification>UNCLASSIFIED</Classification>
    <ApplicableOS>Linux</ApplicableOS>
    <CklTechArea>Web Review</CklTechArea>
  </STIG>
```

### Step 5 — Modify FileList.xml

Open `<Evaluate-STIG-root>/xml/FileList.xml`. Just before the closing `</List>` tag at the
very end of the file, add the following entries for all five custom modules:

```xml
  <!-- MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Custom modules moved to Modules/ directory (updated 01/17/2026) -->
  <File Name="Scan-XCP-ng_VMM_Checks.psd1">
    <Path>\Modules\Scan-XCP-ng_VMM_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XCP-ng_VMM_Checks.psm1">
    <Path>\Modules\Scan-XCP-ng_VMM_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XCP-ng_Dom0_RHEL7_Checks.psd1">
    <Path>\Modules\Scan-XCP-ng_Dom0_RHEL7_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XCP-ng_Dom0_RHEL7_Checks.psm1">
    <Path>\Modules\Scan-XCP-ng_Dom0_RHEL7_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XO_GPOS_Debian12_Checks.psd1">
    <Path>\Modules\Scan-XO_GPOS_Debian12_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XO_GPOS_Debian12_Checks.psm1">
    <Path>\Modules\Scan-XO_GPOS_Debian12_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XO_ASD_Checks.psd1">
    <Path>\Modules\Scan-XO_ASD_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XO_ASD_Checks.psm1">
    <Path>\Modules\Scan-XO_ASD_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XO_WebSRG_Checks.psd1">
    <Path>\Modules\Scan-XO_WebSRG_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
  <File Name="Scan-XO_WebSRG_Checks.psm1">
    <Path>\Modules\Scan-XO_WebSRG_Checks</Path>
    <ScanReq>Required</ScanReq>
    <SHA256Hash></SHA256Hash>
  </File>
```

> **Note:** The `<SHA256Hash>` fields are intentionally left empty for custom modules. The
> framework will warn about integrity violations — this is expected. You must use the
> `-AllowIntegrityViolations` flag when running all scans (see Running Scans below).

### Step 6 — Modify STIGDetection.psm1

Open `<Evaluate-STIG-root>/Modules/Master_Functions/STIGDetection/STIGDetection.psm1`.

This file contains the OS detection logic that determines which STIGs apply to a given target.
You need to add XCP-ng and Debian 12 detection.

#### 6a. Add `XCPng` to the ValidateSet (around line 1049)

Find the `ValidateSet` parameter for the `Test-IsRunningOS` function and add `XCPng` to the
list. Look for a line like:

```powershell
[ValidateSet("Windows10", "Windows11", "RHEL7", "RHEL8", ...)]
```

Add `"XCPng"` and `"Debian12"` to this list.

#### 6b. Add XCPng detection case (around line 1268)

In the switch/case block that tests OS types, add a case for `XCPng`. The detection must check
both `ID=xcp-ng` and `ID=xenenterprise` (XCP-ng 8.x uses `xenenterprise` in `/etc/os-release`):

```powershell
# MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added XCP-ng hypervisor detection
# MODIFIED_BY: Kismet Agbasi on 01/18/2026 - Added ID=xenenterprise detection (XCP-ng 8.x uses xenenterprise in /etc/os-release)
"XCPng" {
    $OSRelease = $(Get-Content /etc/os-release 2>&1)
    If ($OSRelease -like '*ID=xcp-ng*' -or $OSRelease -like '*ID="xcp-ng"*' -or
        $OSRelease -like '*ID=xenenterprise*' -or $OSRelease -like '*ID="xenenterprise"*' -or
        $OSRelease -like '*PLATFORM_NAME="XCP-ng"*') {
        Return $true
    }
    Return $false
}
```

#### 6c. Add Debian12 detection case

Similarly, add a case for `Debian12`:

```powershell
# MODIFIED_BY: Kismet Agbasi on 01/16/2026 - Added Debian 12 detection for Xen Orchestra
"Debian12" {
    $OSRelease = $(Get-Content /etc/os-release 2>&1)
    If ($OSRelease -like '*NAME="Debian*"*' -and $OSRelease -like '*VERSION_ID="12"*') {
        Return $true
    }
    Return $false
}
```

For the exact diff, see `Docs/MODIFICATIONS.md` in this folder.

### Step 7 — Modify FormatOutput.psm1

Open `<Evaluate-STIG-root>/Modules/Master_Functions/FormatOutput/FormatOutput.psm1`.

Find the section around line 1443 that writes XCCDF `<fact>` elements. It contains a loop
like this:

```powershell
ForEach ($Item in @("HostName", "FQDN", "MacAddress", "IpAddress", ...)) {
    $xmlWriter.WriteAttributeString("type", $ScanObject.TargetData.$Item.GetType().Name.ToLower())
```

The `.GetType()` call will throw a null reference error when Linux systems leave some fields
empty (e.g., `MacAddress`, `IpAddress`). Wrap it with a null check:

```powershell
# MODIFIED_BY: Kismet Agbasi on 01/18/2026 - Added null check to prevent crash on XCP-ng
ForEach ($Item in @("HostName", "FQDN", "MacAddress", "IpAddress", "Role", "WebOrDatabase", "Instance", "Site")) {
    $ItemValue = $ScanObject.TargetData.$Item
    $xmlWriter.WriteStartElement("cdf", "fact", $Namespace)
    If ($null -eq $ItemValue -or $ItemValue -eq "") {
        $xmlWriter.WriteAttributeString("type", "string")
        $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($Item.ToLower())")
        $xmlWriter.WriteString("")
    }
    Else {
        $xmlWriter.WriteAttributeString("type", $ItemValue.GetType().Name.ToLower())
        $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($Item.ToLower())")
        $xmlWriter.WriteString("$ItemValue")
    }
    $xmlWriter.WriteEndElement()
}
```

Without this fix, XCCDF output files will not generate when scanning XCP-ng hosts.

### Step 8 — Modify Master_Functions.psm1

Open `<Evaluate-STIG-root>/Modules/Master_Functions/Master_Functions.psm1`.

Find the Linux network interface enumeration (around line 2647). The original uses `ip addr`
which returns ALL interfaces including virtual ones created by the hypervisor. Replace it with
a version that only returns interfaces with active IPv4 addresses:

```powershell
# MODIFIED_BY: Kismet Agbasi on 01/19/2026 - Filter to only interfaces with IPv4 addresses
$NetAdapters = @(ip -4 addr | grep -B1 "inet " | grep "^[0-9]\+:" | awk '{print $2}' | sed 's/://')
```

Without this fix, XCP-ng hosts will report dozens of virtual/bridge interfaces as network
adapters in the scan output.

---

## Running Scans

All scans must be run from your scanning workstation (Windows, PowerShell 7.2+). Navigate to
the Evaluate-STIG root directory first:

```powershell
cd "C:\Evaluate-STIG"   # adjust path to your installation
```

### Verify Module Loading (Pre-Scan Check)

Before running a full scan, confirm the custom modules load without errors:

```powershell
# Test XO modules
Import-Module ".\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1" -Force -ErrorAction Stop
(Get-Command -Module Scan-XO_WebSRG_Checks).Count
# Expected: 126

Import-Module ".\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psd1" -Force -ErrorAction Stop
(Get-Command -Module Scan-XO_ASD_Checks).Count
# Expected: 286

# Test XCP-ng modules
Import-Module ".\Modules\Scan-XCP-ng_VMM_Checks\Scan-XCP-ng_VMM_Checks.psd1" -Force -ErrorAction Stop
(Get-Command -Module Scan-XCP-ng_VMM_Checks).Count
# Expected: 204
```

If any module fails to load or shows fewer functions than expected, do not proceed with scans.
Check the error message — it usually points to a syntax error in the module file.

### Scan a Xen Orchestra (XO) Host

XO runs on Debian 12. All three XO-related STIGs apply simultaneously:

```powershell
.\Evaluate-STIG.ps1 `
    -ComputerName "xo1.example.com" `
    -SelectSTIG "XO_GPOS_Debian12","XO_ASD","XO_WebSRG" `
    -AnswerKey "XO" `
    -AnswerFile ".\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml" `
    -Output CKL `
    -AllowIntegrityViolations
```

**Parameter Reference:**

| Parameter | Purpose |
|---|---|
| `-ComputerName` | Hostname or IP address of the XO server |
| `-SelectSTIG` | Comma-separated list of STIG short names to scan |
| `-AnswerKey` | Must be `"XO"` to match entries in the answer file |
| `-AnswerFile` | Path to the answer file for COMMENTS field population |
| `-Output CKL` | Generates `.ckl` checklist files (use `CKLB` for newer viewer) |
| `-AllowIntegrityViolations` | Required — custom modules have no hash in FileList.xml |

**Output files** will be saved to `.\Results\<hostname>\<date>\` by default.

#### Optional: Scan with SSH credentials

If you do not have a default SSH key configured, specify credentials:

```powershell
.\Evaluate-STIG.ps1 `
    -ComputerName "xo1.example.com" `
    -SSHUsername "root" `
    -SelectSTIG "XO_GPOS_Debian12","XO_ASD","XO_WebSRG" `
    -AnswerKey "XO" `
    -AnswerFile ".\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml" `
    -Output CKL `
    -AllowIntegrityViolations
```

### Scan an XCP-ng Hypervisor

XCP-ng hosts get two STIGs: the VMM SRG and the RHEL 7 STIG (adapted for Dom0):

```powershell
.\Evaluate-STIG.ps1 `
    -ComputerName "xcpng-host.example.com" `
    -SelectSTIG "XCP-ng_VMM","XCP-ng_Dom0_RHEL7" `
    -Output CKL `
    -AllowIntegrityViolations
```

> **Note:** The answer file and `-AnswerKey` parameters are not required for XCP-ng scans
> unless you have created an XCP-ng answer file. They are only needed for XO scans.

### Scan All STIGs on a System (Auto-Detect)

To let the framework auto-detect which STIGs apply to a given host:

```powershell
.\Evaluate-STIG.ps1 `
    -ComputerName "target.example.com" `
    -Output CKL `
    -AllowIntegrityViolations
```

The framework uses `Test-IsRunningOS` to auto-detect whether the target is XCP-ng, Debian 12,
or another OS, and applies the appropriate STIGs automatically.

### List Applicable STIGs Without Scanning

To see which STIGs would apply to a host without running a full scan:

```powershell
.\Evaluate-STIG.ps1 -ComputerName "target.example.com" -ListApplicableProducts
```

---

## Understanding Scan Output

### Output Files

After a successful scan, output is in `.\Results\<hostname>\<timestamp>\`:

| File | Description |
|---|---|
| `*.ckl` | STIG Viewer 2.x checklist — open with DISA STIG Viewer |
| `*.cklb` | STIG Viewer 3.x checklist — open with STIG Viewer 3 |
| `*.xccdf.xml` | XCCDF results — for import into SCAP tools |
| `SummaryReport.html` | Human-readable scan summary |
| `Evaluate-STIG_*.log` | Scan log with detailed execution output |

### Status Values in CKL

| Status | Meaning |
|---|---|
| `NotAFinding` | The automated check confirmed compliance |
| `Open` | The automated check found a compliance issue, or the check determined manual verification is required |
| `Not_Applicable` | The requirement does not apply to this system (per STIG guidance) |
| `Not_Reviewed` | The framework timed out or could not execute the check — investigate why |

A `Not_Reviewed` result most commonly means the check exceeded the 15-second timeout
(`VulnTimeout`). If you see many `Not_Reviewed` results, check the scan log for timeout
messages and verify SSH connectivity is stable.

### COMMENTS Field in CKL

When using the `-AnswerFile` and `-AnswerKey "XO"` parameters, the `COMMENTS` field in each
WebSRG CKL entry is automatically populated with:
- For `NotAFinding` entries: a summary of what was verified and documentation guidance for the ISSO
- For `Open` entries: step-by-step remediation instructions for the system administrator

This content is sourced from `AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml`.

---

## XO API Token Setup (Optional but Recommended)

Several WebSRG checks (V-206367, V-206386, V-206396, V-206397, and others) can use the XO
REST API to perform more accurate compliance verification. To enable this, create a read-only
API token on the XO server and store it in a file:

```bash
# On the XO server
# 1. Generate an API token via xo-cli or the XO web interface
#    (Settings → API → Create Token)

# 2. Create the secure token file
mkdir -p /etc/xo-server/stig
echo "YOUR-API-TOKEN-HERE" > /etc/xo-server/stig/api-token
chmod 600 /etc/xo-server/stig/api-token
chown root:root /etc/xo-server/stig/api-token
```

The checks automatically look for the token in this location. Without a token, affected checks
fall back to file-based and process-based detection methods, which are less precise.

---

## Troubleshooting

### Scan log shows missing hardware data (CPU, memory, BIOS fields empty)

Required Linux packages are missing from the target system. Install them and re-scan:

```bash
# Debian 12 (XO)
apt-get install -y lshw libicu-dev dmidecode bc

# XCP-ng (Dom0)
yum install -y lshw libicu dmidecode bc
```

The scan will still complete and generate a CKL, but hardware inventory fields (CPU model,
memory, BIOS version) in the CKL asset information will be blank until these packages are
present. STIG check results are not affected.

### "Integrity violation" warnings during scan

**Expected behavior.** Custom modules have empty `<SHA256Hash>` values in FileList.xml.
Always use `-AllowIntegrityViolations` with these modules.

### Scan shows "Not_Applicable" for all XCP-ng VMM checks

The XCP-ng OS was not detected. Verify:
1. The target is actually running XCP-ng (check `/etc/os-release` via SSH)
2. Your copy of `STIGDetection.psm1` includes the XCP-ng detection code (Step 6)
3. The `ID=` line in `/etc/os-release` is either `xcp-ng`, `xenenterprise`, or similar

```bash
# On the XCP-ng host
cat /etc/os-release | grep ^ID
```

### Scan hangs or takes more than 10 minutes

Test SSH remoting manually (see Prerequisites section). If the session hangs on
`New-PSSession`, there is an SSH configuration problem.

Also verify PowerShell is correctly installed on the target:
```bash
pwsh --version
```

### Many "Not_Reviewed" results in the WebSRG or ASD modules

1. Ensure SSH connectivity is fast and stable
2. Check the scan log for lines containing `VulnTimeout` or `Not_Reviewed`
3. Verify the PowerShell SSH subsystem is configured in `/etc/ssh/sshd_config`

### XCCDF output file not generated (only CKL/CKLB)

The `FormatOutput.psm1` null-check modification (Step 7) was not applied. Apply the fix and
re-run the scan.

### "COMMENTS" field is empty in the CKL file

The answer file was not specified or the `AnswerKey` does not match. Verify:
1. You used `-AnswerFile ".\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml"` in the command
2. You used `-AnswerKey "XO"` in the command
3. The answer file is valid XML: open it in a browser or run `[xml](Get-Content .\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml)` in PowerShell (no errors = valid)
4. The function's actual `Status` matches the `ExpectedStatus` in the answer file entry

### Module loads but shows fewer functions than expected

A syntax error in the module file is preventing some functions from loading. Run:

```powershell
Import-Module ".\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1" -Force -Verbose 2>&1 | Where-Object { $_ -match "error|warning" -and $_ -notmatch "IntegrityViolation" }
```

### Clean up remote PowerShell module cache between tests

The framework caches modules on the remote host. If you update a module and re-run a scan,
clean the cache first:

```bash
# On the remote target host
rm -rf /tmp/Evaluate-STIG_RemoteComputer
```

---

## Updating the Framework (Evaluate-STIG Version Changes)

When NAVSEA releases a new version of Evaluate-STIG, you cannot simply overwrite the installed
copy with the new release. The custom integration modifies several upstream files. If those
changes are lost, scans will fail. Follow this process for every version update.

### Before Updating — Create a Backup

1. Copy your entire working installation to a versioned backup folder:
   ```
   C:\Evaluate-STIG-v1.2507.6\   ← current working copy (keep this)
   C:\Evaluate-STIG-v1.XXXX.X\   ← new release (fresh extract)
   ```
2. Never overwrite in place. Work side-by-side so you can roll back if needed.

### Step-by-Step Update Process

#### 1. Extract the new release to a clean folder

Do not modify it yet. This is your reference copy.

#### 2. Check whether the modified upstream files changed in the new release

The custom integration touches these framework files. Compare them against the new release:

| File | Change Type | What to Check |
|---|---|---|
| `xml/STIGList.xml` | Custom entries appended | Does the file structure/schema change in new version? |
| `xml/FileList.xml` | Custom entries appended | Any new required fields or changed schema? |
| `Modules/Master_Functions/STIGDetection/STIGDetection.psm1` | XCPng/Debian12 detection added | Did the ValidateSet or switch block structure change? |
| `Modules/Master_Functions/FormatOutput/FormatOutput.psm1` | Null-check fix (line ~1443) | Was the XCCDF fact-writing block rewritten in the new version? |
| `Modules/Master_Functions/Master_Functions.psm1` | Interface filter fix (line ~2647) | Was the network interface enumeration changed? |

Use a diff tool (VS Code, WinMerge, or `git diff`) to compare each file:

```powershell
# Example using VS Code diff
code --diff "C:\Evaluate-STIG-v1.2507.6\xml\STIGList.xml" "C:\Evaluate-STIG-NEW\xml\STIGList.xml"
```

#### 3. Apply the custom integration to the new release

For each modified file, apply the custom changes to the new version's copy of that file.
Do **not** copy the old modified file over the new version — copy the new file and re-apply
the custom changes on top of it.

Refer to `Docs/MODIFICATIONS.md` for the exact changes with their `# MODIFIED_BY` comments.
All custom additions include these inline attribution comments so you can find them:
- In `.psm1` and `.ps1` files: `# MODIFIED_BY: Kismet Agbasi on MM/DD/YYYY`
- In `.xml` files: `<!-- MODIFIED_BY: Kismet Agbasi on MM/DD/YYYY -->`

#### 4. Copy the custom modules (no changes needed)

The five custom module folders are self-contained and do not reference version-specific paths.
Copy them as-is into the new release's `Modules/` directory:

```
Scan-XCP-ng_VMM_Checks/
Scan-XCP-ng_Dom0_RHEL7_Checks/
Scan-XO_GPOS_Debian12_Checks/
Scan-XO_ASD_Checks/
Scan-XO_WebSRG_Checks/
```

#### 5. Copy the answer file

```
Evaluate-STIG/AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml
```

Copy to the new release's `AnswerFiles/` folder. The answer file is not version-specific.

#### 6. Copy the XCCDF content files

If the new release does not include the custom XCCDF files, copy them from the old installation:

```
StigContent/U_Virtual_Machine_Manager_SRG_V2R2_Manual-xccdf.xml
StigContent/U_RHEL_7_STIG_V3R15_Manual-xccdf.xml
StigContent/U_GPOS_SRG_V3R2_Manual-xccdf.xml
StigContent/U_ASD_STIG_V6R4_Manual-xccdf.xml
StigContent/U_Web_Server_SRG_V4R4_Manual-xccdf.xml
```

> **Tip:** If NAVSEA ships a new version of one of these XCCDF files (e.g., updated VMM SRG),
> also update the `<ContentHash>` in `STIGList.xml` to match the new file's SHA-256 hash.
> Compute the hash with:
> ```powershell
> Get-FileHash ".\StigContent\U_Virtual_Machine_Manager_SRG_V2R2_Manual-xccdf.xml" -Algorithm SHA256
> ```

#### 7. Verify the updated installation

Run the module load test and a quick scan against a known-good target:

```powershell
# In the new Evaluate-STIG directory
Import-Module ".\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1" -Force -ErrorAction Stop
(Get-Command -Module Scan-XO_WebSRG_Checks).Count   # Expect 126

Import-Module ".\Modules\Scan-XCP-ng_VMM_Checks\Scan-XCP-ng_VMM_Checks.psd1" -Force -ErrorAction Stop
(Get-Command -Module Scan-XCP-ng_VMM_Checks).Count   # Expect 204
```

Then run a full scan and compare the exit code and EvalScore against your baseline results.
A scan producing Exit Code 0 and a consistent EvalScore confirms the update was successful.

### What Can Break After an Update

| Scenario | Symptom | Fix |
|---|---|---|
| `STIGList.xml` custom entries lost | Custom STIGs not detected / `-ListApplicableProducts` doesn't show them | Re-add custom `<STIG>` blocks from Step 4 in this guide |
| `STIGDetection.psm1` custom cases lost | All XCP-ng VMM checks return `Not_Applicable` | Re-apply XCPng/Debian12 detection cases (Steps 6b, 6c) |
| `FormatOutput.psm1` fix lost | XCCDF files not generated when scanning XCP-ng | Re-apply null check (Step 7) |
| `Master_Functions.psm1` fix lost | XCP-ng reports excessive network adapters | Re-apply interface filter (Step 8) |
| New `ValidateSet` in `STIGDetection.psm1` | PowerShell error "XCPng is not in the ValidateSet" | Re-add `XCPng` and `Debian12` to the ValidateSet |
| New framework version changes `FileList.xml` schema | Hash validation errors or startup errors | Re-apply FileList.xml custom entries (Step 5) |

### Handling a Framework Downgrade

The same process applies when reverting to an older version. Extract the older release to a
clean folder and re-apply all custom changes from this guide. Never overwrite a working
installation — always work in a separate folder.

### Keeping Track of Changes

The `Docs/MODIFICATIONS.md` file in this folder documents every change made to upstream
framework files, including the exact lines modified and the date. Update this document
whenever a new modification is made. It is the authoritative reference for re-applying
changes after a framework update.

---

## Known Compliance Gaps (Vates Action Required)

The following findings will always return **Open** until Vates addresses them at the product level.
Document these in your POA&M and System Security Plan:

| Finding | Description | Impact |
|---|---|---|
| **FIPS 140-2 Authentication** | XO uses bcrypt for password hashing; bcrypt is not FIPS 140-2 validated | CAT I — Requires LDAP/AD integration or code change to PBKDF2 |
| **No Built-in MFA/2FA** | XO has no native multi-factor authentication | CAT II — Requires LDAP + smart card configuration |
| **TLS 1.1 Enabled** | TLS 1.1 is still available on default XO installations | CAT II — Disable via Nginx/Node.js TLS configuration |
| **No Centralized Audit Server** | XO does not ship with built-in SIEM forwarding | CAT II — Configure rsyslog/syslog-ng forwarding to site SIEM |
| **Local Timezone Timestamps** | Audit logs use local time (US/Eastern), not UTC | CAT II — Set `TZ=UTC` in the xo-server systemd unit file |

See `Docs/VATES_COMPLIANCE_BLOCKERS.md` for detailed remediation guidance on each item.

---

## Quick Reference: Scan Commands

```powershell
# Scan XO host (all three XO STIGs + answer file)
.\Evaluate-STIG.ps1 -ComputerName xo1 -SelectSTIG "XO_GPOS_Debian12","XO_ASD","XO_WebSRG" -AnswerKey XO -AnswerFile .\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml -Output CKL -AllowIntegrityViolations

# Scan XCP-ng host (both XCP-ng STIGs)
.\Evaluate-STIG.ps1 -ComputerName xcpng01 -SelectSTIG "XCP-ng_VMM","XCP-ng_Dom0_RHEL7" -Output CKL -AllowIntegrityViolations

# List applicable STIGs without scanning
.\Evaluate-STIG.ps1 -ComputerName target -ListApplicableProducts

# Test module load (XO WebSRG — expect 126 functions)
Import-Module .\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1 -Force; (Get-Command -Module Scan-XO_WebSRG_Checks).Count
```

---

## Related Documentation

| Document | Location | Purpose |
|---|---|---|
| MODIFICATIONS.md | `Docs/` | Complete diff of all framework file changes |
| STATUS.md | `Docs/` | Current implementation status per module |
| VATES_COMPLIANCE_BLOCKERS.md | `Docs/` | Compliance gaps requiring Vates action |
| CLAUDE.md | Project root | AI assistant context and session history |
| XO_WebSRG Implementation Guide | `Docs/XO_v5.x_WebSRG/` | Deep-dive on WebSRG check implementation |
