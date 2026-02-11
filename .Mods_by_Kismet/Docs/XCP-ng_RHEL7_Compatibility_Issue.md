# XCP-ng Dom0 (RHEL 7) PowerShell Compatibility Issue

## Summary
**RESOLVED**: PowerShell 7.3.12 is compatible with XCP-ng Dom0 (RHEL 7). While PowerShell 7.4+ fails due to glibc incompatibility, version 7.3.12 has compatible C++ dependencies and enables full Evaluate-STIG scanning.

## Environment
- **Host OS**: XCP-ng (RHEL 7 base)
- **Current libstdc++**: 4.8.5-28.el7_5.1
- **PowerShell Version (Working)**: 7.3.12 ✓
- **PowerShell Version (Failed)**: 7.4+ ✗
- **OpenSSH Version**: 7.4

## Root Cause (PowerShell 7.4+)
PowerShell 7.4+ requires glibc versions not available on RHEL 7:
```
GLIBCXX_3.4.20 (not available in RHEL 7)
GLIBCXX_3.4.21 (not available in RHEL 7)
```

RHEL 7's libstdc++ (4.8.5) only provides up to `GLIBCXX_3.4.19` and cannot be upgraded further on RHEL 7.

## Solution
PowerShell 7.3.12 has compatible C++ dependencies for RHEL 7 and resolves this issue.

## Installation & Deployment

### Install on XCP-ng Dom0
```bash
# Download and install PowerShell 7.3.12
yum install -y ./powershell-7.3.12-1.rh.x86_64.rpm
```

### Verify Installation
```bash
pwsh -NoProfile -Command '$PSVersionTable | Select-Object PSVersion, OS'
```

Output (expected):
```
PSVersion OS
--------- --
7.3.12    Linux 4.19.0+1 #1 SMP Fri Sep 19 15:09:21 UTC 2025
```

## Impact (with PowerShell 7.3.12)
- ✓ Remote scans of XCP-ng Dom0 via `-ComputerName` now supported
- ✓ Local scans on XCP-ng Dom0 now supported
- ✓ XCP-ng GPOS and VMM STIGs can be scanned directly from Evaluate-STIG
- ✓ PowerShell remoting subsystem works correctly via SSH
- ✓ XOA (Xen Orchestra Appliance) scans continue to work

## Recommendations
- **For XCP-ng on RHEL 7**: Deploy PowerShell 7.3.12 for full Evaluate-STIG compatibility
- **For PowerShell 7.4+ support**: Upgrade XCP-ng Dom0 to RHEL 8 or newer
- **For Evaluate-STIG team**: Document PowerShell version compatibility matrix (7.3.12 → RHEL 7; 7.4+ → RHEL 8+)

---
**Date**: January 16, 2026  
**Tested On**: VMH01.wgsdac.net (XCP-ng, RHEL 7)  
**Resolution Status**: ✓ RESOLVED via PowerShell 7.3.12  
**Verified Working**: pwsh 7.3.12 binary, local execution, SSH remoting subsystem
