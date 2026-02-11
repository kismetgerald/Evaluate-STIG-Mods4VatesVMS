@{
    RootModule = 'Scan-XO_GPOS_Debian12_Checks.psm1'
    ModuleVersion = '1.0.0'
    GUID = '6f9d4c2e-7a5b-4e3f-8c1a-9b2d5e3a1f6c'
    Author = 'Debian 12 STIG Compliance Team'
    CompanyName = 'Evaluate-STIG Contributors'
    Description = 'PowerShell STIG compliance checking module for Debian 12 General Purpose Operating System (GPOS) requirements'
    PowerShellVersion = '7.1'
    
    # Functions to export
    FunctionsToExport = @(
        # User Account Management (V-254317 - V-254335)
        'Get-V254317', 'Get-V254318', 'Get-V254319', 'Get-V254320', 'Get-V254321',
        'Get-V254322', 'Get-V254323', 'Get-V254324', 'Get-V254325', 'Get-V254326',
        'Get-V254327', 'Get-V254328', 'Get-V254329', 'Get-V254330', 'Get-V254331',
        'Get-V254332', 'Get-V254333', 'Get-V254334', 'Get-V254335',
        
        # File Permissions & Access Control (V-254336 - V-254355)
        'Get-V254336', 'Get-V254337', 'Get-V254338', 'Get-V254339', 'Get-V254340',
        'Get-V254341', 'Get-V254342', 'Get-V254343', 'Get-V254344', 'Get-V254345',
        'Get-V254346', 'Get-V254347', 'Get-V254348', 'Get-V254349', 'Get-V254350',
        'Get-V254351', 'Get-V254352', 'Get-V254353', 'Get-V254354', 'Get-V254355',
        
        # Authentication & Password Policy (V-254356 - V-254375)
        'Get-V254356', 'Get-V254357', 'Get-V254358', 'Get-V254359', 'Get-V254360',
        'Get-V254361', 'Get-V254362', 'Get-V254363', 'Get-V254364', 'Get-V254365',
        'Get-V254366', 'Get-V254367', 'Get-V254368', 'Get-V254369', 'Get-V254370',
        'Get-V254371', 'Get-V254372', 'Get-V254373', 'Get-V254374', 'Get-V254375',
        
        # SSH Configuration (V-254376 - V-254395)
        'Get-V254376', 'Get-V254377', 'Get-V254378', 'Get-V254379', 'Get-V254380',
        'Get-V254381', 'Get-V254382', 'Get-V254383', 'Get-V254384', 'Get-V254385',
        'Get-V254386', 'Get-V254387', 'Get-V254388', 'Get-V254389', 'Get-V254390',
        'Get-V254391', 'Get-V254392', 'Get-V254393', 'Get-V254394', 'Get-V254395',
        
        # Audit & Logging (V-254396 - V-254415)
        'Get-V254396', 'Get-V254397', 'Get-V254398', 'Get-V254399', 'Get-V254400',
        'Get-V254401', 'Get-V254402', 'Get-V254403', 'Get-V254404', 'Get-V254405',
        'Get-V254406', 'Get-V254407', 'Get-V254408', 'Get-V254409', 'Get-V254410',
        'Get-V254411', 'Get-V254412', 'Get-V254413', 'Get-V254414', 'Get-V254415',
        
        # Kernel & Module Management (V-254416 - V-254435)
        'Get-V254416', 'Get-V254417', 'Get-V254418', 'Get-V254419', 'Get-V254420',
        'Get-V254421', 'Get-V254422', 'Get-V254423', 'Get-V254424', 'Get-V254425',
        'Get-V254426', 'Get-V254427', 'Get-V254428', 'Get-V254429', 'Get-V254430',
        'Get-V254431', 'Get-V254432', 'Get-V254433', 'Get-V254434', 'Get-V254435',
        
        # Security Controls & AppArmor (V-254436 - V-254455)
        'Get-V254436', 'Get-V254437', 'Get-V254438', 'Get-V254439', 'Get-V254440',
        'Get-V254441', 'Get-V254442', 'Get-V254443', 'Get-V254444', 'Get-V254445',
        'Get-V254446', 'Get-V254447', 'Get-V254448', 'Get-V254449', 'Get-V254450',
        'Get-V254451', 'Get-V254452', 'Get-V254453', 'Get-V254454', 'Get-V254455',
        
        # System Updates & Patches (V-254456 - V-254475)
        'Get-V254456', 'Get-V254457', 'Get-V254458', 'Get-V254459', 'Get-V254460',
        'Get-V254461', 'Get-V254462', 'Get-V254463', 'Get-V254464', 'Get-V254465',
        'Get-V254466', 'Get-V254467', 'Get-V254468', 'Get-V254469', 'Get-V254470',
        'Get-V254471', 'Get-V254472', 'Get-V254473', 'Get-V254474', 'Get-V254475'
    )
    
    # Version history
    # 1.0.0 (January 2026) - Initial implementation of 159 Debian12 GPOS STIG checks
    
    PrivateData = @{
        PSData = @{
            Tags = @('STIG', 'Compliance', 'Debian', 'Debian12', 'GPOS', 'Linux')
            ProjectUri = 'https://github.com/Evaluate-STIG/Evaluate-STIG'
            LicenseUri = 'https://raw.githubusercontent.com/Evaluate-STIG/Evaluate-STIG/master/LICENSE'
            ReleaseNotes = @'
Version 1.0.0 (January 2026)
============================
Initial implementation of Debian 12 GPOS STIG compliance module.
Implements 159 checks for GPOS STIG on Debian 12 systems.

Feature Summary:
- User account management and password policy checks
- File permission and access control verification
- SSH security configuration validation
- Audit and logging compliance
- Kernel module and security controls
- AppArmor enforcement verification (Debian alternative to SELinux)
- System updates and patch management

Key Adaptations for Debian 12:
- Uses apt package manager instead of yum/dnf
- SSH service named 'ssh' instead of 'sshd'
- AppArmor for MAC instead of SELinux
- Netplan for network configuration
- Multiple firewall options (ufw, firewalld, nftables, iptables, or none)
  * Note: Debian lacks standardized firewall like RHEL's firewalld
  * Checks detect and validate whatever firewall implementation is active
  * Some systems may have no active firewall service
- /var/log/syslog instead of /var/log/messages

For each check:
- Automated compliance verification where possible
- Debian-specific file paths and commands
- Manual review guidance for non-automatable requirements
- Consistent output format with detailed findings
- Platform-aware implementation for maximum compatibility
'@
        }
    }
}
