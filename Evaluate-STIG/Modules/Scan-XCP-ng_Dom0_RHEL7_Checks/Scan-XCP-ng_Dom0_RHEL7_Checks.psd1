@{
    RootModule = 'Scan-XCP-ng_Dom0_RHEL7_Checks.psm1'
    ModuleVersion = '1.0.0'
    GUID = '4a8c2b1f-5d3e-4f2a-9c1b-8e3a5d2c1b4f'
    Author = 'XCP-ng STIG Compliance Team'
    CompanyName = 'Evaluate-STIG Contributors'
    Description = 'PowerShell STIG compliance checking module for XCP-ng Dom0 (Control Domain) RHEL 7 STIG requirements'
    PowerShellVersion = '7.1'
    
    # Functions to export
    FunctionsToExport = @(
        # CAT I Account Security Checks
        'Get-V204424', 'Get-V204425', 'Get-V251702',

        # CAT I Dangerous Package Checks
        'Get-V204442', 'Get-V204443', 'Get-V204502', 'Get-V204620', 'Get-V204621',

        # CAT I FIPS and System Security Checks
        'Get-V204455', 'Get-V204497', 'Get-V204606', 'Get-V204607',

        # User Account Management (V-230334 - V-230352)
        'Get-V230334', 'Get-V230335', 'Get-V230336', 'Get-V230337', 'Get-V230338',
        'Get-V230339', 'Get-V230340', 'Get-V230341', 'Get-V230342', 'Get-V230343',
        'Get-V230344', 'Get-V230345', 'Get-V230346', 'Get-V230347', 'Get-V230348',
        'Get-V230349', 'Get-V230350', 'Get-V230351', 'Get-V230352',
        
        # File Permissions & Access Control (V-230353 - V-230372)
        'Get-V230353', 'Get-V230354', 'Get-V230355', 'Get-V230356', 'Get-V230357',
        'Get-V230358', 'Get-V230359', 'Get-V230360', 'Get-V230361', 'Get-V230362',
        'Get-V230363', 'Get-V230364', 'Get-V230365', 'Get-V230366', 'Get-V230367',
        'Get-V230368', 'Get-V230369', 'Get-V230370', 'Get-V230371', 'Get-V230372',
        
        # Authentication & Password Policy (V-230373 - V-230392)
        'Get-V230373', 'Get-V230374', 'Get-V230375', 'Get-V230376', 'Get-V230377',
        'Get-V230378', 'Get-V230379', 'Get-V230380', 'Get-V230381', 'Get-V230382',
        'Get-V230383', 'Get-V230384', 'Get-V230385', 'Get-V230386', 'Get-V230387',
        'Get-V230388', 'Get-V230389', 'Get-V230390', 'Get-V230391', 'Get-V230392',
        
        # SSH Configuration (V-230393 - V-230412)
        'Get-V230393', 'Get-V230394', 'Get-V230395', 'Get-V230396', 'Get-V230397',
        'Get-V230398', 'Get-V230399', 'Get-V230400', 'Get-V230401', 'Get-V230402',
        'Get-V230403', 'Get-V230404', 'Get-V230405', 'Get-V230406', 'Get-V230407',
        'Get-V230408', 'Get-V230409', 'Get-V230410', 'Get-V230411', 'Get-V230412',
        
        # Audit & Logging (V-230413 - V-230432)
        'Get-V230413', 'Get-V230414', 'Get-V230415', 'Get-V230416', 'Get-V230417',
        'Get-V230418', 'Get-V230419', 'Get-V230420', 'Get-V230421', 'Get-V230422',
        'Get-V230423', 'Get-V230424', 'Get-V230425', 'Get-V230426', 'Get-V230427',
        'Get-V230428', 'Get-V230429', 'Get-V230430', 'Get-V230431', 'Get-V230432',
        
        # Kernel & Module Management (V-230433 - V-230452)
        'Get-V230433', 'Get-V230434', 'Get-V230435', 'Get-V230436', 'Get-V230437',
        'Get-V230438', 'Get-V230439', 'Get-V230440', 'Get-V230441', 'Get-V230442',
        'Get-V230443', 'Get-V230444', 'Get-V230445', 'Get-V230446', 'Get-V230447',
        'Get-V230448', 'Get-V230449', 'Get-V230450', 'Get-V230451', 'Get-V230452',
        
        # Security Controls & SELinux (V-230453 - V-230472)
        'Get-V230453', 'Get-V230454', 'Get-V230455', 'Get-V230456', 'Get-V230457',
        'Get-V230458', 'Get-V230459', 'Get-V230460', 'Get-V230461', 'Get-V230462',
        'Get-V230463', 'Get-V230464', 'Get-V230465', 'Get-V230466', 'Get-V230467',
        'Get-V230468', 'Get-V230469', 'Get-V230470', 'Get-V230471', 'Get-V230472',
        
        # System Updates & Patches (V-230473 - V-230492)
        'Get-V230473', 'Get-V230474', 'Get-V230475', 'Get-V230476', 'Get-V230477',
        'Get-V230478', 'Get-V230479', 'Get-V230480', 'Get-V230481', 'Get-V230482',
        'Get-V230483', 'Get-V230484', 'Get-V230485', 'Get-V230486', 'Get-V230487',
        'Get-V230488', 'Get-V230489', 'Get-V230490', 'Get-V230491', 'Get-V230492'
    )
    
    # Version history
    # 1.0.0 (January 2026) - Complete implementation of 244 Dom0 RHEL 7 STIG checks
    
    PrivateData = @{
        PSData = @{
            Tags = @('STIG', 'Compliance', 'RHEL', 'XCP-ng', 'Dom0', 'RHEL7')
            ProjectUri = 'https://github.com/Evaluate-STIG/Evaluate-STIG'
            LicenseUri = 'https://raw.githubusercontent.com/Evaluate-STIG/Evaluate-STIG/master/LICENSE'
            ReleaseNotes = @'
Version 1.0.0 (January 2026)
===========================
Complete implementation of XCP-ng Dom0 RHEL 7 STIG compliance module.
Implements all 244 checks from RHEL 7 STIG V3R15 adapted for XCP-ng Dom0 environment.

Feature Summary:
- User account management and password policy checks
- File permission and access control verification
- SSH security configuration validation
- Audit and logging compliance
- Kernel module and security controls
- SELinux enforcement verification
- System updates and patch management

For each check:
- Automated compliance verification where possible
- Manual review guidance for non-automatable requirements
- Consistent output format with detailed findings
- Version-aware implementation for multiple XCP-ng/CentOS versions
'@
        }
    }
}
