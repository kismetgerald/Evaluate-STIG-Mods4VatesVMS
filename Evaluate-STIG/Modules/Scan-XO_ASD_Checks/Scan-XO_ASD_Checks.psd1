@{
    RootModule        = 'Scan-XO_ASD_Checks.psm1'
    ModuleVersion     = '1.2026.1.20'
    GUID              = '12345678-1234-1234-1234-123456789012'
    Author            = 'Kismet Agbasi'
    CompanyName       = 'NAVSEA Modified'
    Description       = 'Application Security & Development STIG check module for Xen Orchestra'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-V*')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('STIG', 'Xen-Orchestra', 'ASD', 'Security')
            ProjectUri = 'https://github.com/NAVSEA/Evaluate-STIG'
            LicenseUri = 'https://github.com/NAVSEA/Evaluate-STIG/blob/master/LICENSE'
        }
    }
}