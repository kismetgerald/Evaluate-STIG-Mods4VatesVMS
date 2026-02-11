@{
    RootModule        = 'Scan-XO_WebSRG_Checks.psm1'
    ModuleVersion     = '1.2026.1.16'
    GUID              = '87654321-4321-4321-4321-210987654321'
    Author            = 'Kismet Agbasi'
    CompanyName       = 'NAVSEA Modified'
    Description       = 'Web Server SRG check module for Xen Orchestra'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-*')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('STIG', 'Xen-Orchestra', 'Web-Server', 'SRG', 'Security')
            ProjectUri = 'https://github.com/NAVSEA/Evaluate-STIG'
            LicenseUri = 'https://github.com/NAVSEA/Evaluate-STIG/blob/master/LICENSE'
        }
    }
}
