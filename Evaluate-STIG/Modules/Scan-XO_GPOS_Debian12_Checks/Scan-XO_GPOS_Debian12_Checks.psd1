@{
    RootModule        = 'Scan-XO_GPOS_Debian12_Checks.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '6f9d4c2e-7a5b-4e3f-8c1a-9b2d5e3a1f6c'
    Author            = 'Kismet Agbasi'
    CompanyName       = 'Evaluate-STIG Contributors'
    Description       = 'GPOS SRG V3R2 compliance checking module for Xen Orchestra (Debian 12)'
    PowerShellVersion = '7.1'
    FunctionsToExport = @('Get-V*')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('STIG', 'Xen-Orchestra', 'GPOS', 'Debian12', 'Security')
            ProjectUri = 'https://github.com/kismetgerald/Evaluate-STIG-Mods4VatesVMS'
        }
    }
}
