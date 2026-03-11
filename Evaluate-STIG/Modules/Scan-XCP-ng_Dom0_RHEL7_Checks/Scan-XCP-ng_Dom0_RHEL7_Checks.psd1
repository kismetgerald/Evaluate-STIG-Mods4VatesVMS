@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'Scan-XCP-ng_Dom0_RHEL7_Checks.psm1'

    # Version number of this module.
    ModuleVersion = '1.2026.3.11'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID = '4a8c2b1f-5d3e-4f2a-9c1b-8e3a5d2c1b4f'

    # Author of this module
    Author = 'XCP-ng STIG Compliance Implementation'

    # Company or vendor of this module
    CompanyName = 'Naval Sea Systems Command (NAVSEA)'

    # Copyright statement for this module
    Copyright = '(c) 2026 U.S. Government. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Evaluate-STIG scan module for Red Hat Enterprise Linux 7 STIG on XCP-ng Dom0 (Control Domain). Implements 244 RHEL 7 STIG V3R15 vulnerability checks (V-204392 through V-256970) adapted for CentOS 7-based XCP-ng hypervisor hosts.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.1'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.psd1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    # 244 functions matching RHEL 7 STIG V3R15 XCCDF (V-204392 through V-256970)
    FunctionsToExport = @('Get-V*')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('STIG', 'RHEL7', 'XCP-ng', 'Dom0', 'Compliance', 'Security', 'CentOS7')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'XCP-ng Dom0 RHEL 7 STIG compliance check module implementing 244 security requirements from RHEL 7 STIG V3R15, adapted for CentOS 7-based XCP-ng hypervisor Dom0 environment.'
        } # End of PSData hashtable
    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
