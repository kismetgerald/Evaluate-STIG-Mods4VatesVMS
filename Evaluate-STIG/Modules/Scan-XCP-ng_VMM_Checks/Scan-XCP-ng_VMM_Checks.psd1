@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'Scan-XCP-ng_VMM_Checks.psm1'

    # Version number of this module.
    ModuleVersion = '1.2026.1.16'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID = 'a1f4c8e2-7d9b-4b3e-8c5a-9f2d1e6c4a7b'

    # Author of this module
    Author = 'XCP-ng STIG Compliance Implementation'

    # Company or vendor of this module
    CompanyName = 'Naval Sea Systems Command (NAVSEA)'

    # Copyright statement for this module
    Copyright = '(c) 2026 U.S. Government. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Evaluate-STIG scan module for Virtual Machine Manager (VMM) SRG on XCP-ng hypervisors. Implements 204 VMM SRG vulnerability checks (V-207338 through V-264326) for XCP-ng 8.x and 9.x hosts with version-conditional rule application.'

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
    FunctionsToExport = @(
        'Get-V207338', 'Get-V207339', 'Get-V207340', 'Get-V207341', 'Get-V207342',
        'Get-V207343', 'Get-V207344', 'Get-V207345', 'Get-V207346', 'Get-V207347',
        'Get-V207348', 'Get-V207349', 'Get-V207350', 'Get-V207351', 'Get-V207352',
        'Get-V207353', 'Get-V207354', 'Get-V207355', 'Get-V207356', 'Get-V207357',
        'Get-V207358', 'Get-V207359', 'Get-V207360', 'Get-V207361', 'Get-V207362',
        'Get-V207363', 'Get-V207364', 'Get-V207365', 'Get-V207366', 'Get-V207367',
        'Get-V207368', 'Get-V207369', 'Get-V207370', 'Get-V207371', 'Get-V207372',
        'Get-V207373', 'Get-V207374', 'Get-V207375', 'Get-V207376', 'Get-V207377',
        'Get-V207378', 'Get-V207379', 'Get-V207380', 'Get-V207381', 'Get-V207382',
        'Get-V207383', 'Get-V207384', 'Get-V207385', 'Get-V207386', 'Get-V207387',
        'Get-V207388', 'Get-V207389', 'Get-V207390', 'Get-V207391', 'Get-V207392',
        'Get-V207393', 'Get-V207394', 'Get-V207395', 'Get-V207396', 'Get-V207397',
        'Get-V207398', 'Get-V207399', 'Get-V207400', 'Get-V207401', 'Get-V207402',
        'Get-V207403', 'Get-V207404', 'Get-V207405', 'Get-V207406', 'Get-V207407',
        'Get-V207408', 'Get-V207409', 'Get-V207410', 'Get-V207411', 'Get-V207412',
        'Get-V207413', 'Get-V207414', 'Get-V207415', 'Get-V207416', 'Get-V207417',
        'Get-V207418', 'Get-V207419', 'Get-V207420', 'Get-V207421', 'Get-V207422',
        'Get-V207423', 'Get-V207424', 'Get-V207425', 'Get-V207426', 'Get-V207427',
        'Get-V207428', 'Get-V207429', 'Get-V207430', 'Get-V207431', 'Get-V207432',
        'Get-V207433', 'Get-V207434', 'Get-V207435', 'Get-V207436', 'Get-V207437',
        'Get-V207438', 'Get-V207439', 'Get-V207440', 'Get-V207441', 'Get-V207442',
        'Get-V207443', 'Get-V207444', 'Get-V207445', 'Get-V207446', 'Get-V207447',
        'Get-V207448', 'Get-V207449', 'Get-V207450', 'Get-V207451', 'Get-V207452',
        'Get-V207453', 'Get-V207454', 'Get-V207455', 'Get-V207456', 'Get-V207457',
        'Get-V207458', 'Get-V207459', 'Get-V207460', 'Get-V207461', 'Get-V207462',
        'Get-V207463', 'Get-V207464', 'Get-V207465', 'Get-V207466', 'Get-V207467',
        'Get-V207468', 'Get-V207469', 'Get-V207470', 'Get-V207471', 'Get-V207472',
        'Get-V207473', 'Get-V207474', 'Get-V207475', 'Get-V207476', 'Get-V207477',
        'Get-V207478', 'Get-V207479', 'Get-V207480', 'Get-V207481', 'Get-V207482',
        'Get-V207483', 'Get-V207484', 'Get-V207485', 'Get-V207486', 'Get-V207487',
        'Get-V207488', 'Get-V207489', 'Get-V207490', 'Get-V207491', 'Get-V207492',
        'Get-V207493', 'Get-V207494', 'Get-V207495', 'Get-V207496', 'Get-V207497',
        'Get-V207498', 'Get-V207499', 'Get-V207500', 'Get-V207501', 'Get-V207502',
        'Get-V207503', 'Get-V207504', 'Get-V207505', 'Get-V207506', 'Get-V207507',
        'Get-V207508', 'Get-V207509', 'Get-V207510', 'Get-V207511', 'Get-V207512',
        'Get-V207513', 'Get-V207514', 'Get-V207515', 'Get-V207516', 'Get-V207517',
        'Get-V207518', 'Get-V207519', 'Get-V207520', 'Get-V207521', 'Get-V207522',
        'Get-V207523', 'Get-V207524', 'Get-V207525', 'Get-V207526', 'Get-V207527',
        'Get-V207528', 'Get-V207529',
        'Get-V264315', 'Get-V264316', 'Get-V264317', 'Get-V264318', 'Get-V264319',
        'Get-V264320', 'Get-V264321', 'Get-V264322', 'Get-V264323', 'Get-V264324',
        'Get-V264325', 'Get-V264326'
    )

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
            Tags = @('STIG', 'VMM', 'XCP-ng', 'Xen', 'Compliance', 'Security', 'Hypervisor')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'XCP-ng VMM SRG compliance check module implementing 204 virtual machine manager security requirements for Xen/XCP-ng hypervisors.'
        } # End of PSData hashtable
    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
