# Integration script for Session #32 Batch 1
$modulePath = "Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
$moduleContent = Get-Content $modulePath -Raw

# Function files to integrate
$functions = @{
    "V206426" = "V206426_implementation.ps1"
    "V264341" = "V264341_implementation.ps1"
    "V264358" = "V264358_implementation.ps1"
    "V264359" = "V264359_implementation.ps1"
}

$stubs = @{}
$implementations = @{}

# Read all implementations
foreach ($key in $functions.Keys) {
    $implPath = $functions[$key]
    if (Test-Path $implPath) {
        $implementations[$key] = Get-Content $implPath -Raw
        Write-Host "[OK] Read $implPath ($(implementations[$key].Length) chars)"
    }
    else {
        Write-Host "[ERROR] File not found: $implPath"
        exit 1
    }
}

# Extract stub patterns (simpler approach - use regex for stub detection)
# V-206426 stub
$stub426 = @'
Function Get-V206426 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206426
        STIG ID    : SRG-APP-000001-WSR-000001
        Rule ID    : SV-206426r508029_rule
        Rule Title : \[STUB\].*
'@

Write-Host "`nStarting integration..."
Write-Host "Module size before: $($moduleContent.Length) chars"

# Replace stubs with implementations
foreach ($key in $implementations.Keys) {
    $funcName = "Get-V$key"
    Write-Host "`nProcessing $funcName..."
    
    # Find function start and end using regex
    $pattern = "(?s)(Function $funcName \{.*?return Send-CheckResult @SendCheckParams\s*\})"
    if ($moduleContent -match $pattern) {
        $oldFunc = $matches[1]
        $newFunc = $implementations[$key].Trim()
        $moduleContent = $moduleContent.Replace($oldFunc, $newFunc)
        Write-Host "  [OK] Replaced $funcName (old: $($oldFunc.Length) -> new: $($newFunc.Length) chars)"
    }
    else {
        Write-Host "  [WARN] Could not find $funcName in module"
    }
}

# Write updated module
Set-Content -Path $modulePath -Value $moduleContent -NoNewline
Write-Host "`nModule size after: $($moduleContent.Length) chars"
Write-Host "Integration complete!"
