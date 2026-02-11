#!/usr/bin/env pwsh
# Execution trace test for V-264357
# This creates a traced version of the function to identify execution bottlenecks

$ErrorActionPreference = 'Stop'

Write-Host "Creating traced version of Get-V264357..." -ForegroundColor Cyan

# Define traced function inline
function Get-V264357-Traced {
param (
    [Parameter(Mandatory = $true)]
    [String]$ScanType,

    [Parameter(Mandatory = $false)]
    [String]$AnswerFile,

    [Parameter(Mandatory = $false)]
    [String]$AnswerKey,

    [Parameter(Mandatory = $false)]
    [String]$Username,

    [Parameter(Mandatory = $false)]
    [String]$UserSID,

    [Parameter(Mandatory = $false)]
    [String]$Hostname,

    [Parameter(Mandatory = $false)]
    [String]$Instance,

    [Parameter(Mandatory = $false)]
    [String]$Database,

    [Parameter(Mandatory = $false)]
    [String]$SiteName
)

Write-Host "[TRACE] Function entry" -ForegroundColor Yellow
$ModuleName = "Scan-XO_WebSRG_Checks"
$VulnID = "V-264357"
$RuleID = "SV-264357r984416_rule"
$Status = "Not_Reviewed"
$FindingDetails = ""
$Comments = ""
$AFKey = ""
$AFStatus = ""
$SeverityOverride = ""
$Justification = ""

Write-Host "[TRACE] Variables initialized" -ForegroundColor Yellow

#---=== Begin Custom Code ===---#
Write-Host "[TRACE] Starting custom code" -ForegroundColor Yellow
$output = @()
Write-Host "[TRACE] Output array created" -ForegroundColor Yellow

$output += "=" * 80
$output += "V-264357: Protected Cryptographic Key Storage"
$output += "DoD Requirement: Organization-defined safeguards and/or hardware protected key store"
$output += "=" * 80
$output += ""
Write-Host "[TRACE] Header added to output" -ForegroundColor Yellow

# Protection mechanism counters
$protectionCount = 0
$protectionMethods = @()

# Check 1: Private Key File Discovery and Permissions
$output += "Check 1: Private Key File Discovery and Permissions"
$output += "-" * 50
Write-Host "[TRACE] Check 1 started" -ForegroundColor Yellow

$keyFound = $false
$keyPaths = @()
$configPaths = @("/opt/xo/xo-server/config.toml", "/etc/xo-server/config.toml")

Write-Host "[TRACE] About to check config paths" -ForegroundColor Yellow
foreach ($configPath in $configPaths) {
    Write-Host "[TRACE]   Checking: $configPath" -ForegroundColor Gray
    if (Test-Path $configPath) {
        Write-Host "[TRACE]   Config exists, reading content" -ForegroundColor Gray
        $config = Get-Content $configPath -Raw -ErrorAction SilentlyContinue
        Write-Host "[TRACE]   Config read, length: $($config.Length)" -ForegroundColor Gray

        if ($config -match 'key\s*=\s*[''"]([^''"]+)[''"]') {
            $keyPath = $matches[1]
            Write-Host "[TRACE]   Found key path in config: $keyPath" -ForegroundColor Gray
            if (Test-Path $keyPath) {
                $output += "   [FOUND] Private key file (from config): $keyPath"
                $keyPaths += $keyPath
                $keyFound = $true
            }
        }
    } else {
        Write-Host "[TRACE]   Config does not exist" -ForegroundColor Gray
    }
}

Write-Host "[TRACE] Config check complete, keyFound=$keyFound" -ForegroundColor Yellow

# Fallback: search common private key locations
if (-not $keyFound) {
    Write-Host "[TRACE] Starting fallback search" -ForegroundColor Yellow
    $commonKeyPaths = @("/etc/ssl/private", "/etc/ssl", "/etc/pki/tls/private", "/etc/xo-server", "/opt/xo")
    foreach ($dir in $commonKeyPaths) {
        Write-Host "[TRACE]   Searching directory: $dir" -ForegroundColor Gray
        if (Test-Path $dir) {
            Write-Host "[TRACE]   Directory exists, running find command" -ForegroundColor Gray
            $keys = $(bash -c "find '$dir' -maxdepth 3 -name '*.key' -o -name '*-key.pem' 2>/dev/null | head -10" 2>&1)
            Write-Host "[TRACE]   Find result length: $($keys.Length)" -ForegroundColor Gray
            if ($keys) {
                $output += "   [FOUND] Private keys in ${dir}:"
                $output += $keys
                $keyPaths += $keys -split "`n" | Where-Object { $_ }
                $keyFound = $true
            }
        }
    }
}

Write-Host "[TRACE] Key search complete, found $($keyPaths.Count) keys" -ForegroundColor Yellow

if (-not $keyFound) {
    $output += "   [NOT FOUND] No private key files detected"
    $Status = "Not_Applicable"
} else {
    # Check permissions on found keys
    Write-Host "[TRACE] Checking permissions on found keys" -ForegroundColor Yellow
    foreach ($keyPath in $keyPaths) {
        Write-Host "[TRACE]   Analyzing: $keyPath" -ForegroundColor Gray
        $stat = $(bash -c "stat -c '%a %U:%G' '$keyPath' 2>/dev/null" 2>&1)
        Write-Host "[TRACE]   Stat result: $stat" -ForegroundColor Gray
        $output += "   File: $keyPath"
        $output += "   Permissions: $stat"
    }
    $Status = "Open"
}

$FindingDetails = $output -join "`n"
Write-Host "[TRACE] FindingDetails populated, length: $($FindingDetails.Length)" -ForegroundColor Yellow
#---=== End Custom Code ===---#

Write-Host "[TRACE] Custom code complete, Status=$Status" -ForegroundColor Yellow

# Return simple result
$result = @{
    Status = $Status
    FindingDetails = $FindingDetails
    AFKey = $AFKey
    AFStatus = $AFStatus
    Comments = $Comments
}

Write-Host "[TRACE] Function exit" -ForegroundColor Yellow
return $result
}

# Test the traced function
Write-Host "`nExecuting traced function..." -ForegroundColor Cyan
$testParams = @{
    ScanType = 'Classified'
    AnswerFile = ''
    AnswerKey  = 'V-264357'
    Username   = 'NA'
    UserSID    = 'NA'
    Hostname   = 'localhost'
    Instance   = 'NA'
    Database   = 'NA'
    SiteName   = 'NA'
}

$startTime = Get-Date
$result = Get-V264357-Traced @testParams
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "TRACED EXECUTION RESULTS" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Execution time: $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
Write-Host "Status: $($result.Status)" -ForegroundColor Yellow
Write-Host "FindingDetails length: $($result.FindingDetails.Length)" -ForegroundColor Yellow
Write-Host "`nFindingDetails preview:" -ForegroundColor Cyan
Write-Host $result.FindingDetails.Substring(0, [Math]::Min(500, $result.FindingDetails.Length))
