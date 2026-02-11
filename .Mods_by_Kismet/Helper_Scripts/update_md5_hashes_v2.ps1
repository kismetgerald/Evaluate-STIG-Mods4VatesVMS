# Update MD5 hashes in the module file (Version 2 - handles actual format)
$modulePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
$csvPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\session29_md5_hashes.csv"

# Load the CSV with hash values
$hashes = Import-Csv $csvPath

# Read the module content as array of lines
$lines = Get-Content $modulePath

$updatedCount = 0

# Process each hash
foreach ($hash in $hashes) {
    $vulnID = $hash.VulnID
    $discussMD5 = $hash.DiscussMD5
    $checkMD5 = $hash.CheckMD5
    $fixMD5 = $hash.FixMD5

    Write-Host "Processing $vulnID..." -ForegroundColor Cyan

    # Find the function
    $functionIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^Function Get-$vulnID \{") {
            $functionIndex = $i
            break
        }
    }

    if ($functionIndex -eq -1) {
        Write-Host "  Function not found!" -ForegroundColor Red
        continue
    }

    Write-Host "  Found function at line $($functionIndex + 1)" -ForegroundColor Green

    # Look for the .DESCRIPTION section (within next 50 lines)
    $updated = $false
    for ($i = $functionIndex; $i -lt [Math]::Min($functionIndex + 50, $lines.Count); $i++) {
        # Look for DiscussMD5 line
        if ($lines[$i] -match '^\s+DiscussMD5\s+:\s+[0-9a-f]+\s*$') {
            $lines[$i] = $lines[$i] -replace '[0-9a-f]+\s*$', $discussMD5
            Write-Host "  Updated DiscussMD5 at line $($i + 1): $discussMD5" -ForegroundColor Yellow
        }
        # Look for CheckMD5 line
        elseif ($lines[$i] -match '^\s+CheckMD5\s+:\s+[0-9a-f]+\s*$') {
            $lines[$i] = $lines[$i] -replace '[0-9a-f]+\s*$', $checkMD5
            Write-Host "  Updated CheckMD5 at line $($i + 1): $checkMD5" -ForegroundColor Yellow
        }
        # Look for FixMD5 line
        elseif ($lines[$i] -match '^\s+FixMD5\s+:\s+[0-9a-f]+\s*$') {
            $lines[$i] = $lines[$i] -replace '[0-9a-f]+\s*$', $fixMD5
            Write-Host "  Updated FixMD5 at line $($i + 1): $fixMD5" -ForegroundColor Yellow
            $updated = $true
            $updatedCount++
            break
        }
    }

    if (-not $updated) {
        Write-Host "  WARNING: Could not find MD5 fields for $vulnID" -ForegroundColor Red
    }
}

# Save the updated content
$lines | Set-Content -Path $modulePath

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Update Complete!" -ForegroundColor Green
Write-Host "Functions updated: $updatedCount / $($hashes.Count)" -ForegroundColor Yellow
Write-Host "Module: $modulePath" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
