# Update MD5 hashes in the module file
$modulePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
$csvPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\session29_md5_hashes.csv"

# Load the CSV with hash values
$hashes = Import-Csv $csvPath

# Read the module content
$content = Get-Content $modulePath -Raw

# Update each function
foreach ($hash in $hashes) {
    $vulnID = $hash.VulnID
    $discussMD5 = $hash.DiscussMD5
    $checkMD5 = $hash.CheckMD5
    $fixMD5 = $hash.FixMD5

    Write-Host "Updating $vulnID..." -ForegroundColor Cyan
    Write-Host "  DiscussMD5: $discussMD5" -ForegroundColor Green
    Write-Host "  CheckMD5  : $checkMD5" -ForegroundColor Green
    Write-Host "  FixMD5    : $fixMD5" -ForegroundColor Green

    # Pattern to find the .DESCRIPTION section for this function
    # We need to find the function and update the MD5 hashes
    $pattern = "(?s)(Function Get-$vulnID \{.*?\.DESCRIPTION.*?Vuln ID\s+: $vulnID.*?)DiscussMD5 : 00000000000000000000000000000000(.*?)CheckMD5\s+: 00000000000000000000000000000000(.*?)FixMD5\s+: 00000000000000000000000000000000"

    if ($content -match $pattern) {
        # Build the replacement string
        $replacement = "`${1}DiscussMD5 : $discussMD5`${2}CheckMD5   : $checkMD5`${3}FixMD5     : $fixMD5"
        $content = $content -replace $pattern, $replacement
        Write-Host "  Updated successfully!" -ForegroundColor Yellow
    } else {
        Write-Host "  Pattern not found - trying alternative pattern..." -ForegroundColor Red

        # Try alternative pattern (in case the MD5 values are not all zeros)
        $pattern2 = "(?s)(Function Get-$vulnID \{.*?\.DESCRIPTION.*?Vuln ID\s+: $vulnID.*?)DiscussMD5 : [0-9a-f]{32}(.*?)CheckMD5\s+: [0-9a-f]{32}(.*?)FixMD5\s+: [0-9a-f]{32}"

        if ($content -match $pattern2) {
            $replacement = "`${1}DiscussMD5 : $discussMD5`${2}CheckMD5   : $checkMD5`${3}FixMD5     : $fixMD5"
            $content = $content -replace $pattern2, $replacement
            Write-Host "  Updated successfully with alternative pattern!" -ForegroundColor Yellow
        } else {
            Write-Host "  FAILED - Could not find function header" -ForegroundColor Red
        }
    }
}

# Save the updated content
Set-Content -Path $modulePath -Value $content -NoNewline

Write-Host "`nModule updated successfully!" -ForegroundColor Green
Write-Host "Location: $modulePath" -ForegroundColor Cyan
