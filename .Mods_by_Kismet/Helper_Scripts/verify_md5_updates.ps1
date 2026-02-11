# Verify all MD5 hashes were updated correctly
$modulePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
$csvPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\session29_md5_hashes.csv"

# Load expected hashes
$expectedHashes = Import-Csv $csvPath

# Read module content
$moduleContent = Get-Content $modulePath -Raw

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MD5 Hash Verification Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$allMatch = $true
$matchCount = 0

foreach ($expected in $expectedHashes) {
    $vulnID = $expected.VulnID
    Write-Host "Checking $vulnID..." -ForegroundColor Yellow

    # Find the function and extract its MD5 values
    if ($moduleContent -match "(?s)Function Get-$vulnID \{.*?DiscussMD5 : ([0-9a-f]{32}).*?CheckMD5\s+: ([0-9a-f]{32}).*?FixMD5\s+: ([0-9a-f]{32})") {
        $actualDiscuss = $matches[1]
        $actualCheck = $matches[2]
        $actualFix = $matches[3]

        $discussMatch = $actualDiscuss -eq $expected.DiscussMD5
        $checkMatch = $actualCheck -eq $expected.CheckMD5
        $fixMatch = $actualFix -eq $expected.FixMD5

        if ($discussMatch -and $checkMatch -and $fixMatch) {
            Write-Host "  ✓ All MD5 hashes match!" -ForegroundColor Green
            $matchCount++
        } else {
            Write-Host "  ✗ MISMATCH DETECTED!" -ForegroundColor Red
            $allMatch = $false

            if (-not $discussMatch) {
                Write-Host "    DiscussMD5: Expected $($expected.DiscussMD5), Got $actualDiscuss" -ForegroundColor Red
            }
            if (-not $checkMatch) {
                Write-Host "    CheckMD5:   Expected $($expected.CheckMD5), Got $actualCheck" -ForegroundColor Red
            }
            if (-not $fixMatch) {
                Write-Host "    FixMD5:     Expected $($expected.FixMD5), Got $actualFix" -ForegroundColor Red
            }
        }

        # Show actual values for reference
        Write-Host "    DiscussMD5: $actualDiscuss" -ForegroundColor Gray
        Write-Host "    CheckMD5:   $actualCheck" -ForegroundColor Gray
        Write-Host "    FixMD5:     $actualFix" -ForegroundColor Gray
    } else {
        Write-Host "  ✗ Could not find MD5 hashes in module!" -ForegroundColor Red
        $allMatch = $false
    }

    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
if ($allMatch) {
    Write-Host "SUCCESS: All $matchCount/$($expectedHashes.Count) functions verified!" -ForegroundColor Green
} else {
    Write-Host "FAILURE: Some functions have mismatched MD5 hashes" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
