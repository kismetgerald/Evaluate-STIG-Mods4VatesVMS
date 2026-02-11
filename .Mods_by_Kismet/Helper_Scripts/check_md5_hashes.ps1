$vulnIds = @('V-206351','V-206352','V-206353','V-206354','V-206367','V-206384','V-206385','V-206386','V-206387','V-206388','V-206389','V-206390','V-206391','V-206392','V-206398','V-206400','V-206401','V-206402','V-206403','V-206404','V-206405','V-206407','V-206408','V-206409','V-206436','V-206439','V-206441','V-206442','V-239371','V-264360','V-264361')

$modulePath = 'Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1'
$content = Get-Content $modulePath -Raw

$results = @()

foreach ($vuln in $vulnIds) {
    if ($content -match "Vuln ID\s*:\s*$vuln[\s\S]{0,500}?DiscussMD5\s*:\s*([^\r\n]+)[\s\S]{0,100}?CheckMD5\s*:\s*([^\r\n]+)[\s\S]{0,100}?FixMD5\s*:\s*([^\r\n]+)") {
        $discuss = $matches[1].Trim()
        $check = $matches[2].Trim()
        $fix = $matches[3].Trim()

        # Check if any hash is not a valid MD5 (32 hex characters or all zeros)
        $discussValid = $discuss -match '^[0-9a-fA-F]{32}$'
        $checkValid = $check -match '^[0-9a-fA-F]{32}$'
        $fixValid = $fix -match '^[0-9a-fA-F]{32}$'

        if (-not $discussValid -or -not $checkValid -or -not $fixValid) {
            Write-Host "$vuln - INVALID HASHES:" -ForegroundColor Red
            if (-not $discussValid) { Write-Host "  DiscussMD5: $discuss" -ForegroundColor Yellow }
            if (-not $checkValid) { Write-Host "  CheckMD5: $check" -ForegroundColor Yellow }
            if (-not $fixValid) { Write-Host "  FixMD5: $fix" -ForegroundColor Yellow }

            $results += [PSCustomObject]@{
                VulnID = $vuln
                DiscussMD5 = $discuss
                CheckMD5 = $check
                FixMD5 = $fix
                DiscussValid = $discussValid
                CheckValid = $checkValid
                FixValid = $fixValid
            }
        } else {
            Write-Host "$vuln - OK" -ForegroundColor Green
        }
    } else {
        Write-Host "$vuln - NOT FOUND" -ForegroundColor Magenta
    }
}

Write-Host ""
Write-Host "Summary: $($results.Count) functions with invalid MD5 hashes" -ForegroundColor Cyan

if ($results.Count -gt 0) {
    $results | Export-Csv -Path 'invalid_md5_hashes.csv' -NoTypeInformation
    Write-Host "Results exported to invalid_md5_hashes.csv" -ForegroundColor Green
}
