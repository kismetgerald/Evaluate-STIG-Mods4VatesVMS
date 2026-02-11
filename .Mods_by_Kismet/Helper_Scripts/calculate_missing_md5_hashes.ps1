$xccdfPath = 'StigContent/U_Web_Server_SRG_V4R4_Manual-xccdf.xml'
$vulnIds = @('V-206351','V-206352','V-206353','V-206367','V-206386','V-206400','V-206401','V-206402','V-206403','V-206404','V-206405','V-206407','V-206408','V-206409','V-264360','V-264361')

[xml]$xccdf = Get-Content $xccdfPath

$results = @()

foreach ($vulnId in $vulnIds) {
    $group = $xccdf.Benchmark.Group | Where-Object { $_.id -eq $vulnId }

    if ($group) {
        $rule = $group.Rule
        $ruleId = $rule.id
        $title = $rule.title

        # Extract VulnDiscussion
        $vulnDiscuss = $rule.description -replace '<VulnDiscussion>', '' -replace '</VulnDiscussion>.*', ''

        # Extract Check content
        $checkContent = $rule.check.'check-content'

        # Extract Fix text
        $fixText = $rule.fixtext.'#text'

        # Calculate MD5 hashes
        $discussMD5 = if ($vulnDiscuss.Trim()) {
            (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($vulnDiscuss))) -Algorithm MD5).Hash.ToLower()
        } else {
            '00000000000000000000000000000000'
        }

        $checkMD5 = if ($checkContent.Trim()) {
            (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($checkContent))) -Algorithm MD5).Hash.ToLower()
        } else {
            '00000000000000000000000000000000'
        }

        $fixMD5 = if ($fixText.Trim()) {
            (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($fixText))) -Algorithm MD5).Hash.ToLower()
        } else {
            '00000000000000000000000000000000'
        }

        $results += [PSCustomObject]@{
            VulnID = $vulnId
            RuleID = $ruleId
            Title = $title
            DiscussMD5 = $discussMD5
            CheckMD5 = $checkMD5
            FixMD5 = $fixMD5
        }

        Write-Host ""
        Write-Host "=== $vulnId ===" -ForegroundColor Cyan
        Write-Host "Rule ID: $ruleId"
        Write-Host "Title: $title"
        Write-Host "DiscussMD5: $discussMD5"
        Write-Host "CheckMD5: $checkMD5"
        Write-Host "FixMD5: $fixMD5"
    } else {
        Write-Host "WARNING: $vulnId not found in XCCDF" -ForegroundColor Yellow
    }
}

# Export to CSV
$results | Export-Csv -Path 'missing_md5_hashes.csv' -NoTypeInformation
Write-Host ""
Write-Host "Results exported to missing_md5_hashes.csv" -ForegroundColor Green
Write-Host "Total functions processed: $($results.Count)" -ForegroundColor Cyan
