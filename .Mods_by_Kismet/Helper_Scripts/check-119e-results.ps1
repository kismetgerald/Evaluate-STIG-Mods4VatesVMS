#!/usr/bin/env pwsh
# Check Test119e results for all 7 Session #34 functions

$cklPath = "./Results/XO1/Checklist/XO1_XO_WebSRG_V4R4_20260209-194912.ckl"

if (-not (Test-Path $cklPath)) {
    Write-Host "CKL file not found: $cklPath" -ForegroundColor Red
    exit 1
}

[xml]$ckl = Get-Content $cklPath

$vulnIds = @('V-264346', 'V-264347', 'V-264348', 'V-264351', 'V-264352', 'V-264354', 'V-264357')

Write-Host "=" * 100
Write-Host "Test119e Results for Session #34 Functions (7 total)"
Write-Host "=" * 100
Write-Host ""

$results = @()

foreach ($vulnId in $vulnIds) {
    $vuln = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object {
        ($_.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' }).ATTRIBUTE_DATA -eq $vulnId
    }

    if ($vuln) {
        $status = $vuln.STATUS
        $findingDetails = $vuln.FINDING_DETAILS
        $comments = $vuln.COMMENTS

        $hasFindings = $findingDetails -and $findingDetails.Trim().Length -gt 0
        $hasComments = $comments -and $comments.Trim().Length -gt 0

        $result = [PSCustomObject]@{
            VulnID = $vulnId
            Status = $status
            FindingDetails = if ($hasFindings) { "$($findingDetails.Length) chars" } else { "EMPTY" }
            Comments = if ($hasComments) { "$($comments.Length) chars" } else { "EMPTY" }
            Result = if ($hasFindings -and $hasComments) { "PASS" } else { "FAIL" }
        }

        $results += $result

        $color = if ($result.Result -eq "PASS") { "Green" } else { "Red" }
        Write-Host "$vulnId : $status" -ForegroundColor $color
        Write-Host "  Finding Details: $($result.FindingDetails)" -ForegroundColor $color
        Write-Host "  Comments: $($result.Comments)" -ForegroundColor $color
        Write-Host "  Result: $($result.Result)" -ForegroundColor $color
        Write-Host ""
    } else {
        Write-Host "$vulnId : NOT FOUND IN CKL" -ForegroundColor Red
        Write-Host ""
    }
}

Write-Host "=" * 100
Write-Host "Summary"
Write-Host "=" * 100

$passCount = ($results | Where-Object { $_.Result -eq "PASS" }).Count
$failCount = ($results | Where-Object { $_.Result -eq "FAIL" }).Count

Write-Host "PASS: $passCount / 7" -ForegroundColor Green
Write-Host "FAIL: $failCount / 7" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })

if ($failCount -eq 0) {
    Write-Host "`nALL FUNCTIONS VALIDATED SUCCESSFULLY!" -ForegroundColor Green
} else {
    Write-Host "`nSOME FUNCTIONS FAILED VALIDATION" -ForegroundColor Red
}
