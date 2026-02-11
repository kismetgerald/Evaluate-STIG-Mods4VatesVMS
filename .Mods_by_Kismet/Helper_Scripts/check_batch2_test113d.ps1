#!/usr/bin/env pwsh
# Check Test113d CKL Results for Session #32 Batch 2 Functions

$cklPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\.Mods_by_Kismet\Test\Results\XO1\Checklist\XO1_XO_WebSRG_V4R4_20260203-215540.ckl"

Write-Host "=" * 80
Write-Host "Session #32 Batch 2 - Test113d CKL Results Verification"
Write-Host "=" * 80
Write-Host ""

# Load CKL file
[xml]$ckl = Get-Content $cklPath

# Batch 2 Vuln IDs
$batch2VulnIds = @("V-206416", "V-206417", "V-206418", "V-206421", "V-206422")

# Results table
$results = @()

foreach ($vulnId in $batch2VulnIds) {
    # Find the Vuln entry
    $vuln = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Vuln_Num" -and $_.ATTRIBUTE_DATA -eq $vulnId } }

    if ($vuln) {
        $status = $vuln.STATUS
        $comments = $vuln.COMMENTS
        $findingDetails = $vuln.FINDING_DETAILS

        $hasComments = $comments -and $comments.Trim().Length -gt 0
        $hasFindingDetails = $findingDetails -and $findingDetails.Trim().Length -gt 0

        # Check if FINDING_DETAILS contains error message
        $hasError = $findingDetails -match '\*\*\* Scan-.*Failed\.\s\*\*\*|\$Result\.Status is null|parameter cannot be found'

        $results += [PSCustomObject]@{
            VulnID = $vulnId
            Status = $status
            HasComments = if ($hasComments) { "YES" } else { "NO" }
            HasFindingDetails = if ($hasFindingDetails) { "YES" } else { "NO" }
            HasError = if ($hasError) { "ERROR" } else { "OK" }
            CommentsLength = if ($comments) { $comments.Length } else { 0 }
            FindingDetailsLength = if ($findingDetails) { $findingDetails.Length } else { 0 }
        }
    } else {
        $results += [PSCustomObject]@{
            VulnID = $vulnId
            Status = "NOT FOUND"
            HasComments = "N/A"
            HasFindingDetails = "N/A"
            HasError = "N/A"
            CommentsLength = 0
            FindingDetailsLength = 0
        }
    }
}

# Display results
$results | Format-Table -AutoSize

Write-Host ""
Write-Host "Summary:"
Write-Host "-" * 80

$foundCount = ($results | Where-Object { $_.Status -ne "NOT FOUND" }).Count
$commentsCount = ($results | Where-Object { $_.HasComments -eq "YES" }).Count
$findingDetailsCount = ($results | Where-Object { $_.HasFindingDetails -eq "YES" }).Count
$errorCount = ($results | Where-Object { $_.HasError -eq "ERROR" }).Count
$notReviewedCount = ($results | Where-Object { $_.Status -eq "Not_Reviewed" }).Count

$statusCounts = $results | Where-Object { $_.Status -ne "NOT FOUND" } | Group-Object -Property Status | Select-Object Name, Count

Write-Host "Functions Found: $foundCount/5"
Write-Host "Functions with COMMENTS: $commentsCount/5"
Write-Host "Functions with FINDING_DETAILS: $findingDetailsCount/5"
Write-Host "Functions with ERRORS: $errorCount/5"
Write-Host "Functions with Not_Reviewed: $notReviewedCount/5"
Write-Host ""
Write-Host "Status Distribution:"
foreach ($statusGroup in $statusCounts) {
    Write-Host "  $($statusGroup.Name): $($statusGroup.Count)"
}

Write-Host ""
Write-Host "=" * 80

if ($foundCount -eq 5 -and $commentsCount -eq 5 -and $findingDetailsCount -eq 5 -and $errorCount -eq 0 -and $notReviewedCount -eq 0) {
    Write-Host "RESULT: ALL BATCH 2 FUNCTIONS VALIDATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host ""
    Write-Host "Session #32 Batch 2 - IMPLEMENTATION COMPLETE" -ForegroundColor Green
    exit 0
} elseif ($errorCount -gt 0 -or $notReviewedCount -gt 0) {
    Write-Host "RESULT: VALIDATION FAILED - EXECUTION ERRORS DETECTED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "RESULT: VALIDATION INCOMPLETE - REVIEW REQUIRED" -ForegroundColor Yellow
    exit 2
}

Write-Host "=" * 80
