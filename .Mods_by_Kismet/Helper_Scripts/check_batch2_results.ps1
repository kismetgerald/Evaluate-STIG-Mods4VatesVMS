#!/usr/bin/env pwsh
# Check Test113b CKL Results for Session #32 Batch 2 Functions

$cklPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\.Mods_by_Kismet\Test\Results\XO1\Checklist\XO1_XO_WebSRG_V4R4_20260203-205501.ckl"

Write-Host "=" -NoNewline; Write-Host ("=" * 79)
Write-Host "Session #32 Batch 2 - Test113b CKL Results Verification"
Write-Host "=" -NoNewline; Write-Host ("=" * 79)
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

        $results += [PSCustomObject]@{
            VulnID = $vulnId
            Status = $status
            HasComments = if ($hasComments) { "YES" } else { "NO" }
            HasFindingDetails = if ($hasFindingDetails) { "YES" } else { "NO" }
            CommentsLength = if ($comments) { $comments.Length } else { 0 }
            FindingDetailsLength = if ($findingDetails) { $findingDetails.Length } else { 0 }
        }
    } else {
        $results += [PSCustomObject]@{
            VulnID = $vulnId
            Status = "NOT FOUND"
            HasComments = "N/A"
            HasFindingDetails = "N/A"
            CommentsLength = 0
            FindingDetailsLength = 0
        }
    }
}

# Display results
$results | Format-Table -AutoSize

Write-Host ""
Write-Host "Summary:"
Write-Host "-" -NoNewline; Write-Host ("-" * 79)

$foundCount = ($results | Where-Object { $_.Status -ne "NOT FOUND" }).Count
$commentsCount = ($results | Where-Object { $_.HasComments -eq "YES" }).Count
$findingDetailsCount = ($results | Where-Object { $_.HasFindingDetails -eq "YES" }).Count

$statusCounts = $results | Where-Object { $_.Status -ne "NOT FOUND" } | Group-Object -Property Status | Select-Object Name, Count

Write-Host "Functions Found: $foundCount/5"
Write-Host "Functions with COMMENTS: $commentsCount/5"
Write-Host "Functions with FINDING_DETAILS: $findingDetailsCount/5"
Write-Host ""
Write-Host "Status Distribution:"
foreach ($statusGroup in $statusCounts) {
    Write-Host "  $($statusGroup.Name): $($statusGroup.Count)"
}

Write-Host ""
Write-Host "=" -NoNewline; Write-Host ("=" * 79)

if ($foundCount -eq 5 -and $commentsCount -eq 5 -and $findingDetailsCount -eq 5) {
    Write-Host "RESULT: ALL BATCH 2 FUNCTIONS VALIDATED SUCCESSFULLY"
} else {
    Write-Host "RESULT: VALIDATION INCOMPLETE - REVIEW REQUIRED"
}

Write-Host "=" -NoNewline; Write-Host ("=" * 79)
