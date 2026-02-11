# Analyze Test110b CKL results for Session #30 functions

$cklPath = "../../.Mods_by_Kismet/Test/Results/XO1/Checklist/XO1_XO_WebSRG_V4R4_20260201-213623.ckl"
[xml]$ckl = Get-Content $cklPath

$session30Vulns = @("V-206427", "V-206428", "V-206432", "V-206433", "V-206443", "V-206445", "V-264343", "V-264344", "V-264355", "V-264356")

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Session #30 Test110b Results Analysis" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

$results = @()
foreach ($vulnId in $session30Vulns) {
    $vuln = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object {
        $_.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' -and $_.ATTRIBUTE_DATA -eq $vulnId }
    }

    if ($vuln) {
        $status = $vuln.STATUS
        $hasComments = $vuln.COMMENTS -and $vuln.COMMENTS.Length -gt 0
        $commentLength = if ($hasComments) { $vuln.COMMENTS.Length } else { 0 }
        $findingDetailsLength = if ($vuln.FINDING_DETAILS) { $vuln.FINDING_DETAILS.Length } else { 0 }

        $results += [PSCustomObject]@{
            VulnID = $vulnId
            Status = $status
            HasComments = $hasComments
            CommentLength = $commentLength
            FindingLength = $findingDetailsLength
        }
    }
}

$results | Format-Table -AutoSize

Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  NotAFinding: $($results | Where-Object { $_.Status -eq 'NotAFinding' } | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "  Open: $($results | Where-Object { $_.Status -eq 'Open' } | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "  With Comments: $($results | Where-Object { $_.HasComments } | Measure-Object | Select-Object -ExpandProperty Count)/10"
Write-Host ""
