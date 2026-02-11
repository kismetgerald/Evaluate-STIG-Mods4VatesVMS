# Find Remaining Stub Functions from Test112b CKL
$cklFile = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\.Mods_by_Kismet\Test\Results\XO1\Checklist\XO1_XO_WebSRG_V4R4_20260203-185924.ckl"

[xml]$ckl = Get-Content $cklFile

# Find all Not_Reviewed functions with stub-like finding details
$stubs = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object {
    $_.STATUS -eq 'Not_Reviewed' -and
    ($_.FINDING_DETAILS -like '*unable to determine*' -or
     $_.FINDING_DETAILS -like '*manual review*' -or
     $_.FINDING_DETAILS.Length -lt 500)
}

Write-Host "`nRemaining Stub Functions (Not_Reviewed):" -ForegroundColor Cyan
Write-Host "=========================================`n"

$vulnList = @()
foreach ($stub in $stubs) {
    $vulnId = ($stub.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Vuln_Num" }).ATTRIBUTE_DATA
    $title = ($stub.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Rule_Title" }).ATTRIBUTE_DATA
    $vulnList += $vulnId

    Write-Host "$vulnId" -ForegroundColor Yellow -NoNewline
    Write-Host " - $($title.Substring(0, [Math]::Min(80, $title.Length)))"
}

Write-Host "`nTotal Stubs: $($vulnList.Count)" -ForegroundColor Cyan
Write-Host "`nVuln IDs:" -ForegroundColor Cyan
$vulnList | Sort-Object | ForEach-Object { Write-Host "  $_" }
