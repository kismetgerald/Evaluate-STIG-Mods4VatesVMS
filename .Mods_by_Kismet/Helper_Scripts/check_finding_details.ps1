#!/usr/bin/env pwsh
# Check FINDING_DETAILS for V-206416, V-206417, V-206418 to diagnose Not_Reviewed status

$cklPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\.Mods_by_Kismet\Test\Results\XO1\Checklist\XO1_XO_WebSRG_V4R4_20260203-205501.ckl"

[xml]$ckl = Get-Content $cklPath

$vulnIds = @("V-206416", "V-206417", "V-206418")

foreach ($vulnId in $vulnIds) {
    $vuln = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Vuln_Num" -and $_.ATTRIBUTE_DATA -eq $vulnId } }

    Write-Host "=" * 80
    Write-Host "$vulnId - Status: $($vuln.STATUS)"
    Write-Host "=" * 80
    Write-Host $vuln.FINDING_DETAILS
    Write-Host ""
}
