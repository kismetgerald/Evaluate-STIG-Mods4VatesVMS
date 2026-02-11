# Investigate failed Session #30 functions

$cklPath = "../../.Mods_by_Kismet/Test/Results/XO1/Checklist/XO1_XO_WebSRG_V4R4_20260201-213623.ckl"
[xml]$ckl = Get-Content $cklPath

$failedVulns = @("V-206432", "V-206445", "V-264343", "V-264344", "V-264356")

foreach ($vulnId in $failedVulns) {
    $vuln = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object {
        $_.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' -and $_.ATTRIBUTE_DATA -eq $vulnId }
    }

    if ($vuln) {
        Write-Host "=" * 80 -ForegroundColor Red
        Write-Host "$vulnId - Status: $($vuln.STATUS)" -ForegroundColor Red
        Write-Host "=" * 80 -ForegroundColor Red
        Write-Host ""

        $findingText = $vuln.FINDING_DETAILS

        # Check if it's an error
        if ($findingText -like "*Failed*" -or $findingText -like "*ERROR*") {
            Write-Host "ERROR DETECTED:" -ForegroundColor Yellow
            Write-Host $findingText.Substring(0, [Math]::Min(500, $findingText.Length))
        }
        # Check if it's a stub
        elseif ($findingText -like "*manual review*" -and $findingText.Length -lt 500) {
            Write-Host "STUB DETECTED (short generic text):" -ForegroundColor Yellow
            Write-Host $findingText
        }
        # Otherwise show first part
        else {
            Write-Host "Finding Details (first 400 chars):" -ForegroundColor Cyan
            Write-Host $findingText.Substring(0, [Math]::Min(400, $findingText.Length))
        }

        Write-Host ""
    }
}
