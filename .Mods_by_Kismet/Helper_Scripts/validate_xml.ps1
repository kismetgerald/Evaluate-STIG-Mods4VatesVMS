#!/usr/bin/env pwsh
# Validate answer file XML structure

$AnswerFilePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml"

try {
    [xml]$xml = Get-Content $AnswerFilePath -ErrorAction Stop
    Write-Host "XML Validation: PASSED" -ForegroundColor Green
    $vulnCount = ($xml.AnswerFile.Vuln | Measure-Object).Count
    Write-Host "Total Vuln entries: $vulnCount" -ForegroundColor Cyan

    # Check for unescaped ampersands
    $content = Get-Content $AnswerFilePath -Raw
    $unescaped = $content | Select-String '(?<!&)(amp;|lt;|gt;|quot;|apos;)\s*&\s*(?!amp;|lt;|gt;|quot;|apos;)' -AllMatches

    if ($null -eq $unescaped -or $unescaped.Matches.Count -eq 0) {
        Write-Host "Ampersand check: All ampersands properly escaped" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Found $($unescaped.Matches.Count) potentially unescaped ampersands" -ForegroundColor Yellow
    }

    exit 0
} catch {
    Write-Host "XML Validation: FAILED" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
