try {
    [xml]$xml = Get-Content "../../AnswerFiles/XO_v5.x_WebSRG_AnswerFile.xml"
    Write-Host "✅ XML is valid" -ForegroundColor Green
    Write-Host "Root element: $($xml.STIGComments.Name)"
    Write-Host "Vuln count: $($xml.STIGComments.Vuln.Count)"

    # Check for duplicate Vuln IDs
    $vulnIds = $xml.STIGComments.Vuln | Select-Object -ExpandProperty ID
    $duplicates = $vulnIds | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($duplicates) {
        Write-Host "❌ DUPLICATES FOUND:" -ForegroundColor Red
        $duplicates | ForEach-Object { Write-Host "  $($_.Name): $($_.Count) instances" -ForegroundColor Red }
    } else {
        Write-Host "✅ No duplicate Vuln IDs" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ XML ERROR:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
