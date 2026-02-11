$modulePath = ".\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
try {
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-Host "Module loaded successfully!" -ForegroundColor Green
    $count = (Get-Command -Module Scan-XO_WebSRG_Checks).Count
    Write-Host "Function count: $count" -ForegroundColor Cyan
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
}
