$modulePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"

$content = Get-Content $modulePath -Raw
$parseErrors = $null
$null = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$parseErrors)

Write-Host "Total errors found: $($parseErrors.Count)" -ForegroundColor Cyan

foreach ($err in $parseErrors | Select-Object -First 10) {
    Write-Host "`nLine $($err.Token.StartLine): $($err.Message)" -ForegroundColor Red

    $lines = $content -split "`n"
    if ($err.Token.StartLine -le $lines.Count) {
        $lineNum = $err.Token.StartLine - 1
        Write-Host "  Code: $($lines[$lineNum].Trim())" -ForegroundColor Yellow

        # Show context (2 lines before and after)
        for ($i = [Math]::Max(0, $lineNum - 2); $i -le [Math]::Min($lines.Count - 1, $lineNum + 2); $i++) {
            if ($i -eq $lineNum) {
                Write-Host "  $($i + 1): >>> $($lines[$i])" -ForegroundColor Red
            } else {
                Write-Host "  $($i + 1):     $($lines[$i])" -ForegroundColor Gray
            }
        }
    }
}
