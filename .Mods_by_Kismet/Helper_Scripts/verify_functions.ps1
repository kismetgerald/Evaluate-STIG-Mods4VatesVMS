# Count lines in each function from start to end
$psm1Path = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"

$content = Get-Content $psm1Path -Raw
$lines = Get-Content $psm1Path

# Find function starts
$v206398Start = [array]::FindIndex($lines, [System.Predicate[string]]{ param($x) $x -match "^Function Get-V206398" }) + 1
$v206435Start = [array]::FindIndex($lines, [System.Predicate[string]]{ param($x) $x -match "^Function Get-V206435" }) + 1
$v206436Start = [array]::FindIndex($lines, [System.Predicate[string]]{ param($x) $x -match "^Function Get-V206436" }) + 1

Write-Host "Function Locations in psm1 file:"
Write-Host "  V-206398 starts at line: $v206398Start"
Write-Host "  V-206435 starts at line: $v206435Start"
Write-Host "  V-206436 starts at line: $v206436Start"

# Find next function after each
$v206368Start = [array]::FindIndex($lines, $v206398Start, [System.Predicate[string]]{ param($x) $x -match "^Function Get-V206368" }) + 1
$nextAfter435 = [array]::FindIndex($lines, $v206435Start, [System.Predicate[string]]{ param($x) $x -match "^Function Get-V206437" }) + 1
$nextAfter436 = [array]::FindIndex($lines, $v206436Start, [System.Predicate[string]]{ param($x) $x -match "^Function Get-V206437" }) + 1

Write-Host "`nApproximate line counts:"
Write-Host "  V-206398: ~$(($nextAfter435 - $v206398Start) + 1) lines"
Write-Host "  V-206435: ~$(($nextAfter436 - $v206435Start) + 1) lines"
Write-Host "  V-206436: ~$(($nextAfter436 - $v206436Start) + 1) lines (estimated)"

# Quick validation - check for critical elements
Write-Host "`nValidation checks:"
$v206398Content = $lines[$v206398Start..$($v206435Start-2)] -join "`n"
$v206435Content = $lines[$v206435Start..$($v206436Start-2)] -join "`n"
$v206436Content = $lines[$v206436Start..$($nextAfter436-2)] -join "`n"

@{
    "V-206398" = @{
        hasSendCheckResult = $v206398Content -match "return Send-CheckResult"
        hasParam = $v206398Content -match "param \("
        hasStatus = $v206398Content -match '\$Status = "(NotAFinding|Open)"'
        lineCount = $v206435Start - $v206398Start
    }
    "V-206435" = @{
        hasSendCheckResult = $v206435Content -match "return Send-CheckResult"
        hasParam = $v206435Content -match "param \("
        hasStatus = $v206435Content -match '\$Status = "(NotAFinding|Open)"'
        lineCount = $v206436Start - $v206435Start
    }
    "V-206436" = @{
        hasSendCheckResult = $v206436Content -match "return Send-CheckResult"
        hasParam = $v206436Content -match "param \("
        hasStatus = $v206436Content -match '\$Status = "(NotAFinding|Open)"'
        lineCount = $lines.Count - $v206436Start
    }
} | ConvertTo-Json
