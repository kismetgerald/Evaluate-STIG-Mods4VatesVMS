#!/usr/bin/env pwsh
# Analyze Test119e execution times

$log = Get-Content './Logs/Test119e_XO1_Evaluate-STIG.log'

$groupIds = $log | Select-String 'Group ID : V-' | ForEach-Object {
    if ($_ -match 'Group ID : (V-\d+).*time="(\d+):(\d+):(\d+\.\d+)') {
        [PSCustomObject]@{
            VulnID = $matches[1]
            TimeString = "$($matches[2]):$($matches[3]):$($matches[4])"
            TotalSeconds = [int]$matches[2] * 3600 + [int]$matches[3] * 60 + [double]$matches[4]
        }
    }
}

Write-Host "Functions with execution time >30 seconds:" -ForegroundColor Cyan
Write-Host "=" * 60

$longRunning = @()
for ($i = 0; $i -lt ($groupIds.Count - 1); $i++) {
    $current = $groupIds[$i]
    $next = $groupIds[$i + 1]
    $duration = $next.TotalSeconds - $current.TotalSeconds
    if ($duration -gt 30) {
        $longRunning += [PSCustomObject]@{
            VulnID = $current.VulnID
            Duration = [math]::Round($duration, 1)
        }
    }
}

if ($longRunning.Count -gt 0) {
    $longRunning | Sort-Object -Property Duration -Descending | ForEach-Object {
        Write-Host "$($_.VulnID): $($_.Duration) seconds" -ForegroundColor Yellow
    }
} else {
    Write-Host "No functions took longer than 30 seconds" -ForegroundColor Green
}

Write-Host "`nTotal scan time:" -ForegroundColor Cyan
$first = $groupIds[0]
$last = $groupIds[$groupIds.Count - 1]
$totalSeconds = $last.TotalSeconds - $first.TotalSeconds
$totalMinutes = [math]::Floor($totalSeconds / 60)
Write-Host "$totalMinutes minutes, $([math]::Round($totalSeconds % 60, 1)) seconds"
