# Test XO REST API - Explore Audit Logs Endpoint
# Created: January 24, 2026
# Purpose: Test XO API for V-206367 timestamp verification

$ErrorActionPreference = 'Stop'

# Configuration
$xoUrl = "https://xo1.wgsdac.net"
$token = "uaQQvl89KhfVWqiXJNvJIJmlK25irCEowCNXP1C91vA"

# PowerShell 7+ uses -SkipCertificateCheck parameter instead of ServicePointManager
# No additional SSL bypass needed - we'll use -SkipCertificateCheck on Invoke-RestMethod

# Set up headers with authentication token
$headers = @{
    "Cookie" = "authenticationToken=$token"
    "Accept" = "application/json"
}

Write-Host "`n=== XO REST API Test ===" -ForegroundColor Cyan
Write-Host "URL: $xoUrl" -ForegroundColor White
Write-Host "Token: $($token.Substring(0,10))..." -ForegroundColor White

# Test 1: Get audit logs
Write-Host "`n[Test 1] Querying Audit Logs Endpoint" -ForegroundColor Yellow
Write-Host "Endpoint: /rest/v0/plugins/audit/records" -ForegroundColor Gray

try {
    $auditUrl = "$xoUrl/rest/v0/plugins/audit/records?limit=10"
    Write-Host "Fetching: $auditUrl" -ForegroundColor Gray

    $auditLogs = Invoke-RestMethod -Uri $auditUrl -Headers $headers -Method GET -SkipCertificateCheck -ErrorAction Stop

    Write-Host "SUCCESS: Received audit logs" -ForegroundColor Green
    Write-Host "Number of records: $($auditLogs.Count)" -ForegroundColor White

    if ($auditLogs -and $auditLogs.Count -gt 0) {
        Write-Host "`nLatest Audit Log Entry:" -ForegroundColor Cyan
        $latestLog = $auditLogs[0]
        $latestLog | Format-List

        # Check for timestamp fields
        Write-Host "`nTimestamp Fields Found:" -ForegroundColor Cyan
        $latestLog.PSObject.Properties | Where-Object { $_.Name -match 'time|date|stamp' } | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
        }

        # Parse timestamp and compare to system time
        if ($latestLog.time -or $latestLog.timestamp -or $latestLog.created) {
            $timestampField = if ($latestLog.time) { $latestLog.time }
                             elseif ($latestLog.timestamp) { $latestLog.timestamp }
                             else { $latestLog.created }

            Write-Host "`nTimestamp Analysis:" -ForegroundColor Cyan
            Write-Host "  Log timestamp value: $timestampField" -ForegroundColor White

            try {
                # Try parsing as Unix timestamp (milliseconds)
                if ($timestampField -is [int64] -or $timestampField -match '^\d+$') {
                    $logTime = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$timestampField).DateTime
                    Write-Host "  Parsed as Unix timestamp: $($logTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
                }
                # Try parsing as ISO 8601
                else {
                    $logTime = [datetime]::Parse($timestampField)
                    Write-Host "  Parsed as ISO 8601: $($logTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
                }

                $systemTime = Get-Date
                $timeDiff = [math]::Abs(($systemTime - $logTime).TotalMinutes)

                Write-Host "  System time: $($systemTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
                Write-Host "  Time difference: $([math]::Round($timeDiff, 2)) minutes" -ForegroundColor White

                if ($timeDiff -le 60) {
                    Write-Host "  RESULT: PASS (within 60 minutes)" -ForegroundColor Green
                }
                else {
                    Write-Host "  RESULT: FAIL (more than 60 minutes difference)" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "  ERROR parsing timestamp: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}
catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details:" -ForegroundColor Yellow
    Write-Host $_.Exception -ForegroundColor Gray
}

# Test 2: Try alternative endpoints
Write-Host "`n[Test 2] Trying Alternative Log Endpoints" -ForegroundColor Yellow

$alternativeEndpoints = @(
    "/rest/v0/logs",
    "/rest/v0/events",
    "/rest/v0/audit/records",
    "/rest/v0/plugins/audit/logs"
)

foreach ($endpoint in $alternativeEndpoints) {
    try {
        Write-Host "`nTesting: $endpoint" -ForegroundColor Gray
        $result = Invoke-RestMethod -Uri "$xoUrl$endpoint" -Headers $headers -Method GET -SkipCertificateCheck -TimeoutSec 5 -ErrorAction Stop
        Write-Host "  SUCCESS - Found data!" -ForegroundColor Green
        Write-Host "  Response type: $($result.GetType().Name)" -ForegroundColor White
        if ($result.Count) {
            Write-Host "  Record count: $($result.Count)" -ForegroundColor White
        }
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Host "  404 Not Found" -ForegroundColor DarkGray
        }
        elseif ($_.Exception.Message -match 'timeout') {
            Write-Host "  Timeout (5 sec)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}

# Test 3: Get current user info (verify authentication)
Write-Host "`n[Test 3] Verify Authentication" -ForegroundColor Yellow
try {
    $userInfo = Invoke-RestMethod -Uri "$xoUrl/rest/v0/users/me" -Headers $headers -Method GET -SkipCertificateCheck -ErrorAction Stop
    Write-Host "SUCCESS: Authenticated as $($userInfo.email)" -ForegroundColor Green
    Write-Host "User ID: $($userInfo.id)" -ForegroundColor White
    Write-Host "Permission: $($userInfo.permission)" -ForegroundColor White
}
catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
