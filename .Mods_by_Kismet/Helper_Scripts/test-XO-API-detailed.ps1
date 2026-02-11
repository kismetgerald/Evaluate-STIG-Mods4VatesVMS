# Test XO REST API - Detailed Response Analysis
# Created: January 24, 2026
# Purpose: Analyze the actual structure of audit log API responses

$ErrorActionPreference = 'Stop'

# Configuration
$xoUrl = "https://xo1.wgsdac.net"
$token = "uaQQvl89KhfVWqiXJNvJIJmlK25irCEowCNXP1C91vA"

# Set up headers
$headers = @{
    "Cookie" = "authenticationToken=$token"
    "Accept" = "application/json"
}

Write-Host "`n=== XO REST API Detailed Analysis ===" -ForegroundColor Cyan

# Test: Get audit logs and examine structure
Write-Host "`n[Test] Audit Logs API Response Structure" -ForegroundColor Yellow

try {
    $auditUrl = "$xoUrl/rest/v0/plugins/audit/records?limit=10"
    Write-Host "Fetching: $auditUrl" -ForegroundColor Gray

    $response = Invoke-RestMethod -Uri $auditUrl -Headers $headers -Method GET -SkipCertificateCheck -ErrorAction Stop

    Write-Host "`nResponse Type: $($response.GetType().FullName)" -ForegroundColor Cyan
    Write-Host "Response Count: $($response.Count)" -ForegroundColor White

    if ($response -is [Array] -or $response -is [System.Collections.IEnumerable]) {
        Write-Host "`nFirst Element:" -ForegroundColor Cyan
        Write-Host "  Type: $($response[0].GetType().FullName)" -ForegroundColor White
        Write-Host "  Value: $($response[0])" -ForegroundColor White

        if ($response[0] -is [String]) {
            Write-Host "`n  [INFO] API returned string IDs, not full objects" -ForegroundColor Yellow
            Write-Host "  [ACTION] Need to fetch individual records" -ForegroundColor Yellow

            # Try fetching the individual record
            Write-Host "`nFetching individual record..." -ForegroundColor Cyan
            $recordId = $response[0]
            $recordUrl = "$xoUrl$recordId"
            Write-Host "  URL: $recordUrl" -ForegroundColor Gray

            try {
                $record = Invoke-RestMethod -Uri $recordUrl -Headers $headers -Method GET -SkipCertificateCheck -ErrorAction Stop

                Write-Host "`nIndividual Record:" -ForegroundColor Green
                Write-Host "  Type: $($record.GetType().FullName)" -ForegroundColor White
                $record | Format-List

                # Check for timestamp fields
                Write-Host "`nTimestamp Fields:" -ForegroundColor Cyan
                if ($record.PSObject.Properties) {
                    $record.PSObject.Properties | Where-Object { $_.Name -match 'time|date|stamp' } | ForEach-Object {
                        Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
                    }
                }

                # Show all fields
                Write-Host "`nAll Fields:" -ForegroundColor Cyan
                if ($record.PSObject.Properties) {
                    $record.PSObject.Properties | ForEach-Object {
                        Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
                    }
                }
            }
            catch {
                Write-Host "  ERROR fetching individual record: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "`nFirst Record Details:" -ForegroundColor Green
            $response[0] | Format-List

            # Check for timestamp fields
            Write-Host "`nTimestamp Fields:" -ForegroundColor Cyan
            $response[0].PSObject.Properties | Where-Object { $_.Name -match 'time|date|stamp' } | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
            }
        }
    }
    else {
        Write-Host "`nDirect Response:" -ForegroundColor Green
        $response | Format-List
    }

    # Try converting to JSON to see raw structure
    Write-Host "`nRaw JSON Response (first 2 records):" -ForegroundColor Cyan
    $response | Select-Object -First 2 | ConvertTo-Json -Depth 10
}
catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        Write-Host "Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    }
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
