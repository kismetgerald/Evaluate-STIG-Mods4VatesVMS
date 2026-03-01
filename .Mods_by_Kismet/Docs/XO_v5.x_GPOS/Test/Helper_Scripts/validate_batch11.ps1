$modulePath = "Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"
try {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        Write-Host "Parse ERRORS: $($errors.Count)"
        foreach ($e in $errors) {
            Write-Host "  Line $($e.Extent.StartLineNumber): $($e.Message)"
        }
    }
    else {
        $funcs = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)
        Write-Host "Parse: OK ($($funcs.Count) functions, 0 errors)"
        $batch11 = @('Get-V203649','Get-V203657','Get-V203658','Get-V203659','Get-V203660','Get-V203661','Get-V203663','Get-V203664','Get-V203683','Get-V203684')
        foreach ($fn in $batch11) {
            $found = $funcs | Where-Object { $_.Name -eq $fn }
            if ($found) {
                Write-Host "  $fn : Found (line $($found.Extent.StartLineNumber))"
            } else {
                Write-Host "  $fn : MISSING!"
            }
        }
    }
} catch {
    Write-Host "Parse FAILED: $($_.Exception.Message)"
}
