$filePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1"
$content = Get-Content $filePath -Raw

# Original content length
$originalLength = $content.Length

# The parameter block to insert
$paramsToAdd = @"

        [Parameter(Mandatory = `$false)]
        [String]`$Username,

        [Parameter(Mandatory = `$false)]
        [String]`$UserSID,

        [Parameter(Mandatory = `$false)]
        [String]`$Hostname,
"@

# Pattern to find and replace - looking for the AnswerKey parameter followed by Instance
# Using multiline mode and being very specific
$pattern = '(\[Parameter\(Mandatory = \$false\)\]\r?\n\s+\[String\]\$AnswerKey,)\r?\n\s+(\[Parameter\(Mandatory = \$false\)\]\r?\n\s+\[String\]\$Instance,)'
$replacement = "`$1$paramsToAdd`n`n        `$2"

# Perform the replacement
$newContent = $content -replace $pattern, $replacement

# Count how many replacements were made
$replacementCount = ([regex]::Matches($content, $pattern)).Count

# Save the file
$newContent | Set-Content $filePath -NoNewline

Write-Host "File updated successfully"
Write-Host "Original length: $originalLength"
Write-Host "New length: $($newContent.Length)"
Write-Host "Replacements made: $replacementCount"
Write-Host "Username parameters now in file: $((Select-String -Pattern '\$Username' -Path $filePath).Count)"
