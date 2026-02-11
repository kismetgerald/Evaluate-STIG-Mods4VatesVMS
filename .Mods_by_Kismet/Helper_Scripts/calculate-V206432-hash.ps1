$discussion = "An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration.
To prohibit an attacker from stopping the web server, the process ID (pid) of the web server and the utilities used to start/stop the web server must be protected from access by non-privileged users. By knowing the pid and having access to the web server utilities, a non-privileged user has a greater capability of stopping the server, whether intentionally or unintentionally."

$checkContent = "Review the web server documentation and deployed configuration to determine where the process ID is stored and which utilities are used to start/stop the web server.

If they are not protected, this is a finding."

$fixText = "Remove or modify non-privileged account access to the web server process ID and the utilities used for starting/stopping the web server."

# Function to calculate MD5 hash of text
function Get-MD5Hash {
    param([string]$Text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = $md5.ComputeHash($bytes)
    return ($hash | ForEach-Object { $_.ToString("X2") }) -join ""
}

$discussMD5 = Get-MD5Hash -Text $discussion
$checkMD5 = Get-MD5Hash -Text $checkContent
$fixMD5 = Get-MD5Hash -Text $fixText

Write-Host "DiscussMD5: $discussMD5"
Write-Host "CheckMD5  : $checkMD5"
Write-Host "FixMD5    : $fixMD5"
Write-Host ""
Write-Host "Rule ID   : SV-206432r961620_rule"
Write-Host "Rule Title: The web server must be protected from being stopped by a non-privileged user."
