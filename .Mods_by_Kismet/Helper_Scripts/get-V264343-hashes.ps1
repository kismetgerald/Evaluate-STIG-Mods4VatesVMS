# Extract V-264343 metadata from XCCDF and calculate MD5 hashes
$xccdfPath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\StigContent\U_Web_Server_SRG_V4R4_Manual-xccdf.xml"

# Load XML
[xml]$xccdf = Get-Content $xccdfPath

# Find V-264343 group
$group = $xccdf.Benchmark.Group | Where-Object { $_.id -eq 'V-264343' }
$rule = $group.Rule

# Extract fields
$vulnDiscussion = $rule.description -replace '<VulnDiscussion>','<VulnDiscussion>' -replace '</VulnDiscussion>.*',''
$checkContent = $rule.check.'check-content'
$fixText = $rule.fixtext.'#text'

# Calculate MD5 hashes
function Get-MD5Hash {
    param([string]$text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $hash = $md5.ComputeHash($bytes)
    return [BitConverter]::ToString($hash) -replace '-',''
}

Write-Output "=== V-264343 Metadata ==="
Write-Output "VulnID: $($group.id)"
Write-Output "RuleID: $($rule.id)"
Write-Output "Version: $($rule.version)"
Write-Output "Title: $($rule.title)"
Write-Output ""
Write-Output "=== MD5 Hashes ==="
Write-Output "DiscussMD5: $(Get-MD5Hash $vulnDiscussion)"
Write-Output "CheckMD5: $(Get-MD5Hash $checkContent)"
Write-Output "FixMD5: $(Get-MD5Hash $fixText)"
