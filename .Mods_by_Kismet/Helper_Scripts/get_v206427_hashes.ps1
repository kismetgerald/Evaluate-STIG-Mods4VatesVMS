[xml]$xccdf = Get-Content '../../StigContent/U_Web_Server_SRG_V4R4_Manual-xccdf.xml'
$vulnId = 'V-206427'
$group = $xccdf.Benchmark.Group | Where-Object { $_.id -eq $vulnId }

if ($group) {
    $rule = $group.Rule
    $vulnDiscuss = $rule.description -replace '<VulnDiscussion>', '' -replace '</VulnDiscussion>.*', ''
    $checkContent = $rule.check.'check-content'
    $fixText = $rule.fixtext.'#text'

    $discussMD5 = if ($vulnDiscuss.Trim()) {
        (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($vulnDiscuss))) -Algorithm MD5).Hash.ToLower()
    } else {
        '00000000000000000000000000000000'
    }

    $checkMD5 = if ($checkContent.Trim()) {
        (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($checkContent))) -Algorithm MD5).Hash.ToLower()
    } else {
        '00000000000000000000000000000000'
    }

    $fixMD5 = if ($fixText.Trim()) {
        (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($fixText))) -Algorithm MD5).Hash.ToLower()
    } else {
        '00000000000000000000000000000000'
    }

    Write-Output "VulnID: $vulnId"
    Write-Output "RuleID: $($rule.id)"
    Write-Output "Title: $($rule.title)"
    Write-Output "DiscussMD5: $discussMD5"
    Write-Output "CheckMD5: $checkMD5"
    Write-Output "FixMD5: $fixMD5"
} else {
    Write-Output 'V-206427 not found in XCCDF'
}
