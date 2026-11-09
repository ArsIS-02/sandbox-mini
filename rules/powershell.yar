rule PowerShell_DownloadCradle {
    meta:
        description = "PowerShell: загрузка и выполнение кода из сети"
        severity = "high"
    strings:
        $iex1 = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Net.WebClient" nocase
        $enc1 = "-enc " nocase
        $enc2 = "-encodedcommand" nocase
        $bypass = "ExecutionPolicy Bypass" nocase
    condition:
        (any of ($iex*) and any of ($dl*)) or (any of ($enc*) and any of ($dl*))
        or (any of ($enc*) and $bypass)
}

rule PowerShell_Base64_PE {
    meta:
        description = "PowerShell-скрипт со встроенным PE в base64"
        severity = "high"
    strings:
        $ps = /(powershell|pwsh)/ nocase
        $b64pe = "TVqQ"  // 'MZ' в base64
    condition:
        $ps and $b64pe
}
