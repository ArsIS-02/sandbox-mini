rule Mimikatz_Strings {
    meta:
        description = "Характерные строки Mimikatz (sekurlsa, kerberos)"
        severity = "high"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "sekurlsa::wdigest" nocase
        $m3 = "kerberos::golden" nocase
        $m4 = "lsadump::sam" nocase
        $m5 = "mimikatz" nocase
        $m6 = "gentilkiwi" nocase
    condition:
        any of them
}

rule Credential_Dump_API {
    meta:
        description = "Доступ к памяти LSASS / SAM: характерные API"
        severity = "medium"
    strings:
        $a1 = "seclogon.dll" nocase
        $a2 = "SamIConnect" nocase
        $a3 = "MiniDumpWriteDump" nocase
        $lsas = "lsass.exe" nocase
    condition:
        $lsas and any of ($a*)
}
