rule Office_Macro_PowerShell_Dropper
{
    meta:
        description = "Detects Office macro dropper patterns invoking PowerShell or URLDownloadToFile"
        severity = "high"
        author = "AEGIS SENTINEL"
    strings:
        $auto1 = "AutoOpen" nocase ascii wide
        $auto2 = "Document_Open" nocase ascii wide
        $auto3 = "Workbook_Open" nocase ascii wide
        $exec1 = "WScript.Shell" nocase ascii wide
        $exec2 = "powershell" nocase ascii wide
        $exec3 = "URLDownloadToFile" nocase ascii wide
    condition:
        any of ($auto*) and any of ($exec*)
}