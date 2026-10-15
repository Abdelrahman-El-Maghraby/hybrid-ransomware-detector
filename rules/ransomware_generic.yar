rule Ransomware_Note_And_ShadowCopy_Inhibition
{
    meta:
        description = "Detects ransomware extortion notes and shadow copy deletion commands"
        severity = "critical"
        author = "AEGIS SENTINEL"
    strings:
        $extort1 = "all your files have been encrypted" nocase ascii wide
        $extort2 = "send bitcoin to" nocase ascii wide
        $extort3 = "decrypt your files" nocase ascii wide
        $vss1 = "vssadmin delete shadows" nocase ascii wide
        $vss2 = "wmic shadowcopy delete" nocase ascii wide
        $vss3 = "bcdedit /set {default} recoveryenabled no" nocase ascii wide
    condition:
        any of ($vss*) or 2 of ($extort*)
}