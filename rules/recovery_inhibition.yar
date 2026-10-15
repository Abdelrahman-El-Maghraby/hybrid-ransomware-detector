/*
    recovery_inhibition.yar
    Original rules for MITRE ATT&CK T1490 (Inhibit System Recovery). Before
    encrypting, almost every ransomware family deletes Volume Shadow Copies and
    disables Windows recovery so the victim cannot roll back. The commands are
    often embedded verbatim in droppers: macros, scripts, LNK arguments, or
    batch files hidden in archives. Written from scratch for this project.

    Strings are matched case-insensitively in ASCII and UTF-16LE ("wide"),
    which is how they appear in VBA, PowerShell and Windows binaries.
*/

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Deletes Volume Shadow Copies / backup catalogs (T1490)"
        severity    = "critical"
        mitre       = "T1490"
    strings:
        $vss1 = "vssadmin delete shadows"            nocase wide ascii
        $vss2 = "vssadmin.exe delete shadows"        nocase wide ascii
        $vss3 = "vssadmin resize shadowstorage"      nocase wide ascii
        $wmi1 = "shadowcopy delete"                  nocase wide ascii
        $wmi2 = "Get-WmiObject Win32_Shadowcopy"     nocase wide ascii
        $wmi3 = "Get-CimInstance Win32_ShadowCopy"   nocase wide ascii
        $wbad = "wbadmin delete catalog"             nocase wide ascii
        $wbs  = "wbadmin delete systemstatebackup"   nocase wide ascii
    condition:
        any of them
}

rule Ransomware_Boot_Recovery_Tampering
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Disables Windows recovery / boot repair before encryption (T1490)"
        severity    = "high"
        mitre       = "T1490"
    strings:
        $bcd  = "bcdedit"                            nocase wide ascii
        $re   = "recoveryenabled no"                 nocase wide ascii
        $bsp  = "bootstatuspolicy ignoreallfailures" nocase wide ascii
        $wre  = "reagentc /disable"                  nocase wide ascii
    condition:
        ($bcd and ($re or $bsp)) or $wre
}
