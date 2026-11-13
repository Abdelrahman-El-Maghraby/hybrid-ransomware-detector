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
        // M29: resizing deletes copies only with a /maxsize= limit; the bare
        // command (help, listing scripts) does not.
        $vss3 = /vssadmin resize shadowstorage[^\r\n]{0,200}maxsize=/ nocase wide ascii
        $wmi1 = "shadowcopy delete"                  nocase wide ascii
        $wbad = "wbadmin delete catalog"             nocase wide ascii
        $wbs  = "wbadmin delete systemstatebackup"   nocase wide ascii
        // M29: the WMI/CIM class names alone only list restore points; they
        // count with a deletion verb.
        $cls2 = "Get-WmiObject Win32_Shadowcopy"     nocase wide ascii
        $cls3 = "Get-CimInstance Win32_ShadowCopy"   nocase wide ascii
        $del1 = ".Delete("                           nocase wide ascii
        $del2 = "Remove-WmiObject"                   nocase wide ascii
        $del3 = "Remove-CimInstance"                 nocase wide ascii
        // M29: in a page or text that only shows a command, an API that runs it
        $run1 = "ActiveXObject"                      nocase wide ascii
        $run2 = "WScript.Shell"                      nocase wide ascii
        $run3 = "Shell.Application"                  nocase wide ascii
        $run4 = "ShellExecute"                       nocase wide ascii
        $run5 = "CreateObject"                       nocase wide ascii
        $run6 = "child_process"                      nocase wide ascii
    condition:
        (any of ($vss*, $wmi1, $wbad, $wbs) or (any of ($cls*) and any of ($del*)))
        // M29: prose formats (an advisory, an article, a help page) quote the
        // commands; there they count only next to an API that executes them.
        // Scripts, HTAs, macros, programs and smuggled payloads (scanned under
        // their own names) are unchanged.
        and (not (file_ext == "html" or file_ext == "htm" or file_ext == "xhtml"
                  or file_ext == "txt" or file_ext == "md")
             or any of ($run*))
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
