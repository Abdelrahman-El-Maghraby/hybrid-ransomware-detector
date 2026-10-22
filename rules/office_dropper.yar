/*
    office_dropper.yar
    Original YARA heuristics for weaponised document droppers (Office macros and
    malicious PDFs). Complements the olevba macro layer: olevba parses VBA
    semantically, while these rules catch indicator strings directly in the file
    bytes (useful for OOXML containers and PDFs). Written from scratch.
*/

// file_ext is passed by the scanner (lower-case extension without the dot).
private rule Doc_Like_Extension
{
    condition:
        file_ext matches /^(html?|xhtml|md|markdown|rst|txt|pdf|svg|json|css)$/
}

private rule Program_Extension
{
    condition:
        file_ext matches /^(exe|dll|sys|ocx|cpl|drv|efi|mui|scr|com|msi|pyd|node|ax|winmd)$/
}

rule Office_Macro_AutoExec_Execution
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "VBA auto-run trigger combined with a process/shell primitive"
        severity    = "high"
    strings:
        $a1 = "AutoOpen"        nocase wide ascii
        $a2 = "Auto_Open"       nocase wide ascii
        $a3 = "Document_Open"   nocase wide ascii
        $a4 = "Workbook_Open"   nocase wide ascii
        $a5 = "AutoExec"        nocase wide ascii
        $x1 = "Shell"           nocase wide ascii
        $x2 = "WScript.Shell"   nocase wide ascii
        $x3 = "CreateObject"    nocase wide ascii
        $x4 = "powershell"      nocase wide ascii
        $x5 = "cmd.exe"         nocase wide ascii
        $vb = "Attribute VB_"   ascii wide
    condition:
        // 4.4.0-beta.2: only in Office binaries (OLE), Word 2003 XML / MHTML
        // exports, or VBA source - the words also occur in manuals and scripts.
        // 4.4.0: small web pages and text are manuals, not macros.
        (uint32(0) == 0xE011CFD0 or $vb or (filesize < 64KB and not Doc_Like_Extension))
        and (any of ($a*)) and (any of ($x*))
}

rule Office_Macro_Payload_Download
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "VBA networking primitives used to pull a remote payload"
        severity    = "high"
    strings:
        $n1 = "URLDownloadToFile" nocase wide ascii
        $n2 = "MSXML2.XMLHTTP"    nocase wide ascii
        $n3 = "WinHttp.WinHttpRequest" nocase wide ascii
        $n4 = "ADODB.Stream"      nocase wide ascii
        $h1 = "http://"           nocase wide ascii
        $h2 = "https://"          nocase wide ascii
        $vb = "Attribute VB_"     ascii wide
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        // 4.4.0-beta.2: Office binaries, VBA source or small dropped scripts only
        // 4.4.0: small web pages and text are manuals, not macros.
        ($ole at 0 or $vb or (filesize < 64KB and not Doc_Like_Extension))
        and (any of ($n*)) and (any of ($h*))
}

rule PDF_AutoLaunch_Action
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "PDF that auto-runs JavaScript or launches an external program"
        severity    = "medium"
    strings:
        $pdf  = "%PDF-"
        $oa   = "/OpenAction"
        $aa   = "/AA"
        $js   = "/JavaScript"
        $js2  = "/JS"
        $lnch = "/Launch"
    condition:
        $pdf at 0 and (($oa or $aa) and ($js or $js2 or $lnch))
}

rule Embedded_Executable_In_Document
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Windows PE executable (MZ header at offset 0) masquerading as a document"
        severity    = "high"
    strings:
        // MZ DOS header followed (loosely) by the PE signature.
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        // 4.4.0: a program named as a program is not masquerading (it was
        // firing on every .exe/.dll); archive / mail layers judge delivered ones.
        $mz at 0 and ($pe or $dos_stub) and not Program_Extension
}
