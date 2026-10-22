/*
    delivery_techniques.yar
    Original rules (4.4.0-beta.2) for the file types that replaced Office macros
    as first stages after macros from the internet were blocked by default:
    Windows shortcuts with a hidden command line, HTML Applications, encoded
    scripts, OneNote notebooks carrying a script or program, and the
    LOLBin download one-liners they all run. Written from scratch for this
    project; each rule was run over a benign corpus before it was added.
*/


rule LNK_Shortcut_Runs_Script_Host
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Windows shortcut whose arguments start a script host or LOLBin"
        severity    = "high"
        mitre       = "T1204.002"
    strings:
        $h1 = "powershell"  nocase wide ascii
        $h2 = "cmd.exe"     nocase wide ascii
        $h3 = "mshta"       nocase wide ascii
        $h4 = "wscript"     nocase wide ascii
        $h5 = "cscript"     nocase wide ascii
        $h6 = "rundll32"    nocase wide ascii
        $h7 = "regsvr32"    nocase wide ascii
        $h8 = "certutil"    nocase wide ascii
        $a1 = "http://"     nocase wide ascii
        $a2 = "https://"    nocase wide ascii
        $a3 = " -enc"       nocase wide ascii
        $a4 = "hidden"      nocase wide ascii
        $a5 = "/c "         nocase wide ascii
        $a6 = "javascript:" nocase wide ascii
        $a7 = "%temp%"      nocase wide ascii
        $a8 = "\\Users\\Public" nocase wide ascii
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401   // shell link header + CLSID
        and filesize < 2MB
        and any of ($h*) and any of ($a*)
}

rule HTA_Application_With_Script_Execution
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "HTML Application that creates shell / process objects"
        severity    = "high"
        mitre       = "T1218.005"
    strings:
        $hta  = "<hta:application" nocase ascii wide
        $x1   = "WScript.Shell"     nocase ascii wide
        $x2   = "Shell.Application" nocase ascii wide
        $x3   = "Win32_Process"     nocase ascii wide
        $x4   = "Scripting.FileSystemObject" nocase ascii wide
        $x5   = "ADODB.Stream"      nocase ascii wide
        $run1 = ".Run"              nocase ascii wide
        $run2 = ".Exec"             nocase ascii wide
        $run3 = "ShellExecute"      nocase ascii wide
        $run4 = ".SaveToFile"       nocase ascii wide
    condition:
        $hta and any of ($x*) and any of ($run*)
}

rule Script_Encoder_Encoded_Block
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Windows Script Encoder output (.vbe / .jse) - source deliberately hidden"
        severity    = "medium"
        mitre       = "T1027"
    strings:
        $se = /#@~\^[A-Za-z0-9+\/]{6}==/
    condition:
        $se
}

rule OneNote_Embedded_Script_Or_Program
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "OneNote notebook with an embedded file that runs on double-click"
        severity    = "high"
        mitre       = "T1566.001"
    strings:
        // FileDataStoreObject header GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
        $fdso = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }
        $e1 = ".hta"  nocase wide ascii
        $e2 = ".vbs"  nocase wide ascii
        $e3 = ".js\x00" nocase wide ascii
        $e4 = ".cmd"  nocase wide ascii
        $e5 = ".bat"  nocase wide ascii
        $e6 = ".exe"  nocase wide ascii
        $e7 = ".lnk"  nocase wide ascii
        $e8 = ".ps1"  nocase wide ascii
        $e9 = ".wsf"  nocase wide ascii
        $mz = { 4D 5A 90 00 }
    condition:
        // .one section header GUID {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
        uint32(0) == 0x7B5C52E4 and uint32(4) == 0x4DA7D88C
        and $fdso and (any of ($e*) or $mz)
}

rule LOLBin_Download_Command
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Built-in Windows tool used to download a file (certutil / bitsadmin / mshta)"
        severity    = "high"
        mitre       = "T1105"
    strings:
        $c1 = /certutil(\.exe)?\s+[^\r\n]{0,40}-urlcache[^\r\n]{0,40}https?:\/\//  nocase ascii wide
        $c2 = /bitsadmin(\.exe)?\s+\/transfer\s+[^\r\n]{0,80}https?:\/\//        nocase ascii wide
        $c3 = /mshta(\.exe)?\s+["']?(https?:\/\/|javascript:|vbscript:)/          nocase ascii wide
        $c4 = /regsvr32(\.exe)?\s+[^\r\n]{0,40}\/i:\s*https?:\/\/[^\r\n]{0,120}scrobj/ nocase ascii wide
    condition:
        any of them
}

rule PowerShell_Defender_Tampering
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Turns off Microsoft Defender or excludes paths from scanning"
        severity    = "high"
        mitre       = "T1562.001"
    strings:
        $mp1 = "Set-MpPreference" nocase ascii wide
        $mp2 = "Add-MpPreference" nocase ascii wide
        $d1  = "DisableRealtimeMonitoring" nocase ascii wide
        $d2  = "DisableBehaviorMonitoring" nocase ascii wide
        $d3  = "DisableIOAVProtection"     nocase ascii wide
        $d4  = "DisableScriptScanning"     nocase ascii wide
        $x1  = "ExclusionPath"             nocase ascii wide
        $x2  = "ExclusionProcess"          nocase ascii wide
        $x3  = "ExclusionExtension"        nocase ascii wide
        $reg = "\\Windows Defender\\DisableAntiSpyware" nocase ascii wide
    condition:
        ($mp1 and any of ($d*)) or ($mp2 and any of ($x*)) or $reg
}
