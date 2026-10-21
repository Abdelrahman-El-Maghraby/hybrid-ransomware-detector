/*
    ransomware_behaviour.yar
    Original rules (4.4.0-beta.2) for what ransomware does around the encryption
    itself: stopping databases, backup agents and Office so their files can be
    opened, booting into Safe Mode where security tools do not start, clearing
    event logs, and the encryptor's own fingerprint (a long list of target file
    extensions next to file-encryption APIs). Written from scratch; thresholds
    were set against a benign corpus of system binaries and scripts.
*/

rule Ransomware_Stops_Services_And_Processes
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Stops database, backup and Office processes in bulk before encryption"
        severity    = "high"
        mitre       = "T1489"
    strings:
        $k1 = "taskkill"         nocase ascii wide
        $k2 = "net stop"         nocase ascii wide
        $k3 = "sc stop"          nocase ascii wide
        $k4 = "Stop-Service"     nocase ascii wide
        $k5 = "Stop-Process"     nocase ascii wide
        $t1 = "sqlservr"         nocase ascii wide
        $t2 = "sqlwriter"        nocase ascii wide
        $t3 = "oracle.exe"       nocase ascii wide
        $t4 = "mysqld"           nocase ascii wide
        $t5 = "veeam"            nocase ascii wide
        $t6 = "backupexec"       nocase ascii wide
        $t7 = "msexchange"       nocase ascii wide
        $t8 = "winword.exe"      nocase ascii wide
        $t9 = "excel.exe"        nocase ascii wide
        $t10 = "outlook.exe"     nocase ascii wide
        $t11 = "thunderbird.exe" nocase ascii wide
        $t12 = "vss"             nocase ascii wide fullword
        $t13 = "sophos"          nocase ascii wide
        $t14 = "acronis"         nocase ascii wide
    condition:
        any of ($k*) and 5 of ($t*)
}

rule Ransomware_Safe_Mode_Boot
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Forces a reboot into Safe Mode, where most security tools do not run"
        severity    = "critical"
        mitre       = "T1562.009"
    strings:
        $b1 = /bcdedit(\.exe)?\s+\/set\s+\{(default|current)\}\s+safeboot\s+(minimal|network)/ nocase ascii wide
        $b2 = "\\SafeBoot\\Minimal\\" nocase ascii wide
        $b3 = "\\SafeBoot\\Network\\" nocase ascii wide
        $r  = "shutdown"              nocase ascii wide
    condition:
        $b1 or (($b2 or $b3) and $r and filesize < 5MB)
}

rule Event_Log_Clearing
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Clears Windows event logs to remove traces"
        severity    = "medium"
        mitre       = "T1070.001"
    strings:
        $w1 = /wevtutil(\.exe)?\s+(cl|clear-log)\s+(system|security|application)/ nocase ascii wide
        $w2 = "Clear-EventLog"    nocase ascii wide
        $w3 = "Remove-EventLog"   nocase ascii wide
        $w4 = /for \/f[^\r\n]{0,80}wevtutil[^\r\n]{0,40}\bel\b/ nocase ascii
    condition:
        any of them
}

rule Ransomware_Encryptor_Target_Extensions
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Executable with a long list of user-data extensions next to file-encryption APIs"
        severity    = "high"
        mitre       = "T1486"
    strings:
        $x1  = ".docx"  nocase ascii wide
        $x2  = ".xlsx"  nocase ascii wide
        $x3  = ".pptx"  nocase ascii wide
        $x4  = ".pdf"   nocase ascii wide
        $x5  = ".jpg"   nocase ascii wide
        $x6  = ".sql"   nocase ascii wide
        $x7  = ".mdb"   nocase ascii wide
        $x8  = ".pst"   nocase ascii wide
        $x9  = ".vmdk"  nocase ascii wide
        $x10 = ".vhdx"  nocase ascii wide
        $x11 = ".bak"   nocase ascii wide
        $x12 = ".accdb" nocase ascii wide
        $x13 = ".odt"   nocase ascii wide
        $x14 = ".psd"   nocase ascii wide
        $x15 = ".dwg"   nocase ascii wide
        $x16 = ".7z"    nocase ascii wide
        $x17 = ".kdbx"  nocase ascii wide
        $x18 = ".sqlite" nocase ascii wide
        $c1  = "CryptEncrypt"      ascii wide
        $c2  = "BCryptEncrypt"     ascii wide
        $c3  = "CryptGenRandom"    ascii wide
        $c4  = "BCryptGenRandom"   ascii wide
        $c5  = "CryptImportKey"    ascii wide
        $c6  = "RtlGenRandom"      ascii wide
        $c7  = "SystemFunction036" ascii wide
        $f1  = "FindFirstFile"     ascii wide
        $f2  = "FindNextFile"      ascii wide
        $f3  = "MoveFileEx"        ascii wide
        $n1  = "decrypt"           nocase ascii wide
        $n2  = ".onion"            nocase ascii wide
        $n3  = "readme"            nocase ascii wide
        $n4  = "vssadmin"          nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB
        and 12 of ($x*) and 2 of ($c*) and 2 of ($f*) and 2 of ($n*)
}

rule Ransom_Note_Tor_Negotiation
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Ransom note pointing to a Tor negotiation site"
        severity    = "high"
        mitre       = "T1486"
    strings:
        $onion = /[a-z2-7]{56}\.onion/ nocase ascii wide
        $tor1  = "Tor Browser"        nocase ascii wide
        $tor2  = "torproject.org"     nocase ascii wide
        $n1    = "decrypt"            nocase ascii wide
        $n2    = "encrypted"          nocase ascii wide
        $n3    = "your personal ID"   nocase ascii wide
        $n4    = "your ID"            nocase ascii wide
        $n5    = "leak"               nocase ascii wide
        $n6    = "negotiat"           nocase ascii wide
    condition:
        filesize < 1MB and $onion and any of ($tor*) and 2 of ($n*)
}
