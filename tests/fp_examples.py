"""M29 and M32: the documented local examples for the two false-positive fixes.

Every example is short, inert text written for these tests: no program, no
executable script, no real sample. HARMLESS files describe or quote ransomware
techniques the way advisories, articles, help pages and admin scripts do;
HARMFUL files carry the structure the rules are for (ransom notes, droppers).
These are synthetic: they show that the conditions behave as intended on the
cases named, not how the rules perform on real mail or real malware.
"""

ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"
WALLET = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

HARMLESS = [
    # M29, check 21: a page quoting the command in prose
    ("article.html", b"<html><body><h1>How ransomware stops recovery</h1><p>Attackers often run "
                     b"<code>vssadmin delete shadows /all /quiet</code> before encrypting, so "
                     b"keep offline backups.</p></body></html>"),
    ("advisory-wbadmin.txt", b"Detection note: alert on 'wbadmin delete catalog' and on "
                             b"'wmic shadowcopy delete' in process logs.\r\n"),
    ("hardening.md", b"# Recovery hardening\n\nWatch for `vssadmin resize shadowstorage /for=C: "
                     b"/on=C: /maxsize=401MB` in command lines.\n"),
    ("list_shadows.ps1", b"# list existing restore points for the backup report\r\n"
                         b"Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate\r\n"),
    # M32, check 24: an advisory describing a ransom demand
    ("advisory.html", b"<html><body><h1>Ransomware advisory</h1><p>Victims report that all your "
                      b"files are encrypted messages appear and that the gang demands payment in "
                      b"bitcoin within 48 hours, threatening that your data will be lost forever. "
                      b"Do not pay the ransom; restore your files from backups.</p></body></html>"),
    ("helpdesk-notice.txt", b"If a message says your files are encrypted and demands a ransom "
                            b"payment within 24 hours, do not pay: your data can be restored. "
                            b"Contact the helpdesk and decrypt nothing yourself.\r\n"),
    ("payroll-notice.txt", b"Payroll update: your data is encrypted in transit. The payroll "
                           b"deadline is Friday; payload sizes are listed in the decrypt tool "
                           b"manual, or your files will be lost forever from the queue.\r\n"),
]

HARMFUL = [
    # ransom notes, as they are left on disk
    ("README_DECRYPT.txt", (f"YOUR FILES ARE ENCRYPTED. Send the payment in bitcoin to {WALLET} "
                            "within 48 hours or your files are lost forever. To decrypt, "
                            "contact us.\r\n").encode()),
    ("HOW_TO_RECOVER.html", (f"<html><body><p>All your files are encrypted. Your personal ID: "
                             f"7F3A-11C2. Visit {ONION} to pay the ransom within 24 hours; after "
                             f"the deadline your data is deleted. Decrypt one file for free."
                             f"</p></body></html>").encode()),
    ("note-no-wallet.txt", b"Your files are encrypted. Send the payment in bitcoin within 48 "
                           b"hours or the key is lost forever. Decrypt tool on request.\r\n"),
    # droppers that carry the T1490 commands
    ("wipe.bat", b"@echo off\r\nvssadmin delete shadows /all /quiet\r\nwbadmin delete catalog "
                 b"-quiet\r\n"),
    ("dropper.hta", b'<hta:application/><script>new ActiveXObject("WScript.Shell").Run('
                    b'"cmd /c vssadmin delete shadows /all /quiet", 0)</script>'),
    ("dropper.html", b'<html><script>var s = new ActiveXObject("WScript.Shell"); s.Run("cmd /c '
                     b'vssadmin delete shadows /all /quiet", 0);</script></html>'),
    ("wmi_delete.ps1", b"Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }\r\n"),
]
