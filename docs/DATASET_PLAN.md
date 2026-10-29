# Evaluation dataset plan

For re-collecting the labelled dataset that `tools/evaluate.py` measures. Part 1
lists what the scanner inspects, taken from the code (v4.7.0). Part 2 is the
collection plan. Collect, unpack and run everything **inside the isolated analysis
VM**; nothing here downloads anything. Only hashes, labels and results leave the
VM.

## Part 1: what the scanner inspects, by layer

**Supported extensions** (`engine/config.py`, `SUPPORTED_EXTENSIONS`; folder scans
and `tools/evaluate.py` pick files by these):
`.pdf .docx .doc .docm .dotm .xlsx .xlsm .xls .pptx .pptm .ppt .rtf .zip .7z .rar
.iso .img .pkg .mpkg .dmg .eml .msg .html .htm .svg .js .jse .vbs .vbe .wsf .hta
.ps1 .bat .cmd .one .chm .msi .xll .exe .dll .scr .cpl .sys .jpg .jpeg .png .gif
.bmp .webp`. Images are left out of folder scans by default but are scanned when
uploaded, inside archives and e-mails, and by `evaluate.py`.

**Every file** goes through `hashes`, `allowlist`, `local-db` (MD5 list), `fuzzy`
(TLSH / ssdeep), `yara`, `integrity` and `ml` (except archives and mail), plus
`llm`, `virustotal` and `sandbox` when configured.

| Layer | Applies to (extension) | Recognised by (format) | Looks for |
|---|---|---|---|
| integrity | every file; expected formats for documents, archives and images | magic bytes: pdf, rtf, zip (OOXML), ole, 7z, rar, jpeg / png / gif / bmp / webp; executables pe, elf, macho, lnk, shebang script | a disguised executable (format does not match the extension), payloads appended after an image, ransom extensions (`.locked`, `.lockbit`, `.djvu`, ...), encrypted content, legitimate vaults (kdbx, pgp, age, LUKS, openssl enc) |
| pe | any extension | `MZ` + `PE\0\0` header | sections, entropy, packers, imports incl. delay-loaded (injection chain, encrypt + walk + write), recovery-inhibition commands, overlays, signature presence |
| elf | any extension | `\x7fELF` | sections, packing, behaviour categories |
| macro | `.doc .docm .dot .dotm .xls .xlsm .xlsb .xlm .xltm .xlam .ppt .pptm .potm .ppsm .ppam .docx .xlsx .pptx` | OLE / OOXML (oletools) | VBA auto-exec and suspicious keywords, VBA stomping, Excel 4.0 (XLM) macros, IOCs |
| relationships | OOXML (`.docx .docm .dotx .dotm .xlsx .xlsm .xltx .xltm .pptx .pptm ...`), `.rtf` (and RTF saved as `.doc` / `.dot`) | OOXML `.rels`, RTF | remote templates, external OLE links (CVE-2017-0199), Follina-style references |
| prompt-guard | OOXML, `.xls`, `.pdf`, web files (text) | text extraction | hidden content and prompt-injection text |
| qr | images, OOXML (embedded media), `.pdf` | image decoding (zbar) | QR codes, their URLs (shorteners, credential phishing) |
| embedded | content-detected: OneNote, CHM, MSI, encrypted Office, XLL; OLE objects in `.doc .xls .ppt` | magic / OLE CLSID / `xlAutoOpen` export | scripts and programs embedded in OneNote / CHM / MSI, encrypted documents, Excel add-ins |
| script | `.js .jse .vbs .vbe .wsf .wsh .hta .ps1 .psm1 .bat .cmd` | extension | download, execution, obfuscation and recovery-inhibition markers |
| web | `.html .htm .shtml .xhtml .hta .svg` | extension | HTML / SVG smuggling, embedded payloads, phishing forms |
| archive | `.zip`, `.7z`, `.rar`, `.iso .img`, `.pkg .mpkg`, `.dmg` | extension **and** magic must agree | members (scanned by every layer, nested to the limits), encrypted members (tries passwords from the delivery mail), zip slip, zip bombs, executables in archives |
| mail | `.eml`, `.msg` (Outlook OLE or RFC 822) | MIME / OLE | SPF / DKIM / DMARC, spoofing, risky attachments (scanned as members), forwarded items |
| emulation | `.js .jse` (off by default) | box-js | URLs fetched, files written, commands run |

Not scanned by extension (skipped by folder scans and by `evaluate.py`), although
some are recognised by content when they arrive inside an archive, an e-mail or an
API upload: `.lnk`, `.jar`, `.sh`, `.so`, `.elf`, `.xlsb`, `.vhd(x)`, `.url`,
`.tar`, `.gz`, `.cab`, extension-less files.

## Part 2: collection plan

Suggested `file_type` values follow MalwareBazaar's file-type naming; check the
exact value with the API (`query=get_file_type`) before bulk queries. Tags are
free-form on MalwareBazaar; families are its `signature` field
(`query=get_siginfo`). Counts are a target, not a minimum; see "How many" below.

| File type | Malicious samples (MalwareBazaar `file_type` / tags / families) | Benign samples (public source) | Count (mal / benign) |
|---|---|---|---|
| **Windows executable (PE)**<br>`.exe` | `file_type`: exe<br>tags: ransomware, loader, stealer, packed, UPX<br>families: LockBit, Conti, BlackCat (ALPHV), Akira, Phobos, STOP/Djvu, Babuk, Royal, Medusa; loaders/RATs: GuLoader, AgentTesla, Formbook, Remcos, AsyncRAT, Lumma | Open-source Windows releases (GitHub releases, Chocolatey packages, PyPI/npm Windows binaries); programs from a clean Windows VM (keep in the VM)<br>*Main PE layer type. Keep any one family under about 15 % of the malicious set.* | 400 / 800 |
| **Windows DLL (PE)**<br>`.dll` | `file_type`: dll<br>tags: loader, dll-sideloading, ransomware<br>families: QakBot, IcedID, Bumblebee, DarkGate, Latrodectus, PikaBot, Emotet (DLL era) | DLLs from the same open-source releases; System32 of a clean Windows VM | 150 / 400 |
| **Screen saver / Control Panel item (PE)**<br>`.scr, .cpl` | `file_type`: scr, cpl<br>tags: scr, cpl, phishing<br>families: AgentTesla, Formbook, Remcos (often shipped as .scr) | System32 *.scr / *.cpl of a clean Windows VM<br>*Rare: 30 of each is enough.* | 60 / 60 |
| **Windows driver (PE)**<br>`.sys` | `file_type`: sys<br>tags: driver, BYOVD, rootkit<br>families: vulnerable drivers used to kill EDR (BYOVD), rootkits | System32\drivers of a clean Windows VM | 40 / 100 |
| **Linux executable (ELF)**<br>`.elf (content-detected)` | `file_type`: elf<br>tags: elf, ransomware, ESXi, botnet, Mirai<br>families: LockBit Linux/ESXi, Royal, Akira ESXi, BlackCat ESXi, Babuk ESXi, RansomEXX; Mirai, Gafgyt, XorDDoS, Tsunami | Binaries from Debian/Ubuntu packages and the Alpine minirootfs, BusyBox<br>*Measured by content: evaluate.py counts .elf samples.* | 200 / 400 |
| **Legacy Office (OLE)**<br>`.doc, .xls, .ppt` | `file_type`: doc, xls, ppt<br>tags: macro, XLM, VBA, CVE-2017-11882, Emotet<br>families: Emotet, Dridex, QakBot, IcedID (macro waves); Equation Editor exploits (CVE-2017-11882) | GovDocs1 (Digital Corpora), NapierOne<br>*Macro, embedded-object and integrity layers.* | 150 / 300 |
| **Office Open XML**<br>`.docx, .xlsx, .pptx` | `file_type`: docx, xlsx, pptx<br>tags: remote template, CVE-2017-0199, Follina, CVE-2022-30190, QR, phishing<br>families: remote-template droppers, Follina (CVE-2022-30190) documents, QR-code phishing documents | GovDocs1, NapierOne, Common Crawl document corpora<br>*Relationship, prompt-guard and QR layers.* | 150 / 400 |
| **Macro-enabled Office**<br>`.docm, .dotm, .xlsm, .pptm` | `file_type`: docm, xlsm, pptm, dotm<br>tags: macro, VBA, AutoOpen<br>families: Emotet, QakBot, Dridex, Ursnif, Hancitor | Hard to find benign: vendor templates, VBA projects on GitHub, your own macro workbooks<br>*Benign macro files are the main false-positive risk: collect as many as possible.* | 150 / 150 |
| **Rich Text Format**<br>`.rtf (incl. RTF saved as .doc)` | `file_type`: rtf<br>tags: CVE-2017-11882, CVE-2017-0199, OLE, rtf<br>families: Formbook / AgentTesla loaders via Equation Editor exploits, remote-OLE RTF | GovDocs1, LibreOffice and Apache Tika test corpora<br>*Relationship and embedded layers.* | 100 / 150 |
| **PDF**<br>`.pdf` | `file_type`: pdf<br>tags: phishing, QR, js, pdf<br>families: phishing lures (credential and QR phishing), JavaScript PDFs, PDFs that drop or link payloads | GovDocs1, arXiv papers, Common Crawl PDF corpus (Digital Corpora CC-MAIN PDF set), SEC EDGAR filings<br>*Most common benign type in real traffic: keep the benign set large.* | 300 / 1000 |
| **ZIP archive**<br>`.zip` | `file_type`: zip<br>tags: zip, password protected, phishing<br>families: delivery archives holding loaders, scripts or LNK files | Archives you build from the benign documents; software archives from GitHub releases<br>*Do NOT count MalwareBazaar's own download wrapper (zip, password 'infected'): extract it in the VM first.* | 100 / 200 |
| **7-Zip / RAR archive**<br>`.7z, .rar` | `file_type`: 7z, rar<br>tags: rar, 7z, password protected<br>families: same delivery families, often password-protected with the password in the e-mail | Archives you build (7-Zip, RAR) from benign files; open-source releases shipped as .7z<br>*Include RAR5 and RAR4, encrypted and not.* | 100 / 100 |
| **Disk image**<br>`.iso, .img` | `file_type`: iso, img<br>tags: iso, img, HTML smuggling<br>families: QakBot, IcedID, Bumblebee, BazarLoader (2022 ISO/LNK wave) | Small Linux netinstall ISOs, FreeDOS images<br>*Large images: keep under the archive size limits or expect partial scans.* | 50 / 50 |
| **macOS installer**<br>`.pkg, .mpkg, .dmg` | `file_type`: pkg, dmg<br>tags: macOS, stealer, dmg<br>families: Atomic Stealer (AMOS), Cuckoo, Poseidon, Banshee, Cthulhu | Open-source macOS apps from GitHub releases (DMG / PKG) | 50 / 50 |
| **E-mail**<br>`.eml, .msg` | `file_type`: eml, msg (few on MalwareBazaar)<br>tags: phishing, malspam<br>families: malspam carrying any of the payload families above | SpamAssassin public corpus (ham), Enron e-mail dataset; Outlook .msg test files of open-source MSG parsers<br>*Malicious mail: the public phishing_pot repository (real phishing .eml) and malspam on MalwareBazaar. About 30 of each count is .msg.* | 180 / 330 |
| **HTML**<br>`.html, .htm` | `file_type`: html, htm<br>tags: HTML smuggling, phishing, html<br>families: HTML smuggling droppers (QakBot, Duck), credential-phishing pages | Common Crawl pages, saved web pages | 150 / 500 |
| **SVG image**<br>`.svg` | `file_type`: svg<br>tags: svg, smuggling, phishing<br>families: SVG smuggling and phishing attachments | Wikimedia Commons, open icon sets (Material Icons, Font Awesome)<br>*Web layer.* | 50 / 200 |
| **JScript / encoded JScript**<br>`.js, .jse` | `file_type`: js, jse<br>tags: js, WSH, Gootloader, JScript<br>families: Gootloader, WSHRAT, Vjw0rm, STRRAT droppers | npm packages (Node.js, not WSH - still useful benign JavaScript), Windows Script Host samples<br>*Script layer (and emulation when enabled).* | 150 / 300 |
| **VBScript / encoded VBScript**<br>`.vbs, .vbe` | `file_type`: vbs, vbe<br>tags: vbs, VBScript, loader<br>families: AsyncRAT and Remcos VBS loaders, DarkGate | Sysadmin VBScript collections on GitHub | 100 / 150 |
| **PowerShell**<br>`.ps1` | `file_type`: ps1<br>tags: PowerShell, loader, obfuscated<br>families: PowerShell loaders and stagers (e.g. Lumma, AsyncRAT droppers), Invoke-Obfuscation output | PowerShell Gallery modules, GitHub admin scripts | 120 / 300 |
| **Batch**<br>`.bat, .cmd` | `file_type`: bat, cmd<br>tags: bat, cmd, batch<br>families: batch droppers, BatCloak/BatchShield-obfuscated loaders, ransomware helper scripts (vssadmin, bcdedit) | Build and admin scripts from open-source repositories<br>*Recovery-inhibition rules apply.* | 80 / 200 |
| **Windows Script File / HTA**<br>`.wsf, .hta` | `file_type`: wsf, hta<br>tags: hta, wsf, mshta<br>families: HTA droppers, Kimsuky / APT HTA lures | Windows SDK and sysadmin samples<br>*Rare: 30 of each is enough.* | 60 / 50 |
| **OneNote**<br>`.one` | `file_type`: one<br>tags: OneNote, one<br>families: AsyncRAT, QakBot, IcedID (early-2023 OneNote wave) | Notebooks you create yourself; Microsoft templates<br>*Embedded layer (content-detected).* | 50 / 30 |
| **Compiled HTML Help**<br>`.chm` | `file_type`: chm<br>tags: chm<br>families: APT37 and other CHM lures | Help files shipped with software (for example 7-Zip, older Python for Windows) | 30 / 50 |
| **Windows Installer**<br>`.msi` | `file_type`: msi<br>tags: msi, DarkGate, Matanbuchus<br>families: DarkGate, Matanbuchus, fake-installer campaigns | Open-source MSI installers (7-Zip, Node.js, PowerShell, Git for Windows)<br>*Embedded layer (CLSID-detected).* | 50 / 100 |
| **Excel add-in (XLL)**<br>`.xll` | `file_type`: xll<br>tags: xll, Excel-DNA<br>families: AgentTesla, Formbook and Dridex XLL droppers | Excel-DNA sample add-ins on GitHub<br>*Rare on both sides.* | 30 / 20 |
| **Images (QR, polyglots)**<br>`.jpg, .jpeg, .png, .gif, .bmp, .webp` | `file_type`: jpg, png, gif<br>tags: QR, steganography, polyglot<br>families: QR-phishing images; images with an appended executable | Open Images / Wikimedia Commons photos; QR codes you generate for benign URLs<br>*Not in folder scans by default, but evaluate.py includes them. Generated QR images with test URLs can stand in for malicious QR samples.* | 30 / 500 |
| **Ransomware artefacts (optional)**<br>`encrypted files, ransom notes (.locked, .lockbit, .djvu, ...)` | `file_type`: -<br>tags: -<br>families: output of real ransomware runs | NapierOne (includes ransomware-encrypted copies of benign files)<br>*Tests the integrity layer's encrypted-file and ransom-extension checks; not executable.* | 50 / 50 |
| **Total** | | | **3130 / 6940** |

## Before you collect

1. **Files recognised by content.** `tools/evaluate.py` measures a file when its
   extension is supported **or** its content is a format the engine analyses
   whatever the name: PE, ELF, Windows shortcut (LNK), OneNote, CHM, MSI. So
   `<sha256>.elf`, `.lnk` and extension-less samples are measured; the summary lists
   them ("Recognised by content"). `.sh`, `.jar` and `.xlsb` still count as
   unsupported (the engine has no layer for them by content).
2. **Unwrap MalwareBazaar downloads.** Each sample arrives in a ZIP with the
   password `infected`. Extract it in the VM; do not put the wrapper ZIPs in the
   malicious folder, or every "zip" result is the same password-protected wrapper.
3. **Labels file.** `--labels` expects `sha256,type,family` (SHA-256 in column 1,
   family in column 3). MalwareBazaar's CSV export has the SHA-256 in column 2:
   convert it.
4. **Folder layout.** `--malicious` and `--benign` take folders; the first
   sub-folder name becomes the "group" in the report, so one folder per file type
   (for example `malicious/pdf/`, `benign/pdf/`) gives per-type tables directly.
5. **No duplicates across labels.** The tool counts each SHA-256 once and drops
   files labelled both malicious and benign; check the summary's duplicate line.

## How many, and how to split

* With **n** samples, a detection rate near 90 % is known to about
  ±1.96·√(0.09/n): n = 30 gives ±11 points, n = 100 ±6, n = 400 ±3. The rarer
  types (30 to 60) give a rough rate only; the common delivery types (PE, PDF,
  Office, HTML, scripts) get 100 to 400.
* **False positives matter more than misses** in real traffic, so the benign
  sets are larger (about 2:1 overall, more for PDF and Office). A 0.5 % false-alarm
  rate needs about 1,000 benign files of a type to be seen at all.
* **Families:** at least 5 per type where they exist, and no family above about
  15 % of a type, so one family does not decide the rate.
* **Split:** measure with `tools/evaluate.py --split test` after any weight
  calibration (`tools/calibrate_weights.py --split calibration`): the split is
  grouped by family, so the rates are on families the weights never saw.
* **Recency:** prefer samples from the last 12 to 18 months for delivery types
  (lures change), but keep some older ones for regression (macro era, ISO wave).

Totals of the table: about 3,100 malicious and 6,900 benign files.
