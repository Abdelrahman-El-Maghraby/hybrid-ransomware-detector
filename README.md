# 🛡️ Hybrid Ransomware Detection System

*Desktop app name: **Aegis Sentinel**.*

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/version-4.8.0-brightgreen)
[![tests](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/actions/workflows/tests.yml/badge.svg)](https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/actions/workflows/tests.yml)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Arch](https://img.shields.io/badge/Arch-x86__64%20%7C%20ARM64-lightgrey)

A multi-layered scanner that inspects **PDF, Microsoft Office (Word / Excel / PowerPoint), RTF documents, archives (ZIP, 7z, RAR, ISO), scripts, web pages and e-mails (.eml / Outlook .msg, or straight from an IMAP mailbox)** for ransomware and other malicious indicators. It fuses **twenty detection layers** through a **transparent weighted scoring matrix** that produces a 0–100 risk score, a verdict band, and a report showing *why* each file scored what it did. Around the scanner sit two host-side protections: **ransomware canary tripwires** and an **AES-256-GCM encrypted quarantine vault**.

Runs on **Windows, macOS, and Linux** (x86_64 and ARM64), from the command line or a desktop GUI, with optional autostart at login.

Originally built as my B.Sc. graduation project as a three-layer scanner, then grown release by release: structural detection and the scoring matrix (v3); file integrity, prompt-injection defence, external links, archives, canaries and quarantine (v4); e-mail and ML (4.1); an explicit pipeline (4.2); RAR and Outlook OLE objects (4.3); scripts, QR codes, ELF, an optional sandbox and signed CI releases (4.4); mailbox scanning, canary response actions and script emulation (4.5); Windows program analysis, process containment, typed internals and production operations (4.6); a hardened Docker deployment, scan completeness and provenance (4.7). It is intended for **defensive and educational use**: analysing suspicious documents, not creating malware.

![Aegis Sentinel dashboard](docs/screenshot-v4-dashboard.png)

---

## 📖 Table of Contents

- [🆕 What's new in 4.7](#-whats-new-in-47)
- [🆕 What's new in 4.6](#-whats-new-in-46)
- [🆕 What's new in 4.5](#-whats-new-in-45)
- [🗂️ Earlier releases](#️-earlier-releases)
- [🧩 Why "hybrid"?](#-why-hybrid)
- [🔬 Detection layers](#-detection-layers)
- [⚖️ Weighted scoring matrix](#️-weighted-scoring-matrix)
- [🛡️ Protection features](#️-protection-features)
- [📦 Requirements](#-requirements)
- [🚀 Installation](#-installation)
- [📦 Standalone executables](#-standalone-executables)
- [🔑 Configuration](#-configuration)
- [💻 Usage](#-usage)
- [🪟 Graphical interface](#-graphical-interface)
- [🧪 Testing](#-testing)
- [📂 Project structure](#-project-structure)
- [🏗️ Engineering](#️-engineering)
- [🌐 Cross-platform & architecture notes](#-cross-platform--architecture-notes)
- [⚠️ Limitations](#️-limitations)
- [🧭 Roadmap](#-roadmap)
- [🚨 Disclaimer](#-disclaimer)
- [👤 Author](#-author)

---

## 🆕 What's new in 4.8

- **Desktop folder monitoring:** new, modified and renamed files are scanned
  after settling, in isolated workers, with bounded queues and own-output exclusions.
- **Monitoring** and **Alerts & cloud** GUI pages: live monitoring results,
  delivery status, TLS e-mail test, optional S3-compatible report/log upload test,
  and quarantine key export/import on **Protection**.
- **Persistent alert outbox:** webhook and TLS e-mail delivery retry after failures;
  canary trips and verdicts share the delivery path. Docker sends mail through intel.
- **Optional desktop cloud storage:** off by default; an allowlisted redacted view
  of reports and structured log events. Bucket retention is operator-controlled.
- **Fail-closed isolation** for every scan, schema 1.4 isolation provenance,
  event-driven worker dispatch, confined rule-pack installs, streamed DMG/CHM
  members and hash-verified dependency installs. Weights and thresholds unchanged.

See [operations](docs/OPERATIONS.md), [data policy](docs/DATA_POLICY.md) and
[upgrade notes](CHANGELOG.md). CLI exit code **3** means isolated workers could
not start and files were not scanned. API callers receive 503 in this case.

## 🆕 What's new in 4.7

The on-prem production edition (`docs/RELEASE_SCOPE.md`).

- **A hardened Docker deployment** ([deployment](docs/DEPLOYMENT.md), [operations](docs/OPERATIONS.md)). The service that opens files runs with **no network** and without any API key. A separate intel service is the only part that reaches VirusTotal, an LLM or a sandbox, through fixed operations and to allowlisted destinations only. TLS terminates at a proxy. Every container runs non-root, with a read-only file system and no capabilities.
- **Never a silent "Clean".** Every result says whether the scan was `complete`, `partial`, `locked`, `unsupported` or `failed`, and lists what was not inspected and why. That includes damaged documents, archives that would not open, parser errors and layers that are not installed.
- **Provenance in every result:** the rules version and hash, the registry and schema versions, which layers ran, and **what was sent outside** for that file.
- **Security fixes:** API login throttling; secrets in the OS keyring or Docker secrets; a cache of external answers that a compromised parser cannot poison; signed rule packs that cannot be replayed, with signed rollback and recovery from a compromised key; GitHub Actions pinned to commits.
- **Operations:** `/ready`, start-up checks of required layers, backup and restore scripts, runbooks, a data policy, and per-artifact SBOMs. Releases include the server images for offline install.
- **Desktop:** a Diagnostics panel, Windows alerts, and undo of a quarantine from the result view.

## 🆕 What's new in 4.6

- **Windows programs are analysed on their own.** A new layer reads `.exe` / `.dll` / `.sys` structure without running it and without extra libraries:
  - per-section entropy, packer section names (UPX, VMProtect, Themida …) and writable+executable sections;
  - the import table by name: the process-injection chain (alloc + write + thread in another process), encryption plus directory walking plus file writing in an unsigned program, and imports resolved only at run time;
  - shadow-copy and backup deletion commands (`vssadmin delete shadows /all`, `wbadmin delete catalog -quiet`, `bcdedit … recoveryenabled no`), in ASCII or UTF-16. The help text of those Windows tools does not match;
  - programs appended to programs, near-random appended data, and whether an Authenticode signature is present (not verified).

  Folder scans now include `.exe`, `.dll`, `.scr`, `.cpl` and `.sys`. On 3,713 benign files (including 401 real Windows binaries from PyPI and npm), it added no High or Critical result.
- **Canaries contain, not only alert.** On a trip, `CANARY_RESPONSE=stop_writers` suspends the processes that have files open for writing in the canary folders, together with their child processes (`/proc` on Linux, `lsof` on macOS, the Restart Manager on Windows). `lock_folders` removes write access to the folders you name, and `controlled_folder_access` switches on Defender's own blocker. System, indexing and antivirus processes, other users' processes and this tool itself are never touched. `--resume-pid` and `--unlock-folders` undo the containment after a false alarm. This is damage mitigation, not kernel-level prevention: the [limitations](#️-limitations) say what it cannot catch.
- **Memory limits on every OS.** Scan workers are capped on Windows (Job Object) and macOS (a watchdog in the parent process), as they already were on Linux.
- **Production operations:**
  - start-up validation of every setting: a typo stops the program with a clear message instead of silently becoming a default;
  - `LOG_FORMAT=json` structured logs;
  - `/metrics` in JSON or Prometheus format;
  - API rate limiting, an upload limit enforced before parsing, and a limit on concurrent scans;
  - a [deployment guide](docs/DEPLOYMENT.md) with nginx and Caddy TLS setups.
- **Internals:**
  - typed signals between the layers and the scorer, checked by mypy;
  - one scorer function per layer;
  - a configuration module with no import-time side effects;
  - every function under cyclomatic complexity 20, enforced in CI;
  - 858 tests, 91 % coverage.

## 🆕 What's new in 4.5

- **Scan the mailbox itself (IMAP).** `python RansomwareScanner.py --scan-imap` reads new messages from `IMAP_FOLDER` with their full transport headers, so SPF / DKIM / DMARC and spoofing checks work even when saved copies would have lost them. Read-only (the folder is opened with EXAMINE and bodies fetched with `BODY.PEEK[]`, so nothing is marked as read), TLS only with certificate checks, each message scanned in an isolated worker, nothing scanned twice (last UID per folder, reset when the server's UIDVALIDITY changes), bounded by `IMAP_MAX_MESSAGES` and `IMAP_MAX_MB`. With `--background` and `IMAP_CHECK_MINUTES`, the mailbox is checked on a schedule. Use an app password.
- **Canary response actions.** A tripwire can now act, not only alert: `CANARY_RESPONSE=network_off` disables the network adapters (PowerShell `Disable-NetAdapter`, `nmcli networking off`, `networksetup`), and `script` runs your own response script with the alert as JSON on stdin. Off by default; the script must be an absolute path only its owner can change, and every action is time-limited and logged in the alert file. On Windows, also turn on **Controlled Folder Access**: it blocks unknown programs from writing to protected folders (since 4.6 the `controlled_folder_access` action can switch it on when a canary trips).
- **JavaScript emulation (optional).** With `EMULATION_ENABLED=1` and [box-js](https://github.com/CapacitorSet/box-js) installed, `.js` / `.jse` files are run against fake WScript / ActiveX objects and what they tried to do is recorded: URLs fetched (including ones built at run time), files written and commands run. A fetch plus a run or a dropped program scores 65 (`emulated_dropper`, dynamic category). It executes the attacker's script in a Node sandbox, so enable it inside an analysis VM only.
- **More formats closed:** Equation Editor 3.0 objects (CVE-2017-11882) in RTF and legacy Office files, hidden / very hidden sheets in `.xls`, LUKS and `openssl enc` files recognised as legitimate encrypted containers.
- **Security hardening:** helper programs are never taken from the current directory, ML models other users could change are refused, bandit runs in CI, and type checking covers every detector.

---

## 🗂️ Earlier releases

The full history is in the [changelog](CHANGELOG.md).

<details>
<summary>4.4, 4.3, 4.2, 4.1 and 4.0</summary>

### 4.4

> **Measured so far:** on 3,312 benign files, 0.8% High/Critical (25 of the 27 are installer scripts that really download and silently run a program) and about 6x faster scans than the first 4.4 build. **Not measured yet:** the detection rate on real malware samples (`tools/evaluate.py`). See the [changelog](CHANGELOG.md) for details.

- **HTML and SVG attachments.** HTML smuggling (a payload hidden in the page as base64 and rebuilt in the browser with `Blob` + an object URL / download link) is detected, and the hidden payload is decoded and scanned through the whole pipeline. Also flagged: SVG images with active content (scripts, event handlers, embedded HTML), password forms posting to an external host, redirects and script obfuscation. Nothing is executed or fetched.
- **Images.** A payload appended after the end of a PNG, JPEG, GIF, BMP or WEBP image, and an executable renamed to an image extension. Pictures are supported but not part of folder scans by default; inside archives and e-mails they are always checked.
- **macOS installers.** `.pkg` packages are read in Python (install scripts and payload unpacked); `.dmg` disk images are opened through 7-Zip when it is installed. An installer's programs and scripts are listed and each one is scanned, but they are not scored just for being there, and a large app image is reported as not unpacked rather than as a decompression bomb.
- Image, SVG and installer handling are covered by 62 tests.
- **QR codes.** Phishing links hidden in QR codes ("quishing") in images, PDF pages, Office documents and e-mail attachments are decoded and judged: bare IP addresses, punycode, `user@host` tricks, URL shorteners and script schemes are suspicious on their own; plain HTTP, throw-away TLDs and lure words count only in pairs. Links are defanged in reports. Decoding needs `pip install pyzbar` plus the zbar library (`brew install zbar`, `sudo apt-get install libzbar0`; the Windows wheel includes it) or `opencv-python-headless`; without either, the report says QR codes were not checked.
- **Linux ELF files.** Header, packing (UPX or near-random content), a stripped section table, and behaviour strings: ransom notes, cryptominer pools, reverse shells, download-and-run one-liners, log/firewall tampering and persistence. Nothing is executed.
- **Faster scans.** The slow layers (ML, LLM, VirusTotal) run last and in parallel, and are skipped when the local layers already reach 100 (the verdict cannot change; the report lists them under `[Skipped]`). Set `SKIP_HEAVY_WHEN_SATURATED=false` or `PARALLEL_HEAVY_LAYERS=false` to turn either off.
- **Script attachments.** `.js`, `.vbs`, `.hta`, `.wsf`, `.ps1`, `.bat` and their encoded variants: download and execute primitives, shadow-copy deletion and other recovery tampering, Defender/AMSI tampering, persistence and obfuscation. PowerShell `-EncodedCommand` payloads are decoded. Download *plus* execute (a dropper) is High; either one alone, as in many admin scripts, stays Low.
- **Password in the e-mail.** "Password: 4471" in the subject or body (eleven languages) is tried on the mail's encrypted ZIP / 7z / RAR attachments before the built-in list, so the contents are scanned; using it adds a 30-point technical signal.
- **Encoded scripts.** `.vbe` / `.jse` (Windows Script Encoder) are decoded and the real source is analysed.
- **Fuzzy database builder.** `python tools/build_fuzzy_db.py SAMPLES_DIR --out fuzzy_signatures.json --benign BENIGN_DIR`, run inside the analysis VM, turns confirmed samples into TLSH/ssdeep signatures, drops near-duplicates and any signature that matches a benign file. Only digests leave the VM.
- **Layered obfuscation.** Scripts are unwound up to five nested encodings (base64 inside a Chr() chain inside a reversed string ...), and every layer is analysed.
- **OneNote, CHM, MSI, XLL, password-protected Office.** The files these carry are carved out or decrypted and scanned like attachments; XLL add-ins and CHM command objects are flagged. Locked Office documents are opened with the password from the e-mail when there is one (`pip install msoffcrypto-tool`).
- **Allowlist.** `python RansomwareScanner.py --allow vendor_setup.ps1 --note "checked"` adds a known-good SHA-256; the file is still scanned and reported but not scored.
- **Optional sandbox.** Point `SANDBOX_URL` at your own [CAPEv2](https://github.com/kevoreilly/CAPEv2) server and suspicious top-level files are detonated there; behaviour signatures (shadow-copy deletion, encryption, injection ...) are scored in a new *dynamic* category. Nothing is sent anywhere else, and it is off by default.
- **Calibration.** `python tools/calibrate_weights.py --malicious DIR --benign DIR --out calib` proposes scoring weights from labelled data, with cross-validated detection and false-alarm rates, for review.
- **Tools.** `python tools/mbox_to_eml.py OUT_DIR corpus.mbox` splits mbox mailboxes into `.eml` files for scanning and evaluation.

### 4.3

- HTML smuggling now has automated tests (embedded ZIP and executable payloads, split strings, `msSaveOrOpenBlob`, data-URI anchors, phishing forms).
- **RAR archives** (RAR 4 and RAR 5, including encrypted members and encrypted file names). Names, sizes, symlinks and encryption are read in Python by `rarfile`, so the lure, slip and limit checks always run. Decompressing needs a program that is usually already installed: 7-Zip (found in Program Files on Windows automatically), `unrar`, `unar` or `bsdtar`. The tool is only asked to stream one member to stdout, never to write files, so its own path handling is never trusted.
- **OLE objects in Outlook messages.** A file pasted into a mail as an icon (the Packager trick: the icon says `invoice.pdf`, double-clicking runs `invoice.pdf.exe`) is unpacked under its **real** name and scanned. Embedded Word/Excel/PowerPoint files and PDFs are extracted too; legacy `.doc/.xls/.ppt` objects are repacked as standalone files so the macro layer can read them. This also works inside forwarded Outlook items.

### 4.2

Seven limitations listed in 4.1, closed:

- **More archive formats.** AES-encrypted ZIPs (`pyzipper`), **7z** including archives whose file names are encrypted (`py7zr`), and **ISO / IMG** disc images, a common way to smuggle executables past Mark-of-the-Web (`pycdlib`). All three use the same bomb / slip / member-count limits as ZIP, the same delivery-password list, and nest inside each other (ISO → 7z → ZIP → document). Without the library the report says the archive could not be opened and which `pip install` fixes it.
- **Excel and PowerPoint hidden content.** Hidden and *very hidden* sheets, hidden rows and columns that hold text, white text, ≤ 2 pt fonts, hidden shapes and slides, and text placed outside the visible slide. Prompt-injection phrases inside any of them count as confirmed attempts, as in Word.
- **Outlook items inside Outlook items.** A forwarded `.msg` attached to a `.msg` is rebuilt as `.eml` with its own headers and attachments and scanned like any other attached mail (up to 3 levels).
- **Quarantine key backup.** `--export-key` writes the key encrypted with a passphrase (scrypt + AES-GCM); `--import-key` installs it on another machine. A different existing key is never replaced unless you add `--replace-key`, and the old one is kept as a backup.
- **Fewer ML false positives on password vaults.** KeePass (`.kdbx`), GPG (`.gpg/.pgp`) and age (`.age`) files are recognised by header *and* extension. Only the ML layer uses this: the encrypted-content check ignores it, so ransomware can't hide an encrypted `.docx` by prepending a vault header.
- **Real-time canary watching.** With `watchdog` installed, canary folders are watched for file events and verified about a second after a canary is changed, renamed or a ransom note appears, in `--background` and in the GUI. The interval check stays as a safety net.


### 4.1

![MailGuard result](docs/screenshot-v41-mail.png)

- **MailGuard: `.eml` and Outlook `.msg` e-mails.** Reads the SPF / DKIM / DMARC verdicts your mail server recorded (only the *topmost* `Authentication-Results`: lower copies are written by the sender and can be forged), flags display-name spoofing, Reply-To diversion and links whose text shows one domain while the href goes to another, and unpacks every attachment (including attached e-mails and ZIPs) into a sandbox for the full pipeline. The message body feeds the prompt-injection and LLM layers. `.msg` files are read stream-by-stream with `olefile`, so no extra dependency is needed.
- **Static ML classifier.** 15 explainable byte and PE features (entropy profile, packer section names, writable+executable sections, import count, …). Train a RandomForest on your own labelled folders with `--train-ml`, and it reports held-out precision, recall and false-positive rate. Without a model, a transparent rule engine runs. ML has its own small **statistical** score budget (≤ 20) and, like the LLM, can never push a file past Medium on its own.
- **Standalone executables.** `python build.py` packages the CLI and the GUI with PyInstaller, then **smoke-tests the binary with real scans** before packaging it with a SHA-256 checksum.
- **210 automated tests** (+1 opt-in GUI test), including real Outlook compound files built at test time, run on Python 3.9, 3.11, 3.12 and 3.13.


### 4.0

- **File integrity & ransomware impact.** Flags executables disguised as documents (`invoice.pdf` that is really a PE, ELF, Mach-O, `.lnk` or script) and documents that have **already been encrypted** (format signature gone, bytes statistically random), including intermittent encryption that only scrambles the first few KB.
- **Prompt-injection defence.** Detects hidden text in Word files and PDFs (hidden runs, 1–2 pt fonts, white text, invisible PDF render mode) and text aimed at an AI analyst ("ignore previous instructions…"). LLM prompts now wrap the document in per-request random delimiters.
- **Office external links.** Remote template injection (T1221), Follina-style OLE links (CVE-2022-30190), `ms-msdt:` / `search-ms:` handlers and NTLM-leaking UNC paths: the macro-less document attacks.
- **Archive inspection.** ZIP files (including nested and password-protected ones) are unpacked into a sandbox; zip bombs, zip slip, double extensions (`receipt.pdf.exe`) and RTLO filename spoofing are flagged, and **every member goes through the full pipeline**.
- **Macro upgrades.** VBA stomping (P-code vs source mismatch) and Excel 4.0 (XLM) macro sheets.
- **Canary tripwires** that turn the background mode into a near-real-time ransomware alarm, and an **encrypted quarantine vault** with verify-before-delete.
- **Safer external calls.** VirusTotal is now **hash-lookup only by default** (uploads are opt-in), requests have timeouts, retries and quota pacing, and VirusTotal/LLM answers are cached by SHA-256.
- **146 automated tests** (unit, end-to-end, CLI and GUI), run on Python 3.9, 3.11, 3.12 and 3.13.

Full details in the [changelog](CHANGELOG.md) and [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md).

</details>

---

## 🧩 Why "hybrid"?

Most lightweight scanners rely on a single technique (usually a hash lookup), which misses anything not already in a database. This tool layers complementary approaches (exact, structural, behavioural, reputational, and semantic) so a file flagged by **any** of them is surfaced, and the **weighted scoring matrix** makes the verdict reflect *which kind* of evidence fired. A real exec primitive in a macro counts for far more than a phishing-flavoured sentence.

```mermaid
flowchart TD
    IN["Files and folders<br/>PDF · Office · RTF · scripts · HTML / SVG · images<br/>ZIP · 7z · RAR · ISO · EML / MSG"]
    MBX["IMAP mailbox<br/>read-only, TLS"] --> IN
    IN --> S1

    subgraph S1["1 · Static layers: always on, nothing executed, no network"]
        direction LR
        H["Hashes + local DB<br/>allowlist"]
        FZ["Fuzzy hashing<br/>TLSH / ssdeep"]
        MA["Macros<br/>VBA · XLM · stomping"]
        Y["YARA<br/>23 rules"]
        FI["File integrity<br/>disguise · encryption"]
        EL["Linux ELF"]
        PE["Windows PE<br/>imports · T1490 · overlay"]
        SC["Scripts<br/>layered deobfuscation"]
        PG["Hidden content<br/>prompt injection"]
        RL["External links<br/>RTI · Follina · UNC"]
        QR["QR codes<br/>quishing"]
    end

    subgraph S2["2 · Containers: every member goes through the pipeline again"]
        direction LR
        MG["MailGuard<br/>SPF / DKIM / DMARC · spoofing"]
        AR["Archives<br/>bomb · slip · lures"]
        WB["Web pages<br/>HTML smuggling · SVG"]
        EM["OneNote · CHM<br/>MSI · XLL"]
    end

    subgraph S3["3 · Slow layers: in parallel, skipped once the score is 100"]
        direction LR
        ML["ML classifier"]
        LLM["LLM<br/>local-first"]
        VT["VirusTotal<br/>hash only"]
        EMU["JS emulation<br/>opt-in"]
        SB["CAPEv2 sandbox<br/>opt-in"]
    end

    S1 --> S2 --> S3
    S2 -. "members and attachments" .-> IN
    S3 --> SM["Weighted scoring matrix<br/>technical · reputation · semantic · statistical · dynamic"]
    SM --> OUT["Risk 0-100 + verdict<br/>TXT / JSON report · JSON Lines · signed webhook"]
    SM --> Q["Auto-quarantine<br/>AES-256-GCM vault"]
    CN["Canary tripwires<br/>watched in real time"] --> AL["Alert + containment<br/>stop writers · lock folders · network off"]
```

Signals fall into five weight categories: **technical** (everything structural, including MailGuard), **reputation** (VirusTotal), **semantic** (LLM and lure wording), **statistical** (ML classifier) and **dynamic** (behaviour seen by emulation or the sandbox). Technical evidence is designed to mathematically outweigh semantic and statistical signals: those two together can never push a file past Medium. Archives and e-mails send every member or attachment back through all layers (dotted arrows), and the container is scored like its most dangerous member.

---

## 🔬 Detection layers

1. **Cryptographic hashing + local hash database.** MD5 and SHA-256 with chunked reads (constant memory), and an O(1) lookup of the MD5 against a streamed CSV of known-malicious hashes. Instant, offline detection of known samples.
2. **Fuzzy / structural hashing (polymorphic families).** **TLSH** and **ssdeep** (pure-Python `ppdeep`) digests compared against a signature database of *confirmed* malicious samples. The digests stay *similar* when a file stays *structurally similar*, which catches polymorphic variants whose exact SHA-256 has never been seen.
3. **Macro analysis (Office dropper mechanism).** `oletools` / `olevba` statically extract and triage VBA and XLM macros **without executing them**: auto-run triggers (`AutoOpen`, `Document_Open`, …), execution/download primitives (`Shell`, `CreateObject`, `URLDownloadToFile`, `powershell`, …), other suspicious calls, and IOCs. v4 adds:
   - **VBA stomping**: the visible source was replaced while the compiled P-code (what Office actually runs) still holds the payload. The mismatch is itself strong evidence of evasion.
   - **Excel 4.0 (XLM) macro sheets**, a favourite of Emotet/Qakbot loaders, in both `.xls` (BIFF) and OOXML workbooks.
4. **YARA rules engine (structural IOCs).** Compiles every `.yar` / `.yara` file in `rules/` and scans each file. Rules carry a `severity` meta the scoring matrix reads. 23 original rules ship in five files: ransom-note language, extortion + urgency, Bitcoin addresses with payment context, PowerShell download cradles, Office dropper structures, PDF auto-launch actions, executables disguised as documents, **shadow-copy deletion and boot-recovery tampering** (MITRE T1490), and since 4.4.0 shortcuts that start a script host, HTML Applications, Script Encoder output, OneNote notebooks with embedded scripts, LOLBin downloads, Defender tampering, bulk stopping of database/backup services, Safe Mode boot, event-log clearing, encryptor binaries (target-extension lists + crypto APIs) Tor ransom notes, and since 4.5 Equation Editor 3.0 objects (CVE-2017-11882) in RTF and legacy Office files. Rules see the file's extension, so a program named `.exe` is not called "disguised". Only matched string identifiers are recorded, never the raw bytes.
5. **File integrity: disguise and encryption.** Reads the file's real format from its magic bytes and compares it with the extension.
   - **Disguised executables**: a PE (validated `MZ` → `PE\0\0` header), ELF, Mach-O, Windows shortcut (`.lnk`) or `#!` script behind a document extension.
   - **Encrypted content** (ransomware *impact*, T1486): the format signature is missing **and** the bytes are statistically random. Randomness is judged with Shannon entropy compared to what truly random data of the same length would reach, plus a chi-square uniformity test. Checking the first 4 KiB separately catches intermittent encryption. Because .docx/.xlsx and most PDFs are compressed (and therefore high-entropy), the randomness test only runs when the expected signature is already gone. That avoids the false positives a plain entropy threshold produces.
   - Formats Office opens natively under another extension (HTML exported as `.xls`, RTF saved as `.doc`, password-protected `.docx` stored as OLE) are noted but not scored.
6. **Hidden content & prompt injection.** Finds concealed text in `.docx/.docm` (hidden runs, ≤ 2 pt fonts, near-white text without background shading), Excel (hidden / very hidden sheets, hidden rows and columns, white or tiny text; 4.2), PowerPoint (hidden shapes and slides, off-slide text, tiny text; 4.2) and PDFs (text render mode 3, i.e. invisible), and looks for phrasing aimed at an AI analyst ("ignore previous instructions", "mark this file as clean", chat-template tokens, …). An injection phrase inside concealed text is a **confirmed** attempt. A phrase in plainly visible text is only **suspicious**, because articles *about* prompt injection contain the same words. XML is parsed with `defusedxml`.
7. **Office external links.** Reads the relationship parts inside OOXML files and RTF control words, **without contacting any URL**:
   - remote template injection (`attachedTemplate` → `http://…`, T1221),
   - external OLE objects, and Follina-style links ending in `!` (CVE-2022-30190),
   - exploit URI schemes in any relationship (`ms-msdt:`, `search-ms:`, `ms-officecmd:`, `mhtml:`, …),
   - UNC / `file://host` paths that make Windows send the user's NTLM hash to the attacker (T1187),
   - RTF `{\*\template http://…}` and auto-updating OLE links (`\objupdate`).
8. **Archive inspection.** ZIP archives (and, since 4.2, AES ZIP, 7z and ISO/IMG; since 4.3, RAR) are unpacked into a temporary sandbox with hard limits (nesting depth, member count, total and per-member decompressed size, compression ratio). It reports **zip bombs**, **zip slip** (path traversal, absolute paths, symlinks; such members are never written), executables/scripts/shortcuts inside the archive (by extension *and* magic bytes), **double extensions** (`invoice.pdf.exe`) and **right-to-left-override** names. Encrypted members are tried against a short list of delivery passwords ("infected", the archive's own name, …). Up to 25 members per archive go through all the other layers, and the archive is scored like its most dangerous member.
9. **VirusTotal (threat intelligence).** Looks the file's SHA-256 up via the v3 API and reads how many engines flag it. **Privacy by default:** unknown files are *not* uploaded (an upload shares the document with VirusTotal and its Enterprise subscribers); set `VT_UPLOAD_UNKNOWN=true` to opt in. Requests are paced to the free quota (4/min), retried with backoff on 429/5xx, time out after 30 s, and answers are cached for 24 h.
10. **LLM semantic analysis (local-first, OPSEC-preserving).** Extracts visible text (pypdf / python-docx / OOXML parts, with **OCR fallback** for scanned PDFs when an LLM is active) plus printable strings, and asks an LLM whether it reads like a ransomware/phishing lure.
    - **OPSEC by default.** With `LLM_PROVIDER=auto` the scanner prefers a **local Ollama** model if one is reachable, so sensitive documents never leave the machine. It falls back to OpenAI only if no local model is available *and* a key is set, and logs the egress.
    - **Prompt-injection hardening.** Instructions live in the system role, the document in the user role, temperature 0, JSON-only output, and (new) the document is wrapped in **per-request random delimiters** (`<UNTRUSTED_DATA_5F2C…>`). Look-alike tags inside the document are neutralised, so it cannot close the data block and talk to the model directly. Answers are cached by SHA-256.

11. **E-mail: MailGuard (new in 4.1).** `.eml` (MIME) and Outlook `.msg` (compound file, read with `olefile`):
    - **Sender authentication:** SPF, DKIM and DMARC as recorded by the receiving server. Only the topmost `Authentication-Results` / `Received-SPF` is trusted; copies further down were written by whoever sent the mail, so they are ignored and counted. One valid DKIM signature is enough. Nothing is re-checked against DNS, because a saved message can be years old.
    - **Spoofing:** a display name that carries a different address or domain (`"billing@paypal.com" <x@evil.tld>`), and a Reply-To that diverts answers to another organisation (the business-e-mail-compromise set-up).
    - **Deceptive links:** HTML anchors whose visible text shows one domain while the `href` goes to another.
    - **Attachments:** executables, scripts and macro-enabled Office files; double extensions; RTLO names; attached e-mails (saved as `.eml` and scanned recursively), and OLE objects such as packaged files (unpacked under their real name; 4.3). Every attachment goes through all the other layers in a sandbox that is deleted after the scan, and the mail is scored like its worst attachment. Containers are followed two levels deep (mail → ZIP → document).
    - **Lure subjects** (payment, urgency, credential, delivery) are a *semantic* signal and are scored as such.
12. **Static ML classifier (new in 4.1).** 15 features from the first 8 MiB: entropy, the share of high-entropy 1 KiB windows, head/tail entropy, PE section count/entropy, imported DLL count, packer section names, writable+executable sections, size, null/printable ratios, a *known compressed format* flag (ZIP, gzip, PNG, JPEG… are *expected* to look random), and extension risk.
    - **With a trained model** (`--train-ml BENIGN_DIR MALICIOUS_DIR`, scikit-learn RandomForest), it outputs P(suspicious) plus the most important features. Training reports held-out accuracy, precision, recall and false-positive rate. Models are joblib files; load only models you trained.
    - **Without a model**, a transparent rule engine runs: random-throughout content in a non-compressed format, packer sections, W+X sections, near-empty import tables.
    - Scored in its own **statistical** category (max 20 points). If the file-integrity layer has already proved the content is encrypted, the ML opinion is not counted twice.

13. **Linux ELF triage (4.4).** Header, packing (UPX or near-random content), a removed section table, and behaviour strings: ransom notes, cryptominer pools, reverse shells, download-and-run one-liners, log/firewall tampering and persistence.
14. **Windows programs (4.6).** PE structure read without executing it: per-section entropy and packer section names, writable+executable sections, the import table by name (process-injection chain; encrypt + walk + write in unsigned programs; imports resolved only at run time), shadow-copy and backup deletion commands in ASCII and UTF-16 (T1490), programs appended after the sections, near-random overlays that are no known installer, malformed headers, and whether an Authenticode signature directory is present (reported, not verified). A packed program is scored once: its writable code and hidden imports are the packer's doing, and the ML opinion on the same sections is not added.
15. **Scripts (4.4).** `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`, `.hta`, `.ps1`, `.bat`, `.cmd`: up to five nested encodings are unwound (Script Encoder, base64, `Chr()` / `fromCharCode` chains, reversed strings, PowerShell `-EncodedCommand`), then download, execute, recovery tampering (T1490), Defender/AMSI tampering and persistence are looked for. Download *plus* execute (a dropper) is High; either one alone stays Low.
16. **QR codes (4.4).** Codes in images, PDF pages, Office documents and attachments are decoded and their links judged (bare IP, punycode, `user@host`, shorteners, script schemes). Needs `pyzbar` + zbar or OpenCV.
17. **Web pages (4.4).** HTML smuggling (a payload rebuilt in the browser from base64 with `Blob`), active SVG, password forms posting elsewhere and redirects. Hidden payloads are decoded and scanned like attachments.
18. **Embedded content (4.4).** OneNote notebooks, CHM help files, MSI installers, XLL add-ins and password-protected Office files: the files they carry are carved out or decrypted (with the password from the e-mail when there is one) and scanned.
19. **JavaScript emulation (4.5, opt-in).** With [box-js](https://github.com/CapacitorSet/box-js) installed and `EMULATION_ENABLED=1`, scripts run against fake WScript / ActiveX objects and the URLs fetched, files written and commands run are recorded, including URLs built only at run time. Enable it inside an analysis VM.
20. **CAPEv2 sandbox (4.4, opt-in).** Suspicious top-level files go to *your own* CAPEv2 server (`SANDBOX_URL`); its behaviour signatures are scored in the dynamic category.

Every optional layer **degrades gracefully**: a missing library, a missing local model, or a missing API key produces a warning, not a crash, and the remaining layers still run.

---

## ⚖️ Weighted scoring matrix

The original hardcoded equation (`10·db + 5·llm + 5·vt`) gave a *semantic* guess the same weight as multi-engine reputation. `detectors/scoring.py` replaces it with a transparent matrix: every signal contributes through an explicit rule with a **category**, a **weight**, and a human-readable **detail**, under three principles:

1. **Technical > semantic, mathematically.** The semantic (LLM) category is capped at 24, so a phishing lure can never by itself out-score a real structural indicator.
2. **Semantic-alone cannot be "High".** If no technical or reputation signal fired, the verdict is clamped to at most **Medium**. The same holds for the **statistical** (ML) category.
3. **Explainability.** Each result carries a per-indicator breakdown, so the report shows exactly which signals drove the verdict and by how much.

| Indicator | Category | Points |
|---|---|---:|
| Local hash-DB match | technical | 100 |
| YARA match (critical / high / medium / low; +8 per extra rule) | technical | 90 / 65 / 40 / 18 |
| VBA stomping · executable disguised as a document · exploit URI scheme / Follina-style OLE | technical | 90 |
| Archive zip slip | technical | 80 |
| Fuzzy family match | technical | 72 × confidence |
| Encrypted content (ransomware impact) · HTML smuggling · payload appended to an image | technical | 70 |
| External link: remote template / external OLE / UNC (+8 per extra kind) | technical | 70 |
| Script: recovery tampering / dropper / ransom note / defence evasion / persistence / download or execute alone (+8 per extra) | technical | 70 / 65 / 60 / 40 / 25 / 20 |
| ELF: ransom note / miner or reverse shell / download-and-run / evasion / persistence (+8 per extra) | technical | 60 / 45 / 35 / 25 / 20 |
| Windows program deletes shadow copies / backups (T1490) | technical | 60 |
| Double extension or RTLO name (archive or mail) · zip bomb · CHM command object · file embedded in a web page | technical | 60 |
| XLM macro sheet | technical | 55 |
| Confirmed prompt injection | technical | 50 |
| Mail: executable, script or macro-enabled attachment · OneNote page with a runnable file | technical | 45 |
| Macro: exec primitive (+8 each extra) / auto-run / dropper synergy / other suspicious call | technical | 40 / 22 / 20 / 10 |
| Active SVG · MSI script custom action · XLL add-in | technical | 40 |
| Mail: DMARC failure (SPF/DKIM failure without it) | technical | 35 (20) |
| Executable inside an archive · password form posting elsewhere · QR code to a risky link | technical | 35 |
| Mail: display-name spoof · archive password in the body · deceptive link · Reply-To diversion | technical | 30 · 30 · 25 · 15 |
| Script Encoder output · scan failed (timeout or crash) · program appended to a program | technical | 30 · 25 · 25 |
| Encrypted archive not opened · obfuscated script · packed ELF or Windows program · process-injection imports · page redirect | technical | 20 |
| Unsigned program importing encrypt + directory walk + file write | technical | 15 |
| Hidden content · injection phrasing · format mismatch · obfuscated page script · page builds a download | technical | 15 |
| Archive only partly unpacked · locked Office document · ELF without section table · writable code section · imports resolved at run time · malformed Windows program | technical | 10 |
| Near-random appended data in an unsigned program | technical | 8 |
| Worst archive member / mail attachment / embedded file | its own categories | carried over |
| VirusTotal detections | reputation | max(35, 80 × ratio) |
| LLM lure assessment | semantic | 24 × confidence |
| Mail: lure subject · QR code carrying a link | semantic | 8 |
| ML classifier | statistical | 20 × P(suspicious) |
| Sandbox: ransomware behaviour · other signatures by severity (max 70) | dynamic | 80 · 25 / 12 / 4 |
| Emulation: download and run / contacts a URL | dynamic | 65 / 25 |

All weights live in [`detectors/indicators.yaml`](detectors/indicators.yaml); `tools/calibrate_weights.py` proposes data-driven values for review.

Category caps: technical 100, reputation 80, semantic 24, statistical 20, dynamic 100; the total is clamped to 100.

| Risk score | Verdict |
|-----------:|---------|
| 0 | Clean |
| 1–24 | Low |
| 25–49 | Medium |
| 50–79 | High |
| 80–100 | Critical |

The legacy **severity score (0–10)** (`risk / 10`) is still produced so older reports and integrations keep working: a pure local-DB hit is exactly `10.0`, a clean file `0.0`.

---

## 🛡️ Protection features

### Canary tripwires

```bash
python RansomwareScanner.py --deploy-canaries            # your configured scan folders
python RansomwareScanner.py --deploy-canaries ~/Documents ~/Desktop
python RansomwareScanner.py --verify-canaries             # exit code 2 if tripped
python RansomwareScanner.py --remove-canaries
```

Decoy documents (`!000_Finance_Records_Backup.docx`, `!000_Signed_Contracts_Archive.pdf`, `!000_Asset_Inventory.csv`) are planted where an alphabetical ransomware walk reaches them first. Each is a valid, unique file whose SHA-256 is recorded. If one is **deleted, modified, rewritten with random bytes, or renamed with an appended extension** (`….docx.lockbit`), or a ransom-note-named file appears beside it, the tripwire fires. It writes `canary_alert_<time>.txt` next to the reports, logs at CRITICAL, and raises a desktop notification on macOS/Linux. With `watchdog` installed, canary folders are also **watched in real time**: a verification runs about a second after a canary is touched. `--background` checks every 5 minutes as well (`CANARY_CHECK_MINUTES`), the GUI does the same while it is open, and canary files are never scanned or quarantined themselves. A trip can also **act** (`CANARY_RESPONSE`, run in this order): `stop_writers` suspends the processes writing in the canary folders with their children (`CANARY_CONTAIN_MODE=terminate` kills them), `lock_folders` removes write access to `CANARY_LOCK_DIRS`, `controlled_folder_access` turns on Windows' own blocker, `network_off` disconnects the machine, and `script` runs your playbook. `--resume-pid PID` and `--unlock-folders` undo the containment. It is a **rapid-containment and damage-mitigation tripwire**: it acts after encryption has started and cannot replace kernel-level EDR prevention.

### Encrypted quarantine vault

```bash
python RansomwareScanner.py --quarantine ~/Downloads/invoice.docm
python RansomwareScanner.py --list-quarantine
python RansomwareScanner.py --restore 3fa9            # full id or unique prefix
python RansomwareScanner.py --restore 3fa9 --restore-to ~/analysis/
```

Files are encrypted with **AES-256-GCM** in 64 KiB chunks. Each file gets its own key (HKDF-SHA256 from a local master key and a random salt), and the header, every chunk (with its sequence number) and an explicit end-of-file frame are all authenticated, so tampering, reordering and truncation are all detected. The original is deleted **only after** the encrypted copy has been decrypted again and its SHA-256 verified. Restore never overwrites a file that has since appeared at the original path. Set `AUTO_QUARANTINE=critical` (or `high`) to quarantine automatically after each scan; it is off by default.

Back the key up so quarantined items can be restored on another machine:

```bash
python RansomwareScanner.py --export-key ~/backup/quarantine.hrdkey   # asks for a passphrase (10+ chars)
python RansomwareScanner.py --import-key quarantine.hrdkey             # on the other machine
python RansomwareScanner.py --import-key quarantine.hrdkey --replace-key  # replace a different key
```

The backup is encrypted with your passphrase (scrypt + AES-256-GCM) and prints a short fingerprint to compare on both machines. `HRD_KEY_PASSPHRASE` can supply the passphrase in scripts.

> The vault neutralises a file: it can't be opened, executed, or re-flagged by other tools. It is not a secrecy boundary against someone who already controls your account, because the key lives on the same disk.

### Ransomware impact in reports

While walking folders, file *names* are checked for ransom notes (`HOW_TO_DECRYPT.txt`, `_readme.txt`, `!!!READ_ME!!!.txt`, …) and known ransomware extensions (`.lockbit`, `.locked`, Dharma-style `.id-XXXX.[mail].ext`, …). Together with files whose content looks encrypted, these feed a **"POSSIBLE ACTIVE RANSOMWARE IMPACT"** banner at the top of the report.

---

## 📦 Requirements

**Python:** 3.9+ (see `requirements.txt`; every dependency ships x86_64 and ARM64 wheels or is pure Python, so installation needs no compiler; `python-tlsh` is skipped on Windows, where a built-in port computes the same digests).

**Detection-layer libraries (optional, recommended):** `python-tlsh` + `ppdeep` (fuzzy hashing; on Windows, where python-tlsh has no wheels, a built-in TLSH port gives the same digests), `oletools` (macros), `yara-python` (YARA), `defusedxml` (hidden-content and external-link layers for Office files), `cryptography` (quarantine vault). If any are absent, that layer or feature is skipped.

**Local LLM (optional, for OPSEC).** Install **[Ollama](https://ollama.com)** and pull a model; the scanner finds it automatically:

```bash
ollama pull llama3.1          # or any chat model you prefer
# the scanner auto-detects a running Ollama at http://localhost:11434
```

**System packages: Tesseract OCR + Poppler.** Only needed for the **OCR fallback on scanned/image-only PDFs**, and only used when an LLM is active.

- **Windows:** install **Tesseract OCR** and **Poppler**, and add both to your `PATH`.
- **macOS:** `brew install tesseract poppler`
- **Linux (Debian/Ubuntu):** `sudo apt-get install tesseract-ocr poppler-utils`

**For the GUI only: Tkinter.** Bundled with the official Python installers on Windows and macOS. On minimal Linux installs: `sudo apt-get install python3-tk`.

---

## 🚀 Installation

```bash
git clone https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector.git
cd hybrid-ransomware-detector

python -m venv .venv
# Windows:        .venv\Scripts\activate
# macOS / Linux:  source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-ml.txt     # optional: train / load ML models
```

---

## 📦 Standalone executables

`build.py` turns the project into programs that run without a Python install:

```bash
pip install -r requirements.txt -r requirements-ml.txt -r requirements-build.txt
python build.py              # folder build  -> dist/HybridRansomwareDetector/
python build.py --onefile    # one file per program
python build.py --no-ml      # leave scikit-learn out (~100 MB smaller)
```

| Program | What it is |
|---|---|
| `hrd-scanner` (`.exe` on Windows) | the CLI, with every flag shown under Usage |
| `hrd-scanner-gui` | the desktop app (no console window); on macOS also `Hybrid Ransomware Detector.app` |

After PyInstaller finishes, the script **runs the built CLI** in a throw-away home folder (`--version`, then real scans of a clean PDF and of an executable disguised as a PDF) and fails if a verdict is wrong. A binary that starts but can't find its YARA rules never gets packaged. The result is archived as `dist/hrd-scanner-<version>-<os>-<arch>.zip` / `.tar.gz` with a `SHA256SUMS` file.

Notes:
- **Build on each target OS.** PyInstaller doesn't cross-compile, so a CI matrix (Windows / macOS / Linux runners running `python build.py`) produces all three.
- **UPX is off on purpose.** UPX-packed executables look like malware to AV engines, and to this scanner's own ML layer.
- **Settings in a packaged build** live in `~/RansomwareScanner/.env` (the bundle folder is temporary or read-only). Autostart and shortcuts launch the executable directly.
- **Unsigned:** Windows SmartScreen will warn, and macOS needs `xattr -dr com.apple.quarantine "Hybrid Ransomware Detector.app"` (or code signing and notarisation).
- Tesseract/Poppler (OCR fallback) stay system packages and are not bundled.

## 🔑 Configuration

Settings are loaded from a local `.env` file and are **never** stored in the code. Secrets
(`OPENAI_API_KEY`, `VIRUSTOTAL_API_KEY`, `SANDBOX_TOKEN`, `WEBHOOK_SECRET`, `IMAP_PASSWORD`) come
from the environment first (or `NAME_FILE`, e.g. a Docker secret), then the OS keyring (the
desktop app saves keys there), then `.env`. Since 4.7 a secret found in `.env` is moved to the OS
keyring on the next start: written, read back, and only then removed from the file.

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `auto` | `auto` \| `ollama` \| `openai` \| `none` |
| `OLLAMA_HOST`, `OLLAMA_MODEL` | `http://localhost:11434`, `llama3.1` | local model |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | empty, `gpt-4` | optional cloud fallback |
| `VIRUSTOTAL_API_KEY` | empty | reputation layer |
| `VT_UPLOAD_UNKNOWN` | `false` | upload files VirusTotal has never seen (shares their content) |
| `VT_REQUESTS_PER_MINUTE` | `4` | client-side pacing (free API quota); `0` disables |
| `HTTP_TIMEOUT` | `30` | seconds, every external call |
| `CACHE_ENABLED`, `CACHE_TTL_HOURS` | `true`, `24` | VirusTotal/LLM result cache |
| `AUTO_QUARANTINE` | empty (off) | `high` or `critical` |
| `CANARY_CHECK_MINUTES` | `5` | canary verification interval |
| `FUZZY_SIGNATURE_DB`, `YARA_RULES_DIR` | bundled | custom signature/rule locations |
| `SKIP_HEAVY_WHEN_SATURATED` | `true` | skip ML/LLM/VirusTotal when the local layers already score 100 |
| `PARALLEL_HEAVY_LAYERS` | `true` | run ML/LLM/VirusTotal concurrently |
| `QR_SCAN_ENABLED` | `true` | decode QR codes (needs pyzbar or OpenCV) |
| `ALLOWLIST_PATH` | `~/RansomwareScanner/data/allowlist.txt` | known-good SHA-256 hashes |
| `SANDBOX_URL`, `SANDBOX_TOKEN` | empty (off) | your CAPEv2 server and API token |
| `SANDBOX_SUBMIT`, `SANDBOX_WAIT_SECONDS` | `suspicious`, `600` | which files to detonate; how long to wait for a report |
| `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD` | empty (off) | mailbox for `--scan-imap` (use an app password) |
| `IMAP_PORT`, `IMAP_STARTTLS`, `IMAP_FOLDER` | `993`, `false`, `INBOX` | connection and folder (TLS only) |
| `IMAP_SINCE_DAYS`, `IMAP_MAX_MESSAGES`, `IMAP_MAX_MB` | `7`, `200`, `25` | first-run look-back, per-run and per-message limits |
| `IMAP_CHECK_MINUTES` | `0` (off) | check the mailbox on a schedule in `--background` |
| `CANARY_RESPONSE`, `CANARY_RESPONSE_SCRIPT` | empty (alert only) | `stop_writers`, `lock_folders`, `controlled_folder_access`, `network_off`, `script`; absolute path of your response script |
| `CANARY_CONTAIN_MODE`, `CANARY_CONTAIN_EXCLUDE`, `CANARY_LOCK_DIRS` | `suspend`, empty, canary folders | `terminate` to kill; extra process names never stopped; folders `lock_folders` makes read-only |
| `LOG_FORMAT`, `LOG_LEVEL` | `text`, `INFO` | `json` for one JSON object per log line |
| `AEGIS_API_RATE_PER_MINUTE`, `AEGIS_API_BURST`, `AEGIS_API_MAX_CONCURRENT_SCANS`, `AEGIS_API_TRUST_PROXY` | `60`, `10`, `2`, off | REST API abuse limits (see [deployment](docs/DEPLOYMENT.md)) |
| `AEGIS_API_SOCKET`, `AEGIS_INTEL_SOCKET`, `AEGIS_INTEL_TOKEN` | empty | Docker deployment: API on a Unix socket; external services through the intel service (see [deployment](docs/DEPLOYMENT.md)) |
| `EMULATION_ENABLED`, `EMULATION_TOOL`, `EMULATION_TIMEOUT` | `false`, `box-js`, `20` | JavaScript emulation (analysis VM only) |
| `ISOLATE_SCANS`, `SCAN_WORKERS`, `SCAN_TIMEOUT_SECONDS`, `WORKER_MEMORY_MB` | `true`, auto, `300`, `2048` | isolated worker processes for every scan (folders, single files, the API). When workers cannot start, nothing is scanned in the main process: the files get a `failed` result (`isolation_unavailable`), the CLI exits with code 3 and the API answers 503. `ISOLATE_SCANS=0` is a development-only opt-out, recorded in `provenance.isolation` and refused under `AEGIS_PROFILE=production` |
| `ML_ENABLED`, `ML_MODEL_PATH` | `true`, data folder | ML layer and a model you trained |
| `JSONL_PATH`, `WEBHOOK_URL`, `WEBHOOK_SECRET`, `WEBHOOK_MIN_VERDICT` | empty, empty, empty, `High` | SIEM outputs (HMAC-signed webhook) |
| `WATCH_DIRS`, `WATCH_SETTLE_SECONDS`, `WATCH_MAX_QUEUE`, `WATCH_RETRY_MINUTES` | empty, `2`, `1000`, `5` | desktop monitoring roots (semicolon-separated), settle delay, queue bound and retry delay |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`, `SMTP_PASSWORD` | empty, `465`, `tls`, empty, empty | e-mail over verified TLS (`starttls` also supported); password from secret store; Docker settings belong to intel |
| `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`, `ALERT_EMAIL_MIN_VERDICT` | empty, empty, `High` | sender, comma-separated recipients, verdict threshold |
| `ALERT_EMAIL_PER_HOUR`, `ALERT_EMAIL_PER_DAY` | `20`, `100` | delivery caps |
| `OUTBOX_DIR`, `OUTBOX_MAX_AGE_HOURS` | app outbox, `24` | persistent pending alerts and expiry |
| `CLOUD_UPLOAD`, `CLOUD_ENDPOINT`, `CLOUD_REGION`, `CLOUD_BUCKET`, `CLOUD_PREFIX` | `false`, empty, `us-east-1`, empty, `aegis` | optional desktop report/log uploads to HTTPS S3-compatible storage |
| `CLOUD_ACCESS_KEY_ID`, `CLOUD_SECRET_ACCESS_KEY`, `CLOUD_CA_BUNDLE` | empty | restricted upload credentials and optional private CA |
| `CLOUD_CONDITIONAL_WRITES`, `CLOUD_UPLOAD_FULL` | `true`, `false` | create-only writes; explicit full-result opt-in with privacy warning |
| `CLOUD_SPOOL_DIR`, `CLOUD_SPOOL_DAYS`, `CLOUD_SPOOL_MAX_MB` | app cloud_spool, `30`, `1024` | local pending-upload retention, separate from bucket lifecycle |
| `RULEPACK_PUBLIC_KEYS`, `WEIGHTS_OVERRIDE` | empty | trusted rule-pack signers; reviewed weight changes |

> Every setting is checked at start-up; an invalid value stops the program with one line per problem.
>
> The local layers (hashes, fuzzy, macros, YARA, integrity, hidden content, external links, archives) need **no keys at all**. VirusTotal needs a key; the LLM layer needs a running Ollama (recommended) or an OpenAI key.

### Malware-hash dataset

The local database is a CSV with at least the columns `FileName`, `md5Hash`, and `Benign` (`Benign = 0` marks a malicious entry):

```bash
python RansomwareScanner.py --import-database /path/to/your/dataset.csv
```

A suitable dataset can be sourced from public malware-hash collections on Kaggle. The dataset itself is intentionally **not** committed to this repo.

### Fuzzy signature database

Fuzzy hashing matches files against the digests of *confirmed* malicious samples. To grow your own database, print a sample's digests and paste them into a signature entry:

```bash
python RansomwareScanner.py --fuzzy-hash /path/to/confirmed_sample
```

```json
{
  "version": 1,
  "signatures": [
    {"family": "Acme.Locker", "tlsh": "T1...", "ssdeep": "3:...", "note": "source / provenance"}
  ]
}
```

Point the scanner at it with `FUZZY_SIGNATURE_DB` in `.env` (the bundled sample is used otherwise). **Never commit live malware**, only its fuzzy digests.

### YARA rules

Every `.yar` / `.yara` file in `rules/` is compiled automatically. Add your own files there (or point `YARA_RULES_DIR` elsewhere) and give each rule a `severity` meta (`low` / `medium` / `high` / `critical`).

---

## 💻 Usage

```bash
# Launch the graphical interface
python gui.py                                   # or: python RansomwareScanner.py --gui

# Scan
python RansomwareScanner.py --scan-now                       # all configured folders
python RansomwareScanner.py --scan-file suspicious.docx      # one file, full verdict
python RansomwareScanner.py --scan-file mail_attachment.zip  # archives: every member
python RansomwareScanner.py --scan-file setup.iso            # also .7z, .rar, .img, AES ZIP
python RansomwareScanner.py --scan-file suspicious.eml       # e-mail: headers + attachments
python RansomwareScanner.py --scan-file message.msg          # Outlook format too
python RansomwareScanner.py --scan-file x.docx --llm-provider ollama   # force local LLM
python RansomwareScanner.py --scan-now --llm-provider none --no-cache
python RansomwareScanner.py --scan-imap                      # new mail in the IMAP folder, read-only
python RansomwareScanner.py --scan-now --jsonl results.jsonl # also one JSON line per file (SIEM)

# Protection
python RansomwareScanner.py --deploy-canaries [DIR ...]
python RansomwareScanner.py --verify-canaries
python RansomwareScanner.py --resume-pid 4242,4243     # after a false alarm: resume suspended processes
python RansomwareScanner.py --unlock-folders           # give back write access removed by lock_folders
python RansomwareScanner.py --quarantine FILE
python RansomwareScanner.py --list-quarantine
python RansomwareScanner.py --restore ID [--restore-to PATH]
python RansomwareScanner.py --export-key FILE | --import-key FILE [--replace-key]
python RansomwareScanner.py --allow vendor_setup.ps1 --note "checked by IT"   # known-good file

# Background mode: scheduled scans + canary checks (+ the mailbox with IMAP_CHECK_MINUTES)
python RansomwareScanner.py --background
python RansomwareScanner.py --setup-autostart      # at login (Windows / macOS / Linux)
python RansomwareScanner.py --remove-autostart

# Utilities
python RansomwareScanner.py --import-database dataset.csv
python RansomwareScanner.py --fuzzy-hash confirmed_sample.bin
python RansomwareScanner.py --clear-cache
python RansomwareScanner.py --train-ml clean_samples/ malware_samples/   # ML model
python RansomwareScanner.py --create-shortcut      # Windows & Linux
python RansomwareScanner.py --update-rules pack.tar.gz   # signed YARA / fuzzy rule pack
aegis-api                                         # optional REST API (pip install -e ".[api]")
python RansomwareScanner.py --version
```

Scan directories, file types and the scan interval come from `.env` and the defaults in `engine/config.py` (or the GUI's Scan page). All paths are derived from the user's home directory via `pathlib`, so they adapt to the host OS.

### Example report (excerpt)

```
Ransomware Scan Report
======================
Engine version:         4.6.0
Total files scanned:    6
Files flagged:          5
Highest verdict:        Critical
Detection layers used:  hashes, local-db, fuzzy, macro, yara, integrity, elf, pe, script, prompt-guard, relationships, archives, mail, web, embedded, qr, ml, llm, virustotal
LLM posture:            LOCAL (llama3.1)

############################################################
POSSIBLE ACTIVE RANSOMWARE IMPACT - investigate this machine now
############################################################
  Files whose content looks encrypted: 1
    - /home/me/Downloads/Q3_budget.xlsx
  Ransom-note-like files: 1
    - /home/me/Downloads/HOW_TO_DECRYPT.txt

Verdict breakdown:  Critical: 2 | High: 3 | Medium: 0 | Low: 0

============================================================
CRITICAL (2)
============================================================

- File:     /home/me/Downloads/invoice_7731.pdf
  Verdict:  Critical (risk 100/100, severity 10.0/10)
  [YARA]      Rule(s) matched [Embedded_Executable_In_Document] (top severity 'high').
  [Integrity] Windows PE executable disguised with a '.pdf' document extension.
  Score breakdown:
    +  65.0  [technical] yara_match
    +  90.0  [technical] disguised_executable
    = category totals: technical=100.0

- File:     /home/me/Downloads/shipping_docs.zip
  Verdict:  Critical (risk 100/100, severity 10.0/10)
  [Archive]   2 member(s), 37,007 bytes extracted; 1 executable/script member(s); double-extension lure name(s).
              ! double extension: shipping_docs.zip!/DHL_receipt.pdf.exe
              - /home/me/Downloads/shipping_docs.zip!/docs/job_offer_copy.docx: High (risk 70/100)
  Score breakdown:
    +  60.0  [technical] archive_double_extension
    +  35.0  [technical] archive_executable
    +  70.0  [technical] archive_member:external_relationship
    = category totals: technical=100.0

============================================================
HIGH (3)
============================================================

- File:     /home/me/Downloads/Q3_budget.xlsx
  Verdict:  High (risk 70/100, severity 7.0/10)
  [Integrity] Format signature missing and the content is statistically random - consistent with ransomware encryption.

- File:     /home/me/Downloads/job_offer.docx
  Verdict:  High (risk 70/100, severity 7.0/10)
  [External]  remote_template -> hxxp://203.0.113[.]5/tpl.dotm

- File:     /home/me/Downloads/cv_jane.docx
  Verdict:  High (risk 65/100, severity 6.5/10)
  [Hidden]    Concealed content: hidden_attribute.
  [Injection] confirmed prompt-injection attempt: ignore_previous_instructions, verdict_override.
```

A machine-readable `ransomware_scan_<timestamp>.json` with the complete per-layer evidence trail is written alongside the text summary. External URLs in reports are defanged (`hxxp://…[.]com`).

---

## 🪟 Graphical interface

**Aegis Sentinel**, a desktop front-end built with CustomTkinter that uses the scanner as a library. The CLI keeps working on its own, and both share the same configuration, reports, hash database, canaries and vault.

**Dashboard** (screenshot at the top of this page). A status card per layer: hash database, fuzzy hashing (signature count), macro analysis, YARA (rule-file count), VirusTotal, the LLM (**LOCAL vs CLOUD**), and in v4 the heuristic layers, canary tripwires and quarantine vault. Scans run with live per-file progress; each row shows a compact per-layer summary (e.g. `DB– fuzzy– macro! yara✓3 exe! VT 14/72 AI 0.80`) next to a 0–100 risk bar and the verdict. Double-click a row for the full breakdown.

![Result detail](docs/screenshot-detail.png)

**Result detail.** The verdict and risk score, then what every layer concluded, followed by the **weighted score breakdown**. For archives, every member is listed with its own verdict. A **Quarantine file** button moves the file into the vault.

| Archive member breakdown | Prompt-injection finding |
|---|---|
| ![Archive detail](docs/screenshot-v4-archive.png) | ![Injection detail](docs/screenshot-v4-injection.png) |

![Protection page](docs/screenshot-v4-protection.png)

**Monitoring.** Configure watched roots, start/stop monitoring and inspect queue, pause and drop status. Results appear in the dashboard and reports.

**Alerts & cloud.** Configure delivery, test e-mail/upload and inspect pending or expired items. Cloud upload is optional and desktop only.

**Protection.** Export/import the encrypted quarantine key backup. Deploy, verify and remove canaries, set automatic quarantine, restore or delete vault items, and clear the result cache. While the window is open, canaries are re-checked every few minutes and a trigger raises an alert.

![Scan page](docs/screenshot-v4-scan.png)

**Scan, Reports, Database, Logs, Settings.** Monitored directories and file types, past JSON/TXT reports and canary alerts, the malware-hash dataset, the live log stream, the scan schedule, start-at-login, the VirusTotal-upload switch, and API keys. Secrets are saved in the OS keyring; non-secret settings go in the git-ignored `.env` file.

![Settings](docs/screenshot-settings.png)

Engineering notes: scanning and canary checks run in worker threads and talk to the UI through queues (Tkinter is not thread-safe); *Stop* cancels cleanly after the current file. All screenshots show v4.3 (synthetic samples, no LLM or VirusTotal key configured).

### How autostart works per platform

| OS | Mechanism | Where it lives |
|----|-----------|----------------|
| Windows | Registry `Run` key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| macOS | launchd LaunchAgent | `~/Library/LaunchAgents/com.abdelrahman.ransomwarescanner.plist` |
| Linux | systemd **user** service (cron `@reboot` fallback) | `~/.config/systemd/user/ransomware-scanner.service` |

`--remove-autostart` cleanly reverses whichever mechanism was used.

---

## 🧪 Testing

```bash
pip install -e ".[dev]"          # or: pip install -r requirements.lock pytest hypothesis qrcode
python -m pytest                 # ~860 tests: unit, end-to-end, CLI, fuzz, regression (+1 opt-in GUI test)
python -m pytest --cov           # coverage report; CI fails under 85 %
ruff check . && mypy             # lint (incl. complexity < 20, lazy logging) and types, also in CI
bandit -r engine detectors core api -ll   # security linter, also in CI
python test_smoke.py             # the original v3 smoke test, still passing

# optional: the GUI test drives the real window (needs a display)
RUN_GUI_TESTS=1 xvfb-run -a python -m pytest tests/test_gui_smoke.py
```

Every push and pull request runs the suite on **Windows, macOS and Linux** with Python 3.9 and 3.12 (GitHub Actions, `.github/workflows/tests.yml`).

The suite covers each detector and protection feature in isolation, the full scan pipeline, the CLI commands, and the GUI flow (scan → quarantine → restore → canary trigger). Highlights:

- the encrypted-content heuristic accepts 200 random samples at each size and rejects compressed Office files, gzip, and text,
- quarantine detects bit flips, truncation, chunk reordering and a wrong key, and never leaves partial files behind,
- zip-slip members are never written, and the extraction sandbox is gone after the scan,
- hostile XML (entity expansion) is refused rather than parsed,
- VirusTotal is never asked to upload anything unless explicitly enabled,
- forged lower `Authentication-Results` headers are ignored, and `.msg` parsing is tested on real compound files generated by the suite (`tests/msg_builder.py`),
- AES ZIP, 7z (including encrypted file names) and ISO archives are built at test time and hit the same bomb / slip limits as ZIP,
- RAR archives (built at test time, plus rarfile's encrypted RAR 5 fixtures) hit the same checks, and still report lure names with no decompressor installed,
- a Packager OLE object labelled `invoice.pdf` is scanned as the `invoice.pdf.exe` it really is,
- a forged KeePass/GPG header on an encrypted `.xlsx` is still scored as encrypted content,
- canary watching fires on modify, rename and ransom notes, coalesces bursts, and doesn't loop on its own reads,
- a trained ML model round-trips through disk with identical predictions, and foreign or stale model files fall back to the rule engine.

All test samples are **synthetic** and built at test time (a relationship pointing at a documentation IP, an `MZ` header, random bytes, a ZipCrypto archive). No live malware is stored or used.

### Measuring detection on real samples

The unit tests prove each check works; `tools/evaluate.py` measures how the engine does on real files. Point it at a folder of malicious samples and a folder of benign files (for example MalwareBazaar samples and Govdocs1 / SpamAssassin files, kept in an isolated VM):

```bash
python tools/evaluate.py --malicious ~/samples/malicious --benign ~/samples/benign \
                         --labels ~/samples/labels.csv --out eval_out
```

It reports the detection rate and the false-positive rate at the Low, Medium and High thresholds, broken down by file type, malware family (from an optional `sha256,type,family` CSV) and folder, plus every miss and every false alarm with the indicators behind it (`eval_out/summary.md`, one row per file in `eval_out/results.csv`). It measures the **engine only** by default: VirusTotal, the LLM layer and the cache are off, because a reputation hit on a known sample says nothing about the detection logic (`--with-vt` / `--with-llm` measure the full product). Each file is scanned in a worker process with a time limit, so one pathological file cannot stop the run.

#### Dataset credits

Evaluation runs on public research datasets that are **not** redistributed in this repository. If you use the CIC-Trap4Phish 2025 dataset, cite:

> F. Nejati, M. Rabbani, M. Eskandarian, M. Mirani, G. Piya, I. Opushnyev, A. A. Ghorbani, and S. Dadkhah, "CIC-Trap4Phish: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection," arXiv:2602.09015, 2026. Canadian Institute for Cybersecurity, University of New Brunswick. https://www.unb.ca/cic/datasets/trap4phish2025.html

The dataset is licensed for non-commercial use (CC BY-NC 4.0).

---

## 📂 Project structure

```
hybrid-ransomware-detector/
├── RansomwareScanner.py         # CLI entry point (scan, --scan-imap, protection, --allow, --update-rules, --jsonl)
├── gui.py                       # desktop app entry point (Aegis Sentinel)
├── aegis_gui/                   # the desktop app: common, formatting, state, widgets, detail, pages/, app
├── engine/                      # the scanner itself
│   ├── config.py                # version, per-user paths, .env, CONFIG; init_runtime() (no import side effects)
│   ├── validation.py            # start-up configuration checks
│   ├── logs.py, metrics.py      # text / JSON logging; runtime counters (/metrics)
│   ├── scanner.py               # RansomwareScanner facade: engines, folder walks, runs
│   ├── staging.py               # pipeline runner, layer guard, heavy-layer gate
│   ├── protection.py            # quarantine and canary handling
│   ├── layers.py                # the ordered detection layers; ScanContext (file read once)
│   ├── workers.py               # isolated, parallel folder scans (timeout, memory limit)
│   ├── containers.py            # mail / archive / web / embedded content, re-scanned recursively
│   ├── external.py              # LLM + VirusTotal lookups (cached)
│   ├── text.py                  # text and string extraction
│   └── report.py                # text + JSON reports
├── detectors/                   # independently-optional detection engines
│   ├── indicators.yaml          # THE registry: weights, caps, categories, labels
│   ├── registry.py, scoring.py  # loads the registry; one scorer per layer (SCORERS)
│   ├── signals.py               # typed signals: the contract between layers and scorers
│   ├── pe_analysis.py           # Windows PE: sections, imports, T1490 commands, overlay
│   ├── file_integrity.py        # magic bytes, disguised executables, encrypted content
│   ├── macro_analysis.py        # olevba VBA/XLM triage + VBA stomping
│   ├── yara_engine.py, fuzzy_hash.py, tlsh_py.py (TLSH port for Windows), entropy.py
│   ├── prompt_guard.py          # hidden content + prompt-injection detection
│   ├── relationship_scanner.py  # remote template / Follina / UNC / RTF links
│   ├── container_extractor.py   # ZIP / AES ZIP / 7z / RAR / ISO, bomb / slip / lures
│   ├── mail_analyzer.py         # MailGuard: auth, spoofing, links, attachments, archive passwords
│   ├── web_content.py           # HTML smuggling, SVG, phishing forms
│   ├── script_analysis.py       # JS / VBS / HTA / PS1 / BAT, layered deobfuscation
│   ├── embedded_content.py      # OneNote / CHM / MSI / XLL / password-protected Office
│   ├── elf_analysis.py, qr_scanner.py, macos_packages.py
│   ├── emulation.py             # optional box-js JavaScript emulation
│   ├── ml_classifier.py, llm_backends.py, cfb_writer.py
├── core/                        # host-side services
│   ├── quarantine.py            # AES-256-GCM vault, verify-before-delete
│   ├── canary.py, canary_watch.py
│   ├── allowlist.py             # known-good SHA-256 hashes
│   ├── rulepack.py              # signed rule-pack verify / install
│   ├── sandbox.py               # optional CAPEv2 client
│   ├── mailbox.py               # IMAP mailbox scanning (read-only, TLS)
│   ├── response.py              # canary response actions (stop writers, lock folders, network off, script)
│   ├── containment.py           # find / suspend the writing process; folder lock and unlock
│   ├── tools.py                 # helper programs found outside the current directory
│   ├── outputs.py               # JSON Lines + signed webhook
│   ├── cache.py, http.py
├── api/                         # result JSON schema + optional REST API (FastAPI) + abuse limits
├── rules/                       # YARA rules (23 original rules in five files)
├── tools/                       # evaluate, calibrate_weights, profile_layers, build_fuzzy_db, rulepack, mbox_to_eml
├── tests/                       # pytest suite (synthetic samples only), incl. fuzz + regression corpus
├── fuzz/                        # atheris harness for long coverage-guided fuzzing
├── docs/                        # ARCHITECTURE.md, THREAT_MODEL.md, DEPLOYMENT.md, DETECTION_v3/v4.md, screenshots
├── .github/workflows/           # tests (3 OS), quality gates (lint, types, bandit, coverage, audit, regression), release
├── pyproject.toml               # package metadata, extras, tool configuration
├── requirements.txt             # loose requirements; requirements.lock = pinned versions
├── build.py, scanner.spec       # PyInstaller build + smoke test + packaging
└── CHANGELOG.md, .env.example, LICENSE, README.md
```

See [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md) for the design of the v4 layers (and [`docs/DETECTION_v3.md`](docs/DETECTION_v3.md) for the earlier ones), and [`CHANGELOG.md`](CHANGELOG.md) for the version history.

---

## 🏗️ Engineering

How the project is built to be trusted, not only to detect. Details in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

- **One indicator registry.** Every weight, category cap and label lives in `detectors/indicators.yaml`; scoring, the desktop app and the calibration tool read it. Reports record the registry version. Reviewed changes can be applied as an override file (`WEIGHTS_OVERRIDE`) without editing code.
- **Isolation.** Folder and API scans run each file in a worker process with a time limit and a memory limit (RLIMIT_AS on Linux, a Job Object on Windows, a resident-memory watchdog on macOS); a file that hangs or kills a worker is reported as `scan_failed`. Inside a scan, every layer runs in a guard, so a failing parser only loses its own evidence (`layer_errors`). Each file is read once and shared by the layers that need all its bytes.
- **Fuzzed parsers.** Every parser is fuzzed in the suite (Hypothesis) and can be fuzzed for hours with atheris (`fuzz/`). Fuzzing found a ZIP that ended a scan (fixed); `pip-audit` found a parser hang in PyPDF2 (CVE-2023-36464), fixed by moving to `pypdf`.
- **Typed contracts.** Layers fill typed signal dataclasses and each layer has one scorer function; mypy checks both sides, so a renamed field is a type error, not a silent missed detection.
- **Quality gates in CI.** ruff (lint, import order, bug and security patterns, cyclomatic complexity under 20, lazy log arguments), bandit, mypy over every engine and detector module, an 85 % coverage floor, `pip-audit` on the pinned lock file, and a 13-file regression corpus whose verdicts, scores and indicators must not change unintentionally.
- **Integration.** A versioned JSON schema for results (`api/scan_result.schema.json`), JSON Lines output (`--jsonl`), HMAC-signed webhook alerts (`WEBHOOK_URL`), an optional REST API (`aegis-api`: token-protected, rate-limited, size-limited before parsing, isolated scans), structured JSON logs and Prometheus metrics.
- **Signed detection content.** Rules and fuzzy signatures can be updated without a new release: `tools/rulepack.py` builds and Ed25519-signs a pack; `--update-rules` installs it only if the signature, manifest hashes, version and rule compilation all check out.
- **Releases.** Pushing a `v*` tag builds and smoke-tests binaries on Windows, macOS and Linux, then publishes them with SHA-256 sums, a CycloneDX SBOM and keyless Sigstore signatures (pre-release for `-beta` tags).

---

## 🌐 Cross-platform & architecture notes

- **OS-aware paths:** all runtime paths (app dir, logs, reports, vault, cache) are built from `Path.home()`; nothing is hardcoded to one OS.
- **No architecture lock-in:** dependencies are pure Python or ship x86_64 and ARM64 wheels (Windows/macOS/Linux), including Apple Silicon.
- **Tested** in CI on Windows, macOS and Linux with Python 3.9 and 3.12, and the GUI headlessly on Linux. The code avoids OS-specific APIs outside the autostart and notification helpers, which branch per platform.
- **Graceful degradation:** missing libraries, keys, OCR binaries or scan folders produce warnings, not crashes.

---

## ⚠️ Limitations

Being explicit about what the tool does *not* do:

- **Static analysis by default.** Nothing is executed. Behaviour that only shows at run time (a payload downloaded later, environment checks) is missed unless you turn on JavaScript emulation (`EMULATION_ENABLED`, box-js) or connect your own CAPEv2 sandbox (`SANDBOX_URL`); both are off by default and belong in an analysis VM.
- **Archives:** ZIP (ZipCrypto and AES), 7z, RAR and ISO/IMG. RAR contents need an external decompressor (7-Zip, unrar, unar or bsdtar); without one only the member names are checked. Multi-volume RAR sets are not reassembled. Encrypted archives open only with a password from the built-in delivery list or one written in the e-mail that carried them. Archives with more than 500 entries are partly unpacked (programs and scripts first; every name is still checked).
- **Encrypted-content detection** needs at least 1 KiB of data, and a raw, headerless compressed stream can look as random as ciphertext. That is why it only runs once a document's own signature is already missing.
- **E-mail authentication** is read from the headers your server recorded, not re-verified. A message saved without transport headers (drafts, sent items, some exports) has no SPF/DKIM/DMARC verdict; scan the mailbox with `--scan-imap` to get messages as delivered. Microsoft Graph (Exchange Online without IMAP) is not supported yet. OLE objects that are neither a packaged file nor an Office/PDF document are counted but not unpacked; Equation Editor 3.0 objects (the CVE-2017-11882 exploit carrier) are flagged by YARA in RTF and legacy Office files.
- **The ML layer is only as good as its training data.** No model ships with the project (a model trained on synthetic data would claim accuracy it doesn't have). The rule engine flags any non-compressed file that is random throughout, which can include legitimate encrypted files. KeePass, GPG, age, LUKS and `openssl enc` files with their normal extension are recognised; other encrypted formats are not (PDFs whose object structure is intact are). That's why the layer is capped at 20 points.
- **Hidden-content detection** covers Word, Excel, PowerPoint (OOXML), PDF, and hidden / very hidden sheets in legacy `.xls` workbooks. Legacy `.ppt` and conditional-formatting tricks are not inspected.
- **Canaries are a rapid-containment tripwire, not prevention.** They fire about a second after a canary in a watched folder changes. `stop_writers` then suspends the process that has files open there for writing. Ransomware that opens, encrypts and closes each file in a few milliseconds may have no file open at that moment and is not found; the folder lock and network cut still apply. Files encrypted before the trip stay encrypted. Stopping a process *before* it writes needs kernel-level hooks (an EDR); on Windows, Controlled Folder Access is the built-in blocker.
- **Quarantine key** is stored locally (`~/RansomwareScanner/keystore`, mode 0600). Use `--export-key` to back it up; a lost key and no backup means quarantined items can't be restored.
- **Detection content is a starting point:** the bundled YARA rules are original triage heuristics and the fuzzy database ships empty. Real coverage grows with your own signatures.
- **Windows programs: static structure only.** The PE layer reads headers, sections, imports and strings. Code that resolves its APIs at run time, unpacks itself in memory or is protected by a strong packer shows only as *packed* or *hidden imports*. Authenticode signatures are reported, not verified against the Windows trust store. Delay-load imports are read in their modern (RVA) form; the old VC6 form is not.
- **Detection rate on real malware is not measured yet.** False alarms are (0.7% High/Critical on 3,713 benign files, including 401 Windows binaries); `tools/evaluate.py` measures detection on your own labelled samples.

---

## 🧭 Roadmap

Delivered in v4.6.0: Windows PE analysis, process containment and folder locking for canaries, memory limits on every OS, typed signals and per-layer scorers, start-up validation, JSON logs, metrics and API abuse limits. Delivered in v4.5.0: IMAP mailbox scanning, canary response actions and optional JavaScript emulation. Delivered in v4.4: QR codes, ELF, scripts, the optional CAPEv2 sandbox, signed releases and the benign-corpus benchmark. Delivered in v4.3.0: RAR archives and OLE objects in Outlook messages. Delivered in v4.2.0: AES ZIP / 7z / ISO, Excel and PowerPoint hidden content, nested Outlook items, quarantine key backup, vault-aware ML, and real-time canary watching. Delivered in v4.1.0: MailGuard (.eml/.msg), the static ML classifier and standalone executables. Delivered in v4.0.0: file-integrity and ransomware-impact detection, prompt-injection defence, Office external-link analysis, archive inspection, VBA-stomping/XLM detection, canary tripwires, the quarantine vault, and safer external calls (see the [changelog](CHANGELOG.md)). Next:

- **Microsoft Graph mailbox scanning** for Exchange Online tenants that disable IMAP.
- **A curated, labelled training corpus** and published ML evaluation numbers.
- **Windows toast notifications** for canary alerts (macOS and Linux are supported today).
- **Richer detection content:** a broader YARA rule set and a curated starter fuzzy-signature database.

---

## 🚨 Disclaimer

This project is for **educational and defensive** purposes only: identifying potentially malicious documents. Do not use it to create or distribute malware. Always analyse untrusted files in an isolated environment.

## 👤 Author

**Abdelrahman El-Maghraby**, Cybersecurity Specialist
[LinkedIn](https://www.linkedin.com/in/abdelrahman-el-maghraby/)

Released under the [MIT License](LICENSE).
