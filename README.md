# 🛡️ Hybrid Ransomware Detection System

*Desktop app name: **Aegis Sentinel**.*

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/version-4.4.0--beta.2-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Arch](https://img.shields.io/badge/Arch-x86__64%20%7C%20ARM64-lightgrey)

A multi-layered scanner that inspects **PDF, Microsoft Office (Word / Excel / PowerPoint), RTF documents, archives (ZIP, 7z, RAR, ISO) and e-mails (.eml / Outlook .msg)** for ransomware and other malicious indicators. It fuses **twelve independent detection layers** through a **transparent weighted scoring matrix** that produces a 0–100 risk score, a verdict band, and a report showing *why* each file scored what it did. Around the scanner sit two host-side protections: **ransomware canary tripwires** and an **AES-256-GCM encrypted quarantine vault**.

Runs on **Windows, macOS, and Linux** (x86_64 and ARM64), from the command line or a desktop GUI, with optional autostart at login.

Originally built as my B.Sc. graduation project as a three-layer scanner. v3 added structural detection (fuzzy hashing, macros, YARA), a local-first LLM, and the weighted scoring matrix. v4 adds file-integrity and ransomware-impact detection, prompt-injection defence for the LLM layer, Office external-link analysis, safe archive inspection, canaries, and quarantine. v4.1 adds e-mail analysis (MailGuard), a static ML classifier, and standalone executables. v4.2 refactors the engine into an explicit pipeline and adds 7z/ISO/AES-ZIP, Excel and PowerPoint hidden content, quarantine key backup and real-time canary watching; v4.3 adds RAR and OLE objects in Outlook messages. It is intended for **defensive and educational use**: analysing suspicious documents, not creating malware.

---

## 📖 Table of Contents

- [🧪 What's new in 4.4 (beta)](#-whats-new-in-44-beta)
- [🆕 What's new in 4.3](#-whats-new-in-43)
- [🆕 What's new in 4.2](#-whats-new-in-42)
- [🆕 What's new in 4.1](#-whats-new-in-41)
- [🆕 What's new in 4.0](#-whats-new-in-40)
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
- [🌐 Cross-platform & architecture notes](#-cross-platform--architecture-notes)
- [⚠️ Limitations](#️-limitations)
- [🧭 Roadmap](#-roadmap)
- [🚨 Disclaimer](#-disclaimer)
- [👤 Author](#-author)

---

## 🧪 What's new in 4.4 (beta)

> **Pre-release.** These checks are new and are being validated on real samples. The stable release is 4.3.1; nothing below changes how the file types 4.3.1 already supported are scored (the regression corpus gives identical verdicts).

- **HTML and SVG attachments.** HTML smuggling (a payload hidden in the page as base64 and rebuilt in the browser with `Blob` + an object URL / download link) is detected, and the hidden payload is decoded and scanned through the whole pipeline. Also flagged: SVG images with active content (scripts, event handlers, embedded HTML), password forms posting to an external host, redirects and script obfuscation. Nothing is executed or fetched.
- **Images.** A payload appended after the end of a PNG, JPEG, GIF, BMP or WEBP image, and an executable renamed to an image extension. Pictures are supported but not part of folder scans by default; inside archives and e-mails they are always checked.
- **macOS installers.** `.pkg` packages are read in Python (install scripts and payload unpacked); `.dmg` disk images are opened through 7-Zip when it is installed. An installer's programs and scripts are listed and each one is scanned, but they are not scored just for being there, and a large app image is reported as not unpacked rather than as a decompression bomb.
- Image, SVG and installer handling are covered by 62 tests.
- **QR codes (beta.2).** Phishing links hidden in QR codes ("quishing") in images, PDF pages, Office documents and e-mail attachments are decoded and judged: bare IP addresses, punycode, `user@host` tricks, URL shorteners and script schemes are suspicious on their own; plain HTTP, throw-away TLDs and lure words count only in pairs. Links are defanged in reports. Decoding needs `pip install pyzbar` plus the zbar library (`brew install zbar`, `sudo apt-get install libzbar0`; the Windows wheel includes it) or `opencv-python-headless`; without either, the report says QR codes were not checked.
- **Linux ELF files (beta.2).** Header, packing (UPX or near-random content), a stripped section table, and behaviour strings: ransom notes, cryptominer pools, reverse shells, download-and-run one-liners, log/firewall tampering and persistence. Nothing is executed.
- **Faster scans (beta.2).** The slow layers (ML, LLM, VirusTotal) run last and in parallel, and are skipped when the local layers already reach 100 (the verdict cannot change; the report lists them under `[Skipped]`). Set `SKIP_HEAVY_WHEN_SATURATED=false` or `PARALLEL_HEAVY_LAYERS=false` to turn either off.
- **Script attachments (beta.2).** `.js`, `.vbs`, `.hta`, `.wsf`, `.ps1`, `.bat` and their encoded variants: download and execute primitives, shadow-copy deletion and other recovery tampering, Defender/AMSI tampering, persistence and obfuscation. PowerShell `-EncodedCommand` payloads are decoded. Download *plus* execute (a dropper) is High; either one alone, as in many admin scripts, stays Low.
- **Password in the e-mail (beta.2).** "Password: 4471" in the subject or body (eleven languages) is tried on the mail's encrypted ZIP / 7z / RAR attachments before the built-in list, so the contents are scanned; using it adds a 30-point technical signal.
- **Encoded scripts (beta.2).** `.vbe` / `.jse` (Windows Script Encoder) are decoded and the real source is analysed.
- **Fuzzy database builder (beta.2).** `python tools/build_fuzzy_db.py SAMPLES_DIR --out fuzzy_signatures.json --benign BENIGN_DIR`, run inside the analysis VM, turns confirmed samples into TLSH/ssdeep signatures, drops near-duplicates and any signature that matches a benign file. Only digests leave the VM.
- **Layered obfuscation (beta.2).** Scripts are unwound up to five nested encodings (base64 inside a Chr() chain inside a reversed string ...), and every layer is analysed.
- **OneNote, CHM, MSI, XLL, password-protected Office (beta.2).** The files these carry are carved out or decrypted and scanned like attachments; XLL add-ins and CHM command objects are flagged. Locked Office documents are opened with the password from the e-mail when there is one (`pip install msoffcrypto-tool`).
- **Allowlist (beta.2).** `python RansomwareScanner.py --allow vendor_setup.ps1 --note "checked"` adds a known-good SHA-256; the file is still scanned and reported but not scored.
- **Optional sandbox (beta.2).** Point `SANDBOX_URL` at your own [CAPEv2](https://github.com/kevoreilly/CAPEv2) server and suspicious top-level files are detonated there; behaviour signatures (shadow-copy deletion, encryption, injection ...) are scored in a new *dynamic* category. Nothing is sent anywhere else, and it is off by default.
- **Calibration (beta.2).** `python tools/calibrate_weights.py --malicious DIR --benign DIR --out calib` proposes scoring weights from labelled data, with cross-validated detection and false-alarm rates, for review.
- **Tools (beta.2).** `python tools/mbox_to_eml.py OUT_DIR corpus.mbox` splits mbox mailboxes into `.eml` files for scanning and evaluation.
- HTML smuggling now has automated tests (embedded ZIP and executable payloads, split strings, `msSaveOrOpenBlob`, data-URI anchors, phishing forms).


- **RAR archives** (RAR 4 and RAR 5, including encrypted members and encrypted file names). Names, sizes, symlinks and encryption are read in Python by `rarfile`, so the lure, slip and limit checks always run. Decompressing needs a program that is usually already installed: 7-Zip (found in Program Files on Windows automatically), `unrar`, `unar` or `bsdtar`. The tool is only asked to stream one member to stdout, never to write files, so its own path handling is never trusted.
- **OLE objects in Outlook messages.** A file pasted into a mail as an icon (the Packager trick: the icon says `invoice.pdf`, double-clicking runs `invoice.pdf.exe`) is unpacked under its **real** name and scanned. Embedded Word/Excel/PowerPoint files and PDFs are extracted too; legacy `.doc/.xls/.ppt` objects are repacked as standalone files so the macro layer can read them. This also works inside forwarded Outlook items.

---

## 🆕 What's new in 4.2

Seven limitations listed in 4.1, closed:

- **More archive formats.** AES-encrypted ZIPs (`pyzipper`), **7z** including archives whose file names are encrypted (`py7zr`), and **ISO / IMG** disc images, a common way to smuggle executables past Mark-of-the-Web (`pycdlib`). All three use the same bomb / slip / member-count limits as ZIP, the same delivery-password list, and nest inside each other (ISO → 7z → ZIP → document). Without the library the report says the archive could not be opened and which `pip install` fixes it.
- **Excel and PowerPoint hidden content.** Hidden and *very hidden* sheets, hidden rows and columns that hold text, white text, ≤ 2 pt fonts, hidden shapes and slides, and text placed outside the visible slide. Prompt-injection phrases inside any of them count as confirmed attempts, as in Word.
- **Outlook items inside Outlook items.** A forwarded `.msg` attached to a `.msg` is rebuilt as `.eml` with its own headers and attachments and scanned like any other attached mail (up to 3 levels).
- **Quarantine key backup.** `--export-key` writes the key encrypted with a passphrase (scrypt + AES-GCM); `--import-key` installs it on another machine. A different existing key is never replaced unless you add `--replace-key`, and the old one is kept as a backup.
- **Fewer ML false positives on password vaults.** KeePass (`.kdbx`), GPG (`.gpg/.pgp`) and age (`.age`) files are recognised by header *and* extension. Only the ML layer uses this: the encrypted-content check ignores it, so ransomware can't hide an encrypted `.docx` by prepending a vault header.
- **Real-time canary watching.** With `watchdog` installed, canary folders are watched for file events and verified about a second after a canary is changed, renamed or a ransom note appears, in `--background` and in the GUI. The interval check stays as a safety net.

---

## 🆕 What's new in 4.1

![MailGuard result](docs/screenshot-v41-mail.png)

- **MailGuard: `.eml` and Outlook `.msg` e-mails.** Reads the SPF / DKIM / DMARC verdicts your mail server recorded (only the *topmost* `Authentication-Results`: lower copies are written by the sender and can be forged), flags display-name spoofing, Reply-To diversion and links whose text shows one domain while the href goes to another, and unpacks every attachment (including attached e-mails and ZIPs) into a sandbox for the full pipeline. The message body feeds the prompt-injection and LLM layers. `.msg` files are read stream-by-stream with `olefile`, so no extra dependency is needed.
- **Static ML classifier.** 15 explainable byte and PE features (entropy profile, packer section names, writable+executable sections, import count, …). Train a RandomForest on your own labelled folders with `--train-ml`, and it reports held-out precision, recall and false-positive rate. Without a model, a transparent rule engine runs. ML has its own small **statistical** score budget (≤ 20) and, like the LLM, can never push a file past Medium on its own.
- **Standalone executables.** `python build.py` packages the CLI and the GUI with PyInstaller, then **smoke-tests the binary with real scans** before packaging it with a SHA-256 checksum.
- **210 automated tests** (+1 opt-in GUI test), including real Outlook compound files built at test time, run on Python 3.9, 3.11, 3.12 and 3.13.

---

## 🆕 What's new in 4.0

![Dashboard v4](docs/screenshot-v4-dashboard.png)

- **File integrity & ransomware impact.** Flags executables disguised as documents (`invoice.pdf` that is really a PE, ELF, Mach-O, `.lnk` or script) and documents that have **already been encrypted** (format signature gone, bytes statistically random), including intermittent encryption that only scrambles the first few KB.
- **Prompt-injection defence.** Detects hidden text in Word files and PDFs (hidden runs, 1–2 pt fonts, white text, invisible PDF render mode) and text aimed at an AI analyst ("ignore previous instructions…"). LLM prompts now wrap the document in per-request random delimiters.
- **Office external links.** Remote template injection (T1221), Follina-style OLE links (CVE-2022-30190), `ms-msdt:` / `search-ms:` handlers and NTLM-leaking UNC paths: the macro-less document attacks.
- **Archive inspection.** ZIP files (including nested and password-protected ones) are unpacked into a sandbox; zip bombs, zip slip, double extensions (`receipt.pdf.exe`) and RTLO filename spoofing are flagged, and **every member goes through the full pipeline**.
- **Macro upgrades.** VBA stomping (P-code vs source mismatch) and Excel 4.0 (XLM) macro sheets.
- **Canary tripwires** that turn the background mode into a near-real-time ransomware alarm, and an **encrypted quarantine vault** with verify-before-delete.
- **Safer external calls.** VirusTotal is now **hash-lookup only by default** (uploads are opt-in), requests have timeouts, retries and quota pacing, and VirusTotal/LLM answers are cached by SHA-256.
- **146 automated tests** (unit, end-to-end, CLI and GUI), run on Python 3.9, 3.11, 3.12 and 3.13.

Full details in the [changelog](CHANGELOG.md) and [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md).

---

## 🧩 Why "hybrid"?

Most lightweight scanners rely on a single technique (usually a hash lookup), which misses anything not already in a database. This tool layers complementary approaches (exact, structural, behavioural, reputational, and semantic) so a file flagged by **any** of them is surfaced, and the **weighted scoring matrix** makes the verdict reflect *which kind* of evidence fired. A real exec primitive in a macro counts for far more than a phishing-flavoured sentence.

```mermaid
flowchart TD
    A[PDF / Office / RTF<br/>ZIP / 7z / RAR / ISO<br/>EML / MSG] --> B[1. Hashes + local DB<br/>exact known-bad]
    A --> C[2. Fuzzy hashing<br/>TLSH / ssdeep families]
    A --> D[3. Macro analysis<br/>VBA, XLM, stomping]
    A --> E[4. YARA rules<br/>structural IOCs]
    A --> F[5. File integrity<br/>disguise / encryption]
    A --> G[6. Hidden content<br/>prompt injection]
    A --> H[7. External links<br/>RTI / Follina / UNC]
    A --> I[8. Archive inspection<br/>ZIP, 7z, RAR, ISO<br/>bomb / slip / lures]
    A --> J[9. VirusTotal<br/>hash reputation]
    A --> K[10. LLM semantic<br/>local-first, spotlighted]
    A --> L[11. MailGuard<br/>SPF / DKIM / DMARC, spoofing<br/>attachments, OLE objects]
    A --> P[12. ML classifier<br/>byte + PE structure]
    I -. members re-scanned .-> A
    L -. attachments re-scanned .-> A
    B & C & D & E & F & G & H & I & J & K & L & P --> M[Weighted scoring matrix]
    M --> N[Risk 0-100 + verdict band<br/>+ explainable JSON / TXT report]
    M --> Q[Optional auto-quarantine<br/>AES-256-GCM vault]
    T[Canary tripwires<br/>watched in real time] --> R[Alert file + desktop notification]
```

Signals fall into four weight categories: **technical** (everything structural, including MailGuard), **reputation** (VirusTotal), **semantic** (LLM and lure wording), and **statistical** (ML classifier). Technical evidence is designed to mathematically outweigh the others: semantic and statistical signals together can never push a file past Medium. Archives and e-mails send every member or attachment back through all layers (dotted arrows), and the container is scored like its most dangerous member.

---

## 🔬 Detection layers

1. **Cryptographic hashing + local hash database.** MD5 and SHA-256 with chunked reads (constant memory), and an O(1) lookup of the MD5 against a streamed CSV of known-malicious hashes. Instant, offline detection of known samples.
2. **Fuzzy / structural hashing (polymorphic families).** **TLSH** and **ssdeep** (pure-Python `ppdeep`) digests compared against a signature database of *confirmed* malicious samples. The digests stay *similar* when a file stays *structurally similar*, which catches polymorphic variants whose exact SHA-256 has never been seen.
3. **Macro analysis (Office dropper mechanism).** `oletools` / `olevba` statically extract and triage VBA and XLM macros **without executing them**: auto-run triggers (`AutoOpen`, `Document_Open`, …), execution/download primitives (`Shell`, `CreateObject`, `URLDownloadToFile`, `powershell`, …), other suspicious calls, and IOCs. v4 adds:
   - **VBA stomping**: the visible source was replaced while the compiled P-code (what Office actually runs) still holds the payload. The mismatch is itself strong evidence of evasion.
   - **Excel 4.0 (XLM) macro sheets**, a favourite of Emotet/Qakbot loaders, in both `.xls` (BIFF) and OOXML workbooks.
4. **YARA rules engine (structural IOCs).** Compiles every `.yar` / `.yara` file in `rules/` and scans each file. Rules carry a `severity` meta the scoring matrix reads. 21 original rules ship in five files: ransom-note language, extortion + urgency, Bitcoin addresses with payment context, PowerShell download cradles, Office dropper structures, PDF auto-launch actions, executables disguised as documents, **shadow-copy deletion and boot-recovery tampering** (MITRE T1490), and since 4.4.0-beta.2 shortcuts that start a script host, HTML Applications, Script Encoder output, OneNote notebooks with embedded scripts, LOLBin downloads, Defender tampering, bulk stopping of database/backup services, Safe Mode boot, event-log clearing, encryptor binaries (target-extension lists + crypto APIs) and Tor ransom notes. Only matched string identifiers are recorded, never the raw bytes.
5. **File integrity: disguise and encryption (new).** Reads the file's real format from its magic bytes and compares it with the extension.
   - **Disguised executables**: a PE (validated `MZ` → `PE\0\0` header), ELF, Mach-O, Windows shortcut (`.lnk`) or `#!` script behind a document extension.
   - **Encrypted content** (ransomware *impact*, T1486): the format signature is missing **and** the bytes are statistically random. Randomness is judged with Shannon entropy compared to what truly random data of the same length would reach, plus a chi-square uniformity test. Checking the first 4 KiB separately catches intermittent encryption. Because .docx/.xlsx and most PDFs are compressed (and therefore high-entropy), the randomness test only runs when the expected signature is already gone. That avoids the false positives a plain entropy threshold produces.
   - Formats Office opens natively under another extension (HTML exported as `.xls`, RTF saved as `.doc`, password-protected `.docx` stored as OLE) are noted but not scored.
6. **Hidden content & prompt injection (new).** Finds concealed text in `.docx/.docm` (hidden runs, ≤ 2 pt fonts, near-white text without background shading), Excel (hidden / very hidden sheets, hidden rows and columns, white or tiny text; 4.2), PowerPoint (hidden shapes and slides, off-slide text, tiny text; 4.2) and PDFs (text render mode 3, i.e. invisible), and looks for phrasing aimed at an AI analyst ("ignore previous instructions", "mark this file as clean", chat-template tokens, …). An injection phrase inside concealed text is a **confirmed** attempt. A phrase in plainly visible text is only **suspicious**, because articles *about* prompt injection contain the same words. XML is parsed with `defusedxml`.
7. **Office external links (new).** Reads the relationship parts inside OOXML files and RTF control words, **without contacting any URL**:
   - remote template injection (`attachedTemplate` → `http://…`, T1221),
   - external OLE objects, and Follina-style links ending in `!` (CVE-2022-30190),
   - exploit URI schemes in any relationship (`ms-msdt:`, `search-ms:`, `ms-officecmd:`, `mhtml:`, …),
   - UNC / `file://host` paths that make Windows send the user's NTLM hash to the attacker (T1187),
   - RTF `{\*\template http://…}` and auto-updating OLE links (`\objupdate`).
8. **Archive inspection (new).** ZIP archives (and, since 4.2, AES ZIP, 7z and ISO/IMG; since 4.3, RAR) are unpacked into a temporary sandbox with hard limits (nesting depth, member count, total and per-member decompressed size, compression ratio). It reports **zip bombs**, **zip slip** (path traversal, absolute paths, symlinks; such members are never written), executables/scripts/shortcuts inside the archive (by extension *and* magic bytes), **double extensions** (`invoice.pdf.exe`) and **right-to-left-override** names. Encrypted members are tried against a short list of delivery passwords ("infected", the archive's own name, …). Up to 25 members per archive go through all the other layers, and the archive is scored like its most dangerous member.
9. **VirusTotal (threat intelligence).** Looks the file's SHA-256 up via the v3 API and reads how many engines flag it. **Privacy by default:** unknown files are *not* uploaded (an upload shares the document with VirusTotal and its Enterprise subscribers); set `VT_UPLOAD_UNKNOWN=true` to opt in. Requests are paced to the free quota (4/min), retried with backoff on 429/5xx, time out after 30 s, and answers are cached for 24 h.
10. **LLM semantic analysis (local-first, OPSEC-preserving).** Extracts visible text (PyPDF2 / python-docx / OOXML parts, with **OCR fallback** for scanned PDFs when an LLM is active) plus printable strings, and asks an LLM whether it reads like a ransomware/phishing lure.
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

Every optional layer **degrades gracefully**: a missing library, a missing local model, or a missing API key produces a warning, not a crash, and the remaining layers still run.

---

## ⚖️ Weighted scoring matrix

The original hardcoded equation (`10·db + 5·llm + 5·vt`) gave a *semantic* guess the same weight as multi-engine reputation. `detectors/scoring.py` replaces it with a transparent matrix: every signal contributes through an explicit rule with a **category**, a **weight**, and a human-readable **detail**, under three principles:

1. **Technical > semantic, mathematically.** The semantic (LLM) category is capped at 24, so a phishing lure can never by itself out-score a real structural indicator.
2. **Semantic-alone cannot be "High".** If no technical or reputation signal fired, the verdict is clamped to at most **Medium**. The same holds for the 4.1 **statistical** (ML) category.
3. **Explainability.** Each result carries a per-indicator breakdown, so the report shows exactly which signals drove the verdict and by how much.

| Indicator | Category | Points |
|---|---|---:|
| Local hash-DB match | technical | 100 |
| YARA match (critical / high / medium / low) | technical | 90 / 65 / 40 / 18 (+8 per extra rule) |
| VBA stomping | technical | 90 |
| Executable disguised as a document | technical | 90 |
| External link: exploit URI scheme / Follina-style OLE | technical | 90 |
| Archive zip slip | technical | 80 |
| Fuzzy family match | technical | 72 × confidence |
| Encrypted content (ransomware impact) | technical | 70 |
| External link: remote template / external OLE / UNC | technical | 70 (+8 per extra kind) |
| Archive double extension / RTLO spoof | technical | 60 |
| Archive zip bomb | technical | 60 |
| XLM macro sheet | technical | 55 |
| Confirmed prompt injection | technical | 50 |
| Macro: exec primitive / auto-run / dropper synergy / other suspicious call | technical | 40 (+8 each extra) / 22 / 20 / 10 |
| Executable inside an archive | technical | 35 |
| Encrypted archive the scanner could not open | technical | 20 |
| Mail: double-extension / RTLO attachment | technical | 60 |
| Mail: executable, script or macro-enabled attachment | technical | 45 |
| Mail: DMARC failure (SPF/DKIM failure without DMARC failure) | technical | 35 (20) |
| Mail: display-name spoof · deceptive link · Reply-To diversion | technical | 30 · 25 · 15 |
| Worst mail attachment | its own categories | carried over |
| Hidden content · suspicious injection phrasing · format mismatch | technical | 15 each |
| Worst archive member | its own categories | carried over |
| VirusTotal detections | reputation | max(35, 80 × ratio) |
| LLM lure assessment | semantic | 24 × confidence |
| Mail: lure subject | semantic | 8 |
| ML classifier | statistical | 20 × P(suspicious) |

Category caps: technical 100, reputation 80, semantic 24, statistical 20; the total is clamped to 100.

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

Decoy documents (`!000_Finance_Records_Backup.docx`, `!000_Signed_Contracts_Archive.pdf`, `!000_Asset_Inventory.csv`) are planted where an alphabetical ransomware walk reaches them first. Each is a valid, unique file whose SHA-256 is recorded. If one is **deleted, modified, rewritten with random bytes, or renamed with an appended extension** (`….docx.lockbit`), or a ransom-note-named file appears beside it, the tripwire fires. It writes `canary_alert_<time>.txt` next to the reports, logs at CRITICAL, and raises a desktop notification on macOS/Linux. With `watchdog` installed, canary folders are also **watched in real time**: a verification runs about a second after a canary is touched. `--background` checks every 5 minutes as well (`CANARY_CHECK_MINUTES`), the GUI does the same while it is open, and canary files are never scanned or quarantined themselves.

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

**Python:** 3.9+ (see `requirements.txt`; every dependency ships x86_64 and ARM64 wheels or is pure Python, so installation needs no compiler).

**Detection-layer libraries (optional, recommended):** `python-tlsh` + `ppdeep` (fuzzy hashing), `oletools` (macros), `yara-python` (YARA), `defusedxml` (hidden-content and external-link layers for Office files), `cryptography` (quarantine vault). If any are absent, that layer or feature is skipped.

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

API keys and settings are loaded from a local `.env` file and are **never** stored in the code.

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

# Protection
python RansomwareScanner.py --deploy-canaries [DIR ...]
python RansomwareScanner.py --verify-canaries
python RansomwareScanner.py --quarantine FILE
python RansomwareScanner.py --list-quarantine
python RansomwareScanner.py --restore ID [--restore-to PATH]
python RansomwareScanner.py --export-key FILE | --import-key FILE [--replace-key]

# Background mode: scheduled scans + canary checks
python RansomwareScanner.py --background
python RansomwareScanner.py --setup-autostart      # at login (Windows / macOS / Linux)
python RansomwareScanner.py --remove-autostart

# Utilities
python RansomwareScanner.py --import-database dataset.csv
python RansomwareScanner.py --fuzzy-hash confirmed_sample.bin
python RansomwareScanner.py --clear-cache
python RansomwareScanner.py --train-ml clean_samples/ malware_samples/   # ML model
python RansomwareScanner.py --create-shortcut      # Windows & Linux
python RansomwareScanner.py --version
```

Scan directories, file types and the scan interval live in the `CONFIG` block near the top of `RansomwareScanner.py` (or on the GUI's Scan page). All paths are derived from the user's home directory via `pathlib`, so they adapt to the host OS.

### Example report (excerpt)

```
Ransomware Scan Report
======================
Engine version:         4.0.0
Total files scanned:    6
Files flagged:          5
Highest verdict:        Critical
Detection layers used:  hashes, local-db, fuzzy, macro, yara, integrity, prompt-guard, relationships, archives, llm, virustotal
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

**Dashboard** (screenshot at the [top of this page](#-whats-new-in-40)). A status card per layer: hash database, fuzzy hashing (signature count), macro analysis, YARA (rule-file count), VirusTotal, the LLM (**LOCAL vs CLOUD**), and in v4 the heuristic layers, canary tripwires and quarantine vault. Scans run with live per-file progress; each row shows a compact per-layer summary (e.g. `DB– fuzzy– macro! yara✓3 exe! VT 14/72 AI 0.80`) next to a 0–100 risk bar and the verdict. Double-click a row for the full breakdown.

![Result detail](docs/screenshot-detail.png)

**Result detail.** The verdict and risk score, then what every layer concluded, followed by the **weighted score breakdown**. For archives, every member is listed with its own verdict. A **Quarantine file** button moves the file into the vault.

| Archive member breakdown | Prompt-injection finding |
|---|---|
| ![Archive detail](docs/screenshot-v4-archive.png) | ![Injection detail](docs/screenshot-v4-injection.png) |

![Protection page](docs/screenshot-v4-protection.png)

**Protection (new).** Deploy, verify and remove canaries, set automatic quarantine, restore or delete vault items, and clear the result cache. While the window is open, canaries are re-checked every few minutes and a trigger raises an alert.

![Scan page](docs/screenshot-v4-scan.png)

**Scan, Reports, Database, Logs, Settings.** Monitored directories and file types, past JSON/TXT reports and canary alerts, the malware-hash dataset, the live log stream, the scan schedule, start-at-login, the VirusTotal-upload switch, and API keys. Keys are written only to the git-ignored `.env` file.

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
pip install pytest
python -m pytest                 # 548 tests: unit + end-to-end + CLI (+1 opt-in GUI test)
python test_smoke.py             # the original v3 smoke test, still passing

# optional: the GUI test drives the real window (needs a display)
RUN_GUI_TESTS=1 xvfb-run -a python -m pytest tests/test_gui_smoke.py
```

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

---

## 📂 Project structure

```
hybrid-ransomware-detector/
├── RansomwareScanner.py         # CLI entry point, autostart, shortcuts, hash-DB import
├── gui.py                       # desktop GUI (uses the scanner as a library)
├── test_smoke.py                # original v3 smoke test (still passing)
├── engine/                      # the scanner itself
│   ├── config.py                # version, per-user paths, logging, .env, CONFIG
│   ├── scanner.py               # RansomwareScanner: runs the pipeline, folders, vault, canaries
│   ├── layers.py                # the ordered detection layers (the scan pipeline)
│   ├── containers.py            # ZIP / e-mail: one loop, members re-scanned recursively
│   ├── external.py              # LLM + VirusTotal lookups (cached)
│   ├── text.py                  # text and string extraction
│   └── report.py                # text + JSON reports
├── detectors/                   # independently-optional detection engines
│   ├── fuzzy_hash.py            # TLSH + ssdeep structural hashing
│   ├── macro_analysis.py        # olevba VBA/XLM triage + VBA stomping
│   ├── yara_engine.py           # YARA rule compilation + scanning
│   ├── file_integrity.py        # magic bytes, disguised executables, encrypted content
│   ├── prompt_guard.py          # hidden content + prompt-injection detection
│   ├── relationship_scanner.py  # remote template / Follina / UNC / RTF links
│   ├── container_extractor.py   # safe ZIP / AES ZIP / 7z / RAR / ISO extraction (bomb / slip / lures)
│   ├── mail_analyzer.py         # MailGuard: .eml/.msg auth, spoofing, links, attachments
│   ├── cfb_writer.py            # minimal OLE compound-file writer (repacks embedded documents)
│   ├── ml_classifier.py         # 15 byte/PE features, RandomForest or rule engine
│   ├── llm_backends.py          # local Ollama / cloud OpenAI / none, spotlighted prompts
│   └── scoring.py               # transparent weighted scoring matrix
├── core/                        # host-side protection services
│   ├── quarantine.py            # AES-256-GCM vault, verify-before-delete
│   ├── canary.py                # canary tripwires + desktop notifications
│   ├── canary_watch.py          # real-time canary watching (watchdog)
│   ├── cache.py                 # SQLite (WAL) cache for VirusTotal/LLM answers
│   └── http.py                  # timeouts, retry/backoff, rate limiter
├── rules/                       # YARA rules (drop in your own .yar files)
│   ├── ransomware_generic.yar
│   ├── office_dropper.yar
│   └── recovery_inhibition.yar
├── tests/                       # pytest suite (synthetic samples only)
├── docs/                        # screenshots + DETECTION_v3.md / DETECTION_v4.md
├── fuzzy_signatures.sample.json # documented placeholder fuzzy signature DB
├── build.py                     # PyInstaller build + smoke test + packaging
├── scanner.spec                 # PyInstaller recipe (CLI + GUI, UPX off)
├── requirements.txt
├── requirements-ml.txt          # optional: scikit-learn / joblib / numpy
├── requirements-build.txt       # optional: PyInstaller
├── CHANGELOG.md
├── .env.example                 # template for keys + settings
├── .gitignore
├── LICENSE
└── README.md
```

See [`docs/DETECTION_v4.md`](docs/DETECTION_v4.md) for the design of the v4 layers (and [`docs/DETECTION_v3.md`](docs/DETECTION_v3.md) for the earlier ones), and [`CHANGELOG.md`](CHANGELOG.md) for the version history.

---

## 🌐 Cross-platform & architecture notes

- **OS-aware paths:** all runtime paths (app dir, logs, reports, vault, cache) are built from `Path.home()`; nothing is hardcoded to one OS.
- **No architecture lock-in:** dependencies are pure Python or ship x86_64 and ARM64 wheels (Windows/macOS/Linux), including Apple Silicon.
- **Tested** on Python 3.9, 3.11, 3.12 and 3.13 (Linux), with the GUI exercised headlessly. The code avoids OS-specific APIs outside the autostart and notification helpers, which branch per platform.
- **Graceful degradation:** missing libraries, keys, OCR binaries or scan folders produce warnings, not crashes.

---

## ⚠️ Limitations

Being explicit about what the tool does *not* do:

- **Static analysis only.** Nothing is executed; there is no sandbox detonation.
- **Archives:** ZIP (ZipCrypto and AES), 7z, RAR and ISO/IMG. RAR contents need an external decompressor (7-Zip, unrar, unar or bsdtar); without one only the member names are checked. Multi-volume RAR sets are not reassembled. Encrypted archives open only with a password from the built-in delivery list.
- **Encrypted-content detection** needs at least 1 KiB of data, and a raw, headerless compressed stream can look as random as ciphertext. That is why it only runs once a document's own signature is already missing.
- **E-mail authentication** is read from the headers your server recorded, not re-verified. A message saved without transport headers (drafts, sent items, some exports) has no SPF/DKIM/DMARC verdict. OLE objects that are neither a packaged file nor an Office/PDF document (e.g. equations) are counted but not unpacked.
- **The ML layer is only as good as its training data.** No model ships with the project (a model trained on synthetic data would claim accuracy it doesn't have). The rule engine flags any non-compressed file that is random throughout, which can include legitimate encrypted files. KeePass, GPG and age files with their normal extension are recognised; other encrypted formats are not. That's why the layer is capped at 20 points.
- **Hidden-content detection** covers Word, Excel, PowerPoint (OOXML) and PDF. Legacy binary `.xls/.ppt` and conditional-formatting tricks are not inspected.
- **Canaries detect, they don't block.** They catch encryption in the folders where they are planted: within about a second with `watchdog`, otherwise at the check interval. This is a tripwire, not an EDR.
- **Quarantine key** is stored locally (`~/RansomwareScanner/keystore`, mode 0600). Use `--export-key` to back it up; a lost key and no backup means quarantined items can't be restored.
- **Detection content is a starting point:** the bundled YARA rules are original triage heuristics and the fuzzy database ships empty. Real coverage grows with your own signatures.

---

## 🧭 Roadmap

Delivered in v4.3.0: RAR archives and OLE objects in Outlook messages. Delivered in v4.2.0: AES ZIP / 7z / ISO, Excel and PowerPoint hidden content, nested Outlook items, quarantine key backup, vault-aware ML, and real-time canary watching. Delivered in v4.1.0: MailGuard (.eml/.msg), the static ML classifier and standalone executables. Delivered in v4.0.0: file-integrity and ransomware-impact detection, prompt-injection defence, Office external-link analysis, archive inspection, VBA-stomping/XLM detection, canary tripwires, the quarantine vault, and safer external calls (see the [changelog](CHANGELOG.md)). Next:

- **Optional sandbox integration** (e.g. a self-hosted CAPE): dynamic results as a separate, opt-in scoring category.
- **A curated, labelled training corpus** and published ML evaluation numbers.
- **Windows toast notifications** for canary alerts (macOS and Linux are supported today).
- **CI** running the test suite and `build.py` on Windows, macOS and Linux for every push, with the binaries attached to releases.
- **Richer detection content:** a broader YARA rule set and a curated starter fuzzy-signature database.

---

## 🚨 Disclaimer

This project is for **educational and defensive** purposes only: identifying potentially malicious documents. Do not use it to create or distribute malware. Always analyse untrusted files in an isolated environment.

## 👤 Author

**Abdelrahman El-Maghraby**, Cybersecurity Specialist
[LinkedIn](https://www.linkedin.com/in/abdelrahman-el-maghraby/)

Released under the [MIT License](LICENSE).
