# Inputs, formats, platforms and dependencies

## How a file is selected and recognised

Two different gates decide what is analysed:

1. **Which files are picked up.** A *direct* scan (`--scan-file`, the GUI's single-file
   scan, an API upload) accepts any regular file. A *folder* scan, the background service
   and the folder monitor select files **by extension only**, from `file_extensions`
   (`engine/config.py`). The default list has {{fact:default_extensions}} extensions; the
   six image types are supported but left out by default (a Downloads folder can hold
   thousands, and each could cost a VirusTotal lookup). Images inside archives and e-mails
   are always checked. Office lock files (`~$*`), canary files and anything that is not a
   regular file (FIFO, socket, device) are skipped during the walk.
2. **How each layer treats it.** Inside the pipeline most layers decide by **content**
   (magic bytes): PE, ELF, OneNote, CHM, MSI, XLL, encrypted Office and the integrity
   check's format detection. Others decide by **extension**: scripts, mail, web pages,
   macro analysis, QR and text extraction. Archives require **both**: the extension *and*
   matching magic bytes (`ContainerExtractor.is_container`). A real ZIP renamed to `.dat` is
   therefore not opened; the integrity layer still notices ZIP content and the completeness
   check reports it as `partial` ("content was not opened").

An extension list alone does not prove support. The format matrix at the end of this
chapter states what each family actually gets.



## Nested and embedded content

Containers send their members back through the *whole* pipeline at depth + 1
(`engine/containers.py`). Limits stop the descent; each one is visible in the result.

| Limit | Default | Key | What happens beyond it |
|---|---|---|---|
| Container nesting through the pipeline | {{fact:max_nesting}} | `max_nesting` | members of a container at that depth are listed, not scanned: `partial` |
| Archive nesting expanded by the extractor | {{fact:archive_max_depth}} | `archive_max_depth` | flagged as a decompression bomb |
| Unpacked bytes per container (archive and mail) | {{fact:archive_max_total_mb}} MB | `archive_max_total_mb` | unpacking stops: bomb flag, `partial` |
| Entries per archive | {{fact:archive_max_members}} | `archive_max_members` | names checked, content not unpacked: `partial` |
| Compression ratio | 100x (members over 1 MiB) | constructor argument | bomb flag |
| Members given the full pipeline | archive {{fact:archive_scan_members}}, mail {{fact:mail_scan_attachments}}, web 5, embedded 25 | `archive_scan_members`, `mail_scan_attachments`; web and embedded fixed | listed, not scanned: `partial`; risky members (programs, scripts, containers, RTLO names) take the budget first |
| Attachments per message | {{fact:mail_max_attachments}} | `mail_max_attachments` | `attachments_skipped`, `partial` |
| Message size | 60 MiB | fixed | not analysed, `partial` |
| Web page read | 20 MiB; at most 5 payloads of 60 MiB | fixed | `truncated`, `partial` (since RV-S1) |

The limit keys without an environment variable can be changed only in configuration
code; `engine/validation.py` bounds the ones that can be set.

## Damaged, locked, unsupported, oversized and special inputs

| Input | Result |
|---|---|
| FIFO, socket, device (or a link to one) | skipped in folder walks (`skipped_special_file` log event); hashing refuses it (`open_regular` with `O_NONBLOCK`) |
| Password-protected archive member, encrypted Office, PDF needing a user password | tried with passwords from the message, a short list of common ones and the file name; if not opened: `locked` |
| Damaged archive or document | the rest of the archive is reported as "could not be parsed completely"; a parser error is recorded per layer; `partial` |
| Format with no specific analysis | `unsupported` (generic layers only) |
| Larger than the shared read (64 MiB) | layers stream from disk instead of sharing one in-memory copy |
| Larger than the fuzzy-hash limit ({{fact:fuzzy_max_mib}} MiB) | fuzzy layer skipped with a recorded reason: `partial` |
| Too slow or too large for the worker | time-out or memory limit: `failed`, with any evidence reported earlier kept (chapter 8) |

## Platforms

| Platform | State |
|---|---|
| Docker Engine on Linux x86_64 (Python 3.12 image) | The supported server edition. [[ci]] on `3e5a3f2` only; [[pending]] at this baseline (Docker was not running on the review host) |
| Source install on macOS arm64, Python 3.14.2 | [[local]]: the full safe test selection at `2672376` |
| Source install on Linux and Windows, Python 3.9 and 3.12 | [[ci]] on `3e5a3f2` only; [[pending]] for the 175 newer commits |
| Kubernetes 1.29+ (`deploy/kubernetes/`) | [[impl]], statically checked; [[pending]] on any cluster |
| Linux arm64, Windows arm64, macOS Intel | [[pending]]: no runner |
| Desktop GUI on a real display | [[pending]]: only headless widget tests ran |

Platform-specific mechanisms: worker memory limits use `RLIMIT_AS` on Linux, a Job Object on
Windows and a parent-side resident-memory watchdog every 0.25 s on macOS (which does not
enforce `RLIMIT_AS`). Containment uses `/proc` on Linux, `lsof` on macOS and the Restart
Manager API on Windows. TLSH has no Windows wheel, so a pure-Python port is used there.

## Dependencies

Core Python dependencies (`pyproject.toml`): requests, schedule, python-dotenv, PyYAML,
pypdf, python-docx, Pillow, defusedxml, cryptography, olefile, keyring. Optional extras add
the fuzzy hashes (python-tlsh, ppdeep, numpy), oletools, yara-python, the archive libraries
(pyzipper, py7zr, pycdlib, rarfile), msoffcrypto-tool, pyzbar, OCR (pdf2image, pytesseract),
watchdog, the ML stack (scikit-learn, joblib, numpy), the API (fastapi, uvicorn,
python-multipart) and boto3 for cloud upload. External programs are found with
`core.tools.trusted_which`, which uses absolute `PATH` entries only and never the current
directory: 7-Zip, unrar, unar or bsdtar, zbar, poppler, Tesseract and box-js.

A layer whose dependency is missing is reported `down` at start-up (`--capabilities`,
`GET /ready`), recorded in each result's provenance, and makes a scan `partial` *only for
files it applies to*. The production profile (`AEGIS_PROFILE=production`) refuses to start
without the required layers (chapter 3). OCR and 7-Zip for DMG and CHM are not part of the
capability states, so their absence is visible only in individual results.

@landscape

## Format matrix (source-verified)

| Family | Recognised as | Analysed by | Library or tool | Default folder scan | If the dependency is missing |
|---|---|---|---|---|---|
| Office OLE (`.doc .dot .xls .xlm .ppt`) | extension (macro); magic (integrity, encrypted Office) | macro (olevba, VBA stomping, XLM), embedded (encrypted Office), YARA, prompt-guard (legacy `.xls` hidden sheets), strings | `oletools`, `msoffcrypto-tool`, `olefile` | yes | macro layer `down`, scan `partial` ("layer unavailable") |
| Office Open XML (`.docx .docm .xlsx .xlsm .xlsb .pptx .pptm`, templates, add-ins) | extension, plus `[Content_Types].xml` check | macro, prompt-guard (hidden content, injection), relationships (remote templates, Follina-style links, UNC), QR in media, text, YARA | `oletools`, `defusedxml`, `python-docx`, `pyzbar` | yes (except `.dotx .xltx .potx .ppsx`) | prompt-guard and relationships `down` without `defusedxml` |
| Encrypted Office | magic (EncryptedPackage, RC4/XOR) | embedded: decrypt with known defaults, passwords from the e-mail or the file name, then scan the content | `msoffcrypto-tool` | as Office | not decrypted: `locked` |
| RTF | magic | relationships (RTF remote template, auto-updating OLE), YARA, generic layers | standard library | yes | — |
| PDF | extension (text, QR); magic (integrity) | prompt-guard (invisible text, injection), text for the LLM, QR in page images, locked-PDF check, YARA | `pypdf`; OCR only with an LLM configured: `pdf2image` + poppler, `pytesseract` + Tesseract | yes | without OCR an image-only PDF yields no text (silently); a parser error makes the scan `partial` |
| ZIP | extension + magic | archive container: members through the whole pipeline | `zipfile`; AES needs `pyzipper` | yes | AES members unreadable; archive layer `down` |
| 7z | extension + magic | archive container | `py7zr` | yes | `partial` "needs py7zr" |
| RAR | extension + magic | archive container | `rarfile` + 7-Zip, unrar, unar or bsdtar | yes | `partial` "needs a RAR decompressor"; bsdtar cannot decrypt |
| ISO 9660 (`.iso`, `.img`) | extension + `CD001` | archive container | `pycdlib` | yes | `partial` "needs pycdlib"; an `.img` without ISO 9660 is not a container |
| macOS `.pkg` / `.mpkg` | extension + XAR magic | archive container: XAR, then Scripts and Payload cpio | pure Python + `defusedxml` | yes | `partial` |
| macOS `.dmg` | extension + `koly` trailer | archive container, one level into file-system images; encrypted images reported | 7-Zip | yes | `partial` "7-Zip (to open DMG disk images)" |
| E-mail `.eml`, `.msg` | extension; OLE magic decides `.msg` | mail container: sender authentication results, spoofing, deceptive links, risky attachments, passwords in the body; attachments and attached messages recurse | `email` (stdlib); `.msg` needs `olefile` | yes | `.msg`: "olefile is not installed", `partial` |
| Web (`.html .htm .svg .hta`, also `.shtml .xhtml`) | extension | web container: HTML smuggling, embedded payloads (scanned), active SVG, credential forms, redirects, obfuscation | pure Python | yes (not `.shtml .xhtml`) | — |
| Scripts (`.js .jse .vbs .vbe .wsf .hta .ps1 .bat .cmd`, also `.wsh .psm1`) | extension | script (categories, obfuscation, encoded scripts decoded statically); emulation only if enabled | standard library; box-js for emulation | yes (not `.wsh .psm1`) | emulation `down` when enabled without box-js |
| Windows PE (`.exe .dll .scr .cpl .sys`, any name) | magic `MZ` + PE header | PE (sections, imports, recovery inhibition, overlay, signature presence), XLL check | standard library | yes | — |
| Linux ELF (any name) | magic | ELF (packing, removed section table, hostile strings) | standard library | not by extension; direct scans and archive members | — |
| OneNote, CHM, MSI, XLL | magic | embedded container: carved members scanned | `olefile`; 7-Zip for CHM | yes | CHM: `partial` "7-Zip is needed" |
| Images (`.png .jpg .jpeg .gif .bmp .webp`) | extension | QR (URL judged, never fetched), integrity (payload appended after the image end) | Pillow + `pyzbar`/zbar, or OpenCV | **no** (inside containers: yes) | QR `down`; scan `partial` where it applies |
| gzip, bzip2, xz, zstd, cab, tar, LNK, Mach-O, unknown | magic (integrity) | generic layers only: hashes, YARA, integrity, ML, strings | — | no | `unsupported` (no type-specific analysis) |

@endlandscape
