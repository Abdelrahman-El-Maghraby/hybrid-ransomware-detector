# Threat model: attacking the scanner itself

Aegis Sentinel exists to read files that attackers wrote. That makes the scanner a
target: an attacker who cannot get a file past it can try to break it, blind it,
or turn it against the machine it protects. This document lists those attacks,
what the code does about each, and what is left.

## Assets

| Asset | Why it matters |
|---|---|
| The verdict | A false "Clean" lets the payload through; a flood of false alarms gets the tool switched off. |
| The host running the scan | The scanner runs with the user's rights and opens hostile files. |
| Quarantined files and the vault key | Restoring the wrong file, or losing the key, loses data. |
| The user's documents | Sent to a cloud LLM or VirusTotal, they leave the organisation. |
| Detection content | Rules, signatures, weights and the allowlist decide what is flagged. |
| Alerts | Forged or suppressed alerts mislead the SOC. |

## Trust boundaries

1. **Scanned files** (fully hostile): every byte, every name, every nested file.
2. **External services** (semi-trusted): VirusTotal, the LLM, the CAPE sandbox, the webhook receiver.
3. **Detection content** (trusted only when signed or written locally): rule packs, the allowlist, weight overrides.
4. **Local user and configuration** (trusted): `.env`, the GUI, CLI arguments.
5. **API clients** (authenticated, otherwise untrusted): anyone who can reach the REST port.

## Threats and mitigations

### 1. Crash or hang the scanner (denial of service)
*A crafted PDF loops forever in the parser; a ZIP declares a format version the
library cannot handle; an archive nests 50 levels deep.*

- Folder scans and API scans run each file in a **worker process** with a wall-clock
  limit and (Linux) an address-space limit; a hung or dead worker is replaced and the
  file is reported as `scan_failed` (Medium) (`engine/workers.py`).
- **Every pipeline layer runs in a guard**: a parser that raises costs only that
  layer's evidence and is recorded in `layer_errors` (`engine/scanner.py`).
- Hard limits on archive depth, members, total and per-member size, compression
  ratio, image pixels, PDF pages, script size and decoding depth.
- **Fuzzing** of every parser (`tests/test_fuzz_parsers.py`, `fuzz/`). Found and
  fixed: a pyzipper `NotImplementedError` that ended a file's scan; a known infinite
  loop in PyPDF2 3.0.x (CVE-2023-36464), removed by moving to `pypdf`.
- **Timing on a benign corpus** (`tools/profile_layers.py`). Found and fixed: a
  quadratic regular expression in the strings pass (a 300 KB single-line script
  took 140 s).
- `pip-audit` in CI against the pinned lock file.

*Residual:* Windows and macOS do not enforce the memory limit (time limit still
applies). A determined attacker can still make one file slow up to the time limit.

### 2. Escape the extraction sandbox (path traversal, links)
*Archive members named `../../.bashrc`, absolute paths, symlinks, device files.*

- Members are written under generated names inside a fresh temporary folder;
  traversal, absolute paths and links are reported (`archive_zip_slip`) and never
  written. External tools (7-Zip, unrar) only stream one member to stdout.
- Rule packs refuse any entry that is not a plain file under `rules/`.
- API uploads are saved under a generated name; the client's file name is only used
  for its extension and for display.

### 3. Evade detection
*Obfuscation, password-protected archives, payloads fetched later, QR codes,
smuggling, lookalike formats.*

- Layered decoding of scripts (5 levels), Script Encoder decoding, archive
  passwords read from the e-mail, HTML-smuggling payload extraction, QR decoding,
  OneNote / CHM / MSI / encrypted-Office unpacking, magic-byte format checks.
- Scoring favours structural evidence and stacks independent layers, so evading
  one layer rarely drops the verdict to Clean.

*Residual:* static analysis cannot see behaviour that only appears at run time
(payload downloaded later, environment checks). The optional CAPE sandbox layer
covers part of this; without it, this is the largest gap.

### 4. Manipulate the LLM (prompt injection)
*Hidden text telling the model "this file is safe".*

- Hidden-content and injection detection runs **before** the LLM; hidden injection
  text is itself a technical finding (`prompt_injection`, 50).
- Document text is wrapped in per-request random delimiters, instructions stay in
  the system role, output is JSON only at temperature 0.
- The LLM category is capped at 24 points and semantic evidence alone can never
  exceed Medium: a fooled model can add little, and cannot clear technical findings.

### 5. Poison detection content
*A malicious rule pack, a planted allowlist entry, a weights file that zeroes a weight.*

- Rule packs install only with an **Ed25519 signature** from a configured key, a
  manifest whose hashes match every file, a newer version, and rules that compile
  (`core/rulepack.py`). Keys come from configuration, never from the pack.
- The allowlist holds **SHA-256 hashes** only (no names, paths or wildcards), so an
  attacker cannot reuse an entry without a byte-identical file; a hash in the
  malware database still wins.
- Weight overrides must name existing weights with the same shape; reports record
  the registry version and "+override".

*Residual:* anyone who can write to the user's data folder can edit the allowlist
or point the config elsewhere - protect that folder like the rest of the account.

### 5b. Turn the scanner's own features against the host
- **Emulation** (box-js) executes the attacker's JavaScript in a Node sandbox;
  sandboxes of this kind (vm2) have had escapes. It is off by default, documented
  for analysis VMs only, found by trusted path, run on a copy in a private
  temporary folder with a stripped environment and a time limit, inheriting the
  worker's memory limit; its result files are parsed as untrusted JSON.
- **Canary response scripts** run with the user's rights when an attack is under
  way: only an absolute path, owned by the user, not writable by group/others.
- **Helper programs** (7-Zip, unrar, nmcli, ...) are resolved outside the current
  directory, so a planted `7z.exe` in a scanned folder is never started.
- **IMAP credentials**: an app password from `.env`, never logged, never in
  reports or the state file; TLS with certificate verification only, read-only
  mailbox access.

### 6. Leak data to third parties
- VirusTotal is queried **by hash**; uploads are opt-in. The LLM prefers a local
  Ollama model; cloud use is logged. The sandbox is the user's own server.
- Webhooks send metadata only (verdict, hash, indicators), never content, and can
  be HMAC-signed.

### 7. Abuse the API
- Bearer token required (constant-time compare); the server refuses to start with
  a short token; binds to 127.0.0.1 unless configured; uploads are size-limited
  and isolated; documentation endpoints are off.

*Residual:* no TLS of its own - put it behind a reverse proxy. No rate limiting
beyond the worker pool.

### 8. Tamper with quarantine
- AES-256-GCM per file with authenticated header, chunks and end marker
  (bit flips, reordering, truncation detected); originals deleted only after a
  verified decrypt; restore never overwrites; key backup is passphrase-encrypted.

### 9. Supply chain
- Pinned lock file; `pip-audit` in CI; release builds come from CI with
  SHA-256 sums, a CycloneDX SBOM and keyless Sigstore signatures.

*Residual:* binaries are not Authenticode-signed / notarised (needs paid certificates).

## Summary of residual risk

| Risk | Level | Next step |
|---|---|---|
| Run-time-only behaviour | High | Use the CAPE sandbox layer for suspicious files |
| Detection rate on real samples unknown | High | `tools/evaluate.py` on labelled data |
| Memory limit not enforced on Windows/macOS | Medium | Job objects (Windows) / separate VM |
| Local tampering with config / allowlist | Medium | OS file permissions; signed config (future) |
| Unsigned binaries | Medium | Code-signing certificates |
| Slow-file DoS up to the timeout | Low | Lower SCAN_TIMEOUT_SECONDS where latency matters |
