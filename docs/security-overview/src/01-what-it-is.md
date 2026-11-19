# What Aegis Sentinel is

## Purpose and intended use

Aegis Sentinel (Python package `hybrid-ransomware-detector`, engine {{fact:engine_version}})
inspects files **without running them** and reports how much evidence of malicious intent
they carry. Its focus is the delivery stage of ransomware and other intrusions: Office
documents with macros or remote templates, archives and disc images, e-mail messages,
scripts, Windows and Linux programs, web pages that smuggle payloads, and images that carry
QR codes. For each file it produces:

- a **risk score** from 0 to 100 and a **verdict band** (Clean, Low, Medium, High,
  Critical), with every contributing indicator and its points listed;
- a **scan status** that says how much of the file was actually inspected (`complete`,
  `unsupported`, `partial`, `locked`, `failed`) and why;
- **provenance**: which layers ran, which were unavailable or skipped, which external
  services were configured, and exactly what, if anything, was sent off the host.

The same engine is used from a desktop GUI, a command-line tool, a background service, a
folder monitor, an IMAP mailbox poller and a REST API. The REST API in Docker is the
supported server edition; Kubernetes manifests exist as an optional, not yet
cluster-verified deployment ([[pending]]).

## What "hybrid" means here

"Hybrid" refers to combining several *kinds* of evidence about one file, each with a
different reliability, into one explainable score:

| Kind of evidence | Layers | Scoring category | Trust placed in it |
|---|---|---|---|
| Structural and static technical indicators | macro, YARA, integrity, ELF, PE, script, archive, mail, web, embedded, relationships, QR, prompt-guard, fuzzy, local-db | `technical` | Highest; can reach Critical on its own |
| Reputation from a third party | VirusTotal | `reputation` | Capped at {{fact:cap_reputation}} points |
| Semantic opinion about the text | LLM | `semantic` | Capped at {{fact:cap_semantic}} points; alone never above {{fact:semantic_only_max}} (Medium) |
| Statistical byte-shape opinion | ML (a transparent rule engine unless a model is supplied) | `statistical` | Capped at {{fact:cap_statistical}} points; alone never above {{fact:semantic_only_max}} |
| Observed behaviour | emulation (box-js), CAPE sandbox | `dynamic` | Capped at {{fact:cap_dynamic}}; off by default |

The design rule is that **a confident opinion never outweighs structure**: an LLM that
finds a phishing lure, or a classifier that dislikes a byte distribution, cannot by itself
push a file above Medium. Chapter 7 shows the arithmetic.

## Main capabilities

- {{fact:layer_instances}} pipeline layers built from {{fact:layer_classes}} layer classes
  (chapter 6), with recursion into archives, disc images, macOS packages, e-mail
  attachments, payloads hidden in web pages, and content embedded in OneNote, CHM, MSI,
  encrypted Office and XLL files.
- Isolated scan workers: every file is parsed in a separate process with a wall-clock limit
  ({{fact:scan_timeout_seconds}} s) and a memory limit ({{fact:worker_memory_mb}} MB) by
  default; if workers cannot start, nothing is parsed in the main process (fail closed).
- A versioned indicator registry (`detectors/indicators.yaml`, {{fact:indicators}}
  indicators, {{fact:scorers}} scorer functions); 25 bundled YARA rules; signed rule packs.
- Host protection on desktops: canary files, optional containment, an encrypted quarantine
  vault.
- Delivery: report files, JSON Lines, signed webhooks, metadata-only e-mail alerts through a
  persistent outbox, optional redacted upload to S3-compatible storage.
- Optional external opinions: VirusTotal, a local (Ollama) or cloud (OpenAI) LLM, and the
  operator's own CAPE sandbox, each off by default and recorded in provenance when used.

## Limitations and non-goals

These come from the code and from `docs/RELEASE_SCOPE.md`; they are deliberate.

- **Not antivirus or EDR.** There is no on-access scanning, no kernel component, no
  process monitoring and no prevention before a file is written or opened. The folder
  monitor scans files *after* they arrive; canaries notice encryption *after* it starts.
- **No measured detection rate.** No detection or false-positive rate has been established
  on real samples (finding M1/X1). The weights are expert-set, not calibrated.
- **Static by default.** Behaviour that appears only at run time is invisible unless the
  optional sandbox is configured. Emulation exists but is excluded from the production
  profile because it executes attacker JavaScript.
- **Single organisation, single instance.** One deployment serves one organisation; there
  are no tenants, user roles or high availability.
- **No shipped ML model**: a transparent rule engine runs unless a model is supplied.
- **Worker processes are a reliability boundary, not a security sandbox.** They contain
  hangs, crashes and memory blow-ups. The security boundaries are the Docker containers
  (or Kubernetes Pods) and the separate CAPE environment.

## Five things that are easy to confuse

| Term | What it is in this project | What it is not |
|---|---|---|
| **File analysis** | Parsing a file's bytes in a worker and scoring the evidence | Watching the file being used |
| **Monitoring** | `FolderMonitor` (`core/folder_watch.py`): a desktop watcher that queues new or changed files in configured folders for an ordinary isolated scan once they stop changing | On-access interception; files are already on disk when scanned |
| **Canaries** | Decoy documents (`core/canary.py`) whose size and SHA-256 are recorded and re-checked on an interval and, with `watchdog`, on file-system events | Detection of the first encrypted file; by design they trip after encryption has begun |
| **Quarantine** | Moving a file into an AES-256-GCM vault after a verified encrypted copy exists (`core/quarantine.py`); manual, or automatic after batch scans at a configured verdict | A verdict; quarantine is a separate action decision |
| **Containment** | Optional, desktop-only reactions to a canary trip (`core/response.py`, `core/containment.py`): suspend or kill processes writing in the canary folders, remove write access, disable network adapters, run a script | Prevention; it shortens damage after the alarm |

## Indicator, score, behaviour, proof

The report vocabulary is easy to over-read. Keep these apart:

- An **indicator** is one observed fact that a rule considers suspicious, for example
  `macro_autoexec` (an auto-run macro exists) or `pe_recovery_inhibition` (a program
  contains a shadow-copy deletion command line). Each has a weight in the registry.
- The **risk score** is a weighted, capped sum of indicators. It orders files by how much
  suspicious evidence they carry. It is **not a calibrated probability** of maliciousness;
  "80" does not mean "80 % likely".
- **Observed behaviour** exists only when the sandbox or emulation actually ran the sample
  (`dynamic` category). Everything else is static evidence about what the file *contains*.
- **Proven maliciousness** is not something this system asserts. A Critical verdict says
  the evidence is strong; it is not attribution or proof. Conversely, **no findings does
  not prove safety**: unknown techniques, encrypted content and run-time-only behaviour
  can produce a Clean verdict. A Clean verdict on a scan that was not `complete` is shown
  as "Clean (partial scan)" so that it is never read as a plain all-clear.
