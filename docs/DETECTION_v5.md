# AEGIS SENTINEL v5.2.0 — Detection, Cryptography & AI Correlation Specification

This document specifies the internal data structures, cryptographic framing, authentication state machines, and scoring mathematics implemented in **AEGIS SENTINEL v5.2.0**.

---

## 1. End-to-End Signal Flow & Category Caps

```text
Artifact / Email / Process
          │
          ├──► [Technical Pillar] ──► Hash DB (100), Canary (100), Zip-Bomb (100),
          │                           VBA Stomping (90), Memory RWX/PE (90), YARA (90),
          │                           Sigma/YARA-L (90), Behavioral (85), Fuzzy (72),
          │                           RTI/Follina (70), XLM (55), PromptInj (50),
          │                           Mail Auth/Lookalike (45), Macro Exec (40),
          │                           Calibrated ML (<=35), Hidden Text (25)
          │                                     │
          │                                     ▼
          │                        min(100.0, sum(technical))
          │
          ├──► [Reputation Pillar] ─► TIP Active IOC (95 -> cap 80),
          │                           VirusTotal Ratio (max(35, 80*r)),
          │                           MailGuard Malicious URL (65)
          │                                     │
          │                                     ▼
          │                        min(80.0, sum(reputation))
          │
          └──► [Semantic Pillar] ───► Local LLM Lure Analysis (24 * conf),
                                      MailGuard Phishing Keywords (<=20)
                                                │
                                                ▼
                                   min(24.0, sum(semantic))
                                                │
                                                ▼
                     +----------------------------------------------------+
                     | Hard-Signal Guardrail:                             |
                     | If Technical == 0 AND Reputation == 0:             |
                     |     Final Risk Score = min(raw_score, 49) [Medium] |
                     | Else:                                              |
                     |     Final Risk Score = min(100, round(raw_score))  |
                     +----------------------------------------------------+
```

### Mathematical Formulation

Let $C_{\text{tech}}$, $C_{\text{rep}}$, and $C_{\text{sem}}$ denote the sets of individual indicator contributions in the technical, reputation, and semantic categories. The category totals $T_{\text{tech}}, T_{\text{rep}}, T_{\text{sem}}$ are bounded by strict ceilings:

$$T_{\text{tech}} = \min\left(100.0, \sum_{c \in C_{\text{tech}}} w_c\right), \quad T_{\text{rep}} = \min\left(80.0, \sum_{c \in C_{\text{rep}}} w_c\right), \quad T_{\text{sem}} = \min\left(24.0, \sum_{c \in C_{\text{sem}}} w_c\right)$$

The raw composite score $S_{\text{raw}}$ is:

$$S_{\text{raw}} = \min\left(100.0, \; T_{\text{tech}} + T_{\text{rep}} + T_{\text{sem}}\right)$$

To guarantee that semantic or uncorroborated LLM hallucinations never trigger automatic containment (`High >= 50` or `Critical >= 80`), the hard-signal constraint is applied:

$$S_{\text{final}} = \begin{cases} \min\left(\lfloor S_{\text{raw}} + 0.5 \rfloor, \; 49\right) & \text{if } T_{\text{tech}} = 0 \text{ and } T_{\text{rep}} = 0 \\ \lfloor S_{\text{raw}} + 0.5 \rfloor & \text{otherwise} \end{cases}$$

---

## 2. AES-256-GCM Chunked Quarantine Framing (`core/quarantine.py`)

Quarantined artifacts are moved atomically into the vault staging area, stripped of execution permissions, and encrypted in 64 KB chunks using `AESGCM` (256-bit key) with per-chunk nonce derivation and Additional Authenticated Data (AAD) binding.

### Binary File Layout (`.quar`)

```text
+-----------------------------------------------------------------------+
|                        FILE HEADER (Variable)                         |
+---------------+---------------+---------------+-----------------------+
| Magic (6 B)   | Version (1 B) | Flags (1 B)   | Scrypt Salt (16 B)    |
| "AEGISQ"      | 0x01          | 0x00 or 0x01  | (0x00*16 if raw key)  |
+---------------+---------------+---------------+-----------------------+
| Base Nonce (8 B)              | KeyID Len(1B) | Key ID (UTF-8 Bytes)  |
| os.urandom(8)                 | N             | e.g., "k1-default"    |
+-------------------------------+---------------+-----------------------+
|                     ENCRYPTED CHUNK FRAMES (0..K)                     |
+---------------+-------------------------------+-----------------------+
| FinalFlag(1B) | Ciphertext+Tag Length (4 B)   | Ciphertext + GCM Tag  |
| 0x00 or 0x01  | Big-Endian uint32             | Up to 64 KB + 16 B    |
+---------------+-------------------------------+-----------------------+
```

### Per-Chunk Nonce & AAD Construction
* **12-Byte Nonce for Chunk $i$:** $\text{Nonce}_i = \text{BaseNonce}_{8\text{B}} \parallel \text{uint32\_be}(i)$
* **Per-Chunk AAD:**
  $$\text{AAD}_i = \text{FileHeader} \parallel \text{"\vert{}"} \parallel \text{QuarantineUUID} \parallel \text{"\vert{}"} \parallel \text{SHA256}_{\text{expected}} \parallel \text{uint32\_be}(i) \parallel \text{uint8}(\text{FinalFlag}_i)$$

Any modification to the file header, chunk order, truncation of the final chunk (`FinalFlag != 1`), or mismatch against the original plaintext `SHA-256` raises `cryptography.exceptions.InvalidTag` and aborts restoration before touching the destination path.

---

## 3. Aegis MailGuard Authentication Honesty Model (`detectors/mail_analyzer.py`)

Unlike naive email scanners that blindly trust any `Authentication-Results` header (which attackers trivially forge by prepending their own header prior to delivery), **Aegis MailGuard** enforces a 3-state verification model:

| Status Label | Definition | Scoring Weight Multiplier |
| :--- | :--- | :--- |
| **`verified`** | Cryptographically verified directly by AEGIS SENTINEL (`dkimpy` RSA/Ed25519 signature check over raw RFC 5322 bytes or live DNS `SPF`/`DMARC` policy evaluation). | **100%** of base weight (`1.0x`) |
| **`reported`** | Parsed from an `Authentication-Results` or `Received-SPF` header whose `authserv-id` matches `CONFIG["trusted_authserv"]` (e.g., `mx.google.com`, `protection.outlook.com`). | **80%** of base weight (`0.80x`) |
| **`unavailable`** | No trusted header exists and live DNS/DKIM verification is disabled or unreachable. | **0 points** (logged under `inconclusive_notes`) |

**Forged Header Detection:** Any `Authentication-Results` header whose `authserv-id` is not in `trusted_authserv` is stripped from trust evaluation, recorded in `untrusted_authserv_headers`, and penalized with `+35.0` technical points (`mail_untrusted_auth_header`).

---

## 4. PromptGuard & Nonce Spotlighting (`detectors/prompt_guard.py`)

Before any document or email text is passed to the local Ollama model (or OpenAI fallback):
1. **Concealed Text Inspection:** `.docx` `word/document.xml` runs are parsed via `defusedxml` to extract `<w:vanish/>`, `<w:webHidden/>`, font sizes $\le 2\text{pt}$ (`w:sz val <= 4`), and near-white RGB colors (`>= F0F0F0`). HTML bodies are scanned for `display:none`, `visibility:hidden`, `opacity:0`, and `font-size:0`.
2. **Head / Middle / Tail Sampling:** Text is sampled deterministically (40% head, 30% middle, 30% tail) within a strict 3,000-character visible budget and 2,000-character embedded strings budget so adversaries cannot hide payloads at the end of a padded document.
3. **Nonce-Delimited Spotlighting:** A per-request 128-bit random hex nonce (`{NONCE}`) wraps all untrusted text inside `<UNTRUSTED_DATA_{NONCE}> ... </UNTRUSTED_DATA_{NONCE}>`, and any literal `</UNTRUSTED_DATA_` sequence inside the file is neutralized prior to wrapping.