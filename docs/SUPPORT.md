# Reporting a false positive (or a miss)

Thank you - every report makes the next rule pack better. Please send what is
listed below to your support contact. Send hashes and results, **not the file**,
unless support asks for it and your policy allows sharing it.

## What to send

1. **The result JSON** of the scan (the `/scan` answer, or the `.json` report of a
   folder scan). It holds the verdict, the score breakdown (which indicators fired,
   with their points), `scan_status` and `incomplete_reasons`, and `provenance`:
   engine version, rules version and SHA-256, registry version, which layers ran,
   and what was sent outside. It contains no secrets.
2. **The SHA-256** of the file (`sha256_hash` in the result) and the file type.
3. **What you expected** and why (for example "signed installer from our vendor",
   "invoice template we create ourselves").
4. **Version and setup:** `GET /version` (engine, schema, registry, rules) or the
   first lines of the text report; Docker or desktop; profile.
5. For a desktop install, the **Diagnostics report** (Settings > Diagnostics > Copy
   report); for a server, the output of `GET /ready` with the token.

Remove anything confidential from file names and paths before sending; the rest of
the result does not contain document content.

## While you wait

A file you have checked can be allowed by its hash so it is not reported again:

```bash
hrd-scanner --allow /path/to/file --note "checked by J. Doe, vendor installer"
```

In Docker the allowlist is part of the detection content, read-only for the
service; add to it with the maintenance service, which can write it:

```bash
docker compose run --rm -v "$PWD/checked:/import:ro" content --allow /import/<file> --note "checked by ..."
```

Allowlisting is by SHA-256 only: a changed file is scanned again, and a hash in
the malware database still wins.

## Misses (malware not detected)

Send the SHA-256, the result JSON and, if available, a public reference (a
MalwareBazaar or VirusTotal link). Do not send live malware by e-mail; support will
arrange a safe transfer (a password-protected archive) if the sample is needed.
